"""信任判定单元测试：每种失败原因可区分；时间窗口边界确定。"""
from __future__ import annotations

import pytest

from app.errors import (
    BodyTamperedError,
    MissingCredentialError,
    ScopeDeniedError,
    ScopeInsufficientError,
    SignatureMismatchError,
    TimestampExpiredError,
    TimestampFutureError,
    UnknownPrincipalError,
)
from app.security import Principal, PrincipalStore, RequestVerifier, sign

from .conftest import ACCOUNTS, TRANSFERS


@pytest.fixture
def verifier(clock):
    store = PrincipalStore(
        {
            "svc-accounts": Principal("svc-accounts", "secret-accounts", frozenset({ACCOUNTS})),
            "svc-admin": Principal("svc-admin", "secret-admin", frozenset({ACCOUNTS, TRANSFERS})),
        }
    )
    return RequestVerifier(store, clock=clock, window_past=300, window_future=30)


def headers_for(verifier, clock, *, key="svc-accounts", scope=ACCOUNTS, ts=None, nonce="n1",
                method="POST", path="/v1/accounts", body=b'{"name":"alice"}'):
    ts = int(clock.now_unix()) if ts is None else ts
    secrets = {"svc-accounts": "secret-accounts", "svc-admin": "secret-admin"}
    digest, sig = sign(
        secret=secrets[key],
        key_id=key,
        timestamp=ts,
        nonce=nonce,
        scope=scope,
        method=method,
        path=path,
        body=body,
    )
    h = {
        "X-ZT-Key-Id": key,
        "X-ZT-Timestamp": str(ts),
        "X-ZT-Nonce": nonce,
        "X-ZT-Scope": scope,
        "X-ZT-Body-Sha256": digest,
        "X-ZT-Signature": sig,
    }
    return h, body


def test_valid_request_passes(verifier, clock):
    h, body = headers_for(verifier, clock)
    vr = verifier.verify(
        headers=h, body=body, method="POST", path="/v1/accounts", required_scope=ACCOUNTS
    )
    assert vr.principal.key_id == "svc-accounts"
    assert vr.credentials.scope == ACCOUNTS


def test_missing_header_is_distinguishable(verifier, clock):
    h, body = headers_for(verifier, clock)
    del h["X-ZT-Signature"]
    with pytest.raises(MissingCredentialError) as ei:
        verifier.verify(headers=h, body=body, method="POST", path="/v1/accounts", required_scope=ACCOUNTS)
    assert ei.value.code == "missing_credential"
    assert "x-zt-signature" in ei.value.details["missing"]


def test_bad_timestamp_format(verifier, clock):
    h, body = headers_for(verifier, clock)
    h["X-ZT-Timestamp"] = "not-a-number"
    with pytest.raises(MissingCredentialError):
        verifier.verify(headers=h, body=body, method="POST", path="/v1/accounts", required_scope=ACCOUNTS)


def test_unknown_principal(verifier, clock):
    h, body = headers_for(verifier, clock)
    h["X-ZT-Key-Id"] = "svc-ghost"
    with pytest.raises(UnknownPrincipalError) as ei:
        verifier.verify(headers=h, body=body, method="POST", path="/v1/accounts", required_scope=ACCOUNTS)
    assert ei.value.code == "unknown_principal"


def test_scope_not_granted_to_principal(verifier, clock):
    # svc-accounts 只被授予 accounts:write，却声明 transfers:write
    h, body = headers_for(verifier, clock, key="svc-accounts", scope=TRANSFERS)
    with pytest.raises(ScopeDeniedError) as ei:
        verifier.verify(headers=h, body=body, method="POST", path="/v1/accounts", required_scope=TRANSFERS)
    assert ei.value.code == "scope_denied"


def test_scope_does_not_cover_route(verifier, clock):
    # 主体持有该域（scope_denied 不触发），但路由要求另一个域
    h, body = headers_for(
        verifier, clock, key="svc-admin", scope=ACCOUNTS, path="/v1/transfers"
    )
    with pytest.raises(ScopeInsufficientError) as ei:
        verifier.verify(headers=h, body=body, method="POST", path="/v1/transfers", required_scope=TRANSFERS)
    assert ei.value.code == "scope_insufficient"
    assert ei.value.details == {"declared": ACCOUNTS, "required": TRANSFERS}


@pytest.mark.parametrize(
    "delta,expected",
    [
        (-300, "ok"),       # 下界（含边界）
        (-301, "expired"),  # 越界 1 秒
        (30, "ok"),         # 上界（含边界）
        (31, "future"),     # 越界 1 秒
        (0, "ok"),
    ],
)
def test_timestamp_window_boundaries(verifier, clock, delta, expected):
    now = int(clock.now_unix())
    h, body = headers_for(verifier, clock, ts=now + delta)
    if expected == "ok":
        verifier.verify(headers=h, body=body, method="POST", path="/v1/accounts", required_scope=ACCOUNTS)
    elif expected == "expired":
        with pytest.raises(TimestampExpiredError) as ei:
            verifier.verify(headers=h, body=body, method="POST", path="/v1/accounts", required_scope=ACCOUNTS)
        assert ei.value.code == "timestamp_expired"
    else:
        with pytest.raises(TimestampFutureError) as ei:
            verifier.verify(headers=h, body=body, method="POST", path="/v1/accounts", required_scope=ACCOUNTS)
        assert ei.value.code == "timestamp_in_future"


def test_body_tampered_detected_before_signature(verifier, clock):
    h, _ = headers_for(verifier, clock)
    tampered = b'{"name":"mallory"}'
    with pytest.raises(BodyTamperedError) as ei:
        verifier.verify(headers=h, body=tampered, method="POST", path="/v1/accounts", required_scope=ACCOUNTS)
    assert ei.value.code == "body_tampered"


def test_signature_mismatch_when_header_tampered(verifier, clock):
    h, body = headers_for(verifier, clock)
    h["X-ZT-Nonce"] = "forged-nonce"  # 改了被签名的内容，签名失效
    with pytest.raises(SignatureMismatchError) as ei:
        verifier.verify(headers=h, body=body, method="POST", path="/v1/accounts", required_scope=ACCOUNTS)
    assert ei.value.code == "signature_mismatch"


def test_signature_recomputed_with_wrong_secret_fails(verifier, clock):
    h, body = headers_for(verifier, clock)
    h["X-ZT-Signature"] = "0" * 64
    with pytest.raises(SignatureMismatchError):
        verifier.verify(headers=h, body=body, method="POST", path="/v1/accounts", required_scope=ACCOUNTS)
