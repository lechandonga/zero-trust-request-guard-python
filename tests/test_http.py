"""端到端 HTTP 测试：信任边界拒绝原因可区分、副作用恰好一次、错误不透出堆栈。"""
from __future__ import annotations

import json
import logging
import threading
import time

import pytest

from .conftest import ACCOUNTS, TRANSFERS, make_headers, jbody


def _open_accounts(client, clock):
    """先建两个账户，供转账测试。"""
    for name in ("alice", "bob"):
        body = jbody({"name": name, "opening_balance": 100 if name == "alice" else 0})
        h = make_headers("svc-admin", ACCOUNTS, "POST", "/v1/accounts", body, nonce=f"init-{name}", clock=clock)
        r = client.post("/v1/accounts", content=body, headers=h)
        assert r.status_code == 201, r.text


def test_happy_path_account_create(env, clock):
    client, svc, _ = env
    body = jbody({"name": "alice", "opening_balance": 50})
    h = make_headers("svc-accounts", ACCOUNTS, "POST", "/v1/accounts", body, clock=clock)
    r = client.post("/v1/accounts", content=body, headers=h)
    assert r.status_code == 201
    assert r.json()["status"] == "opened"
    assert svc.snapshot() == {"alice": 50}


def test_missing_credential(env, clock):
    client, _, _ = env
    body = jbody({"name": "alice"})
    h = make_headers("svc-accounts", ACCOUNTS, "POST", "/v1/accounts", body, clock=clock)
    del h["X-ZT-Signature"]
    r = client.post("/v1/accounts", content=body, headers=h)
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "missing_credential"


def test_unknown_principal(env, clock):
    client, _, _ = env
    body = jbody({"name": "alice"})
    h = make_headers("svc-accounts", ACCOUNTS, "POST", "/v1/accounts", body, clock=clock)
    h["X-ZT-Key-Id"] = "svc-ghost"
    r = client.post("/v1/accounts", content=body, headers=h)
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "unknown_principal"


def test_signature_tampered_header(env, clock):
    client, svc, _ = env
    body = jbody({"name": "alice"})
    h = make_headers("svc-accounts", ACCOUNTS, "POST", "/v1/accounts", body, clock=clock)
    h["X-ZT-Nonce"] = "forged"  # 改了被签名内容 -> 签名不匹配
    r = client.post("/v1/accounts", content=body, headers=h)
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "signature_mismatch"
    assert svc.snapshot() == {}  # 未产生任何副作用


def test_body_tampered_after_signing(env, clock):
    client, svc, _ = env
    body = jbody({"name": "alice", "opening_balance": 10})
    h = make_headers("svc-accounts", ACCOUNTS, "POST", "/v1/accounts", body, clock=clock)
    evil = jbody({"name": "alice", "opening_balance": 99999})  # 重写 body
    r = client.post("/v1/accounts", content=evil, headers=h)
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "body_tampered"
    assert svc.snapshot() == {}


def test_timestamp_expired_and_future(env, clock):
    client, _, _ = env
    body = jbody({"name": "alice"})

    old = make_headers("svc-accounts", ACCOUNTS, "POST", "/v1/accounts", body, timestamp=int(clock.t) - 301, clock=clock)
    r = client.post("/v1/accounts", content=body, headers=old)
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "timestamp_expired"

    fut = make_headers("svc-accounts", ACCOUNTS, "POST", "/v1/accounts", body, timestamp=int(clock.t) + 31, clock=clock)
    r2 = client.post("/v1/accounts", content=body, headers=fut)
    assert r2.status_code == 401
    assert r2.json()["error"]["code"] == "timestamp_in_future"


def test_timestamp_boundary_accepted(env, clock):
    client, svc, _ = env
    for i, delta in enumerate((-300, 30)):
        body = jbody({"name": f"u{i}"})
        h = make_headers("svc-accounts", ACCOUNTS, "POST", "/v1/accounts", body, timestamp=int(clock.t) + delta, nonce=f"b{i}", clock=clock)
        r = client.post("/v1/accounts", content=body, headers=h)
        assert r.status_code == 201, (delta, r.text)
    assert set(svc.snapshot()) == {"u0", "u1"}


def test_scope_denied_principal_not_granted(env, clock):
    # svc-accounts 未被授予 transfers:write
    client, _, _ = env
    body = jbody({"from": "a", "to": "b", "amount": 1})
    h = make_headers("svc-accounts", TRANSFERS, "POST", "/v1/transfers", body, clock=clock)
    r = client.post("/v1/transfers", content=body, headers=h)
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "scope_denied"


def test_scope_insufficient_for_route(env, clock):
    # 持有 accounts:write，去调 transfers 路由
    client, _, _ = env
    body = jbody({"from": "a", "to": "b", "amount": 1})
    h = make_headers("svc-admin", ACCOUNTS, "POST", "/v1/transfers", body, clock=clock)
    r = client.post("/v1/transfers", content=body, headers=h)
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "scope_insufficient"


def test_replay_identical_signed_request_runs_once(env, clock):
    client, svc, ds = env
    _open_accounts(client, clock)
    body = jbody({"from": "alice", "to": "bob", "amount": 30, "reference": "R-1"})
    h = make_headers("svc-transfers", TRANSFERS, "POST", "/v1/transfers", body, nonce="r1", clock=clock)

    r1 = client.post("/v1/transfers", content=body, headers=h)
    assert r1.status_code == 201
    r2 = client.post("/v1/transfers", content=body, headers=h)
    assert r2.status_code == 409
    assert r2.json()["error"]["code"] == "idempotency_replay"

    # 钱只移动一次，下游只记一次账
    assert svc.snapshot() == {"alice": 70, "bob": 30}
    assert ds.call_count == 1


def test_concurrent_duplicates_exactly_once_http(env, clock):
    client, svc, ds = env
    _open_accounts(client, clock)
    body = jbody({"from": "alice", "to": "bob", "amount": 20, "reference": "R-C"})
    h = make_headers("svc-transfers", TRANSFERS, "POST", "/v1/transfers", body, nonce="rc", clock=clock)
    ds.block_first = True

    outcomes: list[str] = []
    lock = threading.Lock()

    def fire():
        r = client.post("/v1/transfers", content=body, headers=h)
        code = "ok" if r.status_code == 201 else r.json()["error"]["code"]
        with lock:
            outcomes.append(code)

    threads = [threading.Thread(target=fire) for _ in range(4)]
    for t in threads:
        t.start()

    # 等待唯一赢家真正进入下游（处理进行中），不预设是哪个线程
    assert ds.entered.wait(10), "赢家未进入下游"

    # 等待其余 3 个并发重复都被识别（赢家仍被闸门阻塞）
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        with lock:
            if outcomes.count("concurrent_duplicate") == 3:
                break
        time.sleep(0.01)
    with lock:
        assert outcomes.count("concurrent_duplicate") == 3, outcomes
        assert "ok" not in outcomes  # 赢家还没被放行

    # 放行赢家并收尾
    ds.release.set()
    for t in threads:
        t.join(timeout=10)

    assert sorted(outcomes) == sorted(
        ["ok", "concurrent_duplicate", "concurrent_duplicate", "concurrent_duplicate"]
    ), outcomes
    assert svc.snapshot() == {"alice": 80, "bob": 20}  # 钱只动一次
    assert ds.call_count == 1  # 下游只记账一次


def test_business_error_insufficient_funds_is_distinguishable(env, clock):
    client, svc, _ = env
    _open_accounts(client, clock)
    body = jbody({"from": "alice", "to": "bob", "amount": 10_000, "reference": "R-X"})
    h = make_headers("svc-transfers", TRANSFERS, "POST", "/v1/transfers", body, nonce="rx", clock=clock)
    r = client.post("/v1/transfers", content=body, headers=h)
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "insufficient_funds"
    assert svc.snapshot() == {"alice": 100, "bob": 0}  # 余额未变


def test_downstream_failure_rolls_back_and_is_retryable(app_factory, clock):
    from fastapi.testclient import TestClient

    def boom(action, payload):
        raise OSError("connection reset by peer: " + "X" * 80)

    app2, svc2, ds2 = app_factory(downstream_script=boom)

    with TestClient(app2, raise_server_exceptions=False) as c2:
        for name in ("alice", "bob"):
            b = jbody({"name": name, "opening_balance": 100 if name == "alice" else 0})
            hh = make_headers("svc-admin", ACCOUNTS, "POST", "/v1/accounts", b, nonce=f"i-{name}", clock=clock)
            assert c2.post("/v1/accounts", content=b, headers=hh).status_code == 201

        body = jbody({"from": "alice", "to": "bob", "amount": 40, "reference": "R-D"})
        h = make_headers("svc-transfers", TRANSFERS, "POST", "/v1/transfers", body, nonce="rd", clock=clock)
        r = c2.post("/v1/transfers", content=body, headers=h)
        assert r.status_code == 502
        data = r.json()
        assert data["error"]["code"] == "downstream_unavailable"
        assert "connection reset" not in r.text  # 内部异常不透出
        assert svc2.snapshot() == {"alice": 100, "bob": 0}  # 回滚干净

        # 恢复下游后，相同签名允许重试且成功
        ds2._scripted = None
        r2 = c2.post("/v1/transfers", content=body, headers=h)
        assert r2.status_code == 201, r2.text
        assert svc2.snapshot() == {"alice": 60, "bob": 40}


def test_unknown_exception_maps_to_internal_error_without_leak(monkeypatch, env, clock):
    client, svc, _ = env

    # 让业务处理抛出非 AppError 的未知异常
    from app.routes import build_router as original_build  # noqa: F401
    import app.services as services_mod

    def boom(self, *a, **k):
        raise RuntimeError("super secret internal detail / stacktrace marker")

    monkeypatch.setattr(services_mod.AccountingService, "create_account", boom)
    body = jbody({"name": "alice"})
    h = make_headers("svc-accounts", ACCOUNTS, "POST", "/v1/accounts", body, clock=clock)
    r = client.post("/v1/accounts", content=body, headers=h)
    assert r.status_code == 500
    assert r.json() == {"error": {"code": "internal_error", "message": "internal server error"}}
    assert "secret internal detail" not in r.text
    assert "Traceback" not in r.text


def test_guard_logs_feature_and_decision_reason(env, caplog, clock):
    client, _, _ = env
    body = jbody({"name": "alice"})
    with caplog.at_level(logging.INFO, logger="zero_trust.guard"):
        # 成功
        h = make_headers("svc-accounts", ACCOUNTS, "POST", "/v1/accounts", body, nonce="log1", clock=clock)
        client.post("/v1/accounts", content=body, headers=h)
        # 拒绝（签名被改）
        h2 = make_headers("svc-accounts", ACCOUNTS, "POST", "/v1/accounts", body, nonce="log2", clock=clock)
        h2["X-ZT-Nonce"] = "x"
        client.post("/v1/accounts", content=body, headers=h2)

    text = caplog.text
    assert "decision=ALLOW" in text
    assert "reason=signature_mismatch" in text
    assert "key_id=svc-accounts" in text
    assert "nonce=log1" in text
    assert "sig=" in text  # 判定行的签名指纹
    assert "'signature':" in text  # 请求特征 dict 含签名
    assert "'body_sha256':" in text  # 请求特征含内容摘要
