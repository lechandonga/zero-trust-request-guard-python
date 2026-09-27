"""幂等存储与守卫：重放、并发重复可区分；同签名请求恰好生效一次。"""
from __future__ import annotations

import threading

import pytest

from app.errors import (
    ConcurrentDuplicateError,
    ReplayDetectedError,
    DownstreamError,
)
from app.guard import TrustGuard
from app.replay import ReplayStore
from app.security import Principal, PrincipalStore, RequestVerifier

from .conftest import ACCOUNTS


def make_guard(clock, handler):
    store = PrincipalStore(
        {"svc-accounts": Principal("svc-accounts", "secret-accounts", frozenset({ACCOUNTS}))}
    )
    verifier = RequestVerifier(store, clock=clock)
    guard = TrustGuard(verifier, ReplayStore(clock=lambda: clock.now_unix()))
    return guard


def signed_headers(clock, *, nonce="n1", ts_delta=0):
    from app.security import sign

    ts = int(clock.now_unix()) + ts_delta
    body = b'{"k":1}'
    digest, sig = sign(
        secret="secret-accounts",
        key_id="svc-accounts",
        timestamp=ts,
        nonce=nonce,
        scope=ACCOUNTS,
        method="POST",
        path="/v1/accounts",
        body=body,
    )
    h = {
        "X-ZT-Key-Id": "svc-accounts",
        "X-ZT-Timestamp": str(ts),
        "X-ZT-Nonce": nonce,
        "X-ZT-Scope": ACCOUNTS,
        "X-ZT-Body-Sha256": digest,
        "X-ZT-Signature": sig,
    }
    return h, body


def test_store_states(clock):
    s = ReplayStore(clock=lambda: clock.now_unix())
    k = ("svc-accounts", "sig")
    s.begin(k)
    with pytest.raises(ConcurrentDuplicateError):
        s.begin(k)
    s.complete(k, {"v": 1})
    with pytest.raises(ReplayDetectedError):
        s.begin(k)
    assert s.get_completed_result(k) == {"v": 1}


def test_store_fail_clears_placeholder(clock):
    s = ReplayStore(clock=lambda: clock.now_unix())
    k = ("p", "sig")
    s.begin(k)
    s.fail(k)
    s.begin(k)  # 不抛错：允许同签名重试
    s.complete(k, {"v": 2})


def test_store_ttl_expiry(clock):
    s = ReplayStore(ttl_seconds=600, clock=lambda: clock.now_unix())
    k = ("p", "sig")
    s.begin(k)
    s.complete(k, {"v": 1})
    clock.t += 601
    assert s.purge_expired() == 1
    s.begin(k)  # 已过期 -> 视为新请求


def test_guard_replay_vs_concurrent_distinguishable(clock):
    counter = {"n": 0}

    def handler(vr):
        counter["n"] += 1
        return {"n": counter["n"]}

    guard = make_guard(clock, handler)
    h, body = signed_headers(clock)

    r1 = guard.execute(
        headers=h, body=body, method="POST", path="/v1/accounts",
        required_scope=ACCOUNTS, handler=handler,
    )
    assert r1 == {"n": 1}

    # 重放（已完成后重复提交）
    with pytest.raises(ReplayDetectedError) as ei:
        guard.execute(
            headers=h, body=body, method="POST", path="/v1/accounts",
            required_scope=ACCOUNTS, handler=handler,
        )
    assert ei.value.code == "idempotency_replay"
    assert counter["n"] == 1  # 业务没有第二次执行


def test_guard_concurrent_duplicates_execute_once(clock):
    entered = threading.Event()
    release = threading.Event()
    counter = {"n": 0}

    def slow_handler(vr):
        counter["n"] += 1
        entered.set()
        release.wait(timeout=5)
        return {"ok": True}

    guard = make_guard(clock, slow_handler)
    h, body = signed_headers(clock)
    results: list[Exception | dict] = []

    def run():
        try:
            r = guard.execute(
                headers=h, body=body, method="POST", path="/v1/accounts",
                required_scope=ACCOUNTS, handler=slow_handler,
            )
            results.append(r)
        except Exception as exc:  # noqa: BLE001 - 收集到结果列表
            results.append(exc)

    threads = [threading.Thread(target=run) for _ in range(5)]
    for t in threads:
        t.start()
    assert entered.wait(2), "handler 未被执行"
    # 首个正在处理时，其余 4 个并发重复必须立即被识别
    # 等待其它线程结束（它们应拿到 concurrent_duplicate）
    for t in threads[1:]:
        t.join(timeout=2)
    release.set()
    threads[0].join(timeout=2)

    assert counter["n"] == 1, "同一签名请求被执行了多次"
    oks = [r for r in results if isinstance(r, dict)]
    dups = [r for r in results if isinstance(r, ConcurrentDuplicateError)]
    assert len(oks) == 1
    assert len(dups) == 4
    assert all(r.code == "concurrent_duplicate" for r in dups)


def test_guard_failure_clears_idempotency_allowing_retry(clock):
    attempts = {"n": 0}

    def flaky(vr):
        attempts["n"] += 1
        raise DownstreamError()

    def ok(vr):
        attempts["n"] += 1
        return {"recovered": True}

    guard = make_guard(clock, flaky)
    h, body = signed_headers(clock)
    for _ in range(2):
        with pytest.raises(DownstreamError):
            guard.execute(
                headers=h, body=body, method="POST", path="/v1/accounts",
                required_scope=ACCOUNTS, handler=flaky,
            )
    # 失败后占位被清除：相同签名换成功 handler 可再次执行
    r = guard.execute(
        headers=h, body=body, method="POST", path="/v1/accounts",
        required_scope=ACCOUNTS, handler=ok,
    )
    assert r == {"recovered": True}
    assert attempts["n"] == 3
