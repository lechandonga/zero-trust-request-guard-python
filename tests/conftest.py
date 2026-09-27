"""测试夹具：签名助手、可控时钟、可脚本化/可阻塞的下游。"""
from __future__ import annotations

import json
import logging
import threading
import time

import pytest
from fastapi.testclient import TestClient

from app.app import create_app
from app.security import Principal, PrincipalStore, RequestVerifier, sign
from app.services import AccountingService, FlakyDownstream

# 让单测日志打印请求特征与判定依据
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)

ACCOUNTS = "accounts:write"
TRANSFERS = "transfers:write"

PRINCIPALS = {
    "svc-accounts": ("secret-accounts", frozenset({ACCOUNTS})),
    "svc-transfers": ("secret-transfers", frozenset({TRANSFERS})),
    "svc-admin": ("secret-admin", frozenset({ACCOUNTS, TRANSFERS})),
}


class MutableClock:
    def __init__(self, t: float | None = None):
        self.t = time.time() if t is None else t

    def now_unix(self) -> float:
        return self.t


def make_headers(
    key_id: str,
    scope: str,
    method: str,
    path: str,
    body: bytes,
    *,
    timestamp: int | None = None,
    nonce: str = "nonce-1",
    secret: str | None = None,
    clock: MutableClock | None = None,
) -> dict[str, str]:
    secret = secret or PRINCIPALS[key_id][0]
    base = clock.now_unix() if clock is not None else time.time()
    ts = int(base) if timestamp is None else timestamp
    digest, signature = sign(
        secret=secret,
        key_id=key_id,
        timestamp=ts,
        nonce=nonce,
        scope=scope,
        method=method,
        path=path,
        body=body,
    )
    return {
        "X-ZT-Key-Id": key_id,
        "X-ZT-Timestamp": str(ts),
        "X-ZT-Nonce": nonce,
        "X-ZT-Scope": scope,
        "X-ZT-Body-Sha256": digest,
        "X-ZT-Signature": signature,
    }


class ScriptedDownstream(FlakyDownstream):
    """带调用计数与可阻塞闸门的下游。"""

    def __init__(self, scripted=None):
        super().__init__(scripted)
        self.entered = threading.Event()
        self.release = threading.Event()
        self.block_first = False

    def invoke(self, action: str, payload: dict) -> dict:
        if self.block_first:
            with self._lock:
                first = self._calls == 1
            if first:
                self.entered.set()
                self.release.wait(timeout=5)
        return super().invoke(action, payload)


@pytest.fixture
def clock():
    return MutableClock()


@pytest.fixture
def downstream():
    return ScriptedDownstream()


@pytest.fixture
def app_factory(clock, downstream):
    def _factory(downstream_script=None, ds=None, replay_ttl=600.0):
        actual_ds = ds or downstream
        svc = AccountingService(actual_ds)
        if downstream_script is not None:
            actual_ds._scripted = downstream_script
        store = PrincipalStore(
            {
                kid: Principal(kid, secret, scopes)
                for kid, (secret, scopes) in PRINCIPALS.items()
            }
        )
        verifier = RequestVerifier(store, clock=clock)
        return create_app(verifier=verifier, accounting=svc, replay_ttl=replay_ttl), svc, actual_ds

    return _factory


@pytest.fixture
def env(app_factory):
    app, svc, ds = app_factory()
    # 不在测试进程里重新抛出服务端异常，使其走到 500 错误映射（生产 ASGI 同此路径）
    with TestClient(app, raise_server_exceptions=False) as client:
        yield client, svc, ds


def jbody(obj: dict) -> bytes:
    return json.dumps(obj, separators=(",", ":")).encode()
