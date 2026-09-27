"""测试公共夹具：固定时钟、签名助手、独立应用实例。"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from app import clock
from app.main import create_app
from app.security import sign

FIXED_NOW = 1_700_000_000  # 固定的"当前时间"，保证时间窗口行为确定

CLIENT_ID = "payments-service"
CLIENT_SECRET = "dev-secret-payments"
READER_ID = "ledger-reader"       # 已注册但无任何写作用域
READER_SECRET = "dev-secret-ledger"


@pytest.fixture()
def fixed_clock():
    clock.set_clock(lambda: float(FIXED_NOW))
    yield FIXED_NOW
    clock.reset_clock()


@pytest.fixture()
def client():
    """每个测试独立的应用实例（独立的注册表/幂等存储/账户存储）。"""
    return TestClient(create_app())


def make_headers(
    *,
    client_id: str = CLIENT_ID,
    secret: str = CLIENT_SECRET,
    method: str,
    path: str,
    body: bytes,
    timestamp: int = FIXED_NOW,
    signature: str | None = None,
) -> dict[str, str]:
    """构造合法（或按需篡改）的签名请求头。"""
    sig = signature or sign(
        secret=secret,
        client_id=client_id,
        timestamp=timestamp,
        method=method,
        path=path,
        body=body,
    )
    return {
        "X-Client-Id": client_id,
        "X-Timestamp": str(timestamp),
        "X-Signature": sig,
        "Content-Type": "application/json",
    }


def json_body(payload: dict) -> bytes:
    return json.dumps(payload).encode()
