"""信任边界测试：篡改、过期、超前、越权、未知来源、缺头、窗口边界。"""

from __future__ import annotations

import logging

from tests.conftest import (
    CLIENT_ID,
    CLIENT_SECRET,
    FIXED_NOW,
    READER_ID,
    READER_SECRET,
    json_body,
    make_headers,
)

TRANSFER = {"from_account": "a", "to_account": "b", "amount": 10}


def _setup_accounts(client) -> None:
    for aid, bal in (("a", 100), ("b", 0)):
        body = json_body({"account_id": aid, "balance": bal})
        r = client.post(
            "/accounts",
            content=body,
            headers=make_headers(method="POST", path="/accounts", body=body),
        )
        assert r.status_code == 201, r.text


def test_valid_request_accepted(client, fixed_clock, caplog):
    _setup_accounts(client)
    body = json_body(TRANSFER)
    with caplog.at_level(logging.INFO, logger="app.guard"):
        r = client.post(
            "/transfers",
            content=body,
            headers=make_headers(method="POST", path="/transfers", body=body),
        )
    assert r.status_code == 200, r.text
    assert r.json()["from_balance"] == 90
    # 日志包含请求特征与判定依据
    assert any("信任判定通过" in m and CLIENT_ID in m and "/transfers" in m for m in caplog.messages)


def test_tampered_signature_rejected(client, fixed_clock, caplog):
    body = json_body(TRANSFER)
    headers = make_headers(method="POST", path="/transfers", body=body)
    headers["X-Signature"] = "0" * 64  # 伪造签名
    with caplog.at_level(logging.INFO, logger="app.guard"):
        r = client.post("/transfers", content=body, headers=headers)
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "signature_invalid"
    assert any("信任判定拒绝" in m and "signature_invalid" in m for m in caplog.messages)


def test_tampered_body_rejected(client, fixed_clock):
    body = json_body(TRANSFER)
    headers = make_headers(method="POST", path="/transfers", body=body)
    tampered = json_body({**TRANSFER, "amount": 99999})  # 签名后篡改内容
    r = client.post("/transfers", content=tampered, headers=headers)
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "signature_invalid"


def test_expired_timestamp_rejected(client, fixed_clock):
    body = json_body(TRANSFER)
    headers = make_headers(
        method="POST", path="/transfers", body=body, timestamp=FIXED_NOW - 301
    )
    r = client.post("/transfers", content=body, headers=headers)
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "timestamp_skewed"
    assert "过期" in r.json()["error"]["message"]


def test_future_timestamp_rejected(client, fixed_clock):
    body = json_body(TRANSFER)
    headers = make_headers(
        method="POST", path="/transfers", body=body, timestamp=FIXED_NOW + 301
    )
    r = client.post("/transfers", content=body, headers=headers)
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "timestamp_skewed"
    assert "超前" in r.json()["error"]["message"]


def test_timestamp_window_boundary_inclusive(client, fixed_clock):
    """窗口边界（恰好 ±300s）必须确定性地被接受。"""
    for i, ts in enumerate((FIXED_NOW - 300, FIXED_NOW + 300)):
        body = json_body({"account_id": f"edge-{i}", "balance": 1})
        r = client.post(
            "/accounts",
            content=body,
            headers=make_headers(method="POST", path="/accounts", body=body, timestamp=ts),
        )
        assert r.status_code == 201, r.text


def test_unknown_client_rejected(client, fixed_clock):
    body = json_body(TRANSFER)
    headers = make_headers(
        client_id="ghost", secret="x", method="POST", path="/transfers", body=body
    )
    r = client.post("/transfers", content=body, headers=headers)
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "unknown_client"


def test_missing_headers_rejected(client, fixed_clock):
    r = client.post("/transfers", json=TRANSFER)
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "missing_credentials"


def test_insufficient_scope_rejected(client, fixed_clock, caplog):
    """已注册、签名有效，但没有 transfers:write 作用域 → 403。"""
    body = json_body(TRANSFER)
    headers = make_headers(
        client_id=READER_ID,
        secret=READER_SECRET,
        method="POST",
        path="/transfers",
        body=body,
    )
    with caplog.at_level(logging.INFO, logger="app.guard"):
        r = client.post("/transfers", content=body, headers=headers)
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "scope_insufficient"
    assert any("scope_insufficient" in m for m in caplog.messages)
