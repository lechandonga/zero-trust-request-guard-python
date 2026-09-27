"""幂等与重放防护测试：重复提交、并发重复提交，副作用只发生一次。"""

from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor

from app.main import create_app
from fastapi.testclient import TestClient

from tests.conftest import json_body, make_headers

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


def _balance(client, aid: str) -> int:
    return client.get(f"/accounts/{aid}").json()["balance"]


def test_replay_rejected_and_side_effect_once(client, fixed_clock, caplog):
    _setup_accounts(client)
    body = json_body(TRANSFER)
    headers = make_headers(method="POST", path="/transfers", body=body)

    r1 = client.post("/transfers", content=body, headers=headers)
    assert r1.status_code == 200, r1.text

    with caplog.at_level(logging.INFO, logger="app.guard"):
        r2 = client.post("/transfers", content=body, headers=headers)  # 原样重放
    assert r2.status_code == 409
    assert r2.json()["error"]["code"] == "replay_detected"

    # 副作用只发生一次
    assert _balance(client, "a") == 90
    assert _balance(client, "b") == 10
    assert any("replay_detected" in m for m in caplog.messages)


def test_concurrent_duplicate_executes_exactly_once(fixed_clock, caplog):
    """并发提交同一签名请求：恰好一个成功，其余被识别为并发重复。"""
    def slow_downstream(from_id: str, to_id: str, amount: int) -> None:
        # 让首个请求在处理中停留，制造确定性的并发重叠窗口
        time.sleep(0.3)

    client = TestClient(create_app(downstream=slow_downstream))
    _setup_accounts(client)

    body = json_body(TRANSFER)
    headers = make_headers(method="POST", path="/transfers", body=body)

    def submit():
        return client.post("/transfers", content=body, headers=headers)

    with caplog.at_level(logging.INFO, logger="app.guard"):
        with ThreadPoolExecutor(max_workers=8) as pool:
            responses = list(pool.map(lambda _: submit(), range(8)))

    codes = [r.status_code for r in responses]
    assert codes.count(200) == 1, f"应恰好成功一次，实际: {codes}"
    duplicates = [r for r in responses if r.status_code == 409]
    assert len(duplicates) == 7, f"其余 7 个应被拒绝，实际: {codes}"
    for r in duplicates:
        assert r.json()["error"]["code"] == "concurrent_duplicate"

    # 并发下副作用只发生一次
    assert _balance(client, "a") == 90
    assert _balance(client, "b") == 10
    assert any("concurrent_duplicate" in m for m in caplog.messages)


def test_same_signature_is_the_dedup_key(client, fixed_clock):
    """内容不同 → 签名不同 → 视为不同请求，不会被误判为重放。"""
    _setup_accounts(client)
    for amount in (10, 20):
        body = json_body({**TRANSFER, "amount": amount})
        r = client.post(
            "/transfers",
            content=body,
            headers=make_headers(method="POST", path="/transfers", body=body),
        )
        assert r.status_code == 200, r.text
    assert _balance(client, "a") == 70
