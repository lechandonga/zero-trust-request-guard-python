"""失败映射测试：业务错误 vs 系统错误可区分；失败不留半截副作用；内部细节不透出。"""

from __future__ import annotations

import logging

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


def test_business_error_maps_to_422_and_no_side_effect(client, fixed_clock):
    _setup_accounts(client)
    body = json_body({**TRANSFER, "amount": 99999})  # 余额不足
    r = client.post(
        "/transfers",
        content=body,
        headers=make_headers(method="POST", path="/transfers", body=body),
    )
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "business_rule_violation"
    assert "余额不足" in r.json()["error"]["message"]
    # 无任何副作用
    assert _balance(client, "a") == 100
    assert _balance(client, "b") == 0


def test_business_error_replay_is_recognized(client, fixed_clock):
    """业务错误属于'已完成的处理'：同一请求重放应被识别为 replay。"""
    _setup_accounts(client)
    body = json_body({**TRANSFER, "amount": 99999})
    headers = make_headers(method="POST", path="/transfers", body=body)
    r1 = client.post("/transfers", content=body, headers=headers)
    assert r1.status_code == 422
    r2 = client.post("/transfers", content=body, headers=headers)
    assert r2.status_code == 409
    assert r2.json()["error"]["code"] == "replay_detected"


def test_downstream_failure_maps_to_500_without_leaking_internals(fixed_clock, caplog):
    def boom(from_id: str, to_id: str, amount: int) -> None:
        raise RuntimeError("ledger-service connection refused at 10.0.0.7:9001")

    client = TestClient(create_app(downstream=boom), raise_server_exceptions=False)
    _setup_accounts(client)

    body = json_body(TRANSFER)
    headers = make_headers(method="POST", path="/transfers", body=body)
    with caplog.at_level(logging.ERROR, logger="app.main"):
        r = client.post("/transfers", content=body, headers=headers)

    assert r.status_code == 500
    err = r.json()["error"]
    assert err["code"] == "internal_error"
    # 内部细节与堆栈不透出
    assert "ledger-service" not in r.text
    assert "10.0.0.7" not in r.text
    assert "Traceback" not in r.text
    # 但服务端日志保留了内部细节
    assert any("内部处理失败" in m for m in caplog.messages)

    # 不留半截副作用
    assert _balance(client, "a") == 100
    assert _balance(client, "b") == 0


def test_retry_allowed_after_system_error(fixed_clock):
    """系统错误释放幂等占位：修正下游后，同一请求可成功重试。"""
    state = {"fail": True}

    def flaky(from_id: str, to_id: str, amount: int) -> None:
        if state["fail"]:
            raise RuntimeError("downstream down")

    client = TestClient(create_app(downstream=flaky), raise_server_exceptions=False)
    _setup_accounts(client)

    body = json_body(TRANSFER)
    headers = make_headers(method="POST", path="/transfers", body=body)
    r1 = client.post("/transfers", content=body, headers=headers)
    assert r1.status_code == 500

    state["fail"] = False
    r2 = client.post("/transfers", content=body, headers=headers)
    assert r2.status_code == 200, r2.text
    assert _balance(client, "a") == 90
    assert _balance(client, "b") == 10
