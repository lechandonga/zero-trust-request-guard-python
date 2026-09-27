"""HTTP 路由：所有改动状态的接口统一经过 TrustGuard。

写接口（POST /v1/accounts、POST /v1/transfers）必须携带完整的
零信任头部并通过同一套信任判定；GET 只读接口不需要签名。
"""
from __future__ import annotations

import json
import asyncio
import functools

from fastapi import APIRouter, Request

from .errors import InvalidRequestError
from .guard import TrustGuard
from .security import VerifiedRequest
from .services import AccountingService

SCOPE_ACCOUNTS = "accounts:write"
SCOPE_TRANSFERS = "transfers:write"


def _json_body(raw: bytes) -> dict:
    try:
        data = json.loads(raw.decode("utf-8") or "{}")
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InvalidRequestError("body must be valid JSON") from exc
    if not isinstance(data, dict):
        raise InvalidRequestError("body must be a JSON object")
    return data


def build_router(guard: TrustGuard, accounts: AccountingService) -> APIRouter:
    """组装带统一信任守卫的写接口与只读接口。

    每次调用都新建 router，避免在模块级单例上重复注册路由闭包
    （否则后建 app 的请求会命中先注册 app 捕获的旧业务对象）。
    """
    router = APIRouter(prefix="/v1")

    async def _guarded(
        request: Request,
        *,
        required_scope: str,
        act,
    ):
        raw = await request.body()
        headers = {k.decode(): v.decode() for k, v in request.headers.raw}
        loop = asyncio.get_running_loop()
        # 阻塞式守卫放到线程执行：并发请求在真实线程上争用同一把幂等锁
        return await loop.run_in_executor(
            None,
            functools.partial(
                guard.execute,
                headers=headers,
                body=raw,
                method=request.method,
                path=request.url.path,  # query 不参与签名
                required_scope=required_scope,
                handler=act,
            ),
        )

    @router.post("/accounts", status_code=201)
    async def create_account(request: Request):
        def act(vr: VerifiedRequest):
            data = _json_body(vr.body)
            name = data.get("name")
            balance = int(data.get("opening_balance", 0))
            if not isinstance(name, str) or not name:
                raise InvalidRequestError("name is required")
            return accounts.create_account(name, balance)

        return await _guarded(request, required_scope=SCOPE_ACCOUNTS, act=act)

    @router.post("/transfers", status_code=201)
    async def create_transfer(request: Request):
        def act(vr: VerifiedRequest):
            data = _json_body(vr.body)
            return accounts.transfer(
                from_name=data["from"],
                to_name=data["to"],
                amount=int(data["amount"]),
                reference=str(data.get("reference", "")),
            )

        return await _guarded(request, required_scope=SCOPE_TRANSFERS, act=act)

    @router.get("/accounts")
    async def list_accounts():
        """只读接口：便于测试断言副作用，无需签名。"""
        return {"accounts": accounts.snapshot()}

    return router
