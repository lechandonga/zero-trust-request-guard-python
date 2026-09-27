"""FastAPI 装配：统一信任判定 + 统一错误映射。

错误映射（调用方可据 code 区分处理）：
- 401 missing_credentials / unknown_client / signature_invalid / timestamp_skewed
- 403 scope_insufficient
- 409 replay_detected / concurrent_duplicate
- 422 business_rule_violation
- 500 internal_error（内部异常细节只进服务端日志，不透出）
"""

from __future__ import annotations

import logging
from collections.abc import Callable

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app.credentials import (
    SCOPE_ACCOUNTS_WRITE,
    SCOPE_TRANSFERS_WRITE,
    default_registry,
)
from app.domain import AccountStore
from app.errors import BusinessError, ErrorBody, ErrorCode, GuardError
from app.guard import RequestGuard, TrustedRequest
from app.idempotency import IdempotencyStore

logger = logging.getLogger("app.main")

GUARD_ERROR_STATUS: dict[ErrorCode, int] = {
    ErrorCode.MISSING_CREDENTIALS: 401,
    ErrorCode.UNKNOWN_CLIENT: 401,
    ErrorCode.SIGNATURE_INVALID: 401,
    ErrorCode.TIMESTAMP_SKEWED: 401,
    ErrorCode.SCOPE_INSUFFICIENT: 403,
    ErrorCode.REPLAY_DETECTED: 409,
    ErrorCode.CONCURRENT_DUPLICATE: 409,
}


class CreateAccountIn(BaseModel):
    account_id: str = Field(min_length=1)
    balance: int = Field(ge=0)


class TransferIn(BaseModel):
    from_account: str = Field(min_length=1)
    to_account: str = Field(min_length=1)
    amount: int = Field(gt=0)


def create_app(
    *,
    guard: RequestGuard | None = None,
    accounts: AccountStore | None = None,
    downstream: Callable[[str, str, int], None] | None = None,
) -> FastAPI:
    app = FastAPI(title="zero-trust-request-guard")
    app.state.guard = guard or RequestGuard(default_registry(), IdempotencyStore())
    app.state.accounts = accounts or AccountStore()
    app.state.downstream = downstream

    def error_response(status: int, code: ErrorCode, message: str, request_id: str | None) -> JSONResponse:
        return JSONResponse(
            status_code=status,
            content=ErrorBody(code=code, message=message, request_id=request_id).to_dict(),
        )

    async def run_guarded(
        request: Request,
        required_scope: str,
        handler: Callable[[], tuple[int, dict]],
    ) -> JSONResponse:
        """统一管线：信任判定 → 幂等占位 → 执行业务 → 记录/释放占位。"""
        guard: RequestGuard = request.app.state.guard
        body = await request.body()
        trusted: TrustedRequest | None = None
        try:
            trusted = guard.authenticate(
                method=request.method,
                path=request.url.path,
                headers=request.headers,
                body=body,
                required_scope=required_scope,
            )
            guard.begin(trusted)
        except GuardError as e:
            rid = trusted.request_id if trusted else None
            return error_response(GUARD_ERROR_STATUS[e.code], e.code, e.message, rid)

        try:
            status, payload = handler()
        except BusinessError as e:
            # 业务错误：属于"已完成的处理"，记录结果使重放被识别为 replay
            payload = ErrorBody(
                code=ErrorCode.BUSINESS_RULE_VIOLATION,
                message=e.message,
                request_id=trusted.request_id,
            ).to_dict()
            guard.complete(trusted, status_code=422, body=payload)
            return JSONResponse(status_code=422, content=payload)
        except Exception:
            # 系统错误：释放占位允许重试；细节只进日志，响应不透出
            guard.abort(trusted)
            logger.exception("内部处理失败 | request_id=%s", trusted.request_id)
            return error_response(
                500, ErrorCode.INTERNAL_ERROR, "内部错误，请稍后重试", trusted.request_id
            )

        guard.complete(trusted, status_code=status, body=payload)
        return JSONResponse(status_code=status, content=payload)

    @app.get("/")
    def read_root() -> dict:
        return {"Hello": "World"}

    @app.get("/accounts/{account_id}")
    def get_account(account_id: str) -> JSONResponse:
        account = app.state.accounts.get(account_id)
        if account is None:
            return error_response(404, ErrorCode.BUSINESS_RULE_VIOLATION, f"账户不存在: {account_id}", None)
        return JSONResponse(
            status_code=200,
            content={"account_id": account.account_id, "balance": account.balance},
        )

    @app.post("/accounts")
    async def create_account(request: Request, payload: CreateAccountIn) -> JSONResponse:
        def handler() -> tuple[int, dict]:
            account = request.app.state.accounts.create(payload.account_id, payload.balance)
            return 201, {"account_id": account.account_id, "balance": account.balance}

        return await run_guarded(request, SCOPE_ACCOUNTS_WRITE, handler)

    @app.post("/transfers")
    async def transfer(request: Request, payload: TransferIn) -> JSONResponse:
        def handler() -> tuple[int, dict]:
            result = request.app.state.accounts.transfer(
                from_id=payload.from_account,
                to_id=payload.to_account,
                amount=payload.amount,
                downstream=request.app.state.downstream,
            )
            return 200, result

        return await run_guarded(request, SCOPE_TRANSFERS_WRITE, handler)

    return app


app = create_app()
