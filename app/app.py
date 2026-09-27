"""应用装配与统一错误映射。

对外错误信封统一为::

    {"error": {"code": <稳定错误码>, "message": <安全描述>, "details": {...}}}

- TrustError -> 401/403/409，每种拒绝原因有独立 code；
- BusinessError -> 4xx，业务错误可区分；
- DownstreamError -> 502；
- 其余未知异常 -> 500 internal_error，堆栈只进服务端日志。
"""
from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .errors import AppError, DownstreamError
from .guard import TrustGuard
from .replay import ReplayStore
from .routes import SCOPE_ACCOUNTS, SCOPE_TRANSFERS, build_router
from .security import Principal, PrincipalStore, RequestVerifier, SystemClock
from .services import AccountingService, FlakyDownstream

logger = logging.getLogger("zero_trust")


def error_body(code: str, message: str, *, details: dict | None = None) -> dict:
    """统一对外错误信封；不包含堆栈/内部信息。"""
    body: dict = {"code": code, "message": message}
    if details:
        body["details"] = details
    return {"error": body}


def create_app(
    *,
    principals: dict[str, Principal] | None = None,
    downstream_script=None,
    replay_ttl: float = 600.0,
    verifier: RequestVerifier | None = None,
    accounting: AccountingService | None = None,
) -> FastAPI:
    """构建应用（默认装配一套演示主体与健康账本）。"""
    if principals is None:
        principals = {
            "svc-accounts": Principal(
                "svc-accounts", "secret-accounts", frozenset({SCOPE_ACCOUNTS})
            ),
            "svc-transfers": Principal(
                "svc-transfers", "secret-transfers", frozenset({SCOPE_TRANSFERS})
            ),
            "svc-admin": Principal(
                "svc-admin", "secret-admin", frozenset({SCOPE_ACCOUNTS, SCOPE_TRANSFERS})
            ),
        }

    if verifier is None:
        verifier = RequestVerifier(PrincipalStore(principals), clock=SystemClock())
    replays = ReplayStore(ttl_seconds=replay_ttl)
    guard = TrustGuard(verifier, replays)

    if accounting is None:
        downstream = FlakyDownstream(downstream_script)
        accounting = AccountingService(downstream)

    app = FastAPI(title="Zero-Trust Request Guard", version="0.1.0")
    app.include_router(build_router(guard, accounting))

    @app.exception_handler(AppError)
    async def handle_app_error(request: Request, exc: AppError):
        # 业务错误为预期；下游/系统错误在服务端记录细节
        if isinstance(exc, DownstreamError):
            logger.warning("downstream failure path=%s", request.url.path)
        return JSONResponse(
            status_code=exc.http_status,
            content=error_body(exc.code, exc.safe_message, details=exc.details),
        )

    @app.exception_handler(Exception)
    async def handle_unknown_error(request: Request, exc: Exception):
        # 内部异常与堆栈绝不直接透出，仅服务端日志保留
        logger.exception("unhandled exception path=%s", request.url.path)
        return JSONResponse(
            status_code=500,
            content=error_body("internal_error", "internal server error"),
        )

    @app.get("/healthz")
    async def healthz():
        return {"status": "ok"}

    return app
