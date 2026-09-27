"""统一错误分类：信任边界错误、业务错误、系统错误。

所有拒绝结论都带稳定的 ``error.code``，调用方据此区分原因；
内部异常不直接透出，统一映射为对外错误码。
"""
from __future__ import annotations


class AppError(Exception):
    """应用错误基类。"""

    http_status: int = 500
    code: str = "internal_error"
    safe_message: str = "internal error"

    def __init__(self, code: str = "", message: str = "", *, details: dict | None = None):
        self.code = code or self.code
        self.safe_message = message or self.safe_message
        self.details = details
        super().__init__(f"{self.code}: {self.safe_message}")


# --- 信任边界错误（4xx，原因可区分） ---
class TrustError(AppError):
    http_status = 401


class MissingCredentialError(TrustError):
    http_status, code = 401, "missing_credential"
    safe_message = "required trust headers are missing"


class SignatureMismatchError(TrustError):
    http_status, code = 401, "signature_mismatch"
    safe_message = "signature verification failed"


class BodyTamperedError(TrustError):
    http_status, code = 401, "body_tampered"
    safe_message = "request body digest mismatch"


class TimestampExpiredError(TrustError):
    http_status, code = 401, "timestamp_expired"
    safe_message = "request timestamp outside accepted window"


class TimestampFutureError(TrustError):
    http_status, code = 401, "timestamp_in_future"
    safe_message = "request timestamp is too far in the future"


class UnknownPrincipalError(TrustError):
    http_status, code = 401, "unknown_principal"
    safe_message = "unknown principal"


class ScopeDeniedError(TrustError):
    http_status, code = 403, "scope_denied"
    safe_message = "principal scope insufficient"


class ScopeInsufficientError(TrustError):
    http_status, code = 403, "scope_insufficient"
    safe_message = "request scope insufficient for route"


# --- 幂等：重放 / 并发重复（409，可区分） ---
class ReplayDetectedError(TrustError):
    http_status, code = 409, "idempotency_replay"
    safe_message = "signed request already processed"


class ConcurrentDuplicateError(TrustError):
    http_status, code = 409, "concurrent_duplicate"
    safe_message = "same signed request is being processed"


# --- 业务错误（4xx） ---
class BusinessError(AppError):
    http_status = 422


class InvalidRequestError(BusinessError):
    http_status, code = 400, "invalid_request"
    safe_message = "request body is not valid"


class AccountExistsError(BusinessError):
    http_status, code = 409, "account_exists"
    safe_message = "account already exists"


class InsufficientFundsError(BusinessError):
    http_status, code = 422, "insufficient_funds"
    safe_message = "insufficient funds"


class AccountNotFoundError(BusinessError):
    http_status, code = 404, "account_not_found"
    safe_message = "account not found"


# --- 系统错误（对外不透明） ---
class DownstreamError(AppError):
    http_status, code = 502, "downstream_unavailable"
    safe_message = "downstream dependency unavailable"


class InternalError(AppError):
    http_status, code = 500, "internal_error"
    safe_message = "internal server error"
