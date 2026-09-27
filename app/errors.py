"""可区分的错误码与异常类型。

设计目标：信任边界上的每一类问题都有独立、稳定的 error code，
调用方可以据此区分处理；内部异常细节不直接透出给调用方。
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class ErrorCode(StrEnum):
    """对调用方可见的稳定错误码。"""

    # ---- 信任边界（401）----
    MISSING_CREDENTIALS = "missing_credentials"      # 缺少签名相关请求头
    UNKNOWN_CLIENT = "unknown_client"                # 来源标识无法识别
    SIGNATURE_INVALID = "signature_invalid"          # 签名不匹配（签名或内容被篡改）
    TIMESTAMP_SKEWED = "timestamp_skewed"            # 时间戳过期或超前，超出允许窗口

    # ---- 授权（403）----
    SCOPE_INSUFFICIENT = "scope_insufficient"        # 作用域不足以执行该操作

    # ---- 幂等（409）----
    REPLAY_DETECTED = "replay_detected"              # 已完成的同一签名请求被重复提交
    CONCURRENT_DUPLICATE = "concurrent_duplicate"    # 同一签名请求正在并发处理中

    # ---- 业务（422）----
    BUSINESS_RULE_VIOLATION = "business_rule_violation"  # 业务校验失败（如余额不足）

    # ---- 系统（500）----
    INTERNAL_ERROR = "internal_error"                # 未预期的系统错误，细节不透出


@dataclass(slots=True)
class ErrorBody:
    """统一的错误响应体。"""

    code: ErrorCode
    message: str
    request_id: str | None = None

    def to_dict(self) -> dict:
        return {
            "error": {
                "code": str(self.code),
                "message": self.message,
                "request_id": self.request_id,
            }
        }


class GuardError(Exception):
    """信任判定阶段的拒绝（在进入业务逻辑之前抛出）。"""

    def __init__(self, code: ErrorCode, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class BusinessError(Exception):
    """业务校验失败（如余额不足、资源不存在），映射为 422。"""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message
