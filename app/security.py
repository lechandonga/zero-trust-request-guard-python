"""HMAC 签名构造与校验。

签名输入的规范化串（canonical string）：

    v1
    <client_id>
    <timestamp>          # Unix 秒，整数
    <METHOD>             # 大写
    <path>               # 不含 query
    <sha256_hex(body)>   # 原始请求体的 SHA-256 十六进制

签名 = HMAC-SHA256(secret, canonical) 的十六进制小写。

时间窗口规则（确定性）：当且仅当 abs(now - timestamp) <= window_seconds
时接受；窗口边界（恰好等于 window_seconds）视为有效。过旧与超前
都归入 TIMESTAMP_SKEWED，并在 message 中区分方向。
"""

from __future__ import annotations

import hashlib
import hmac

from app import clock
from app.errors import ErrorCode, GuardError

SIGNATURE_VERSION = "v1"
DEFAULT_WINDOW_SECONDS = 300.0


def body_digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def canonical_string(
    *,
    client_id: str,
    timestamp: int,
    method: str,
    path: str,
    body: bytes,
) -> str:
    return "\n".join(
        [
            SIGNATURE_VERSION,
            client_id,
            str(timestamp),
            method.upper(),
            path,
            body_digest(body),
        ]
    )


def sign(
    *,
    secret: str,
    client_id: str,
    timestamp: int,
    method: str,
    path: str,
    body: bytes,
) -> str:
    """计算签名（客户端与测试使用同一实现，避免两边规则漂移）。"""
    canonical = canonical_string(
        client_id=client_id,
        timestamp=timestamp,
        method=method,
        path=path,
        body=body,
    )
    return hmac.new(secret.encode(), canonical.encode(), hashlib.sha256).hexdigest()


def parse_timestamp(raw: str) -> int:
    """解析时间戳请求头；非整数视为缺少有效凭证。"""
    try:
        return int(raw)
    except (TypeError, ValueError):
        raise GuardError(
            ErrorCode.MISSING_CREDENTIALS,
            "X-Timestamp 头缺失或不是整数 Unix 秒",
        ) from None


def check_timestamp(timestamp: int, window_seconds: float = DEFAULT_WINDOW_SECONDS) -> None:
    """校验时间戳是否落在允许窗口内（边界含端点）。"""
    now = clock.now()
    skew = now - timestamp
    if skew > window_seconds:
        raise GuardError(
            ErrorCode.TIMESTAMP_SKEWED,
            f"时间戳过期：偏移 {skew:.1f}s 超出允许窗口 {window_seconds:.0f}s",
        )
    if skew < -window_seconds:
        raise GuardError(
            ErrorCode.TIMESTAMP_SKEWED,
            f"时间戳超前：偏移 {skew:.1f}s 超出允许窗口 {window_seconds:.0f}s",
        )


def verify_signature(
    *,
    secret: str,
    client_id: str,
    timestamp: int,
    method: str,
    path: str,
    body: bytes,
    provided_signature: str,
) -> None:
    """常量时间比较签名；任何不匹配（含内容被篡改）都报 SIGNATURE_INVALID。"""
    expected = sign(
        secret=secret,
        client_id=client_id,
        timestamp=timestamp,
        method=method,
        path=path,
        body=body,
    )
    if not hmac.compare_digest(expected, provided_signature.strip().lower()):
        raise GuardError(
            ErrorCode.SIGNATURE_INVALID,
            "签名校验失败：签名无效或请求内容被篡改",
        )
