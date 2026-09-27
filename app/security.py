"""零信任请求来源校验：HMAC 签名、时间戳窗口、作用域。

判定顺序（每一步失败即给出不同结论）：
1. 必填头部完整性        -> missing_credential
2. 时间戳为 Unix 秒整数  -> missing_credential
3. 来源主体是否登记      -> unknown_principal
4. 主体是否被授予声明域  -> scope_denied
5. 时间窗口（未来/过期，边界闭区间） -> timestamp_in_future / timestamp_expired
6. 请求体摘要            -> body_tampered
7. HMAC 签名（常量时间比较）-> signature_mismatch
8. 声明域是否覆盖路由域  -> scope_insufficient
"""
from __future__ import annotations

import hmac
import time
from dataclasses import dataclass, field
from hashlib import sha256
from typing import Protocol

from .errors import (
    MissingCredentialError,
    ScopeDeniedError,
    ScopeInsufficientError,
    SignatureMismatchError,
    BodyTamperedError,
    TimestampExpiredError,
    TimestampFutureError,
    UnknownPrincipalError,
)

#: 默认接受的时间窗口：[now - 300s, now + 30s]，边界值有效
DEFAULT_WINDOW_PAST_SECONDS = 300
DEFAULT_WINDOW_FUTURE_SECONDS = 30

#: 信任边界头部（小写规范化后匹配）
H_KEY_ID = "x-zt-key-id"
H_TIMESTAMP = "x-zt-timestamp"
H_NONCE = "x-zt-nonce"
H_SCOPE = "x-zt-scope"
H_BODY_DIGEST = "x-zt-body-sha256"
H_SIGNATURE = "x-zt-signature"

_REQUIRED_HEADERS = (
    H_KEY_ID,
    H_TIMESTAMP,
    H_NONCE,
    H_SCOPE,
    H_BODY_DIGEST,
    H_SIGNATURE,
)
_PROTOCOL_VERSION = "ZT1"


class Clock(Protocol):
    def now_unix(self) -> float: ...


class SystemClock:
    def now_unix(self) -> float:
        return time.time()


@dataclass(frozen=True)
class Principal:
    """已登记的调用方主体及其密钥、被授予的作用域。"""

    key_id: str
    secret: str
    scopes: frozenset[str] = field(default_factory=frozenset)


@dataclass(frozen=True)
class RequestCredentials:
    """从信任边界头部解析出的来源标识。"""

    key_id: str
    timestamp: int
    nonce: str
    scope: str
    body_sha256: str
    signature: str


@dataclass(frozen=True)
class VerifiedRequest:
    """校验通过后的可信请求视图。"""

    principal: Principal
    credentials: RequestCredentials
    body: bytes
    method: str
    path: str


class PrincipalStore:
    """key_id -> Principal 的登记目录。"""

    def __init__(self, principals: dict[str, Principal] | None = None):
        self._principals = dict(principals or {})

    def get(self, key_id: str) -> Principal | None:
        return self._principals.get(key_id)


def body_digest(body: bytes) -> str:
    """请求体的十六进制 SHA-256 摘要。"""
    return sha256(body).hexdigest()


def canonical_string(
    *,
    key_id: str,
    timestamp: int,
    nonce: str,
    scope: str,
    method: str,
    path: str,
    body: bytes,
) -> str:
    """构造被签名的规范字符串：版本行 + 每个字段独占一行（确定性）。"""
    return "\n".join(
        (
            _PROTOCOL_VERSION,
            key_id,
            str(timestamp),
            nonce,
            scope,
            method.upper(),
            path,
            body_digest(body),
        )
    )


def compute_signature(secret: str, canonical: str) -> str:
    """用主体密钥计算 HMAC-SHA256（十六进制）。"""
    return hmac.new(secret.encode("utf-8"), canonical.encode("utf-8"), sha256).hexdigest()


def sign(
    *,
    secret: str,
    key_id: str,
    timestamp: int,
    nonce: str,
    scope: str,
    method: str,
    path: str,
    body: bytes,
) -> tuple[str, str]:
    """供客户端/测试使用：返回 (body_sha256, signature)。"""
    digest = body_digest(body)
    canonical = canonical_string(
        key_id=key_id,
        timestamp=timestamp,
        nonce=nonce,
        scope=scope,
        method=method,
        path=path,
        body=body,
    )
    return digest, compute_signature(secret, canonical)


class RequestVerifier:
    """对单个请求执行完整信任判定。"""

    def __init__(
        self,
        principals: PrincipalStore,
        clock: Clock | None = None,
        window_past: float = DEFAULT_WINDOW_PAST_SECONDS,
        window_future: float = DEFAULT_WINDOW_FUTURE_SECONDS,
    ):
        self._principals = principals
        self._clock = clock or SystemClock()
        self._window_past = float(window_past)
        self._window_future = float(window_future)

    def verify(
        self,
        *,
        headers: dict[str, str],
        body: bytes,
        method: str,
        path: str,
        required_scope: str,
    ) -> VerifiedRequest:
        """执行 8 步判定；失败抛对应 TrustError，成功返回 VerifiedRequest。"""
        norm = {k.lower(): v for k, v in headers.items()}

        # 1. 必填头部完整性（空串视为缺失）
        missing = [h for h in _REQUIRED_HEADERS if not norm.get(h)]
        if missing:
            raise MissingCredentialError(details={"missing": missing})

        # 2. 时间戳格式
        raw_ts = norm[H_TIMESTAMP]
        try:
            timestamp = int(raw_ts)
        except (TypeError, ValueError):
            raise MissingCredentialError("timestamp must be unix seconds integer")

        creds = RequestCredentials(
            key_id=norm[H_KEY_ID],
            timestamp=timestamp,
            nonce=norm[H_NONCE],
            scope=norm[H_SCOPE],
            body_sha256=norm[H_BODY_DIGEST],
            signature=norm[H_SIGNATURE],
        )

        # 3. 主体登记
        principal = self._principals.get(creds.key_id)
        if principal is None:
            raise UnknownPrincipalError()

        # 4. 主体被授予声明作用域
        if creds.scope not in principal.scopes:
            raise ScopeDeniedError(
                details={"principal": creds.key_id, "requested_scope": creds.scope}
            )

        # 5. 时间窗口，整数秒闭区间：
        #    [floor(now)-past, floor(now)+future]，边界值有效；
        #    向外 1 秒分别判 timestamp_expired / timestamp_in_future。
        now = int(self._clock.now_unix())
        lower = now - int(self._window_past)
        upper = now + int(self._window_future)
        if timestamp > upper:
            raise TimestampFutureError(
                details={"skew_seconds": timestamp - now, "upper_bound": upper}
            )
        if timestamp < lower:
            raise TimestampExpiredError(
                details={"age_seconds": now - timestamp, "lower_bound": lower}
            )

        # 6. 请求体摘要（先于签名判定，区分"内容被改过"）
        actual_digest = body_digest(body)
        if not hmac.compare_digest(actual_digest, creds.body_sha256):
            raise BodyTamperedError()

        # 7. HMAC 签名
        canonical = canonical_string(
            key_id=creds.key_id,
            timestamp=creds.timestamp,
            nonce=creds.nonce,
            scope=creds.scope,
            method=method,
            path=path,
            body=body,
        )
        expected = compute_signature(principal.secret, canonical)
        if not hmac.compare_digest(expected, creds.signature):
            raise SignatureMismatchError()

        # 8. 声明域覆盖路由域
        if creds.scope != required_scope:
            raise ScopeInsufficientError(
                details={"declared": creds.scope, "required": required_scope}
            )

        return VerifiedRequest(
            principal=principal,
            credentials=creds,
            body=body,
            method=method.upper(),
            path=path,
        )
