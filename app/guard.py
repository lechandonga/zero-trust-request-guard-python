"""信任判定管线。

所有改动状态的请求统一经过以下判定顺序（任一失败即拒绝，可区分）：

1. 凭证齐全性  —— 必要请求头是否都存在且格式合法
2. 来源识别    —— client_id 是否已注册
3. 时间窗口    —— 时间戳是否在允许窗口内（边界含端点）
4. 签名完整性  —— HMAC 常量时间比较，篡改即拒绝
5. 作用域授权  —— 是否持有该操作所需作用域
6. 幂等占位    —— 重放 / 并发重复识别

每一步都记录请求特征与判定依据到日志（签名只记前缀，不落全量）。
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Mapping
from dataclasses import dataclass

from app import security
from app.credentials import ClientIdentity, CredentialRegistry
from app.errors import ErrorCode, GuardError
from app.idempotency import BeginResult, IdempotencyStore

logger = logging.getLogger("app.guard")

HEADER_CLIENT_ID = "x-client-id"
HEADER_TIMESTAMP = "x-timestamp"
HEADER_SIGNATURE = "x-signature"


@dataclass(slots=True)
class TrustedRequest:
    """通过信任判定的请求上下文。"""

    request_id: str
    client: ClientIdentity
    idempotency_key: str  # 即请求签名
    fingerprint: str


class RequestGuard:
    def __init__(
        self,
        registry: CredentialRegistry,
        store: IdempotencyStore,
        window_seconds: float = security.DEFAULT_WINDOW_SECONDS,
    ) -> None:
        self._registry = registry
        self._store = store
        self._window = window_seconds

    def authenticate(
        self,
        *,
        method: str,
        path: str,
        headers: Mapping[str, str],
        body: bytes,
        required_scope: str,
    ) -> TrustedRequest:
        """执行第 1~5 步判定；失败抛 GuardError，成功返回请求上下文。"""
        request_id = uuid.uuid4().hex[:12]
        lower = {k.lower(): v for k, v in headers.items()}
        client_id = lower.get(HEADER_CLIENT_ID, "")
        raw_ts = lower.get(HEADER_TIMESTAMP, "")
        signature = lower.get(HEADER_SIGNATURE, "")
        fingerprint = (
            f"request_id={request_id} client_id={client_id or '<missing>'} "
            f"method={method.upper()} path={path} ts={raw_ts or '<missing>'} "
            f"sig={signature[:12] + '…' if signature else '<missing>'} "
            f"scope={required_scope}"
        )

        def reject(err: GuardError) -> GuardError:
            logger.info("信任判定拒绝 | %s | 依据: %s (%s)", fingerprint, err.message, err.code)
            return err

        # 1. 凭证齐全性
        if not client_id or not raw_ts or not signature:
            raise reject(GuardError(
                ErrorCode.MISSING_CREDENTIALS,
                "缺少必要的签名请求头：X-Client-Id / X-Timestamp / X-Signature",
            ))
        timestamp = security.parse_timestamp(raw_ts)

        # 2. 来源识别
        client = self._registry.lookup(client_id)
        if client is None:
            raise reject(GuardError(
                ErrorCode.UNKNOWN_CLIENT,
                f"未注册的来源标识: {client_id}",
            ))

        # 3. 时间窗口
        try:
            security.check_timestamp(timestamp, self._window)
        except GuardError as e:
            raise reject(e) from None

        # 4. 签名完整性
        try:
            security.verify_signature(
                secret=client.secret,
                client_id=client_id,
                timestamp=timestamp,
                method=method,
                path=path,
                body=body,
                provided_signature=signature,
            )
        except GuardError as e:
            raise reject(e) from None

        # 5. 作用域授权
        if required_scope not in client.scopes:
            raise reject(GuardError(
                ErrorCode.SCOPE_INSUFFICIENT,
                f"作用域不足：该操作需要 {required_scope}",
            ))

        logger.info("信任判定通过 | %s | 依据: 签名有效、时间戳在窗口内、作用域齐备", fingerprint)
        return TrustedRequest(
            request_id=request_id,
            client=client,
            idempotency_key=signature.strip().lower(),
            fingerprint=fingerprint,
        )

    def begin(self, trusted: TrustedRequest) -> None:
        """第 6 步：幂等占位。重放/并发重复在此被拒绝。"""
        result = self._store.try_begin(trusted.idempotency_key)
        if result is BeginResult.ACQUIRED:
            logger.info("幂等占位成功 | %s", trusted.fingerprint)
            return
        if result is BeginResult.CONCURRENT:
            err = GuardError(
                ErrorCode.CONCURRENT_DUPLICATE,
                "同一签名请求正在处理中，已拒绝并发重复执行",
            )
        else:
            err = GuardError(
                ErrorCode.REPLAY_DETECTED,
                "同一签名请求已完成，拒绝重放以避免重复副作用",
            )
        logger.info("幂等判定拒绝 | %s | 依据: %s (%s)", trusted.fingerprint, err.message, err.code)
        raise err

    def complete(self, trusted: TrustedRequest, *, status_code: int, body: dict) -> None:
        self._store.complete(trusted.idempotency_key, status_code=status_code, body=body)

    def abort(self, trusted: TrustedRequest) -> None:
        self._store.abort(trusted.idempotency_key)
