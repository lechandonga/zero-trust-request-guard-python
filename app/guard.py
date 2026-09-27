"""信任守卫：所有改动状态的接口共用同一套判定入口。

流程：
    verify() -> replay.begin() -> handler() -> replay.complete()
                                     |
                                     +-- 任意异常 -> replay.fail()（无残留）后抛出

并发下同一签名键只有一个线程能通过 begin，因此 handler 对同一请求
只会真正执行一次；其它线程得到 concurrent_duplicate。
"""
from __future__ import annotations

import logging
from typing import Any, Callable

from .errors import AppError, ReplayDetectedError
from .replay import ReplayKey, ReplayStore
from .security import RequestVerifier, VerifiedRequest

guard_logger = logging.getLogger("zero_trust.guard")


def request_feature(vr: VerifiedRequest) -> dict[str, Any]:
    """请求特征：用于日志（不含密钥与原始体）。"""
    c = vr.credentials
    return {
        "key_id": c.key_id,
        "timestamp": c.timestamp,
        "nonce": c.nonce,
        "scope": c.scope,
        "body_sha256": c.body_sha256,
        "signature": c.signature,
        "method": vr.method,
        "path": vr.path,
    }


def _feature_from_headers(headers: dict[str, str], method: str, path: str) -> dict[str, Any]:
    norm = {k.lower(): v for k, v in headers.items()}
    return {
        "key_id": norm.get("x-zt-key-id", "-"),
        "timestamp": norm.get("x-zt-timestamp", "-"),
        "nonce": norm.get("x-zt-nonce", "-"),
        "scope": norm.get("x-zt-scope", "-"),
        "body_sha256": norm.get("x-zt-body-sha256", "-"),
        "signature": norm.get("x-zt-signature", "-"),
        "method": method.upper(),
        "path": path,
    }


class TrustGuard:
    def __init__(self, verifier: RequestVerifier, replays: ReplayStore):
        self._verifier = verifier
        self._replays = replays

    def execute(
        self,
        *,
        headers: dict[str, str],
        body: bytes,
        method: str,
        path: str,
        required_scope: str,
        handler: Callable[[VerifiedRequest], Any],
    ) -> Any:
        """信任判定 + 恰好一次业务执行。"""
        # 1. 信任判定（含签名/时间戳/作用域等，结论可区分）
        try:
            vr = self._verifier.verify(
                headers=headers,
                body=body,
                method=method,
                path=path,
                required_scope=required_scope,
            )
        except AppError as exc:
            guard_logger.info(
                "trust decision=DENY reason=%s required_scope=%s feature=%s",
                exc.code,
                required_scope,
                _feature_from_headers(headers, method, path),
            )
            raise

        key: ReplayKey = (vr.credentials.key_id, vr.credentials.signature)
        feature = request_feature(vr)

        # 2. 幂等占位：并发重复 / 历史重放在此被识别并区分
        try:
            self._replays.begin(key)
        except ReplayDetectedError as exc:
            guard_logger.info(
                "trust decision=DENY reason=%s feature=%s", exc.code, feature
            )
            exc.details = {"cached_result": self._replays.get_completed_result(key)}
            raise
        except AppError as exc:  # ConcurrentDuplicateError
            guard_logger.info(
                "trust decision=DENY reason=%s feature=%s", exc.code, feature
            )
            raise

        # 3. 执行业务；任何失败都清除占位（不留半成品状态，允许重试）
        try:
            result = handler(vr)
        except AppError:
            self._replays.fail(key)
            guard_logger.info(
                "trust decision=FAIL reason=business_error idempotency=cleared feature=%s",
                feature,
            )
            raise
        except Exception:
            self._replays.fail(key)
            guard_logger.exception(
                "trust decision=FAIL reason=system_error idempotency=cleared feature=%s",
                feature,
            )
            raise

        self._replays.complete(key, result)
        guard_logger.info(
            "trust decision=ALLOW scope=%s key_id=%s nonce=%s sig=%s feature=%s",
            vr.credentials.scope,
            vr.credentials.key_id,
            vr.credentials.nonce,
            vr.credentials.signature,
            feature,
        )
        return result
