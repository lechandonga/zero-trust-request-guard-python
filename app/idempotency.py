"""重放与并发去重存储。

以请求签名作为幂等键（同一签名 = 同一规范化请求）。三种状态：

- 不存在        → 允许执行（占位为 IN_PROGRESS）
- IN_PROGRESS   → 并发重复提交，拒绝（CONCURRENT_DUPLICATE），保证只执行一次
- COMPLETED     → 重放，拒绝（REPLAY_DETECTED），副作用不会再次发生

COMPLETED 记录有 TTL，过期后同一签名视为新请求（窗口外的重放通常
已先被时间戳校验拒绝）。系统错误时调用 abort() 释放占位，允许调用方
修正后重试；业务错误属于"已完成的处理"，同样记录结果。
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from enum import StrEnum

from app import clock

DEFAULT_TTL_SECONDS = 3600.0


class BeginResult(StrEnum):
    ACQUIRED = "acquired"        # 获得执行权
    CONCURRENT = "concurrent"    # 同一请求正在处理中
    REPLAY = "replay"            # 同一请求已完成


@dataclass(slots=True)
class _Entry:
    status: str  # "in_progress" | "completed"
    expires_at: float
    response_status: int | None = None
    response_body: dict | None = None


class IdempotencyStore:
    """线程安全的内存幂等存储。"""

    def __init__(self, ttl_seconds: float = DEFAULT_TTL_SECONDS) -> None:
        self._ttl = ttl_seconds
        self._entries: dict[str, _Entry] = {}
        self._lock = threading.Lock()

    def try_begin(self, key: str) -> BeginResult:
        """原子地尝试占位；整个判定+占位在同一把锁内完成。"""
        with self._lock:
            self._purge_expired_locked()
            entry = self._entries.get(key)
            if entry is None:
                self._entries[key] = _Entry(
                    status="in_progress",
                    expires_at=clock.now() + self._ttl,
                )
                return BeginResult.ACQUIRED
            if entry.status == "in_progress":
                return BeginResult.CONCURRENT
            return BeginResult.REPLAY

    def complete(self, key: str, *, status_code: int, body: dict) -> None:
        """处理完成（含业务错误），记录结果供重放识别。"""
        with self._lock:
            self._entries[key] = _Entry(
                status="completed",
                expires_at=clock.now() + self._ttl,
                response_status=status_code,
                response_body=body,
            )

    def abort(self, key: str) -> None:
        """系统错误时释放占位，允许调用方重试。"""
        with self._lock:
            entry = self._entries.get(key)
            if entry is not None and entry.status == "in_progress":
                del self._entries[key]

    def _purge_expired_locked(self) -> None:
        now = clock.now()
        expired = [k for k, e in self._entries.items() if e.expires_at <= now]
        for k in expired:
            del self._entries[k]
