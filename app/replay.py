"""签名请求的幂等去重存储。

状态机（每个 ReplayKey 一条记录，受锁保护）：

    (无记录) --begin--> 进行中 --complete--> 已完成（缓存结果）
                          |                     ^
                          +--fail--> (删除) ----+  允许相同签名重试

- 进行中再次 begin  -> ConcurrentDuplicateError（并发重复，409）
- 已完成再次 begin  -> ReplayDetectedError（重放，409，携带首次结果）
- 记录在 TTL 到期后视为不存在（惰性回收 + purge_expired）
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Any, Callable

from .errors import ConcurrentDuplicateError, ReplayDetectedError

#: 幂等记录保留时长（>= 时间窗口，保证窗口内一定可识别重放）
DEFAULT_REPLAY_TTL_SECONDS = 600.0

#: 签名请求的去重键
ReplayKey = tuple[str, str]  # (key_id, signature)


@dataclass
class _Entry:
    done: bool = False
    result: Any = None
    expires_at: float = 0.0


class ReplayStore:
    def __init__(
        self,
        ttl_seconds: float = DEFAULT_REPLAY_TTL_SECONDS,
        clock: Callable[[], float] | None = None,
    ):
        self._ttl = float(ttl_seconds)
        self._clock = clock or time.time
        self._lock = threading.Lock()
        self._entries: dict[ReplayKey, _Entry] = {}

    def _get_alive(self, key: ReplayKey) -> _Entry | None:
        """调用方持锁；过期条目就地删除。"""
        entry = self._entries.get(key)
        if entry is not None and entry.expires_at <= self._clock():
            del self._entries[key]
            return None
        return entry

    def begin(self, key: ReplayKey) -> None:
        """声明开始处理；并发重复 / 重放分别抛可区分错误。"""
        with self._lock:
            entry = self._get_alive(key)
            if entry is None:
                self._entries[key] = _Entry(expires_at=self._clock() + self._ttl)
                return
            if entry.done:
                raise ReplayDetectedError(details={"cached": True})
            raise ConcurrentDuplicateError()

    def complete(self, key: ReplayKey, result: Any) -> None:
        """标记成功完成并缓存结果（续期 TTL）。"""
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                # 理论不可达：begin 已占位。防御性处理。
                entry = _Entry()
                self._entries[key] = entry
            entry.done = True
            entry.result = result
            entry.expires_at = self._clock() + self._ttl

    def fail(self, key: ReplayKey) -> None:
        """失败后删除占位：无残留，允许相同签名重试。"""
        with self._lock:
            self._entries.pop(key, None)

    def get_completed_result(self, key: ReplayKey) -> Any:
        with self._lock:
            entry = self._get_alive(key)
            if entry is not None and entry.done:
                return entry.result
        raise ReplayDetectedError()

    def purge_expired(self) -> int:
        """回收过期记录，返回清除条数。"""
        with self._lock:
            now = self._clock()
            dead = [k for k, e in self._entries.items() if e.expires_at <= now]
            for k in dead:
                del self._entries[k]
            return len(dead)
