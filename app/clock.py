"""可替换时钟。

信任判定依赖"当前时间"。把时钟抽象成可注入的 callable，
测试中可以用固定值/步进值替换，从而确定性覆盖时间窗口边界。
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable

_lock = threading.Lock()
_now_fn: Callable[[], float] = time.time


def now() -> float:
    """当前 Unix 时间（秒）。"""
    with _lock:
        fn = _now_fn
    return fn()


def set_clock(fn: Callable[[], float]) -> None:
    """替换时钟（测试用）。"""
    global _now_fn
    with _lock:
        _now_fn = fn


def reset_clock() -> None:
    """恢复为真实时钟。"""
    set_clock(time.time)
