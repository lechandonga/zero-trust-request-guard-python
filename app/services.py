"""示例业务服务：账户开户 + 转账。

多步操作（借记 -> 贷记 -> 下游记账）任一步失败都执行补偿，
保证余额不留"做了一半"的状态。
``FlakyDownstream`` 为可脚本化的下游，用于演示下游失败 -> downstream_unavailable。
"""
from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Callable, Protocol

from .errors import (
    AccountExistsError,
    AccountNotFoundError,
    DownstreamError,
    InsufficientFundsError,
)


class DownstreamClient(Protocol):
    def call(self, action: str, payload: dict) -> dict: ...


class FlakyDownstream:
    """测试用下游：按注入脚本返回；脚本抛 OSError 视为下游不可用。"""

    def __init__(self, scripted: Callable[[str, dict], dict] | None = None):
        self._scripted = scripted
        self._lock = threading.Lock()
        self._calls = 0

    def call(self, action: str, payload: dict) -> dict:
        with self._lock:
            self._calls += 1
        return self.invoke(action, payload)

    def invoke(self, action: str, payload: dict) -> dict:
        """实际下游调用；子类可在调用前后插入闸门。"""
        if self._scripted is None:
            return {"accepted": True, "reference": payload.get("reference")}
        try:
            return self._scripted(action, payload)
        except OSError as exc:  # 网络/下游故障，不把内部异常透给调用方
            raise DownstreamError() from exc

    @property
    def call_count(self) -> int:
        with self._lock:
            return self._calls


@dataclass
class Account:
    name: str
    balance: int = 0


class AccountingService:
    """线程安全的内存账本；写操作均为补偿式。"""

    def __init__(self, downstream: DownstreamClient | None = None):
        self._lock = threading.RLock()
        self._accounts: dict[str, Account] = {}
        self._downstream = downstream or FlakyDownstream()

    def create_account(self, name: str, opening_balance: int) -> dict:
        """开户；重复开户 -> account_exists（业务错误）。"""
        with self._lock:
            if name in self._accounts:
                raise AccountExistsError(details={"name": name})
            self._accounts[name] = Account(name=name, balance=opening_balance)
            return {"name": name, "balance": opening_balance, "status": "opened"}

    def transfer(self, from_name: str, to_name: str, amount: int, reference: str) -> dict:
        """借记 + 贷记 + 下游记账；失败补偿，最终余额不变。"""
        if amount <= 0:
            raise InsufficientFundsError("amount must be positive")
        with self._lock:
            src = self._accounts.get(from_name)
            dst = self._accounts.get(to_name)
            if src is None or dst is None:
                raise AccountNotFoundError(
                    details={"missing": [n for n, a in ((from_name, src), (to_name, dst)) if a is None]}
                )
            if src.balance < amount:
                raise InsufficientFundsError(
                    details={"balance": src.balance, "requested": amount}
                )

            # 1) 借记
            src.balance -= amount
            try:
                # 2) 贷记
                dst.balance += amount
                # 3) 下游记账（可能抛 BusinessError/DownstreamError）
                self._downstream.call(
                    "record_transfer",
                    {"from": from_name, "to": to_name, "amount": amount, "reference": reference},
                )
            except Exception:
                # 补偿：撤销前两步，恢复到调用前状态
                dst.balance -= amount
                src.balance += amount
                raise

            return {
                "from": from_name,
                "to": to_name,
                "amount": amount,
                "reference": reference,
                "status": "settled",
            }

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return {name: acc.balance for name, acc in self._accounts.items()}

    def downstream_call_count(self) -> int:
        ds = self._downstream
        return ds.call_count if hasattr(ds, "call_count") else -1
