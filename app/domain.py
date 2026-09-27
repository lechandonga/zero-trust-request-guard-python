"""示例业务：账户与转账。

要点：
- 先完成全部业务校验，再一次性提交变更，失败时不留半截副作用；
- 下游调用（如下游记账服务）失败时回滚本地变更；
- 业务校验失败抛 BusinessError（→ 422），下游异常向上抛（→ 500，
  由 Web 层兜底并映射为 internal_error，细节不透出）。
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass

from app.errors import BusinessError


@dataclass(slots=True)
class Account:
    account_id: str
    balance: int  # 最小货币单位，避免浮点误差


class AccountStore:
    """线程安全的内存账户存储。"""

    def __init__(self) -> None:
        self._accounts: dict[str, Account] = {}
        self._lock = threading.Lock()

    def create(self, account_id: str, balance: int) -> Account:
        if balance < 0:
            raise BusinessError("初始余额不能为负")
        with self._lock:
            if account_id in self._accounts:
                raise BusinessError(f"账户已存在: {account_id}")
            account = Account(account_id=account_id, balance=balance)
            self._accounts[account_id] = account
            return account

    def get(self, account_id: str) -> Account | None:
        with self._lock:
            account = self._accounts.get(account_id)
            if account is None:
                return None
            return Account(account_id=account.account_id, balance=account.balance)

    def transfer(
        self,
        *,
        from_id: str,
        to_id: str,
        amount: int,
        downstream: Callable[[str, str, int], None] | None = None,
    ) -> dict:
        """转账：校验 → 下游记账 → 本地提交；任一步失败都不留副作用。"""
        if amount <= 0:
            raise BusinessError("转账金额必须为正数")
        with self._lock:
            src = self._accounts.get(from_id)
            dst = self._accounts.get(to_id)
            # 1) 全部业务校验先于任何变更
            if src is None:
                raise BusinessError(f"付款账户不存在: {from_id}")
            if dst is None:
                raise BusinessError(f"收款账户不存在: {to_id}")
            if src.balance < amount:
                raise BusinessError("余额不足")

            # 2) 下游调用失败时本地不做任何变更（异常向上抛 → 500）
            if downstream is not None:
                downstream(from_id, to_id, amount)

            # 3) 一次性提交
            src.balance -= amount
            dst.balance += amount
            return {
                "from": from_id,
                "to": to_id,
                "amount": amount,
                "from_balance": src.balance,
                "to_balance": dst.balance,
            }
