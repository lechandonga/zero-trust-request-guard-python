"""调用方身份、密钥与授权作用域注册表。

真实系统中这些数据来自密钥管理服务；此处用内存注册表演示，
并支持测试时注入自定义注册表。
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class ClientIdentity:
    """一个已注册的调用方。"""

    client_id: str
    secret: str
    scopes: frozenset[str] = field(default_factory=frozenset)


# 作用域命名约定："<资源>:<操作>"
SCOPE_ACCOUNTS_WRITE = "accounts:write"
SCOPE_TRANSFERS_WRITE = "transfers:write"


class CredentialRegistry:
    """按 client_id 查找调用方身份。"""

    def __init__(self, clients: dict[str, ClientIdentity] | None = None) -> None:
        self._clients: dict[str, ClientIdentity] = dict(clients or {})

    def register(self, identity: ClientIdentity) -> None:
        self._clients[identity.client_id] = identity

    def lookup(self, client_id: str) -> ClientIdentity | None:
        return self._clients.get(client_id)


def default_registry() -> CredentialRegistry:
    """演示用默认注册表（密钥仅用于本地开发/测试）。"""
    return CredentialRegistry(
        {
            "payments-service": ClientIdentity(
                client_id="payments-service",
                secret="dev-secret-payments",
                scopes=frozenset({SCOPE_ACCOUNTS_WRITE, SCOPE_TRANSFERS_WRITE}),
            ),
            "ledger-reader": ClientIdentity(
                client_id="ledger-reader",
                secret="dev-secret-ledger",
                scopes=frozenset(),  # 没有任何写作用域，用于演示越权拒绝
            ),
        }
    )
