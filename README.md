# Zero Trust Request Guard（Python / FastAPI）

为所有**改动状态**的接口（`POST /accounts`、`POST /transfers`）统一添加一层
零信任请求校验与幂等重放防护。读接口（`GET`）不受此限制。

## 1. 信任判定规则

每个改状态请求必须携带三个请求头：

| 请求头 | 含义 |
| --- | --- |
| `X-Client-Id` | 可验证的来源标识（调用方身份） |
| `X-Timestamp` | Unix 秒整数，表示请求生成时间 |
| `X-Signature` | 对规范化请求串的 HMAC-SHA256 签名（十六进制小写） |

### 规范化签名串

```
v1
<client_id>
<timestamp>
<METHOD>          # 大写 HTTP 方法
<path>            # URL 路径，不含 query string
<sha256_hex(body)>
```

签名 = `HMAC-SHA256(client_secret, 规范化串)`。密钥按 `client_id` 在服务端
注册表中查找，签名使用常量时间比较（`hmac.compare_digest`），可防时序侧信道。

### 判定顺序（任一失败即拒绝，错误码可区分）

| 顺序 | 判定 | 失败错误码 | HTTP |
| --- | --- | --- | --- |
| 1 | 三个请求头齐全且时间戳为整数 | `missing_credentials` | 401 |
| 2 | `client_id` 已注册（密钥可查） | `unknown_client` | 401 |
| 3 | 时间戳落在允许窗口内 | `timestamp_skewed` | 401 |
| 4 | 签名与请求内容一致（签名或 body 被改过都会失败） | `signature_invalid` | 401 |
| 5 | 调用方持有该操作所需作用域 | `scope_insufficient` | 403 |
| 6 | 同一签名未在处理中 / 未完成过 | `concurrent_duplicate` / `replay_detected` | 409 |

错误响应统一形如：

```json
{ "error": { "code": "signature_invalid", "message": "...", "request_id": "..." } }
```

## 2. 作用域（Scope）含义

作用域命名约定为 `<资源>:<操作>`，注册调用方时按身份授予：

| 作用域 | 允许的操作 |
| --- | --- |
| `accounts:write` | `POST /accounts`（开户） |
| `transfers:write` | `POST /transfers`（转账） |

内置演示身份（密钥仅用于本地开发/测试，见 `app/credentials.py`）：

- `payments-service`：持有两个写作用域
- `ledger-reader`：已注册但**无任何写作用域**，用于演示越权拒绝

作用域不足是在来源已识别、签名有效之后判定的，因此调用方能区分
"身份/签名问题"（401）与"身份合法但未授权"（403）。

## 3. 时间窗口

- 默认允许偏移：**300 秒**（`app.security.DEFAULT_WINDOW_SECONDS`）。
- 接受条件（确定性、边界含端点）：`abs(服务端当前时间 - X-Timestamp) <= 300`。
  - 恰好 ±300s：**接受**；±301s：拒绝。
  - 过旧：`timestamp_skewed`，message 为"时间戳过期"；
  - 超前（防伪造未来时间戳）：`timestamp_skewed`，message 为"时间戳超前"。
- 时间校验先于签名比对，过期请求即使签名正确也会被拒。

## 4. 重放与并发行为

幂等键 = 请求签名（同一签名 ⇔ 同一规范化请求：来源、时间、方法、路径、
body 摘要全部相同；body 不同则签名不同，视为不同请求）。

服务端为每个幂等键维护状态机：

```
不存在 ──try_begin()──▶ IN_PROGRESS ──complete()──▶ COMPLETED
                            │                          │
              并发重复(409) ◀┘              重放(409) ◀┘
                            └── 系统错误 abort()：删除占位，允许重试
```

- **重放**：请求已完成（无论成功还是业务错误，如余额不足）再提交 →
  `409 replay_detected`，业务逻辑**不会再执行**，副作用只发生一次。
- **并发重复**：同一签名请求正在处理中（另有并发请求到达）→
  `409 concurrent_duplicate`。占位判定与状态插入在同一把锁内原子完成，
  并发下**保证真正生效一次**。
- **系统错误**（如下游记账服务异常）：处理过程抛出的非业务异常会释放
  幂等占位（`abort`），调用方修复后可用原请求重试；同时本地不提交任何
  变更，不留下做了一半的副作用。
- COMPLETED 记录有 TTL（默认 3600s，`app.idempotency.DEFAULT_TTL_SECONDS`），
  过期后同签名视为新请求；实践中时间窗口外的重放会先在第 3 步被拒绝。

## 5. 失败映射与信息安全

| 情形 | HTTP | code | 说明 |
| --- | --- | --- | --- |
| 信任/授权/幂等拒绝 | 401 / 403 / 409 | 见上表 | 可区分的稳定错误码 |
| 业务校验失败（余额不足、账户不存在等） | 422 | `business_rule_violation` | message 可安全展示 |
| 未预期异常 / 下游故障 | 500 | `internal_error` | **仅返回通用文案**，内部异常与堆栈只写服务端日志，不透出 |

业务层（`app/domain.py`）先完成全部校验、再调用下游、最后一次性提交
本地变更，保证失败路径不留半截副作用。

## 6. 日志

每次信任/幂等判定都会记录**请求特征与判定依据**，示例：

```
信任判定拒绝 | request_id=08fdaf1294ca client_id=payments-service method=POST
path=/transfers ts=1700000000 sig=000000000000… scope=transfers:write
| 依据: 签名校验失败：签名无效或请求内容被篡改 (signature_invalid)
```

（签名只记录前 12 位，不记录完整签名/密钥。）

## 7. 本地验证

```bash
uv sync

# 全量测试（覆盖：篡改、过期/超前、窗口边界、越权、重放、
# 8 路并发重复、业务错误、下游故障、失败重试）
uv run pytest -q

# 同时打印每个测试的判定日志（请求特征 + 判定依据）
uv run pytest -o log_cli=true -o log_cli_level=INFO

# 启动服务
uv run python main.py    # http://127.0.0.1:8000，文档 /docs
```

手动签名调用可参考下面的最小客户端（对 `/transfers` 的有效请求）：

```python
import hashlib, hmac, json, time, urllib.request

body = json.dumps({"from_account": "a", "to_account": "b", "amount": 10}).encode()
ts = int(time.time())
canonical = "\n".join([
    "v1", "payments-service", str(ts), "POST", "/transfers",
    hashlib.sha256(body).hexdigest(),
])
sig = hmac.new(b"dev-secret-payments", canonical.encode(), hashlib.sha256).hexdigest()
req = urllib.request.Request(
    "http://127.0.0.1:8000/transfers", data=body, method="POST",
    headers={
        "Content-Type": "application/json",
        "X-Client-Id": "payments-service",
        "X-Timestamp": str(ts),
        "X-Signature": sig,
    },
)
print(urllib.request.urlopen(req).read().decode())
```

快速复现几种拒绝结论：

- 改 `amount` 但不改签名 → `401 signature_invalid`
- `ts` 改成 10 分钟前 → `401 timestamp_skewed`（过期）
- 把 `X-Client-Id` 换成 `ledger-reader`（并用其密钥重签）→ `403 scope_insufficient`
- 同一签名请求发两次 → 第二次 `409 replay_detected`
