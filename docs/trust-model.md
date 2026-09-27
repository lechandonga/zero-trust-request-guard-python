# 零信任请求校验与幂等重放防护

所有**改动状态**的接口（写接口）都必须经过同一套信任判定，只读接口不强制签名。
信任判定在请求跨越信任边界时执行；每一种失败原因都有**独立、稳定的错误码**，
调用方可以据此区分，而不是只得到一个笼统的"拒绝"。

## 1. 请求必须携带的来源标识

每个写请求需要以下 HTTP 头部：

| 头部 | 含义 |
| --- | --- |
| `X-ZT-Key-Id` | 调用方主体标识（服务账号 id），服务端据此查密钥与授权作用域 |
| `X-ZT-Timestamp` | 发起请求的 Unix 秒（整数），用于抗重放的时间窗口判定 |
| `X-ZT-Nonce` | 单次请求唯一串；与 key、时间戳、正文一起参与签名 |
| `X-ZT-Scope` | 本次请求**声明**使用的作用域，必须是主体被授予的作用域之一 |
| `X-ZT-Body-Sha256` | 请求体的十六进制 SHA-256 摘要 |
| `X-ZT-Signature` | 对"规范字符串"用主体密钥计算的 HMAC-SHA256（十六进制） |

### 规范字符串（被签名内容）

按固定顺序逐行拼接，字段间用换行分隔，保证确定性、无歧义：

```
ZT1
<key_id>
<timestamp>
<nonce>
<scope>
<METHOD 大写>
<path，不含 query>
<body 的 sha256 十六进制>
```

签名：

```
X-ZT-Signature = hex(HMAC_SHA256(secret, canonical_string))
X-ZT-Body-Sha256 = hex(SHA256(raw_body))
```

query string 不参与签名；`path` 使用请求路径本身。
方法名在签名与校验两侧都统一转为大写。

## 2. 信任判定顺序与可区分结论

校验严格按下面顺序执行，**第一步失败即返回对应错误码**，
因此不同性质的攻击/失误不会被混为一谈：

| 顺序 | 判定 | 失败错误码 | HTTP |
| --- | --- | --- | --- |
| 1 | 必填头部是否齐全且非空 | `missing_credential` | 401 |
| 2 | 时间戳是否为 Unix 秒整数 | `missing_credential` | 401 |
| 3 | 主体（key_id）是否已登记 | `unknown_principal` | 401 |
| 4 | 主体是否被授予了"声明作用域" | `scope_denied` | 403 |
| 5 | 时间戳是否在接受窗口内 | `timestamp_in_future` / `timestamp_expired` | 401 |
| 6 | 请求体摘要是否匹配（内容是否被改过） | `body_tampered` | 401 |
| 7 | HMAC 签名是否匹配（头部是否被改过/密钥是否正确） | `signature_mismatch` | 401 |
| 8 | 声明作用域是否覆盖该路由要求的作用域 | `scope_insufficient` | 403 |

要点：

- **内容被改过**与**签名被改过**是两个不同结论。先比对 body 摘要
  （`body_tampered`），再验签（`signature_mismatch`）。
  修改任何被签名的头部（如 nonce、scope、timestamp、path、method）都会导致
  `signature_mismatch`。
- **两种越权要分开**：
  - 主体压根没被授予该作用域 → `scope_denied`（403）；
  - 主体合法持有声明作用域，但该作用域不足以访问这个路由
    → `scope_insufficient`（403）。
- 签名比较与摘要比较都使用常量时间比较（`hmac.compare_digest`）。

## 3. 作用域（scope）含义

作用域是"主体可以做的事"的最小授权单位，写接口按资源动作划分：

| 作用域 | 可访问写接口 |
| --- | --- |
| `accounts:write` | `POST /v1/accounts`（开户） |
| `transfers:write` | `POST /v1/transfers`（转账） |

- 主体在登记时被授予一个作用域集合；请求里通过 `X-ZT-Scope` **声明本次只使用一个作用域**。
- 服务端先确认"该主体确实拥有这个作用域"（否则 `scope_denied`），
  再确认"这个作用域正好是当前路由要求的"（否则 `scope_insufficient`）。
- 演示主体（见 `app/app.py`）：

  | key_id | secret | 授予作用域 |
  | --- | --- | --- |
  | `svc-accounts` | `secret-accounts` | `accounts:write` |
  | `svc-transfers` | `secret-transfers` | `transfers:write` |
  | `svc-admin` | `secret-admin` | `accounts:write`, `transfers:write` |

## 4. 时间窗口与边界行为

默认接受窗口（可在构造 `RequestVerifier` 时调整）：

- 向后看 **300 秒**：`window_past = 300`
- 向前看 **30 秒**：`window_future = 30`（容忍客户端轻微时钟超前）

时间戳按 **Unix 整数秒**判定，服务端时间也向下取整到整数秒，窗口为**闭区间**：

```
合法当且仅当  floor(now) - 300 <= timestamp <= floor(now) + 30
```

边界行为确定：

- `timestamp = floor(now) - 300` → **接受**（恰好踩在下界）。
- `timestamp = floor(now) - 301` → `timestamp_expired`。
- `timestamp = floor(now) + 30` → **接受**（恰好踩在上界）。
- `timestamp = floor(now) + 31` → `timestamp_in_future`。

## 5. 幂等：重放与并发重复

通过完整信任判定后，请求进入幂等层。去重键为：

```
replay_key = (key_id, signature)
```

同一个签名请求（同主体、同签名）在 TTL 内只会被**真正执行一次**。
记录默认保留 **600 秒**（`replay_ttl`，不短于时间窗口，保证整个时间窗口内都能识别重放），
过期惰性回收，也可通过 `purge_expired()` 主动清理。

### 状态机

```
        begin()                 handler 成功
(无) ───────────────▶ 进行中 ───────────────▶ 已完成(缓存首次结果)
                        │  ▲                       │
                        │  └──── fail() 删除 ───────┘
                        └── 业务/系统失败：删除占位（允许同签名重试）
```

三种情况被明确区分：

| 情况 | 判定 | HTTP | 错误码 |
| --- | --- | --- | --- |
| 首次提交，正常执行 | 放行执行业务 | 201/200 | — |
| **处理进行中**又提交相同签名（并发重复） | 立即拒绝，不执行业务 | 409 | `concurrent_duplicate` |
| **已成功完成**后又提交相同签名（重放） | 拒绝并返回首次结果 | 409 | `idempotency_replay` |

- 重放响应的 `error.details.cached_result` 带回首次成功结果，方便调用方对齐状态。
- 并发重复**不会排队等待**，而是立即得到 `concurrent_duplicate`，调用方可稍后重查。

### 并发下为什么不会执行两次

`ReplayStore` 用锁保护状态迁移：多线程同时 `begin()` 同一个 key 时，
只有一个线程能从"无记录"迁到"进行中"，其余线程在锁内看到记录已存在，
直接得到 `concurrent_duplicate`。业务 handler 因此对同一签名键只可能运行一次。

### 失败可重试

业务处理中抛任何异常（业务校验失败、下游故障、未知系统错误），
守卫都会调用 `fail()` **删除该 key 的占位**。因此：

- 不会留下"占着坑但没做成"的状态；
- 调用方用**相同签名**稍后重试是被允许的（这不算重放，因为上一次并未成功）。

## 6. 错误映射与"不做一半"的副作用

### 统一错误信封

所有错误都返回统一结构，内部异常与堆栈绝不透出：

```json
{ "error": { "code": "<稳定错误码>", "message": "<面向调用方的安全描述>", "details": { } } }
```

| 类别 | 例子 | HTTP |
| --- | --- | --- |
| 信任边界错误 | `missing_credential` / `unknown_principal` / `body_tampered` / `signature_mismatch` / `timestamp_*` | 401 |
| 授权错误 | `scope_denied` / `scope_insufficient` | 403 |
| 幂等冲突 | `idempotency_replay` / `concurrent_duplicate` | 409 |
| 业务错误 | `invalid_request`(400) / `account_not_found`(404) / `account_exists`(409) / `insufficient_funds`(422) | 4xx |
| 下游依赖故障 | `downstream_unavailable` | 502 |
| 未知系统错误 | `internal_error`（唯一对外文案，堆栈只进服务端日志） | 500 |

### 补偿式事务

示例转账分三步：**借记 → 贷记 → 下游记账**。任一步失败都会执行补偿
（撤销前两步），使余额恢复到调用前状态，不会留下"借了没贷"之类的半成品。
配合幂等层"失败即清除占位"，调用方随后可安全重试。

## 7. 可观测性

守卫日志记录器 `zero_trust.guard` 对每次判定打印一行，包含：

- 结论：`decision=ALLOW` / `decision=DENY reason=<code>` / `decision=FAIL`；
- 请求特征（不含密钥与原始正文）：`key_id`、`timestamp`、`nonce`、`scope`、
  `method`、`path`、`body_sha256`、`signature`。

例如：

```
trust decision=DENY reason=signature_mismatch feature={'key_id': 'svc-accounts', 'nonce': 'n1', 'signature': '...', 'body_sha256': '...', ...}
trust decision=ALLOW scope=transfers:write key_id=svc-transfers nonce=t1 sig=... feature={...}
```

这样单测与线上日志都能直接看到"请求长什么样、为什么放行或拒绝"。

## 8. 设计边界与注意事项

- 当前幂等存储是**单进程内存实现**（线程安全）。多副本/多进程部署时，
  应替换为带原子 `SETNX`/唯一约束的共享存储（如 Redis、数据库），
  `ReplayStore` 的 `begin/complete/fail` 形状即为此预留。
- 时间窗口只能限制"陈旧请求"的有效期；真正的一次性保证来自幂等键。
- nonce 本身不要求服务端记忆唯一性——它通过参与签名并入 `(key_id, signature)`
  去重键间接生效；调用方仍应为每个新请求生成唯一 nonce。
