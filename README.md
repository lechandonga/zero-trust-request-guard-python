# Zero-Trust Request Guard（Python / FastAPI）

在 API 服务的信任边界上为所有**改动状态**的接口统一加上：

1. **零信任请求校验**：可验证的来源标识（HMAC 签名）、时间戳、作用域；
   篡改签名/内容、时间戳过期、作用域不足等情况分别给出**可区分**的错误码。
2. **幂等与重放防护**：同一签名请求（含并发重复提交）只真正生效一次，
   重放与并发重复分别用不同结论识别；并发下不会执行两次。
3. **失败不留半成品**：业务/下游失败时执行补偿并清除幂等占位；
   业务错误、下游错误、系统错误映射成不同响应，内部异常与堆栈不外泄。

规则细节（头部、签名算法、判定顺序、作用域、时间窗口边界、重放/并发语义）见
[`docs/trust-model.md`](docs/trust-model.md)。

## 目录结构

```
app/
  errors.py     # 统一错误分类与稳定错误码（信任/业务/系统）
  security.py   # 主体目录、规范串/签名、8 步信任判定、时间窗口
  replay.py     # 线程安全幂等存储（进行中/已完成/失败清除/TTL）
  guard.py      # 信任守卫：校验 -> 幂等占位 -> 恰好一次执行，判定日志
  services.py   # 示例业务：开户 + 补偿式转账 + 可脚本化下游
  routes.py     # 写接口统一经过 TrustGuard；只读接口不签名
  app.py        # 应用装配 + 统一错误信封映射
scripts/
  sign_request.py  # 本地用的签名客户端，可构造各种被拒场景
tests/
  test_security.py  # 8 种判定结论 + 时间窗口闭区间边界
  test_replay.py    # 存储状态机 + 守卫级并发恰好一次
  test_http.py      # 端到端：篡改/过期/越权/重放/并发/回滚/错误映射/日志
docs/
  trust-model.md
```

## 快速开始

需要 Python 3.14+，依赖通过 [uv](https://docs.astral.sh/uv/) 管理。

```bash
uv sync                 # 安装依赖（含 dev 组的 pytest）
uv run uvicorn main:app --host 127.0.0.1 --port 8000
```

健康检查与只读余额（无需签名）：

```bash
curl http://127.0.0.1:8000/healthz
curl http://127.0.0.1:8000/v1/accounts
```

## 发送一个签名请求

```bash
uv run python scripts/sign_request.py \
  --url http://127.0.0.1:8000/v1/accounts \
  --key-id svc-accounts --secret secret-accounts \
  --scope accounts:write --nonce n-001 \
  --data '{"name":"alice","opening_balance":100}'
```

脚本会打印规范时间戳与签名，成功返回：

```
HTTP 201
{"name":"alice","balance":100,"status":"opened"}
```

> 如果本地走了 HTTP 代理，记得让 localhost 直连：
> `export NO_PROXY=127.0.0.1,localhost no_proxy=127.0.0.1,localhost`。

## 本地验证各种拒绝原因

| 场景 | 命令关键参数 | 预期结论 |
| --- | --- | --- |
| 签名/头部被改 | `--secret wrong`（或改 nonce） | 401 `signature_mismatch` |
| 请求体被改 | `--tamper` | 401 `body_tampered` |
| 时间戳过期 | `--age 400` | 401 `timestamp_expired` |
| 时间戳超前太多 | `--future 120` | 401 `timestamp_in_future` |
| 主体未登记 | `--key-id ghost ...` | 401 `unknown_principal` |
| 主体未被授予该作用域 | `svc-accounts` 声明 `transfers:write` | 403 `scope_denied` |
| 作用域不覆盖路由 | `svc-admin` 用 `accounts:write` 调 `/v1/transfers` | 403 `scope_insufficient` |
| 缺少头部 | 去掉某个 `X-ZT-*` 头 | 401 `missing_credential` |

### 重放（顺序重复提交）

用**完全相同**的 `key-id + nonce + body + 时间戳`把同一条命令再发一次：

```bash
# 第一次 201；第二次：
HTTP 409
{"error":{"code":"idempotency_replay", "details":{"cached_result":{...首次结果...}}}}
```

### 并发重复提交

并发用同一签名发起多个请求：恰好一个 `201`，其余立即得到
`409 concurrent_duplicate`；余额只变化一次、下游只记一次账。
该行为由测试 `tests/test_http.py::test_concurrent_duplicates_exactly_once_http`
和 `tests/test_replay.py::test_guard_concurrent_duplicates_execute_once` 覆盖。

### 失败回滚与可重试

下游不可用时转账返回 `502 downstream_unavailable`，余额不变（借记/贷记被补偿），
幂等占位被清除；下游恢复后用**相同签名**重试可成功（不算重放）。
未知内部异常统一返回 `500 internal_error`，响应中不含任何内部信息或堆栈。

## 运行测试

```bash
uv run pytest                 # 全部 35 个用例
uv run pytest -q              # 简洁输出
uv run pytest tests/test_security.py -v   # 只看信任判定
```

测试运行时以 INFO 级别打印守卫日志，可直接看到每个请求的**特征**
（key_id / nonce / scope / body_sha256 / signature）与**判定依据**
（`decision=ALLOW|DENY reason=...`）。

## 时间窗口速查

合法时间戳满足闭区间：`floor(now)-300 <= timestamp <= floor(now)+30`。
踩在 `-300` / `+30` 边界上的请求仍然接受，超出 1 秒才拒绝。
