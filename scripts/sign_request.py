#!/usr/bin/env python3
"""零信任请求签名客户端（本地验证用）。

用法：
    # 1) 起服务
    uv run uvicorn main:app --port 8000

    # 2) 正常签名请求
    uv run python scripts/sign_request.py \
        --url http://127.0.0.1:8000/v1/accounts \
        --key-id svc-accounts --secret secret-accounts \
        --scope accounts:write --nonce n-001 \
        --data '{"name":"alice","opening_balance":100}'

    # 3) 观察不同拒绝原因：
    #    过期：       --age 400
    #    未来时间戳： --future 120
    #    错误密钥：   --secret wrong
    #    篡改 body：  --tamper
    #    作用域不足： --scope transfers:write --key-id svc-accounts
    #    重放：       同一条命令执行两次（相同 key+nonce+timestamp+body）
"""
from __future__ import annotations

import argparse
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.security import sign  # noqa: E402


def main() -> int:
    p = argparse.ArgumentParser(description="发送带零信任签名的请求")
    p.add_argument("--url", required=True)
    p.add_argument("--key-id", required=True)
    p.add_argument("--secret", required=True)
    p.add_argument("--scope", required=True)
    p.add_argument("--nonce", default=f"nonce-{int(time.time())}")
    p.add_argument("--data", default="{}")
    p.add_argument("--method", default="POST")
    p.add_argument("--age", type=int, default=0, help="把时间戳设为 now-age 秒（制造过期）")
    p.add_argument("--future", type=int, default=0, help="把时间戳设为 now+future 秒（制造未来时间）")
    p.add_argument("--tamper", action="store_true", help="签名后篡改实际发送的 body")
    args = p.parse_args()

    body = args.data.encode("utf-8")
    ts = int(time.time()) - args.age + args.future
    path = urlsplit(args.url).path

    digest, signature = sign(
        secret=args.secret,
        key_id=args.key_id,
        timestamp=ts,
        nonce=args.nonce,
        scope=args.scope,
        method=args.method,
        path=path,
        body=body,
    )
    headers = {
        "Content-Type": "application/json",
        "X-ZT-Key-Id": args.key_id,
        "X-ZT-Timestamp": str(ts),
        "X-ZT-Nonce": args.nonce,
        "X-ZT-Scope": args.scope,
        "X-ZT-Body-Sha256": digest,
        "X-ZT-Signature": signature,
    }

    sent_body = b'{"name":"mallory"}' if args.tamper else body
    req = urllib.request.Request(args.url, data=sent_body, headers=headers, method=args.method)
    print(f"canonical timestamp={ts} nonce={args.nonce} scope={args.scope} path={path}")
    print(f"signature={signature}")
    try:
        with urllib.request.urlopen(req) as resp:
            print(f"HTTP {resp.status}")
            print(resp.read().decode())
            return 0
    except urllib.error.HTTPError as e:
        print(f"HTTP {e.code}")
        print(e.read().decode())
        return 1


if __name__ == "__main__":
    sys.exit(main())
