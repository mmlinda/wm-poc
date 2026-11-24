#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""poc_check.py —— PoC 第 1 步的冒烟脚本（零依赖，只用标准库）

做三件事：
  1. 用 Turso 的 HTTP pipeline API 建表 + 写一行 + 读回来（证明"Python 能读写"）
  2. 复算 Worker 那个一次性 token 的 HMAC（证明"两边算法一致"，不然 Actions 永远 401）
  3. 打印 R2 需要你手动跑的两条 curl（S3 API 需要 SigV4，脚本不重复造轮子）

用法：
    set TURSO_URL=https://xxx-yyy.turso.io
    set TURSO_TOKEN=eyJ...
    python poc_check.py turso
    python poc_check.py token --secret mysecret --batch poc-1
    python poc_check.py r2 --bucket wm-bucket --key books/1/1.epub

退出码 0 = 通过。
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import sys
import time
import urllib.request

TURSO_URL = os.environ.get("TURSO_URL", "").rstrip("/")
TURSO_TOKEN = os.environ.get("TURSO_TOKEN", "")


def _arg(v):
    if v is None:
        return {"type": "null", "value": None}
    if isinstance(v, int):
        return {"type": "integer", "value": str(v)}
    return {"type": "text", "value": str(v)}


def sql(q, args=()):
    body = json.dumps({"requests": [
        {"type": "execute", "stmt": {"sql": q, "args": [_arg(a) for a in args]}},
        {"type": "close"}]}).encode()
    req = urllib.request.Request(
        TURSO_URL + "/v2/pipeline", data=body,
        headers={"Authorization": "Bearer " + TURSO_TOKEN,
                 "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        d = json.loads(r.read().decode())
    first = d["results"][0]
    if first.get("type") == "error":
        raise RuntimeError(first["error"])
    res = (first.get("response") or {}).get("result") or {}
    cols = [c["name"] for c in res.get("cols") or []]
    rows = [[c.get("value") if isinstance(c, dict) else c for c in row]
            for row in res.get("rows") or []]
    return cols, rows


def cmd_turso(a):
    if not (TURSO_URL and TURSO_TOKEN):
        print("先设置 TURSO_URL / TURSO_TOKEN 环境变量")
        return 2
    print("① 建表（执行 poc/schema.sql）")
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "schema.sql"), encoding="utf-8") as f:
        stmts = [s.strip() for s in f.read().split(";") if s.strip()
                 and not s.strip().startswith("--")]
    # Turso pipeline 一次执行多条：逐条发，失败即停
    for s in stmts:
        try:
            sql(s)
        except Exception as e:                       # noqa: BLE001
            print("   × 失败：", s.splitlines()[0][:60], "→", str(e)[:120])
            print("   提示：INSERT OR IGNORE / PRAGMA 这类语句在 pipeline 里可能被拒，可以手动跑")
    print("   √ 建表流程结束")

    print("② 写一行（batches）")
    t0 = time.time()
    sql("INSERT OR REPLACE INTO batches(id,admin_id,total,status) VALUES(?,?,?,?)",
        ("poc-" + str(int(time.time())), 1, 3, "queued"))
    w = (time.time() - t0) * 1000

    print("③ 读回来（按主键）")
    t0 = time.time()
    cols, rows = sql("SELECT id,status,total FROM batches ORDER BY created_at DESC LIMIT 1")
    r = (time.time() - t0) * 1000
    print("   cols:", cols)
    print("   row :", rows[0] if rows else "(空)")
    ok = bool(rows) and rows[0][1] == "queued"
    print(f"\n   写 {w:.0f}ms / 读 {r:.0f}ms  →  {'通过' if ok else '失败'}")
    return 0 if ok else 1


def cmd_token(a):
    """复算 Worker 里的 token：base64url(purpose|batch|exp).base64url(hmac)"""
    def b64u(b):
        return base64.urlsafe_b64encode(b).decode().rstrip("=")

    exp = int(time.time()) + a.ttl
    body = f"{a.purpose}|{a.batch}|{exp}"
    sig = b64u(hmac.new(a.secret.encode(), body.encode(), hashlib.sha256).digest())
    tok = b64u(body.encode()) + "." + sig
    print("token =", tok)
    print("\n拿它调 Worker：")
    print(f'  curl -sS -X POST "$WORKER/internal/batch/{a.batch}" -H "X-Act-Token: {tok}"')
    print("\n注意：Worker 侧 checkToken 也用 Web Crypto HMAC-SHA256 + base64url，")
    print("      两边对不上就会 401 —— 这个脚本就是为了在接入 Actions 前先对齐。")
    return 0


def cmd_r2(a):
    print("R2 的 S3 API 需要 SigV4 签名，这里不重复实现，用 aws cli 最省事：\n")
    print("# 1) 配置（R2 控制台 → Manage R2 API Tokens → 生成 Access Key / Secret）")
    print("set R2_ACCOUNT=xxxxxxxx")
    print("set AWS_ACCESS_KEY_ID=...")
    print("set AWS_SECRET_ACCESS_KEY=...")
    print("set R2_ENDPOINT=https://%R2_ACCOUNT%.r2.cloudflarestorage.com\n")
    print(f"# 2) 上传（Actions 里就是这么推成品）")
    print(f'aws --endpoint-url %R2_ENDPOINT% s3 cp test.epub s3://{a.bucket}/{a.key}\n')
    print(f"# 3) 列一下核对")
    print(f'aws --endpoint-url %R2_ENDPOINT% s3 ls s3://{a.bucket}/ --recursive --human-readable\n')
    print("# 4) 计时（PoC 要记的数）：上传 1 个 12MB 文件的秒数")
    print(f'powershell -c "Measure-Command {{ aws --endpoint-url $env:R2_ENDPOINT s3 cp test.epub s3://{a.bucket}/{a.key} }}"')
    return 0


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    p1 = sub.add_parser("turso", help="建表 + 读写冒烟")
    p1.set_defaults(fn=cmd_turso)

    p2 = sub.add_parser("token", help="复算 Actions 一次性 token")
    p2.add_argument("--secret", required=True)
    p2.add_argument("--batch", default="poc-1")
    p2.add_argument("--purpose", default="act")
    p2.add_argument("--ttl", type=int, default=900)
    p2.set_defaults(fn=cmd_token)

    p3 = sub.add_parser("r2", help="打印 R2 的手动验证命令")
    p3.add_argument("--bucket", default="wm-bucket")
    p3.add_argument("--key", default="books/1/1.epub")
    p3.set_defaults(fn=cmd_r2)

    a = ap.parse_args()
    sys.exit(a.fn(a))


if __name__ == "__main__":
    main()
