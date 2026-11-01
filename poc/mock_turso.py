#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mock_turso.py —— 本地"假 Turso"（只实现 /v2/pipeline），用来在没有 Turso 账号时
把 Worker 的 5 个接口完整跑一遍。

为什么要有它：真 Turso 要注册拿 token；但 Worker 里所有 SQL 都能在本地 SQLite 上验证
（Turso 就是 libSQL = SQLite 分支），所以"SQL 能不能跑、索引有没有走到、状态机对不对"
这几件事现在就能验，不用等账号。

用法：
    python mock_turso.py --db poc/local.db --port 8788
    # Worker 侧把 TURSO_URL 指到 http://127.0.0.1:8788，TURSO_TOKEN 随便填

只支持本 PoC 用到的子集：单条 execute + close、? 占位、null/integer/text 三种参数。
返回结构与 Turso 一致：{"results":[{"type":"ok","response":{"type":"execute","result":{"cols":[],"rows":[]}}}]}
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DB = ""


def _val(cell):
    if cell is None:
        return {"type": "null", "value": None}
    if isinstance(cell, int):
        return {"type": "integer", "value": str(cell)}
    if isinstance(cell, float):
        return {"type": "real", "value": str(cell)}
    return {"type": "text", "value": str(cell)}


def _arg(a):
    t = (a or {}).get("type")
    v = (a or {}).get("value")
    if t == "null" or v is None:
        return None
    if t == "integer":
        return int(v)
    if t == "real":
        return float(v)
    return v          # text / blob 都按字符串处理（PoC 够用）


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):       # 安静点
        pass

    def _json(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):                                   # noqa: N802
        n = int(self.headers.get("Content-Length") or 0)
        try:
            req = json.loads(self.rfile.read(n).decode() or "{}")
        except ValueError:
            return self._json(400, {"error": "bad json"})

        results = []
        conn = sqlite3.connect(DB, timeout=10)
        conn.row_factory = None
        try:
            for r in req.get("requests") or []:
                if r.get("type") == "close":
                    results.append({"type": "ok", "response": {"type": "close"}})
                    continue
                if r.get("type") != "execute":
                    continue
                st = r.get("stmt") or {}
                q = st.get("sql") or ""
                args = [_arg(a) for a in (st.get("args") or [])]
                try:
                    cur = conn.execute(q, args)
                    rows = cur.fetchall() if cur.description else []
                    cols = ([{"name": d[0]} for d in cur.description]
                            if cur.description else [])
                    results.append({"type": "ok", "response": {"type": "execute", "result": {
                        "cols": cols,
                        "rows": [[_val(c) for c in row] for row in rows],
                        "affected_row_count": cur.rowcount if cur.rowcount > 0 else 0,
                    }}})
                    conn.commit()
                except Exception as e:                   # noqa: BLE001
                    results.append({"type": "error",
                                    "error": {"message": f"{type(e).__name__}: {e}"}})
                    break
        finally:
            conn.close()
        self._json(200, {"results": results})

    def do_GET(self):                                    # noqa: N802
        # 只给本地调试用
        if self.path == "/health":
            return self._json(200, {"ok": True, "db": DB})
        self._json(404, {"ok": False})


def main():
    global DB
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True)
    ap.add_argument("--port", type=int, default=8788)
    a = ap.parse_args()
    DB = os.path.abspath(a.db)
    srv = ThreadingHTTPServer(("127.0.0.1", a.port), H)
    srv.daemon_threads = True
    print(f"mock turso → http://127.0.0.1:{a.port}  db={DB}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    sys.exit(main())
