#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""trace_post.py —— 在 Actions 里把 decode_trace.py 的结果回写给 Worker。

为什么单独一个脚本而不是在工作流里写 heredoc：
    run: | 里如果有顶格的 heredoc，YAML 会被打断，workflow 直接 422
    （2026-11-22 真实事故）。把逻辑放进 .py，工作流只留一行调用。

读取：
    work/out.txt          decode_trace.py 的 stdout（含 TRACE_JSON= 一行）
    work/err.txt          stderr（失败时把尾巴带回去）
    env: WORKER / JOB_ID / TRACE_TOKEN
"""
import json
import os
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.join(HERE, "..", "work")


def read(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def post(url, token, payload):
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST", headers={
        "Content-Type": "application/json",
        "X-Trace-Token": token,
        "User-Agent": "wm-trace/1.0",
    })
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(req, timeout=60) as r:
        return r.status, r.read()[:200]


def main():
    worker = (os.environ.get("WORKER") or "").rstrip("/")
    job_id = os.environ.get("JOB_ID") or ""
    token = os.environ.get("TRACE_TOKEN") or ""
    if not (worker and job_id and token):
        print("缺 WORKER / JOB_ID / TRACE_TOKEN", file=sys.stderr)
        return 2

    out = read(os.path.join(WORK, "out.txt"))
    err = read(os.path.join(WORK, "err.txt"))

    line = ""
    for ln in out.splitlines():
        if ln.startswith("TRACE_JSON="):
            line = ln[len("TRACE_JSON="):]
    if line:
        try:
            result = json.loads(line)
        except Exception:                      # noqa: BLE001
            result = {"ok": False, "reason": "结果不是合法 JSON"}
            line = ""
        ok = bool(result.get("ok"))
        payload = {"job_id": job_id, "ok": ok, "result": result,
                   "reason": "" if ok else "未命中：文件里没有可识别的水印"}
    else:
        # 没有 JSON 行 = 解码脚本本身挂了（缺依赖 / 文件损坏 / 引擎报错）
        tail = (err or out).strip().splitlines()[-6:]
        payload = {"job_id": job_id, "ok": False, "result": {},
                   "reason": "解码失败：" + " | ".join(tail)[:280]}

    st, body = post(worker + "/internal/trace/result", token, payload)
    print("回调 HTTP %s %s" % (st, body.decode("utf-8", "replace")))
    return 0 if st == 200 else 1


if __name__ == "__main__":
    sys.exit(main())
