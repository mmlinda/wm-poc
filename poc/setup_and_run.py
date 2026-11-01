#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""setup_and_run.py —— 一键配置 + 一键校验 + 自动跑 PoC（纯标准库，不需要 pip install）

它做的事，按顺序：
  1. 交互式问你要 5 组凭据（已有 .env.poc 就按回车沿用；可选项直接回车跳过）
  2. 当场校验：Turso 能不能查询、GitHub PAT 有没有权限、R2 的 S3 口通不通、CF Token 是否有效
  3. 校验通过 → 写 .env.poc（**这个文件别上传到任何仓库**）
  4. 可选：用 CF API 直接把 worker_poc.js 部署上去（有 KV 命名空间、R2 绑定、Secrets）
  5. 接着跑 P1~P6 并把数字打在屏幕上

用法：
    python poc/setup_and_run.py                # 全流程（会问你要凭据）
    python poc/setup_and_run.py --reuse        # 复用 .env.poc，只跑
    python poc/setup_and_run.py --only p1,p2   # 只跑指定步骤
    python poc/setup_and_run.py --skip-run     # 只配 + 校验 + 落盘，不跑
    python poc/setup_and_run.py --p6 5         # 额外做一次 5 并发实测

⚠️ 三个必须知道的点：
   · 本脚本会把凭据明文写进 `poc/.env.poc`（权限 600）。**绝不要提交到 git、绝不要传到 GitHub 仓库**。
   · 校验失败会**停下来**并告诉你是哪一项、怎么修；不会带着错配置去跑。
   · 没给 R2 就自动跳过 P3；没给 CF Token 就跳过 Worker 部署，P4 用"direct 模式"替代。
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
import io as _io

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
ENV_PATH = os.path.join(HERE, ".env.poc")
WORKER_JS = os.path.join(HERE, "worker_poc.js")
SCHEMA_SQL = os.path.join(HERE, "schema.sql")
APP_PY = os.path.join(ROOT, "wm-portal", "app.py")

UA = "wm-poc-setup/1.0"
RESULTS = []          # [(step, ok, detail)]


# ============================================================== 输出/交互
def hr(t=""):
    print("\n" + (("── %s " % t).ljust(72, "─") if t else "─" * 72))


def ok(msg):
    print("  \033[32m✔\033[0m " + msg, flush=True)


def bad(msg):
    print("  \033[31m✘\033[0m " + msg, flush=True)


def warn(msg):
    print("  \033[33m!\033[0m " + msg, flush=True)


def info(msg):
    print("    " + msg, flush=True)


def ask(label, key, env, secret=False, optional=False, default=""):
    """交互取一个值。回车＝沿用旧值/默认值；可选项回车且无旧值＝跳过。"""
    cur = env.get(key, default)
    shown = ("*" * min(8, len(cur)) + "…") if (secret and cur) else (cur or "")
    tip = "（回车沿用 %s）" % shown if cur else ("（没有就回车跳过）" if optional else "")
    while True:
        try:
            raw = input("  %s %s: " % (label, tip)).strip()
        except (EOFError, KeyboardInterrupt):
            print("\n已取消。")
            sys.exit(130)
        if raw:
            return raw
        if cur:
            return cur
        if optional:
            return ""
        bad("这一项必填，再输一次（或 Ctrl+C 退出）")


# ============================================================== HTTP
def http(method, url, headers=None, body=None, timeout=30, follow=True):
    """返回 (status, headers(dict), bytes)。4xx/5xx 不抛异常，方便判断。"""
    h = {"User-Agent": UA}
    h.update(headers or {})
    req = urllib.request.Request(url, data=body, headers=h, method=method)
    ctx = ssl.create_default_context()
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ctx),
        *([] if follow else [urllib.request.HTTPRedirectHandler()]))
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), e.read()
    except urllib.error.URLError as e:
        return 0, {}, str(e.reason).encode()
    except (socket.timeout, TimeoutError):
        return 0, {}, b"timeout"


def jload(b, default=None):
    try:
        return json.loads(b.decode("utf-8"))
    except Exception:                                    # noqa: BLE001
        return default


# ============================================================== 校验：Turso
def norm_turso(u):
    u = (u or "").strip().rstrip("/")
    if u.startswith("libsql://"):
        u = "https://" + u[len("libsql://"):]
    if u and not u.startswith("http"):
        u = "https://" + u
    return u


def turso_pipeline(url, token, stmts, timeout=30):
    """stmts: [(sql, [args...])]；一次发送多条，返回 (ok, 每条的结果列表, 原始)"""
    reqs = [{"type": "execute", "stmt": {"sql": q, "args": [_arg(a) for a in args]}}
            for q, args in stmts]
    reqs.append({"type": "close"})
    body = json.dumps({"requests": reqs}).encode()
    st, _h, rb = http("POST", norm_turso(url) + "/v2/pipeline",
                      {"Authorization": "Bearer " + token,
                       "Content-Type": "application/json"}, body, timeout=timeout)
    d = jload(rb, {}) or {}
    out = []
    for r in d.get("results") or []:
        if r.get("type") == "error":
            out.append(("error", r.get("error", {}).get("message", "")))
        else:
            res = (r.get("response") or {}).get("result") or {}
            cols = [c.get("name") for c in res.get("cols") or []]
            rows = [[(c.get("value") if isinstance(c, dict) else c) for c in row]
                    for row in res.get("rows") or []]
            out.append(("ok", {"cols": cols, "rows": rows}))
    return st, out, rb


def _arg(v):
    if v is None:
        return {"type": "null", "value": None}
    if isinstance(v, int):
        return {"type": "integer", "value": str(v)}
    return {"type": "text", "value": str(v)}


def check_turso(env_):
    url, tok = norm_turso(env_.get("TURSO_URL")), env_.get("TURSO_TOKEN", "")
    if not url or not tok:
        return False, "缺少 TURSO_URL / TURSO_TOKEN"
    t0 = time.time()
    st, out, raw = turso_pipeline(url, tok, [("SELECT 1 AS ok", [])])
    ms = (time.time() - t0) * 1000
    if st != 200:
        return False, "HTTP %s：%s" % (st, raw[:160].decode("utf-8", "replace"))
    if not out or out[0][0] != "ok":
        return False, "查询失败：%s" % (out[0][1] if out else "空响应")
    return True, "SELECT 1 通过，往返 %.0f ms" % ms


# ============================================================== 校验：GitHub
GH = "https://api.github.com"


def gh_headers(pat):
    return {"Authorization": "Bearer " + pat,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"}


def check_github(env_):
    repo, pat = env_.get("GH_REPO", ""), env_.get("GH_PAT", "")
    wf = env_.get("WF_FILE", "watermark_poc.yml")
    if not repo or not pat:
        return False, "缺少 GH_REPO / GH_PAT"
    if not re.fullmatch(r"[\w.-]+/[\w.-]+", repo):
        return False, "GH_REPO 要写成 owner/repo（现在：%r）" % repo

    st, _h, b = http("GET", "%s/repos/%s" % (GH, repo), gh_headers(pat))
    if st == 401:
        return False, "PAT 无效或已过期（401）"
    if st == 404:
        return False, "仓库不存在，或 PAT 没授权这个仓库（404）"
    if st != 200:
        return False, "GET /repos 返回 %s" % st
    r = jload(b, {}) or {}
    if r.get("private"):
        warn("这个仓库是 private：Actions 免费额度只有 2000 分钟/月（约 2~3 批 200 本）。"
             "PoC 能用，正式上线必须换 public。")

    st2, _h, b2 = http("GET", "%s/repos/%s/actions/workflows" % (GH, repo), gh_headers(pat))
    if st2 != 200:
        return False, ("PAT 缺 Actions 权限（GET /actions/workflows → %s）"
                       "。fine-grained token 要勾 'Actions: Read and write'" % st2)
    wfs = (jload(b2, {}) or {}).get("workflows") or []
    hit = [w for w in wfs if (w.get("path") or "").endswith("/" + wf) or w.get("name") == "watermark-poc"]
    if not hit:
        return False, ("仓库里没找到工作流 %s。把它放到 .github/workflows/%s 再推一次"
                       % (wf, wf))
    return True, "仓库可访问（%s），工作流已就位（id=%s）" % (
        "private" if r.get("private") else "public", hit[0].get("id"))


# ============================================================== 校验：R2（SigV4）
def _sign(key, msg):
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def r2_request(env_, method, key_path, query="", body=b"", content_type="", region="auto"):
    """对 R2 的 S3 API 发一次签名请求。key_path 不含 bucket（内部拼）。"""
    endpoint = (env_.get("R2_ENDPOINT") or "").rstrip("/")
    ak, sk = env_.get("R2_AK", ""), env_.get("R2_SK", "")
    bucket = env_.get("R2_BUCKET", "")
    if not (endpoint and ak and sk and bucket):
        return 0, {}, b"missing creds"
    u = urllib.parse.urlsplit(endpoint)
    host = u.netloc
    uri = "/%s%s" % (bucket, ("/" + key_path) if key_path else "")
    uri = urllib.parse.quote(uri, safe="/-_.~")

    now = time.gmtime()
    amzdate = time.strftime("%Y%m%dT%H%M%SZ", now)
    datestamp = amzdate[:8]
    payload_hash = hashlib.sha256(body).hexdigest()
    headers = {"host": host, "x-amz-content-sha256": payload_hash, "x-amz-date": amzdate}
    if content_type:
        headers["content-type"] = content_type
    signed_keys = sorted(headers)
    signed = ";".join(signed_keys)
    canon_headers = "".join("%s:%s\n" % (k, headers[k]) for k in signed_keys)

    # 查询串要按参数名排序并重新编码
    q = ""
    if query:
        parts = urllib.parse.parse_qsl(query, keep_blank_values=True)
        q = "&".join("%s=%s" % (urllib.parse.quote(k, safe="-_.~"),
                                urllib.parse.quote(v, safe="-_.~"))
                     for k, v in sorted(parts))
    canon = "\n".join([method, uri, q, canon_headers, signed, payload_hash])
    scope = "%s/%s/s3/aws4_request" % (datestamp, region)
    sts = "\n".join(["AWS4-HMAC-SHA256", amzdate, scope,
                     hashlib.sha256(canon.encode()).hexdigest()])
    k = _sign(("AWS4" + sk).encode(), datestamp)
    k = _sign(k, region)
    k = _sign(k, "s3")
    k = _sign(k, "aws4_request")
    sig = hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()

    hdr = {"x-amz-content-sha256": payload_hash, "x-amz-date": amzdate,
           "Authorization": "AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s"
                            % (ak, scope, signed, sig)}
    if content_type:
        hdr["Content-Type"] = content_type
    url = "%s%s%s" % (endpoint, uri, ("?" + q) if q else "")
    return http(method, url, hdr, body or None, timeout=30)


def check_r2(env_):
    if not (env_.get("R2_ENDPOINT") and env_.get("R2_AK")):
        return None, "未配置（跳过）"
    t0 = time.time()
    st, _h, b = r2_request(env_, "GET", "", "list-type=2&max-keys=1")
    ms = (time.time() - t0) * 1000
    if st == 200:
        n = re.search(rb"<KeyCount>(\d+)</KeyCount>", b or b"")
        return True, "ListObjects 通过，往返 %.0f ms（桶里现有 %s 个对象）" % (
            ms, n.group(1).decode() if n else "?")
    if st == 403:
        return False, ("403：签名被拒。检查 AK/SK 是否是「Object Read & Write」且范围含这个桶；"
                       "Endpoint 要写成 https://<accountid>.r2.cloudflarestorage.com")
    if st == 404:
        return False, "404：桶不存在（R2_BUCKET=%r）" % env_.get("R2_BUCKET")
    return False, "HTTP %s：%s" % (st, (b or b"")[:160].decode("utf-8", "replace"))


# ============================================================== 校验：Cloudflare
def cf_api(env_, method, path, body=None):
    tok = env_.get("CF_API_TOKEN", "")
    h = {"Authorization": "Bearer " + tok, "Content-Type": "application/json"}
    return http(method, "https://api.cloudflare.com/client/v4" + path, h,
                json.dumps(body).encode() if body is not None else None, timeout=40)


def check_cf(env_):
    if not env_.get("CF_API_TOKEN"):
        return None, "未配置（跳过 Worker 自动部署）"
    st, _h, b = cf_api(env_, "GET", "/user/tokens/verify")
    d = jload(b, {}) or {}
    if st != 200 or (d.get("result") or {}).get("status") != "active":
        return False, "Token 无效/未激活（HTTP %s，%s）" % (st, str(d.get("errors"))[:120])
    acc = env_.get("CF_ACCOUNT_ID", "")
    if acc:
        st2, _h2, b2 = cf_api(env_, "GET", "/accounts/" + acc)
        if st2 != 200:
            return False, "Account ID 不对（GET /accounts/%s → %s）" % (acc, st2)
    return True, "Token 有效%s" % ("，Account 校验通过" if acc else "（未填 Account ID，部署时需要）")


# ============================================================== Worker 部署
def cf_kv_namespace(env_, title="wm_poc_kv"):
    acc = env_["CF_ACCOUNT_ID"]
    st, _h, b = cf_api(env_, "GET", "/accounts/%s/storage/kv/namespaces?per_page=100" % acc)
    d = jload(b, {}) or {}
    for ns in (d.get("result") or []):
        if ns.get("title") == title:
            return ns["id"]
    st, _h, b = cf_api(env_, "POST", "/accounts/%s/storage/kv/namespaces" % acc, {"title": title})
    d = jload(b, {}) or {}
    if st not in (200, 201) or not d.get("success"):
        raise RuntimeError("建 KV 命名空间失败：%s" % str(d.get("errors"))[:200])
    return d["result"]["id"]


def cf_worker_subdomain(env_):
    acc = env_["CF_ACCOUNT_ID"]
    st, _h, b = cf_api(env_, "GET", "/accounts/%s/workers/subdomain" % acc)
    d = jload(b, {}) or {}
    sub = (d.get("result") or {}).get("subdomain")
    if sub:
        return sub
    # 没开通就尝试注册一个（失败不影响：用户可手动开）
    name = re.sub(r"[^a-z0-9-]", "", (env_.get("GH_REPO", "wm").split("/")[0] or "wm").lower())[:20] + "-wm"
    st, _h, b = cf_api(env_, "PUT", "/accounts/%s/workers/subdomain" % acc, {"subdomain": name})
    d = jload(b, {}) or {}
    return (d.get("result") or {}).get("subdomain") or ""


def _multipart(fields):
    """fields: [(name, filename_or_None, content_type, bytes)]"""
    boundary = "----wmpoc" + hashlib.md5(str(time.time()).encode()).hexdigest()[:16]
    out = _io.BytesIO()
    for name, filename, ctype, data in fields:
        out.write(("--%s\r\n" % boundary).encode())
        disp = 'Content-Disposition: form-data; name="%s"' % name
        if filename:
            disp += '; filename="%s"' % filename
        out.write((disp + "\r\n").encode())
        if ctype:
            out.write(("Content-Type: %s\r\n" % ctype).encode())
        out.write(b"\r\n" + data + b"\r\n")
    out.write(("--%s--\r\n" % boundary).encode())
    return out.getvalue(), "multipart/form-data; boundary=" + boundary


def deploy_worker(env_, name="wm-poc"):
    """用 CF API 上传 worker_poc.js（ES module + KV/R2 绑定 + Secrets）。"""
    acc = env_.get("CF_ACCOUNT_ID")
    if not acc:
        raise RuntimeError("缺 CF_ACCOUNT_ID")
    if not os.path.isfile(WORKER_JS):
        raise RuntimeError("找不到 %s" % WORKER_JS)

    ns = cf_kv_namespace(env_)
    sub = cf_worker_subdomain(env_)
    public_base = "https://%s.%s.workers.dev" % (name, sub) if sub else ""
    if not public_base:
        warn("拿不到 workers.dev 子域，PUBLIC_BASE 先留空（领取链接会不完整，但不影响接口校验）")

    bindings = [
        {"type": "kv_namespace", "name": "KV", "namespace_id": ns},
        {"type": "plain_text", "name": "GH_REPO", "text": env_["GH_REPO"]},
        {"type": "plain_text", "name": "WF_FILE", "text": env_.get("WF_FILE", "watermark_poc.yml")},
        {"type": "plain_text", "name": "GH_REF", "text": env_.get("GH_REF", "main")},
        {"type": "plain_text", "name": "TURSO_URL", "text": norm_turso(env_["TURSO_URL"])},
        {"type": "plain_text", "name": "PUBLIC_BASE", "text": public_base},
    ]
    if env_.get("R2_BUCKET"):
        bindings.append({"type": "r2_bucket", "name": "BUCKET", "bucket_name": env_["R2_BUCKET"]})

    meta = {"main_module": "worker_poc.js",
            "compatibility_date": "2026-10-01",
            "bindings": bindings,
            "observability": {"enabled": True}}
    body, ctype = _multipart([
        ("metadata", None, "application/json", json.dumps(meta).encode()),
        ("worker_poc.js", "worker_poc.js", "application/javascript+module",
         open(WORKER_JS, "rb").read()),
    ])
    st, _h, b = http("PUT", "https://api.cloudflare.com/client/v4/accounts/%s/workers/scripts/%s"
                     % (acc, name), {"Authorization": "Bearer " + env_["CF_API_TOKEN"],
                                     "Content-Type": ctype}, body, timeout=90)
    d = jload(b, {}) or {}
    if st not in (200, 201) or not d.get("success"):
        raise RuntimeError("上传脚本失败（HTTP %s）：%s" % (st, str(d.get("errors") or b[:200])[:400]))

    # Secrets：单独接口，避免落进脚本 metadata（那样在面板里能看到明文）
    secrets = {
        "GH_PAT": env_.get("GH_PAT", ""),
        "TURSO_TOKEN": env_.get("TURSO_TOKEN", ""),
        "CB_SECRET": env_.get("CB_SECRET", ""),
        "DL_SECRET": env_.get("DL_SECRET", ""),
        "POC_SERVER_SECRET": env_.get("POC_SERVER_SECRET", ""),
        "POC_DB_KEY": env_.get("POC_DB_KEY", ""),
    }
    failed = []
    for k, v in secrets.items():
        if not v:
            continue
        st, _h, b = cf_api(env_, "PUT", "/accounts/%s/workers/scripts/%s/secrets" % (acc, name),
                           {"name": k, "text": v, "type": "secret_text"})
        if st not in (200, 201):
            failed.append(k)
    env_["WORKER_URL"] = public_base
    if failed:
        warn("以下 Secret 写入失败，需要去面板补：%s" % ", ".join(failed))
    return public_base


# ============================================================== .env.poc
SECRET_KEYS = {"TURSO_TOKEN", "GH_PAT", "R2_AK", "R2_SK", "CF_API_TOKEN",
               "CB_SECRET", "DL_SECRET", "POC_SERVER_SECRET", "POC_DB_KEY"}
ALL_KEYS = ["TURSO_URL", "TURSO_TOKEN", "GH_REPO", "GH_PAT", "WF_FILE", "GH_REF",
            "R2_ENDPOINT", "R2_AK", "R2_SK", "R2_BUCKET",
            "CF_API_TOKEN", "CF_ACCOUNT_ID", "WORKER_URL",
            "CB_SECRET", "DL_SECRET", "POC_SERVER_SECRET", "POC_DB_KEY"]


def load_env():
    env_ = {}
    if os.path.isfile(ENV_PATH):
        for line in open(ENV_PATH, encoding="utf-8"):
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            env_[k.strip()] = v.strip()
    env_.update({k: v for k, v in os.environ.items() if k in ALL_KEYS and v})
    return env_


def save_env(env_):
    lines = ["# 由 poc/setup_and_run.py 生成 —— 含明文凭据，**不要提交到任何仓库**",
             "# 有效期：PoC 期间；跑完请在 Turso / GitHub / Cloudflare 后台吊销这些 token", ""]
    for k in ALL_KEYS:
        v = env_.get(k, "")
        if v:
            lines.append("%s=%s" % (k, v))
    with open(ENV_PATH, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")
    try:
        os.chmod(ENV_PATH, 0o600)
    except OSError:
        pass
    return ENV_PATH


# ============================================================== P1
def p1_turso(env_):
    """建表 + 写读 + 延迟"""
    hr("P1 · Turso 建表与读写")
    sql_txt = open(SCHEMA_SQL, encoding="utf-8").read()
    stmts = []
    for raw in sql_txt.split(";"):
        s = "\n".join(l for l in raw.splitlines() if not l.strip().startswith("--")).strip()
        if not s:
            continue
        if s.upper().startswith("PRAGMA"):
            continue
        stmts.append((s, []))
    t0 = time.time()
    st, out, raw = turso_pipeline(norm_turso(env_["TURSO_URL"]), env_["TURSO_TOKEN"], stmts, timeout=60)
    ms = (time.time() - t0) * 1000
    if st != 200:
        bad("建表失败：HTTP %s %s" % (st, raw[:200].decode("utf-8", "replace")))
        return False, "建表 HTTP %s" % st
    errs = [(i, r[1]) for i, r in enumerate(out) if r[0] == "error"]
    if errs:
        # 只报第一条，并指出是哪句（Turso 不兼容会在这里立刻暴露）
        idx, msg = errs[0]
        stmt = stmts[idx][0].splitlines()[0][:80] if idx < len(stmts) else "?"
        bad("有 %d 条语句执行失败，第一条：%s" % (len(errs), msg))
        info("出错语句：" + stmt)
        return False, "SQL 不兼容：%s" % msg
    ok("建表完成（%d 条语句，%.0f ms）" % (len(stmts), ms))

    # 写 + 读（带延迟）
    bid = "p1-" + str(int(time.time()))
    t0 = time.time()
    turso_pipeline(norm_turso(env_["TURSO_URL"]), env_["TURSO_TOKEN"],
                   [("INSERT OR REPLACE INTO batches(id,admin_id,total,status) VALUES(?,?,?,?)",
                     [bid, 1, 3, "queued"])])
    w = (time.time() - t0) * 1000
    t0 = time.time()
    _st, out, _r = turso_pipeline(norm_turso(env_["TURSO_URL"]), env_["TURSO_TOKEN"],
                                  [("SELECT status,done,total FROM batches WHERE id=?", [bid])])
    r = (time.time() - t0) * 1000
    row = out[0][1]["rows"][0] if out and out[0][0] == "ok" and out[0][1]["rows"] else []
    if row and row[0] == "queued":
        ok("写入 %.0f ms / 读回 %.0f ms，状态=%s" % (w, r, row[0]))
        return True, "写 %.0fms / 读 %.0fms" % (w, r)
    bad("写进去了但读不到：%r" % (row,))
    return False, "读写不一致"


# ============================================================== P2
def gh_dispatch(env_, batch_id, worker="", cb="", qqs="123450001"):
    repo = env_["GH_REPO"]
    wf = env_.get("WF_FILE", "watermark_poc.yml")
    st, _h, b = http("POST", "%s/repos/%s/actions/workflows/%s/dispatches" % (GH, repo, wf),
                     dict(gh_headers(env_["GH_PAT"]), **{"Content-Type": "application/json"}),
                     json.dumps({"ref": env_.get("GH_REF", "main"),
                                 "inputs": {"batch_id": batch_id, "cb": cb,
                                            "worker": worker, "poc_qqs": qqs}}).encode())
    return st, b


def gh_find_run(env_, since, timeout=60):
    repo = env_["GH_REPO"]
    deadline = time.time() + timeout
    while time.time() < deadline:
        st, _h, b = http("GET", "%s/repos/%s/actions/runs?per_page=20&event=workflow_dispatch"
                         % (GH, repo), gh_headers(env_["GH_PAT"]))
        d = jload(b, {}) or {}
        for r in (d.get("workflow_runs") or []):
            created = r.get("created_at", "")
            try:
                ts = time.mktime(time.strptime(created, "%Y-%m-%dT%H:%M:%SZ")) - time.timezone
            except Exception:                            # noqa: BLE001
                continue
            if ts >= since - 10:
                return r
        time.sleep(3)
    return None


def gh_wait_run(env_, run_id, timeout=900):
    repo = env_["GH_REPO"]
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        st, _h, b = http("GET", "%s/repos/%s/actions/runs/%s" % (GH, repo, run_id),
                         gh_headers(env_["GH_PAT"]))
        r = jload(b, {}) or {}
        if r.get("status") != last:
            info("run %s → %s/%s" % (run_id, r.get("status"), r.get("conclusion")))
            last = r.get("status")
        if r.get("status") == "completed":
            return r
        time.sleep(5)
    return None


def gh_logs_text(env_, run_id):
    repo = env_["GH_REPO"]
    st, h, b = http("GET", "%s/repos/%s/actions/runs/%s/logs" % (GH, repo, run_id),
                    gh_headers(env_["GH_PAT"]), timeout=90, follow=False)
    if st in (301, 302, 303, 307, 308):
        loc = h.get("Location") or h.get("location")
        if loc:
            st, _h2, b = http("GET", loc, {}, timeout=90)
    if st != 200:
        return ""
    try:
        zf = zipfile.ZipFile(_io.BytesIO(b))
    except Exception:                                    # noqa: BLE001
        return ""
    return "\n".join(zf.read(n).decode("utf-8", "replace") for n in zf.namelist())


def _ts(s):
    for f in ("%Y-%m-%dT%H:%M:%SZ",):
        try:
            return time.mktime(time.strptime(s, f)) - time.timezone
        except Exception:                                # noqa: BLE001
            return 0
    return 0


def p2_actions(env_):
    hr("P2 · Actions 真实跑一次（这是唯一能测出 t_ready 的地方）")
    batch = "poc-" + time.strftime("%m%d%H%M%S")
    t0 = time.time()
    st, b = gh_dispatch(env_, batch)
    if st != 204:
        bad("dispatch 失败（HTTP %s）：%s" % (st, b[:300].decode("utf-8", "replace")))
        if st == 404:
            info("常见原因：工作流文件不在默认分支上（dispatch 只认默认分支）")
        if st == 403:
            info("常见原因：PAT 缺 Actions:write")
        return False, "dispatch HTTP %s" % st
    ok("已触发（batch=%s），等待 GitHub 分配 runner…" % batch)

    r = gh_find_run(env_, t0)
    if not r:
        bad("60 秒内没找到这次 run（去 Actions 页面看看是不是被并发/权限挡了）")
        return False, "找不到 run"
    rid = r["id"]
    info("run id=%s，等待完成（最多 15 分钟）…" % rid)
    fin = gh_wait_run(env_, rid)
    if not fin:
        return False, "run 超时未完成"
    if fin.get("conclusion") != "success":
        bad("结论是 %s（不是 success），日志里有原因" % fin.get("conclusion"))
        info("看这里：%s" % fin.get("html_url"))
        return False, "run %s" % fin.get("conclusion")

    queue = _ts(fin.get("run_started_at") or "") - _ts(fin.get("created_at") or "")
    total = _ts(fin.get("updated_at") or "") - _ts(fin.get("run_started_at") or "")
    logs = gh_logs_text(env_, rid)
    m = re.search(r"POC_T0=(\d+)\s+POC_T1=(\d+)", logs)
    install = (int(m.group(2)) - int(m.group(1))) if m else 0
    me = re.search(r"POC_EMBED=(\d+)", logs)
    embed = int(me.group(1)) if me else 0
    mw = re.search(r"POC_WID=(WM-[0-9A-Fa-f-]+)", logs)
    model = re.search(r"POC_MODE=(\w+)", logs)

    hr("P2 结果")
    info("排队（created→started）      %5.0f s   ← 这个数不受你控制" % queue)
    info("装依赖（t0→t1）             %5.0f s" % install)
    info("单本打标                    %5.0f s   %s" % (embed, ("水印 " + mw.group(1)) if mw else ""))
    info("**t_ready（排队 + 装依赖）  %5.0f s**" % (queue + install))
    info("run 总时长                  %5.0f s   模式=%s" % (total, model.group(1) if model else "?"))
    okmsg = "t_ready≈%.0fs（排队 %.0f + 依赖 %.0f），单本 %.0fs" % (queue + install, queue, install, embed)
    return True, okmsg


# ============================================================== P3
def p3_r2(env_):
    hr("P3 · R2 上传/下载（走 S3 API，和 Actions 里用的是同一套）")
    if not (env_.get("R2_ENDPOINT") and env_.get("R2_AK")):
        warn("没配 R2，跳过（不影响 P1/P2 的结论）")
        return None, "跳过"
    data = os.urandom(120_000)
    key = "out/poc_selftest.epub"
    t0 = time.time()
    st, _h, b = r2_request(env_, "PUT", key, "", data, "application/epub+zip")
    up = (time.time() - t0) * 1000
    if st not in (200, 201):
        bad("上传失败 HTTP %s：%s" % (st, b[:200].decode("utf-8", "replace")))
        return False, "PUT %s" % st
    t0 = time.time()
    st2, _h, b2 = r2_request(env_, "GET", key)
    down = (time.time() - t0) * 1000
    if st2 != 200 or len(b2) != len(data):
        bad("下载校验失败 HTTP %s，收到 %d 字节（期望 %d）" % (st2, len(b2), len(data)))
        return False, "GET %s" % st2
    r2_request(env_, "DELETE", key)
    ok("上传 %.0f ms / 下载 %.0f ms（120 KB）" % (up, down))
    return True, "上传 %.0fms / 下载 %.0fms" % (up, down)


# ============================================================== P4
def p4_worker(env_):
    hr("P4 · Worker 联动（建批次 → 轮询 → 领取）")
    base = (env_.get("WORKER_URL") or "").rstrip("/")
    if not base:
        warn("没有 WORKER_URL，跳过（先跑 Worker 部署，或手动把地址填进 .env.poc）")
        return None, "跳过"
    st, _h, b = http("GET", base + "/api/wm/batches/nope")
    if st not in (200, 404):
        bad("Worker 不通（HTTP %s）：%s" % (st, b[:160].decode("utf-8", "replace")))
        return False, "Worker 不可达"
    t0 = time.time()
    st, _h, b = http("POST", base + "/api/wm/jobs",
                     {"Content-Type": "application/json"},
                     json.dumps({"qqs": ["123450001"], "book_id": 1}).encode())
    d = jload(b, {}) or {}
    ms = (time.time() - t0) * 1000
    if st != 200 or not d.get("batch_id"):
        bad("建批次失败 HTTP %s：%s" % (st, str(d)[:200]))
        return False, "POST /api/wm/jobs"
    bid = d["batch_id"]
    ok("建批次 %.0f ms（含 dispatch），batch=%s" % (ms, bid[:8]))
    for _ in range(20):
        st, _h, b = http("GET", base + "/api/wm/batches/" + bid)
        s = (jload(b, {}) or {}).get("status")
        if s in ("done", "failed"):
            break
        time.sleep(3)
    info("最终状态：%s（跑到 done 说明 Actions 已经回调回来了）" % s)
    return True, "建批次 %.0fms，状态 %s" % (ms, s)


# ============================================================== P5
def p5_mapping(env_):
    hr("P5 · 水印映射落 Turso（溯源不依赖 mapping.db）")
    wid = "WM-POC%06d-AAAAAA" % int(time.time()) % 1000000
    url, tok = norm_turso(env_["TURSO_URL"]), env_["TURSO_TOKEN"]
    st, out, _b = turso_pipeline(url, tok, [
        ("INSERT OR REPLACE INTO wm_mapping(watermark_id,admin_id,qq,book_id,batch_id) VALUES(?,?,?,?,?)",
         [wid, 1, "123450001", 1, "p5"]),
        ("SELECT qq FROM wm_mapping WHERE watermark_id=?", [wid]),
    ])
    row = out[1][1]["rows"] if len(out) > 1 and out[1][0] == "ok" else []
    if row and row[0][0] == "123450001":
        ok("写入 %s → 反查回 qq=123450001" % wid)
        return True, "映射一致"
    bad("反查失败：%r" % (row,))
    return False, "映射不一致"


# ============================================================== P6
def p6_concurrency(env_, n=3):
    hr("P6 · 并发触发 %d 个 run，看排队会不会崩" % n)
    t0 = time.time()
    ids = []
    for i in range(n):
        st, _b = gh_dispatch(env_, "poc-c%d-%d" % (i, int(time.time())))
        info("dispatch #%d → HTTP %s" % (i + 1, st))
        if st != 204:
            bad("第 %d 个就失败了，停止（并发上限或限流）" % (i + 1))
            return False, "并发触发失败"
    ok("%d 个 dispatch 全部 204（耗时 %.1fs）" % (n, time.time() - t0))
    # 找齐 run 并等全部结束
    time.sleep(8)
    repo = env_["GH_REPO"]
    st, _h, b = http("GET", "%s/repos/%s/actions/runs?per_page=30" % (GH, repo),
                     gh_headers(env_["GH_PAT"]))
    runs = [r for r in ((jload(b, {}) or {}).get("workflow_runs") or [])
            if r.get("created_at") and _ts(r["created_at"]) >= t0 - 30]
    info("找到 %d 个新 run，等待全部结束…" % len(runs))
    deadline = time.time() + 900
    while time.time() < deadline:
        st, _h, b = http("GET", "%s/repos/%s/actions/runs?per_page=30" % (GH, repo),
                         gh_headers(env_["GH_PAT"]))
        cur = [r for r in ((jload(b, {}) or {}).get("workflow_runs") or [])
               if r.get("created_at") and _ts(r["created_at"]) >= t0 - 30]
        if cur and all(r.get("status") == "completed" for r in cur):
            break
        time.sleep(8)
    wall = time.time() - t0
    qs = [_ts(r.get("run_started_at") or "") - _ts(r.get("created_at") or "") for r in cur]
    qs = [q for q in qs if q > 0]
    ok("%d 个 run 全部结束，墙钟 %.0f s；排队 max %.0f s / 平均 %.0f s"
       % (len(cur), wall, max(qs) if qs else 0, sum(qs) / len(qs) if qs else 0))
    return True, "并发 %d 个：墙钟 %.0fs，排队 max %.0fs" % (len(cur), wall, max(qs) if qs else 0)


# ============================================================== main
def collect(env_):
    hr("① 收集凭据（有 .env.poc 就按回车沿用；可选项目直接回车跳过）")
    print("  Turso（必填）：https://turso.tech → 建库 → 复制 URL 与 Token")
    env_["TURSO_URL"] = ask("Turso Database URL", "TURSO_URL", env_)
    env_["TURSO_TOKEN"] = ask("Turso Token", "TURSO_TOKEN", env_, secret=True)

    print("\n  GitHub（必填）：public 仓库 + fine-grained PAT（Actions: Read and write）")
    env_["GH_REPO"] = ask("仓库 owner/repo", "GH_REPO", env_)
    env_["GH_PAT"] = ask("GitHub PAT", "GH_PAT", env_, secret=True)
    env_["WF_FILE"] = ask("工作流文件名", "WF_FILE", env_, default="watermark_poc.yml")
    env_["GH_REF"] = ask("分支", "GH_REF", env_, default="main")

    print("\n  R2（可选，没有就两次回车跳过）：Endpoint / AK / SK / 桶名")
    env_["R2_ENDPOINT"] = ask("R2 Endpoint", "R2_ENDPOINT", env_, optional=True)
    if env_["R2_ENDPOINT"]:
        env_["R2_AK"] = ask("R2 Access Key", "R2_AK", env_, secret=True)
        env_["R2_SK"] = ask("R2 Secret Key", "R2_SK", env_, secret=True)
        env_["R2_BUCKET"] = ask("R2 桶名", "R2_BUCKET", env_, default="wm-poc")

    print("\n  Cloudflare（可选，给了就能自动部署 Worker）：API Token + Account ID")
    env_["CF_API_TOKEN"] = ask("CF API Token", "CF_API_TOKEN", env_, secret=True, optional=True)
    if env_["CF_API_TOKEN"]:
        env_["CF_ACCOUNT_ID"] = ask("CF Account ID", "CF_ACCOUNT_ID", env_, optional=True)

    if not env_.get("CB_SECRET"):
        env_["CB_SECRET"] = os.urandom(16).hex()
    if not env_.get("DL_SECRET"):
        env_["DL_SECRET"] = os.urandom(16).hex()
    if not env_.get("POC_SERVER_SECRET"):
        env_["POC_SERVER_SECRET"] = os.urandom(32).hex()
    if not env_.get("POC_DB_KEY"):
        env_["POC_DB_KEY"] = os.urandom(24).hex()
    info("CB_SECRET / DL_SECRET / 两个引擎密钥 已自动生成")
    return env_


def verify(env_):
    hr("② 当场校验（不通就停，不会带着错配置往下跑）")
    all_ok = True

    r, msg = check_turso(env_)
    (ok if r else bad)("Turso：%s" % msg)
    all_ok &= bool(r)

    r, msg = check_github(env_)
    (ok if r else bad)("GitHub：%s" % msg)
    all_ok &= bool(r)

    r, msg = check_r2(env_)
    if r is None:
        warn("R2：%s" % msg)
    else:
        (ok if r else bad)("R2：%s" % msg)
        all_ok &= bool(r)

    r, msg = check_cf(env_)
    if r is None:
        warn("Cloudflare：%s" % msg)
    else:
        (ok if r else bad)("Cloudflare：%s" % msg)
        all_ok &= bool(r)
    return all_ok


def main():
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8", errors="replace")
        except Exception:                                # noqa: BLE001
            pass

    ap = argparse.ArgumentParser(description="一键配置 + 校验 + 跑 PoC")
    ap.add_argument("--reuse", action="store_true", help="复用 .env.poc，不再询问")
    ap.add_argument("--skip-run", action="store_true", help="只配置+校验+落盘")
    ap.add_argument("--only", default="", help="只跑 p1,p2,p3,p4,p5")
    ap.add_argument("--p6", type=int, default=0, help="额外做 N 并发实测")
    ap.add_argument("--deploy", action="store_true", help="用 CF API 部署 Worker")
    ap.add_argument("--no-verify", action="store_true",
                    help="跳过 ② 校验直接跑（GitHub 抽风时用；不建议常态使用）")
    a = ap.parse_args()

    print("=" * 72)
    print("  WM · Serverless PoC 一键配置（纯标准库，无需 pip install）")
    print("=" * 72)

    env_ = load_env()
    if a.reuse:
        if env_.get("TURSO_URL") and env_.get("GH_PAT"):
            hr("① 复用 %s" % ENV_PATH)
            ok("已加载 %d 项配置" % len(env_))
        else:
            bad("没有可复用的 %s（或里面缺 TURSO_URL / GH_PAT）" % ENV_PATH)
            info("去掉 --reuse 重新跑一次，走交互收集：python poc/setup_and_run.py")
            return 2
    else:
        env_ = collect(env_)

    if not a.no_verify and not verify(env_):
        hr("校验没全过")
        bad("已停止。修好后重跑本脚本（已填的会沿用，不用重新粘）")
        print("\n  常见修法：")
        info("Turso 401   → Token 复制全了吗？Create Token 时选 'Read & Write'")
        info("GitHub 404  → 仓库名写成 owner/repo？PAT 的 Repository access 里勾上这个仓库")
        info("GitHub 403  → fine-grained PAT 要勾 Actions: Read and write")
        info("R2   403    → AK/SK 是 'Object Read & Write' 且范围含这个桶；Endpoint 用 https://<acc>.r2.cloudflarestorage.com")
        info("CF   401    → Token 要是 Account 级，权限含 Workers Scripts:Edit / Workers KV:Edit / R2:Edit")
        return 2

    p = save_env(env_)
    hr("③ 落盘")
    ok("%s（含明文凭据，别提交到 git）" % p)

    if env_.get("CF_API_TOKEN") and env_.get("CF_ACCOUNT_ID") and (a.deploy or not env_.get("WORKER_URL")):
        hr("③b 部署 Worker 到 Cloudflare")
        try:
            base = deploy_worker(env_)
            ok("已部署：%s" % (base or "(无 workers.dev 子域)"))
            if base:
                env_["WORKER_URL"] = base
                save_env(env_)
                st, _h, b = http("GET", base + "/api/wm/batches/nope", timeout=20)
                ok("Worker 自检 GET /api/wm/batches/nope → HTTP %s（200/404 都算通）" % st) \
                    if st in (200, 404) else warn("Worker 已部署但自检 HTTP %s" % st)
        except Exception as e:                           # noqa: BLE001
            bad("自动部署失败：%s" % e)
            info("手动兜底：Cloudflare Dashboard → Workers & Pages → 粘贴 worker_poc.js → "
                 "绑定 KV(变量名 KV) / R2(变量名 BUCKET) / Secrets")
        RESULTS.append(("Worker 部署", bool(env_.get("WORKER_URL")), env_.get("WORKER_URL", "")))

    if a.skip_run:
        hr("已按要求停在配置阶段（--skip-run）")
        return 0

    only = [x.strip() for x in a.only.split(",") if x.strip()]
    steps = [("p1", p1_turso), ("p2", p2_actions), ("p3", p3_r2), ("p4", p4_worker), ("p5", p5_mapping)]
    for name, fn in steps:
        if only and name not in only:
            continue
        try:
            r, msg = fn(env_)
        except Exception as e:                           # noqa: BLE001
            bad("%s 异常：%s: %s" % (name.upper(), type(e).__name__, e))
            r, msg = False, str(e)[:120]
        RESULTS.append((name.upper(), r, msg))

    if a.p6:
        try:
            r, msg = p6_concurrency(env_, a.p6)
        except Exception as e:                           # noqa: BLE001
            r, msg = False, "%s: %s" % (type(e).__name__, e)
        RESULTS.append(("P6", r, msg))

    hr("汇总")
    for name, r, msg in RESULTS:
        if r is None:
            print("  \033[33m↷\033[0m %-6s %s" % (name, msg))
        else:
            print("  %s %-6s %s" % ("\033[32m✔\033[0m" if r else "\033[31m✘\033[0m", name, msg))
    print()
    print("  下一步：把上面的数字发给我，我据此定产品形态（当场等 / 预生成为主）。")
    print("  跑完之后记得去后台吊销这些 token：Turso / GitHub PAT / Cloudflare / R2。")
    return 0 if all(r is not False for _n, r, _m in RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
