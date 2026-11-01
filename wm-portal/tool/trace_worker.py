# -*- coding: utf-8 -*-
"""溯源工单处理程序（跑在你自己的电脑上）。

网页上的「溯源」只是收文件、存文件、显示结果 —— **解码必须在有密钥的这台电脑上做**。
这个小程序就是那条线：它轮询网页上的待处理工单，把文件拉下来，调
`decode_watermark.py` 解码，再把结论推回网页。

用法（在 epub-watermark 目录下，保持窗口开着）：

    # 常驻（每 8 秒看一次）
    python trace_worker.py --url "https://xxx/?sharecode=XXXX" --password 你的密码

    # 只跑一次（处理完就退出）
    python trace_worker.py --url "..." --password 你的密码 --once

    # 普通管理员账号
    python trace_worker.py --url "..." --username xiaoyu --password pw

要点：
  · 网页是按账号隔离的：**用谁的账号跑，就只处理谁的工单**。
  · 一条工单只会被一台电脑取走（服务端会记 claimed_at），多开也不会重复。
  · 结论里既有水印 ID，也有层体检报告（对方清洗到什么程度）。
"""
from __future__ import annotations

import argparse
import http.cookiejar
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

for _k in ("NO_PROXY", "no_proxy"):
    _hosts = os.environ.get(_k, "")
    if "127.0.0.1" not in _hosts:
        os.environ[_k] = (_hosts + "," if _hosts else "") + "127.0.0.1,localhost"

HERE = os.path.dirname(os.path.abspath(__file__))
_CJ = http.cookiejar.CookieJar()
_OP = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(_CJ))


def _req(url: str, data: dict | None = None, timeout: int = 60) -> bytes:
    body = json.dumps(data).encode("utf-8") if data is not None else None
    req = urllib.request.Request(url, data=body,
                                 method="POST" if data is not None else "GET")
    if body is not None:
        req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", "wm-trace/1.0")
    with _OP.open(req, timeout=timeout) as r:
        return r.read()


def _err(e: urllib.error.HTTPError) -> str:
    try:
        raw = e.read().decode("utf-8", "replace")
        return json.loads(raw).get("error") or raw[:120]
    except Exception:                                    # noqa: BLE001
        return ""


def parse_json_block(out: str) -> dict | None:
    """decode_watermark.py --json 会在最后打印一段缩进 JSON。"""
    for marker in ("\n{\n", "{\n"):
        i = out.rfind(marker)
        if i >= 0:
            frag = out[i:].strip()
            try:
                return json.loads(frag)
            except Exception:                            # noqa: BLE001
                continue
    return None


def summarize(data: dict) -> dict:
    """把解码结果压成"给管理员看"的摘要 —— 不含层名、通道名、清洗细节。

    站长要看层信息，网页上会给他全量；管理员只看到"有没有被改过 + 这份是谁的"。
    """
    layers = data.get("layers") or {}
    wid = data.get("watermark_id") or ""
    alive = layers.get("alive") or []
    cleared = layers.get("cleared") or []
    damaged = layers.get("damaged") or []
    inferred = layers.get("inferred") or []
    tampered = bool(cleared or damaged or inferred)
    if not wid:
        summary = "没匹配到本系统的水印：可能是别处来的文件，或水印已被彻底清掉"
    elif tampered:
        summary = "能追到具体的人；但文件疑似被改动过（有痕迹被清除或损坏）"
    else:
        summary = "能追到具体的人；未发现被改动的痕迹"
    return {"matched": bool(wid), "tampered": tampered, "summary": summary,
            "_alive": len(alive)}


def decode_one(path: str, db_path: str) -> tuple[str, str, str, dict]:
    """跑解码，返回 (watermark_id, qq, 完整报告, 摘要)。"""
    cmd = [sys.executable, os.path.join(HERE, "decode_watermark.py"), path, "--json"]
    if db_path:
        cmd += ["--db", db_path]
    try:
        p = subprocess.run(cmd, cwd=HERE, capture_output=True, text=True,
                           timeout=900, encoding="utf-8", errors="replace")
        out = (p.stdout or "") + (("\n" + p.stderr) if p.stderr else "")
    except subprocess.TimeoutExpired:
        return "", "", "解码超时（>15 分钟）", {"matched": False, "tampered": False,
                                              "summary": "解码超时，没能得出结论"}
    data = parse_json_block(out) or {}
    wid = str(data.get("watermark_id") or "")
    rec = data.get("record") or {}
    qq = str(rec.get("qq_number") or "")
    return wid, qq, out[-20000:], summarize(data)


def main() -> int:
    ap = argparse.ArgumentParser(description="轮询网页溯源工单并在本机解码")
    ap.add_argument("--url", required=True, help="网页地址，含 sharecode")
    ap.add_argument("--username", default="", help="管理员用户名（站长不填）")
    ap.add_argument("--password", required=True)
    ap.add_argument("--db", default="", help="mapping.db 路径（默认用 config 的）")
    ap.add_argument("--interval", type=int, default=8)
    ap.add_argument("--once", action="store_true", help="只跑一轮")
    a = ap.parse_args()

    u = urllib.parse.urlparse(a.url)
    if not u.scheme or not u.netloc:
        print("[×] --url 要写完整，例如 https://xxx/?sharecode=ABC")
        return 2
    base = f"{u.scheme}://{u.netloc}"

    try:                                                 # 预热 sharecode 门禁
        _req(f"{base}/?{u.query}" if u.query else base + "/")
    except Exception:                                    # noqa: BLE001
        pass
    is_owner = False
    try:
        lr = json.loads(_req(base + "/api/login",
                             {"username": a.username.strip(),
                              "password": a.password}).decode("utf-8"))
        is_owner = (lr.get("role") == "owner")
    except urllib.error.HTTPError as e:
        detail = _err(e)
        if e.code == 403 and not detail:
            print("[×] 被平台访问门禁挡住：--url 里要带 ?sharecode=...")
        else:
            print(f"[×] 登录失败（HTTP {e.code}）{detail}")
        return 2
    except Exception as exc:                             # noqa: BLE001
        print(f"[×] 连不上：{exc}")
        return 2

    who = a.username.strip() or "站长"
    print(f"[√] 已登录（{who}{'·站长' if is_owner else ''}），开始轮询 {base}"
          f"（每 {a.interval}s，Ctrl+C 退出）")
    if not is_owner:
        print("    提示：你的界面只显示「有没有被改过 + 是谁的」，层信息只在站长那边。")
    idle = 0
    while True:
        try:
            d = json.loads(_req(base + "/api/trace").decode("utf-8"))
            tasks = [t for t in (d.get("traces") or []) if t.get("status") == "pending"]
        except Exception as exc:                         # noqa: BLE001
            print(f"[!] 取工单失败：{exc}")
            tasks = []

        for t in tasks:
            tid = t["id"]
            print(f"[…] 工单 #{tid} {t.get('fname','')}（{t.get('size_text','')}）")
            tmp = ""
            try:
                with _OP.open(base + f"/api/trace/{tid}/file", timeout=120) as r:
                    blob = r.read()
                fd, tmp = tempfile.mkstemp(prefix=f"trace{tid}_", suffix=".epub")
                with os.fdopen(fd, "wb") as f:
                    f.write(blob)
                wid, qq, report, brief = decode_one(tmp, a.db)
                _req(base + f"/api/trace/{tid}/result",
                     {"watermark_id": wid, "qq": qq, "report": report, "brief": brief})
                if is_owner:
                    # 站长：控制台直接给全量（层、通道、清洗细节）
                    print(f"     → {'命中 ' + wid + (' / QQ ' + qq if qq else '') if wid else '没解出来'}")
                    for line in (report or "").strip().split("\n")[-6:]:
                        if line.strip():
                            print("       " + line[:100])
                else:
                    # 管理员：只给结论，不打印任何层信息
                    print(f"     → {brief.get('summary', '')}" +
                          (f"（QQ {qq}）" if qq else ""))
            except Exception as exc:                     # noqa: BLE001
                print(f"     [×] 处理失败：{exc}")
            finally:
                if tmp and os.path.exists(tmp):
                    try:
                        os.remove(tmp)
                    except OSError:
                        pass

        if tasks:
            idle = 0
        else:
            idle += 1
            if a.once:
                print("[√] 没有待处理的工单")
                return 0
            if idle % 15 == 1:
                print(f"    （空闲中，已等 {idle * a.interval}s）")
        if a.once and not tasks:
            return 0
        time.sleep(max(2, a.interval))


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[√] 已停止")
