# -*- coding: utf-8 -*-
"""把「本机已经打好标 / 已发出」的结果回填到网页台账。

为什么要它：网页只负责**名单**，打标和发信必须在**本机**做（母本、密钥、
Pillow/numpy 都在本机）。所以存在一个"账实不符"的窗口 —— 你在本机发完了，
网页上那些人还显示"待发"。这个脚本负责把这个窗口合上。

用法（在 epub-watermark 目录下）：

    # 先看本机有哪些批次
    python push_status.py --url "https://xxx/?sharecode=ABC" --password 你的密码 --list

    # 把最近一批回填到网页（默认最近一批）
    python push_status.py --url "https://xxx/?sharecode=ABC" --password 你的密码

    # 指定批次 / 普通管理员账号
    python push_status.py --url "..." --username xiaoyu --password pw --batch b_20261030

    # 只看会发生什么，不真的改
    python push_status.py --url "..." --password pw --dry-run

要点：
  · **用哪个账号拉的名单，就用哪个账号回填**。网页是每个管理员各自独立的，
    拿站长的账号去回填管理员的名单会全部"对不上"（脚本会明确告诉你）。
  · 只回填 status in ('sent','pending') 的记录；失败(failed)的不回填。
  · 网页上被封禁的人不会被覆盖成"已发"（服务端已做保护）。
"""
from __future__ import annotations

import argparse
import http.cookiejar
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

# 本机有 HTTP_PROXY 时 urllib 连 127.0.0.1 也会走代理（会被 502 拦掉）
for _k in ("NO_PROXY", "no_proxy"):
    _hosts = os.environ.get(_k, "")
    if "127.0.0.1" not in _hosts:
        os.environ[_k] = (_hosts + "," if _hosts else "") + "127.0.0.1,localhost"

_CJ = http.cookiejar.CookieJar()
_OP = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(_CJ))


def _req(url: str, data: dict | None = None) -> bytes:
    body = json.dumps(data).encode("utf-8") if data is not None else None
    req = urllib.request.Request(url, data=body,
                                 method="POST" if data is not None else "GET")
    if body is not None:
        req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", "wm-push/1.0")
    with _OP.open(req, timeout=60) as r:
        return r.read()


def _err_text(e: urllib.error.HTTPError) -> str:
    try:
        raw = e.read().decode("utf-8", "replace")
        return json.loads(raw).get("error") or raw[:120]
    except Exception:                                    # noqa: BLE001
        return ""


def main() -> int:
    ap = argparse.ArgumentParser(description="把本机的打标/发送结果回填到网页台账")
    ap.add_argument("--url", required=True, help="网页地址，含 sharecode")
    ap.add_argument("--username", default="", help="管理员用户名（站长不填）")
    ap.add_argument("--password", required=True)
    ap.add_argument("--batch", default="", help="批次 id（默认最近一批）")
    ap.add_argument("--list", action="store_true", help="只列本机批次")
    ap.add_argument("--limit", type=int, default=0, help="最多回填多少条")
    ap.add_argument("--dry-run", action="store_true", help="只显示，不提交")
    a = ap.parse_args()

    # ---- 本机数据 ----
    try:
        import db  # 需要 config 里的 DB_KEY；在 epub-watermark 目录下运行即可
        from config import DB_PATH
    except Exception as exc:                             # noqa: BLE001
        print(f"[×] 读不到本机映射表：{exc}")
        print("    请在 epub-watermark 目录下运行（需要 .env 里的 DB_KEY）")
        return 2

    conn = db.connect(DB_PATH)
    batches = [dict(r) for r in conn.execute(
        "SELECT batch_id, COUNT(*) n, MAX(id) last_id FROM distributions "
        "GROUP BY batch_id ORDER BY last_id DESC")]
    if a.list:
        print(f"本机共 {len(batches)} 个批次：")
        for b in batches:
            print(f"  {b['batch_id']}  {b['n']} 条")
        conn.close()
        return 0
    if not batches:
        print("[×] 本机映射表里还没有任何分发记录")
        conn.close()
        return 2

    batch = a.batch.strip() or batches[0]["batch_id"]
    if not any(b["batch_id"] == batch for b in batches):
        print(f"[×] 没有这个批次：{batch}")
        print(f"    现有：{[b['batch_id'] for b in batches]}")
        conn.close()
        return 2

    sql = ("SELECT watermark_id, qq_number, status FROM distributions "
           "WHERE batch_id=? AND status IN ('sent','pending') ORDER BY id")
    if a.limit:
        sql += f" LIMIT {int(a.limit)}"
    rows = []
    for r in conn.execute(sql, (batch,)):
        try:
            qq = db.dec(r["qq_number"])
        except Exception:                                # noqa: BLE001
            continue
        if not qq:
            continue
        rows.append({"qq": qq, "watermark_id": r["watermark_id"],
                     "status": "sent" if r["status"] == "sent" else "sent"})
    conn.close()
    if not rows:
        print(f"[!] 批次 {batch} 里没有 sent/pending 的记录")
        return 0
    print(f"[√] 批次 {batch}：{len(rows)} 条要回填")
    if a.dry_run:
        for r in rows[:5]:
            print(f"    {r['qq']} → {r['watermark_id']}")
        if len(rows) > 5:
            print(f"    … 其余 {len(rows) - 5} 条省略")
        print("    （--dry-run：没有提交）")
        return 0

    # ---- 网页接口 ----
    u = urllib.parse.urlparse(a.url)
    if not u.scheme or not u.netloc:
        print("[×] --url 要写完整，例如 https://xxx.workbuddy.host/?sharecode=ABC")
        return 2
    base = f"{u.scheme}://{u.netloc}"

    try:                                                 # 预热 sharecode 门禁
        _req(f"{base}/?{u.query}" if u.query else base + "/")
    except Exception:                                    # noqa: BLE001
        pass
    try:
        _req(base + "/api/login", {"username": a.username.strip(), "password": a.password})
    except urllib.error.HTTPError as e:
        detail = _err_text(e)
        if e.code == 403 and not detail:
            print("[×] 被平台访问门禁挡住：--url 里要带 ?sharecode=...")
        else:
            print(f"[×] 登录失败（HTTP {e.code}）{detail}")
        return 2
    except Exception as exc:                             # noqa: BLE001
        print(f"[×] 连不上：{exc}")
        return 2

    updated = unmatched = 0
    for i in range(0, len(rows), 300):
        chunk = rows[i:i + 300]
        try:
            raw = _req(base + "/api/receipt", {"rows": chunk})
            d = json.loads(raw.decode("utf-8"))
        except urllib.error.HTTPError as e:
            print(f"[×] 回填失败（HTTP {e.code}）{_err_text(e)}")
            return 2
        updated += int(d.get("updated") or 0)
        unmatched += int(d.get("unmatched_count") or 0)
        print(f"    {min(i + 300, len(rows))}/{len(rows)} 已提交…")

    print(f"\n[√] 回填完成：网页上更新 {updated} 条")
    if unmatched:
        print(f"[!] 有 {unmatched} 条在网页上对不上（这个人不在当前账号的名单里）。")
        print("    常见原因：① 拉名单和回填用了不同账号；② 网页上把他删了；")
        print("              ③ 拉名单后又在网页加的人，没参与这次分发。")
    print("    现在打开网页，这些人的状态就是「已发」，并带着水印 ID。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
