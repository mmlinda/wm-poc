#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""keys_to_env.py —— 把本次打标产出的**每一本**的水印密钥与收件人导出成 JSON。

为什么必须有这一步：
    引擎按设计用**随机密钥**（`K.new_keys`），密钥只写进 runner 上的 mapping.db；
    runner 一销毁就没了。回调只带 watermark_id 的话，将来拿到泄露文件**解不出 ID**，
    溯源直接断裂（2026-11-22 实测：decode 返回 None，就是缺这一步）。

批量注意：
    一次 run 可能打 15 本，所以导出的是**数组**（REPORT_JSON），回调按数组逐条入库。
    qq_number 在 field 加密模式下是密文，必须用 db.dec() 解出明文再回传。

用法（workflow 里）：
    python poc/keys_to_env.py "$WIDS" >> "$GITHUB_ENV"
    # $WIDS 形如 "WM-AAAA-BBBB WM-CCCC-DDDD"；不传则取 mapping.db 里最新的 N 条
输出：
    REPORT_JSON=[{"watermark_id":..,"qq":..,"keys":{...}},...]
    KEYS_JSON={...}            # 兼容旧回调，取数组第一条
"""
from __future__ import annotations

import json
import os
import re
import sys

COLS = ("watermark_id", "qq_number", "chaos_seed", "chaos_mu", "css_key", "lsb_key")
WID_RE = re.compile(r"WM-[0-9A-Fa-f]{10}-[0-9A-Fa-f]{6}")


def find_db() -> str:
    # DB_PATH 优先（本地测试/特殊布局时可直接指定），其次 ENGINE_DIR/mapping.db
    cands = [os.environ.get("DB_PATH", "")]
    eng = os.environ.get("ENGINE_DIR")
    if eng:
        cands.append(os.path.join(eng, "mapping.db"))
    cands += ["mapping.db", "wm-portal/tool/mapping.db", "tool/mapping.db"]
    for c in cands:
        if os.path.isfile(c):
            return c
    return ""


def main(argv) -> int:
    dbp = find_db()
    if not dbp:
        sys.stderr.write("keys_to_env: 找不到 mapping.db（ENGINE_DIR=%s）\n"
                         % os.environ.get("ENGINE_DIR"))
        return 2

    eng = os.environ.get("ENGINE_DIR") or os.path.dirname(dbp) or "."
    sys.path.insert(0, os.path.abspath(eng))
    os.environ.setdefault("DB_PATH", os.path.abspath(dbp))
    # ⚠️ 引擎的 db.py 会往 **stdout** 打"[!] 未安装 sqlcipher3…"这类警告。
    #    workflow 是 `python keys_to_env.py ... >> "$GITHUB_ENV"`，
    #    任何不是 KEY=VALUE 的行都会让 GitHub 报
    #    "Invalid format ..." 并整步失败（2026-11-22 真实事故）。
    #    所以：引擎的一切输出统统重定向到 stderr，stdout 只留我们要的两行。
    import contextlib

    stdout_sink = sys.stderr
    try:
        with contextlib.redirect_stdout(stdout_sink):
            import db as engdb                 # 引擎自己的库：负责解密 qq_number
    except Exception as e:                     # noqa: BLE001
        sys.stderr.write("keys_to_env: 无法 import db（%s）\n" % e)
        return 2

    wids = []
    for a in argv[1:]:
        wids += WID_RE.findall(a)
    # 也接受从 run.log 里捞：WIDS 参数可能是一整个日志路径
    for a in argv[1:]:
        if os.path.isfile(a):
            try:
                wids += WID_RE.findall(open(a, encoding="utf-8", errors="replace").read())
            except Exception:                  # noqa: BLE001
                pass
    # 去重（不要写 `seen, wids = set(), [...]`：推导式里的 seen 会被当成自由变量 → NameError）
    seen, uniq = set(), []
    for w in wids:
        if w in seen:
            continue
        seen.add(w)
        uniq.append(w)
    wids = uniq

    with contextlib.redirect_stdout(stdout_sink):
        con = engdb.connect(dbp)
    con.row_factory = __import__("sqlite3").Row
    try:
        if wids:
            q = ("SELECT %s FROM distributions WHERE watermark_id IN (%s)"
                 % (",".join(COLS), ",".join("?" * len(wids))))
            rows = con.execute(q, wids).fetchall()
        else:
            n = int(os.environ.get("BATCH_LIMIT", "15") or 15)
            rows = con.execute(
                "SELECT %s FROM distributions ORDER BY id DESC LIMIT ?" % ",".join(COLS),
                (n,)).fetchall()
    finally:
        con.close()

    if not rows:
        sys.stderr.write("keys_to_env: distributions 里没有记录（wids=%r）\n" % (wids[:3],))
        return 2

    out = []
    for r in rows:
        wid = r["watermark_id"]
        if not wid:
            continue
        try:
            qq = engdb.dec(r["qq_number"] or "")
        except Exception:                      # noqa: BLE001
            qq = r["qq_number"] or ""          # 明文模式直接用
        out.append({
            "watermark_id": wid,
            "qq": str(qq),
            "keys": {
                "chaos_seed": r["chaos_seed"], "chaos_mu": r["chaos_mu"],
                "css_key": r["css_key"], "lsb_key": r["lsb_key"],
            },
        })

    if not out:
        sys.stderr.write("keys_to_env: 记录里没有有效 watermark_id\n")
        return 2

    sys.stderr.write("keys_to_env: 导出 %d 本（%s …）\n" % (len(out), out[0]["watermark_id"]))
    line = json.dumps(out, ensure_ascii=False, separators=(",", ":"))
    print("REPORT_JSON=" + line)
    print("KEYS_JSON=" + json.dumps(out[0]["keys"] | {"watermark_id": out[0]["watermark_id"]},
                                    ensure_ascii=False, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
