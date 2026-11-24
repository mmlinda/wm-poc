#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""purge_orphans.py —— 清理"上传了但没有归属"的成品文件，回收 R2 配额。

背景（真实事故）：
    批次失败（回调 5xx、密钥导出失败等）时，Actions 已经把成品 PUT 进 R2，
    但 Worker 没来得及写 files 行 → 这些对象永远没人认领，也不会被"按 files 清理"的逻辑带走。
    实测一次 20 人测试失败两轮，就白占了 1.2GB（配额 9GB 的 13%）。

判定：key 形如 out/<batch_id>/... 或 out/<batch_id>.epub，
      若该 batch_id 在 wm_batches 里状态不是 done → 视为孤儿。

用法：
    python poc/purge_orphans.py --dry        # 只看会删什么（默认就是 dry）
    python poc/purge_orphans.py --apply      # 真删，并重算 r2_usage
"""
from __future__ import annotations

import argparse
import importlib.util
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BATCH_RE = re.compile(r"^out/([0-9a-fA-F-]{36})(?:/|\.epub$)")


def load_setup():
    spec = importlib.util.spec_from_file_location("sar", os.path.join(HERE, "setup_and_run.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def main() -> int:
    ap = argparse.ArgumentParser(description="清理 R2 里的孤儿成品")
    ap.add_argument("--apply", action="store_true", help="真的删除（默认 dry-run）")
    a = ap.parse_args()

    m = load_setup()
    env = m.load_env()
    url, tok = m.norm_turso(env["TURSO_URL"]), env["TURSO_TOKEN"]

    st, out, _ = m.turso_pipeline(url, tok, [("SELECT id,status FROM wm_batches", [])])
    status = {}
    for r in out or []:
        if r[0] == "ok":
            for row in r[1].get("rows") or []:
                status[row[0]] = row[1]
    print("库内批次: %d 个（done %d）" % (len(status), sum(1 for v in status.values() if v == "done")))

    st, h, b = m.r2_request(env, "GET", "", "list-type=2&max-keys=1000", region="auto")
    xml = (b or b"").decode("utf-8", "replace")
    ents = re.findall(r"<Contents>.*?<Key>(.*?)</Key>.*?<Size>(\d+)</Size>.*?</Contents>", xml, re.S)
    print("桶内对象: %d 个 / %.1f MB" % (len(ents), sum(int(s) for _k, s in ents) / 1048576))

    orphan, keep = [], 0
    for key, size in ents:
        if key.startswith("books/") or key.startswith("trac"):
            keep += 1
            continue
        mt = BATCH_RE.match(key)
        if not mt:
            keep += 1
            continue
        bid = mt.group(1)
        if status.get(bid) == "done":
            keep += 1
        else:
            orphan.append((key, int(size)))

    print("\n孤儿对象: %d 个 / %.1f MB（可回收）"
          % (len(orphan), sum(s for _k, s in orphan) / 1048576))
    for k, s in orphan[:8]:
        print("   %-70s %8.1f MB" % (k, s / 1048576))
    if len(orphan) > 8:
        print("   … 其余 %d 个" % (len(orphan) - 8))

    if not orphan:
        return 0
    if not a.apply:
        print("\n[dry-run] 加 --apply 才会真删")
        return 0

    freed = 0
    for k, s in orphan:
        st2, _h, _b = m.r2_request(env, "DELETE", k)
        if st2 in (200, 204):
            freed += s
        else:
            print("  删除失败 %s → HTTP %s" % (k, st2))
    print("\n已删除 %d 个，回收 %.1f MB" % (len(orphan), freed / 1048576))

    # 重算账本（以桶为准）
    st, h, b = m.r2_request(env, "GET", "", "list-type=2&max-keys=1000", region="auto")
    xml = (b or b"").decode("utf-8", "replace")
    ents = re.findall(r"<Contents>.*?<Key>(.*?)</Key>.*?<Size>(\d+)</Size>.*?</Contents>", xml, re.S)
    total = sum(int(s) for _k, s in ents)
    m.turso_pipeline(url, tok, [
        ("UPDATE r2_usage SET bytes=?, objects=?, updated_at=datetime('now') WHERE id=1",
         [total, len(ents)]),
    ])
    print("账本已重算: %d 个对象 / %.1f MB" % (len(ents), total / 1048576))
    return 0


if __name__ == "__main__":
    sys.exit(main())
