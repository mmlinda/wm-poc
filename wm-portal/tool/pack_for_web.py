# -*- coding: utf-8 -*-
"""把某一批分发出来的成品，按「QQ 号.epub」重新命名并打成一个 zip，供网页上传。

为什么要它：网页上传时用文件名里的 QQ 号决定"这份是谁的"。而本机 `out/` 里的
文件名是 `书名-WM-xxxxx-xxxx.epub`（按水印 ID 命名，方便自己对账），不带 QQ。
这个脚本用 `mapping.db` 里的映射，把两者对上。

用法（在 epub-watermark 目录下）：

    # 看有哪些批次
    python pack_for_web.py --list

    # 打最近一批
    python pack_for_web.py -o 交付包.zip

    # 指定批次 / 指定成品目录
    python pack_for_web.py --batch b_20261030 --dir out -o 交付包.zip

然后：网页 → 更多 → 交付与领取 → 新建一个交付 → 上传这个 zip。
"""
from __future__ import annotations

import argparse
import csv
import os
import sys
import zipfile

import db
from config import DB_PATH, FILENAME_MODE


def find_file(out_dir: str, watermark_id: str) -> str | None:
    """按当前命名模式在 out/ 里找这份成品。"""
    if not os.path.isdir(out_dir):
        return None
    hits = []
    for name in os.listdir(out_dir):
        if not name.lower().endswith(".epub"):
            continue
        if watermark_id in name:                     # full 模式
            hits.append(name)
        elif name.endswith(f"-{watermark_id[-4:]}.epub"):   # short 模式
            hits.append(name)
    if not hits:
        return None
    return os.path.join(out_dir, sorted(hits)[0])


def main() -> int:
    ap = argparse.ArgumentParser(description="把某批次成品按 QQ 命名打成 zip，供网页上传")
    ap.add_argument("--batch", default="", help="批次 id（默认最近一批）")
    ap.add_argument("--dir", default="out", help="成品目录（默认 out）")
    ap.add_argument("--db", default=DB_PATH)
    ap.add_argument("--list", action="store_true", help="只列批次")
    ap.add_argument("-o", "--out", default="交付包.zip")
    ap.add_argument("--csv", default="", help="同时导出一份 qq→文件 对照表")
    a = ap.parse_args()

    conn = db.connect(a.db)
    rows = [dict(r) for r in conn.execute(
        "SELECT batch_id, COUNT(*) n, MAX(id) last_id FROM distributions "
        "GROUP BY batch_id ORDER BY last_id DESC")]
    if a.list or not rows:
        print(f"共 {len(rows)} 个批次：")
        for r in rows:
            print(f"  {r['batch_id']}  {r['n']} 条")
        conn.close()
        return 0 if rows else 2

    batch = a.batch.strip() or rows[0]["batch_id"]
    if not any(r["batch_id"] == batch for r in rows):
        print(f"[×] 没有这个批次：{batch}")
        print(f"    现有：{[r['batch_id'] for r in rows]}")
        conn.close()
        return 2

    recs = [dict(r) for r in conn.execute(
        "SELECT watermark_id, qq_number, status FROM distributions "
        "WHERE batch_id=? AND status IN ('sent','pending','revoked') ORDER BY id",
        (batch,))]
    conn.close()

    pairs, missing = [], []
    for r in recs:
        try:
            qq = db.dec(r["qq_number"])
        except Exception:                                # noqa: BLE001
            continue
        if not qq:
            continue
        path = find_file(a.dir, r["watermark_id"])
        if not path:
            missing.append((qq, r["watermark_id"]))
            continue
        pairs.append((qq, r["watermark_id"], path))

    if not pairs:
        print(f"[×] 在 {a.dir} 里一份成品都没找到。")
        if FILENAME_MODE == "clean":
            print("    当前 FILENAME_MODE=clean（文件名是 001.epub 这种），")
            print("    无法从文件名反查水印 ID —— 请把 config.FILENAME_MODE 改回 full 重新生成。")
        else:
            print(f"    这批 {len(recs)} 条记录，逐个都没匹配到文件名。")
        return 2

    with zipfile.ZipFile(a.out, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for qq, _wid, path in pairs:
            arc = f"{qq}{os.path.splitext(path)[1].lower() or '.epub'}"
            z.write(path, arc)

    print(f"[√] 已打包 {len(pairs)} 份 → {os.path.abspath(a.out)}"
          f"（{os.path.getsize(a.out)/1024/1024:.1f} MB）")
    print(f"    批次 {batch}｜按 QQ 命名｜覆盖 {len({p[0] for p in pairs})} 个不同 QQ")
    if missing:
        print(f"[!] {len(missing)} 条在 {a.dir} 里找不到对应成品（可能已删/未生成）：")
        for qq, wid in missing[:8]:
            print(f"    {qq}  {wid}")
        if len(missing) > 8:
            print(f"    … 其余 {len(missing) - 8} 条")

    if a.csv:
        with open(a.csv, "w", encoding="utf-8-sig", newline="") as f:
            w = csv.writer(f)
            w.writerow(["qq", "watermark_id", "source_file"])
            for qq, wid, path in pairs:
                w.writerow([qq, wid, os.path.basename(path)])
        print(f"[√] 对照表 → {os.path.abspath(a.csv)}")

    print("\n下一步：网页 → 更多 → 交付与领取 → 新建交付 → 上传这个 zip")
    return 0


if __name__ == "__main__":
    sys.exit(main())
