# -*- coding: utf-8 -*-
"""把打标工具打成一个"可以发给管理员"的 zip。

**只打代码，不带任何密钥和台账**：
  · 排除 .env（每个管理员自己用 make_env.py 生成）
  · 排除 mapping.db（水印ID↔QQ 的映射，只有本人该有）
  · 排除 out/ backups/ legacy_samples/（成品、备份、旧样本）
  · 建议排除母本（母本由各人自己放）

用法（在 epub-watermark 目录下）：

    python pack_admin_kit.py                 # → 管理员工具包.zip
    python pack_admin_kit.py -o 给小鱼.zip
"""
from __future__ import annotations

import argparse
import os
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))

# 这些**一定**不能进包
EXCLUDE_FILES = {".env", ".env.bak", "mapping.db", "mapping.db.plain.bak",
                 "recipients.csv", "gui_error.log"}
EXCLUDE_DIRS = {"__pycache__", ".git", "backups", "out", "legacy_samples",
                "files", "data", "node_modules", ".idea", ".vscode"}
EXCLUDE_EXT = {".pyc", ".pyo", ".db", ".log", ".epub", ".zip", ".csv"}
# 这些要带上（即使是 md）
KEEP_EXTRA = {"管理员上手.md", "HANDOVER.md", "使用说明.html"}


def main() -> int:
    ap = argparse.ArgumentParser(description="打一个可发给管理员的工具包")
    ap.add_argument("-o", "--out", default="管理员工具包.zip")
    a = ap.parse_args()

    picked, skipped_secret = [], 0
    for root, dirs, names in os.walk(HERE):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS and not d.startswith(".")]
        for nm in names:
            full = os.path.join(root, nm)
            rel = os.path.relpath(full, HERE)
            ext = os.path.splitext(nm)[1].lower()
            if nm in EXCLUDE_FILES or nm.startswith("recipients") and nm.endswith(".csv"):
                skipped_secret += 1
                continue
            if ext in EXCLUDE_EXT and nm not in KEEP_EXTRA:
                if ext in (".db", ".epub", ".log"):
                    skipped_secret += 1
                continue
            picked.append((full, rel))

    if not picked:
        print("[×] 没找到可打包的文件（是不是在错误的目录跑的？）")
        return 2

    # 保险：绝不能把密钥/台账塞进去
    bad = [r for _f, r in picked
           if os.path.basename(r) in (".env", "mapping.db")]
    if bad:
        print(f"[×] 拒绝打包：包里出现了密钥文件 {bad}")
        return 2

    out = os.path.abspath(a.out)
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for full, rel in picked:
            z.write(full, rel.replace(os.sep, "/"))

    size = os.path.getsize(out) / 1024
    print(f"[√] 已打包 {len(picked)} 个文件 → {out}（{size:.0f} KB）")
    print(f"    已排除密钥/台账类文件 {skipped_secret} 个（.env / mapping.db / 成品 / 备份）")
    print("    包内应包含：管理员上手.md、make_env.py、generate_and_send.py、trace_worker.py …")
    print("\n发给管理员后，让他按「管理员上手.md」走：装 Python 3.10 → make_env.py → 放母本")
    print("⚠️ 别忘了单独把『网页账号 + 初始密码』告诉他，别写在包里")
    return 0


if __name__ == "__main__":
    sys.exit(main())
