# -*- coding: utf-8 -*-
"""生成这台机器专属的 `.env`（密钥文件）。

**每个管理员跑一份自己的**：你自己的 `SERVER_SECRET` / `DB_KEY` 决定"只有你能解开
自己发出去的书"。绝对不要把别人的 `.env` 拷过来覆盖，也不要把它发给任何人。

用法（在工具目录下）：

    python make_env.py            # 已有 .env 就停下来，不覆盖
    python make_env.py --force    # 覆盖重建（⚠️ 旧的书就再也解不开了）
"""
from __future__ import annotations

import argparse
import os
import secrets
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ENV = os.path.join(HERE, ".env")


def main() -> int:
    ap = argparse.ArgumentParser(description="生成本机专属的 .env")
    ap.add_argument("--force", action="store_true", help="覆盖已有的 .env（危险）")
    a = ap.parse_args()

    if os.path.exists(ENV) and not a.force:
        print(f"[!] 已经有 .env 了：{ENV}")
        print("    它是你这台机器唯一的溯源凭据 —— 不要覆盖、不要外发。")
        print("    确实要重建（旧书会永久解不开）再跑：python make_env.py --force")
        return 2

    if os.path.exists(ENV) and a.force:
        try:
            os.rename(ENV, ENV + ".bak")
            print(f"[!] 旧 .env 已备份为 {os.path.basename(ENV)}.bak")
        except OSError:
            pass

    lines = [
        "# 这台机器专属的密钥。丢了 = 你发出去的书永久无法溯源。",
        "# 不要提交到 git，不要发给任何人（包括站长）。",
        f"SERVER_SECRET={secrets.token_hex(32)}",
        f"DB_KEY={secrets.token_hex(24)}",
    ]
    with open(ENV, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    try:
        os.chmod(ENV, 0o600)
    except OSError:
        pass

    print(f"[√] 已生成 {ENV}")
    print("    请把它和 mapping.db、你的母本一起备份（三样缺一不可）")
    print("    下一步：python test_watermark.py  看环境是否正常")
    return 0


if __name__ == "__main__":
    sys.exit(main())
