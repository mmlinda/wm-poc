# -*- coding: utf-8 -*-
"""批量复查：把已生成的 EPUB 逐个做**真实溯源解码**，确认真的能定位到人。

为什么需要它：
    生成时的自检与事后溯源如果扫描范围不一致，就会出现「日志显示成功、
    事后却解不出来」。本脚本走的是与 decode_watermark.py 完全相同的
    解码路径，用来在**发出去之前**把这类问题挑出来。

用法：
    python verify_all.py                     # 复查 out/ 下所有 epub
    python verify_all.py --dir out --json    # 输出 JSON
    python verify_all.py --file x.epub       # 只查一个文件

退出码：全部可解 = 0；存在解不出的 = 1（可接入自动化流程）
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys
import time

import db
from config import DB_PATH, OUTPUT_DIR
from core import css_steg, epub_io, zw_encoder
from watermark_embed import extract_watermark

# 零宽 / 变体选择符字符全集（用于模拟"被清洗"）
ZW_CHARS = set()
for _cs in zw_encoder.CHARSETS.values():
    ZW_CHARS |= set(_cs)
ZW_CHARS |= {chr(c) for c in range(0xE0100, 0xE0100 + 32)}

WM_IN_NAME = re.compile(r"WM-[0-9A-F]{10}-[0-9A-F]{6}")


def keys_for(conn, watermark_id: str) -> list[tuple[float, float]]:
    """某个水印 ID 专用的密钥，优先用它试，比全量试快得多。

    必须复用 db.keys_for_watermark()：它包含 channel_key() 派生的
    attr / opf / zip 三组密钥。此前这里只取库里的 3 组基础密钥，
    导致「快路径」对那三层永远不命中，只能回落全量扫描（纯属变慢），
    还会打出误导性的"专属密钥未命中，请留意"。
    """
    return db.keys_for_watermark(conn, watermark_id)


def check_one(path: str, conn, all_keys: list) -> dict:
    name = os.path.basename(path)
    t0 = time.time()
    res = {"file": name, "ok": False, "watermark_id": "", "channel": "",
            "qq": "", "email": "", "status": "", "seconds": 0.0, "note": ""}

    # 文件名里带着水印 ID 时，先用它自己的密钥试（快）
    hint = WM_IN_NAME.search(name)
    tried_fast = False
    if hint:
        fast = keys_for(conn, hint.group(0))
        if fast:
            tried_fast = True
            wm, ch = extract_watermark(path, keys_list=fast)
            if wm:
                res.update(ok=True, watermark_id=wm, channel=ch or "")
    if not res["ok"]:
        wm, ch = extract_watermark(path, keys_list=all_keys)
        if wm:
            res.update(ok=True, watermark_id=wm, channel=ch or "")
            if tried_fast:
                res["note"] = "专属密钥未命中，靠全量密钥解出（请留意）"
    res["seconds"] = round(time.time() - t0, 1)

    if res["ok"]:
        rec = db.find_by_watermark(conn, res["watermark_id"])
        if rec:
            res.update(qq=rec["qq_number"], email=rec["email"],
                       status=rec["status"])
        else:
            res["note"] = (res["note"] + "；" if res["note"] else "") + "无映射记录"
    return res


def make_variant(src: str, mode: str) -> str:
    """造一个"被攻击过"的副本，用来验证冗余通道是否真的独立可用。"""
    out = src[:-5] + f".{mode}.epub"
    with epub_io.EpubWork(src) as w:
        if mode == "nozw":          # 模拟微信读书等过滤掉全部隐形字符
            for p in w.xhtml_items():
                t, enc = w.read_text(p)
                w.write_text(p, "".join(c for c in t if c not in ZW_CHARS), enc)
        elif mode == "css":         # 模拟样式表被工具重排
            for p in w.css_items():
                t, enc = w.read_text(p)
                new = t
                for b in sorted(css_steg.parse_blocks(t),
                                key=lambda x: x.start, reverse=True):
                    new = (new[:b.start]
                           + css_steg._render(css_steg._canonical_order(b.decls))
                           + new[b.end:])
                w.write_text(p, new, enc)
        w.save(out)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="批量复查成品是否可溯源")
    ap.add_argument("--dir", default=OUTPUT_DIR, help="成品目录（默认 out/）")
    ap.add_argument("--file", default="", help="只查指定文件")
    ap.add_argument("--db", default=DB_PATH)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--layers", action="store_true",
                    help="额外模拟攻击：清除零宽 / 重排 CSS，验证冗余通道独立可用")
    args = ap.parse_args()

    files = [args.file] if args.file else sorted(
        glob.glob(os.path.join(args.dir, "*.epub")))
    files = [f for f in files if os.path.isfile(f)]
    if not files:
        print(f"[×] 目录下没有 epub：{args.dir}")
        return 2

    conn = db.connect(args.db)
    all_keys = db.all_keys(conn)
    if not all_keys:
        print("[×] 数据库里没有水印密钥，无法复查（先跑 generate_and_send.py）")
        return 2

    print(f"[…] 复查 {len(files)} 个文件（候选密钥 {len(all_keys)} 组）")
    results = []
    for f in files:
        r = check_one(f, conn, all_keys)
        if args.layers and r["ok"]:
            r["layers"] = {}
            for mode in ("nozw", "css"):
                tmp = make_variant(f, mode)
                try:
                    wm, ch = extract_watermark(tmp, keys_list=all_keys)
                    r["layers"][mode] = (ch if wm == r["watermark_id"] else "FAIL")
                finally:
                    try:
                        os.remove(tmp)
                    except OSError:
                        pass
        results.append(r)
    conn.close()

    bad = [r for r in results if not r["ok"]]
    if args.json:
        print(json.dumps({"total": len(results), "ok": len(results) - len(bad),
                          "failed": len(bad), "items": results},
                         ensure_ascii=False, indent=2))
    else:
        print()
        for r in results:
            flag = "OK  " if r["ok"] else "FAIL"
            if r["ok"]:
                extra = ""
                if r.get("layers"):
                    extra = " | 清洗零宽:" + str(r["layers"].get("nozw")) \
                            + " 重排CSS:" + str(r["layers"].get("css"))
                print(f"  [{flag}] {r['file'][:52]:<52} {r['channel']:<12} "
                      f"QQ:{r['qq'] or '-':<12} {r['seconds']}s{extra}")
            else:
                print(f"  [{flag}] {r['file'][:52]:<52} 解不出水印")
        print()
        print(f"合计 {len(results)} 个：可溯源 {len(results) - len(bad)}，"
              f"失败 {len(bad)}")
        if bad:
            print("失败清单（不要发出去，重新生成）：")
            for r in bad:
                print("   -", r["file"])
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
