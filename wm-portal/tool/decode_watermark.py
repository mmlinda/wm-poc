# -*- coding: utf-8 -*-
"""溯源解码：可疑 EPUB → 水印 ID → QQ 号 / 邮箱 / 发送时间。

用法：
    python decode_watermark.py 可疑文件.epub
    python decode_watermark.py 可疑文件.epub --note "闲鱼卖家 xxx" --revoke
    python decode_watermark.py 可疑文件.epub --layers     # 只看层体检，不查身份
"""
from __future__ import annotations

import argparse
import os
import sys

import db
from config import DB_PATH
from watermark_embed import extract_watermark
import layer_report as LR


def main() -> int:
    ap = argparse.ArgumentParser(description="水印溯源解码")
    ap.add_argument("epub", help="可疑 EPUB 路径")
    ap.add_argument("--db", default=DB_PATH)
    ap.add_argument("--note", default="", help="发现渠道备注")
    ap.add_argument("--revoke", action="store_true", help="标记该记录为已封禁")
    ap.add_argument("--no-layers", action="store_true",
                    help="跳过层体检（默认开启，大书可关以提速）")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    if not os.path.isfile(args.epub):
        print(f"[×] 文件不存在: {args.epub}")
        return 2

    conn = db.connect(args.db)
    keys_list = db.all_keys(conn)
    if not keys_list:
        print("[×] 数据库中没有水印密钥，无法解码（先跑 generate_and_send.py）")
        return 2
    print(f"[…] 载入 {len(keys_list)} 组候选密钥，解码 {args.epub}")

    wm_id, channel = extract_watermark(args.epub, keys_list=keys_list)

    # ---- 层体检 ----
    # 默认开启：用户要的不只是"是谁"，还有"这份文件被清洗到什么程度"——
    # 存活几层本身就在告诉你对方的技术水平。大书会慢几秒，可用 --no-layers 关。
    rep = None
    if not args.no_layers:
        # 定位到具体水印之后，只用这一条的密钥做体检：
        # 全量密钥随分发人数线性增长，逐层尝试会让体检慢好几倍
        lr_keys = db.keys_for_watermark(conn, wm_id) if wm_id else keys_list
        rep = LR.analyze_layers(args.epub, lr_keys, watermark_id=wm_id)
        print()
        print(LR.format_layer_report(rep))
        print()

    if not wm_id:
        print("[×] 三个通道均未命中：文件可能非本系统生成，或水印已被完全清除")
        conn.close()
        return 1

    print("\n" + "=" * 58)
    print(f"水印 ID : {wm_id}")
    print(f"命中通道 : {channel}")
    rec = db.find_by_watermark(conn, wm_id)
    if rec:
        print(f"QQ 号   : {rec['qq_number']}")
        print(f"邮 箱   : {rec['email']}")
        print(f"状 态   : {rec['status']}")
        print(f"发送时间 : {rec['sent_at'] or '(未发送)'}")
        print(f"登记时间 : {rec['created_at']}")
        print(f"批次     : {rec['batch_id']}")
        if rec.get("error_message"):
            print(f"错误信息 : {rec['error_message']}")
    else:
        print("映射记录 : 无（该水印未登记，可能来自未入库的测试文件）")

    if args.note or args.revoke:
        # 层体检结果一并入库：以后回看这条溯源记录时，能知道当时这份文件
        # 被清洗到什么程度（是"随手转发"还是"专业处理"）
        conn.execute(
            "INSERT INTO trace_logs (watermark_id, qq_number, channel, source_note, "
            "layers_alive, layers_cleared, clean_ops) VALUES (?,?,?,?,?,?,?)",
            (wm_id, db.enc((rec or {}).get("qq_number", "")), channel, args.note,
             ",".join(rep["alive"]) if rep else "",
             ",".join(rep["cleared"]) if rep else "",
             "; ".join(rep["inferred"]) if rep else ""))
        conn.commit()
        print(f"溯源日志 : 已记录（{args.note or '无备注'}）")
    if args.revoke and rec:
        conn.execute("UPDATE distributions SET status='revoked' WHERE watermark_id=?", (wm_id,))
        conn.commit()
        print(f"封 禁    : {wm_id} 已标记为 revoked（后续分发请排除该 QQ）")

    if args.json:
        import json
        payload = {"watermark_id": wm_id, "channel": channel,
                   "record": {k: v for k, v in (rec or {}).items()
                              if k not in ("chaos_seed", "chaos_mu",
                                           "css_key", "lsb_key")}}
        if rep:
            payload["layers"] = {k: rep[k] for k in
                                 ("alive", "cleared", "damaged", "absent",
                                  "inferred", "verdict", "summary")}
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
