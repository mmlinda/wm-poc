#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""decode_trace.py —— 可疑 EPUB 溯源（Serverless 版：密钥在 Turso，不在本地 mapping.db）

为什么要单独写一个：
    引擎自带的 `decode_watermark.py` 从**本地 mapping.db** 取候选密钥。
    新架构下密钥在 Turso 的 `wm_mapping` 表里，Actions 的 mapping.db 早就没了。
    直接跑原脚本会得到「数据库中没有水印密钥，无法解码」。

用法：
    python poc/decode_trace.py 可疑.epub
    python poc/decode_trace.py 可疑.epub --batch <batch_id>   # 只试这个批次（更快）
    python poc/decode_trace.py --ls                            # 只列库里有密钥的记录数

输出：命中时打印 watermark_id → qq / book / batch，并给出层命中通道。
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ENV_PATH = os.path.join(HERE, ".env.poc")
TOOL = os.path.join(HERE, "..", "wm-portal", "tool")


def load_env() -> dict:
    """环境变量优先（GitHub Actions 里没有 .env.poc），文件只补缺的。"""
    env = {}
    for k in ("TURSO_URL", "TURSO_TOKEN", "POC_SERVER_SECRET", "POC_DB_KEY"):
        if os.environ.get(k):
            env[k] = os.environ[k]
    if os.path.isfile(ENV_PATH):
        for ln in open(ENV_PATH, encoding="utf-8"):
            ln = ln.strip()
            if ln and not ln.startswith("#") and "=" in ln:
                k, _, v = ln.partition("=")
                env.setdefault(k, v)
    return env


def norm_turso(url: str) -> str:
    """libsql://xxx → https://xxx（HTTP pipeline 走 https）。"""
    u = (url or "").strip().rstrip("/")
    if u.startswith("libsql://"):
        u = "https://" + u[len("libsql://"):]
    return u


def turso_pipeline(url: str, token: str, stmts, timeout: int = 60):
    """Turso HTTP pipeline。自己实现，避免 Actions 里还要拖 setup_and_run.py。"""
    payload = {"requests": [
        {"type": "execute", "stmt": {"sql": q, "args": [
            ({"type": "integer", "value": str(a)} if isinstance(a, int) else
             {"type": "float", "value": a} if isinstance(a, float) else
             {"type": "null"} if a is None else
             {"type": "text", "value": str(a)}) for a in (args or [])]}}
        for q, args in stmts]}
    body = json.dumps(payload).encode()
    req = urllib.request.Request(url + "/v2/pipeline", data=body, method="POST",
        headers={"Authorization": "Bearer " + token, "Content-Type": "application/json",
                 "User-Agent": "wm-trace/1.0"})
    # 显式禁用系统代理：本机若有 HTTP_PROXY 会把 Turso 请求塞进不支持的隧道
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(req, timeout=timeout) as r:
        d = json.loads(r.read().decode("utf-8"))
    out = []
    for item in d.get("results") or []:
        if item.get("type") == "ok":
            res = item.get("response", {}).get("result", {})
            cols = [c.get("name") for c in res.get("cols") or []]
            rows = []
            for row in res.get("rows") or []:
                vals = []
                for cell in row:
                    t = cell.get("type")
                    if t == "null":
                        vals.append(None)
                    elif t == "integer":
                        vals.append(int(cell.get("value") or 0))
                    elif t == "float":
                        vals.append(float(cell.get("value") or 0))
                    else:
                        vals.append(cell.get("value"))
                rows.append(vals)
            out.append(("ok", {"cols": cols, "rows": rows}))
        else:
            out.append(("err", item))
    return 200, out, b""


def fetch_keys(env, batch=""):
    """从 Turso 取所有带密钥的映射记录。"""
    url, tok = norm_turso(env["TURSO_URL"]), env["TURSO_TOKEN"]
    # css_key / lsb_key 必须一起取：缺了它们，CSS 与图片层永远解不出来
    # 带上书名：疑文件里的 dc:title 能先把候选从几百条缩到几本（见 narrow_by_title）
    sql = ("SELECT m.watermark_id,m.qq,m.book_id,m.batch_id,m.chaos_seed,m.chaos_mu,"
           "m.css_key,m.lsb_key,m.version_id,IFNULL(b.title,'') AS title "
           "FROM wm_mapping m LEFT JOIN books b ON b.id=m.book_id "
           "WHERE m.chaos_seed IS NOT NULL AND m.chaos_seed != ''")
    args = []
    if batch:
        sql += " AND batch_id=?"
        args.append(batch)
    st, out, raw = turso_pipeline(url, tok, [(sql, args)], timeout=60)
    rows = []
    for r in out or []:
        if r[0] == "ok":
            cols = r[1].get("cols") or []
            for row in r[1].get("rows") or []:
                rows.append(dict(zip(cols, row)))
    return rows


def epub_title(path: str) -> str:
    """从 OPF 里读 dc:title（不依赖第三方库）。"""
    import re
    import zipfile
    try:
        with zipfile.ZipFile(path) as z:
            opf = next((n for n in z.namelist() if n.lower().endswith(".opf")), "")
            if not opf:
                return ""
            text = z.read(opf).decode("utf-8", "replace")
        m = re.search(r"<dc:title[^>]*>(.*?)</dc:title>", text, re.S | re.I)
        return re.sub(r"<[^>]+>", "", m.group(1)).strip() if m else ""
    except Exception:                     # noqa: BLE001
        return ""


def _norm(s: str) -> str:
    import re
    return re.sub(r"[^0-9a-z\u4e00-\u9fff]", "", (s or "").lower())


def narrow_by_title(rows, title: str):
    """按书名把候选密钥缩到"这一本"。

    为什么必须做：每解码一份可疑文件，引擎要把**每条记录的 6 组密钥**都试一遍；
    库里 80 条记录 = 480 组，实测 2.2 秒/组 → 十几分钟（2026-11-27 真实卡死）。
    文件名/OPF 里的书名和 books.title 对得上时，候选通常只剩个位数。
    """
    t = _norm(title)
    if not t or len(t) < 2:
        return rows, 0
    hit = [r for r in rows if _norm(r.get("title", "")) and
           (_norm(r.get("title", "")) in t or t in _norm(r.get("title", "")))]
    return (hit, len(hit)) if hit else (rows, 0)


def build_keys_list(rows):
    """把库里的记录变成引擎要的候选密钥池。

    ⚠ 这里曾经只放 (chaos_seed, chaos_mu) —— 那只是**零宽层**的密钥。
    CSS 层用的是 css_key、图片 DCT 用的是 lsb_key，属性/OPF/ZIP 三层用
    channel_key(name) 派生出来的第三组。只喂 chaos 的话，另外六层永远"解不出"，
    层报告会把它们误判成 not_embedded（看起来像"没嵌进去"，其实是没给对钥匙）。

    正确做法：让引擎自己把一条记录的六个通道密钥都展开（WatermarkKeys.all_keys()）。
    """
    try:
        if TOOL not in sys.path:
            sys.path.insert(0, TOOL)                  # 引擎包在 wm-portal/tool 下
        from core.keys import WatermarkKeys          # noqa: E402
    except Exception:                                 # noqa: BLE001
        WatermarkKeys = None

    keys_list = []
    for r in rows:
        pairs = []
        if WatermarkKeys is not None and r.get("css_key") and r.get("lsb_key"):
            try:
                pairs = WatermarkKeys(
                    watermark_id=r["watermark_id"],
                    chaos_seed=float(r["chaos_seed"]),
                    chaos_mu=float(r["chaos_mu"]),
                    css_key=r["css_key"],
                    lsb_key=r["lsb_key"],
                ).all_keys()
            except Exception:                         # noqa: BLE001
                pairs = []
        if not pairs:
            try:
                pairs = [(float(r["chaos_seed"]), float(r["chaos_mu"]))]
            except (TypeError, ValueError):
                continue
        for p in pairs:
            if p not in keys_list:
                keys_list.append(p)
    return keys_list


def mark_running() -> None:
    """告诉 Worker"我开始解码了"。

    以前只有结束才回调，界面在整段解码期间都显示"排队中"、进度条卡在 92%，
    运营以为卡死了（2026-11-27 反馈）。这里打个卡，界面就能显示"解码中 + 已用时"。
    """
    worker = os.environ.get("WORKER", "").rstrip("/")
    tok = os.environ.get("TRACE_TOKEN", "")
    jid = os.environ.get("JOB_ID", "")
    if not (worker and tok and jid):
        return
    try:
        req = urllib.request.Request(
            worker + "/internal/trace/progress",
            data=json.dumps({"job_id": jid}).encode("utf-8"),
            headers={"Content-Type": "application/json", "X-Trace-Token": tok,
                     "User-Agent": "wm-trace/1.0"})
        urllib.request.urlopen(req, timeout=10).read()
    except Exception:            # noqa: BLE001
        pass                     # 打卡失败不影响解码


def main() -> int:
    ap = argparse.ArgumentParser(description="可疑 EPUB 溯源（密钥取 Turso）")
    ap.add_argument("epub", nargs="?", default="", help="可疑文件路径")
    ap.add_argument("--batch", default="", help="只试某个批次")
    # 零宽层是**铺开到每个正文页**的（embed 时 _zw_pages 全铺），
    # 所以溯源只要扫几页就够命中；多扫只会把"每条记录 × 每页"的代价乘上去。
    ap.add_argument("--max-pages", type=int, default=5,
                    help="扫多少页正文（默认 5；水印每页都有，扫多了只是更慢）")
    ap.add_argument("--max-images", type=int, default=2,
                    help="扫多少张图（图片层最贵；默认 2）")
    ap.add_argument("--ls", action="store_true", help="只统计库里有密钥的记录")
    ap.add_argument("--json", action="store_true", help="输出 TRACE_JSON= 一行，给网页回调消费")
    args = ap.parse_args()

    env = load_env()
    if not env.get("TURSO_URL"):
        print("缺少 .env.poc 里的 TURSO_URL", file=sys.stderr)
        return 2

    rows = fetch_keys(env, args.batch)
    print("库中可溯源的记录：%d 条%s" % (len(rows), ("（batch=%s）" % args.batch) if args.batch else ""))
    if args.ls:
        for r in rows[:10]:
            print("  %s → qq=%s batch=%s" % (r["watermark_id"], r["qq"], (r["batch_id"] or "")[:8]))
        if len(rows) > 10:
            print("  ...")
        return 0

    if not args.epub:
        print("请给出可疑文件路径（或用 --ls 只统计）", file=sys.stderr)
        return 2
    if not rows:
        print("库里没有任何带密钥的记录 —— 说明打标时没把密钥回传（历史上确实如此）", file=sys.stderr)
        return 2

    title = epub_title(args.epub)
    if not args.batch and title:
        orig_n = len(rows)
        rows2, kept = narrow_by_title(rows, title)
        if kept:
            rows = rows2
            print("按书名「%s」收窄候选：%d 条记录（原 %d 条）" % (title, kept, orig_n))
        else:
            print("书名「%s」在库里没对上，仍按全部 %d 条试" % (title, len(rows)))

    keys_list = build_keys_list(rows)
    if not keys_list:
        print("记录里没解析出合法密钥", file=sys.stderr)
        return 2

    # 引擎的 config 在 import 时就要求这两个环境变量（用于校验水印 ID 的签名段）。
    # 这里自动从 .env.poc 注入，省得每次手工 export。
    os.environ.setdefault("SERVER_SECRET", env.get("POC_SERVER_SECRET", ""))
    os.environ.setdefault("DB_KEY", env.get("POC_DB_KEY", ""))
    os.environ.setdefault("DB_PATH", os.path.join(HERE, "_decode_tmp.db"))
    if not os.environ.get("SERVER_SECRET"):
        print("缺少 POC_SERVER_SECRET（在 .env.poc 里）", file=sys.stderr)
        return 2

    sys.path.insert(0, os.path.abspath(TOOL))
    from watermark_embed import extract_watermark       # noqa: E402

    print("用 %d 组候选密钥解码…" % len(keys_list))
    mark_running()
    wid, ch = extract_watermark(args.epub, keys_list=keys_list,
                                max_pages=args.max_pages,
                                max_images=args.max_images)

    # 7 层体检：**没命中也要做**。
    # "抓不到水印"本身需要解释 —— 是本来就没嵌过，还是被对方清干净了？
    # 层报告能区分（cleared vs absent），这直接决定要不要怀疑对方有备而来。 */
    try:
        import layer_report as LR          # noqa: E402
    except Exception as e:                 # noqa: BLE001
        LR = None
        print("[!] 层体检模块不可用：%s" % e, file=sys.stderr)

    rep = None
    if LR is not None:
        try:
            # 已命中时层体检只做浅扫：完整再扫一遍等于把时间翻倍，
            # 而命中的层已经由上面那次扫描给出了结论。
            rep = LR.analyze_layers(args.epub, keys_list,
                                    watermark_id=wid,
                                    max_pages=min(args.max_pages, 4))
        except Exception as e:             # noqa: BLE001
            print("[!] 层体检失败：%s" % e, file=sys.stderr)

    hit = next((r for r in rows if r["watermark_id"] == wid), {}) if wid else {}

    if args.json:
        out = {
            "ok": bool(wid), "watermark_id": wid, "channel": ch,
            "qq": hit.get("qq"), "book_id": hit.get("book_id"),
            "batch_id": hit.get("batch_id"),
        }
        if rep:
            out.update({
                "layers": rep.get("layers"), "summary": rep.get("summary"),
                "verdict": rep.get("verdict"), "strongest": rep.get("strongest"),
                "decoy_note": rep.get("decoy_note"),
                "alive": rep.get("alive"), "cleared": rep.get("cleared"),
                "damaged": rep.get("damaged"), "absent": rep.get("absent"),
            })
        print("TRACE_JSON=" + json.dumps(out, ensure_ascii=False))
        return 0 if wid else 1

    if not wid:
        print("未命中：文件里没有可识别的水印（可能不是本系统产物，或已被剥离）")
        if rep and LR:
            print("\n" + LR.format_layer_report(rep))
        return 1

    print("\n命中！")
    print("  watermark_id : %s" % wid)
    print("  通道         : %s" % ch)
    print("  qq           : %s" % hit.get("qq", "(库里没这条)"))
    print("  book_id      : %s" % hit.get("book_id"))
    print("  batch_id     : %s" % hit.get("batch_id"))
    if rep and LR:
        print("\n" + LR.format_layer_report(rep))
    return 0


if __name__ == "__main__":
    sys.exit(main())
