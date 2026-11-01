# -*- coding: utf-8 -*-
"""对抗模拟：把刚生成的副本拿去"洗"一遍，看还剩几层能溯源。

为什么要有这个脚本：
    光看"生成成功"没有意义 —— 真正要回答的是"对方清洗之后还能不能查到人"。
    这里按已知的清洗手法逐个模拟，量化每一层的存活情况。

    ⚠️ 注意：模拟出来的"清洗者"比真实倒卖者强得多（它知道所有层的存在），
    所以它洗不掉的，真人也基本洗不掉；它能洗掉的，真人未必洗得掉。
    把它当成**下限**看：结果越差越要警惕，结果好不代表高枕无忧。

用法：
    python adversarial_sim.py                       # 用 mother.epub 现造一份
    python adversarial_sim.py --epub out/xxx.epub   # 直接用已有成品
    python adversarial_sim.py --epub a.epub --json
"""
from __future__ import annotations

import argparse
import io
import json
import os
import re
import shutil
import sys
import tempfile
import time
import warnings
import zipfile

warnings.simplefilter("ignore")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from PIL import Image                                   # noqa: E402

from core import epub_io, keys as K                     # noqa: E402
from crypto_utils import generate_watermark_id          # noqa: E402
import layer_report as LR                               # noqa: E402
from watermark_embed import embed_watermark             # noqa: E402

# 不可见 / 格式字符全集（与对抗方口径一致：Unicode Cf 类别 + 常见补充）
import unicodedata                                      # noqa: E402
_INVIS = sorted(
    {chr(c) for c in range(0x110000)
     if unicodedata.category(chr(c)) == "Cf"} |
    {chr(c) for c in (0x3164, 0xFFA0, 0x115F, 0x1160, 0x2800)})
_INVIS_RE = re.compile("[" + re.escape("".join(_INVIS)) + "]")

# 诱饵 / 扩容用的自定义属性块
_WM_BLOCK_RE = re.compile(r"[^{};]*\{[^{}]*--wm-[^{}]*\}")


# ------------------------------------------------------------------ 清洗手法
def op_strip_invisible(work) -> None:
    """① 附加型：剥掉全部不可见字符（最常见，一行正则就能做）。"""
    for p in work.xhtml_items():
        t, enc = work.read_text(p)
        work.write_text(p, _INVIS_RE.sub("", t), enc)


def op_normalize_quotes(work) -> None:
    """② 标记层：属性引号统一为双引号（渲染零差异，diff 才看得出）。"""
    for p in work.xhtml_items():
        t, enc = work.read_text(p)
        # 只处理标签内部：把 attr='..' 换成 attr=".."
        def _fix(m):
            return m.group(1) + '"' + m.group(2) + '"'
        new = re.sub(r"(=)'(.*?)'", _fix, t, flags=re.S)
        work.write_text(p, new, enc)


def op_strip_wm_css(work) -> None:
    """③ 样式层：删掉 --wm- 自定义属性块（对抗方报告里的第一发现）。"""
    for p in work.css_items():
        t, enc = work.read_text(p)
        work.write_text(p, _WM_BLOCK_RE.sub("", t), enc)


def op_normalize_opf(work) -> None:
    """④ 元数据层：把 manifest / spine 按名称重排（Sigil 另存会做）。

    按**整行**重排而不是按正则匹配重排：后者会把中间的文本也搬走，
    很容易拼出"junk after document element"这种坏 XML。
    """
    try:
        opf = work.opf_text
    except Exception:                                   # noqa: BLE001
        return
    lines = opf.split("\n")
    for tag in ("item", "itemref"):
        out, i = [], 0
        while i < len(lines):
            if re.search(r"<%s[\s/>]" % tag, lines[i]):
                j = i
                while j < len(lines) and re.search(r"<%s[\s/>]" % tag, lines[j]):
                    j += 1
                block = [ln for ln in lines[i:j]]
                # 只重排"单行自闭合"的条目，跨行条目保持原样更安全
                if all(ln.rstrip().endswith("/>") for ln in block):
                    out.extend(sorted(block, key=lambda s: s.strip()))
                else:
                    out.extend(block)
                i = j
            else:
                out.append(lines[i])
                i += 1
        lines = out
    if work.opf_path:
        work.write_text(work.opf_path, "\n".join(lines), work.opf_enc)


def op_rebuild_zip(src: str, dst: str) -> None:
    """⑤ 容器层：按文件名排序重新打包（容器层唯一的死穴）。"""
    with zipfile.ZipFile(src) as zin, zipfile.ZipFile(dst, "w",
                                                      zipfile.ZIP_DEFLATED) as zout:
        for info in sorted(zin.infolist(), key=lambda i: i.filename):
            data = zin.read(info.filename)
            zi = zipfile.ZipInfo(info.filename, date_time=info.date_time)
            zi.compress_type = zipfile.ZIP_DEFLATED
            zout.writestr(zi, data)


def op_recompress_images(work) -> None:
    """⑥ 介质层：把图片重编码一遍（专业处理，一般人不会做）。"""
    for name, _size in work.image_items():
        try:
            raw = work.read_raw(name)
            img = Image.open(io.BytesIO(raw))
            if img.mode == "P":
                continue                    # 调色板图重编码代价大，真人也常跳过
            buf = io.BytesIO()
            img.convert("RGB").save(buf, format="JPEG", quality=82)
            work.write_raw(name, buf.getvalue())
        except Exception:                               # noqa: BLE001
            continue


# (名称, 说明, 是否要重建 zip)
_SCENARIOS = [
    ("原样",           "不做任何处理（对照基准）",                 None),
    ("去不可见字符",   "正则剥掉全部 Cf 字符",                     "invisible"),
    ("统一属性引号",   "attr='x' 全部改成 attr=\"x\"",             "quotes"),
    ("删 --wm- 样式",  "删掉 CSS 里的自定义属性块（含诱饵）",       "wmcss"),
    ("重排 OPF",       "manifest / spine 按名称重排",              "opf"),
    ("重新打包",       "ZIP 按文件名排序重建",                     "rezip"),
    ("重编码图片",     "图片 JPEG q82 重新压缩（专业手法）",        "reimg"),
    ("全套清洗",       "上面全部做一遍（最强对手）",                "all"),
]


def make_variant(src: str, kind: str | None, tmpdir: str, tag: str) -> str:
    out = os.path.join(tmpdir, f"{tag}.epub")
    if kind is None:
        shutil.copy(src, out)
        return out
    if kind == "rezip":
        op_rebuild_zip(src, out)
        return out

    with epub_io.EpubWork(src) as w:
        if kind in ("invisible", "all"):
            op_strip_invisible(w)
        if kind in ("quotes", "all"):
            op_normalize_quotes(w)
        if kind in ("wmcss", "all"):
            op_strip_wm_css(w)
        if kind in ("opf", "all"):
            op_normalize_opf(w)
        if kind in ("reimg", "all"):
            op_recompress_images(w)
        w.save(out)
    if kind == "all":
        rezip = out + ".z.epub"
        op_rebuild_zip(out, rezip)
        os.replace(rezip, out)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="对抗模拟：清洗后还剩几层能溯源")
    ap.add_argument("--epub", default="", help="已有成品；不给就用 mother.epub 现造")
    ap.add_argument("--keys", default="", help="该成品的水印 ID（不给就现造一份）")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    tmpdir = tempfile.mkdtemp(prefix="wmadv_")
    src, wid, keys_list = args.epub, None, None

    if src:
        if not os.path.isfile(src):
            print(f"[×] 文件不存在: {src}")
            return 2
        # 优先从数据库取密钥（真实分发的成品都是随机密钥，无法从 ID 派生）
        if os.path.isfile("mapping.db"):
            try:
                import db
                conn = db.connect("mapping.db")
                keys_list = db.all_keys(conn)
                rec = None
                m = re.search(r"WM-[0-9A-F]{10}-[0-9A-F]{6}",
                              os.path.basename(src))
                if m:
                    wid = m.group(0)
                    rec = db.find_by_watermark(conn, wid)
                conn.close()
                if keys_list:
                    print(f"[…] 从 mapping.db 载入 {len(keys_list)} 组密钥")
                    if rec:
                        print(f"    登记人: QQ {rec.get('qq_number')} "
                              f"{rec.get('email')}")
            except Exception as exc:                    # noqa: BLE001
                print(f"[!] 读库失败: {exc}")
        if not keys_list:
            # 兜底：按文件名里的水印 ID 派生（只适用于测试用的确定性密钥）
            m = re.search(r"WM-[0-9A-F]{10}-[0-9A-F]{6}", os.path.basename(src))
            if m:
                wid = m.group(0)
                from watermark_embed import derive_keys
                keys_list = derive_keys(wid).all_keys()
    else:
        mother = "mother.epub"
        if not os.path.isfile(mother):
            from core.epub_io import make_sample_epub
            make_sample_epub(mother)
        src = os.path.join(tmpdir, "src.epub")
        wid = generate_watermark_id()
        print(f"[…] 现造一份带水印的副本：{wid}")
        rep = embed_watermark(mother, wid, src, on_step=lambda m: None)
        # 必须用**实际嵌入时用的密钥**，而不是从 ID 派生 ——
        # embed_watermark 默认用随机密钥，两者不是一回事
        keys_list = K.WatermarkKeys(
            wid, rep["keys"]["chaos_seed"], rep["keys"]["chaos_mu"],
            rep["keys"]["css_key"], rep["keys"]["lsb_key"]).all_keys()
        print(f"    零宽页 {rep.get('zw_pages')} / 属性 {rep.get('attributes')}"
              f" / 图 {rep.get('images')} / 诱饵 {rep.get('decoy')}")

    if not keys_list:
        print("[×] 没有可用密钥（成品文件名里没有 WM- 水印 ID）")
        return 2

    print()
    print("=" * 74)
    print("  对抗模拟：模拟各种清洗手法，看还剩几层能溯源")
    print("=" * 74)
    print(f"  样本: {os.path.basename(src)}")
    print(f"  水印: {wid}")
    print()

    results = []
    for tag, desc, kind in _SCENARIOS:
        try:
            vpath = make_variant(src, kind, tmpdir, tag)
            t0 = time.time()
            rep = LR.analyze_layers(vpath, keys_list, watermark_id=wid)
            ok = rep["verdict"] == "可溯源"
            results.append({"scenario": tag, "desc": desc, "ok": ok,
                            "alive": len(rep["alive"]),
                            "layers": rep["alive"],
                            "cleared": rep["cleared"],
                            "decoy": rep["decoy"], "seconds": round(
                                time.time() - t0, 1)})
            flag = "可溯源" if ok else "失  败"
            print("  %-14s %-36s %s  存活 %d/7  诱饵:%s" % (
                tag, desc, flag, len(rep["alive"]),
                "在" if rep["decoy"] else "已清除"))
            print("  %-14s %s" % ("", ",".join(rep["alive"]) or "（无）"))
        except Exception as exc:                        # noqa: BLE001
            results.append({"scenario": tag, "desc": desc, "ok": False,
                            "error": str(exc)})
            print(f"  {tag:<14} 模拟失败: {exc}")

    print()
    print("=" * 74)
    worst = [r for r in results if not r.get("ok")]
    if not worst:
        print("  全部场景都能溯源 —— 即使「全套清洗」也查得到人。")
    else:
        print("  以下场景会失效（需要重点关注）：")
        for r in worst:
            print(f"    · {r['scenario']}：{r['desc']}")
    print("=" * 74)

    if args.json:
        print(json.dumps(results, ensure_ascii=False, indent=2))
    shutil.rmtree(tmpdir, ignore_errors=True)
    return 0 if not worst else 1


if __name__ == "__main__":
    sys.exit(main())
