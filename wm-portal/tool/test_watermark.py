# -*- coding: utf-8 -*-
"""单元 + 集成测试（不需要任何外部服务，离线可跑）。

    python test_watermark.py
"""
from __future__ import annotations

import io
import os
import re
import shutil
import sys
import tempfile

import numpy as np
from PIL import Image

from config import PSNR_THRESHOLD
from crypto_utils import (generate_watermark_id, sign_random_part,
                          verify_watermark_id)
import layer_report as LR
import watermark_embed
from watermark_embed import (dct_qim_embed, dct_qim_extract, derive_keys,
                             embed_watermark, extract_watermark, check_psnr,
                             precheck_mother, select_candidates, to_payload, from_payload)
from core import epub_io, zw_encoder, css_steg, keys as keys_mod

PASS, FAIL = [], []
HERE = os.path.dirname(os.path.abspath(__file__))

# 只匹配诱饵块（--wm-a / --wm-b），用于验证"诱饵与真实 CSS 通道正交"
_decoy_only_re = re.compile(r"[^{};]*\{[^{}]*--wm-[ab]\d*\s*:[^{}]*\}")
# 匹配所有 --wm- 自定义属性块（真实扩容声明 + 诱饵），模拟"对方整块清洗"
_wm_block_re = re.compile(r"[^{};]*\{[^{}]*--wm-[^{}]*\}")


def check(name: str, cond: bool, extra: str = "") -> None:
    (PASS if cond else FAIL).append(name)
    print(f"  [{'√' if cond else '×'}] {name}" + (f"  {extra}" if extra else ""))


def make_realistic_image(w: int = 800, h: int = 800) -> Image.Image:
    x = np.linspace(0, 255, w)
    y = np.linspace(0, 255, h)
    xx, yy = np.meshgrid(x, y)
    base = ((xx + yy) / 2).astype(np.uint8)
    noise = np.random.randint(-10, 10, (h, w), dtype=np.int16)
    gray = np.clip(base.astype(np.int16) + noise, 0, 255).astype(np.uint8)
    return Image.fromarray(np.stack([gray, gray, gray], axis=2))


def ensure_mother() -> str:
    """没有 mother.epub 时自动生成一本样本书用于测试。"""
    mother = os.path.join(HERE, "mother.epub")
    if not os.path.exists(mother):
        epub_io.make_sample_epub(mother, chapters=3, paragraphs=60)
        print(f"[…] 未找到 mother.epub，已生成样本书 → {mother}")
    return mother


# ------------------------------------------------------------------ 用例

def test_hmac() -> None:
    print("\n[1] HMAC 水印 ID")
    wid = generate_watermark_id()
    check("签名可验证", verify_watermark_id(wid), wid)
    check("伪造被拒绝", not verify_watermark_id("WM-FAKE000000-ABCDEF"))
    check("篡改被拒绝", not verify_watermark_id(wid[:5] + "ZZ" + wid[7:]))


def test_phase4_roundtrip() -> None:
    print("\n[2] 图片 QIM 往返")
    img = make_realistic_image()
    wid = generate_watermark_id()
    key = derive_keys(wid).lsb()
    marked = dct_qim_embed(img, wid, "image/jpeg", key=key)
    got = dct_qim_extract(marked, keys=[key])
    check("PNG/JPEG 往返", got == wid, str(got))

    psnr = check_psnr(img, marked, PSNR_THRESHOLD)
    check(f"PSNR ≥ {PSNR_THRESHOLD}dB", psnr >= PSNR_THRESHOLD, f"{psnr:.1f} dB")


def test_phase4_jpeg() -> None:
    print("\n[3] 图片 QIM 抗 JPEG 重压缩")
    img = make_realistic_image()
    wid = generate_watermark_id()
    key = derive_keys(wid).lsb()
    marked = dct_qim_embed(img, wid, "image/jpeg", key=key)
    for q in (90, 85, 75):
        buf = io.BytesIO()
        marked.save(buf, format="JPEG", quality=q)
        buf.seek(0)
        got = dct_qim_extract(Image.open(buf).convert("RGB"), keys=[key])
        check(f"JPEG q={q} 仍可解", got == wid, str(got))


def test_phase4_keyed_positions() -> None:
    print("\n[4] 抗差分攻击（不同用户的水印落在不同块）")
    img = make_realistic_image()
    a = dct_qim_embed(img, generate_watermark_id(), "image/png", key=(0.11, 3.61))
    b = dct_qim_embed(img, generate_watermark_id(), "image/png", key=(0.83, 3.99))
    diff = np.abs(np.asarray(a, dtype=np.int16) - np.asarray(b, dtype=np.int16))
    # 若块位置不随密钥变化，两份文件的差异会集中在相同的前 N 个块；
    # 这里只验证「差异分布不是固定前缀」这一必要条件
    blocks_h = diff.shape[0] // 8
    top = diff[:8 * 12].mean()          # 前 12 行块
    bottom = diff[-8 * 12:].mean()      # 后 12 行块
    check("改动分布随密钥扩散（非固定前缀）", bottom > top * 0.3,
          f"前段={top:.2f} 后段={bottom:.2f}")
    del blocks_h


def test_full_pipeline() -> None:
    print("\n[5] 完整 EPUB 流程往返")
    mother = ensure_mother()
    tmp = tempfile.mkdtemp(prefix="wm_")
    try:
        precheck_mother(mother)
        wid = generate_watermark_id()
        keys = derive_keys(wid)
        out = os.path.join(tmp, "out.epub")
        rep = embed_watermark(mother, wid, out, keys=keys)
        check("三通道自检至少两个通过",
              sum([rep["zero_width"], rep.get("css", False), rep["image_qim"]]) >= 2,
              f"零宽={rep['zero_width']} CSS={rep.get('css')} 图片={rep['image_qim']}")
        check("封面 PSNR 达标", rep.get("psnr", 0) >= PSNR_THRESHOLD, f"{rep.get('psnr')} dB")

        got, ch = extract_watermark(out, keys_list=keys.all_keys())
        check("解出水印 ID", got == wid, f"{got} via {ch}")

        # 排版保真
        from core.textscan import iter_text_segments
        zw_set = set(zw_encoder.CHARSETS["ext8"])
        vs_set = {chr(0xE0100 + i) for i in range(32)}
        with epub_io.EpubWork(mother) as a, epub_io.EpubWork(out) as b:
            same = True
            for p in a.xhtml_items():
                ta, _ = a.read_text(p)
                tb, _ = b.read_text(p)
                def norm(t):
                    t = "".join(c for c in t if c not in zw_set and c not in vs_set)
                    return t.replace("'", '"')      # 属性引号层会改引号，统一后比较
                fa, fb = norm(ta), norm(tb)
                if fa != fb:
                    same = False
                    break
        check("去掉隐形字符后正文逐字一致", same)

        # 抗清洗：删掉所有零宽字符，图片通道仍应存活
        cleaned = os.path.join(tmp, "clean.epub")
        with epub_io.EpubWork(out) as w:
            for p in w.xhtml_items():
                t, enc = w.read_text(p)
                w.write_text(p, "".join(c for c in t if c not in zw_set), enc)
            w.save(cleaned)
        got2, ch2 = extract_watermark(cleaned, keys_list=keys.all_keys())
        check("清除零宽后仍可溯源", got2 == wid, f"{got2} via {ch2}")

        # 抗清洗：CSS 被重排
        recss = os.path.join(tmp, "recss.epub")
        with epub_io.EpubWork(out) as w:
            for p in w.css_items():
                t, enc = w.read_text(p)
                blocks = css_steg.parse_blocks(t)
                new = t
                for b in sorted(blocks, key=lambda x: x.start, reverse=True):
                    new = new[:b.start] + css_steg._render(css_steg._canonical_order(b.decls)) + new[b.end:]
                w.write_text(p, new, enc)
            w.save(recss)
        got3, ch3 = extract_watermark(recss, keys_list=keys.all_keys())
        check("CSS 重排后仍可溯源", got3 == wid, f"{got3} via {ch3}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_wrong_key() -> None:
    print("\n[6] 密钥隔离")
    mother = ensure_mother()
    tmp = tempfile.mkdtemp(prefix="wm_")
    try:
        wid = generate_watermark_id()
        out = os.path.join(tmp, "o.epub")
        embed_watermark(mother, wid, out, keys=derive_keys(wid))
        other = derive_keys("WM-0000000000-000000").all_keys()
        got, _ = extract_watermark(out, keys_list=other)
        check("错误密钥解不出", got is None, str(got))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_multi_image_cover_swap() -> None:
    """只开图片通道：验证「换掉封面也解得出」——插图才是主力载体。"""
    print("\n[7] 多插图嵌入 + 换封面后仍可溯源")
    import importlib
    import config
    mother = ensure_mother()
    tmp = tempfile.mkdtemp(prefix="wm_")
    try:
        saved = (config.ZW_ENABLED, config.CSS_ENABLED, config.MAX_IMAGES)
        config.ZW_ENABLED = False
        config.CSS_ENABLED = False
        config.MAX_IMAGES = 12
        importlib.reload(watermark_embed)          # 让新配置重新绑定

        with epub_io.EpubWork(mother) as w:
            n_all = len(select_candidates(w, 99))
        check("母本含多张可用插图", n_all >= 3, f"{n_all} 张")

        wid = generate_watermark_id()
        out = os.path.join(tmp, "o.epub")
        rep = watermark_embed.embed_watermark(mother, wid, out)
        check("图片通道生效", rep["image_qim"], f"嵌入 {rep['images']} 张")
        check("不止嵌封面一张", rep["images"] >= 2, f"{rep['images']} 张")
        keys = rep["keys"]
        cand = [keys["chaos_seed"] and (keys["chaos_seed"], keys["chaos_mu"]),
                _pair(keys["css_key"]), _pair(keys["lsb_key"])]
        cand = [c for c in cand if c]

        swapped = os.path.join(tmp, "swap.epub")
        with epub_io.EpubWork(out) as w:
            cover = w.cover_item()
            buf = io.BytesIO()
            Image.new("RGB", (600, 800), (30, 60, 90)).save(buf, "JPEG", quality=92)
            w.write_raw(cover, buf.getvalue())
            w.save(swapped)
        got, ch = watermark_embed.extract_watermark(swapped, keys_list=cand)
        check("换掉封面后仍由插图解出", got == wid, f"{got} via {ch}")
    finally:
        config.ZW_ENABLED, config.CSS_ENABLED, config.MAX_IMAGES = saved
        importlib.reload(watermark_embed)
        shutil.rmtree(tmp, ignore_errors=True)


def _pair(text):
    try:
        a, b = str(text).split(",")[:2]
        return (float(a), float(b))
    except (ValueError, AttributeError):
        return None


def make_palette_png(w: int = 420, h: int = 320) -> Image.Image:
    """造一张「调色板 + 透明蒙版」的 PNG，模拟精排书的头图。"""
    rng = np.random.RandomState(7)
    # 横向渐变 + 噪声，模拟真实头图的丰富色阶（180 色左右）
    ramp = (np.linspace(0, 1, w) * 176).astype(np.int16) + 1
    idx = np.tile(ramp, (h, 1))
    idx = np.clip(idx + rng.randint(-4, 5, (h, w)), 1, 180)
    idx[:40, :] = 0                              # 顶部整块透明 = 蒙版
    idx = idx.astype(np.uint8)
    pal = [0] * 768
    pal[0:3] = [255, 255, 255]     # 索引 0：透明区（会被蒙版遮住）
    for i in range(1, 256):
        v = 40 + (i * 7) % 200
        pal[i * 3:i * 3 + 3] = [v, (v * 2) % 256, (255 - v)]
    img = Image.fromarray(idx, mode="P")
    img.putpalette(pal)
    img.info["transparency"] = 0   # 索引 0 完全透明
    return img


def test_palette_channel() -> None:
    """带蒙版的调色板 PNG：水印要能嵌进去，蒙版/体积/模式都不能变。"""
    print("\n[8] 调色板通道（带蒙版头图）")
    from core import palette_steg as pst
    src = make_palette_png()
    buf = io.BytesIO()
    src.save(buf, format="PNG", optimize=True)
    data = buf.getvalue()

    wid = generate_watermark_id()
    key = derive_keys(wid).lsb()
    out, info = pst.embed_palette(data, to_payload(wid), *key, copies=3)

    got_p = pst.decode_palette(out, [key])
    ok = bool(got_p) and from_payload(got_p[0]["watermark_id"]) == wid
    check("调色板往返解码", ok, str(info.get("colors")) + " 色")

    a = Image.open(io.BytesIO(data))
    b = Image.open(io.BytesIO(out))
    check("仍是调色板 P 模式", b.mode == "P", b.mode)
    check("透明蒙版保留", "transparency" in b.info, str(b.info.get("transparency")))
    check("像素数据零改动（蒙版不受影响）",
          np.array_equal(np.asarray(a), np.asarray(b)))
    ratio = len(out) / len(data)
    check("体积基本不变（<±10%）", 0.9 < ratio < 1.1, f"{ratio:.3f}x")

    # 重新保存一次后仍应可解（模拟阅读器/工具另存）
    buf2 = io.BytesIO()
    b.save(buf2, format="PNG", optimize=True)
    check("重新保存后仍可解码",
          bool(pst.decode_palette(buf2.getvalue(), [key])))


def test_container_and_meta_layers() -> None:
    """容器层（ZIP 顺序）与元数据层（OPF 顺序）—— 并验证它们的已知边界。"""
    print("\n[9] 六层正交（容器层 / 元数据层）")
    import zipfile
    from core import epub_io as epubio
    from watermark_embed import _collect_channels

    tmp = tempfile.mkdtemp(prefix="wm_")
    try:
        # 排列通道需要足够多的条目（n! 要大于载荷），造一本条目够多的样本
        mother = os.path.join(tmp, "big.epub")
        epubio.make_sample_epub(mother, chapters=14, paragraphs=18, figures=10)
        wid = generate_watermark_id()
        out = os.path.join(tmp, "o.epub")
        rep = embed_watermark(mother, wid, out)
        kk = keys_mod.WatermarkKeys(
            wid, rep["keys"]["chaos_seed"], rep["keys"]["chaos_mu"],
            rep["keys"]["css_key"], rep["keys"]["lsb_key"])
        hits = _collect_channels(out, kk.all_keys())
        good = {c: w for c, w in hits.items() if w == wid}
        check("属性层（XHTML 引号）", "attributes" in good)
        check("元数据层（OPF 顺序）", "opf_order" in good)
        check("容器层（ZIP 顺序）", "zip_order" in good)
        check("命中层数 ≥ 5", len(good) >= 5, str(sorted(good)))

        # 已知边界：重新打包会丢掉容器层，但内容层必须还在
        # 普通"解压再压"若保持顺序，容器层其实还在；真正会破坏的是
        # 按文件名排序重写（部分打包/整理工具的行为）
        repacked = os.path.join(tmp, "repack.epub")
        with zipfile.ZipFile(out) as zin, zipfile.ZipFile(repacked, "w") as zout:
            for info in sorted(zin.infolist(), key=lambda i: i.filename):
                data = zin.read(info.filename)
                ni = zipfile.ZipInfo(info.filename, date_time=info.date_time)
                ni.compress_type = info.compress_type
                zout.writestr(ni, data)
        hits2 = _collect_channels(repacked, kk.all_keys())
        good2 = {c: w for c, w in hits2.items() if w == wid}
        check("重排打包后容器层失效（符合预期）", "zip_order" not in good2)
        check("重打包后仍能溯源", len(good2) >= 3, str(sorted(good2)))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_payload_roundtrip() -> None:
    """[10] B1 回归：5 字节随机段必须 1:1 还原。

    历史上 parse_payload() 先试 UTF-8 —— 约 1.9% 的水印 ID 的 5 个随机字节
    恰好是合法 UTF-8，会被解成多字节字符，from_payload() 再 encode('latin-1')
    还原不回来 → verify_watermark_id() 恒 False → 三通道自检全 False
    （而嵌入其实是成功的）。且重试无效：payload 只由 watermark_id 决定，
    换密钥（chaos/css/lsb）救不了。这正是"连续 6 次自检失败"的真因。
    """
    print("\n[10] 载荷往返（B1 回归：含历史坏 ID）")
    from core.payload import build_payload, parse_payload

    fixed = ("E5929C5234", "6104C9A736", "1122334455", "0000000000", "FFFFFFFFFF")
    ok = 0
    for rp in fixed:
        wid = sign_random_part(rp)
        got = from_payload(parse_payload(build_payload(to_payload(wid), 1)))
        if got == wid and verify_watermark_id(got):
            ok += 1
    check("固定历史坏 ID 全部可还原", ok == len(fixed), f"{ok}/{len(fixed)}")

    import secrets
    N = 20000
    bad = 0
    for _ in range(N):
        rp = "".join("0123456789ABCDEF"[secrets.randbelow(16)] for _ in range(10))
        wid = sign_random_part(rp)
        got = from_payload(parse_payload(build_payload(to_payload(wid), 1)))
        if not (got == wid and verify_watermark_id(got)):
            bad += 1
    check(f"随机 {N} 次往返零失败", bad == 0, f"失败 {bad} 次")

    # ---- 两代兼容（这条决定"改动是否会让已发出去的旧副本失联"）----
    # 新解码器必须是旧解码器的**超集**：旧代码能还原的，新代码必须也能。
    # 反过来说是：不允许出现"以前能解、现在不能"的回归。
    def old_pipeline(wid: str) -> str:
        """复现旧版：parse_payload 先试 UTF-8，from_payload 走 latin-1 还原。"""
        raw = build_payload(to_payload(wid), 1)
        body = raw[5:5 + raw[4]]
        try:
            text = body.decode("utf-8")          # ← 旧版的 UTF-8 优先
        except UnicodeDecodeError:
            text = body.decode("latin-1")
        if not text:
            return ""
        if text.startswith("WM-") and len(text) > 10:
            return text
        try:
            raw_back = text.encode("latin-1")
        except UnicodeEncodeError:
            return text
        return sign_random_part(raw_back.hex().upper()) if len(raw_back) == 5 else text

    def new_pipeline(wid: str) -> str:
        return from_payload(parse_payload(build_payload(to_payload(wid), 1)))

    regression = improved = 0
    N2 = 50000
    for _ in range(N2):
        rp = "".join("0123456789ABCDEF"[secrets.randbelow(16)] for _ in range(10))
        wid = sign_random_part(rp)
        o, n = old_pipeline(wid), new_pipeline(wid)
        if o == wid and n != wid:
            regression += 1
        elif n == wid and o != wid:
            improved += 1
    check("两代兼容：无「以前能解、现在不能」的回归", regression == 0,
          f"回归 {regression}；新救回 {improved}/{N2}（旧代码必失败的坏 ID）")


def test_decoy_end_to_end() -> None:
    """[11] B2 回归（端到端）：诱饵要真的落盘、检得出来，且不被误判。

    历史上 decoy.embed_decoy() 复用 css_steg.embed_css()，而后者为保 CSS 通道
    正交加了 _is_decoy_block() 排除规则 —— 诱饵块被自己排除干净，从未落盘，
    detect_decoy() 恒 False，层体检于是对**任何干净文件**都报
    "诱饵已被清除、对方有备而来"（与"这份文件没被清洗"自相矛盾）。
    """
    print("\n[11] 诱饵探针 + 层体检（B2 回归，端到端）")
    mother = ensure_mother()
    tmp = tempfile.mkdtemp(prefix="wm_")
    try:
        wid = generate_watermark_id()
        keys = derive_keys(wid)
        out = os.path.join(tmp, "d.epub")
        rep = embed_watermark(mother, wid, out, keys=keys)
        check("嵌入报告 decoy=True", bool(rep.get("decoy")))

        r = LR.analyze_layers(out, keys.all_keys(), watermark_id=wid)
        check("层体检：诱饵仍在", bool(r["decoy"]))
        check("层体检：不再误报「对方有备而来」",
              "有备而来" not in r["decoy_note"], r["decoy_note"][:40])
        check("层体检：结论行不重复打印",
              "层    存活" not in LR.format_layer_report(r))

        # 正交性：删掉诱饵块不应影响真实 CSS 通道（反之亦然）
        nodecoy = os.path.join(tmp, "nodecoy.epub")
        with epub_io.EpubWork(out) as w:
            for p in w.css_items():
                t, enc = w.read_text(p)
                w.write_text(p, _decoy_only_re.sub("", t), enc)
            w.save(nodecoy)
        r2 = LR.analyze_layers(nodecoy, keys.all_keys(), watermark_id=wid)
        check("删掉诱饵块后 CSS 层仍在可溯源结果里", r2["verdict"] == "可溯源",
              ",".join(r2["alive"]))

        # 模拟"对方把 --wm- 块整块清掉" → 诱饵必须消失
        cleaned = os.path.join(tmp, "c.epub")
        with epub_io.EpubWork(out) as w:
            for p in w.css_items():
                t, enc = w.read_text(p)
                w.write_text(p, _wm_block_re.sub("", t), enc)
            w.save(cleaned)
        r3 = LR.analyze_layers(cleaned, keys.all_keys(), watermark_id=wid)
        check("整块清洗后诱饵消失（探针有效）", not r3["decoy"])
        check("整块清洗后仍可溯源", r3["verdict"] == "可溯源",
              ",".join(r3["alive"]))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_palette_min_colors() -> None:
    """[12] B3 回归：颜色数 < 一个完整载荷时必须**明确失败**，不能假成功。

    历史上 MIN_COLORS=64，而载荷是 96 bit。64~95 色的调色板 PNG 会
    "嵌入不报错、解码永远失败"，层体检还会误判成"调色板被 pngquant 重建"。
    """
    print("\n[12] 调色板容量下限（B3 回归）")
    from core import palette_steg as pst

    def mk(ncolors: int, w: int = 400, h: int = 300) -> bytes:
        idx = np.tile(np.arange(w) % ncolors, (h, 1)).astype(np.uint8)
        pal = [0] * 768
        for i in range(ncolors):
            v = (40 + i * 5) % 200
            pal[i * 3:i * 3 + 3] = [v, (v * 2) % 256, (255 - v)]
        im = Image.fromarray(idx, mode="P")
        im.putpalette(pal)
        b = io.BytesIO()
        im.save(b, format="PNG", optimize=True)
        return b.getvalue()

    key = (0.31, 3.78)
    body = b"\x11\x22\x33\x44\x55"          # 5 字节 = 一个真实水印载荷
    refused = 0
    for nc in (64, 80, 95):
        try:
            pst.embed_palette(mk(nc), body, *key, copies=3)
        except ValueError:
            refused += 1
    check("64/80/95 色被明确拒绝（不再假成功）", refused == 3, f"{refused}/3")

    okc = 0
    for nc in (96, 128, 256):
        out, _ = pst.embed_palette(mk(nc), body, *key, copies=3)
        if pst.decode_palette(out, [key]):
            okc += 1
    check("96/128/256 色嵌入后都能解出", okc == 3, f"{okc}/3")





if __name__ == "__main__":
    np.random.seed(20261009)
    test_hmac()
    test_phase4_roundtrip()
    test_phase4_jpeg()
    test_phase4_keyed_positions()
    test_full_pipeline()
    test_wrong_key()
    test_multi_image_cover_swap()
    test_palette_channel()
    test_container_and_meta_layers()
    test_payload_roundtrip()
    test_decoy_end_to_end()
    test_palette_min_colors()
    print("\n" + "=" * 56)
    print(f"通过 {len(PASS)} 项，失败 {len(FAIL)} 项")
    for f in FAIL:
        print("  × " + f)
    sys.exit(1 if FAIL else 0)
