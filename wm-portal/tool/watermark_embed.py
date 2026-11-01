# -*- coding: utf-8 -*-
"""水印嵌入 / 提取核心。

相对原方案的关键加固：
  1. EPUB 用 zip 原地替换（不用 ebooklib 重写），精排排版 0 损失；
     XHTML 只在字节流层面插入隐形字符，不做 DOM 重建。
  2. 零宽通道改为「混沌密钥流加密 + 多副本 + 滑窗搜索」：
     原方案全书一条连续明文链，删掉任意一个字符就整体错位失效。
  3. CSS 规则重排作为第三通道（不插入任何字符，抗清洗）。
  4. 图片 QIM 在**亮度域**嵌入、块位置由密钥随机挑选、逐块限幅：
     原方案按固定顺序遍历块，拿到两份文件 diff 就能定位并抹平水印。
"""
from __future__ import annotations

import base64
import io
import os
import re
from dataclasses import dataclass, asdict

import numpy as np
from PIL import Image

from core import (epub_io, zw_encoder, vs_encoder, css_steg,
                  image_watermark as qim, palette_steg as pst, keys as K,
                  attr_steg as ast, opf_steg as ost, zip_steg as zst,
                  decoy as pdecoy)
from core.textscan import iter_text_segments
from config import (ZW_ENABLED, CSS_ENABLED, IMG_ENABLED, ZW_CHARSET,
                    ZW_COPIES, CSS_COPIES, IMG_COPIES, MAX_XHTML, MAX_IMAGES,
                    ZW_SPREAD_PAGES, ATTR_SPREAD_PAGES, ATTR_COPIES,
                    JPEG_QUALITY, DELTA, DELTA_PNG, PSNR_THRESHOLD,
                    MAX_EMBED_ITER, IMG_MIN_BYTES, IMG_MIN_PIXELS,
                    IMG_MAX_PIXELS, ATTR_ENABLED, OPF_ENABLED, ZIP_ENABLED,
                    VS_ENABLED, ATTR_PAGES, DECOY_ENABLED)
from crypto_utils import verify_watermark_id, sign_random_part

# 母本里可能自带的零宽/双向控制字符，先清掉再嵌入，避免干扰提取
STRIP_ZW = re.compile(
    "[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u206a-\u206f\ufeff"
    "\U000e0100-\U000e01ef]")

INLINE_IMG_RE = re.compile(r'(<img\b[^>]*src\s*=\s*")(data:image/[^"]+)(")',
                           re.IGNORECASE | re.DOTALL)


# ------------------------------------------------------------------ 密钥

def derive_keys(watermark_id: str) -> K.WatermarkKeys:
    """由水印 ID 确定性派生密钥（单元测试与兜底用；正式分发用随机密钥存库）。"""
    import hashlib
    seed = hashlib.sha256(f"derive|{watermark_id}".encode()).digest()
    x0 = 0.05 + (int.from_bytes(seed[0:6], "big") % 900000) / 1000000.0 * 0.9
    mu = 3.57 + (int.from_bytes(seed[6:12], "big") % 430000) / 1000000.0
    return K.WatermarkKeys(
        watermark_id=watermark_id,
        chaos_seed=round(x0, 12), chaos_mu=round(mu, 12),
        css_key=K.format_pair(round(0.05 + (int.from_bytes(seed[12:18], "big") % 900000) / 1000000.0 * 0.9, 12),
                              round(3.57 + (int.from_bytes(seed[18:24], "big") % 430000) / 1000000.0, 12)),
        lsb_key=K.format_pair(round(0.05 + (int.from_bytes(seed[24:30], "big") % 900000) / 1000000.0 * 0.9, 12),
                              round(3.57 + (int.from_bytes(seed[30:32], "big") % 430000) / 1000000.0, 12)),
    )


# ------------------------------------------------------------------ 载荷编解码
# 水印 ID 形如 WM-{10位hex}-{6位HMAC}。HMAC 可以由随机段重算，因此文件里
# 只需放 10 位 hex（5 字节）：载荷从 27 字节降到 12 字节，容量与鲁棒性双赢。

def to_payload(watermark_id: str) -> bytes:
    parts = watermark_id[3:].split("-")
    if len(parts) == 2 and len(parts[0]) == 10:
        try:
            return bytes.fromhex(parts[0])
        except ValueError:
            pass
    return watermark_id.encode("utf-8")


def from_payload(text: str) -> str:
    """把通道解出的载荷还原成完整水印 ID。"""
    if not text:
        return ""
    if text.startswith("WM-") and len(text) > 10:
        return text
    try:
        raw = text.encode("latin-1")
    except (UnicodeEncodeError, AttributeError):
        return text
    if len(raw) == 5:
        return sign_random_part(raw.hex().upper())
    return text


# ------------------------------------------------------------------ 图片候选

@dataclass
class ImageSlot:
    name: str
    kind: str          # 'zip' | 'inline'
    media_type: str
    data: bytes
    xhtml: str = ""    # inline 图所在的 XHTML 路径
    real_format: str = ""   # PIL 解出的真实格式
    mode: str = ""          # PIL 解出的色彩模式（P = 调色板）

    @property
    def is_jpeg(self) -> bool:
        return self.media_type.lower() in ("image/jpeg", "image/jpg")


def _decode_inline(data_url: str) -> tuple[str, bytes] | None:
    m = re.match(r"data:image/([\w+]+);base64,(.+)", data_url, re.DOTALL)
    if not m:
        return None
    try:
        return "image/" + m.group(1).lower(), base64.b64decode(m.group(2))
    except Exception:                                   # noqa: BLE001
        return None


def scan_images(work: epub_io.EpubWork) -> list[ImageSlot]:
    """收集书中所有可用图片（zip 内图片 + XHTML 内联 base64 图片）。"""
    slots: list[ImageSlot] = []
    for path, size in work.image_items()[:40]:
        mt = "image/jpeg"
        for attrs in work.manifest.values():
            if work.abs_path(attrs["href"]) == path:
                mt = (attrs.get("media-type") or "").split(";")[0].strip()
                break
        if path.lower().endswith((".png", ".jpg", ".jpeg", ".webp")):
            try:
                slots.append(ImageSlot(path, "zip", mt, work.read_raw(path)))
            except KeyError:
                continue
    for xp in work.xhtml_items():
        try:
            text, _ = work.read_text(xp)
        except KeyError:
            continue
        for m in INLINE_IMG_RE.finditer(text):
            got = _decode_inline(m.group(2))
            if got:
                slots.append(ImageSlot(f"{xp}#inline", "inline", got[0], got[1], xp))
    return slots


def _slot_ok(s: ImageSlot) -> bool:
    """图片是否值得嵌入：格式可处理、够大、不是矢量图。

    格式以 PIL 解出的真实格式为准 —— OPF 里声明的 media-type 可能与文件
    实际内容不符（见过 PNG 被声明成 jpeg 的精排书），照声明处理会把 PNG
    存成 JPEG，透明蒙版直接报废。
    """
    if len(s.data) < IMG_MIN_BYTES:
        return False
    try:
        img = Image.open(io.BytesIO(s.data))
        w, h = img.size
        fmt = (img.format or "").upper()
    except Exception:                                   # noqa: BLE001
        return False
    if fmt not in ("JPEG", "PNG", "WEBP", "MPO"):       # 排除 GIF 动图 / SVG
        return False
    # 调色板（P 模式）PNG 不再跳过 —— 走专门的调色板隐写通道：
    # 只改颜色表的最低位，像素数据、透明蒙版、文件体积都不动。
    if img.mode == "P":
        used = sum(1 for c in img.histogram()[:256] if c > 0)
        if used < pst.MIN_COLORS:
            return False
    if w < IMG_MIN_PIXELS or h < IMG_MIN_PIXELS:
        return False
    if w * h > IMG_MAX_PIXELS:      # 超大图耗时陡增，跳过
        return False
    # 大片高饱和（纯白底/纯色底）的图没有可调余量，硬嵌只会把图弄脏、
    # 水印还留不住，直接跳过这类图（常见于章节装饰图）。
    try:
        hist = img.convert("L").histogram()
        total = sum(hist) or 1
        hot = sum(hist[246:])
        if hot / total > 0.55:
            return False
    except Exception:                                   # noqa: BLE001
        pass
    s.real_format = fmt
    s.mode = img.mode
    return True


def select_candidates(work: epub_io.EpubWork, max_count: int = MAX_IMAGES) -> list[ImageSlot]:
    """挑选承载图片水印的插图。

    策略（重要）：封面最容易被替换，所以**不能只嵌封面**。
    这里封面 + 正文插图一起上，并按文档顺序**均匀采样**，
    保证一本书从头到尾都有水印分布 —— 换掉封面、删掉几章都还能解出来。
    """
    if max_count <= 0:
        return []
    slots: list[ImageSlot] = []
    seen: set[str] = set()
    for s in scan_images(work):
        if not _slot_ok(s):
            continue
        h = hashlib_md5(s.data)
        if h in seen:
            continue
        seen.add(h)
        slots.append(s)
    if not slots:
        return []

    cover = work.cover_item()
    cover_slot = next((s for s in slots if s.name == cover), None)
    rest = [s for s in slots if s is not cover_slot]

    budget = max_count - (1 if cover_slot else 0)
    if budget > 0 and len(rest) > budget:
        # 等间隔抽样，覆盖全书而非只取前几张
        step = len(rest) / float(budget)
        rest = [rest[int(i * step)] for i in range(budget)]
    elif budget <= 0:
        rest = []

    out = ([cover_slot] if cover_slot else []) + rest
    return out[:max_count]


def hashlib_md5(data: bytes) -> str:
    import hashlib
    return hashlib.md5(data).hexdigest()


# ------------------------------------------------------------------ PSNR

def check_psnr(orig: Image.Image, marked: Image.Image, threshold: float = PSNR_THRESHOLD) -> float:
    a = np.asarray(orig.convert("RGB"), dtype=np.float64)
    b = np.asarray(marked.convert("RGB"), dtype=np.float64)
    if a.shape != b.shape:
        h = min(a.shape[0], b.shape[0])
        w = min(a.shape[1], b.shape[1])
        a, b = a[:h, :w], b[:h, :w]
    mse = float(np.mean((a - b) ** 2))
    if mse <= 1e-9:
        return float("inf")
    psnr = 10 * np.log10(255.0 ** 2 / mse)
    if psnr < threshold:
        raise ValueError(f"PSNR {psnr:.1f}dB 低于阈值 {threshold}dB")
    return psnr


# ------------------------------------------------------------------ 单图 QIM（供测试直接调用）

def dct_qim_embed(pil_img: Image.Image, watermark_id: str,
                  media_type: str = "image/jpeg",
                  key: tuple[float, float] | None = None) -> Image.Image:
    """在单张图上嵌入水印并返回 PIL 图像（密钥缺省时由 ID 派生）。"""
    if key is None:
        key = derive_keys(watermark_id).lsb()
    buf = io.BytesIO()
    fmt = "JPEG" if media_type.lower() in ("image/jpeg", "image/jpg") else "PNG"
    pil_img.convert("RGB").save(buf, format=fmt, quality=99 if fmt == "JPEG" else None)
    out, _ = qim.embed_image(buf.getvalue(), to_payload(watermark_id),
                             key[0], key[1], copies=IMG_COPIES,
                             quality=JPEG_QUALITY, q=DELTA)
    return Image.open(io.BytesIO(out)).convert("RGB")


def dct_qim_extract(pil_img: Image.Image,
                    keys: list[tuple[float, float]] | None = None,
                    watermark_id: str | None = None) -> str | None:
    """从单张图提取水印 ID。keys 缺省时用「按 ID 派生」的密钥尝试。"""
    buf = io.BytesIO()
    pil_img.convert("RGB").save(buf, format="PNG")
    if keys is None:
        if watermark_id:
            keys = [derive_keys(watermark_id).lsb()]
        else:
            return None
    seen = []
    for q in (DELTA, DELTA_PNG):
        for h in qim.decode_image(buf.getvalue(), keys, q=q):
            wid = from_payload(h["watermark_id"])
            if wid and verify_watermark_id(wid):
                return wid
            seen.append(wid)
    return None


# ------------------------------------------------------------------ 嵌入主流程

def _clean_mother(work: epub_io.EpubWork) -> int:
    """清掉母本自带的零宽/变体选择符，避免与我们的水印混淆。"""
    removed = 0
    for path in work.xhtml_items():
        try:
            text, enc = work.read_text(path)
        except KeyError:
            continue
        cleaned = STRIP_ZW.sub("", text)
        if cleaned != text:
            removed += len(text) - len(cleaned)
            work.write_text(path, cleaned, enc)
    return removed


_PICK_CACHE: dict[str, list[str]] = {}


def _pick_xhtml(work: epub_io.EpubWork, max_files: int) -> list[str]:
    """挑选承载文本水印的正文页（按正文字数降序）。

    结果按母本缓存：一本 168 页的书逐页统计字数要几秒，批量分发时每个副本
    都重算一遍非常浪费。
    """
    key = ""
    try:
        st = os.stat(work.path)
        key = f"{work.path}|{st.st_size}|{int(st.st_mtime)}|{max_files}"
    except OSError:
        pass
    if key and key in _PICK_CACHE:
        return _PICK_CACHE[key]

    scored = []
    for p in work.xhtml_items():
        try:
            text, _ = work.read_text(p)
        except KeyError:
            continue
        scored.append((sum(len(s.text) for s in iter_text_segments(text)), p))
    scored.sort(key=lambda t: (-t[0], t[1]))
    out = [p for _, p in scored[:max_files]]
    if key:
        _PICK_CACHE[key] = out
    return out


def scan_pool(work: epub_io.EpubWork) -> int:
    """统一的候选图池大小。

    嵌入、自检、溯源必须共用同一个池子：之前溯源只看前 MAX_IMAGES 张，
    而嵌入是从 2 倍候选里挑成功者写入的，结果就是「生成时自检通过、
    事后溯源却解不出来」。
    """
    return max(MAX_IMAGES * 2, MAX_IMAGES + 4)


def _spread_pages(work: epub_io.EpubWork, limit: int) -> list[str]:
    """把承载页**均匀铺开**到整本书（而不是只挑字数最多的几章）。

    这是被对抗方逼出来的改动：他们不解密，只统计"哪几章的写法不一样"。
    只嵌 6/94 章 = 显著的少数派特征；每章固定 96 个字符 = 显著的定额特征。
    均匀铺开之后，每章都有改动、每章数量还不一样，统计上就无从归因。

    limit=0 表示全部正文页；>0 时按等间隔抽样（保持"覆盖全书"的观感，
    而不是退化成"只取前 N 章"）。
    """
    # 必须按**文件名排序**，不能用 zip 的物理顺序：
    # 容器层（ZIP 顺序通道）会重排条目，而属性层是"跨页累积"的编号流，
    # 一旦页顺序随物理顺序变化，编号就整体错位 —— 那两层就不是正交的了
    # （容器被重建时属性层会跟着一起废，这不是我们想要的）。
    pages = sorted(work.xhtml_items())
    if not pages:
        return []
    if limit and len(pages) > limit:
        step = len(pages) / float(limit)
        pages = [pages[min(len(pages) - 1, int(i * step))]
                 for i in range(limit)]
    return pages


def _zw_pages(work: epub_io.EpubWork) -> list[str]:
    """零宽通道承载页 —— 嵌入端与解码端必须一致。"""
    return _spread_pages(work, ZW_SPREAD_PAGES)


def _attr_pages(work: epub_io.EpubWork) -> list[str]:
    """属性通道使用的页面列表 —— 嵌入端与解码端必须完全一致。

    属性位是按「页面顺序 + 页内顺序」编号的跨页累积流，两端取到不同页面
    或不同顺序都会让编号错位，水印就解不出来。
    """
    return _spread_pages(work, ATTR_SPREAD_PAGES)


def _scan_pages(work: epub_io.EpubWork, max_pages: int) -> list[str]:
    """解码时要扫的正文页：优先嵌入时挑中的页，再补上靠前的页。

    只扫「前 N 页」是不够的 —— 水印是按正文字数挑页嵌入的，可能落在第 90 页，
    扫前 8 页就永远解不出来（这正是那本 168 页精排书自检失败的原因）。
    """
    pages = work.xhtml_items()
    if not pages:
        return []
    # 顺序必须同时覆盖**两代**规则，否则旧版生成的文件会突然解不出来：
    #   旧版：按正文字数挑前几页（_pick_xhtml）
    #   新版：按文件名排序、铺开到全部页（_zw_pages）
    # 只取一种就会漏掉另一代文件 —— 这个坑真实踩过。
    order: list[str] = []
    for p in _pick_xhtml(work, max(4, max_pages // 2)):
        if p not in order:
            order.append(p)
    for p in _zw_pages(work):
        if len(order) >= max_pages:
            break
        if p not in order:
            order.append(p)
    for p in pages:
        if len(order) >= max_pages:
            break
        if p not in order:
            order.append(p)
    return order[:max_pages]


def embed_watermark(epub_path: str, watermark_id: str, output_path: str,
                    keys: K.WatermarkKeys | None = None,
                    on_step=None, retry: int = 2) -> dict:
    """给一个用户生成专属水印副本。返回统计与自检结果。

    on_step(msg)：可选进度回调，GUI 用它把每一步显示到日志里。
    retry       ：自检未通过时换一组密钥重试的次数（水印嵌入依赖随机
                  密钥与图像余量，个别组合下会失败，重试即可）。
    """
    last: dict | None = None
    for attempt in range(retry + 1):
        k = keys or K.new_keys(watermark_id)
        rep = _embed_once(epub_path, watermark_id, output_path, k, on_step)
        if rep.get("zero_width") or rep.get("css") or rep.get("image_qim"):
            return rep
        last = rep
        if keys is not None:
            break                       # 调用方指定了密钥，不擅自更换
        if attempt < retry and on_step:
            on_step("  · 通道自检未通过，换一组密钥重试…")
    assert last is not None
    detail = {k2: v for k2, v in last.items()
              if k2 in ("zero_width", "css", "image_qim", "images",
                        "palette", "psnr", "image_errors", "zw_copies")}
    raise ValueError("三个通道自检全部失败，拒绝发送；详情：" + str(detail))


def _embed_once(epub_path: str, watermark_id: str, output_path: str,
                keys: K.WatermarkKeys, on_step=None) -> dict:
    def step(msg: str) -> None:
        if on_step:
            on_step(msg)

    if not verify_watermark_id(watermark_id):
        raise ValueError(f"水印 ID 未通过 HMAC 校验：{watermark_id}")
    keys = keys or K.new_keys(watermark_id)

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    report: dict = {"path": output_path, "watermark_id": watermark_id,
                    "keys": keys.as_db_row(), "zero_width": False,
                    "css": False, "image_qim": False, "psnr": 0.0, "images": 0}

    with epub_io.EpubWork(epub_path) as work:
        report["cleaned_chars"] = _clean_mother(work)

        # ---- 通道 1：零宽字符 ----
        if ZW_ENABLED:
            targets = _zw_pages(work)
            step(f"  ├ 文本通道：铺开到 {len(targets)} 个正文页…")
            done = 0
            ok_pages = 0
            for path in targets:
                text, enc = work.read_text(path)
                new_text, copies = zw_encoder.embed_html(
                    text, to_payload(watermark_id), keys.chaos_seed, keys.chaos_mu,
                    charset=ZW_CHARSET, copies=ZW_COPIES)
                if copies:
                    work.write_text(path, new_text, enc)
                    done += copies
                    ok_pages += 1
            report["zero_width"] = done > 0
            report["zw_pages"] = ok_pages
            # 兜底：若铺开的页大多写不进去（书太小/锚点太少），退回挑大页
            if ok_pages < 2:
                step("  │   （铺开的页锚点不足，回退：改按正文字数挑页）")
                for path in _pick_xhtml(work, MAX_XHTML):
                    text, enc = work.read_text(path)
                    new_text, copies = zw_encoder.embed_html(
                        text, to_payload(watermark_id), keys.chaos_seed,
                        keys.chaos_mu, charset=ZW_CHARSET, copies=ZW_COPIES)
                    if copies:
                        work.write_text(path, new_text, enc)
                        done += copies
                        ok_pages += 1
                report["zero_width"] = done > 0
                report["zw_pages"] = ok_pages
            report["zw_copies"] = done

            # 内容层第二编码：属性引号（与零宽同文件、不同载体）
            if ATTR_ENABLED:
                step("  ├ 属性通道：XHTML 属性引号…")
                ak = keys.channel_key("attr")
                apages = _attr_pages(work)
                texts, encs = [], []
                for path in apages:
                    t2, enc2 = work.read_text(path)
                    texts.append(t2)
                    encs.append(enc2)
                new_texts, ainfo = ast.embed_attributes(
                    texts, to_payload(watermark_id), *ak, copies=ATTR_COPIES)
                if ainfo.get("ok"):
                    for path, t3, enc3 in zip(apages, new_texts, encs):
                        work.write_text(path, t3, enc3)
                report["attributes"] = ainfo.get("written", 0)

        # ---- 通道 2：CSS 规则重排 ----
        if CSS_ENABLED:
            step("  ├ 样式通道：重排 CSS 规则…")
            for path in work.css_items()[:3]:
                text, enc = work.read_text(path)
                new_text, info = css_steg.embed_css(
                    text, to_payload(watermark_id), *keys.css(), copies=CSS_COPIES)
                if info.get("used_blocks"):
                    work.write_text(path, new_text, enc)
                    report["css"] = True
                    report["css_blocks"] = info["used_blocks"]

        # ---- 诱饵：写在最容易被发现的层，让对方"以为找到了" ----
        if DECOY_ENABLED:
            cpaths = work.css_items()[:1]
            if cpaths:
                path = cpaths[0]
                text, enc = work.read_text(path)
                new_text, dinfo = pdecoy.embed_decoy(text)
                if dinfo.get("ok"):
                    work.write_text(path, new_text, enc)
                    report["decoy"] = True

        # ---- 元数据层：OPF manifest / spine 顺序 ----
        if OPF_ENABLED and work.opf_path:
            step("  ├ 元数据通道：OPF 条目顺序…")
            new_opf, oinfo = ost.embed_opf(
                work.opf_text, to_payload(watermark_id),
                *keys.channel_key("opf"), copies=2)
            if oinfo["manifest"].get("ok") or oinfo["spine"].get("ok"):
                work.write_text(work.opf_path, new_opf, work.opf_enc)
                report["opf"] = True

        # ---- 通道 3：图片 DCT-QIM ----
        psnrs: list[float] = []
        if IMG_ENABLED:
            # 多取一些候选：有的图（调色板 PNG / 过亮图）会被跳过，
            # 只取恰好 MAX_IMAGES 张的话可能全部落在这批不合格的图上。
            cand_imgs = select_candidates(work, scan_pool(work))
            step(f"  ├ 图片通道：从 {len(cand_imgs)} 张候选中挑 {MAX_IMAGES} 张嵌入…")
            for n_i, slot in enumerate(cand_imgs, 1):
                if report.get("images", 0) >= MAX_IMAGES:
                    break
                step(f"  │   [{n_i}/{len(cand_imgs)}] {os.path.basename(slot.name)}")
                try:
                    orig = Image.open(io.BytesIO(slot.data)).convert("RGB")
                    if slot.mode == "P":
                        new_bytes, info = pst.embed_palette(
                            slot.data, to_payload(watermark_id), *keys.lsb(),
                            copies=IMG_COPIES + 2)
                        report["palette"] = report.get("palette", 0) + 1
                    else:
                        new_bytes, info = qim.embed_image(
                            slot.data, to_payload(watermark_id), *keys.lsb(),
                            copies=IMG_COPIES, quality=JPEG_QUALITY)
                    marked = Image.open(io.BytesIO(new_bytes)).convert("RGB")
                    psnr = 10 * np.log10(255.0 ** 2 / max(
                        float(np.mean((np.asarray(orig, dtype=np.float64)
                                       - np.asarray(marked, dtype=np.float64)) ** 2)), 1e-9))
                    if psnr < PSNR_THRESHOLD:
                        continue
                    # 体积保护：调色板 PNG 转 RGBA 可能把文件撑大数倍，
                    # 宁可这张图不嵌水印，也不让整本书变大（否则会超出邮件附件上限）
                    if len(new_bytes) > len(slot.data) * 1.6:
                        step("  │     体积膨胀过大，跳过本图")
                        continue
                    psnrs.append(psnr)
                    if slot.kind == "zip":
                        work.write_raw(slot.name, new_bytes)
                    else:
                        _update_inline_image(work, slot, new_bytes)
                    report["images"] += 1
                    report["image_qim"] = True
                except Exception as exc:                 # noqa: BLE001
                    report.setdefault("image_errors", []).append(
                        f"{slot.name}: {type(exc).__name__}: {exc}")
            report["psnr"] = round(float(max(psnrs)), 1) if psnrs else 0.0

        step("  └ 写出文件…")
        if ZIP_ENABLED:
            tmp_out = output_path + ".tmp"
            work.save(tmp_out)
            zi = zst.embed_zip(tmp_out, output_path, to_payload(watermark_id),
                               *keys.channel_key("zip"))
            try:
                os.remove(tmp_out)
            except OSError:
                pass
            report["zip"] = zi.get("order_written", 0)
        else:
            work.save(output_path)

    # ---- 双（三）通道自检 ----
    step("  · 通道自检…")
    check = self_check(output_path, keys)
    if not (check["zero_width"] or check["css"] or check["image_qim"]):
        # 自检有扫描范围，可能漏掉；做一次全量复查，避免把好文件误判成废品
        hits, note = deep_check(output_path, keys)
        if hits:
            check["zero_width"] = "zero_width" in hits
            check["css"] = "css" in hits
            check["image_qim"] = "image" in hits
            check["deep_check"] = hits
            report["check_note"] = "自检首轮未命中，全量复查命中：" + str(hits)
        else:
            report["check_note"] = ("全量复查也未命中"
                                    + (f"（{note}）" if note else "")
                                    + f"；嵌入统计 zw={report.get('zw_copies')} "
                                      f"图={report.get('images')}")
    report.update({k: v for k, v in check.items() if k != "watermark_id"})

    # 最终确认：用**与事后溯源完全相同**的函数再解一次。
    # 分通道自检只证明"每层都写进去了"，这一步才真正保证"发出去之后能解出来"。
    step("  · 溯源复核（与 decode_watermark 同一路径）…")
    final_wm, final_ch = extract_watermark(output_path,
                                           keys_list=keys.all_keys())
    report["verify"] = (final_wm == keys.watermark_id)
    report["verify_channel"] = final_ch or ""
    if not report["verify"]:
        report["check_note"] = (
            "分通道自检通过，但溯源复核未解出" if (check["zero_width"] or check["css"]
                                              or check["image_qim"])
            else "自检与复核均未通过")
    if report.get("check_note"):
        step("  · " + report["check_note"])     # 让用户/日志能看到到底哪一步出问题
    return report


def _decode_one_image(slot: ImageSlot, keys, single: bool = False):
    """按图片类型选解码器：调色板 PNG 走调色板通道，其余走 DCT-QIM。

    两个分支都必须返回**完整的水印 ID**（`WM-XXXX-XXXXXX`）。
    dct_qim_extract 内部会做还原，decode_palette 不会 —— 忘了 from_payload
    的话，后续 verify_watermark_id() 对压缩载荷永远返回 False，
    调色板层就会一直显示"检不出"（嵌入其实是成功的）。
    """
    cand = keys if isinstance(keys, list) else keys.all_keys()
    if slot.mode == "P":
        hits = pst.decode_palette(slot.data, cand)
        if not hits:
            return None
        try:
            return from_payload(hits[0]["watermark_id"])
        except Exception:                                # noqa: BLE001
            return None
    try:
        img = Image.open(io.BytesIO(slot.data)).convert("RGB")
    except Exception:                                    # noqa: BLE001
        return None
    return dct_qim_extract(img, keys=cand)


def _collect_channels(epub_path: str, keys_list: list,
                      max_pages: int = 40, max_images: int | None = None,
                      on_step=None, stop_after_first: bool = False) -> dict:
    """扫描所有通道，返回 {通道名: 水印ID}。

    自检与溯源共用这一个扫描器，杜绝「自检通过、溯源失败」。
    stop_after_first=True 时命中一个通道就收工（溯源要快）；
    自检用 False，好把每个通道都验一遍。
    """
    def step(msg):
        if on_step:
            on_step(msg)

    hits: dict[str, str] = {}
    with epub_io.EpubWork(epub_path) as work:
        pages = _scan_pages(work, max_pages)
        step(f"  ├ 扫描正文文本通道（{len(pages)} 页）…")
        for path in pages:
            try:
                text, _ = work.read_text(path)
            except Exception:                            # noqa: BLE001
                continue
            # 已命中的层不再重复解码后续页（层体检要扫全部层，不省这点
            # 的话，187 页的书体检要十几秒）
            if "zero_width" not in hits:
                for hit in zw_encoder.decode_html(text, keys_list):
                    wid = from_payload(hit["watermark_id"])
                    if verify_watermark_id(wid):
                        hits.setdefault("zero_width", wid)
            if VS_ENABLED and "variant_selector" not in hits:
                for hit in vs_encoder.decode_html(text, keys_list):
                    wid = from_payload(hit["watermark_id"])
                    if verify_watermark_id(wid):
                        hits.setdefault("variant_selector", wid)
        page_texts = []
        for path in _attr_pages(work):
            try:
                page_texts.append(work.read_text(path)[0])
            except Exception:                            # noqa: BLE001
                pass
        if page_texts:
            step("  ├ 扫描属性通道（XHTML 引号）…")
            for hit in ast.decode_attributes(page_texts, keys_list):
                wid = from_payload(hit["watermark_id"])
                if verify_watermark_id(wid):
                    hits.setdefault("attributes", wid)
            if "attributes" not in hits:
                # 兼容旧版：老文件的属性位是按"字数最多的几页"编号的，
                # 与现在"按文件名排序铺开"的编号不同，必须再按旧规则试一次
                legacy = []
                for p in _pick_xhtml(work, min(8, MAX_XHTML)):
                    try:
                        legacy.append(work.read_text(p)[0])
                    except Exception:                    # noqa: BLE001
                        pass
                if legacy:
                    for hit in ast.decode_attributes(legacy, keys_list):
                        wid = from_payload(hit["watermark_id"])
                        if verify_watermark_id(wid):
                            hits.setdefault("attributes", wid)
        if hits and stop_after_first:
            return hits

        try:
            opf_text = work.opf_text
        except Exception:                                # noqa: BLE001
            opf_text = ""
        if opf_text:
            step("  ├ 扫描元数据通道（OPF）…")
            for hit in ost.decode_opf(opf_text, keys_list):
                wid = from_payload(hit["watermark_id"])
                if verify_watermark_id(wid):
                    hits.setdefault("opf_order", wid)
        if hits and stop_after_first:
            return hits

        step("  ├ 扫描样式通道…")
        for path in work.css_items()[:3]:
            try:
                css, _ = work.read_text(path)
            except Exception:                            # noqa: BLE001
                continue
            for hit in css_steg.decode_css(css, keys_list):
                wid = from_payload(hit["watermark_id"])
                if verify_watermark_id(wid):
                    hits.setdefault("css_reorder", wid)
        if hits and stop_after_first:
            return hits

        limit = scan_pool(work) if max_images is None else max_images
        imgs = select_candidates(work, limit) if limit else []
        if imgs:
            step(f"  └ 扫描图片通道（{len(imgs)} 张，{len(keys_list)} 组密钥）…")
            quick = min(4, len(imgs))
            for phase, group in (("快扫", imgs[:quick]), ("深扫", imgs[quick:])):
                for n_i, slot in enumerate(group, 1):
                    step(f"      [{phase} {n_i}/{len(group)}] "
                         f"{os.path.basename(slot.name)}")
                    wm = _decode_one_image(slot, keys_list)
                    if wm and verify_watermark_id(wm):
                        hits.setdefault("palette" if slot.mode == "P"
                                        else "image_qim", wm)
                if hits and stop_after_first:
                    break

        step("  └ 扫描容器通道（ZIP 结构）…")
        for hit in zst.decode_zip(epub_path, keys_list):
            wid = from_payload(hit["watermark_id"])
            if verify_watermark_id(wid):
                hits.setdefault("zip_order", wid)
    return hits


# 溯源时的通道优先级：文本最快，图片最慢
_CHANNEL_ORDER = ("zero_width", "css_reorder", "attributes", "opf_order",
                  "image_qim", "palette", "zip_order", "variant_selector")


def extract_watermark(epub_path: str,
                      keys_list: list[tuple[float, float]] | None = None,
                      watermark_ids: list[str] | None = None,
                      max_pages: int = 40, max_images: int | None = None,
                      on_step=None):
    """解码可疑文件，返回 (watermark_id, channel)。

    keys_list     候选密钥（从数据库读取）
    watermark_ids 无密钥时的兜底：按 ID 派生密钥尝试（测试/自检场景）
    max_pages     正文扫描页数上限（预检时调小可显著提速）
    max_images    图片扫描张数上限，None 表示用统一的候选池
    """
    if keys_list is None:
        keys_list = []
        for wid in (watermark_ids or []):
            k = derive_keys(wid)
            for pair in k.all_keys():
                if pair not in keys_list:
                    keys_list.append(pair)
    if not keys_list:
        return None, None

    hits = _collect_channels(epub_path, keys_list, max_pages, max_images,
                             on_step, stop_after_first=True)
    for ch in _CHANNEL_ORDER:
        if ch in hits:
            return hits[ch], ch
    return None, None


def deep_check(epub_path: str, keys: K.WatermarkKeys, max_images: int = 32) -> tuple[dict, str]:
    """自检未通过时的全量复查：扫**全部**正文页 + 更多候选图。

    自检为了省时间只扫一部分；若因为挑页/挑图的随机性恰好错过嵌入位置，
    就会被误判成「水印没嵌进去」而拒绝发送。这里做一次不限量的复查来兜底，
    同时给出诊断信息（哪一层真的解出来了），避免再靠猜。
    """
    cand = keys.all_keys()
    hits: dict[str, str] = {}
    note = []
    with epub_io.EpubWork(epub_path) as work:
        for path in work.xhtml_items():
            try:
                text, _ = work.read_text(path)
            except Exception:                            # noqa: BLE001
                note.append(f"读取失败: {os.path.basename(path)}")
                continue
            for hit in zw_encoder.decode_html(text, cand):
                wid = from_payload(hit["watermark_id"])
                if wid == keys.watermark_id:
                    hits["zero_width"] = os.path.basename(path)
            for hit in vs_encoder.decode_html(text, cand):
                wid = from_payload(hit["watermark_id"])
                if wid == keys.watermark_id:
                    hits["variant"] = os.path.basename(path)
        for path in work.css_items():
            try:
                css, _ = work.read_text(path)
            except Exception:                            # noqa: BLE001
                continue
            for hit in css_steg.decode_css(css, cand):
                if from_payload(hit["watermark_id"]) == keys.watermark_id:
                    hits["css"] = os.path.basename(path)
        for slot in select_candidates(work, max_images):
            wm = _decode_one_image(slot, cand)
            if wm and wm == keys.watermark_id:
                hits["image"] = os.path.basename(slot.name)
    return hits, ("; ".join(note[:3]) if note else "")


def _update_inline_image(work: epub_io.EpubWork, slot: ImageSlot, new_bytes: bytes) -> bool:
    """替换 XHTML 内联 base64 图片（按顺序逐个替换，不做索引映射）。"""
    try:
        text, enc = work.read_text(slot.xhtml)
    except KeyError:
        return False
    mt = slot.media_type
    new_url = f"data:{mt};base64," + base64.b64encode(new_bytes).decode("ascii")
    # 按原始顺序匹配：只替换第 n 个 data:image 图（n 由 slot 在扫描时的顺序决定）
    matches = list(INLINE_IMG_RE.finditer(text))
    for m in matches:
        got = _decode_inline(m.group(2))
        if got and hashlib_md5(got[1]) == hashlib_md5(slot.data):
            text = text[:m.start(2)] + new_url + text[m.end(2):]
            work.write_text(slot.xhtml, text, enc)
            return True
    return False


# ------------------------------------------------------------------ 提取 / 自检

def self_check(epub_path: str, keys: K.WatermarkKeys) -> dict:
    """成品自检。

    刻意**复用 extract_watermark**（也就是事后溯源用的同一个函数），
    不再另写一套更宽松的扫描逻辑 —— 否则会出现「自检通过、溯源失败」。
    """
    hits = _collect_channels(epub_path, keys.all_keys())
    mine = {c: w for c, w in hits.items() if w == keys.watermark_id}
    return {"watermark_id": keys.watermark_id,
            "zero_width": "zero_width" in mine,
            "css": "css_reorder" in mine,
            "image_qim": ("image_qim" in mine) or ("palette" in mine),
            "variant": "variant_selector" in mine,
            "channel": ",".join(sorted(mine)) or ""}


def precheck_mother(epub_path: str, keys_list=None, on_step=None) -> None:
    """母本预检：确认结构可读、没有残留水印。

    这里刻意做抽样检查（少量页 + 少量图 + 最多 40 组密钥）：
    全量扫描在多插图的书上会耗掉几十秒，用户会以为程序卡死。
    """
    def step(msg):
        if on_step:
            on_step(msg)
        else:
            print(msg)

    import time as _t
    t0 = _t.time()
    step("· 读取母本结构…")
    with epub_io.EpubWork(epub_path) as work:
        pages = work.xhtml_items()
        if not pages:
            raise ValueError("母本没有可识别的正文页，可能不是有效 EPUB")
        n_css, n_img = len(work.css_items()), len(work.image_items())
        has_cover = bool(work.cover_item())
        step(f"· 正文页 {len(pages)}，样式表 {n_css}，图片 {n_img}"
             + ("（含封面）" if has_cover else ""))
        if n_img == 0:
            step("· ⚠ 母本没有图片，图片通道将不可用（建议换一本带插图的母本）")

    if keys_list:
        step(f"· 抽样比对 {min(len(keys_list), 40)} 组历史密钥，确认母本未带水印…")
        wid, ch = extract_watermark(epub_path, keys_list=keys_list[:40],
                                    max_pages=2, max_images=3, on_step=None)
        if wid:
            raise ValueError(f"母本已包含本系统水印 {wid}（通道：{ch}），请换原始文件")
    step(f"[√] 母本检查通过（{_t.time() - t0:.1f}s）")
