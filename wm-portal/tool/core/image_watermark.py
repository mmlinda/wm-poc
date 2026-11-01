"""第 4 层：封面图片 DCT 域 QIM 水印（设计文档中的 "DCT-LSB"）。

真正的 LSB（空域最低位）对 JPEG 重压缩毫无抵抗力，因此这里采用
「8×8 块 DCT + 中频系数量化索引调制（QIM）」：
    c' = (round(c / Q) ± 0.25) * Q
提取时对同一网格重新做 DCT，残差符号即为比特。
中频系数对 JPEG 有损压缩、缩放、轻度滤波都有较好抵抗力，
且改动仅落在 ±0.25Q 量级，肉眼完全不可察觉。
"""
from __future__ import annotations

import io
import numpy as np
from PIL import Image

from . import chaos
from .bitsearch import sliding_search, DEFAULT_WINDOW_BITS
from .crc import bytes_to_bits, bits_to_bytes
from .payload import build_payload, parse_payload, PayloadError

SALT = "img4"

BLOCK = 8
# 选用的中频系数坐标（8×8 块内，行/列索引）。频率越低越抗 JPEG 重压缩，
# 但改动也更容易被察觉；(1,2)(2,1)(2,2)(3,0) 是不可见性与鲁棒性的折中。
COEF_POS = [(1, 2), (2, 1), (2, 2), (3, 0)]

# 量化步长：JPEG 有损容器需要更大的步长才能扛住二次压缩
JPEG_Q = 32.0
PNG_Q = 16.0

_DCT_MATRIX: np.ndarray | None = None


def dct_matrix(n: int = BLOCK) -> np.ndarray:
    global _DCT_MATRIX
    if _DCT_MATRIX is None:
        T = np.zeros((n, n), dtype=np.float64)
        for k in range(n):
            alpha = np.sqrt(1.0 / n) if k == 0 else np.sqrt(2.0 / n)
            for i in range(n):
                T[k, i] = alpha * np.cos(np.pi * (2 * i + 1) * k / (2 * n))
        _DCT_MATRIX = T
    return _DCT_MATRIX


def _to_blocks(arr2d: np.ndarray) -> tuple[np.ndarray, tuple[int, int]]:
    """(H,W) → (bh, bw, 8, 8)，裁掉不足 8 的右/下边缘。"""
    h, w = arr2d.shape
    bh, bw = h // BLOCK, w // BLOCK
    if bh == 0 or bw == 0:
        raise ValueError("图片太小，无法分块")
    return arr2d[:bh * BLOCK, :bw * BLOCK].reshape(bh, BLOCK, bw, BLOCK).transpose(0, 2, 1, 3), (bh, bw)


def block_dct(arr2d: np.ndarray) -> np.ndarray:
    blocks, (bh, bw) = _to_blocks(arr2d)
    T = dct_matrix()
    return np.einsum("ij,abjk,kl->abil", T, blocks, T.T, optimize=True)


def block_idct(coef: np.ndarray) -> np.ndarray:
    T = dct_matrix()
    blocks = np.einsum("ij,abjk,kl->abil", T.T, coef, T, optimize=True)
    bh, bw = blocks.shape[0], blocks.shape[1]
    return blocks.transpose(0, 2, 1, 3).reshape(bh * BLOCK, bw * BLOCK)


def _luma(arr: np.ndarray) -> np.ndarray:
    """ITU-R BT.601 亮度（与 JPEG 编码器使用的转换一致）。"""
    return 0.299 * arr[:, :, 0] + 0.587 * arr[:, :, 1] + 0.114 * arr[:, :, 2]


def _pick_blocks(flat: np.ndarray, perm: list[int], need: int) -> list[int]:
    """按密钥顺序挑选承载块。

    这里**刻意不做内容相关的筛选**：任何基于像素值的筛选在 JPEG 重压缩后
    都可能翻转（阈值边界的块），一旦嵌入端与提取端选中的块集合错位，
    整个比特流就会错位、彻底解不出来。宁可让少数极端块产生误码，
    由多副本投票纠正，也不能让块集合不一致。
    """
    return list(perm[:need])


def _qim_embed(coef_value: float, bit: int, q: float) -> float:
    d = np.round(coef_value / q)
    return (d + (0.25 if bit else -0.25)) * q


def _qim_extract(coef_value: float, q: float) -> int:
    d = np.round(coef_value / q)
    return 1 if (coef_value / q - d) > 0 else 0


# ------------------------------------------------------------------ 嵌入

def embed_image(img_bytes: bytes, watermark_id: str, x0: float, mu: float,
                copies: int = 3, quality: int = 95,
                q: float | None = None, _depth: int = 0) -> tuple[bytes, dict]:
    """在图片中嵌入水印，返回 (新图片字节, 统计信息)。

    两个容易踩的坑，这里都处理了：
      1. 格式以 PIL 解出的**真实格式**为准（而不是 OPF 里声明的 media-type，
         声明可能与实际不符，导致 PNG 被存成 JPEG，透明蒙版直接失效）；
      2. RGBA / LA / 调色板带透明的图，alpha 通道**单独保留**，
         只在 RGB 亮度上加水印后再贴回去，蒙版不会丢。
    """
    img = Image.open(io.BytesIO(img_bytes))
    fmt = (img.format or "").upper()
    if fmt == "MPO":
        fmt = "JPEG"
    if fmt not in ("JPEG", "PNG", "WEBP"):
        raise ValueError(f"不支持嵌入的图片格式：{fmt or '未知'}（仅 JPEG/PNG/WEBP）")
    src_mode = img.mode

    # 透明通道单独取出保存，绝不参与水印改动
    rgba = None
    alpha = None
    if src_mode in ("RGBA", "LA", "PA"):
        rgba = img.convert("RGBA")
    elif src_mode == "P" and "transparency" in img.info:
        rgba = img.convert("RGBA")
    if rgba is not None:
        alpha = rgba.getchannel("A")
        work = rgba.convert("RGB")         # 先 RGBA 再 RGB，避免调色板透明告警
    elif src_mode == "L":
        work = img.convert("RGB")          # 灰度图：按亮度处理，最后转回 L
    else:
        work = img.convert("RGB")

    is_jpeg = fmt == "JPEG"
    if q is None:
        q = JPEG_Q if is_jpeg else PNG_Q

    arr = np.asarray(work).astype(np.float64)
    gray = False                            # 统一按 RGB 处理，输出时再还原模式
    alpha_arr0 = np.asarray(alpha, dtype=np.uint8) if alpha is not None else None

    # 高光留出余量：像素已经是 255 就没有 ±0.25q 的可调空间，水印会嵌不进去。
    # 只压掉超过上限的部分（均匀区域仍然均匀，不会产生块效应）。
    cap = 255.0 - 0.75 * q
    if alpha_arr0 is not None:
        vis = alpha_arr0 > 8
        vmax = float(arr[vis].max()) if vis.any() else 255.0
    else:
        vmax = float(arr.max())
    if vmax > cap:
        arr = np.minimum(arr, cap)
    plane = _luma(arr)

    coef = block_dct(plane)
    bh, bw = coef.shape[0], coef.shape[1]
    n_blocks = bh * bw
    H, W = bh * BLOCK, bw * BLOCK      # 参与嵌入的像素区域（右/下边缘不足一块的部分不动）

    payload = bytes_to_bits(build_payload(watermark_id, 4))
    obf = chaos.xor_bits(payload, x0, mu, salt=SALT)
    need_bits = len(obf) * copies
    bpc = len(COEF_POS)
    need_blocks = (need_bits + bpc - 1) // bpc

    flat = coef.reshape(n_blocks, BLOCK, BLOCK)
    # 块位置由密钥决定的模步进序列给出（O(need)），两端前缀一致
    chosen = _pick_blocks(flat, chaos.block_sequence(
        n_blocks, max(need_blocks, 1), x0, mu, salt="img-block"), need_blocks)
    need_blocks = len(chosen)
    copies = max(1, (need_blocks * bpc) // max(1, len(obf)))

    stream = (obf * copies)[:need_blocks * bpc]
    stream = stream + [0] * (need_blocks * bpc - len(stream))

    orig = flat.copy()
    for idx, block_pos in enumerate(chosen):
        bits = stream[idx * bpc:(idx + 1) * bpc]
        for (r, c), bit in zip(COEF_POS, bits):
            flat[block_pos, r, c] = _qim_embed(flat[block_pos, r, c], bit, q)

    # 逐块限幅：接近纯黑/纯白的块放不下完整幅度，就按比例缩小该块的改动。
    # IDCT 是线性的，所以缩放系数可以按像素余量精确求解；QIM 只看残差符号，
    # 缩小幅度不影响提取，只是抗压缩能力弱一些。
    delta_full = block_idct(flat.reshape(bh, bw, BLOCK, BLOCK)) - plane[:H, :W]
    # 带透明蒙版的图：透明区域的 RGB 是未定义值（常见 0 或 255），
    # 若把它们算进「可用余量」，白底蒙版图会被判成毫无余量、水印直接嵌不进去。
    alpha_arr = np.asarray(alpha, dtype=np.uint8) if alpha is not None else None
    scaled = 0
    for idx, block_pos in enumerate(chosen):
        bi, bj = divmod(int(block_pos), bw)
        r0, c0 = bi * BLOCK, bj * BLOCK
        d = delta_full[r0:r0 + BLOCK, c0:c0 + BLOCK]
        pmax, nmin = float(d.max()), float(d.min())
        base = arr[r0:r0 + BLOCK, c0:c0 + BLOCK]
        if alpha_arr is not None:
            a_blk = alpha_arr[r0:r0 + BLOCK, c0:c0 + BLOCK]
            vis = a_blk > 8
            if not vis.any():
                continue                    # 整块全透明：随便改，无需限幅
            vals = base[vis]
        else:
            vals = base
        head_pos, head_neg = 255.0 - float(vals.max()), float(vals.min())
        s = 1.0
        if pmax > 0 and head_pos < pmax:
            s = min(s, max(0.0, head_pos) / pmax)
        if nmin < 0 and head_neg < -nmin:
            s = min(s, max(0.0, head_neg) / (-nmin))
        if s >= 1.0:
            continue
        scaled += 1
        bits = stream[idx * bpc:(idx + 1) * bpc]
        for (r, c), bit in zip(COEF_POS, bits):
            target = _qim_embed(orig[block_pos, r, c], bit, q)
            flat[block_pos, r, c] = orig[block_pos, r, c] + s * (target - orig[block_pos, r, c])

    coef = flat.reshape(bh, bw, BLOCK, BLOCK)
    new_plane = block_idct(coef)

    # 亮度域的改动量同步加到 RGB 三通道：Y 变化 = delta，Cb/Cr 完全不变，
    # 因此 JPEG 的色度子采样（4:2:0）不会损伤水印。
    # 只把改动叠回可整分的区域，边缘不足一个块的像素原样保留，
    # 保证输出图尺寸与原图完全一致（否则 1650px 宽的封面会变成 1648px）
    delta = new_plane - plane[:H, :W]
    out = arr.copy()
    out[:H, :W, :] = np.clip(arr[:H, :W, :] + delta[:, :, None], 0, 255)
    out_img = Image.fromarray(np.clip(np.round(out), 0, 255).astype(np.uint8),
                              mode="RGB")

    # 还原原始色彩模式与透明通道
    if alpha is not None:
        out_img = out_img.convert("RGBA")
        out_img.putalpha(alpha)
    elif src_mode == "L":
        out_img = out_img.convert("L")

    buf = io.BytesIO()
    if fmt == "JPEG" and alpha is None:
        # 直接用 quality=95 重写会把原图撑大 1.5~2.4 倍（原图可能本就是低质量
        # 高压缩）。优先让 Pillow 沿用原图的量化表（quality="keep"），
        # 老版本不支持时再逐档试探，保证体积不明显膨胀。
        try:
            out_img.save(buf, format="JPEG", quality="keep",
                         subsampling=0, optimize=True)
        except (ValueError, TypeError, OSError):
            for qq in (quality, 92, 88, 85, 80, 75):
                buf = io.BytesIO()
                out_img.save(buf, format="JPEG", quality=int(qq),
                             subsampling=0, optimize=True)
                if len(buf.getvalue()) <= len(img_bytes) * 1.2 or int(qq) <= 75:
                    break
        final_fmt = "JPEG"
    elif fmt == "WEBP":
        out_img.save(buf, format="WEBP", quality=quality, method=4)
        final_fmt = "WEBP"
    else:
        # JPEG 不支持透明：带 alpha 时也退回 PNG，绝不为了省事丢蒙版
        out_img.save(buf, format="PNG", optimize=True)
        final_fmt = "PNG"

    # 调色板 PNG（很多精排书的装饰图是 P 模式 + 透明）：转 RGBA 会让体积涨 3 倍，
    # 这里尝试量化回原调色板；只有确认水印仍能解出才采用，否则保留 RGBA。
    requantized = False
    requantize_error = ""
    if src_mode == "P" and alpha is not None and img.mode == "P":
        try:
            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                cand = out_img.convert("RGB").quantize(
                    palette=img, dither=Image.NONE)
                if "transparency" in img.info:
                    cand.info["transparency"] = img.info["transparency"]
                buf2 = io.BytesIO()
                cand.save(buf2, format="PNG", optimize=True)
            if decode_image(buf2.getvalue(), [(x0, mu)], q=q):
                buf, requantized = buf2, True
            else:
                # 量化把水印改没了。在量化后的图上再嵌一次：此时像素已全部落在
                # 调色板里，第二次量化是无损的，水印就能留下，体积也回到原量级。
                buf3, _info = embed_image(buf2.getvalue(), watermark_id, x0, mu,
                                          copies, quality, q, _depth=_depth + 1)
                buf, requantized = io.BytesIO(buf3), True
        except Exception as exc:                         # noqa: BLE001
            requantize_error = f"{type(exc).__name__}: {exc}"

    return buf.getvalue(), {"blocks": int(need_blocks), "copies": copies,
                            "q": q, "format": final_fmt,
                            "src_format": fmt, "alpha_kept": alpha is not None,
                            "requantized": requantized,
                            "requantize_error": requantize_error,
                            "bits": need_blocks * bpc, "scaled_blocks": scaled}


# ------------------------------------------------------------------ 提取

def extract_bits(img_bytes: bytes, x0: float, mu: float,
                 max_blocks: int | None = None, q: float | None = None) -> list[int]:
    img = Image.open(io.BytesIO(img_bytes))
    if img.mode not in ("RGB", "L"):
        img = img.convert("RGB")
    arr = np.asarray(img).astype(np.float64)
    gray = arr.ndim == 2
    plane = arr if gray else _luma(arr)

    coef = block_dct(plane)
    bh, bw = coef.shape[0], coef.shape[1]
    n_blocks = bh * bw
    flat = coef.reshape(n_blocks, BLOCK, BLOCK)
    is_jpeg = (img.format or "").upper() in ("JPEG", "JPG", "MPO")
    if q is None:
        q = JPEG_Q if is_jpeg else PNG_Q

    limit = min(n_blocks, max_blocks or n_blocks)
    chosen = _pick_blocks(flat, chaos.block_sequence(
        n_blocks, limit, x0, mu, salt="img-block"), limit)
    bits: list[int] = []
    for block_pos in chosen:
        for (r, c) in COEF_POS:
            bits.append(_qim_extract(flat[block_pos, r, c], q))
    return bits


def _vote_and_parse(bits: list[int], x0: float, mu: float, copies: int) -> str | None:
    """多副本逐位多数投票后再解析（抗部分系数被破坏）。"""
    n = len(bits)
    for length in range(1, 33):
        L = (7 + length) * 8
        if L * copies > n:
            continue
        segs = [bits[i * L:(i + 1) * L] for i in range(copies)]
        voted = [1 if sum(s[j] for s in segs) * 2 > copies else 0 for j in range(L)]
        deobf = chaos.xor_bits(voted, x0, mu, salt=SALT)
        try:
            return parse_payload(bits_to_bytes(deobf))
        except (PayloadError, ValueError):
            continue
    return None


def decode_image(img_bytes: bytes, keys: list[tuple[float, float]],
                 window_bits: int = DEFAULT_WINDOW_BITS,
                 robust: bool = True, q: float | None = None) -> list[dict]:
    results = []
    for (x0, mu) in keys:
        bits = extract_bits(img_bytes, x0, mu,
                            max_blocks=max(256, (window_bits // len(COEF_POS)) * 4),
                            q=q)
        if len(bits) < 64:
            continue
        arr = np.array(bits, dtype=np.uint8)
        hit = sliding_search(arr, x0, mu, SALT, window_bits)
        if hit is None and robust:
            for copies in (3, 2, 4):
                wm = _vote_and_parse(bits, x0, mu, copies)
                if wm:
                    hit = (wm, 0, (7 + len(wm.encode("utf-8"))) * 8)
                    break
        if hit:
            results.append({
                "layer": 4,
                "channel": "封面图DCT-QIM",
                "watermark_id": hit[0],
                "offset": hit[1],
                "units": len(bits) // len(COEF_POS),
                "bits": len(bits),
                "key": (x0, mu),
            })
            break
    return results
