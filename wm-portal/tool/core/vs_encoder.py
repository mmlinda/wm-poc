"""第 2 层：Unicode 变体选择符（Variant Selector）隐写。

原理：在汉字之后附加一个变体选择符（VS）。Unicode 中 VS 本身不占宽度、
不单独渲染；当字体没有对应变体字形时，显示结果与基础汉字完全一致。
通过 VS 的序号编码水印比特，肉眼与排版均无任何变化。

与第 1 层互补：零宽字符常被清洗工具按 Unicode 类别 Cf 批量剔除，
而 VS 属于 Mn（组合标记），是不同通道，可独立存活。

两种码位平面：
    ivs  → U+E0100 起（VS17..VS48，表意文字变体序列），5 bit/字符【默认】
    vs1  → U+FE00  起（VS1..VS16），4 bit/字符，兼容性更老
"""
from __future__ import annotations

import numpy as np

from . import chaos
from .bitsearch import sliding_search, DEFAULT_WINDOW_BITS
from .crc import bytes_to_bits
from .payload import build_payload
from .textscan import iter_text_segments, find_cjk_offsets, apply_insertions, is_cjk

PLANES = {
    "ivs": (0xE0100, 5),
    "vs1": (0xFE00, 4),
}
DEFAULT_PLANE = "ivs"
SALT = "vs2"


def _base(plane: str) -> int:
    return PLANES[plane][0]


def _bpc(plane: str) -> int:
    return PLANES[plane][1]


def _is_vs(ch: str, plane: str) -> bool:
    base, bpc = PLANES[plane]
    return base <= ord(ch) < base + (1 << bpc)


def encode_bits(bits: list[int], x0: float, mu: float, plane: str) -> str:
    obf = chaos.xor_bits(bits, x0, mu, salt=SALT)
    bpc = _bpc(plane)
    base = _base(plane)
    out = []
    for i in range(0, len(obf), bpc):
        chunk = obf[i:i + bpc]
        if len(chunk) < bpc:
            chunk = chunk + [0] * (bpc - len(chunk))
        out.append(chr(base + int("".join(map(str, chunk)), 2)))
    return "".join(out)


def vs_to_bits(vs: str, plane: str) -> list[int]:
    base, bpc = PLANES[plane]
    bits: list[int] = []
    for ch in vs:
        v = ord(ch) - base
        bits.extend((v >> i) & 1 for i in range(bpc - 1, -1, -1))
    return bits


def embed_html(html: str, watermark_id: str, x0: float, mu: float,
               plane: str = DEFAULT_PLANE, copies: int = 3,
               min_gap: int = 3) -> tuple[str, int]:
    """在汉字后附加变体选择符，返回 (新 HTML, 实际副本数)。"""
    payload = bytes_to_bits(build_payload(watermark_id, 2))
    bpc = _bpc(plane)
    per_copy = (len(payload) + bpc - 1) // bpc
    if per_copy == 0:
        return html, 0

    cjk: list[int] = []
    for seg in iter_text_segments(html):
        for off in find_cjk_offsets(seg.text):
            cjk.append(seg.start + off)
    if not cjk:
        return html, 0
    copies = max(1, min(copies, len(cjk) // per_copy))
    if copies == 0:
        return html, 0

    perm = chaos.permutation(len(cjk), x0, mu, salt="vs-anchor")
    chosen = sorted(cjk[p] for p in perm[:per_copy * copies])

    # min_gap：避免同一句话里连续汉字都挂 VS（更自然、更抗统计检测）
    filtered: list[int] = []
    last = -10 ** 9
    for pos in chosen:
        if pos - last >= min_gap:
            filtered.append(pos)
            last = pos
    if len(filtered) < per_copy * copies:
        used = set(filtered)
        rest = [p for p in chosen if p not in used]
        filtered.extend(rest[:per_copy * copies - len(filtered)])
        filtered.sort()

    vs = encode_bits(payload, x0, mu, plane) * copies
    # VS 必须紧跟在汉字之后：插入点在汉字索引 +1
    insertions = [(pos + 1, ch) for pos, ch in zip(filtered, vs)]
    return apply_insertions(html, insertions), copies


def extract_vs(html: str, plane: str) -> str:
    """提取所有「汉字后紧跟的变体选择符」。"""
    out: list[str] = []
    for seg in iter_text_segments(html):
        text = seg.text
        for i, ch in enumerate(text):
            if is_cjk(ch) and i + 1 < len(text) and _is_vs(text[i + 1], plane):
                out.append(text[i + 1])
    return "".join(out)


def decode_html(html: str, keys: list[tuple[float, float]],
                planes: list[str] | None = None,
                window_bits: int = DEFAULT_WINDOW_BITS) -> list[dict]:
    results = []
    for plane in (planes or list(PLANES)):
        vs = extract_vs(html, plane)
        if len(vs) < 24:
            continue
        arr = np.array(vs_to_bits(vs, plane), dtype=np.uint8)
        for (x0, mu) in keys:
            hit = sliding_search(arr, x0, mu, SALT, window_bits)
            if hit:
                results.append({
                    "layer": 2,
                    "channel": f"变体选择符({plane})",
                    "watermark_id": hit[0],
                    "offset": hit[1],
                    "units": len(vs),
                    "bits": len(arr),
                    "key": (x0, mu),
                })
                break
    return results
