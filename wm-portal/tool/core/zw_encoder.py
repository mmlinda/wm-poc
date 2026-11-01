"""第 1 层：混沌映射 + 零宽字符隐写。

编码链：
    水印ID → 载荷比特流 → 混沌密钥流 XOR 混淆 → N 位分组 → 零宽字符
    → 按密钥伪随机分散嵌入到「中英文逗号/句号」之前

安全性说明：
    默认的 EXT8 字符集全部是无方向性、不可见的字符（ZWSP/ZWNJ/ZWJ/WJ/
    INVISIBLE× 等）。原始设计方案中出现的 U+200E/U+200F/U+202A-U+202D/
    U+206A-U+206F 属于**双向文本控制符**，会让标点在混排时发生左右跳动，
    因此放到 FULL16 字符集里，需显式开启才使用。
"""
from __future__ import annotations

from typing import Iterable

import numpy as np

from . import chaos
from .bitsearch import sliding_search, DEFAULT_WINDOW_BITS
from .crc import bytes_to_bits
from .payload import build_payload
from .textscan import iter_text_segments, find_anchor_offsets, apply_insertions

CHARSETS: dict[str, list[str]] = {
    # 2 bit/字符：兼容性最好
    "safe4": ["\u200b", "\u200c", "\u200d", "\u2060"],
    # 3 bit/字符：默认，全部为无渲染影响的不可见字符
    "ext8": ["\u200b", "\u200c", "\u200d", "\u2060",
             "\u2061", "\u2062", "\u2063", "\u2064"],
    # 4 bit/字符：含双向控制符，可能干扰标点方向，**谨慎开启**
    "full16": ["\u200b", "\u200c", "\u200d", "\u200e", "\u200f", "\ufeff",
               "\u202a", "\u202b", "\u202c", "\u202d", "\u206a", "\u206b",
               "\u206c", "\u206d", "\u206e", "\u206f"],
}

DEFAULT_CHARSET = "ext8"
SALT = "zw1"
BITS_PER_CHAR = {"safe4": 2, "ext8": 3, "full16": 4}


def _bits_per_char(charset: str) -> int:
    return BITS_PER_CHAR[charset]


def _chunks(bits: list[int], n: int) -> Iterable[list[int]]:
    for i in range(0, len(bits), n):
        chunk = bits[i:i + n]
        if len(chunk) < n:
            chunk = chunk + [0] * (n - len(chunk))
        yield chunk


def encode_bits(bits: list[int], x0: float, mu: float, charset: str) -> str:
    """比特流 → 零宽字符串。"""
    obf = chaos.xor_bits(bits, x0, mu, salt=SALT)
    table = CHARSETS[charset]
    return "".join(table[int("".join(map(str, c)), 2)]
                   for c in _chunks(obf, _bits_per_char(charset)))


def zw_to_bits(zw: str, charset: str) -> list[int]:
    """零宽字符串 → 比特流（不做解混淆）。"""
    table = CHARSETS[charset]
    bpc = _bits_per_char(charset)
    index = {c: i for i, c in enumerate(table)}
    bits: list[int] = []
    for ch in zw:
        v = index.get(ch)
        if v is None:
            raise ValueError("零宽字符串含未知字符")
        bits.extend((v >> i) & 1 for i in range(bpc - 1, -1, -1))
    return bits


def embed_html(html: str, watermark_id: str, x0: float, mu: float,
               charset: str = DEFAULT_CHARSET, copies: int = 3) -> tuple[str, int]:
    """把水印嵌入单个 XHTML 文档，返回 (新 HTML, 实际嵌入副本数)。"""
    payload = bytes_to_bits(build_payload(watermark_id, 1))
    bpc = _bits_per_char(charset)
    per_copy = (len(payload) + bpc - 1) // bpc
    if per_copy == 0:
        return html, 0

    anchors: list[int] = []
    for seg in iter_text_segments(html):
        for off in find_anchor_offsets(seg.text):
            anchors.append(seg.start + off)
    if not anchors:
        return html, 0
    copies = max(1, min(copies, len(anchors) // per_copy))
    if copies == 0:
        return html, 0
    needed = per_copy * copies

    # 用密钥伪随机挑选锚点：不同文件嵌入位置完全不同，难以被模式化清洗
    perm = chaos.permutation(len(anchors), x0, mu, salt="zw-anchor")
    chosen = sorted(anchors[p] for p in perm[:needed])

    zw = encode_bits(payload, x0, mu, charset) * copies
    return apply_insertions(html, list(zip(chosen, zw))), copies


def extract_zw(html: str, charset: str) -> str:
    """提取文档中属于该字符集的所有零宽字符（保持文档顺序）。"""
    chars = set(CHARSETS[charset])
    out: list[str] = []
    for seg in iter_text_segments(html):
        for ch in seg.text:
            if ch in chars:
                out.append(ch)
    return "".join(out)


def decode_html(html: str, keys: list[tuple[float, float]],
                charsets: list[str] | None = None,
                window_bits: int = DEFAULT_WINDOW_BITS) -> list[dict]:
    """从 XHTML 解码第 1 层水印。"""
    results = []
    for charset in (charsets or list(CHARSETS)):
        zw = extract_zw(html, charset)
        if len(zw) < 32:
            continue
        arr = np.array(zw_to_bits(zw, charset), dtype=np.uint8)
        for (x0, mu) in keys:
            hit = sliding_search(arr, x0, mu, SALT, window_bits)
            if hit:
                results.append({
                    "layer": 1,
                    "channel": f"零宽字符({charset})",
                    "watermark_id": hit[0],
                    "offset": hit[1],
                    "units": len(zw),
                    "bits": len(arr),
                    "key": (x0, mu),
                })
                break
    return results
