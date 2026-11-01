# -*- coding: utf-8 -*-
"""元数据层隐写：OPF 里 manifest / spine 的条目顺序。

和 CSS 重排用的是同一套排列编码，但载体是 OPF 而不是 CSS ——
**不同文件，才是真正正交**：重写样式表不会动 OPF，反之亦然。

只调 <item> / <itemref> 标签的先后顺序，不改任何内容：
manifest 与 spine 的顺序在 EPUB 里本来就不要求按字母排，阅读器按 spine 读。
"""
from __future__ import annotations

import re

from . import chaos
from .bitsearch import FIXED_PAYLOAD_BITS, parse_fixed
from .crc import bytes_to_bits
from .payload import build_payload
from .permcodec import (bits_to_value, capacity_bits, perm_to_value,
                        value_to_bits, value_to_perm)

SALT = "opf-order"
LAYER_ID = 9

ITEM_RE = re.compile(r"<item\b[^>]*/>")
ITEMREF_RE = re.compile(r"<itemref\b[^>]*/>")


def _blocks(text: str, pattern) -> list[tuple[int, int, str]]:
    return [(m.start(0), m.end(0), m.group(0)) for m in pattern.finditer(text)]


def _reorder(text: str, pattern, payload, x0, mu, copies, layer_id, salt):
    blocks = _blocks(text, pattern)
    n = len(blocks)
    cap = capacity_bits(n)
    if n < 6 or cap < 96:
        return text, {"ok": False, "reason": "条目过少", "count": n}

    obf = chaos.xor_bits(bytes_to_bits(build_payload(payload, layer_id)),
                         x0, mu, salt=salt)
    width = min(len(obf), cap)
    stream = obf[:width]
    order = value_to_perm(bits_to_value(stream), n)
    # 基准 = 按标签文本排序（解码端能独立算出同一个基准）
    base = sorted(range(n), key=lambda i: blocks[i][2])

    new = []
    last = 0
    for i, (start, end, _s) in enumerate(blocks):
        new.append(text[last:start])
        new.append(blocks[base[order[i]]][2])
        last = end
    new.append(text[last:])
    return "".join(new), {"ok": True, "count": n, "written": width,
                          "capacity_bits": cap}


def embed_opf(text: str, payload, x0: float, mu: float,
              copies: int = 2) -> tuple[str, dict]:
    """先排 manifest，再排 spine（同一份文本里两个独立位置）。"""
    text, info1 = _reorder(text, ITEM_RE, payload, x0, mu, copies,
                           LAYER_ID, SALT)
    text, info2 = _reorder(text, ITEMREF_RE, payload, x0, mu, copies,
                           LAYER_ID, SALT + "-spine")
    return text, {"manifest": info1, "spine": info2}


def _extract_order_bits(text: str, pattern, width: int = FIXED_PAYLOAD_BITS):
    blocks = _blocks(text, pattern)
    n = len(blocks)
    if n < 6:
        return []
    # 基准顺序 = 原文本字母序（两端一致，不依赖当前顺序）
    base = sorted(b[2] for b in blocks)
    pos = {s: i for i, s in enumerate(base)}
    perm = [pos[b[2]] for b in blocks]
    return value_to_bits(perm_to_value(perm), width)


def decode_opf(text: str, keys: list[tuple[float, float]]) -> list[dict]:
    results = []
    for (x0, mu) in keys:
        for pattern, tag in ((ITEM_RE, "opf_manifest"), (ITEMREF_RE, "opf_spine")):
            bits = _extract_order_bits(text, pattern)
            if len(bits) < 64:
                continue
            salt = SALT if tag == "opf_manifest" else SALT + "-spine"
            wm = parse_fixed(bits, x0, mu, salt)
            if wm:
                results.append({"layer": LAYER_ID, "channel": tag,
                                "watermark_id": wm, "offset": 0,
                                "units": len(bits), "bits": len(bits),
                                "key": (x0, mu)})
    return results
