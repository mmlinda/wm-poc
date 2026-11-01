# -*- coding: utf-8 -*-
"""内容层第二编码：XHTML 属性引号类型（" ↔ '）。

与零宽字符互补：
    · 零宽怕「过滤不可见字符」
    · 引号类型怕「DOM 重新序列化」（和 CSS 重排同一类威胁）
两者载体不同、清洗方式不同，同一份文件里互为备份。

只改引号，不改属性顺序、不改属性值 → XML 解析结果完全一致，
渲染零影响，文件大小也不变。

坑：正则必须**同时匹配单双引号**。只匹配双引号的话，嵌入后部分属性变成
单引号就再也匹配不到，两端位置集合会错位，水印直接解不出来。
"""
from __future__ import annotations

import re

import numpy as np

from . import chaos
from .bitsearch import DEFAULT_WINDOW_BITS, sliding_search
from .crc import bytes_to_bits
from .payload import build_payload

SALT = "attr-quote"
LAYER_ID = 8

# 第 3 组 = 带引号的属性值；单双引号都接受
ATTR_RE = re.compile(r"""([ \t\r\n])([A-Za-z_][\w:.\-]*)=("[^"]*"|'[^']*')""")


def _positions(text: str) -> list[tuple[int, int, int]]:
    """可编码位置 → (整体起始, 整体结束, 引号所在下标)。"""
    out = []
    for m in ATTR_RE.finditer(text):
        out.append((m.start(0), m.end(0), m.start(3)))
    return out


def _with_quote(seg: str, want_single: bool) -> str | None:
    """把 ` name="v"` 形式的片段改成指定引号，改不了返回 None。"""
    eq = seg.find("=")
    if eq < 0:
        return None
    i = eq + 1
    while i < len(seg) and seg[i] not in "\"'":
        i += 1
    if i >= len(seg):
        return None
    old = seg[i]
    new = "'" if want_single else '"'
    if old == new:
        return seg
    # 注意：inner 已经去掉了尾部引号，不要再补 tail，否则会多出一个引号
    inner = seg[i + 1:-1] if seg[-1] in "\"'" else seg[i + 1:]
    if new in inner:            # 属性值里本身有该引号，跳过避免破坏
        return None
    return seg[:i] + new + inner + new


def _global_positions(texts: list[str]) -> list[tuple[int, int, int, int]]:
    """跨页收集所有属性位置（页序号, 起始, 结束, 引号下标）。

    单页往往凑不满一个载荷（样本书每页仅约 41 个属性位，而载荷要 96 位），
    所以必须把多页的属性位拼成一条长比特流。
    """
    out = []
    for ti, t in enumerate(texts):
        for (start, end, q) in _positions(t):
            out.append((ti, start, end, q))
    return out


def embed_attributes(texts: list[str], payload, x0: float, mu: float,
                     copies: int = 3) -> tuple[list[str], dict]:
    """把水印写进属性引号，返回 (新文本, 统计)。"""
    gp = _global_positions(texts)
    if len(gp) < 64:
        return texts, {"ok": False, "reason": "属性过少", "slots": len(gp)}

    obf = chaos.xor_bits(bytes_to_bits(build_payload(payload, LAYER_ID)),
                         x0, mu, salt=SALT)
    need = len(obf) * copies
    slots = min(need, len(gp))
    seq = chaos.block_sequence(len(gp), slots, x0, mu, salt="attr-idx")
    plan = {seq[k]: int(obf[k % len(obf)]) for k in range(slots)}

    # 按页分组、页内倒序改写（避免改动影响后续位置）
    edits: dict[int, list] = {}
    for gi, bit in plan.items():
        ti, start, end, _q = gp[gi]
        edits.setdefault(ti, []).append((start, end, bit))

    new_texts = list(texts)
    done = 0
    for ti, items in edits.items():
        t = new_texts[ti]
        for start, end, bit in sorted(items, reverse=True):
            new_seg = _with_quote(t[start:end], bit == 1)
            if new_seg is None:
                continue
            t = t[:start] + new_seg + t[end:]
            done += 1
        new_texts[ti] = t
    return new_texts, {"ok": done > 0, "slots": len(gp), "written": done,
                       "copies": copies}


def extract_bits(texts: list[str], x0: float, mu: float,
                 slots: int = 1024) -> list[int]:
    """按密钥顺序、跨页读回引号类型位。"""
    gp = _global_positions(texts)
    if not gp:
        return []
    n = len(gp)
    slots = min(slots, n)
    seq = chaos.block_sequence(n, slots, x0, mu, salt="attr-idx")
    return [1 if texts[gp[seq[k]][0]][gp[seq[k]][3]] == "'" else 0
            for k in range(slots)]


def decode_attributes(texts: list[str], keys: list[tuple[float, float]],
                      window_bits: int = DEFAULT_WINDOW_BITS) -> list[dict]:
    results = []
    for (x0, mu) in keys:
        bits = extract_bits(texts, x0, mu)
        if len(bits) < 64:
            continue
        hit = sliding_search(np.array(bits, dtype=np.uint8), x0, mu,
                             SALT, window_bits)
        if hit:
            results.append({"layer": LAYER_ID, "channel": "attributes",
                            "watermark_id": hit[0], "offset": hit[1],
                            "units": len(bits), "bits": len(bits),
                            "key": (x0, mu)})
    return results
