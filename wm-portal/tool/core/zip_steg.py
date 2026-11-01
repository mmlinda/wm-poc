# -*- coding: utf-8 -*-
"""容器层隐写：ZIP 结构（条目顺序 + 时间戳位）。

时间戳子通道默认关闭：各家压缩工具的 extra field / 时间规范化差异较大，
不够稳；需要时把 use_mtime 打开即可。

EPUB 本质是 ZIP。这两层与「内容」完全独立 —— 清洗正文、重写 CSS、重压图片
都碰不到它，AI 清洗脚本更是想不到。

代价要说清楚：
    **重新打包就没了**。Calibre 转格式、Sigil 另存、解压再压缩都会重建 ZIP。
    所以它抗「内容清洗 / AI 洗稿」，不抗「重新打包」，与内容层互为补充。

两个子通道：
    zip_order    — 除 mimetype 外的条目排列顺序（容量 log2(n!)，几百 bit）
    zip_mtime    — 每个条目的修改时间秒数最低位（1 bit/条目，重打包同样会丢）
"""
from __future__ import annotations

import io
import os
import shutil
import zipfile

from . import chaos
from .bitsearch import FIXED_PAYLOAD_BITS, parse_fixed
from .crc import bytes_to_bits
from .payload import build_payload
from .permcodec import bits_to_value, capacity_bits, perm_to_value, value_to_bits, value_to_perm

SALT_ORDER = "zip-order"
SALT_MTIME = "zip-mtime"
LAYER_ORDER = 6
LAYER_MTIME = 7
MIMETYPE = "mimetype"


def _entries(path: str):
    """返回 (mimetype 条目, 其余条目列表)。"""
    with zipfile.ZipFile(path) as zf:
        items = [(i, zf.read(i.filename)) for i in zf.infolist()]
    fixed = [it for it in items if it[0].filename == MIMETYPE]
    rest = [it for it in items if it[0].filename != MIMETYPE]
    return fixed, rest


def embed_zip(src_path: str, dst_path: str, payload, x0: float, mu: float,
              copies: int = 2, use_mtime: bool = False) -> dict:
    """按水印重排 ZIP 条目（并可选写时间戳位），生成新的 epub。"""
    fixed, rest = _entries(src_path)
    n = len(rest)
    cap = capacity_bits(n)
    info: dict = {"entries": n, "capacity_bits": cap, "format": "zip"}

    # ---- 子通道 1：条目顺序 ----
    if n >= 8 and cap >= 96:
        obf = chaos.xor_bits(bytes_to_bits(build_payload(payload, LAYER_ORDER)),
                             x0, mu, salt=SALT_ORDER)
        # 单副本：排列容量远大于载荷，且定点解析要求副本起点为 0
        width = min(len(obf), cap)
        stream = obf[:width]
        value = bits_to_value(stream)
        order = value_to_perm(value, n)
        # 基准必须是「按文件名排序」—— 解码端只能看到当前顺序，
        # 只有用这个两端都能算出来的基准，排列才对得上
        base = sorted(range(n), key=lambda i: rest[i][0].filename)
        rest = [rest[base[i]] for i in order]
        info["order_written"] = width
    else:
        info["order_written"] = 0

    # ---- 子通道 2：时间戳最低位 ----
    if use_mtime:
        obf2 = chaos.xor_bits(bytes_to_bits(build_payload(payload, LAYER_MTIME)),
                              x0, mu, salt=SALT_MTIME)
        need2 = len(obf2) * copies
        slots = min(need2, n)
        if slots >= 64:
            seq = chaos.block_sequence(n, slots, x0, mu, salt="zip-mtime-idx")
            for k in range(slots):
                info_i = rest[seq[k]][0]
                dt = list(info_i.date_time)
                # ZIP 的 DOS 时间戳只存 2 秒精度，秒数恒为偶数，
                # 所以只能用 (sec//2) 的最低位，直接改 sec 的最低位是无效的
                dt[5] = (dt[5] & ~2) | (int(obf2[k % len(obf2)]) << 1)
                info_i.date_time = tuple(dt)
            info["mtime_written"] = slots

    # ---- 写出（保持 mimetype 首位且不压缩）----
    tmp = dst_path + ".tmp"
    with zipfile.ZipFile(tmp, "w") as out:
        for info_i, data in fixed:
            ni = zipfile.ZipInfo(info_i.filename, date_time=info_i.date_time)
            ni.compress_type = zipfile.ZIP_STORED
            ni.external_attr = info_i.external_attr
            out.writestr(ni, data)
        for info_i, data in rest:
            ni = zipfile.ZipInfo(info_i.filename, date_time=info_i.date_time)
            ni.compress_type = info_i.compress_type
            ni.external_attr = info_i.external_attr
            out.writestr(ni, data)
    shutil.move(tmp, dst_path)
    return info


def extract_order_bits(path: str, width: int) -> list[int]:
    """按条目顺序还原比特流。基准顺序 = 排序后的文件名（两端一致）。"""
    with zipfile.ZipFile(path) as zf:
        names = [i.filename for i in zf.infolist()]
    rest = [x for x in names if x != MIMETYPE]
    if len(rest) < 8:
        return []
    base = sorted(rest)
    pos = {name: i for i, name in enumerate(base)}
    perm = [pos[n] for n in rest]
    return value_to_bits(perm_to_value(perm), width)


def extract_mtime_bits(path: str, x0: float, mu: float,
                       slots: int = 128) -> list[int]:
    """按密钥顺序读时间戳里藏的位（与写入端严格对应）。"""
    with zipfile.ZipFile(path) as zf:
        rest = [i for i in zf.infolist() if i.filename != MIMETYPE]
    n = len(rest)
    if n < 64:
        return []
    slots = min(slots, n)
    seq = chaos.block_sequence(n, slots, x0, mu, salt="zip-mtime-idx")
    return [(rest[seq[k]].date_time[5] >> 1) & 1 for k in range(slots)]


def decode_zip(path: str, keys: list[tuple[float, float]]) -> list[dict]:
    """用候选密钥解容器层。"""
    results = []
    for (x0, mu) in keys:
        bits = extract_order_bits(path, FIXED_PAYLOAD_BITS)
        if len(bits) >= 64:
            wm = parse_fixed(bits, x0, mu, SALT_ORDER)
            if wm:
                results.append({"layer": LAYER_ORDER, "channel": "zip_order",
                                "watermark_id": wm, "offset": 0,
                                "units": len(bits), "bits": len(bits),
                                "key": (x0, mu)})
        mbits = extract_mtime_bits(path, x0, mu)
        if len(mbits) >= 64:
            wm2 = parse_fixed(mbits, x0, mu, SALT_MTIME)
            if wm2:
                results.append({"layer": LAYER_MTIME, "channel": "zip_mtime",
                                "watermark_id": wm2, "offset": 0,
                                "units": len(mbits), "bits": len(mbits),
                                "key": (x0, mu)})
    return results
