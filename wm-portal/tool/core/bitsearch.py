"""通用比特流滑窗搜索器（四层通道共用）。

所有通道的混淆都采用「混沌密钥流 XOR」——与位置无关，因此解码时可以从
任意比特偏移起对齐解密，再用 magic + CRC16 判定是否命中。
"""
from __future__ import annotations

import numpy as np

from . import chaos
from .crc import bits_to_bytes
from .payload import parse_payload, PayloadError

DEFAULT_WINDOW_BITS = (7 + 24) * 8     # 支持到 24 字节的水印 ID
# 文件里只放水印 ID 的 5 字节随机段 → 载荷固定 (7+5)*8 = 96 bit
FIXED_PAYLOAD_BITS = (7 + 5) * 8


def sliding_search(bits, x0: float, mu: float, salt: str,
                   window_bits: int = DEFAULT_WINDOW_BITS):
    """在比特序列中搜索合法水印载荷。

    返回 (watermark_id, 起始偏移, 载荷比特长度) 或 None。
    bits: 一维 0/1 序列（list 或 np.ndarray）
    """
    arr = np.asarray(bits, dtype=np.uint8)
    L = min(window_bits, len(arr))
    if L < 8 * 8:
        return None
    ks = np.frombuffer(chaos.keystream_bytes(x0, mu, (L + 7) // 8, salt=salt),
                       dtype=np.uint8)
    ksb = np.unpackbits(ks)[:L].astype(np.uint8)

    windows = np.lib.stride_tricks.sliding_window_view(arr, L)
    cand = windows ^ ksb
    head = np.packbits(cand[:, :16], axis=1).ravel()
    hits = np.flatnonzero((head[0::2] == 0x57) & (head[1::2] == 0x4D))
    for start in hits:
        row = cand[start]
        try:
            length = int(np.packbits(row[32:40])[0])
            total = (7 + length) * 8
            if total == 0 or total > len(row):
                continue
            wm_id = parse_payload(bits_to_bytes(row[:total]))
            return wm_id, int(start), total
        except (PayloadError, ValueError, IndexError):
            continue
    return None


def parse_fixed(bits, x0: float, mu: float, salt: str,
                length: int = FIXED_PAYLOAD_BITS):
    """从**固定起点 0** 解析载荷（排列类通道专用）。

    sliding_search 依赖"副本起点处密钥对齐"，而排列通道是把比特流转成整数，
    高位补零会让副本起点不在 0，滑窗就永远对不上。排列容量本来就绰绰有余
    （200 个条目约 1200 bit），所以直接用单副本 + 定点解析即可。
    """
    arr = np.asarray(bits, dtype=np.uint8)
    if len(arr) < length:
        arr = np.concatenate([np.zeros(length - len(arr), dtype=np.uint8), arr])
    arr = arr[:length]
    ks = np.frombuffer(chaos.keystream_bytes(x0, mu, (length + 7) // 8,
                                             salt=salt), dtype=np.uint8)
    cand = arr ^ np.unpackbits(ks)[:length].astype(np.uint8)
    try:
        wm_id = parse_payload(bits_to_bytes(cand))
        return wm_id if wm_id else None
    except (PayloadError, ValueError, IndexError):
        return None
