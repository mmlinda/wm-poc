"""CRC16-CCITT 校验（多项式 0x1021，初值 0xFFFF）。

用于水印载荷完整性校验：解码时用 CRC 判断是否解出了正确的水印 ID，
也是在未知密钥时快速筛选候选密钥的判据。
"""
from typing import Iterable

_POLY = 0x1021
_INIT = 0xFFFF


def crc16(data: bytes, init: int = _INIT) -> int:
    crc = init & 0xFFFF
    for b in data:
        crc ^= (b << 8) & 0xFFFF
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ _POLY) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc & 0xFFFF


def crc16_bytes(data: bytes) -> bytes:
    return crc16(data).to_bytes(2, "big")


# ---------------------------------------------------------------- 比特流工具

def bytes_to_bits(data: bytes) -> list[int]:
    return [(b >> i) & 1 for b in data for i in range(7, -1, -1)]


def bits_to_bytes(bits: Iterable[int]) -> bytes:
    bits = list(bits)
    if len(bits) % 8:
        raise ValueError(f"比特数必须是 8 的倍数，当前 {len(bits)}")
    out = bytearray()
    for i in range(0, len(bits), 8):
        v = 0
        for b in bits[i:i + 8]:
            v = (v << 1) | (1 if b else 0)
        out.append(v)
    return bytes(out)


def int_to_bits(value: int, width: int) -> list[int]:
    return [(value >> i) & 1 for i in range(width - 1, -1, -1)]


def bits_to_int(bits: Iterable[int]) -> int:
    v = 0
    for b in bits:
        v = (v << 1) | (1 if b else 0)
    return v
