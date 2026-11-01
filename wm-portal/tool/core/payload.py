"""统一水印载荷格式：四层通道共用，保证任意一层解出即可溯源。

布局（大端）：
    magic      2B   b'WM'
    version    1B   当前 1
    layer_id   1B   通道编号 1..4（便于解码时区分来源，不影响匹配）
    length     1B   payload 字节数
    payload    NB   水印 ID 的 UTF-8 字节，如 b'WM-A3F8C1'
    crc16      2B   对 magic..payload 的 CRC16-CCITT

总长 = 7 + N 字节（head 5 字节 + body N 字节 + crc 2 字节）。
"""
from __future__ import annotations

from .crc import crc16, bytes_to_bits, bits_to_bytes

MAGIC = b"WM"
VERSION = 1


class PayloadError(ValueError):
    pass


def build_payload(watermark_id: str | bytes, layer_id: int) -> bytes:
    # 允许直接传字节：只嵌入水印 ID 的「随机段」可显著缩短载荷
    body = watermark_id if isinstance(watermark_id, (bytes, bytearray)) \
        else watermark_id.encode("utf-8")
    body = bytes(body)
    if len(body) > 255:
        raise ValueError("水印 ID 过长（>255 字节）")
    head = MAGIC + bytes([VERSION & 0xFF, layer_id & 0xFF, len(body)])
    return head + body + crc16(head + body).to_bytes(2, "big")


def parse_payload(raw: bytes) -> str:
    """解析载荷，返回水印 ID；格式或 CRC 错误抛 PayloadError。"""
    if len(raw) < 8:
        raise PayloadError("载荷长度不足")
    if raw[0:2] != MAGIC:
        raise PayloadError("magic 不匹配")
    if raw[2] != VERSION:
        raise PayloadError(f"版本不支持: {raw[2]}")
    length = raw[4]
    if len(raw) < 6 + length:
        raise PayloadError("载荷被截断")
    body = raw[5:5 + length]
    crc_expected = int.from_bytes(raw[5 + length:7 + length], "big")
    if crc16(raw[:5 + length]) != crc_expected:
        raise PayloadError("CRC 校验失败")
    # 必须用 latin-1（对任意字节都是 1:1 可逆），**不能**先试 utf-8。
    #
    # 载荷 body 通常是「水印 ID 的压缩随机段」（见 to_payload：10 位 hex → 5 字节），
    # 是任意二进制。如果先试 utf-8：约 1.9% 的 5 字节序列恰好是合法 UTF-8，
    # 会被解成多字节字符（字符数 <5），调用方 from_payload() 再 encode('latin-1')
    # 就还原不回原 5 字节 → 水印 ID 还原失败 → verify_watermark_id() 恒 False。
    # 表现就是"嵌入明明成功（zw_copies/images/psnr 都正常），三个通道自检却全 False"，
    # 且重试无效（payload 只由 watermark_id 决定，换密钥救不了）。
    return body.decode("latin-1")


def payload_bits(watermark_id: str, layer_id: int) -> list[int]:
    return bytes_to_bits(build_payload(watermark_id, layer_id))


def from_bits(bits: list[int]) -> str:
    return parse_payload(bits_to_bytes(bits))
