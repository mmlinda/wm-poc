# -*- coding: utf-8 -*-
"""水印 ID 的 HMAC 签名 + 双通道自检所需的工具函数。

签名作用：即使有人把自己拿到的水印序列复制到别人的文件里，解出来的仍是
他自己的 ID，无法栽赃；同时能一眼识别出「非本系统生成」的伪造水印。
"""
from __future__ import annotations

import hashlib
import hmac
import secrets

from config import SERVER_SECRET

ALPHABET = "0123456789ABCDEF"


def generate_watermark_id() -> str:
    """WM-{10位随机}-{6位HMAC}"""
    random_part = "".join(ALPHABET[secrets.randbelow(16)] for _ in range(10))
    return _sign(random_part)


def sign_random_part(random_part: str) -> str:
    """由 10 位随机段还原完整水印 ID（HMAC 可直接重算，无需写进文件）。"""
    mac = hmac.new(SERVER_SECRET.encode(), random_part.encode(), hashlib.sha256)
    return f"WM-{random_part}-{mac.hexdigest()[:6].upper()}"


_sign = sign_random_part


def verify_watermark_id(watermark_id: str) -> bool:
    if not watermark_id or not watermark_id.startswith("WM-"):
        return False
    parts = watermark_id[3:].split("-")
    if len(parts) != 2 or len(parts[0]) != 10 or len(parts[1]) != 6:
        return False
    random_part, mac_part = parts[0].upper(), parts[1].upper()
    expected = hmac.new(SERVER_SECRET.encode(), random_part.encode(),
                        hashlib.sha256).hexdigest()[:6].upper()
    return hmac.compare_digest(mac_part, expected)


def hamming_distance(a, b) -> int:
    return sum(1 for x, y in zip(a, b) if x != y)


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()
