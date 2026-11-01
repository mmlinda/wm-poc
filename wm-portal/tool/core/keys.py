"""水印密钥生成与序列化（对应 D1 file_pool 表的四个密钥列）。"""
from __future__ import annotations

import hashlib

import re
from dataclasses import dataclass, asdict

from . import chaos


@dataclass
class WatermarkKeys:
    watermark_id: str
    chaos_seed: float      # 第 1 层（零宽字符）混沌初值
    chaos_mu: float        # 第 1 层混沌参数
    css_key: str           # 第 3 层（CSS 重排）密钥，格式 "x0,mu"
    lsb_key: str           # 第 4 层（图片 DCT）密钥，格式 "x0,mu"

    def as_db_row(self) -> dict:
        return asdict(self)

    # 各层实际使用的 (x0, mu) 元组
    def chaos(self) -> tuple[float, float]:
        return (self.chaos_seed, self.chaos_mu)

    def css(self) -> tuple[float, float]:
        return parse_pair(self.css_key)

    def lsb(self) -> tuple[float, float]:
        return parse_pair(self.lsb_key)

    def channel_key(self, name: str) -> tuple[float, float]:
        """为某个通道派生专用密钥。

        新增通道不必改数据库表结构：由主密钥确定性派生即可。
        各通道密钥互不相同 → 攻破一层不影响其它层。
        """
        h = hashlib.sha256(
            f"{self.chaos_seed}|{self.chaos_mu}|{name}".encode()).digest()
        x0 = 0.05 + (int.from_bytes(h[0:6], "big") % 900000) / 1000000.0 * 0.9
        mu = 3.57 + (int.from_bytes(h[6:12], "big") % 430000) / 1000000.0
        return (round(x0, 12), round(mu, 12))

    # 派生通道名（解码时也要逐个尝试，所以列在这里统一管理）
    CHANNELS = ("attr", "opf", "zip")

    def all_keys(self) -> list[tuple[float, float]]:
        """去重后的候选密钥列表（解码时逐层尝试）。"""
        out: list[tuple[float, float]] = []
        pool = [self.chaos(), self.css(), self.lsb()]
        pool += [self.channel_key(c) for c in self.CHANNELS]
        for k in pool:
            if k not in out:
                out.append(k)
        return out


def parse_pair(text: str) -> tuple[float, float]:
    m = re.findall(r"-?\d+(?:\.\d+)?(?:[eE][-+]?\d+)?", text or "")
    if len(m) < 2:
        raise ValueError(f"非法密钥格式: {text!r}")
    return (float(m[0]), float(m[1]))


def format_pair(x0: float, mu: float) -> str:
    return f"{x0:.12f},{mu:.12f}"


def new_keys(watermark_id: str) -> WatermarkKeys:
    a = chaos.random_key()
    b = chaos.random_key()
    c = chaos.random_key()
    return WatermarkKeys(
        watermark_id=watermark_id,
        chaos_seed=round(a[0], 12),
        chaos_mu=round(a[1], 12),
        css_key=format_pair(*b),
        lsb_key=format_pair(*c),
    )


def keys_from_db(row: dict) -> WatermarkKeys:
    return WatermarkKeys(
        watermark_id=row["watermark_id"],
        chaos_seed=float(row["chaos_seed"]),
        chaos_mu=float(row["chaos_mu"]),
        css_key=row["css_key"],
        lsb_key=row["lsb_key"],
    )


def new_watermark_id(prefix: str = "WM") -> str:
    import secrets
    alphabet = "0123456789ABCDEF"
    body = "".join(alphabet[secrets.randbelow(16)] for _ in range(6))
    return f"{prefix}-{body}"


def new_secret_code(length: int = 8) -> str:
    """生成暗号（去掉易混淆字符 0/O/1/I/L）。"""
    import secrets
    alphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
    return "".join(alphabet[secrets.randbelow(len(alphabet))] for _ in range(length))
