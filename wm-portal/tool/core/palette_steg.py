# -*- coding: utf-8 -*-
"""调色板 PNG 隐写 —— 专门给「带透明蒙版的头图」用。

为什么需要它：
    精排书的头图大量是 P 模式（调色板）+ transparency 的 PNG。这类图要做
    DCT 水印必须先转 RGBA，体积会涨 2~3 倍，量化回去又极慢。

思路：
    P 模式图的像素值其实是「调色板索引」，真正决定颜色的是那张 256 色的表。
    只改调色板里颜色的最低位（±1/255），人眼完全看不出来，而：
      · 像素数据一个字节都不动 → 透明蒙版 100% 保留
      · 调色板长度不变、像素不变 → 文件体积几乎不变
      · 只改 256 个颜色 → 速度是毫秒级（DCT 方案要几百毫秒）

代价：依赖调色板顺序。若图片被 pngquant 之类的工具重新生成调色板会失效，
所以它是**补充通道**，与 DCT 通道互为备份，不单独承担全部溯源。
"""
from __future__ import annotations

import io

import numpy as np
from PIL import Image

from . import chaos
from .bitsearch import DEFAULT_WINDOW_BITS, sliding_search
from .crc import bytes_to_bits
from .payload import build_payload

SALT = "pal5"
LAYER_ID = 5
# 调色板容量 = 实际用到的颜色数（1 色承载 1 bit）。一个完整载荷是
# (7 + 5) * 8 = 96 bit（水印 ID 的 5 字节随机段），所以阈值**必须 >= 96**。
# 曾经设为 64：64~95 色的 PNG 会"嵌入不报错、解码永远失败"（假成功），
# 在层体检里还会被误判成"调色板被重建（pngquant）"。
MIN_COLORS = 96


def _used_indices(img: Image.Image) -> list[int]:
    """实际被用到的调色板索引（按升序，两端一致且不依赖文件内容改动）。"""
    hist = img.histogram()
    n = min(len(hist), 256)
    return [i for i in range(n) if hist[i] > 0]


def embed_palette(img_bytes: bytes, watermark_id, x0: float, mu: float,
                  copies: int = 3) -> tuple[bytes, dict]:
    """在调色板中嵌入水印，返回 (新字节, 统计)。"""
    img = Image.open(io.BytesIO(img_bytes))
    if img.mode != "P":
        raise ValueError("embed_palette 仅支持调色板(P) PNG")
    used = _used_indices(img)
    if len(used) < MIN_COLORS:
        raise ValueError(f"调色板颜色过少（{len(used)} < {MIN_COLORS}），不适合嵌入")

    obf = chaos.xor_bits(bytes_to_bits(build_payload(watermark_id, LAYER_ID)),
                         x0, mu, salt=SALT)
    # 精确容量校验（阈值只是个粗筛）：载荷本身多长就要求多少色。
    # 不做这一步就会出现"写进去了、还报了成功，但解码端永远凑不齐一个载荷"。
    if len(used) < len(obf):
        raise ValueError(f"调色板容量不足（{len(used)} 色 < 载荷 {len(obf)} bit），"
                         "承载不下一个完整载荷，拒绝嵌入（避免假成功）")
    need = len(obf) * copies
    if len(used) < need:
        copies = max(1, len(used) // max(1, len(obf)))
        need = len(obf) * copies
    stream = (obf * copies)[:len(used)]

    # 索引顺序由密钥决定：拿到两份文件也无法靠 diff 定位到具体颜色
    order = chaos.block_sequence(len(used), len(stream), x0, mu, salt="pal-idx")
    pal = list(img.getpalette())
    for k, bit in enumerate(stream):
        idx = used[order[k]]
        pal[idx * 3] = (pal[idx * 3] & 0xFE) | int(bit)     # R 通道最低位

    out = img.copy()
    out.putpalette(pal)
    if "transparency" in img.info:
        out.info["transparency"] = img.info["transparency"]

    buf = io.BytesIO()
    out.save(buf, format="PNG", optimize=True)
    return buf.getvalue(), {"blocks": len(stream), "copies": copies,
                            "colors": len(used), "format": "PNG",
                            "mode": "P", "alpha_kept": True}


def extract_bits(img_bytes: bytes, x0: float, mu: float) -> list[int]:
    img = Image.open(io.BytesIO(img_bytes))
    if img.mode != "P":
        return []
    used = _used_indices(img)
    pal = list(img.getpalette())
    n = len(used)
    order = chaos.block_sequence(n, n, x0, mu, salt="pal-idx")
    return [pal[used[order[k]] * 3] & 1 for k in range(n)]


def decode_palette(img_bytes: bytes,
                   keys: list[tuple[float, float]],
                   window_bits: int = DEFAULT_WINDOW_BITS) -> list[dict]:
    results = []
    for (x0, mu) in keys:
        bits = extract_bits(img_bytes, x0, mu)
        if len(bits) < 64:
            continue
        hit = sliding_search(np.array(bits, dtype=np.uint8), x0, mu,
                             SALT, window_bits)
        if hit:
            results.append({"layer": LAYER_ID, "channel": "调色板",
                            "watermark_id": hit[0], "offset": hit[1],
                            "units": len(bits), "bits": len(bits),
                            "key": (x0, mu)})
    return results
