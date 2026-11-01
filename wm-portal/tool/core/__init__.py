"""EPUB 隐形水印溯源系统 · 核心包。

四层水印通道：
    1. 混沌映射 + 零宽字符      （文本，抗清洗：中）
    2. Unicode 变体选择符        （文本，抗清洗：强）
    3. CSS 规则重排隐写          （样式，抗 Calibre 重排：强）
    4. 封面图 DCT 域 QIM 水印    （图片，抗格式转换：强）
"""
__version__ = "1.0.0"

__all__ = [
    "chaos", "crc", "payload", "bitsearch", "textscan",
    "zw_encoder", "vs_encoder", "css_steg", "image_watermark",
    "epub_io", "keys", "embed", "decode", "keystore", "storage",
]
