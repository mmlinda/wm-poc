"""XHTML 保真文本扫描器。

不解析 DOM、不重新序列化，只在原始字节流层面定位"可安全插入隐形字符"的
纯文本区间（跳过标签、注释、CDATA、script/style），从而 100% 保留母本排版。
"""
from __future__ import annotations

from typing import Iterable

SKIP_ELEMENTS = ("script", "style", "svg", "math")


class TextSegment:
    __slots__ = ("start", "end", "text")

    def __init__(self, start: int, end: int, text: str):
        self.start = start
        self.end = end
        self.text = text

    def __repr__(self) -> str:  # pragma: no cover
        return f"TextSegment({self.start}, {self.end})"


def iter_text_segments(html: str) -> list[TextSegment]:
    """返回所有可编辑的纯文本区间（标签外的正文）。"""
    segs: list[TextSegment] = []
    i, n = 0, len(html)
    buf_start = None
    buf: list[str] = []

    def flush(end: int):
        nonlocal buf_start, buf
        if buf_start is not None:
            text = "".join(buf)
            if text:
                segs.append(TextSegment(buf_start, end, text))
        buf_start = None
        buf = []

    while i < n:
        ch = html[i]
        if ch == "<":
            # 标签起点
            if html.startswith("<!--", i):
                flush(i)
                end = html.find("-->", i + 4)
                i = n if end == -1 else end + 3
                continue
            if html.startswith("<![CDATA[", i):
                flush(i)
                end = html.find("]]>", i + 9)
                i = n if end == -1 else end + 3
                continue
            if html.startswith("<?", i) or html.startswith("<!", i):
                flush(i)
                end = html.find(">", i + 2)
                i = n if end == -1 else end + 1
                continue
            end = html.find(">", i + 1)
            if end == -1:
                break
            raw = html[i + 1:end]
            name = raw.strip().lstrip("/").split()[0].lower() if raw.strip() else ""
            closing = name.startswith("/") or raw.strip().endswith("/")
            name = name.lstrip("/")
            flush(i)
            i = end + 1
            if name in SKIP_ELEMENTS and not closing:
                # 跳过整个元素内容直到闭合标签
                close = html.find(f"</{name}", i)
                if close == -1:
                    close = html.find("/>", i)
                i = n if close == -1 else html.find(">", close) + 1
                if i == 0:
                    i = n
            continue
        if buf_start is None:
            buf_start = i
        buf.append(ch)
        i += 1
    flush(n)
    return segs


def apply_insertions(html: str, insertions: Iterable[tuple[int, str]]) -> str:
    """按绝对位置插入字符串（insertions 需按位置升序）。"""
    items = sorted(insertions, key=lambda t: t[0])
    out: list[str] = []
    cursor = 0
    for pos, s in items:
        if pos < cursor:
            raise ValueError("插入位置冲突（未升序）")
        out.append(html[cursor:pos])
        out.append(s)
        cursor = pos
    out.append(html[cursor:])
    return "".join(out)


ANCHOR_CHARS = "，。,.、；;：:！!？?…"


def find_anchor_offsets(text: str, anchors: str = ANCHOR_CHARS) -> list[int]:
    """返回文本中所有锚点（标点）的索引，零宽字符将插在这些标点之前。"""
    return [i for i, c in enumerate(text) if c in anchors]


CJK_RANGES = (
    (0x3400, 0x4DBF),    # CJK 扩展 A
    (0x4E00, 0x9FFF),    # CJK 基本区
    (0xF900, 0xFAFF),    # 兼容表意文字
    (0x20000, 0x2A6DF),  # CJK 扩展 B
)


def is_cjk(ch: str) -> bool:
    cp = ord(ch)
    for lo, hi in CJK_RANGES:
        if lo <= cp <= hi:
            return True
    return False


def find_cjk_offsets(text: str) -> list[int]:
    return [i for i, c in enumerate(text) if is_cjk(c)]
