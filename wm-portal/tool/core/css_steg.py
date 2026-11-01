"""第 3 层：CSS 规则重排隐写。

不插入任何额外字符，只改变「同一规则块内声明的排列顺序」来编码信息。
由于这些声明之间不存在层叠依赖（已过滤简写/长写冲突与重复属性），
重排后渲染结果与母本 100% 一致，肉眼与 diff 工具都无法察觉异常字符。

编码：把待传比特看作一个大整数 N，用阶乘进制（factorial number system）
      拆成 Lehmer code，再把声明按该排列重排。k 条声明可承载 floor(log2(k!)) bit。
解码：计算当前排列相对「属性名字典序」的 Lehmer code，还原 N。
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field

import numpy as np

from . import chaos
from .bitsearch import sliding_search, DEFAULT_WINDOW_BITS
from .crc import bytes_to_bits
from .payload import build_payload

SALT = "css3"
MAX_K = 14               # 参与排列的声明上限（14! ≈ 8.7e10，约 36 bit）
# 扩容用「虚假声明」：自定义属性，未被 var() 引用时对渲染零影响
DUMMY_PREFIX = "--wm-"
DUMMY_VALUE = "default"
MAX_DUMMY = 12

# 简写 → 受其影响的长写属性前缀
SHORTHAND_MAP: dict[str, tuple[str, ...]] = {
    "margin": ("margin-top", "margin-right", "margin-bottom", "margin-left", "margin-block", "margin-inline"),
    "padding": ("padding-top", "padding-right", "padding-bottom", "padding-left", "padding-block", "padding-inline"),
    "border": ("border-width", "border-style", "border-color", "border-top", "border-right",
               "border-bottom", "border-left", "border-radius", "border-image"),
    "border-radius": ("border-top-left-radius", "border-top-right-radius",
                      "border-bottom-right-radius", "border-bottom-left-radius"),
    "font": ("font-family", "font-size", "font-weight", "font-style", "font-variant",
             "font-stretch", "line-height", "font-feature-settings"),
    "background": ("background-color", "background-image", "background-repeat",
                   "background-position", "background-size", "background-attachment",
                   "background-clip", "background-origin"),
    "list-style": ("list-style-type", "list-style-position", "list-style-image"),
    "flex": ("flex-grow", "flex-shrink", "flex-basis"),
    "grid": ("grid-template", "grid-template-rows", "grid-template-columns", "grid-auto-flow"),
    "grid-area": ("grid-row", "grid-column", "grid-row-start", "grid-column-start"),
    "transition": ("transition-property", "transition-duration", "transition-timing-function", "transition-delay"),
    "animation": ("animation-name", "animation-duration", "animation-timing-function",
                  "animation-delay", "animation-iteration-count", "animation-direction"),
    "overflow": ("overflow-x", "overflow-y"),
    "inset": ("top", "right", "bottom", "left"),
    "gap": ("row-gap", "column-gap"),
    "text-decoration": ("text-decoration-line", "text-decoration-color", "text-decoration-style"),
    "outline": ("outline-width", "outline-style", "outline-color"),
    "mask": ("mask-image", "mask-position", "mask-size", "mask-repeat"),
    "page-break-after": (),
}


@dataclass
class Decl:
    prop: str
    value: str
    important: bool = False

    def raw(self) -> str:
        imp = " !important" if self.important else ""
        return f"{self.prop}: {self.value}{imp}"


@dataclass
class Block:
    selector: str
    start: int          # '{' 之后的位置
    end: int            # 匹配 '}' 的位置
    decls: list[Decl] = field(default_factory=list)
    body: str = ""
    safe: bool = True
    reason: str = ""


# --------------------------------------------------------------- CSS 解析

def _split_top_level(body: str) -> list[str]:
    """按 ';' 切分声明，忽略引号与括号内的分号。"""
    parts, buf = [], []
    depth = 0
    quote = None
    for ch in body:
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in "\"'":
            quote = ch
            buf.append(ch)
            continue
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth = max(0, depth - 1)
        if ch == ";" and depth == 0:
            parts.append("".join(buf))
            buf = []
            continue
        buf.append(ch)
    parts.append("".join(buf))
    return [p.strip() for p in parts if p.strip()]


def _parse_decl(text: str) -> Decl | None:
    if ":" not in text:
        return None
    prop, _, value = text.partition(":")
    prop = prop.strip()
    value = value.strip()
    if not prop or not value:
        return None
    important = False
    if value.lower().endswith("!important"):
        important = True
        value = value[: -len("!important")].strip()
    return Decl(prop.lower(), value, important)


def _block_is_safe(decls: list[Decl]) -> tuple[bool, str]:
    if len(decls) < 2:
        return False, "decl<2"
    props = [d.prop for d in decls]
    if len(set(props)) != len(props):
        return False, "dup-prop"
    propset = set(props)
    for shorthand, longs in SHORTHAND_MAP.items():
        if shorthand in propset and any(l in propset for l in longs):
            return False, f"shorthand:{shorthand}"
    # 自定义属性本身无害，但第三方自定义属性语义不明，保守排除；
    # 本系统自己注入的 --wm-* 扩容声明是安全的，予以放行
    if any(p.startswith("--") and not p.startswith(DUMMY_PREFIX) for p in propset):
        return False, "custom-prop"
    if any(d.prop in ("direction", "writing-mode", "unicode-bidi") for d in decls):
        return False, "direction"
    return True, ""


def parse_blocks(css: str) -> list[Block]:
    """扫描 CSS，返回所有「声明块」（@规则内的嵌套块会被递归处理）。"""
    blocks: list[Block] = []
    i, n = 0, len(css)
    while i < n:
        j = css.find("{", i)
        if j == -1:
            break
        # selector：从上一结构结束处到 '{'
        prev = max(css.rfind("}", 0, j), css.rfind(";", 0, j))
        selector = css[prev + 1:j].strip()
        # 匹配对应的 '}'
        depth = 0
        k = j
        quote = None
        while k < n:
            ch = css[k]
            if quote:
                if ch == quote:
                    quote = None
            elif ch in "\"'":
                quote = ch
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    break
            k += 1
        if k >= n:
            break
        body = css[j + 1:k]
        if "{" in body:
            # 嵌套块（@media 等）：交给下一轮扫描处理
            i = j + 1
            continue
        block = Block(selector=selector, start=j + 1, end=k, body=body)
        for part in _split_top_level(body):
            if part.startswith("@"):
                block.safe = False
                block.reason = "at-rule"
                block.decls = []
                break
            d = _parse_decl(part)
            if d is None:
                block.safe = False
                block.reason = "unparsable"
                block.decls = []
                break
            block.decls.append(d)
        if block.safe and block.decls:
            ok, reason = _block_is_safe(block.decls)
            block.safe = ok
            block.reason = reason
        else:
            block.safe = False
        blocks.append(block)
        i = k + 1
    return blocks


# -------------------------------------------------- 阶乘进制 / 排列编解码

_FACT = [math.factorial(i) for i in range(MAX_K + 2)]


def _capacity_bits(k: int) -> int:
    if k < 2:
        return 0
    k = min(k, MAX_K)
    return int(math.floor(math.log2(math.factorial(k))))


def _value_to_lehmer(value: int, k: int) -> list[int]:
    lehmer = [0] * k
    for i in range(k):
        f = math.factorial(k - 1 - i)
        lehmer[i] = value // f
        value %= f
    return lehmer


def _lehmer_to_value(lehmer: list[int], k: int) -> int:
    v = 0
    for i in range(k):
        v += lehmer[i] * math.factorial(k - 1 - i)
    return v


def _apply_lehmer(lehmer: list[int]) -> list[int]:
    """Lehmer code → 排列（对 0..k-1 的索引排列）。"""
    available = list(range(len(lehmer)))
    out = []
    for l in lehmer:
        out.append(available.pop(min(l, len(available) - 1)))
    return out


def _inverse_lehmer(perm: list[int]) -> list[int]:
    """排列 → Lehmer code。"""
    available = sorted(perm)
    lehmer = []
    for p in perm:
        idx = available.index(p)
        lehmer.append(idx)
        available.pop(idx)
    return lehmer


def _canonical_order(decls: list[Decl]) -> list[Decl]:
    return sorted(decls, key=lambda d: d.prop)


def _render(decls: list[Decl]) -> str:
    return "; ".join(d.raw() for d in decls)


# ------------------------------------------------------------------ 嵌入

# 诱饵块（core/decoy.py 写在样式表末尾的 --wm-a / --wm-b 自定义属性块）
# **不参与** CSS 通道：块集合一旦随诱饵的有无而变化，
# chaos.permutation(len(usable)) 算出的顺序就会变，两端对不上（实测
# 加了诱饵后 CSS 通道从 6/6 掉到 4/6）。诱饵必须与之正交：
# 删掉诱饵也不能影响 CSS 水印，反过来同理。
# 这里不能 import decoy（它 import 了本模块，会循环）。
_DECOY_PROP_PREFIXES = ("--wm-a", "--wm-b")


def _is_decoy_block(b) -> bool:
    try:
        return any(str(d.prop).startswith(_DECOY_PROP_PREFIXES)
                   for d in b.decls)
    except Exception:                                    # noqa: BLE001
        return False


# 注意 exclude_decoy 的语义：它只该用来把「诱饵块」从**真实 CSS 水印通道**的
# 块集合里摘出去（否则块数变化会让 chaos.permutation 顺序漂移，正交性归零）。
# 但诱饵**自己的编解码**走的也是这两个函数 —— 若在那边也排除，诱饵块会被
# 自己排除干净：usable 为空 → 诱饵根本写不进去 / 检测恒 False。
# 所以 decoy.py 调用时必须传 exclude_decoy=False。这个坑真实发生过：
# 诱饵从未落盘，层体检却对**任何干净文件**都报"诱饵已被清除、对方有备而来"。
def embed_css(css: str, watermark_id: str, x0: float, mu: float,
              copies: int = 2, fill_random: bool = True,
              exclude_decoy: bool = True) -> tuple[str, dict]:
    """把水印写进 CSS，返回 (新 CSS, 统计信息)。"""
    blocks = parse_blocks(css)
    usable = [b for b in blocks
              if b.safe and _capacity_bits(len(b.decls)) > 0
              and not (exclude_decoy and _is_decoy_block(b))]
    if not usable:
        return css, {"blocks": 0, "capacity_bits": 0, "copies": 0}

    # 用密钥决定块的遍历顺序（每个文件不同）
    perm = chaos.permutation(len(usable), x0, mu, salt="css-block")
    ordered = [usable[p] for p in perm]

    payload = bytes_to_bits(build_payload(watermark_id, 3))
    obf = chaos.xor_bits(payload, x0, mu, salt=SALT)

    # 1) 计算需要多少条「虚假声明」扩容（自定义属性，对渲染零影响）
    def capacity_with(dummy: int) -> int:
        return sum(_capacity_bits(min(len(b.decls) + dummy, MAX_K)) for b in ordered)

    need = len(obf) * copies
    dummy = 0
    while dummy < MAX_DUMMY and capacity_with(dummy) < need:
        dummy += 1
    total_capacity = capacity_with(dummy)
    if total_capacity < len(obf):
        # 装不下哪怕一个完整载荷就不写，避免留下残缺密文
        return css, {"blocks": len(usable), "capacity_bits": total_capacity,
                     "copies": 0, "skipped": "capacity_too_small"}

    # 2) 追加虚假声明（内存中扩展，解码端重新解析 CSS 时自然得到同样的集合）
    for b in ordered:
        for j in range(dummy):
            b.decls.append(Decl(f"{DUMMY_PREFIX}{j}", DUMMY_VALUE))

    # 3) 构造要写入的完整比特流（多副本，尾部不足一个副本时用混沌随机填充）
    # 必须**整块**分配：解码端 extract_bits 是按每个块的完整容量读的，
    # 若这里最后一个块只写一部分（take < cap），那个块剩下的位会变成
    # "多读出来的前导零"，从该块起后面的比特全部错位 ——
    # 表现就是"小容量样式表解不出"（实测某书从第 92 位开始错）。
    plan: list[tuple[Block, int]] = []
    cursor = 0
    for b in ordered:
        k = min(len(b.decls), MAX_K)
        cap = _capacity_bits(k)
        if cap <= 0:
            continue
        plan.append((b, cap))
        cursor += cap
        if cursor >= need:
            break
    actual_copy_bits = cursor
    if actual_copy_bits == 0:
        return css, {"blocks": len(usable), "capacity_bits": total_capacity, "copies": 0}

    stream: list[int] = []
    while len(stream) < actual_copy_bits:
        stream.extend(obf)
    stream = stream[:actual_copy_bits]
    if fill_random and actual_copy_bits % len(obf):
        tail_start = (actual_copy_bits // len(obf)) * len(obf)
        stream[tail_start:] = chaos.bit_stream(x0, mu, actual_copy_bits - tail_start,
                                               channel=3)[:actual_copy_bits - tail_start]

    # 4) 按 plan 重排写入
    edits: list[tuple[int, int, str]] = []   # (start, end, new_body)
    pos = 0
    for b, take in plan:
        chunk = stream[pos:pos + take]
        value = int("".join(map(str, chunk)), 2) if chunk else 0
        k = min(len(b.decls), MAX_K)
        canon = _canonical_order(b.decls)
        head, tail = canon[:k], canon[k:]
        order_idx = _apply_lehmer(_value_to_lehmer(value, k))
        new_decls = [head[i] for i in order_idx] + tail
        edits.append((b.start, b.end, _render(new_decls)))
        pos += take

    out = css
    for start, end, new_body in sorted(edits, key=lambda t: t[0], reverse=True):
        out = out[:start] + new_body + out[end:]

    copies_done = actual_copy_bits // max(1, len(obf))
    return out, {"blocks": len(usable), "used_blocks": len(plan), "dummy": dummy,
                 "capacity_bits": actual_copy_bits, "copies": copies_done}


# ------------------------------------------------------------------ 提取

def extract_bits(css: str, x0: float, mu: float,
                 exclude_decoy: bool = True) -> tuple[list[int], dict]:
    """从 CSS 还原比特流（需要密钥确定块顺序）。

    exclude_decoy=False 供诱饵自身检测使用（见 embed_css 上方注释）。
    """
    blocks = parse_blocks(css)
    usable = [b for b in blocks
              if b.safe and _capacity_bits(len(b.decls)) > 0
              and not (exclude_decoy and _is_decoy_block(b))]
    if not usable:
        return [], {"blocks": 0}
    perm = chaos.permutation(len(usable), x0, mu, salt="css-block")
    ordered = [usable[p] for p in perm]

    bits: list[int] = []
    for b in ordered:
        k = min(len(b.decls), MAX_K)
        cap = _capacity_bits(k)
        if cap <= 0:
            continue
        canon = _canonical_order(b.decls)
        head = canon[:k]
        # 当前文档中这些声明的出现顺序
        cur_idx = []
        for d in b.decls:
            if d in head:
                cur_idx.append(head.index(d))
        if len(cur_idx) != k:
            continue
        lehmer = _inverse_lehmer(cur_idx)
        value = _lehmer_to_value(lehmer, k)
        bits.extend([(value >> i) & 1 for i in range(cap - 1, -1, -1)])
    return bits, {"blocks": len(usable)}


def decode_css(css: str, keys: list[tuple[float, float]],
               window_bits: int = DEFAULT_WINDOW_BITS) -> list[dict]:
    results = []
    for (x0, mu) in keys:
        bits, info = extract_bits(css, x0, mu)
        if len(bits) < 64:
            continue
        hit = None
        if len(bits) >= window_bits:
            hit = sliding_search(np.array(bits, dtype=np.uint8), x0, mu,
                                 SALT, window_bits)
        if not hit:
            # 有些书的样式表总容量不足一个滑窗（实测某书只有 192 bit < 248），
            # 滑窗永远没机会。载荷是单副本、起点固定为 0，改用定点解析兜底。
            try:
                from .bitsearch import parse_fixed
                wm = parse_fixed(bits, x0, mu, SALT)
                if wm:
                    hit = (wm, 0)
            except Exception:                            # noqa: BLE001
                hit = None
        if hit:
            results.append({
                "layer": 3,
                "channel": "CSS规则重排",
                "watermark_id": hit[0],
                "offset": hit[1],
                "units": info.get("blocks", 0),
                "bits": len(bits),
                "key": (x0, mu),
            })
            break
    return results
