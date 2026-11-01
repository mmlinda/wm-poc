"""诱饵标记（decoy / canary）：写在**最容易被发现的层**，用来判断文件有没有被清洗。

设计原则（重要）：

1. **诱饵绝不指向任何真实用户**。它是一个固定串 `DECOY`，用**公开常量密钥**
   编码。任何人都能验证它 —— 包括拿到书的人。这样它只能用来判断
   "这份文件是否被清洗过"，绝不会冤枉人。

2. **诱饵放在显性层，真实水印放在隐性层**。对抗方报告里的第一句话就是
   "发现 `--wm-0..11` 自定义属性" —— 那正是诱饵的位置。他会以为自己找到了
   水印并清除掉，而真正的身份还在图片层里。这就是"显性钩子误导"。

3. **诱饵消失 = 被清洗过的强证据**。因为它用的不是密钥而是公开常量，
   不需要数据库、不需要密钥就能检测：
     - 诱饵在 + 真实层在  → 文件原样（大概率是直接转发的）
     - 诱饵没了 + 真实层在 → 被人针对性地清洗过（是有备而来，重点怀疑）
     - 诱饵在 + 真实层没了 → 几乎不可能（除非图片被替换）
"""

from __future__ import annotations

import re

from core import css_steg

# 公开常量密钥：刻意选用"看起来像魔法数字"的无意义常数，
# 目的就是让人一眼看出这不是秘密 —— 它不承担保密职责
DECOY_KEY = (0.6180339887498949, 3.8284271247461903)
# 载荷长度必须**正好整除**单块容量：CSS 通道按块分配比特，若最后一块只写
# 一部分（比如 96 bit 分到 36 bit/块 → 末块 24 bit），读回时会按整块 36 bit
# 高位补零，两端就错位了。2 字节 body → 72 bit = 2 块 × 36 bit，正好整除。
DECOY_TAG = "DC"                # Decoy Canary
DECOY_BITS = (7 + 2) * 8        # 72

# 值取常见无害取值，避免像 `--wm-x: default` 那样整齐得扎眼
_VALUES = ("inherit", "auto", "none", "0", "1", "solid", "center",
           "normal", "100%", "0px", "currentColor", "visible",
           "left", "nowrap")
# 必须都以 css_steg.DUMMY_PREFIX（--wm-）开头：CSS 通道会把"看起来像用户
# 自定义属性"的块判为不安全而跳过，用别的前缀会被整块忽略
_PREFIXES = ("--wm-a", "--wm-b")


def _base_css() -> str:
    out = []
    for pi, pre in enumerate(_PREFIXES):
        decls = ";".join(f"{pre}{i}:{_VALUES[(i + pi) % len(_VALUES)]}"
                         for i in range(css_steg.MAX_K))
        out.append(":root{" + decls + "}")
    return "\n".join(out)


# 诱饵专属块：只认自己这两个前缀。检测和嵌入必须用**同一批块** ——
# 否则检测时整份 CSS 里那些不相干的规则块也会被算进容量表，
# 块顺序一变，读出来的比特流就整体错位了。
_BLOCK_RE = re.compile(r"[^{};]*\{[^{}]*--wm-[ab]\d*\s*:[^{}]*\}")


def _decoy_blocks(css: str) -> list[str]:
    return [m.group(0).strip() for m in _BLOCK_RE.finditer(css)]


def embed_decoy(css: str) -> tuple[str, dict]:
    """在样式表末尾追加承载诱饵的规则块。

    刻意与真实 CSS 通道用**不同的块**：真实通道改写已有规则的排列，
    诱饵只追加自己的块，两者互不干扰。
    """
    if _decoy_blocks(css):
        return css, {"ok": False, "reason": "already_has_decoy"}
    try:
        # exclude_decoy=False：诱饵的载体正是 --wm-a/--wm-b 这些块，
        # 而 CSS 通道默认会把它们排除（为了和真实水印正交）。
        # 若不在这里放行，usable 为空 → 诱饵永远写不进去。
        new_block, info = css_steg.embed_css(_base_css(), DECOY_TAG,
                                             *DECOY_KEY, copies=1,
                                             exclude_decoy=False)
    except Exception:                                    # noqa: BLE001
        return css, {"ok": False}
    if not info.get("blocks"):
        return css, {"ok": False, "info": info}
    sep = "\n" if not css.endswith("\n") else ""
    return css + sep + new_block + "\n", {"ok": True, "info": info}


def detect_decoy(css: str) -> bool:
    """用公开常量密钥检测诱饵是否还在。

    刻意不用 css_steg.decode_css：它内部走 sliding_search，窗口是 248 bit，
    而诱饵只有 96 bit，滑窗根本没机会。诱饵是单副本、起点固定为 0，
    用定点解析即可。
    """
    if not css:
        return False
    blocks = _decoy_blocks(css)
    if len(blocks) < len(_PREFIXES):        # 诱饵块被删掉了
        return False
    try:
        from core.bitsearch import parse_fixed
        # exclude_decoy=False：这里传进来的就是诱饵自己的块，
        # 必须放行，否则 usable 为空、bits 长度恒为 0（检测永远 False）
        bits, _info = css_steg.extract_bits("\n".join(blocks), *DECOY_KEY,
                                            exclude_decoy=False)
    except Exception:                                    # noqa: BLE001
        return False
    if len(bits) < DECOY_BITS:
        return False
    try:
        return parse_fixed(bits, *DECOY_KEY, css_steg.SALT,
                           length=DECOY_BITS) == DECOY_TAG
    except Exception:                                    # noqa: BLE001
        return False
