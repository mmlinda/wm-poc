# -*- coding: utf-8 -*-
"""排列 ↔ 整数 的通用编解码（Lehmer code）。

多个通道共用同一套算法：
    · CSS 声明顺序
    · OPF manifest / spine 顺序
    · ZIP 条目顺序
把「顺序」当成一个大整数来读写，容量是 log2(n!)，200 个条目能装上千 bit。
"""
from __future__ import annotations

import math


def _fact(n: int) -> int:
    return math.factorial(n)


def value_to_perm(value: int, n: int) -> list[int]:
    """整数 → 一个 0..n-1 的排列（Lehmer 展开）。"""
    elems = list(range(n))
    perm: list[int] = []
    for k in range(n - 1, -1, -1):
        f = _fact(k)
        idx, value = divmod(value, f)
        if idx >= len(elems):
            idx = len(elems) - 1
        perm.append(elems.pop(int(idx)))
    return perm


def perm_to_value(perm: list[int]) -> int:
    """排列 → 整数（与 value_to_perm 严格互逆）。"""
    elems = list(range(len(perm)))
    value = 0
    for pos, item in enumerate(perm):
        i = elems.index(item)
        value += i * _fact(len(perm) - 1 - pos)
        elems.pop(i)
    return value


def capacity_bits(n: int) -> int:
    """n 个元素的排列能承载多少 bit。"""
    if n <= 1:
        return 0
    v = _fact(n)
    return v.bit_length() - 1


def bits_to_value(bits: list[int]) -> int:
    return int("".join(str(int(b)) for b in bits), 2) if bits else 0


def value_to_bits(value: int, width: int) -> list[int]:
    """整数 → 定长比特流（高位补 0）。"""
    s = bin(int(value))[2:].rjust(width, "0")
    return [int(c) for c in s[-width:]]
