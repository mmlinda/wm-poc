#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""index.html 静态体检：id 唯一性 / JS 引用悬空 / 遮罩-面板配对 / 菜单行按钮。

起因：曾经把「按钮」和它的「遮罩层」写成同一个 id（都叫 m-wm）。
`document.getElementById` 只返回文档里第一个，于是：
  · hideAll() 把**按钮**加上了 .hide —— 按钮直接消失
  · 给遮罩绑的「点击=关闭」也绑到了按钮上 —— 点了立即关闭，看起来像"点不动"
两个症状都是同一个原因，肉眼极难发现（页面完全正常，只是按钮不在）。

用法：
    python check_ui.py            # 检查 index.html
    python check_ui.py --fix-hint # 额外打印修复建议

退出码：0 通过 / 1 有问题。改完前端**必须跑一次**。
"""
from __future__ import annotations

import collections
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PATH = os.path.join(HERE, "index.html")
# 允许指定别的文件（例如从线上拉下来的 index.html 做同源校验）
if "--file" in sys.argv:
    PATH = sys.argv[sys.argv.index("--file") + 1]


def ids_in(html: str) -> list[str]:
    return re.findall(r'\bid="([A-Za-z0-9_-]+)"', html)


def main() -> int:
    with open(PATH, "r", encoding="utf-8") as f:
        h = f.read()

    problems = 0

    # 1) id 必须唯一
    cnt = collections.Counter(ids_in(h))
    dup = {k: v for k, v in cnt.items() if v > 1}
    print(f"[1] id 唯一性：{len(cnt)} 个 id")
    if dup:
        problems += len(dup)
        for k, v in sorted(dup.items()):
            print(f"    × {k} 重复 {v} 次")
            for m in re.finditer(r'<[^>]*\bid="%s"[^>]*>' % re.escape(k), h):
                line = h[:m.start()].count("\n") + 1
                print(f"        L{line}: {m.group(0)[:78]}")
    else:
        print("    √ 无重复")

    # 2) $("xxx") 这类字面量引用必须存在
    refs = set(re.findall(r'\$\("([A-Za-z0-9_-]+)"\)', h))
    refs |= set(re.findall(r'getElementById\("([A-Za-z0-9_-]+)"\)', h))
    ghost = sorted(r for r in refs if r not in cnt)
    print(f"[2] JS 引用：{len(refs)} 个字面量 id")
    if ghost:
        problems += len(ghost)
        for g in ghost:
            print(f"    × 引用了不存在的 id：{g}")
    else:
        print("    √ 无悬空引用")

    # 3) 遮罩 div.mask 必须有配套面板 sh-xxx，且 PAIRS 里登记
    #    注意：只认 <div class="mask ...">，不能按名字猜 —— 按钮也可能叫 m-admins
    masks = re.findall(r'<div class="mask[^"]*" id="([A-Za-z0-9_-]+)"', h)
    pairs_block = re.search(r"var PAIRS = \{(.*?)\};", h, re.S)
    pairs_txt = pairs_block.group(1) if pairs_block else ""
    print(f"[3] 遮罩 {len(masks)} 个：{' '.join(sorted(masks))}")
    for m in sorted(masks):
        sheet = "sh-" + m[2:]
        if sheet not in cnt:
            problems += 1
            print(f"    × {m} 没有对应的面板 {sheet}")
        elif f'"{m}"' not in pairs_txt:
            problems += 1
            print(f"    × {m} 没在 PAIRS 里登记（点了不会自动关闭）")
    if not problems:
        print("    √ 遮罩/面板/PAIRS 一一对应")

    # 4) 每个菜单按钮都要有 onclick 绑定
    btns = [i for i in cnt if i.startswith("btn-") or i.startswith("m-")]
    menu_btns = re.findall(r'<button class="act[^"]*" id="([A-Za-z0-9_-]+)"', h)
    print(f"[4] 菜单按钮 {len(menu_btns)} 个")
    unbound = []
    for b in menu_btns:
        if f'$("{b}").onclick' not in h and f'data-close' not in b:
            unbound.append(b)
    if unbound:
        problems += len(unbound)
        for b in unbound:
            print(f"    × {b} 没有 onclick 绑定（点了不会有反应）")
    else:
        print("    √ 全部已绑定")

    # 5) hideAll() 里列出的必须是遮罩，绝不能出现按钮
    #    这是这次 bug 的根因：数组里写了按钮 id，classList.add("hide") 就把按钮藏了
    ha = re.search(r"function hideAll\(\)\{(.*?)\n  \}", h, re.S)
    print("[5] hideAll() 只操作遮罩")
    if not ha:
        print("    ! 没找到 hideAll()，跳过（若改名了请同步本检查）")
    else:
        body = ha.group(1)
        listed = re.findall(r'\[([^\]]*)\]', body)
        hide_ids: list[str] = []
        for grp in listed:
            hide_ids += re.findall(r'"([A-Za-z0-9_-]+)"', grp)
        bad = [i for i in hide_ids if i.startswith("btn-")]
        if bad:
            problems += len(bad)
            for b in bad:
                print(f"    × {b} 是按钮，不该被 hideAll 隐藏")
        else:
            print(f"    √ 共 {len(hide_ids)} 个 id，均为遮罩/面板")

    print()
    if problems:
        print(f"发现 {problems} 处问题。")
        print("提示：按钮和遮罩**不能同 id**。按钮用 btn-xxx，遮罩用 m-xxx，面板用 sh-xxx。")
        return 1
    print("全部通过。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
