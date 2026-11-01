"""层体检 / 清洗指纹分析。

对抗方（ cleanser ）的定位思路是「全库一致性统计」：不需要密钥、不需要第二份
副本，只要统计"哪几章写法不一样"就能找到水印。所以溯源时除了给出身份，还
必须说清楚「哪几层还活着、哪几层被抹掉了、对方大概做了什么」——

**存活层数本身就是判断对方清洗能力的证据**：
  - 图片层还活着 → 对方只是清了文本/容器，不具备信号域处理能力（最常见）
  - 图片层也没了 → 对方做了重编码，是专业处理，需要警惕
  - 全部都在     → 这份文件根本没被清洗过，可直接定位到人

本模块只做"体检"，不负责分发；依赖 watermark_embed 的扫描能力。
"""

from __future__ import annotations

import re
import zipfile

from core import (css_steg, opf_steg as ost, attr_steg as ast, epub_io,
                  decoy as pdecoy)
from watermark_embed import (_collect_channels, select_candidates, scan_pool)

# ---------------------------------------------------------------- 层元数据
# key -> (所属层, 显示名, 载体说明)
LAYER_META: dict[str, tuple[str, str, str]] = {
    "zero_width":  ("内容层",   "零宽字符", "正文标点前的不可见字符"),
    "attributes":  ("内容层",   "属性引号", 'XHTML 属性用 " 还是 \''),
    "css_reorder": ("样式层",   "CSS 排列", "样式声明的排列顺序"),
    "opf_order":   ("元数据层", "OPF 顺序", "manifest / spine 条目排列"),
    "image_qim":   ("图片层",   "图片 DCT", "真彩图亮度域频域系数"),
    "palette":     ("图片层",   "调色板",   "P 模式 PNG 的 256 色表"),
    "zip_order":   ("容器层",   "ZIP 顺序", "压缩包条目的物理排列"),
}

# 各类不可见字符（含对抗方枚举的 Cf 类别里最常见的几个）
_INVIS_RE = re.compile(
    "[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u206a-\u206f\ufeff"
    "\u3164\uffa0\u115f\u1160\u2800]")

# 每层被清除时，对应对方做过的操作
_CLEAN_HINT = {
    "zero_width":  "文本清洗：剥离了全部不可见字符",
    "attributes":  "标记层归一化：属性引号被统一",
    "css_reorder": "样式表重写：自定义属性 / 声明顺序被重置",
    "opf_order":   "元数据重建：manifest / spine 被重排或重新生成",
    "image_qim":   "图片重编码或替换（对方具备信号域处理能力）",
    "palette":     "调色板被重建（pngquant / 重新量化）",
    "zip_order":   "重新打包：ZIP 容器被重建（条目顺序丢失）",
}

# 层强度排序：越靠前越难清除（用于挑"最强存活层"）
_STRENGTH = ("image_qim", "palette", "attributes", "zero_width",
             "css_reorder", "opf_order", "zip_order")


def layer_traces(epub_path: str, max_pages: int = 60) -> dict:
    """各层载体的痕迹统计——用来区分「从未嵌入」和「被清除」。"""
    t: dict = {
        "zero_width":  {"chars": 0, "pages": 0},
        "attributes":  {"single": 0, "total": 0},
        "css_reorder": {"wm_vars": 0, "blocks": 0},
        "opf_order":   {"items": 0},
        "image_qim":   {"images": 0},
        "palette":     {"images": 0},
        "zip_order":   {"entries": 0, "sorted_by_name": False},
    }

    with epub_io.EpubWork(epub_path) as work:
        for path in work.xhtml_items()[:max_pages]:
            try:
                text, _ = work.read_text(path)
            except Exception:                            # noqa: BLE001
                continue
            n = len(_INVIS_RE.findall(text))
            if n:
                t["zero_width"]["chars"] += n
                t["zero_width"]["pages"] += 1
            try:
                pos = ast._positions(text)
            except Exception:                            # noqa: BLE001
                continue
            t["attributes"]["total"] += len(pos)
            t["attributes"]["single"] += sum(
                1 for (_s, _e, q) in pos if q < len(text) and text[q] == "'")

        for path in work.css_items()[:3]:
            try:
                css, _ = work.read_text(path)
            except Exception:                            # noqa: BLE001
                continue
            t["css_reorder"]["wm_vars"] += css.count("--wm-")
            try:
                t["css_reorder"]["blocks"] += len(css_steg.parse_blocks(css))
            except Exception:                            # noqa: BLE001
                pass

        try:
            opf = work.opf_text
        except Exception:                                # noqa: BLE001
            opf = ""
        if opf:
            t["opf_order"]["items"] = len(ost.ITEM_RE.findall(opf))

        # 诱饵：用公开常量密钥检测，不需要数据库，也不依赖对方是否有密钥
        t["decoy"] = False
        for path in work.css_items()[:3]:
            try:
                css, _ = work.read_text(path)
            except Exception:                            # noqa: BLE001
                continue
            if pdecoy.detect_decoy(css):
                t["decoy"] = True
                break

        try:
            for slot in select_candidates(work, scan_pool(work)):
                if slot.mode == "P":
                    t["palette"]["images"] += 1
                else:
                    t["image_qim"]["images"] += 1
        except Exception:                                # noqa: BLE001
            pass

    try:
        with zipfile.ZipFile(epub_path) as zf:
            names = zf.namelist()
        t["zip_order"]["entries"] = len(names)
        t["zip_order"]["sorted_by_name"] = (names == sorted(names))
    except Exception:                                    # noqa: BLE001
        pass
    return t


def analyze_layers(epub_path: str, keys_list: list,
                   watermark_id: str | None = None,
                   max_pages: int = 120) -> dict:
    """逐层体检：哪几层还活着、哪几层被抹掉、对方大概做了什么。

    与 extract_watermark 的区别：后者命中一层就收工（溯源要快），
    这里把**所有层**都验一遍，并对未命中的层做痕迹统计，分四种状态：

      alive    —— 能用密钥解出，该层完好
      damaged  —— 载体还在但解不出（被部分破坏，或属于别人的水印）
      cleared  —— 别的层命中（证明出自本系统）而该层无痕迹 → 被针对性清除
      absent   —— 无痕迹，且无法确认是否嵌过

    watermark_id 已知时（数据库里有记录）判定更准：只认这一个 ID。
    """
    hits = _collect_channels(epub_path, keys_list, max_pages=max_pages,
                             stop_after_first=False)
    mine = {c: w for c, w in hits.items()
            if watermark_id is None or w == watermark_id}
    traces = layer_traces(epub_path, max_pages)
    known_source = bool(mine)          # 有任意一层命中 → 确认出自本系统

    layers: list[dict] = []
    alive: list[str] = []
    cleared: list[str] = []
    damaged: list[str] = []
    absent: list[str] = []

    for key, (group, name, carrier) in LAYER_META.items():
        tr = traces.get(key, {})
        residue = ""

        if key in mine:
            state, note = "alive", "可解出"
        else:
            has = False
            if key == "zero_width":
                n = tr.get("chars", 0)
                residue = "不可见字符 %d 个" % n
                # 正常 EPUB 里即便有零星不可见字符也就几个；成规模出现才说明
                # 是（残留的）水印 —— 低于阈值就当作源文件自带的噪声
                has = n >= 32
            elif key == "attributes":
                residue = "单引号属性 %d / %d" % (tr.get("single", 0),
                                                  tr.get("total", 0))
                # 不能用"有单引号"证明是水印：母本天然就可能混用引号
                # （实测一本 11842 个属性的书自带 86 个单引号）。
                # 引号是"0 成本可归一化"的写法，清掉了也无从考证，故不判
                # damaged，只在 trace 里给出数量供人工判断。
                has = False
            elif key == "css_reorder":
                residue = "--wm- 残留 %d 个" % tr.get("wm_vars", 0)
                has = tr.get("wm_vars", 0) > 0
            elif key == "zip_order":
                # 条目按名排序 = 被规范化重建的强证据（正常打包不会这么整齐）
                residue = ("条目按名排序（规范化迹象）"
                           if tr.get("sorted_by_name") else "条目顺序非规范")
                has = False
            elif key in ("image_qim", "palette"):
                n = tr.get("images", 0)
                residue = "候选图 %d 张" % n
                has = False
                if n == 0:
                    # 这本书没有可用的该类图 → 不是"被清除"，是"没地方嵌"。
                    # 若不区分，一本没有调色板图的书会被误报成「调色板被重建」。
                    state = "absent"
                    note = ("无可用调色板 PNG（或无此类图）" if key == "palette"
                            else "无可用真彩插图")
                    layers.append({"key": key, "group": group, "name": name,
                                   "carrier": carrier, "state": state,
                                   "note": note, "trace": residue})
                    absent.append(key)
                    continue
            elif key == "opf_order":
                if tr.get("items", 0) < 4:      # 条目太少，排列通道放不下
                    state, note = "absent", "OPF 条目过少，未承载"
                    layers.append({"key": key, "group": group, "name": name,
                                   "carrier": carrier, "state": state,
                                   "note": note, "trace": residue})
                    absent.append(key)
                    continue

            if has:
                state = "damaged"
                note = "载体尚存但解不出（%s）" % residue
            elif known_source:
                state = "cleared"
                note = "该层痕迹已消失"
                if residue and "残留 0" not in residue and "（规范化" not in residue:
                    note = "该层痕迹已消失（%s）" % residue
            else:
                state = "absent"
                note = "未检出"

        layers.append({"key": key, "group": group, "name": name,
                       "carrier": carrier, "state": state, "note": note,
                       "trace": residue})
        {"alive": alive, "cleared": cleared,
         "damaged": damaged, "absent": absent}[state].append(key)

    inferred: list[str] = []
    for key in cleared:
        if key not in _CLEAN_HINT:
            continue
        if key in ("image_qim", "palette"):
            # 图片层未命中不一定是"被重编码" —— 也可能是那几张图当时就没
            # 承载成功（过亮图 / 体积保护被跳过），措辞要留余地
            inferred.append(_CLEAN_HINT[key] + "，或该图未承载水印")
        else:
            inferred.append(_CLEAN_HINT[key])
    for key in damaged:
        inferred.append("部分破坏：" + _CLEAN_HINT.get(key, key))

    # 「本书能用几层」：没有调色板 PNG 的书永远到不了 7/7，
    # 这时候 6/7 就是满分。不说明的话用户会以为漏嵌了什么。
    applicable = [L["key"] for L in layers if L["state"] != "absent"
                  or L["key"] not in ("palette", "image_qim")]
    no_res = [L["name"] for L in layers
              if L["state"] == "absent" and L["key"] in ("palette", "image_qim")]

    if mine:
        verdict = "可溯源"
        strongest = next((k for k in _STRENGTH if k in mine), sorted(mine)[0])
        if no_res:
            summary = ("存活 %d/%d 层（本书可用 %d 层，缺：%s）"
                       " —— 已是本书上限，最强的一层是「%s」" % (
                           len(alive), len(applicable), len(applicable),
                           "、".join(no_res), LAYER_META[strongest][1]))
        else:
            summary = "存活 %d/%d 层，最强的一层是「%s」" % (
                len(alive), len(applicable), LAYER_META[strongest][1])
    else:
        verdict = "无法溯源"
        summary = "全部未命中：可能非本系统文件，或已被彻底清洗"
        strongest = ""

    # 诱饵还在吗？它用公开常量密钥写在最容易被发现的层上，
    # 所以"诱饵消失"是"被针对性清洗过"的强证据
    decoy_alive = bool(traces.get("decoy"))

    # 诱饵还在 = 这份文件根本没被清洗过。那么解不出的层只有一种解释：
    # 当时就没嵌进去（容量不足 / 该书无此资源），而不是"被破坏"。
    # 不区分这一点，会把"生成时没成功"误报成"对方清洗过"，误导判断。
    if decoy_alive and known_source:
        for L in layers:
            if L["state"] in ("cleared", "damaged"):
                L["state"] = "not_embedded"
                L["note"] = "该层未承载水印（诱饵仍在，文件未被清洗）"
        for k in list(cleared):
            cleared.remove(k)
        for k in list(damaged):
            damaged.remove(k)
        # 既然判定为"未承载"而非"被清洗"，之前的清洗推断就不成立了
        inferred = []
    if decoy_alive:
        decoy_note = "诱饵仍在 —— 这份文件没有被针对性清洗"
    elif mine:
        decoy_note = ("诱饵已被清除 —— 对方是**有备而来**（找到了显性标记并清掉），"
                      "真实身份仍在深层")
    else:
        decoy_note = "未检出诱饵（可能非本系统文件）"

    not_embedded = [L["key"] for L in layers if L["state"] == "not_embedded"]
    return {
        "layers": layers, "alive": alive, "cleared": cleared,
        "damaged": damaged, "absent": absent,
        "not_embedded": not_embedded, "applicable": applicable,
        "no_resource": no_res, "traces": traces,
        "inferred": inferred, "verdict": verdict, "summary": summary,
        "strongest": strongest, "decoy": decoy_alive, "decoy_note": decoy_note,
        "watermark_id": watermark_id or (sorted(mine.values())[0]
                                         if mine else None),
        "channel": (sorted(mine)[0] if mine else None),
    }


def format_layer_report(rep: dict) -> str:
    """把体检结果渲染成可直接打印 / 显示的文本。"""
    mark = {"alive": "[√]", "cleared": "[×]", "damaged": "[!]",
            "absent": "[-]", "not_embedded": "[○]"}
    bar = "─" * 64
    out = [bar, "  层体检：哪些还在，哪些被抹掉了", bar]
    for L in rep["layers"]:
        out.append("  %s %-7s %-9s %s" % (mark[L["state"]], L["group"],
                                          L["name"], L["note"]))
    out.append(bar)
    # summary 本身就以「存活 x/y 层…」开头，这里不要再加一次前缀（会重复打印）
    out.append("  " + rep["summary"])
    out.append("  诱饵探针：%s" % rep.get("decoy_note", "—"))

    if rep["inferred"]:
        out.append("")
        out.append("  推断对方做过的清洗操作：")
        out.extend("    · " + h for h in rep["inferred"])

    if rep["verdict"] == "可溯源":
        out.append("")
        if not rep["cleared"] and not rep["damaged"] and not rep.get(
                "not_embedded"):
            out.append("  结论：七层完好 —— 这份文件没有被清洗过。")
        elif rep.get("not_embedded"):
            out.append("  结论：未被清洗（诱饵仍在）；有层当时没嵌进去，"
                       "不影响溯源。")
        elif any(k in rep["alive"] for k in ("image_qim", "palette")):
            out.append("  结论：图片层仍存活 —— 对方只清了文本/容器，")
            out.append("        没有重编码图片（不具备信号域处理能力）。")
        else:
            out.append("  结论：仅靠脆弱层存活，建议尽快确认身份。")
    else:
        out.append("")
        out.append("  结论：无法定位。可尝试用母本重新比对图片层，")
        out.append("        或确认该文件是否出自本系统。")
    out.append(bar)
    return "\n".join(out)
