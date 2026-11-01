# -*- coding: utf-8 -*-
"""从「打标名单」网页拉取指定分组的名单，写成 generate_and_send.py 能直接用的 CSV。

用法（在 epub-watermark 目录下）：

    # 先看有哪些分组
    python pull_recipients.py --url "https://xxx.workbuddy.host/?sharecode=XXXX" --password 你的密码 --list

    # 拉某个分组
    python pull_recipients.py --url "https://xxx.workbuddy.host/?sharecode=XXXX" \
        --password 你的密码 --group "财神春花" -o recipients.csv

要点：
  · 分享链接里的 `?sharecode=...` **要一起传进来** —— 平台会先给浏览器种一个访问
    cookie，不带它直接打 /api/* 会被 403。本脚本会自动先"预热"一次。
  · 拉下来的 CSV 列：qq_number,email,note,status,group；前 4 列与
    load_recipients() 需要的完全一致，多余的列会被忽略。
  · status=banned 的行会被自动剔除（封禁的人不再发）；--only-new 只取「待发」。
"""
from __future__ import annotations

import argparse
import csv
import http.cookiejar
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

_CJ = http.cookiejar.CookieJar()

# 本机有 HTTP_PROXY 时，urllib 默认连 127.0.0.1 也走代理（会被 502 拦掉）。
# 把本机地址加进 no_proxy，本地自测与内网地址才不会莫名失败。
for _k in ("NO_PROXY", "no_proxy"):
    _hosts = os.environ.get(_k, "")
    if "127.0.0.1" not in _hosts:
        os.environ[_k] = (_hosts + "," if _hosts else "") + "127.0.0.1,localhost"

_OP = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(_CJ))


def _req(url: str, data: dict | None = None) -> bytes:
    body = json.dumps(data).encode("utf-8") if data is not None else None
    req = urllib.request.Request(url, data=body, method="POST" if data is not None else "GET")
    if body is not None:
        req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", "wm-pull/1.0")
    with _OP.open(req, timeout=30) as r:
        return r.read()


def _err_text(e: urllib.error.HTTPError) -> str:
    try:
        raw = e.read().decode("utf-8", "replace")
        return json.loads(raw).get("error") or raw[:120]
    except Exception:                                    # noqa: BLE001
        return ""


def main() -> int:
    ap = argparse.ArgumentParser(description="从打标名单网页拉取名单")
    ap.add_argument("--url", required=True,
                    help="网页地址，含 sharecode，如 https://x.workbuddy.host/?sharecode=ABC")
    ap.add_argument("--username", default="",
                    help="管理员用户名（站长不填即可；普通管理员必须填）")
    ap.add_argument("--password", required=True, help="登录密码")
    ap.add_argument("--group", default="", help="分组名（不填 = 全部）")
    ap.add_argument("--only-new", action="store_true", help="只要「待发」的")
    ap.add_argument("--list", action="store_true", help="只列分组，不写文件")
    ap.add_argument("-o", "--out", default="recipients.csv")
    a = ap.parse_args()

    u = urllib.parse.urlparse(a.url)
    if not u.scheme or not u.netloc:
        print("[×] --url 要写完整，例如 https://xxx.workbuddy.host/?sharecode=ABC")
        return 2
    base = f"{u.scheme}://{u.netloc}"

    # ① 预热：带 sharecode 访问首页，让平台种下访问 cookie
    if u.query:
        try:
            _req(f"{base}/?{u.query}")
        except Exception:                                # noqa: BLE001
            pass
    else:
        try:
            _req(base + "/")
        except Exception:                                # noqa: BLE001
            pass

    # ② 登录（普通管理员要带 --username；不填 = 站长的账号）
    try:
        _req(base + "/api/login",
             {"username": a.username.strip(), "password": a.password})
    except urllib.error.HTTPError as e:
        detail = _err_text(e)
        if e.code == 403 and not detail:
            print("[×] 被平台的访问门禁挡住了：--url 里要带上 ?sharecode=... 再试")
        elif e.code == 403:
            print(f"[×] 密码不对（HTTP 403）")
        elif e.code == 404:
            print("[×] 这个地址没有 /api/login —— 确认链接是「打标名单」那个应用")
        else:
            print(f"[×] 登录失败（HTTP {e.code}）{detail}")
        return 2
    except Exception as exc:                             # noqa: BLE001
        print(f"[×] 连不上：{exc}")
        return 2

    st = json.loads(_req(base + "/api/state").decode("utf-8"))
    groups = st.get("groups") or []
    recs = st.get("recipients") or []

    if a.list:
        print(f"共 {len(recs)} 人，{len(groups)} 个分组：")
        print(f"  （未分组） {sum(1 for r in recs if r.get('group_id') in (None, ''))} 人")
        for g in groups:
            n = sum(1 for r in recs if str(r.get("group_id")) == str(g["id"]))
            print(f"  {g['name']}  (id={g['id']}) {n} 人")
        return 0

    gid = None
    if a.group:
        hit = [g for g in groups if g["name"].strip() == a.group.strip()]
        if not hit:
            hit = [g for g in groups if a.group.strip() in g["name"]]
        if not hit:
            print(f"[×] 找不到分组「{a.group}」；现有：{[g['name'] for g in groups]}")
            return 2
        if len(hit) > 1:
            print(f"[×] 分组名不唯一，请写全：{[g['name'] for g in hit]}")
            return 2
        gid = hit[0]["id"]

    rows = [r for r in recs
            if (gid is None or str(r.get("group_id")) == str(gid))
            and r.get("status") != "banned"
            and (not a.only_new or r.get("status") == "new")]

    gmap = {str(g["id"]): g["name"] for g in groups}
    out = os.path.abspath(a.out)
    with open(out, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(["qq_number", "email", "note", "status", "group"])
        for r in rows:
            w.writerow([r.get("qq", ""), r.get("email", ""), r.get("note", ""),
                        r.get("status", ""), gmap.get(str(r.get("group_id")), "")])

    banned = sum(1 for r in recs if r.get("status") == "banned")
    if not rows:
        print("[!] 这个分组里没有可发的人（可能全被封禁，或者还没加人）")
    print(f"[√] 已写出 {len(rows)} 人 → {out}")
    print(f"    分组：{a.group or '全部'}｜已剔除封禁 {banned} 人｜{os.path.getsize(out)} 字节")
    print(f"    下一步：python generate_and_send.py --epub 母本.epub --csv {a.out} "
          f"--title \"书名\" --dry-run")
    return 0


if __name__ == "__main__":
    sys.exit(main())
