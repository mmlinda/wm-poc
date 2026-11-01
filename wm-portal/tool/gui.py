# -*- coding: utf-8 -*-
"""EPUB 水印分发 · 桌面 GUI（tkinter，零第三方依赖）。

启动：
    python gui.py            # 需要用带 tkinter 的 Python（官方安装版自带）
    或双击  启动GUI.bat

四个标签页：分发 / 溯源 / 记录 / 设置。
"""
from __future__ import annotations

import os
import sys

os.environ.setdefault("WM_GUI", "1")
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

import queue
import secrets
import shutil
import threading
import tkinter as tk
import webbrowser
from datetime import datetime
from tkinter import filedialog, messagebox, scrolledtext, ttk

import config
import crypto_utils
import db
import generate_and_send
import layer_report
import send_email
import watermark_embed

FONT = ("Microsoft YaHei", 10)
FONT_B = ("Microsoft YaHei", 10, "bold")
FONT_TITLE = ("Microsoft YaHei", 12, "bold")
MONO = ("Consolas", 9)


def reload_config() -> None:
    """设置页保存后重新加载各模块，使新配置立即生效。"""
    import importlib
    for m in (config, crypto_utils, db, watermark_embed, send_email,
              generate_and_send):
        importlib.reload(m)


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.q: queue.Queue = queue.Queue()
        self.stop_event = threading.Event()
        self.worker: threading.Thread | None = None
        self.sel_wm = ""

        root.title("EPUB 水印分发与溯源 · 管理端")
        root.geometry("980x680")
        root.minsize(900, 620)

        nb = ttk.Notebook(root)
        nb.pack(fill="both", expand=True, padx=8, pady=8)

        self.tab_send = ttk.Frame(nb)
        self.tab_trace = ttk.Frame(nb)
        self.tab_records = ttk.Frame(nb)
        self.tab_settings = ttk.Frame(nb)
        nb.add(self.tab_send, text="  分发  ")
        nb.add(self.tab_trace, text="  溯源  ")
        nb.add(self.tab_records, text="  记录  ")
        nb.add(self.tab_settings, text="  设置  ")

        self._build_send()
        self._build_trace()
        self._build_records()
        self._build_settings()

        # 状态栏
        bar = ttk.Frame(root)
        bar.pack(fill="x", side="bottom")
        self.status = tk.StringVar(value="就绪")
        ttk.Label(bar, textvariable=self.status, anchor="w",
                  font=("Microsoft YaHei", 9)).pack(fill="x", padx=10, pady=4)

        root.after(120, self._drain)
        root.after(300, self._refresh_status)

    # ------------------------------------------------------------ 工具
    def log(self, text: str) -> None:
        self.txt_log.insert("end", text + "\n")
        self.txt_log.see("end")

    def set_status(self, text: str) -> None:
        self.status.set(text)

    def _start_progress(self) -> None:
        # 必须先把残留值清零并切回 determinate 再进滚动模式：
        # 上一轮结束时 value 停在最大，残留值会让新一轮一开始就闪一下满格
        self._prog_determinate = False
        self.progress.stop()
        self.progress.configure(mode="determinate", value=0, maximum=100)
        self.progress.configure(mode="indeterminate")
        self.progress.start(12)

    def _finish_progress(self) -> None:
        try:
            self.progress.stop()
        except Exception:                                # noqa: BLE001
            pass
        if not getattr(self, "_prog_determinate", False):
            self.progress.configure(mode="determinate")
            self._prog_determinate = True

    def _set_progress(self, i: int, n: int) -> None:
        """只在第一次收到进度时切换模式，之后只更新数值（反复 configure 会闪）。"""
        if not getattr(self, "_prog_determinate", False):
            self.progress.stop()
            self.progress.configure(mode="determinate")
            self._prog_determinate = True
        self.progress["maximum"] = max(n, 1)
        self.progress["value"] = min(i, max(n, 1))

    def _drain(self) -> None:
        """把子线程事件搬到主线程处理。"""
        try:
            while True:
                kind, payload = self.q.get_nowait()
                if kind == "log":
                    self.log(payload)
                elif kind == "progress":
                    i, n = payload
                    self._set_progress(i, n)
                    self.set_status(f"处理中 {i}/{n}")
                elif kind == "done":
                    self._finish_progress()
                    self.btn_start["state"] = "normal"
                    self.btn_stop["state"] = "disabled"
                    st = payload.get("stats", {})
                    self.set_status(
                        f"完成：成功 {payload.get('sent')}、失败 {payload.get('failed')}、"
                        f"跳过 {payload.get('skipped')}；库内共 {st.get('total')} 条")
                    self.load_records()
                elif kind == "error":
                    self._finish_progress()
                    messagebox.showerror("出错", payload)
                    self.set_status("出错：" + payload.splitlines()[0][:60])
                elif kind == "layers":
                    self._show_layers(payload)
                elif kind == "trace_step":
                    self.trace_msg.set(payload)
                elif kind == "trace":
                    self._show_trace(payload)
                elif kind == "records":
                    self._fill_records(payload)
        except queue.Empty:
            pass
        self.root.after(120, self._drain)

    # 每类文件各自记住上次打开的目录：母本在电子书目录、名单在表格目录、
    # 待溯源的文件在 out/，混用一个会来回跳（体验很差）
    _last_dir: dict[str, str] = {}

    def _pick(self, var, title, filetypes, tag: str = ""):
        initial = self._last_dir.get(tag) or ""
        if not initial:
            cur = var.get().strip()
            if cur and os.path.isdir(os.path.dirname(cur)):
                initial = os.path.dirname(cur)
            elif tag == "trace" and os.path.isdir(config.OUTPUT_DIR):
                initial = config.OUTPUT_DIR
        path = filedialog.askopenfilename(title=title, filetypes=filetypes,
                                          initialdir=initial or None)
        if path:
            var.set(path)
            if tag:
                self._last_dir[tag] = os.path.dirname(path)

    def _pick_save(self, var, title, defaultextension, filetypes, tag: str = ""):
        """另存为（导出 CSV 等）。"""
        initial = self._last_dir.get(tag) or ""
        path = filedialog.asksaveasfilename(
            title=title, defaultextension=defaultextension,
            filetypes=filetypes, initialdir=initial or None)
        if path:
            var.set(path)
            if tag:
                self._last_dir[tag] = os.path.dirname(path)
        return path

    def _row(self, parent, r, label, widget, **kw):
        ttk.Label(parent, text=label, font=FONT).grid(row=r, column=0, sticky="w",
                                                      padx=(0, 8), pady=4)
        widget.grid(row=r, column=1, columnspan=kw.pop("span", 1), sticky="ew",
                    padx=(0, 6), pady=4)
        return widget

    # ------------------------------------------------------------ 分发页
    def _build_send(self) -> None:
        f = ttk.Frame(self.tab_send, padding=12)
        f.pack(fill="both", expand=True)
        f.columnconfigure(1, weight=1)

        self.v_epub = tk.StringVar()
        self.v_title = tk.StringVar()
        self.v_csv = tk.StringVar(value=os.path.join(BASE_DIR, "recipients.csv"))
        self.v_dry = tk.BooleanVar(value=True)
        self.v_resume = tk.BooleanVar(value=False)
        self.v_limit = tk.StringVar(value="0")
        self.v_backend = tk.StringVar(value="auto")

        self._row(f, 0, "母本 EPUB",
                  ttk.Entry(f, textvariable=self.v_epub, font=FONT))
        ttk.Button(f, text="浏览", command=lambda: self._pick(
            self.v_epub, "选择无水印母本", [("EPUB", "*.epub")],
            tag="mother")).grid(
            row=0, column=2, padx=4)
        self._row(f, 1, "书名", ttk.Entry(f, textvariable=self.v_title, font=FONT))
        self._row(f, 2, "收件人 CSV",
                  ttk.Entry(f, textvariable=self.v_csv, font=FONT))
        ttk.Button(f, text="浏览", command=lambda: self._pick(
            self.v_csv, "选择收件人 CSV", [("CSV", "*.csv")],
            tag="csv")).grid(
            row=2, column=2, padx=4)
        ttk.Button(f, text="从表单转换", command=self._convert).grid(
            row=2, column=3, padx=4)

        opts = ttk.Frame(f)
        opts.grid(row=3, column=0, columnspan=4, sticky="w", pady=8)
        ttk.Checkbutton(opts, text="试运行（只生成不发送）", variable=self.v_dry,
                        command=self._toggle_dry).pack(side="left", padx=(0, 14))
        ttk.Checkbutton(opts, text="续跑（重发已发送者）",
                        variable=self.v_resume).pack(side="left", padx=(0, 14))
        ttk.Label(opts, text="数量上限", font=FONT).pack(side="left")
        ttk.Entry(opts, textvariable=self.v_limit, width=6, font=FONT).pack(
            side="left", padx=(4, 14))
        ttk.Label(opts, text="发信方式", font=FONT).pack(side="left")
        ttk.Combobox(opts, textvariable=self.v_backend, width=8, state="readonly",
                     values=["auto", "resend", "smtp"]).pack(side="left", padx=(4, 0))

        btns = ttk.Frame(f)
        btns.grid(row=4, column=0, columnspan=4, sticky="w", pady=4)
        self.btn_start = ttk.Button(btns, text="开始分发", command=self.start_send)
        self.btn_start.pack(side="left", padx=(0, 8))
        self.btn_stop = ttk.Button(btns, text="停止", command=self.stop_send,
                                   state="disabled")
        self.btn_stop.pack(side="left", padx=(0, 8))
        ttk.Button(btns, text="打开输出目录",
                   command=lambda: self._open_dir(config.OUTPUT_DIR)).pack(side="left")

        self.progress = ttk.Progressbar(f, mode="determinate")
        self.progress.grid(row=5, column=0, columnspan=4, sticky="ew", pady=6)

        ttk.Label(f, text="运行日志", font=FONT_B).grid(row=6, column=0,
                                                        sticky="w", pady=(6, 2))
        self.txt_log = scrolledtext.ScrolledText(f, height=16, font=MONO,
                                                 wrap="word")
        self.txt_log.grid(row=7, column=0, columnspan=4, sticky="nsew")
        f.rowconfigure(7, weight=1)

        if os.path.isfile(os.path.join(BASE_DIR, "mother.epub")):
            self.v_epub.set(os.path.join(BASE_DIR, "mother.epub"))

    def _toggle_dry(self) -> None:
        if not self.v_dry.get():
            if not (config.RESEND_API_KEY or config.SMTP_PASS):
                messagebox.showwarning(
                    "未配置发信", "取消「试运行」前请先到【设置】页填写 Resend 或 SMTP "
                    "配置，否则会全部发送失败。")

    def _open_dir(self, path: str) -> None:
        if not os.path.isdir(path):
            os.makedirs(path, exist_ok=True)
        try:
            os.startfile(path)          # noqa: S606 - Windows only
        except Exception:               # noqa: BLE001
            webbrowser.open("file:///" + path.replace("\\", "/"))

    def _convert(self) -> None:
        src = filedialog.askopenfilename(title="选择表单导出的 CSV",
                                         filetypes=[("CSV", "*.csv")])
        if not src:
            return
        dst = os.path.join(BASE_DIR, "recipients.csv")
        try:
            from convert_form import convert
            res = convert(src, dst, config.POLICY_VERSION, strict=True)
            self.v_csv.set(dst)
            messagebox.showinfo("完成", f"已转换 {res['ok']} 个收件人 →\n{dst}")
        except SystemExit as exc:
            messagebox.showerror("失败", str(exc))

    def start_send(self) -> None:
        if not self.v_epub.get() or not os.path.isfile(self.v_epub.get()):
            messagebox.showerror("缺少母本", "请选择母本 EPUB 文件")
            return
        if not self.v_title.get().strip():
            messagebox.showerror("缺少书名", "请填写书名")
            return
        if not os.path.isfile(self.v_csv.get()):
            messagebox.showerror("缺少名单", "请选择收件人 CSV（可先从表单转换）")
            return
        if not (config.SERVER_SECRET and config.DB_KEY):
            messagebox.showerror("未配置密钥",
                                 "请先在【设置】页生成并保存 SERVER_SECRET / DB_KEY")
            return
        try:
            limit = int(self.v_limit.get() or 0)
        except ValueError:
            limit = 0

        self.stop_event.clear()
        self.btn_start["state"] = "disabled"
        self.btn_stop["state"] = "normal"
        self._start_progress()
        self.txt_log.delete("1.0", "end")
        self.set_status("开始生成…")

        args = (self.v_epub.get(), self.v_csv.get(), self.v_title.get().strip(),
                self.v_resume.get(), self.v_dry.get(), limit,
                self.v_backend.get(), "")

        def work():
            try:
                generate_and_send.run_batch(
                    *args,
                    on_event=lambda k, p: self.q.put((k, p)),
                    should_stop=lambda: self.stop_event.is_set())
            except Exception as exc:                      # noqa: BLE001
                import traceback
                self.q.put(("log", f"[×] 运行异常：{exc}"))
                self.q.put(("log", traceback.format_exc()[-800:]))
                self.q.put(("done", {"sent": 0, "failed": 0, "skipped": 0,
                                     "stats": {}}))

        self.worker = threading.Thread(target=work, daemon=True)
        self.worker.start()

    def stop_send(self) -> None:
        self.stop_event.set()
        self.btn_stop["state"] = "disabled"
        self.set_status("正在停止（处理完当前收件人后停下）…")

    # ------------------------------------------------------------ 溯源页
    def _build_trace(self) -> None:
        f = ttk.Frame(self.tab_trace, padding=12)
        f.pack(fill="both", expand=True)
        f.columnconfigure(1, weight=1)

        self.v_file = tk.StringVar()
        self.v_note = tk.StringVar()
        self._row(f, 0, "可疑 EPUB",
                  ttk.Entry(f, textvariable=self.v_file, font=FONT))
        ttk.Button(f, text="浏览", command=lambda: self._pick(
            self.v_file, "选择可疑 EPUB", [("EPUB", "*.epub")],
            tag="trace")).grid(row=0, column=2)
        self._row(f, 1, "发现渠道备注",
                  ttk.Entry(f, textvariable=self.v_note, font=FONT))
        ttk.Button(f, text="开始解码", command=self.start_trace).grid(
            row=2, column=0, sticky="w", pady=10)

        box = ttk.LabelFrame(f, text="解码结果", padding=10)
        box.grid(row=3, column=0, columnspan=3, sticky="ew")
        box.columnconfigure(1, weight=1)
        self.t_wm = tk.StringVar(value="—")
        self.t_ch = tk.StringVar(value="—")
        self.t_qq = tk.StringVar(value="—")
        self.t_mail = tk.StringVar(value="—")
        self.t_time = tk.StringVar(value="—")
        self.t_state = tk.StringVar(value="—")
        for i, (lab, var) in enumerate([
                ("水印 ID", self.t_wm), ("命中通道", self.t_ch),
                ("QQ 号", self.t_qq), ("邮箱", self.t_mail),
                ("发送时间", self.t_time), ("状态", self.t_state)]):
            ttk.Label(box, text=lab + "：", font=FONT_B).grid(
                row=i, column=0, sticky="w", pady=2)
            ttk.Label(box, textvariable=var, font=MONO).grid(
                row=i, column=1, sticky="w", pady=2)

        ttk.Button(f, text="封禁该账号", command=self.revoke_current).grid(
            row=4, column=0, sticky="w", pady=10)

        # 层体检：哪几层还活着 / 被抹掉了 / 对方大概做了什么
        lb = ttk.LabelFrame(f, text="层体检（哪些还在，哪些被抹掉了）", padding=10)
        lb.grid(row=5, column=0, columnspan=3, sticky="ew")
        lb.columnconfigure(1, weight=1)
        self.layer_rows: dict[str, tk.StringVar] = {}
        for i, (key, (_g, name, carrier)) in enumerate(
                layer_report.LAYER_META.items()):
            ttk.Label(lb, text=name, font=FONT_B).grid(
                row=i, column=0, sticky="w", pady=1)
            var = tk.StringVar(value="—")
            self.layer_rows[key] = var
            mark = ttk.Label(lb, textvariable=var, font=MONO, width=46)
            mark.grid(row=i, column=1, sticky="w", pady=1)
            if carrier:
                ttk.Label(lb, text=carrier, font=FONT,
                          foreground="#6b7280").grid(
                    row=i, column=2, sticky="w", pady=1, padx=(10, 0))

        self.trace_msg = tk.StringVar(value="")
        ttk.Label(f, textvariable=self.trace_msg, font=FONT,
                  foreground="#2563eb", wraplength=760, justify="left").grid(
            row=6, column=0, columnspan=3, sticky="w")

    def start_trace(self) -> None:
        path = self.v_file.get().strip()
        if not path or not os.path.isfile(path):
            messagebox.showerror("文件不存在", "请选择可疑 EPUB 文件")
            return
        if not (config.SERVER_SECRET and config.DB_KEY):
            messagebox.showerror("未配置密钥", "请先在【设置】页配置密钥")
            return
        self.trace_msg.set("正在解码（最多扫描 8 个正文页 + CSS + 封面）…")
        self.set_status("解码中…")

        def work():
            try:
                conn = db.connect(config.DB_PATH)
                keys_list = db.all_keys(conn)
                self.q.put(("trace_step",
                            f"载入 {len(keys_list)} 组候选密钥，开始解码…"))
                wm_id, channel = watermark_embed.extract_watermark(
                    path, keys_list=keys_list,
                    on_step=lambda m: self.q.put(("trace_step", m)))
                rec = db.find_by_watermark(conn, wm_id) if wm_id else None

                # 层体检：告诉用户这份文件被清洗到什么程度。
                # 定位到具体水印后只用这一条的密钥 —— 全量密钥随分发人数
                # 线性增长，逐层尝试会把体检拖到十几秒。
                self.q.put(("trace_step", "正在做层体检（逐层验证存活情况）…"))
                lr_keys = (db.keys_for_watermark(conn, wm_id) if wm_id
                           else keys_list)
                rep = layer_report.analyze_layers(path, lr_keys,
                                                  watermark_id=wm_id)
                self.q.put(("layers", rep))

                if wm_id:
                    conn.execute(
                        "INSERT INTO trace_logs (watermark_id, qq_number, channel,"
                        " source_note, layers_alive, layers_cleared, clean_ops)"
                        " VALUES (?,?,?,?,?,?,?)",
                        (wm_id, db.enc((rec or {}).get("qq_number", "")),
                         channel or "", self.v_note.get(),
                         ",".join(rep["alive"]),
                         ",".join(rep["cleared"]),
                         "; ".join(rep["inferred"])))
                    conn.commit()
                conn.close()
                self.q.put(("trace", {"wm_id": wm_id, "channel": channel,
                                      "rec": rec, "layers": rep}))
            except Exception as exc:                     # noqa: BLE001
                import traceback
                self.q.put(("error", f"溯源失败：{exc}\n\n{traceback.format_exc()[-600:]}"))

        threading.Thread(target=work, daemon=True).start()

    def _show_layers(self, rep: dict) -> None:
        """把层体检结果填到溯源页的表格里。"""
        mark = {"alive": "√ 存活", "cleared": "× 被清除",
                "damaged": "! 载体尚存但解不出", "absent": "- 未检出",
                "not_embedded": "○ 未承载"}
        for L in rep["layers"]:
            var = self.layer_rows.get(L["key"])
            if var is not None:
                var.set("%-18s %s" % (mark.get(L["state"], L["state"]),
                                      L["note"]))

    def _show_trace(self, data: dict) -> None:
        wm_id, channel, rec = data["wm_id"], data["channel"], data["rec"]
        rep = data.get("layers")
        if rep:
            self._show_layers(rep)
            if rep["inferred"]:
                self.layer_note = "；".join(rep["inferred"])
        if not wm_id:
            self.t_wm.set("未命中")
            self.t_ch.set("—")
            self.t_qq.set("—")
            self.t_mail.set("—")
            self.t_time.set("—")
            self.t_state.set("—")
            hint = ""
            if rep:
                if rep["cleared"] or rep["damaged"]:
                    hint = ("层体检显示有被抹掉的痕迹：" +
                            "；".join(rep["inferred"][:2]))
                else:
                    hint = "层体检未发现本系统痕迹，很可能不是本系统生成的文件。"
            self.trace_msg.set("七层均未解出：文件可能不是本系统生成的，"
                               "或水印已被彻底清除。" + hint)
            self.set_status("解码完成：未命中")
            return
        self.sel_wm = wm_id
        self.t_wm.set(wm_id)
        self.t_ch.set(channel or "—")
        self.t_qq.set((rec or {}).get("qq_number") or "（无映射记录）")
        self.t_mail.set((rec or {}).get("email") or "—")
        self.t_time.set(((rec or {}).get("sent_at") or "")[:19] or "—")
        self.t_state.set((rec or {}).get("status") or "—")
        extra = ""
        if rep:
            extra = (" 层体检：存活 %d/7，" % len(rep["alive"]))
            if rep["cleared"] or rep["damaged"]:
                extra += "有被清洗痕迹 —— " + "；".join(rep["inferred"][:2])
            else:
                extra += "未见清洗痕迹（这份文件应是被直接转发的）。"
        self.trace_msg.set("已记录溯源日志。确认外传后点击【封禁该账号】。"
                           + extra)
        self.set_status(f"解码完成：{wm_id}")

    def revoke_current(self) -> None:
        if not self.sel_wm:
            messagebox.showinfo("提示", "请先解码出一个水印 ID")
            return
        self._revoke(self.sel_wm)

    def _revoke(self, wm_id: str, confirm: bool = True,
                refresh: bool = True) -> bool:
        """封禁一条记录。批量调用时关掉 confirm/refresh，避免弹窗刷屏。"""
        conn = db.connect(config.DB_PATH)
        rec = db.find_by_watermark(conn, wm_id)
        if not rec:
            conn.close()
            if confirm:
                messagebox.showinfo("提示", "该水印没有映射记录")
            return False
        if confirm and not messagebox.askyesno(
                "确认封禁",
                "将封禁该领取记录：\n\n水印 ID：" + wm_id +
                "\nQQ：" + str(rec["qq_number"]) +
                "\n\n之后该 QQ 不会再收到本书。继续？"):
            conn.close()
            return False
        conn.execute("UPDATE distributions SET status='revoked' WHERE watermark_id=?",
                     (wm_id,))
        conn.execute("INSERT INTO trace_logs (watermark_id, qq_number, channel,"
                     " source_note) VALUES (?,?,?,?)",
                     (wm_id, db.enc(rec["qq_number"]), "gui", "后台封禁"))
        conn.commit()
        conn.close()
        if confirm:
            messagebox.showinfo("已封禁", f"{wm_id} 已标记为 revoked")
        if refresh:
            self.load_records()
        return True

    # ------------------------------------------------------------ 记录页
    def _build_records(self) -> None:
        f = ttk.Frame(self.tab_records, padding=12)
        f.pack(fill="both", expand=True)
        f.columnconfigure(0, weight=1)
        f.rowconfigure(1, weight=1)

        top = ttk.Frame(f)
        top.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        self.v_search = tk.StringVar()
        self.v_state = tk.StringVar(value="")
        ttk.Entry(top, textvariable=self.v_search, width=28, font=FONT).pack(
            side="left", padx=(0, 8))
        ttk.Combobox(top, textvariable=self.v_state, width=10, state="readonly",
                     values=["", "sent", "failed", "revoked", "pending"]).pack(
            side="left", padx=(0, 8))
        ttk.Button(top, text="搜索", command=self.load_records).pack(side="left")
        ttk.Button(top, text="刷新", command=self.load_records).pack(
            side="left", padx=6)
        ttk.Button(top, text="导出 CSV（脱敏）", command=self.export_csv).pack(
            side="left", padx=6)

        cols = ("watermark_id", "qq", "email", "status", "channels", "psnr", "time")
        # EXTENDED：支持 Ctrl/Shift 多选，批量封禁 / 批量删除才可能
        self.tree = ttk.Treeview(f, columns=cols, show="headings", height=18,
                                 selectmode="extended")
        heads = {"watermark_id": "水印 ID", "qq": "QQ", "email": "邮箱",
                 "status": "状态", "channels": "通道", "psnr": "PSNR", "time": "时间"}
        widths = {"watermark_id": 190, "qq": 110, "email": 170, "status": 70,
                  "channels": 110, "psnr": 60, "time": 130}
        for c in cols:
            self.tree.heading(c, text=heads[c])
            self.tree.column(c, width=widths[c], anchor="w")
        self.tree.grid(row=1, column=0, sticky="nsew")
        sb = ttk.Scrollbar(f, orient="vertical", command=self.tree.yview)
        sb.grid(row=1, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=sb.set)

        bottom = ttk.Frame(f)
        bottom.grid(row=2, column=0, sticky="w", pady=8)
        ttk.Button(bottom, text="封禁选中", command=self.revoke_selected).pack(
            side="left", padx=(0, 8))
        ttk.Button(bottom, text="解除封禁",
                   command=lambda: self.unrevoke_selected()).pack(side="left", padx=(0, 8))
        ttk.Button(bottom, text="删除选中记录",
                   command=self.delete_selected).pack(side="left", padx=(0, 8))
        ttk.Button(bottom, text="全选", command=self.select_all).pack(
            side="left", padx=(0, 8))
        ttk.Button(bottom, text="清空全部记录", command=self.delete_all).pack(
            side="left")
        ttk.Label(bottom, text="（Ctrl/Shift 多选；按住 Ctrl 点已选行可取消）",
                  font=("Microsoft YaHei", 9), foreground="#6b7280").pack(
            side="left", padx=(12, 0))

    def load_records(self) -> None:
        def work():
            conn = db.connect(config.DB_PATH)
            q = self.v_search.get().strip()
            st = self.v_state.get().strip()
            where, args = [], []
            if st:
                where.append("status=?"); args.append(st)
            if q:
                like = "%" + q + "%"
                # QQ/邮箱按**确定性检索列**匹配（field 加密模式下 enc() 带随机 IV，
                # 用它做等值查询永远命中不到）
                where.append("(watermark_id LIKE ? OR qq_hash=? OR email_hash=?)")
                args += [like, db.lookup_hash(q), db.lookup_hash(q)]
            sql = "SELECT * FROM distributions"
            if where:
                sql += " WHERE " + " AND ".join(where)
            sql += " ORDER BY id DESC LIMIT 300"
            rows = [dict(r) for r in conn.execute(sql, args).fetchall()]
            for r in rows:
                r["qq_number"] = db.dec(r["qq_number"])
                r["email"] = db.dec(r["email"])
            conn.close()
            self.q.put(("records", rows))

        def safe():
            try:
                work()
            except Exception as exc:                     # noqa: BLE001
                self.q.put(("error", f"读取记录失败：{exc}"))

        threading.Thread(target=safe, daemon=True).start()

    def _fill_records(self, rows) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)
        for r in rows:
            ch = []
            if r.get("zero_width_ok"):
                ch.append("零宽")
            if r.get("css_ok"):
                ch.append("CSS")
            if r.get("image_qim_ok"):
                ch.append("图片")
            self.tree.insert("", "end", values=(
                r["watermark_id"], r["qq_number"], r["email"], r["status"],
                "/".join(ch) or "—", round(r.get("psnr") or 0, 1),
                (r.get("sent_at") or r.get("created_at") or "")[:16]))
        self.set_status(f"记录 {len(rows)} 条")

    def _selected_wm(self) -> str:
        """单选场景（兼容旧调用）。"""
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("提示", "请先在表格中选中一行")
            return ""
        return self.tree.item(sel[0])["values"][0]

    def _selected_wm_list(self) -> list[str]:
        """当前所有选中行的水印 ID（支持 Ctrl/Shift 多选）。"""
        return [self.tree.item(i)["values"][0]
                for i in self.tree.selection()
                if self.tree.item(i)["values"]]

    def select_all(self) -> None:
        items = self.tree.get_children()
        if items:
            self.tree.selection_set(items)
            self.set_status(f"已选中 {len(items)} 条")

    def revoke_selected(self) -> None:
        wms = self._selected_wm_list()
        if not wms:
            messagebox.showinfo("提示", "请先在表格中选中一行（可 Ctrl/Shift 多选）")
            return
        if len(wms) > 1 and not messagebox.askyesno(
                "确认批量封禁",
                f"将封禁选中的 {len(wms)} 条记录，这些 QQ 之后不会再收到本书。\n\n"
                + "\n".join(wms[:8]) + ("\n…" if len(wms) > 8 else "")):
            return
        for wm in wms:
            self._revoke(wm, confirm=len(wms) == 1, refresh=False)
        self.load_records()
        self.set_status(f"已封禁 {len(wms)} 条")

    def unrevoke_selected(self) -> None:
        wms = self._selected_wm_list()
        if not wms:
            messagebox.showinfo("提示", "请先在表格中选中一行（可 Ctrl/Shift 多选）")
            return
        conn = db.connect(config.DB_PATH)
        for wm in wms:
            conn.execute("UPDATE distributions SET status='sent' WHERE watermark_id=?",
                         (wm,))
        conn.commit()
        conn.close()
        self.load_records()
        self.set_status(f"已解除 {len(wms)} 条")

    def delete_selected(self) -> None:
        wms = self._selected_wm_list()
        if not wms:
            messagebox.showinfo("提示", "请先在表格中选中一行（可 Ctrl/Shift 多选）")
            return
        tip = ("将永久删除选中的 %d 条领取记录（删除后无法再溯源）：\n" % len(wms)
               + "\n".join(wms[:8]) + ("\n…" if len(wms) > 8 else ""))
        if not messagebox.askyesno("确认删除", tip):
            return
        conn = db.connect(config.DB_PATH)
        for wm in wms:
            conn.execute("DELETE FROM distributions WHERE watermark_id=?", (wm,))
        conn.commit()
        conn.close()
        self.load_records()
        self.set_status(f"已删除 {len(wms)} 条")

    def delete_all(self) -> None:
        """清空整库（换一批人重新分发前用）。"""
        conn = db.connect(config.DB_PATH)
        n = conn.execute("SELECT COUNT(*) c FROM distributions").fetchone()["c"]
        conn.close()
        if not n:
            messagebox.showinfo("提示", "库里没有记录")
            return
        if not messagebox.askyesno(
                "确认清空",
                f"将永久删除库内全部 {n} 条记录，且**这些副本从此无法再溯源**。\n\n"
                "仅建议在换一批人重新分发、且旧副本已作废时使用。\n"
                "继续吗？"):
            return
        if not messagebox.askyesno("二次确认", f"真的要删除全部 {n} 条吗？此操作不可撤销。"):
            return
        db.backup(config.DB_PATH)          # 清空前先留一份，万一删错还能找回
        conn = db.connect(config.DB_PATH)
        conn.execute("DELETE FROM distributions")
        conn.execute("DELETE FROM trace_logs")
        conn.commit()
        conn.close()
        self.load_records()
        self.set_status(f"已清空 {n} 条（清空前已自动备份，可在 backups/ 找回）")

    def export_csv(self) -> None:
        path = filedialog.asksaveasfilename(
            title="导出 CSV", defaultextension=".csv",
            initialfile="distributions-%s.csv" % datetime.now().strftime("%Y%m%d"),
            filetypes=[("CSV", "*.csv")])
        if not path:
            return
        import csv as _csv
        conn = db.connect(config.DB_PATH)
        rows = conn.execute("SELECT * FROM distributions ORDER BY id DESC").fetchall()
        conn.close()
        with open(path, "w", encoding="utf-8-sig", newline="") as f:
            w = _csv.writer(f)
            w.writerow(["watermark_id", "qq", "email", "status", "batch_id",
                        "zero_width_ok", "css_ok", "image_qim_ok", "psnr", "sent_at"])
            for r in rows:
                qq = db.dec(r["qq_number"])
                em = db.dec(r["email"])
                qq = qq[:3] + "*" * max(0, len(qq) - 3) if qq else ""
                name, _, dom = em.partition("@")
                em = (name[:2] + "*" * max(0, len(name) - 2) + "@" + dom) if em else ""
                w.writerow([r["watermark_id"], qq, em, r["status"], r["batch_id"],
                            r["zero_width_ok"], r["css_ok"], r["image_qim_ok"],
                            r["psnr"], r["sent_at"]])
        messagebox.showinfo("已导出", path)

    # ------------------------------------------------------------ 设置页
    def _build_settings(self) -> None:
        f = ttk.Frame(self.tab_settings, padding=12)
        f.pack(fill="both", expand=True)
        f.columnconfigure(1, weight=1)

        ttk.Label(f, text="密钥（务必保密，丢失后无法解码已有水印）",
                  font=FONT_TITLE).grid(row=0, column=0, columnspan=3,
                                        sticky="w", pady=(0, 6))
        self.s_secret = tk.StringVar(value=config.SERVER_SECRET)
        self.s_dbkey = tk.StringVar(value=config.DB_KEY)
        self._row(f, 1, "SERVER_SECRET",
                  ttk.Entry(f, textvariable=self.s_secret, font=MONO, width=48))
        ttk.Button(f, text="生成", command=lambda: self.s_secret.set(
            secrets.token_hex(32))).grid(row=1, column=2)
        self._row(f, 2, "DB_KEY",
                  ttk.Entry(f, textvariable=self.s_dbkey, font=MONO, width=48))
        ttk.Button(f, text="生成", command=lambda: self.s_dbkey.set(
            secrets.token_hex(32))).grid(row=2, column=2)

        ttk.Label(f, text="发信配置（Resend 或 SMTP 二选一）",
                  font=FONT_TITLE).grid(row=3, column=0, columnspan=3,
                                        sticky="w", pady=(14, 6))
        self.s_resend = tk.StringVar(value=config.RESEND_API_KEY)
        self.s_from = tk.StringVar(value=config.RESEND_FROM_EMAIL)
        self.s_host = tk.StringVar(value=config.SMTP_HOST)
        self.s_port = tk.StringVar(value=str(config.SMTP_PORT))
        self.s_user = tk.StringVar(value=config.SMTP_USER)
        self.s_pass = tk.StringVar(value=config.SMTP_PASS)
        for i, (lab, var, show) in enumerate([
                ("RESEND_API_KEY", self.s_resend, ""),
                ("RESEND_FROM_EMAIL", self.s_from, ""),
                ("SMTP_HOST", self.s_host, ""),
                ("SMTP_PORT", self.s_port, ""),
                ("SMTP_USER", self.s_user, ""),
                ("SMTP_PASS", self.s_pass, "*")]):
            self._row(f, 4 + i, lab,
                      ttk.Entry(f, textvariable=var, font=MONO, width=48,
                                show=show))

        ttk.Label(f, text="其他", font=FONT_TITLE).grid(
            row=10, column=0, columnspan=3, sticky="w", pady=(14, 6))
        self.s_policy = tk.StringVar(value=config.POLICY_VERSION)
        self.s_interval = tk.StringVar(value=str(config.SEND_INTERVAL))
        self.s_images = tk.StringVar(value=str(config.MAX_IMAGES))
        self._row(f, 11, "条款版本", ttk.Entry(f, textvariable=self.s_policy,
                                               font=FONT, width=20))
        self._row(f, 12, "发送间隔（秒）", ttk.Entry(f, textvariable=self.s_interval,
                                                     font=FONT, width=20))
        self._row(f, 13, "嵌水印图片数", ttk.Entry(f, textvariable=self.s_images,
                                                   font=FONT, width=20))
        ttk.Label(f, text="封面 + 正文插图按文档顺序均匀采样，改大更抗删改、但更慢",
                  font=("Microsoft YaHei", 9), foreground="#6b7280").grid(
            row=14, column=1, sticky="w")

        self.s_fname = tk.StringVar(value=getattr(config, "FILENAME_MODE", "full"))
        self._row(f, 15, "成品文件名", ttk.Combobox(
            f, textvariable=self.s_fname, font=FONT, width=18, state="readonly",
            values=("full", "short", "clean")))
        ttk.Label(f, text="full=带完整水印ID / short=只带后4位 / clean=纯序号。"
                          "邮件附件名始终是不带标记的书名，这里只影响本地 out/ 的命名",
                  font=("Microsoft YaHei", 9), foreground="#6b7280",
                  wraplength=430, justify="left").grid(
            row=16, column=1, sticky="w")

        btns = ttk.Frame(f)
        btns.grid(row=17, column=0, columnspan=3, sticky="w", pady=12)
        ttk.Button(btns, text="保存到 .env 并生效", command=self.save_settings).pack(
            side="left", padx=(0, 8))
        ttk.Button(btns, text="备份数据库", command=self.backup).pack(side="left")

        info = ttk.LabelFrame(f, text="当前状态", padding=10)
        info.grid(row=16, column=0, columnspan=3, sticky="ew")
        self.info_var = tk.StringVar(value="")
        ttk.Label(info, textvariable=self.info_var, font=MONO,
                  justify="left").pack(anchor="w")

    def save_settings(self) -> None:
        env_path = os.path.join(BASE_DIR, ".env")
        data = {
            "SERVER_SECRET": self.s_secret.get().strip(),
            "DB_KEY": self.s_dbkey.get().strip(),
            "RESEND_API_KEY": self.s_resend.get().strip(),
            "RESEND_FROM_EMAIL": self.s_from.get().strip(),
            "SMTP_HOST": self.s_host.get().strip(),
            "SMTP_PORT": self.s_port.get().strip(),
            "SMTP_USER": self.s_user.get().strip(),
            "SMTP_PASS": self.s_pass.get().strip(),
            "POLICY_VERSION": self.s_policy.get().strip(),
            "SEND_INTERVAL": self.s_interval.get().strip(),
            "MAX_IMAGES": self.s_images.get().strip(),
            "FILENAME_MODE": self.s_fname.get().strip(),
        }
        if not data["SERVER_SECRET"] or not data["DB_KEY"]:
            messagebox.showerror("缺少密钥", "SERVER_SECRET 与 DB_KEY 不能为空")
            return
        lines = ["# 由 GUI 自动生成/更新 " + datetime.now().strftime("%Y-%m-%d %H:%M:%S")]
        for k, v in data.items():
            lines.append(f"{k}={v}")
        with open(env_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        for k, v in data.items():
            os.environ[k] = v
        try:
            reload_config()
        except Exception as exc:                          # noqa: BLE001
            messagebox.showwarning("已保存，但热更新失败",
                                   f"配置已写入 .env，请重启程序生效。\n{exc}")
            return
        messagebox.showinfo("已保存", f"配置已写入 {env_path} 并立即生效")
        self._refresh_status()

    def backup(self) -> None:
        try:
            os.makedirs(config.BACKUP_DIR, exist_ok=True)
            dst = os.path.join(
                config.BACKUP_DIR,
                "mapping-%s.db" % datetime.now().strftime("%Y%m%d-%H%M%S"))
            shutil.copy2(config.DB_PATH, dst)
            messagebox.showinfo("备份完成", "已备份到：\n" + dst)
        except Exception as exc:                          # noqa: BLE001
            messagebox.showerror("备份失败", str(exc))

    def _refresh_status(self) -> None:
        try:
            mode = db.encryption_mode()
            conn = db.connect(config.DB_PATH)
            st = db.stats(conn)
            conn.close()
            self.info_var.set(
                "加密模式 : " + mode + ("  ⚠ 明文存储，建议安装 sqlcipher3" if mode == "plain" else "")
                + "\n数据库   : " + config.DB_PATH
                + "\n记录总数 : " + str(st.get("total")) + "   已发送 " + str(st.get("sent"))
                + "   失败 " + str(st.get("failed")) + "   封禁 " + str(st.get("revoked"))
                + "\n通道健康 : 零宽 " + str(st.get("zw_ok")) + "   CSS " + str(st.get("css_ok"))
                + "   图片 " + str(st.get("img_ok")))
        except Exception as exc:                          # noqa: BLE001
            self.info_var.set("状态读取失败：" + str(exc))


def main() -> int:
    """用 pythonw 启动时没有控制台，任何异常都要落盘 + 弹窗，否则界面「无声消失」。"""
    import traceback
    try:
        root = tk.Tk()
        App(root)
        root.mainloop()
        return 0
    except Exception:                                    # noqa: BLE001
        msg = traceback.format_exc()
        try:
            with open(os.path.join(BASE_DIR, "gui_error.log"), "w",
                      encoding="utf-8") as f:
                f.write(msg)
        except Exception:                                # noqa: BLE001
            pass
        try:
            r = tk.Tk()
            r.withdraw()
            messagebox.showerror("启动失败", msg[-1500:])
        except Exception:                                # noqa: BLE001
            pass
        return 1


if __name__ == "__main__":
    sys.exit(main())
