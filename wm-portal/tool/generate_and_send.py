# -*- coding: utf-8 -*-
"""主流程：读收件人 CSV → 逐人生成水印副本 → 发邮件 → 记录映射表。

CLI：
    python generate_and_send.py --epub mother.epub --csv recipients.csv \
        --title "书名" [--resume] [--dry-run] [--limit 10] [--backend resend|smtp]

GUI 直接调用 run_batch()，通过 on_event 回调推送进度与日志、should_stop 支持中途停止。
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import os
import sys
import time
import uuid

import db
import config
from config import DAILY_LIMIT, DB_PATH, OUTPUT_DIR, POLICY_VERSION, SEND_INTERVAL
from crypto_utils import generate_watermark_id, sha256_file
from send_email import safe_filename, send_email
from watermark_embed import embed_watermark, precheck_mother


def load_recipients(csv_path: str, default_policy: str) -> list[dict]:
    seen, out = set(), []
    with open(csv_path, "r", encoding="utf-8-sig", newline="") as f:
        for r in csv.DictReader(f):
            qq = (r.get("qq_number") or "").strip()
            email = (r.get("email") or "").strip() or f"{qq}@qq.com"
            pv = (r.get("policy_version") or "").strip() or default_policy
            sid = (r.get("form_submission_id") or "").strip()
            if not qq or qq in seen:
                continue
            seen.add(qq)
            out.append({"qq_number": qq, "email": email, "pv": pv, "sid": sid})
    return out


def make_output_name(stem: str, watermark_id: str, seq: int = 0) -> str:
    """生成本地成品的文件名。

    三种模式（config.FILENAME_MODE）：
      full  —— 书名-WM-XXXXXXXXXX-XXXXXX.epub（默认，方便管理员一眼对应）
      short —— 书名-后4位短码.epub（隐晦些，记录页搜这 4 位仍能找到）
      clean —— 书名-001.epub（完全看不出带标记，适合手动分发）

    注意：**邮件附件名始终是干净书名**（send_email 用 book_title），
    收件人本来就看不到这些后缀。这里管的是本地 out/ 目录的命名 ——
    只有在你手动把文件发给别人时，命名才会被对方看到。
    """
    mode = (config.FILENAME_MODE or "full").lower()
    if mode == "clean":
        return f"{stem}-{seq:03d}.epub"
    if mode == "short":
        return f"{stem}-{watermark_id[-4:]}.epub"
    return f"{stem}-{watermark_id}.epub"


def run_batch(epub_path: str, csv_path: str, book_title: str,
              resume: bool = False, dry_run: bool = False,
              limit: int = 0, backend: str = "auto", batch_id: str = "",
              on_event=None, should_stop=None) -> dict:
    """执行一次分发。返回统计字典。

    on_event(kind, payload)：kind ∈ {'log', 'progress', 'done'}
    should_stop()：返回 True 时在当前收件人处理完后停止
    """
    def emit(kind, payload=""):
        if on_event:
            try:
                on_event(kind, payload)
            except Exception:                            # noqa: BLE001
                pass
        elif kind == "log":
            print(payload)

    if not os.path.isfile(epub_path):
        emit("log", f"[×] 母本不存在: {epub_path}")
        return {"ok": False, "error": "母本不存在"}

    # 每次分发前先备份：库里的密钥是唯一的溯源凭据，丢了就再也查不到人
    bak = db.backup(DB_PATH)
    if bak:
        emit("log", f"[√] 数据库已备份: {os.path.basename(bak)}")

    conn = db.connect(DB_PATH)
    emit("log", f"[√] 数据库: {DB_PATH}  加密模式: {db.encryption_mode()}")

    emit("log", "· 母本预检开始…")
    try:
        precheck_mother(epub_path, db.all_keys(conn),
                        on_step=lambda m: emit("log", m))
    except ValueError as exc:
        emit("log", f"[×] 母本预检失败：{exc}")
        conn.close()
        return {"ok": False, "error": str(exc)}

    file_hash = sha256_file(epub_path)
    batch_id = batch_id or uuid.uuid4().hex[:12]
    cur = conn.cursor()
    row = cur.execute("SELECT id FROM books WHERE title=? AND file_hash=?",
                      (book_title, file_hash)).fetchone()
    if row:
        book_id = row["id"]
    else:
        cur.execute("INSERT INTO books (title, original_filename, file_hash) VALUES (?,?,?)",
                    (book_title, os.path.basename(epub_path), file_hash))
        conn.commit()
        book_id = cur.lastrowid
    emit("log", f"[√] book_id={book_id}  batch_id={batch_id}")

    recipients = load_recipients(csv_path, POLICY_VERSION)
    if limit:
        recipients = recipients[:limit]
    emit("log", f"[√] 收件人 {len(recipients)} 个")

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    sent = failed = skipped = 0
    stopped = False

    for i, r in enumerate(recipients, 1):
        if should_stop and should_stop():
            stopped = True
            emit("log", "[停止] 用户中止")
            break
        if sent >= DAILY_LIMIT:
            emit("log", f"[停止] 已达日限 {DAILY_LIMIT} 封（剩余可加 --resume 续跑）")
            break

        # 用确定性检索列 qq_hash 判重：qq_number 在 field 加密模式下是随机 IV 的
        # 密文，`WHERE qq_number=enc(q)` 永远匹配不到 → 会把同一人重复发一遍。
        prev = cur.execute(
            "SELECT status FROM distributions WHERE book_id=? AND qq_hash=? "
            "AND status IN ('sent','revoked') ORDER BY id DESC LIMIT 1",
            (book_id, db.lookup_hash(r["qq_number"]))).fetchone()
        if prev:
            if not resume:
                emit("log", f"[{i}/{len(recipients)}] [!] 跳过：已有记录（{prev['status']}）")
                skipped += 1
                continue
            if prev["status"] == "revoked":
                emit("log", f"[{i}/{len(recipients)}] 跳过（已封禁）: {r['qq_number']}")
                skipped += 1
                continue
            emit("log", f"[{i}/{len(recipients)}] 跳过（已发送）: {r['qq_number']}")
            skipped += 1
            continue

        # 进度在**处理完**之后才推进 —— 放在开始处会让进度条超前一格，
        # 尤其在第一个收件人包含母本预检时，看起来像"还没动就 1/N 了"
        emit("progress", (i - 1, len(recipients)))
        watermark_id = generate_watermark_id()
        # 文件名带上母本名，方便在 out/ 里一眼区分是哪本书的哪一份
        stem = safe_filename(os.path.splitext(os.path.basename(epub_path))[0])
        out_path = os.path.join(OUTPUT_DIR, make_output_name(stem, watermark_id, i))
        err = ""
        try:
            # 水印自检偶发失败（密钥随机、个别图余量不足），换一组密钥重试一次
            result = None
            for attempt in (1, 2):
                try:
                    result = embed_watermark(epub_path, watermark_id, out_path,
                                             on_step=lambda m: emit("log", m))
                    break
                except ValueError as exc:
                    if attempt == 2:
                        raise
                    emit("log", f"    第 {attempt} 次生成未通过自检，换密钥重试…"
                                f"（{str(exc)[:80]}）")
            keys = result["keys"]
            cur.execute("""
                INSERT INTO distributions
                (batch_id, book_id, watermark_id, qq_number, qq_hash, email,
                 email_hash, status, agreed_policy_version, policy_hash,
                 form_submission_id, zero_width_ok, css_ok, image_qim_ok,
                 psnr, images, chaos_seed, chaos_mu, css_key, lsb_key)
                VALUES (?,?,?,?,?,?,?, 'pending',?,?,?,?,?,?,?,?,?,?,?,?)
            """, (batch_id, book_id, watermark_id, db.enc(r["qq_number"]),
                  db.lookup_hash(r["qq_number"]), db.enc(r["email"]),
                  db.lookup_hash(r["email"]), r["pv"],
                  hashlib.sha256(r["pv"].encode()).hexdigest()[:16], r["sid"],
                  int(result["zero_width"]), int(result.get("css", False)),
                  int(result["image_qim"]), float(result.get("psnr") or 0.0),
                  result.get("images", 0),
                  keys["chaos_seed"], keys["chaos_mu"], keys["css_key"], keys["lsb_key"]))
            conn.commit()

            tag = f"零宽={result['zero_width']} CSS={result.get('css')} " \
                  f"图片={result['image_qim']} PSNR={result.get('psnr')}"
            if dry_run:
                cur.execute("UPDATE distributions SET status='sent', sent_at=datetime('now') "
                            "WHERE watermark_id=?", (watermark_id,))
                conn.commit()
                sent += 1
                emit("log", f"[{i}/{len(recipients)}] [试运行] {watermark_id} {tag}")
            else:
                send_email(r["email"], out_path, book_title, r["qq_number"],
                           r["pv"], backend=backend)
                cur.execute("UPDATE distributions SET status='sent', sent_at=datetime('now') "
                            "WHERE watermark_id=?", (watermark_id,))
                conn.commit()
                sent += 1
                emit("log", f"[{i}/{len(recipients)}] 已发送 → {r['email']}（{tag}）")
        except Exception as exc:                          # noqa: BLE001
            err = str(exc)
            failed += 1
            emit("log", f"[{i}/{len(recipients)}] 失败 {r['email']}: {err}")
            cur.execute("UPDATE distributions SET status='failed', error_message=? "
                        "WHERE watermark_id=?", (err[:500], watermark_id))
            conn.commit()
        finally:
            # 默认（KEEP_LOCAL=0）发完就删本地成品：成品带水印，堆在本地是风险。
            # 要同时走「网页领取」，设 KEEP_LOCAL=1 保留（或用 --dry-run 只生成不发）。
            if not dry_run and not config.KEEP_LOCAL and os.path.exists(out_path):
                try:
                    os.remove(out_path)
                except OSError:
                    pass
            emit("progress", (i, len(recipients)))       # 本条处理完毕

        if not dry_run and sent < DAILY_LIMIT and not (should_stop and should_stop()):
            time.sleep(SEND_INTERVAL)

    st = db.stats(conn, batch_id)
    conn.close()
    summary = {"ok": True, "sent": sent, "failed": failed, "skipped": skipped,
               "stopped": stopped, "batch_id": batch_id, "stats": st}
    emit("log", f"\n完成：成功 {sent}、失败 {failed}、跳过 {skipped}")
    emit("done", summary)
    return summary


def main() -> int:
    ap = argparse.ArgumentParser(description="生成水印 EPUB 并发送")
    ap.add_argument("--epub", default="mother.epub")
    ap.add_argument("--csv", default="recipients.csv")
    ap.add_argument("--title", required=True)
    ap.add_argument("--resume", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--backend", default="auto", choices=["auto", "resend", "smtp"])
    ap.add_argument("--batch", default="")
    a = ap.parse_args()
    res = run_batch(a.epub, a.csv, a.title, a.resume, a.dry_run, a.limit,
                    a.backend, a.batch)
    print(f"批次统计：{res.get('stats', {})}")
    return 0 if res.get("ok") else 2


if __name__ == "__main__":
    sys.exit(main())
