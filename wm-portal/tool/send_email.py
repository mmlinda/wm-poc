# -*- coding: utf-8 -*-
"""邮件发送：Resend API（主）+ SMTP（备选，QQ 邮箱授权码）。

用标准库 urllib / smtplib 实现，不再依赖 requests，部署只需 Pillow + numpy。
"""
from __future__ import annotations

import base64
import json
import mimetypes
import os
import re
import smtplib
import ssl
import urllib.error
import urllib.request
from email.header import Header
from email.message import EmailMessage

from config import (RESEND_API_KEY, RESEND_FROM_EMAIL, SMTP_HOST, SMTP_PORT,
                    SMTP_USER, SMTP_PASS, SMTP_FROM)

_UNSAFE = re.compile(r'[\\/:*?"<>|\x00-\x1f]')


def safe_filename(title: str) -> str:
    cleaned = _UNSAFE.sub("_", title or "")
    return cleaned.strip().strip(".")[:100] or "book"


def build_body(book_title: str, qq_number: str, policy_version: str) -> str:
    safe = safe_filename(book_title)
    return (
        f"您好！\n\n"
        f"这是您领取的电子书《{safe}》，见附件。\n\n"
        f"说明：\n"
        f"· 该文件包含用于版权保护的技术标识，不影响正常阅读。\n"
        f"· 请勿二次传播，外传文件可被追溯到领取账号。\n"
        f"· 如需删除您的领取记录，回复本邮件即可。\n\n"
        f"条款版本：{policy_version}\n"
        f"领取账号：{qq_number}\n\n"
        f"祝阅读愉快！\n"
    )


# ------------------------------------------------------------------ Resend

def send_email_resend(to_email: str, epub_path: str, book_title: str,
                      qq_number: str, policy_version: str = "") -> str:
    """Resend API（免费 100 封/天，附件上限 40MB）。返回邮件 ID。"""
    if not RESEND_API_KEY:
        raise RuntimeError("未配置 RESEND_API_KEY")
    size = os.path.getsize(epub_path)
    if size > 38 * 1024 * 1024:
        raise RuntimeError(f"附件 {size / 1024 / 1024:.1f}MB 超过 Resend 40MB 上限")

    with open(epub_path, "rb") as f:
        b64 = base64.b64encode(f.read()).decode("ascii")
    safe = safe_filename(book_title)
    payload = {
        "from": RESEND_FROM_EMAIL,
        "to": [to_email],
        "subject": f"您的电子书：{safe}",
        "text": build_body(book_title, qq_number, policy_version),
        "attachments": [{"filename": f"{safe}.epub", "content": b64}],
    }
    req = urllib.request.Request(
        "https://api.resend.com/emails",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Authorization": f"Bearer {RESEND_API_KEY}",
                 "Content-Type": "application/json"},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"Resend 失败: {exc.code} {exc.read().decode('utf-8', 'ignore')[:300]}") from exc
    return data.get("id", "")


# ------------------------------------------------------------------ SMTP 备选

def send_email_smtp(to_email: str, epub_path: str, book_title: str,
                    qq_number: str, policy_version: str = "") -> str:
    """SMTP 发送（QQ 邮箱填授权码；465 SSL）。"""
    if not (SMTP_USER and SMTP_PASS):
        raise RuntimeError("未配置 SMTP_USER / SMTP_PASS")
    safe = safe_filename(book_title)
    msg = EmailMessage()
    msg["Subject"] = Header(f"您的电子书：{safe}", "utf-8")
    msg["From"] = SMTP_FROM
    msg["To"] = to_email
    msg.set_content(build_body(book_title, qq_number, policy_version))

    ctype, _ = mimetypes.guess_type(epub_path)
    maintype, subtype = (ctype or "application/epub+zip").split("/", 1)
    with open(epub_path, "rb") as f:
        msg.add_attachment(f.read(), maintype=maintype, subtype=subtype,
                           filename=f"{safe}.epub")
    ctx = ssl.create_default_context()
    if SMTP_PORT == 465:
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=ctx, timeout=60) as s:
            s.login(SMTP_USER, SMTP_PASS)
            s.send_message(msg)
    else:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=60) as s:
            s.starttls(context=ctx)
            s.login(SMTP_USER, SMTP_PASS)
            s.send_message(msg)
    return "smtp-ok"


def send_email(to_email: str, epub_path: str, book_title: str,
               qq_number: str, policy_version: str = "",
               backend: str = "auto") -> str:
    if backend in ("auto", "resend"):
        if RESEND_API_KEY:
            return send_email_resend(to_email, epub_path, book_title,
                                     qq_number, policy_version)
        if backend == "resend":
            raise RuntimeError("backend=resend 但未配置 RESEND_API_KEY")
    return send_email_smtp(to_email, epub_path, book_title,
                           qq_number, policy_version)
