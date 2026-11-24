#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""打标名单 · 移动端名单管理服务（多管理员版）

零第三方依赖（仅 Python 标准库），单端口 HTTP 服务：

    PORT=8080 python app.py

账号模型：
  · owner（站长，唯一，不可删除）—— 可以创建 / 停用 / 删除管理员、重置他们的密码
  · admin（管理员）—— 由 owner 创建

数据隔离：`groups` / `recipients` 都带 `admin_id`。**每个账号只看到自己名下的
分组和名单**，包括 owner 也只看自己的。owner 在「管理员管理」里只能看到
"各组有多少人"的统计，看不到别人名单里的 QQ / 邮箱内容。

数据落在 ./data/roster.db（SQLite）。导出的 CSV 与
epub-watermark/generate_and_send.py 的 recipients.csv 完全兼容。
"""
from __future__ import annotations

import csv
import calendar
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
from datetime import datetime, timedelta, timezone
import time
import urllib.parse
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BASE = os.path.dirname(os.path.abspath(__file__))
# 数据目录可以用 DATA_DIR 覆盖 —— 如果平台将来提供持久盘，指过去即可迁移，代码不用改。
# **必须 abspath**：叫 wm 引擎的子进程 cwd=tool/，相对路径在那里解析不到，
# 结果就是"上传母本成功、打标 100% 失败（母本不存在）"（QA D-10）。
DATA_DIR = os.path.abspath(os.environ.get("DATA_DIR") or os.path.join(BASE, "data"))
DB_PATH = os.path.join(DATA_DIR, "roster.db")
FILES_DIR = os.path.join(DATA_DIR, "files")      # 上传的成品 / 待溯源文件
TOOL_DIR = os.path.join(BASE, "tool")            # 打标引擎（随应用一起部署，不改一行算法）
TENANT_DIR = os.path.join(DATA_DIR, "tenants")   # 每个管理员一套独立工作区（.env / mapping.db / 母本）
INDEX_PATH = os.path.join(BASE, "index.html")

# 首次设置密码时的一次性口令（设置完成后即失效）。它不是长期密钥。
INIT_CODE = os.environ.get("INIT_CODE", "WM-ROSTER-8F3K")
COOKIE = "wm_sid"
VERSION = "2.3.1"                        # 线上排查用：/api/version 能确认部署的是哪一版
SESSION_TTL = 60 * 60 * 24 * 30          # 30 天

MB = 1024 * 1024
# 压缩包解压上限：**不信 header 里的 file_size**（可伪造），按实际读出字节硬截断
MAX_ZIP_ENTRY = int(os.environ.get("WM_MAX_ZIP_ENTRY_MB") or 200) * MB   # 单个条目
MAX_ZIP_TOTAL = int(os.environ.get("WM_MAX_ZIP_TOTAL_MB") or 1024) * MB  # 一次累计
# 存储策略（都可用环境变量覆盖，改行为不用改代码）
#   WM_QUOTA_MB     每个账号的成品+工单配额，0 = 不限（默认 0，靠总盘水位兜底）
#   WM_RESERVE_MB   给数据库/日志留的余量，剩余空间低于它就拒绝上传（默认 256）
#   WM_KEEP_DAYS    成品保留天数，0 = **不自动删**（默认）。开启后：
#                   已下载的留 N 天、没下载过的留 2N 天。
#                   ⚠️ 默认关：删用户上传的东西必须是"你主动选择"的行为，不能是默认行为。
QUOTA_MB = int(os.environ.get("WM_QUOTA_MB") or 0)
RESERVE_MB = int(os.environ.get("WM_RESERVE_MB") or 256)
KEEP_DAYS = int(os.environ.get("WM_KEEP_DAYS") or 0)

QQ_RE = re.compile(r"^\d{5,12}$")
USER_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.\-]{2,23}$")


# ------------------------------------------------------------------ 数据库

_lock = threading.RLock()


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db() -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(FILES_DIR, exist_ok=True)
    with _lock, db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS meta(
            k TEXT PRIMARY KEY, v TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS admins(
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            username   TEXT NOT NULL COLLATE NOCASE UNIQUE,
            nickname   TEXT NOT NULL DEFAULT '',
            pw_hash    TEXT NOT NULL,
            role       TEXT NOT NULL DEFAULT 'admin',   -- owner | admin
            token      TEXT NOT NULL DEFAULT '',        -- 自助登记链接令牌
            claim_token TEXT NOT NULL DEFAULT '',       -- 领取（下载）链接令牌，与登记分开
            status     TEXT NOT NULL DEFAULT 'active',  -- active | disabled
            created_by INTEGER,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            last_login TEXT
        );
        CREATE TABLE IF NOT EXISTS groups(
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_id   INTEGER NOT NULL DEFAULT 1,
            name       TEXT NOT NULL,
            note       TEXT NOT NULL DEFAULT '',
            sort       INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS recipients(
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_id   INTEGER NOT NULL DEFAULT 1,
            group_id   INTEGER REFERENCES groups(id) ON DELETE CASCADE,
            qq         TEXT NOT NULL,
            email      TEXT NOT NULL DEFAULT '',
            note       TEXT NOT NULL DEFAULT '',
            status     TEXT NOT NULL DEFAULT 'new',
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE UNIQUE INDEX IF NOT EXISTS ux_rec ON recipients(group_id, qq);
        CREATE INDEX IF NOT EXISTS ix_rec_group ON recipients(group_id);
        CREATE TABLE IF NOT EXISTS deliveries(
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_id   INTEGER NOT NULL,
            title      TEXT NOT NULL,
            note       TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS files(
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_id     INTEGER NOT NULL,
            delivery_id  INTEGER NOT NULL,
            qq           TEXT NOT NULL,
            token        TEXT NOT NULL,
            fname        TEXT NOT NULL,
            stored       TEXT NOT NULL,
            size         INTEGER NOT NULL DEFAULT 0,
            sha256       TEXT NOT NULL DEFAULT '',
            watermark_id TEXT NOT NULL DEFAULT '',
            downloads    INTEGER NOT NULL DEFAULT 0,
            last_at      TEXT,
            created_at   TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS traces(
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_id     INTEGER NOT NULL,
            stored       TEXT NOT NULL,
            fname        TEXT NOT NULL,
            size         INTEGER NOT NULL DEFAULT 0,
            status       TEXT NOT NULL DEFAULT 'pending',
            result       TEXT NOT NULL DEFAULT '',
            brief        TEXT NOT NULL DEFAULT '',
            watermark_id TEXT NOT NULL DEFAULT '',
            qq           TEXT NOT NULL DEFAULT '',
            created_at   TEXT NOT NULL DEFAULT (datetime('now')),
            done_at      TEXT,
            claimed_at   TEXT
        );
        CREATE TABLE IF NOT EXISTS settings(
            admin_id INTEGER NOT NULL,
            k        TEXT NOT NULL,
            v        TEXT NOT NULL DEFAULT '',
            PRIMARY KEY(admin_id, k)
        );
        CREATE TABLE IF NOT EXISTS fields(
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_id INTEGER NOT NULL,
            fkey     TEXT NOT NULL,
            label    TEXT NOT NULL,
            kind     TEXT NOT NULL DEFAULT 'text',
            required INTEGER NOT NULL DEFAULT 0,
            on_join  INTEGER NOT NULL DEFAULT 1,
            on_claim INTEGER NOT NULL DEFAULT 0,
            sort     INTEGER NOT NULL DEFAULT 0,
            gen      TEXT NOT NULL DEFAULT 'user',   -- user=填写人自己定 / manual=我逐个填 / random=网页批量生成
            gen_len  INTEGER NOT NULL DEFAULT 8,
            gen_charset TEXT NOT NULL DEFAULT 'alnum',
            gen_prefix  TEXT NOT NULL DEFAULT ''
        );
        CREATE UNIQUE INDEX IF NOT EXISTS ux_fields ON fields(admin_id, fkey);
        CREATE TABLE IF NOT EXISTS wm_books(
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_id   INTEGER NOT NULL,
            title      TEXT NOT NULL,
            fname      TEXT NOT NULL,
            stored     TEXT NOT NULL,
            size       INTEGER NOT NULL DEFAULT 0,
            sha256     TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS wm_jobs(
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_id     INTEGER NOT NULL,
            book_id      INTEGER NOT NULL,
            delivery_id  INTEGER NOT NULL,
            qq           TEXT NOT NULL,
            status       TEXT NOT NULL DEFAULT 'pending',
            watermark_id TEXT NOT NULL DEFAULT '',
            error        TEXT NOT NULL DEFAULT '',
            created_at   TEXT NOT NULL DEFAULT (datetime('now')),
            started_at   TEXT,
            done_at      TEXT
        );
        CREATE TABLE IF NOT EXISTS blocklist(
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_id   INTEGER NOT NULL,
            qq         TEXT NOT NULL,
            reason     TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        """)
    # 注意顺序：**先补列、再建依赖新列的索引**。
    # 反过来（老库上）会直接 `no such column: admin_id` 打不开库 ——
    # 和 watermark 项目里 schema.sql 那个坑是同一类，只有真·老库能测出来。
    _ensure_columns()
    with _lock, db() as c:
        c.executescript("""
        CREATE INDEX IF NOT EXISTS ix_rec_admin ON recipients(admin_id);
        CREATE INDEX IF NOT EXISTS ix_grp_admin ON groups(admin_id);
        CREATE INDEX IF NOT EXISTS ix_dlv_admin ON deliveries(admin_id);
        CREATE INDEX IF NOT EXISTS ix_files_dlv ON files(delivery_id);
        CREATE INDEX IF NOT EXISTS ix_files_adm ON files(admin_id);
        CREATE UNIQUE INDEX IF NOT EXISTS ux_files_tok ON files(token);
        CREATE INDEX IF NOT EXISTS ix_traces_adm ON traces(admin_id);
        CREATE UNIQUE INDEX IF NOT EXISTS ux_block ON blocklist(admin_id, qq);
        CREATE INDEX IF NOT EXISTS ix_wm_books ON wm_books(admin_id);
        CREATE INDEX IF NOT EXISTS ix_wm_jobs ON wm_jobs(status, admin_id);
        """)
    _ensure_owner()


# 旧库补列（CREATE TABLE IF NOT EXISTS 不会给已存在的表加列）
_ADD_COLUMNS = (
    ("recipients", "source", "TEXT NOT NULL DEFAULT 'admin'"),
    ("recipients", "admin_id", "INTEGER NOT NULL DEFAULT 1"),
    ("recipients", "watermark_id", "TEXT NOT NULL DEFAULT ''"),
    ("recipients", "sent_at", "TEXT"),
    ("groups", "admin_id", "INTEGER NOT NULL DEFAULT 1"),
    ("admins", "claim_token", "TEXT NOT NULL DEFAULT ''"),
    ("recipients", "extra", "TEXT NOT NULL DEFAULT '{}'"),
    ("traces", "brief", "TEXT NOT NULL DEFAULT ''"),
    # v2.2：字段的取值来源（自己填 / 我逐个填 / 网页批量生成）
    ("fields", "gen", "TEXT NOT NULL DEFAULT 'user'"),
    ("fields", "gen_len", "INTEGER NOT NULL DEFAULT 8"),
    ("fields", "gen_charset", "TEXT NOT NULL DEFAULT 'alnum'"),
    ("fields", "gen_prefix", "TEXT NOT NULL DEFAULT ''"),
)


def _ensure_columns() -> None:
    with _lock, db() as c:
        for table, col, decl in _ADD_COLUMNS:
            try:
                cols = [r["name"] for r in c.execute(f"PRAGMA table_info({table})")]
            except Exception:                             # noqa: BLE001
                continue
            if cols and col not in cols:
                try:
                    c.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")
                except Exception:                         # noqa: BLE001
                    pass


def new_token() -> str:
    return secrets.token_hex(4)


# 本次进程启动时间（用来区分"重启了"和"数据没了"）
BOOT_AT = int(time.time())


def instance_id() -> str:
    """写在数据目录里的稳定标识：重新部署后如果它没变，说明盘是持久的。

    只用于体检，不参与任何鉴权。
    """
    p = os.path.join(DATA_DIR, "instance_id")
    try:
        with open(p, "r", encoding="utf-8") as f:
            v = f.read().strip()
            if v:
                return v
    except OSError:
        pass
    v = secrets.token_hex(8)
    try:
        with open(p, "w", encoding="utf-8") as f:
            f.write(v)
    except OSError:
        pass
    return v


def _ensure_owner() -> None:
    """老库（只有 meta.pw_hash 的单密码版）升级：把那个密码迁成 owner 账号。"""
    with _lock, db() as c:
        n = c.execute("SELECT COUNT(*) c FROM admins").fetchone()["c"]
        if n:
            # 保证每个账号都有两种令牌（早期版本可能为空）
            for r in c.execute("SELECT id,token,claim_token FROM admins").fetchall():
                if not r["token"]:
                    c.execute("UPDATE admins SET token=? WHERE id=?",
                              (new_token(), r["id"]))
                if not r["claim_token"]:
                    c.execute("UPDATE admins SET claim_token=? WHERE id=?",
                              (secrets.token_hex(6), r["id"]))
            return
        old = c.execute("SELECT v FROM meta WHERE k='pw_hash'").fetchone()
        if not old or not old["v"]:
            return
        c.execute("INSERT INTO admins(username,nickname,pw_hash,role,token,claim_token,"
                  "status) VALUES(?,?,?,?,?,?,'active')",
                  ("admin", "我", old["v"], "owner", new_token(),
                   secrets.token_hex(6)))


def meta_get(k: str, default: str = "") -> str:
    with db() as c:
        row = c.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
    return row["v"] if row else default


def meta_set(k: str, v: str) -> None:
    with _lock, db() as c:
        c.execute("INSERT INTO meta(k,v) VALUES(?,?) "
                  "ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, v))


# ------------------------------------------------------------------ 密码 / 会话

def hash_pw(pw: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt.encode(), 200_000)
    return f"pbkdf2${salt}${dk.hex()}"


def check_pw(pw: str, stored: str) -> bool:
    try:
        algo, salt, digest = stored.split("$", 2)
        if algo != "pbkdf2":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt.encode(), 200_000)
        return hmac.compare_digest(dk.hex(), digest)
    except Exception:                                     # noqa: BLE001
        return False


def _secret() -> str:
    s = meta_get("session_secret")
    if not s:
        s = secrets.token_hex(32)
        meta_set("session_secret", s)
    return s


def pw_tag(pw_hash: str | None) -> str:
    """密码指纹：掺进会话签名，改密码 → 所有旧会话自动失效。"""
    return hashlib.sha256((pw_hash or "").encode()).hexdigest()[:8]


def make_sid(uid: int, pw_hash: str = "") -> str:
    exp = str(int(time.time()) + SESSION_TTL)
    tag = pw_tag(pw_hash)
    msg = f"{uid}.{exp}.{tag}"
    sig = hmac.new(_secret().encode(), msg.encode(), hashlib.sha256).hexdigest()[:32]
    return f"{msg}.{sig}"


def sid_parse(sid: str | None) -> tuple[int, str] | None:
    """解析会话 cookie → (管理员 id, 密码指纹)。

    签名里带 id 不能冒充别人；带 pw_tag 是为了"改密码能吊销旧会话"——
    无状态 cookie 没有服务端记录，只能靠这个让它自动作废。
    """
    if not sid:
        return None
    parts = sid.split(".")
    if len(parts) != 4:          # 老格式（3 段）→ 强制重新登录一次
        return None
    uid, exp, tag, sig = parts
    if not uid.isdigit() or not exp.isdigit() or int(exp) < time.time():
        return None
    want = hmac.new(_secret().encode(), f"{uid}.{exp}.{tag}".encode(),
                    hashlib.sha256).hexdigest()[:32]
    return (int(uid), tag) if hmac.compare_digest(sig, want) else None


# 登录失败限速（防暴力猜测）
_fails: dict[str, list[float]] = {}
_fails_lock = threading.Lock()
# 首次设置也要限速：那把桶的 key 用 SETUP_KEY（不是 IP），这样轮换 XFF 也绕不过
SETUP_KEY = "setup:*"
SETUP_LIMIT = 30


def too_many(ip: str, limit: int = 10) -> bool:
    now = time.time()
    with _fails_lock:
        arr = [t for t in _fails.get(ip, []) if now - t < 600]
        _fails[ip] = arr
        return len(arr) >= limit


def note_fail(ip: str) -> None:
    with _fails_lock:
        _fails.setdefault(ip, []).append(time.time())


def clear_fail(ip: str) -> None:
    with _fails_lock:
        _fails.pop(ip, None)


# ---- 自助登记限速：每个 IP 每小时最多 10 条（防刷名单，不是防爆破）----
_joins: dict[str, list[float]] = {}
_joins_lock = threading.Lock()


def join_allowed(ip: str, limit: int = 10, window: int = 3600) -> bool:
    now = time.time()
    with _joins_lock:
        arr = [t for t in _joins.get(ip, []) if now - t < window]
        _joins[ip] = arr
        if len(arr) >= limit:
            return False
        arr.append(now)
        return True


# ------------------------------------------------------------------ 业务

def normalize_qq(v: str) -> str:
    v = (v or "").strip()
    v = re.sub(r"[^\d]", "", v)
    return v


def guess_email(qq: str, email: str) -> str:
    email = (email or "").strip()
    if email:
        return email
    return f"{qq}@qq.com" if qq else ""


# ------------------------------------------------------------------ 表单字段（可配置）

FORM_DEFAULT = {"qq_label": "QQ 号", "email_on": "1", "email_label": "邮箱",
                "note_on": "1", "note_label": "备注"}
FKEY_RE = re.compile(r"^[a-z][a-z0-9_]{1,19}$")
MAX_FIELDS = 8


def sget(conn, aid: int, k: str, default: str = "") -> str:
    r = conn.execute("SELECT v FROM settings WHERE admin_id=? AND k=?", (aid, k)).fetchone()
    return r["v"] if r else default


def sset(conn, aid: int, k: str, v: str) -> None:
    conn.execute("INSERT INTO settings(admin_id,k,v) VALUES(?,?,?) "
                 "ON CONFLICT(admin_id,k) DO UPDATE SET v=excluded.v", (aid, k, v))


def form_cfg(conn, aid: int) -> dict:
    return {k: sget(conn, aid, k, d) for k, d in FORM_DEFAULT.items()}


def form_fields(conn, aid: int) -> list[dict]:
    return [dict(r) for r in conn.execute(
        "SELECT id,fkey,label,kind,required,on_join,on_claim,sort,"
        "gen,gen_len,gen_charset,gen_prefix FROM fields "
        "WHERE admin_id=? ORDER BY sort,id", (aid,))]


# ------------------------------------------------------------------ 暗号生成
# 默认剔除易混字符（0 O 1 l I），避免手抄错
_GEN_CHARSETS = {
    "digit":       "23456789",
    "alpha":       "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
    "alnum":       "23456789ABCDEFGHJKLMNPQRSTUVWXYZ",
    "alnum_lower": "23456789abcdefghijkmnpqrstuvwxyz",
    "sym":         "23456789ABCDEFGHJKLMNPQRSTUVWXYZ!@#$%^&*",
}
GEN_MIN, GEN_MAX = 4, 32


def gen_code(length: int = 8, charset: str = "alnum", prefix: str = "") -> str:
    pool = _GEN_CHARSETS.get(charset) or _GEN_CHARSETS["alnum"]
    n = max(GEN_MIN, min(GEN_MAX, int(length or 8)))
    body = "".join(secrets.choice(pool) for _ in range(n))
    return (prefix or "")[:8] + body


def parse_extra(raw) -> dict:
    try:
        v = json.loads(raw or "{}")
        return v if isinstance(v, dict) else {}
    except Exception:                                    # noqa: BLE001
        return {}


def field_stats(conn, aid: int) -> dict:
    """每个字段有几个人填了。用于提示「还有 N 人没暗号」——
    没值的字段在领取时会被跳过校验，不说出来就等于暗号形同虚设。"""
    total = conn.execute("SELECT COUNT(*) c FROM recipients WHERE admin_id=?",
                         (aid,)).fetchone()["c"]
    rows = [dict(r) for r in conn.execute(
        "SELECT extra FROM recipients WHERE admin_id=?", (aid,))]
    out = {}
    for f in form_fields(conn, aid):
        n = sum(1 for r in rows
                if str(parse_extra(r["extra"]).get(f["fkey"]) or "").strip())
        out[f["fkey"]] = {"filled": n, "total": total}
    return out


def is_blocked(conn, aid: int, qq: str) -> bool:
    """黑名单：只挡"再发/再领/再登记"，**绝不删记录** —— 已发出去的那份还要靠它溯源。"""
    if not qq:
        return False
    return conn.execute("SELECT 1 FROM blocklist WHERE admin_id=? AND qq=? LIMIT 1",
                        (aid, qq)).fetchone() is not None


def clean_extra(obj, fields: list[dict]) -> tuple[dict, str]:
    """把提交上来的自定义字段收成 {fkey: value}，并按配置校验。返回 (值, 错误)。"""
    if not isinstance(obj, dict):
        obj = {}
    out = {}
    for f in fields:
        v = str(obj.get(f["fkey"]) or "").strip()[:200]
        if f["required"] and not v:
            return {}, f"「{f['label']}」要填"
        if v and f["kind"] == "email" and "@" not in v:
            return {}, f"「{f['label']}」格式不对"
        if v and f["kind"] == "number" and not v.replace("-", "").isdigit():
            return {}, f"「{f['label']}」只能填数字"
        if v:
            out[f["fkey"]] = v
    return out, ""


def parse_bulk(text: str, fkeys: list[str] | None = None) -> tuple[list[dict], int]:
    """把「多行粘贴」解析成名单行。支持：

        123456789
        123456789, a@b.com
        123456789, a@b.com, 备注
        123456789, , 备注          ← 中间空列要保留，否则备注会被当成邮箱
        123456789, a@b.com, 备注, 暗号A   ← 第 4 列起 = 自定义字段（按定义顺序）

    返回 (行列表, 批内重复数)。注意：**不能过滤空字段**，否则 `QQ, ,备注`
    里的空邮箱会被挤掉，备注顶到邮箱位。
    """
    out, seen, dup = [], set(), 0
    for raw in (text or "").replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in re.split(r"[\t,，;；|]+", line)]
        while parts and parts[-1] == "":
            parts.pop()
        if not parts:
            continue
        qq = normalize_qq(parts[0])
        email = parts[1] if len(parts) > 1 else ""
        note = parts[2] if len(parts) > 2 else ""
        # 第二列不像邮箱（没有 @）→ 当作备注，避免把「闲鱼来的」存成邮箱
        if email and "@" not in email:
            if not note:
                note = email
            email = ""
        if not QQ_RE.match(qq):
            continue
        if qq in seen:
            dup += 1
            continue
        seen.add(qq)
        extra = {}
        if fkeys:
            for i, k in enumerate(fkeys):
                idx = 3 + i
                if len(parts) > idx and parts[idx]:
                    extra[k] = parts[idx][:100]
        out.append({"qq": qq, "email": guess_email(qq, email),
                    "note": note[:200], "extra": extra})
    return out, dup


def admin_row(uid: int) -> dict | None:
    with db() as c:
        r = c.execute("SELECT id,username,nickname,role,token,claim_token,status,"
                      "pw_hash FROM admins WHERE id=?", (uid,)).fetchone()
    return dict(r) if r else None


def state(me: dict) -> dict:
    """**只返回当前账号名下的数据。**owner 额外拿到管理员统计（不含名单内容）。"""
    uid = me["id"]
    with db() as c:
        groups = [dict(r) for r in c.execute(
            "SELECT id,name,note,sort FROM groups WHERE admin_id=? "
            "ORDER BY sort,id", (uid,))]
        recs = [dict(r) for r in c.execute(
            "SELECT id,group_id,qq,email,note,status,source,watermark_id,sent_at,extra "
            "FROM recipients WHERE admin_id=? ORDER BY id DESC", (uid,))]
        admins = []
        if me["role"] == "owner":
            admins = [dict(r) for r in c.execute(
                "SELECT a.id,a.username,a.nickname,a.role,a.status,a.token,"
                "a.created_at,a.last_login,"
                "(SELECT COUNT(*) FROM recipients x WHERE x.admin_id=a.id) AS n_rec,"
                "(SELECT COUNT(*) FROM groups g WHERE g.admin_id=a.id) AS n_grp,"
                "(SELECT COUNT(*) FROM recipients x WHERE x.admin_id=a.id "
                "  AND x.status='sent') AS n_sent "
                "FROM admins a ORDER BY (a.role='owner') DESC, a.id")]
    me2 = {"id": me["id"], "username": me["username"], "nickname": me["nickname"],
           "role": me["role"], "token": me["token"],
           "claim_token": me.get("claim_token", "")}
    with db() as c:
        cfg = form_cfg(c, uid)
        flds = form_fields(c, uid)
        stats = field_stats(c, uid)
        blocked = [dict(r) for r in c.execute(
            "SELECT id,qq,reason,created_at FROM blocklist WHERE admin_id=? "
            "ORDER BY id DESC", (uid,))]
    for r in recs:
        try:
            r["extra"] = json.loads(r.get("extra") or "{}")
        except Exception:                                # noqa: BLE001
            r["extra"] = {}
    return {"me": me2, "groups": groups, "recipients": recs, "admins": admins,
            "form": {"cfg": cfg, "fields": flds, "stats": stats},
            "blocked": blocked, "initialized": True}


def group_owner(conn, gid: int) -> int | None:
    r = conn.execute("SELECT admin_id FROM groups WHERE id=?", (gid,)).fetchone()
    return r["admin_id"] if r else None


# ------------------------------------------------------------------ 交付文件

MAX_UPLOAD = 80 * 1024 * 1024          # 单个请求上限
FILE_EXTS = (".epub", ".pdf", ".zip", ".mobi", ".azw3")
# 单个成品能接受什么（不含 .zip —— 压缩包走 zip=1 那条分支，不该被当成"一本书"）
BOOK_EXTS = (".epub", ".pdf", ".mobi", ".azw3")


def to_int(v, default=None):
    """用户输入转 int，非法返回 default。**绝不抛异常** ——
    一个 "abc" 就能让整个请求 500 并掐断连接（评审 D-05 实测）。"""
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return default


class _Body(dict):
    """请求体字典。`.get()` 把 int/float 收敛成字符串，其余原样返回。

    为什么要有这层（QA D-08）：历史代码里满地是
        name = body_str(b, "name").strip()
    客户端一传 `{"name":123}` 就是 AttributeError → 500。_guard 能兜住连接，
    但语义上应该是"按名字 123 处理"或 400，不是 500 + traceback。

    收敛规则故意很窄：
      · int / float  → str   （`{"name":123}` → "123"，`{"qq":123456789}` 也能用）
      · bool         → 原样   （不能变成 "0"/"1"，否则 `only_empty is not False` 这类判断会反）
      · list / dict  → 原样   （由各端点自己判定类型错，回 400）
    """

    __slots__ = ()

    def get(self, key, default=None):
        v = dict.get(self, key, default)
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            return v
        return str(v)


def body_str(b, key: str, default: str = "") -> str:
    """取"字符串型"参数，**任何输入都不抛异常**。

    `.get()` 只把数字收敛成字符串；列表/字典落到字符串字段上时，
    历史写法 `(b.get("name") or "").strip()` 会 AttributeError → 500
    （QA D-08 同一类）。这里统一当"没填"，由各端点回 400 或用自己的默认值。
    """
    v = b.get(key) if hasattr(b, "get") else None
    if v is None or isinstance(v, (list, dict, set, tuple, bool)):
        return default
    return str(v)


def safe_fname(name: str, default: str = "file.epub") -> str:
    name = os.path.basename((name or "").replace("\\", "/"))
    name = re.sub(r'[\\/:*?"<>|\x00-\x1f]+', "_", name).strip()
    return (name or default)[:120]


def qq_from_name(name: str) -> str:
    """从文件名里认 QQ。只认"整段就是 5~12 位数字"的片段，
    避免把 `财神春花-WM-8F25B7212E-58AE11` 里的十六进制当成 QQ。"""
    stem = os.path.splitext(os.path.basename(name or ""))[0]
    for part in re.split(r"[^0-9A-Za-z]+", stem):
        if part.isdigit() and QQ_RE.match(part):
            return part
    return ""


def dlv_dir(did: int) -> str:
    return os.path.join(FILES_DIR, f"d{did}")


def trace_dir(aid: int) -> str:
    return os.path.join(FILES_DIR, "traces", str(aid))


def human(n: int) -> str:
    try:
        n = int(n)
    except (TypeError, ValueError):
        return "0 B"
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} GB"


# ------------------------------------------------------------------ 环境探针

def _guard(fn):
    """给 do_* 包一层兜底：任何未捕获异常都变成 500 JSON，而不是掐断连接。

    之前 `int("abc")` 或 sqlite 约束冲突会让 BaseHTTPRequestHandler 直接关连接，
    客户端收到**空响应**（连 HTTP 状态都没有），排查起来像"网站挂了"。
    """
    def inner(self, *a, **kw):
        try:
            return fn(self, *a, **kw)
        except (BrokenPipeError, ConnectionResetError):
            return
        except Exception as exc:                         # noqa: BLE001
            import traceback
            traceback.print_exc()
            try:
                self._err(500, f"服务端出错（{type(exc).__name__}），已记录")
            except Exception:                            # noqa: BLE001
                pass
    return inner


# ------------------------------------------------------------------ 引擎指纹

_ENGINE_FP: str | None = None


def engine_fingerprint() -> str:
    """引擎代码指纹（sha256 前 12 位）。

    引擎是**拷贝式部署**（`epub-watermark/` → `wm-portal/tool/`），没有单一事实源。
    一旦两边漂移，就会出现"本地测的是 A、线上跑的是 B"。把指纹暴露到
    `/api/version`，和本地算一次对比就能立刻发现，不用猜。
    """
    global _ENGINE_FP
    if _ENGINE_FP is not None:
        return _ENGINE_FP
    h = hashlib.sha256()
    try:
        for root, dirs, files in os.walk(TOOL_DIR):
            dirs[:] = sorted(d for d in dirs if d != "__pycache__")
            for fn in sorted(files):
                if not fn.endswith((".py", ".sql")):
                    continue
                pth = os.path.join(root, fn)
                h.update(os.path.relpath(pth, TOOL_DIR).replace("\\", "/").encode())
                with open(pth, "rb") as f:
                    h.update(f.read())
    except OSError:
        pass
    _ENGINE_FP = h.hexdigest()[:12]
    return _ENGINE_FP


def env_probe() -> dict:
    """这台机器能不能跑水印引擎？（只回版本号和耗时，不涉及任何业务数据）"""
    out = {"ok": True, "python": "", "numpy": "", "pil": "", "cpu": 0, "mem_mb": 0,
           "bench_ms": None, "note": ""}
    import platform
    out["python"] = platform.python_version()
    try:
        import os as _os
        out["cpu"] = _os.cpu_count() or 0
    except Exception:                                    # noqa: BLE001
        pass
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    out["mem_mb"] = int(line.split()[1]) // 1024
                    break
    except OSError:
        pass
    try:
        import numpy as _np
        out["numpy"] = _np.__version__
        import time as _t
        a = _np.random.rand(256, 256).astype("float32")
        t0 = _t.time()
        for _ in range(20):
            _np.sum(_np.abs(a * a))
        out["bench_ms"] = round((_t.time() - t0) * 1000 / 20, 2)
    except Exception as exc:                             # noqa: BLE001
        out["numpy"] = f"缺失({type(exc).__name__})"
    try:
        from PIL import Image
        out["pil"] = getattr(Image, "__version__", "ok")
    except Exception as exc:                             # noqa: BLE001
        out["pil"] = f"缺失({type(exc).__name__})"
    if not out["numpy"].startswith("缺") and not out["pil"].startswith("缺"):
        out["note"] = "可以跑完整引擎（含图片层）"
    elif not out["numpy"].startswith("缺"):
        out["note"] = "有 numpy 没 Pillow：只能跑文字/结构层"
    else:
        out["note"] = "没有 numpy：只能跑纯标准库的轻量层"
    return out


_last_selftest = 0.0


def self_test(timeout: int = 300) -> dict:
    """在临时工作区里跑一遍引擎自检 —— 验证云端能否真正打标（不改任何真实数据）。"""
    global _last_selftest
    now = time.time()
    if now - _last_selftest < 300:
        return {"ok": False, "error": "刚跑过一次，等 5 分钟再来"}
    _last_selftest = now
    tmp = tempfile.mkdtemp(prefix="wm_selftest_")
    try:
        work = os.path.join(tmp, "tool")
        shutil.copytree(TOOL_DIR, work)
        with open(os.path.join(work, ".env"), "w", encoding="utf-8") as f:
            f.write(f"SERVER_SECRET={secrets.token_hex(32)}\n")
            f.write(f"DB_KEY={secrets.token_hex(24)}\n")
        p = subprocess.run([sys.executable, "test_watermark.py"], cwd=work,
                           capture_output=True, text=True, timeout=timeout)
        out = (p.stdout or "") + "\n" + (p.stderr or "")
        return {"ok": p.returncode == 0, "code": p.returncode,
                "seconds": round(time.time() - now, 1),
                "tail": out[-3000:]}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"超时（>{timeout}s）"}
    except Exception as exc:                             # noqa: BLE001
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ------------------------------------------------------------------ 云端打标引擎

_wm_lock = threading.Lock()          # 一次只跑一本，避免 32 核被吃满 / 内存叠爆
_wm_wake = threading.Event()


def ensure_tenant(aid: int) -> dict:
    """每个管理员一套独立工作区：自己的密钥 + 自己的 mapping.db + 自己的 out/。"""
    d = os.path.join(TENANT_DIR, str(aid))
    os.makedirs(os.path.join(d, "in"), exist_ok=True)
    os.makedirs(os.path.join(d, "out"), exist_ok=True)
    with _lock, db() as c:
        sec = sget(c, aid, "wm_secret")
        key = sget(c, aid, "wm_dbkey")
        if not sec:
            sec = secrets.token_hex(32)
            sset(c, aid, "wm_secret", sec)
        if not key:
            key = secrets.token_hex(24)
            sset(c, aid, "wm_dbkey", key)
    return {"dir": d, "secret": sec, "dbkey": key,
            "db": os.path.join(d, "mapping.db"),
            "out": os.path.join(d, "out"),
            "bak": os.path.join(d, "backups")}


def wm_env(t: dict) -> dict:
    """把租户的密钥/路径通过环境变量喂给引擎（配置层是 env 优先，不会读别人的 .env）。"""
    env = dict(os.environ)
    env.update({
        "SERVER_SECRET": t["secret"],
        "DB_KEY": t["dbkey"],
        "DB_PATH": t["db"],
        "OUTPUT_DIR": t["out"],
        "BACKUP_DIR": t["bak"],
        "WM_GUI": "",
    })
    return env


def _wm_python() -> str:
    return sys.executable or "python3"


def run_wm_job(job_id: int) -> None:
    """执行一条打标任务：调真引擎生成一份，然后把它登记成"可领取的文件"。"""
    with db() as c:
        job = c.execute("SELECT * FROM wm_jobs WHERE id=?", (job_id,)).fetchone()
        if not job or job["status"] not in ("pending",):
            return
        book = c.execute("SELECT * FROM wm_books WHERE id=?", (job["book_id"],)).fetchone()
        c.execute("UPDATE wm_jobs SET status='running', started_at=datetime('now') "
                  "WHERE id=?", (job_id,))
    if not book:
        with _lock, db() as c:
            c.execute("UPDATE wm_jobs SET status='failed', error='母本不存在', "
                      "done_at=datetime('now') WHERE id=?", (job_id,))
        return

    t = ensure_tenant(job["admin_id"])
    csv_path = os.path.join(t["dir"], "in", f"job{job_id}.csv")
    with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
        f.write("qq_number,email\n")
        f.write(f"{job['qq']},{job['qq']}@qq.com\n")
    mother = os.path.join(FILES_DIR, book["stored"])
    before = set(os.listdir(t["out"])) if os.path.isdir(t["out"]) else set()
    try:
        proc = subprocess.run(
            [_wm_python(), "generate_and_send.py", "--epub", mother,
             "--csv", csv_path, "--title", book["title"],
             "--dry-run", "--limit", "1"],
            cwd=TOOL_DIR, env=wm_env(t), capture_output=True, text=True,
            timeout=900, encoding="utf-8", errors="replace")
        out = (proc.stdout or "") + "\n" + (proc.stderr or "")
    except subprocess.TimeoutExpired:
        out, proc = "生成超时（>15 分钟）", None
    except Exception as exc:                             # noqa: BLE001
        out, proc = f"{type(exc).__name__}: {exc}", None

    if proc is None or proc.returncode != 0:
        with _lock, db() as c:
            c.execute("UPDATE wm_jobs SET status='failed', error=?, "
                      "done_at=datetime('now') WHERE id=?",
                      ((out or "未知错误")[-900:], job_id))
        _wm_wake.set()
        return

    m = re.search(r"(WM-[0-9A-Fa-f]{10}-[0-9A-Fa-f]{6})", out)
    wid = m.group(1) if m else ""
    if not wid:
        with _lock, db() as c:
            c.execute("UPDATE wm_jobs SET status='failed', error=?, "
                      "done_at=datetime('now') WHERE id=?",
                      ("生成成功但没解析出水印 ID：" + out[-600:], job_id))
        _wm_wake.set()
        return

    # 找到这一步新生成的文件
    after = set(os.listdir(t["out"])) if os.path.isdir(t["out"]) else set()
    fresh = [x for x in (after - before) if x.lower().endswith(".epub")]
    if not fresh:
        fresh = [x for x in after if wid in x]
    if not fresh:
        with _lock, db() as c:
            c.execute("UPDATE wm_jobs SET status='failed', error='没找到生成的成品文件', "
                      "done_at=datetime('now') WHERE id=?", (job_id,))
        _wm_wake.set()
        return
    src = os.path.join(t["out"], sorted(fresh)[0])

    # 登记成可领取的文件（沿用交付/领取那一套）
    did = job["delivery_id"]
    dst_dir = dlv_dir(did)
    os.makedirs(dst_dir, exist_ok=True)
    token = secrets.token_hex(10)
    fname = f"{book['title']}.epub"
    dst = os.path.join(dst_dir, f"{job['qq']}_{token[:8]}.epub")
    try:
        shutil.move(src, dst)
    except OSError:
        shutil.copy2(src, dst)
    rel = os.path.relpath(dst, FILES_DIR)
    size = os.path.getsize(dst)
    with _lock, db() as c:
        old = c.execute("SELECT id FROM files WHERE delivery_id=? AND qq=?",
                        (did, job["qq"])).fetchone()
        if old:
            c.execute("UPDATE files SET fname=?, stored=?, size=?, watermark_id=?, "
                      "created_at=datetime('now') WHERE id=?",
                      (fname, rel, size, wid, old["id"]))
        else:
            c.execute("INSERT INTO files(admin_id,delivery_id,qq,token,fname,stored,"
                      "size,watermark_id) VALUES(?,?,?,?,?,?,?,?)",
                      (job["admin_id"], did, job["qq"], token, fname, rel, size, wid))
        c.execute("UPDATE recipients SET status='sent', watermark_id=?, "
                  "sent_at=datetime('now'), updated_at=datetime('now') "
                  "WHERE admin_id=? AND qq=?", (wid, job["admin_id"], job["qq"]))
        c.execute("UPDATE wm_jobs SET status='done', watermark_id=?, done_at=datetime('now') "
                  "WHERE id=?", (wid, job_id))
    _wm_wake.set()


def recover_jobs() -> int:
    """进程重启后，把上次没跑完的 `running` 任务退回队列。

    不这么做的话，部署/崩溃那一刻正在跑的任务会**永远停在 running**：
    worker 只捞 pending，而 wm_summary 把 running 计入"待处理" →
    前端一直显示"正在生成 1 份…"，轮询也永远停不下来。
    串行单 worker，所以不用担心误踢掉正在执行的任务。
    """
    with _lock, db() as c:
        n = c.execute("UPDATE wm_jobs SET status='pending', started_at=NULL, "
                      "error='' WHERE status='running'").rowcount
    return max(0, n)


def recover_traces() -> int:
    """重启后重新处理还没出结果的溯源工单（否则它们永远停在 pending）。"""
    with db() as c:
        rows = [dict(r) for r in c.execute(
            "SELECT id,admin_id FROM traces WHERE status='pending'").fetchall()]
    for r in rows:
        threading.Thread(target=trace_run, args=(r["id"], r["admin_id"]),
                         daemon=True).start()
    return len(rows)


def wm_worker() -> None:
    """后台单线程消费任务队列。"""
    while True:
        try:
            with db() as c:
                row = c.execute("SELECT id FROM wm_jobs WHERE status='pending' "
                                "ORDER BY id LIMIT 1").fetchone()
            if row:
                run_wm_job(row["id"])
                continue
        except Exception:                                # noqa: BLE001
            pass
        _wm_wake.wait(timeout=3)
        _wm_wake.clear()


def _parse_json_block(out: str) -> dict:
    for marker in ("\n{\n", "{\n"):
        i = out.rfind(marker)
        if i >= 0:
            try:
                return json.loads(out[i:].strip())
            except Exception:                            # noqa: BLE001
                continue
    return {}


def _summarize(data: dict) -> dict:
    """给管理员看的脱敏摘要：不出现层名/通道名。"""
    layers = data.get("layers") or {}
    wid = data.get("watermark_id") or ""
    cleared = layers.get("cleared") or []
    damaged = layers.get("damaged") or []
    inferred = layers.get("inferred") or []
    tampered = bool(cleared or damaged or inferred)
    if not wid:
        summary = "没匹配到本系统的水印：可能是别处来的文件，或水印已被彻底清掉"
    elif tampered:
        summary = "能追到具体的人；但文件疑似被改动过（有痕迹被清除或损坏）"
    else:
        summary = "能追到具体的人；未发现被改动的痕迹"
    return {"matched": bool(wid), "tampered": tampered, "summary": summary}


# 溯源也是起子进程（最长 15 分钟、吃内存）。默认只允许 1 个同时跑，
# 与打标的"串行防打爆"保持一致；可用 WM_TRACE_CONCURRENCY 调整。
_trace_sem = threading.Semaphore(
    max(1, to_int(os.environ.get("WM_TRACE_CONCURRENCY"), 1) or 1))


def trace_run(tid: int, aid: int) -> None:
    with _trace_sem:
        return _trace_run(tid, aid)


def _trace_run(tid: int, aid: int) -> None:
    """网页上提交的可疑文件，直接在本机（云端）用该账号自己的密钥解码。"""
    with db() as c:
        row = c.execute("SELECT stored FROM traces WHERE id=?", (tid,)).fetchone()
    if not row:
        return
    t = ensure_tenant(aid)
    path = os.path.join(FILES_DIR, row["stored"])
    try:
        proc = subprocess.run(
            [_wm_python(), "decode_watermark.py", path, "--json", "--db", t["db"]],
            cwd=TOOL_DIR, env=wm_env(t), capture_output=True, text=True,
            timeout=900, encoding="utf-8", errors="replace")
        out = (proc.stdout or "") + "\n" + (proc.stderr or "")
    except subprocess.TimeoutExpired:
        proc, out = None, "解码超时（>15 分钟）"
    except Exception as exc:                             # noqa: BLE001
        proc, out = None, f"{type(exc).__name__}: {exc}"
    data = _parse_json_block(out) if proc is not None else {}
    wid = str(data.get("watermark_id") or "")
    qq = str((data.get("record") or {}).get("qq_number") or "")
    brief = _summarize(data) if data else {"matched": False, "tampered": False,
                                           "summary": "没解出结论：" + out[-120:]}
    with _lock, db() as c:
        c.execute("UPDATE traces SET status=?, result=?, brief=?, watermark_id=?, qq=?, "
                  "done_at=datetime('now') WHERE id=?",
                  ("done" if wid else "failed", out[-20000:],
                   json.dumps({k: brief.get(k) for k in ("matched", "tampered", "summary")},
                              ensure_ascii=False)[:600],
                   wid, qq, tid))


def wm_summary(aid: int) -> dict:
    with db() as c:
        rows = [dict(r) for r in c.execute(
            "SELECT status, COUNT(*) n FROM wm_jobs WHERE admin_id=? GROUP BY status",
            (aid,))]
    m = {r["status"]: r["n"] for r in rows}
    return {"pending": m.get("pending", 0) + m.get("running", 0),
            "done": m.get("done", 0), "failed": m.get("failed", 0)}


# ------------------------------------------------------------------ 存储

# ---------------------------------------------------------------- 成品保留策略
# 每个账号自己的设置（存 settings 表）：
#   ret_on          1/0        是否开启自动清理
#   ret_hours       72         生成后多少小时删除（**整数**小时，1~8760）
#   ret_at          03:00      每天几点执行（北京时间）
#   ret_only_claimed 1         只删已下载过的（没领过的先留着）
RET_DEFAULTS = {"ret_on": "0", "ret_hours": "72", "ret_at": "03:00",
                "ret_only_claimed": "1"}
BEIJING = timezone(timedelta(hours=8))     # 服务器多半是 UTC，用户说的时间按北京时间算


def ret_cfg(conn, aid: int) -> dict:
    out = dict(RET_DEFAULTS)
    for r in conn.execute("SELECT k,v FROM settings WHERE admin_id=?", (aid,)):
        if r["k"] in out:
            out[r["k"]] = r["v"]
    return out


def parse_sqlite_utc(s: str) -> float:
    """SQLite 的 datetime('now') 是 **UTC**，必须按 UTC 解析，
    否则在 UTC+8 的机器上会整体差 8 小时（多留或少删一批）。"""
    try:
        return calendar.timegm(time.strptime(s, "%Y-%m-%d %H:%M:%S"))
    except Exception:                                    # noqa: BLE001
        return 0.0


def purge_files(aid: int, hours: float, only_claimed: bool) -> tuple[int, int]:
    """删掉超过保留期的成品。返回 (删除个数, 释放字节)。"""
    cutoff = time.time() - max(0.0, float(hours)) * 3600
    with db() as c:
        rows = [dict(r) for r in c.execute(
            "SELECT id,stored,size,downloads,created_at FROM files WHERE admin_id=?",
            (aid,))]
    gone, freed = 0, 0
    for r in rows:
        ts = parse_sqlite_utc(r["created_at"] or "")
        if not ts or ts > cutoff:
            continue
        if only_claimed and not (r["downloads"] or 0):
            continue
        with _lock, db() as c:
            cur = c.execute("DELETE FROM files WHERE id=? AND admin_id=?",
                            (r["id"], aid))
            if cur.rowcount == 0:
                continue
        try:
            os.remove(os.path.join(FILES_DIR, r["stored"]))
        except OSError:
            pass
        gone += 1
        freed += r["size"] or 0
    return gone, freed


def retention_worker() -> None:
    """后台线程：每天到点（北京时间）跑一次清理。

    不用 cron、不依赖外部调度 —— 判据是"现在 HH:MM == 设定值，且今天还没跑过"。
    线程 30 秒醒一次，所以最迟 30 秒内会命中那一分钟。
    """
    while True:
        try:
            now = datetime.now(BEIJING)
            hhmm = now.strftime("%H:%M")
            today = now.strftime("%Y%m%d")
            with db() as c:
                aids = [r["id"] for r in c.execute("SELECT id FROM admins")]
                cfgs = {a: ret_cfg(c, a) for a in aids}
                done = {r["admin_id"]: r["v"] for r in c.execute(
                    "SELECT admin_id,v FROM settings WHERE k='ret_last'")}
            for aid, cfg in cfgs.items():
                if cfg.get("ret_on") != "1":
                    continue
                at = cfg.get("ret_at") or "03:00"
                # 用 "过了这个点就补跑"，而不是 "正好等于那一分钟" ——
                # 否则服务器重启/线程醒来晚 1 分钟，当天就整个错过了
                if hhmm < at:
                    continue
                if done.get(aid) == today:
                    continue
                gone, freed = purge_files(aid, to_int(cfg.get("ret_hours"), 72) or 72,
                                          cfg.get("ret_only_claimed", "1") == "1")
                with _lock, db() as c:
                    c.execute("INSERT INTO settings(admin_id,k,v) VALUES(?,'ret_last',?) "
                              "ON CONFLICT(admin_id,k) DO UPDATE SET v=excluded.v",
                              (aid, today))
                if gone:
                    print(f"[retention] 账号 {aid} 自动清理 {gone} 个成品，"
                          f"释放 {human(freed)}", flush=True)
        except Exception:                                # noqa: BLE001
            pass
        time.sleep(30)


def disk_info() -> dict:
    try:
        u = shutil.disk_usage(DATA_DIR)
        return {"total": u.total, "free": u.free, "used": u.used}
    except OSError:
        return {"total": 0, "free": 0, "used": 0}


def admin_usage(conn, aid: int) -> int:
    a = conn.execute("SELECT COALESCE(SUM(size),0) s FROM files WHERE admin_id=?",
                     (aid,)).fetchone()["s"]
    b = conn.execute("SELECT COALESCE(SUM(size),0) s FROM traces WHERE admin_id=?",
                     (aid,)).fetchone()["s"]
    return int(a) + int(b)


_last_gc = 0.0


def gc_expired(force: bool = False) -> int:
    """按保留期清掉过期的成品/工单，返回释放的字节数。

    **不清理就会把盘吃满，而盘满会让 SQLite 写失败、整个应用不可用** ——
    所以这是保护措施，不是"顺手优化"。
    """
    global _last_gc
    if KEEP_DAYS <= 0:                               # 默认关闭：不删任何东西
        return 0
    now = time.time()
    if not force and now - _last_gc < 1800:          # 半小时最多跑一次
        return 0
    _last_gc = now
    freed = 0
    try:
        with _lock, db() as c:
            rows = c.execute(
                "SELECT id, stored, size, downloads, last_at, created_at FROM files "
                "WHERE (downloads>0 AND julianday('now')-julianday(COALESCE(last_at,created_at))>?)"
                "   OR (downloads=0 AND julianday('now')-julianday(created_at)>?)",
                (KEEP_DAYS, KEEP_DAYS * 2)).fetchall()
            for r in rows:
                try:
                    os.remove(os.path.join(FILES_DIR, r["stored"]))
                except OSError:
                    pass
                c.execute("DELETE FROM files WHERE id=?", (r["id"],))
                freed += int(r["size"] or 0)
            c.execute("DELETE FROM traces WHERE status!='pending' "
                      "AND julianday('now')-julianday(COALESCE(done_at,created_at))>?",
                      (KEEP_DAYS * 2,))
    except Exception:                                    # noqa: BLE001
        return freed
    return freed


def check_room(conn, aid: int, add_bytes: int) -> tuple[int, str]:
    """上传前的空间校验。返回 (HTTP 码, 错误)。码 0 = 通过。

    只管两件事：**别把盘写满**（写满会连数据库一起坏），以及按需的每账号配额。
    """
    d = disk_info()
    if d["free"] and d["free"] - add_bytes < RESERVE_MB * MB:
        return 507, (f"服务器剩余空间不够（剩 {human(d['free'])}，"
                     f"要留 {RESERVE_MB}MB 给数据库）。请先删一些旧成品，"
                     f"或让我加对象存储")
    if QUOTA_MB:
        used = admin_usage(conn, aid)
        if used + add_bytes > QUOTA_MB * MB:
            return 413, (f"超出你的配额：已用 {human(used)} / 上限 {QUOTA_MB}MB。"
                         f"删掉旧交付再传")
    return 0, ""


# ------------------------------------------------------------------ HTTP

class Handler(BaseHTTPRequestHandler):
    server_version = "Roster/1.3"
    protocol_version = "HTTP/1.1"

    # ---------- 基础工具 ----------
    def _send(self, code: int, body: bytes, ctype: str = "application/json; charset=utf-8",
              extra: dict | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, obj, code: int = 200, extra: dict | None = None) -> None:
        self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                   "application/json; charset=utf-8", extra)

    def _err(self, code: int, msg: str) -> None:
        self._json({"ok": False, "error": msg}, code)

    def _body(self) -> dict:
        try:
            n = int(self.headers.get("Content-Length") or 0)
            if n <= 0 or n > 2_000_000:
                return _Body()
            d = json.loads(self.rfile.read(n).decode("utf-8") or "{}")
            # 顶层是数组/数字的 JSON 也是合法报文，但不是对象 —— 回空对象，
            # 让各端点走"参数缺失"的 400，而不是 b.get 上炸出 500
            return _Body(d) if isinstance(d, dict) else _Body()
        except Exception:                                # noqa: BLE001
            return _Body()

    def _raw(self, limit: int = MAX_UPLOAD) -> bytes | None:
        """读原始请求体（上传用）。超过上限返回 None，不把大包读进内存。"""
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return b""
        if n <= 0:
            return b""
        if n > limit:
            return None
        return self.rfile.read(n)

    def _cookie(self, name: str) -> str:
        raw = self.headers.get("Cookie") or ""
        for part in raw.split(";"):
            k, _, v = part.strip().partition("=")
            if k == name:
                return v
        return ""

    def _me(self) -> dict | None:
        parsed = sid_parse(self._cookie(COOKIE))
        if not parsed:
            return None
        uid, tag = parsed
        me = admin_row(uid)
        if not me or me["status"] != "active":
            return None
        if tag != pw_tag(me.get("pw_hash")):
            return None          # 密码改过了 → 这个会话作废
        return me

    def _need(self) -> dict | None:
        me = self._me()
        if not me:
            self._json({"ok": False, "need_login": True,
                        "initialized": self._inited()}, 401)
        return me

    def _need_owner(self) -> dict | None:
        me = self._need()
        if not me:
            return None
        if me["role"] != "owner":
            self._err(403, "只有站长能管理管理员账号")
            return None
        return me

    def _cookie_tail(self) -> str:
        """HTTPS 场景加 Secure；本地 http 不加，否则调试时 cookie 根本存不下。"""
        proto = (self.headers.get("X-Forwarded-Proto") or "").split(",")[0].strip().lower()
        return "; Secure" if proto == "https" else ""

    def _ip(self) -> str:
        """取"离我们最近的那一跳"看到的地址。

        X-Forwarded-For 形如 `client, proxy1, proxy2`，**第一段是客户端自己塞的**，
        可以随便伪造（轮换它就能完全绕过登录限速）。只有最后一跳是可信反代追加的。
        """
        xff = (self.headers.get("X-Forwarded-For") or "").strip()
        if xff:
            tail = xff.split(",")[-1].strip()
            if tail:
                return tail
        return self.client_address[0] or ""

    def log_message(self, fmt, *args):                   # 关掉默认日志，避免把 URL 写进日志
        return

    # ---------- 路由 ----------
    def do_GET(self):                                    # noqa: N802
        path = urllib.parse.urlparse(self.path).path
        if path in ("/", "/index.html"):
            return self._page()
        if path == "/api/health":
            return self._json({"ok": True, "version": VERSION})
        if path == "/api/version":
            return self._json({"ok": True, "version": VERSION,
                               "engine": engine_fingerprint(),
                               "initialized": self._inited()})
        # 这三个会泄露路径/账号量/磁盘水位，或消耗 30 秒 CPU —— 必须登录
        if path in ("/api/persist-check", "/api/env-probe", "/api/selftest"):
            me = self._need()
            if not me:
                return
            if path == "/api/persist-check":
                return self._json(self._persist_check(me))
            if path == "/api/env-probe":
                return self._json(env_probe())
            return self._json(self_test())
        # 公开：领取者自助登记页只想知道"还收不收"，不需要任何身份
        if path == "/api/join/info":
            return self._join_info()
        # 公开：凭不可猜的 token 下载自己的那一份（链接即凭据，可撤销）
        if path == "/download":
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            return self._download((q.get("t") or [""])[0])
        if path == "/api/claim/info":
            return self._claim_info()
        if path == "/api/state":
            me = self._need()
            if not me:
                return
            return self._json({"ok": True, **state(me)})
        if path == "/api/deliveries":
            me = self._need()
            if not me:
                return
            return self._dlv_list(me)
        if path == "/api/files":
            me = self._need()
            if not me:
                return
            return self._files_list(me)
        if path == "/api/storage":
            me = self._need()
            if not me:
                return
            return self._json({"ok": True, **self._storage(me)})
        if path == "/api/retention":
            me = self._need()
            if not me:
                return
            return self._ret_get(me)
        if path == "/api/wm/books":
            me = self._need()
            if not me:
                return
            return self._wm_books_list(me)
        if path == "/api/wm/jobs":
            me = self._need()
            if not me:
                return
            return self._wm_jobs_list(me)
        if path == "/api/form":
            me = self._need()
            if not me:
                return
            with db() as c:
                return self._json({"ok": True, "cfg": form_cfg(c, me["id"]),
                                   "fields": form_fields(c, me["id"]),
                                   "stats": field_stats(c, me["id"])})
        if path == "/api/blocklist":
            me = self._need()
            if not me:
                return
            return self._block_list(me)
        if path == "/api/trace":
            me = self._need()
            if not me:
                return
            return self._trace_list(me)
        m = re.fullmatch(r"/api/trace/(\d+)/file", path)
        if m:
            me = self._need()
            if not me:
                return
            return self._trace_file(me, int(m.group(1)))
        if path == "/api/export.csv":
            me = self._need()
            if not me:
                return
            return self._export_csv(me)
        if path == "/api/backup.json":
            me = self._need()
            if not me:
                return
            return self._export_json(me)
        if path == "/api/admins":
            me = self._need_owner()
            if not me:
                return
            return self._json({"ok": True, **state(me)})
        return self._err(404, "not found")

    def do_HEAD(self):                                   # noqa: N802
        """HEAD 复用 GET（_send 里已按 command 决定要不要写 body）。"""
        return self.do_GET()

    def do_OPTIONS(self):                                # noqa: N802
        """有些网关/浏览器会先发 OPTIONS，别让它掉到 501。"""
        self.send_response(204)
        self.send_header("Allow", "GET, HEAD, POST, PATCH, DELETE, OPTIONS")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _inited(self) -> bool:
        with db() as c:
            return c.execute("SELECT COUNT(*) c FROM admins").fetchone()["c"] > 0

    def _persist_check(self, me: dict | None = None) -> dict:
        """数据体检：重新部署前后各打一次，instance_id 不变 = 盘是持久的，数据没丢。"""
        gc_expired()
        try:
            n_adm = 0
            n_rec = 0
            with db() as c:
                n_adm = c.execute("SELECT COUNT(*) c FROM admins").fetchone()["c"]
                n_rec = c.execute("SELECT COUNT(*) c FROM recipients").fetchone()["c"]
            db_size = os.path.getsize(DB_PATH)
        except Exception:                                # noqa: BLE001
            n_adm = n_rec = db_size = 0
        files, fbytes = 0, 0
        for root, _dirs, names in os.walk(FILES_DIR):
            for nm in names:
                files += 1
                try:
                    fbytes += os.path.getsize(os.path.join(root, nm))
                except OSError:
                    pass
        d = disk_info()
        # 绝对路径只给站长看，普通管理员要它没用、泄露了反而给攻击者指路
        show_dir = bool(me and me.get("role") == "owner")
        return {"ok": True, "instance_id": instance_id(), "boot_at": BOOT_AT,
                "data_dir": DATA_DIR if show_dir else "",
                "admins": n_adm, "recipients": n_rec,
                "db_bytes": db_size, "files": files, "files_bytes": fbytes,
                "disk_total": d["total"], "disk_free": d["free"],
                "disk_total_text": human(d["total"]),
                "disk_free_text": human(d["free"]),
                "disk_free_pct": (round(100.0 * d["free"] / d["total"], 1)
                                  if d["total"] else 0.0),
                "quota_mb": QUOTA_MB, "reserve_mb": RESERVE_MB, "keep_days": KEEP_DAYS}

    def do_POST(self):                                   # noqa: N802
        path = urllib.parse.urlparse(self.path).path
        ip = self._ip()
        if path == "/api/setup":
            return self._setup(ip)
        if path == "/api/login":
            return self._login(ip)
        # 公开：领取者自助登记（无需登录，只能写不能读）
        if path == "/api/join":
            return self._join_submit(ip)
        # 公开：凭 QQ 查自己那份（需带该管理员的领取令牌 a=）
        if path == "/api/claim":
            return self._claim(ip)
        if path == "/api/logout":
            return self._json({"ok": True}, extra={
                "Set-Cookie": f"{COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"})
        me = self._need()
        if not me:
            return
        if path in ("/api/change-password", "/api/me/password"):
            return self._change_pw(me)
        if path == "/api/groups":
            return self._group_create(me)
        if path == "/api/recipients":
            return self._rec_add(me)
        if path == "/api/recipients/bulk":
            return self._rec_bulk(me)
        if path == "/api/receipt":
            return self._receipt(me)
        if path == "/api/deliveries":
            return self._dlv_create(me)
        if path == "/api/wm/books":
            return self._wm_book_upload(me)
        if path == "/api/wm/jobs":
            return self._wm_jobs_create(me)
        if path == "/api/form":
            return self._form_save(me)
        if path == "/api/fields":
            return self._field_create(me)
        if path == "/api/codes/generate":
            return self._codes_generate(me)
        if path == "/api/retention":
            return self._ret_save(me)
        if path == "/api/retention/run":
            return self._ret_run(me)
        if path == "/api/blocklist":
            return self._block_add(me)
        if path == "/api/upload":
            return self._upload(me)
        if path == "/api/trace":
            return self._trace_create(me)
        m = re.fullmatch(r"/api/trace/(\d+)/result", path)
        if m:
            return self._trace_result(me, int(m.group(1)))
        if path == "/api/restore":
            return self._restore(me)
        if path == "/api/admins":
            if me["role"] != "owner":
                return self._err(403, "只有站长能管理管理员账号")
            return self._admin_create(me)
        if path == "/api/me/token":
            return self._rotate_token(me)
        if path == "/api/me/claim-token":
            return self._rotate_claim_token(me)
        return self._err(404, "not found")

    def do_PATCH(self):                                  # noqa: N802
        path = urllib.parse.urlparse(self.path).path
        me = self._need()
        if not me:
            return
        m = re.fullmatch(r"/api/groups/(\d+)", path)
        if m:
            return self._group_update(me, int(m.group(1)))
        m = re.fullmatch(r"/api/recipients/(\d+)", path)
        if m:
            return self._rec_update(me, int(m.group(1)))
        m = re.fullmatch(r"/api/admins/(\d+)", path)
        if m:
            if me["role"] != "owner":
                return self._err(403, "只有站长能管理管理员账号")
            return self._admin_update(me, int(m.group(1)))
        m = re.fullmatch(r"/api/fields/(\d+)", path)
        if m:
            return self._field_update(me, int(m.group(1)))
        return self._err(404, "not found")

    def do_DELETE(self):                                 # noqa: N802
        path = urllib.parse.urlparse(self.path).path
        me = self._need()
        if not me:
            return
        m = re.fullmatch(r"/api/groups/(\d+)", path)
        if m:
            return self._group_delete(me, int(m.group(1)))
        m = re.fullmatch(r"/api/recipients/(\d+)", path)
        if m:
            return self._rec_delete(me, int(m.group(1)))
        m = re.fullmatch(r"/api/admins/(\d+)", path)
        if m:
            if me["role"] != "owner":
                return self._err(403, "只有站长能管理管理员账号")
            return self._admin_delete(me, int(m.group(1)))
        m = re.fullmatch(r"/api/deliveries/(\d+)", path)
        if m:
            return self._dlv_delete(me, int(m.group(1)))
        m = re.fullmatch(r"/api/files/(\d+)", path)
        if m:
            return self._file_delete(me, int(m.group(1)))
        m = re.fullmatch(r"/api/trace/(\d+)", path)
        if m:
            return self._trace_delete(me, int(m.group(1)))
        m = re.fullmatch(r"/api/fields/(\d+)", path)
        if m:
            return self._field_delete(me, int(m.group(1)))
        m = re.fullmatch(r"/api/wm/books/(\d+)", path)
        if m:
            return self._wm_book_delete(me, int(m.group(1)))
        m = re.fullmatch(r"/api/blocklist/(\d+)", path)
        if m:
            return self._block_delete(me, int(m.group(1)))
        return self._err(404, "not found")

    # ---------- 页面 ----------
    def _page(self):
        try:
            with open(INDEX_PATH, "rb") as f:
                body = f.read()
        except OSError:
            return self._send(500, b"index.html missing", "text/plain; charset=utf-8")
        # 不加 X-Frame-Options: DENY —— 应用可能被平台的预览面板用 iframe 打开，
        # DENY 会让它直接白屏（用户会以为是应用坏了）。页面本身有密码门禁。
        self._send(200, body, "text/html; charset=utf-8", {"Cache-Control": "no-store"})

    # ---------- 认证 ----------
    def _setup(self, ip: str):
        # 初始化码是"一次性口令"，但在设置完成前它是唯一防线 ——
        # 不限速就能被爆破（QA D-07：12 次全 403、永不 429）。
        # 双 key：IP 桶 10 次 + 全局桶 30 次。只做 IP 桶没用 —— XFF 是客户端
        # 可控的，轮换一下就换了个桶（就是 P1-1 那个教训）。全局桶兜住轮换攻击，
        # 上限放宽到 30，正常用户输错几次不会撞上；真被刷满，重启进程即清零（内存桶）。
        if too_many(ip) or too_many(SETUP_KEY, SETUP_LIMIT):
            return self._err(429, "尝试次数过多，请 10 分钟后再试")
        if self._inited():
            # 已初始化时这个端点什么都不做（也不校验初始化码），所以**不计数**：
            # 计入限速桶只会让"刷 setup"污染全局桶，对安全没有任何帮助。
            # 口径：初始化码校验失败 30 次/10min → 429；已初始化 → 恒 400。
            return self._err(400, "已经初始化过了，请直接登录")
        b = self._body()
        if body_str(b, "init_code").strip() != INIT_CODE:
            note_fail(ip)
            note_fail(SETUP_KEY)
            return self._err(403, "初始化码不对")
        pw = body_str(b, "password").strip()
        if len(pw) < 8:
            return self._err(400, "密码至少 8 位")
        username = body_str(b, "username", "admin").strip() or "admin"
        if not USER_RE.match(username):
            return self._err(400, "用户名只能用字母/数字/下划线/点/横线，3~24 位")
        # hash_pw 带随机 salt：**只算一次**，存库和签会话必须用同一个值，
        # 否则 pw_tag 对不上 → 刚建好账号就 401（v2.2.0 出过这个事故）
        h = hash_pw(pw)
        with _lock, db() as c:
            n = c.execute("SELECT COUNT(*) c FROM admins").fetchone()["c"]
            if n:
                return self._err(400, "已经初始化过了，请直接登录")
            cur = c.execute(
                "INSERT INTO admins(username,nickname,pw_hash,role,token,claim_token,"
                "status) VALUES(?,?,?,'owner',?,?,'active')",
                (username, body_str(b, "nickname", "我").strip()[:24] or "我",
                 h, new_token(), secrets.token_hex(6)))
            uid = cur.lastrowid
            # 老库里的孤儿数据（admin_id 默认 1）归到新 owner 名下
            c.execute("UPDATE groups SET admin_id=? WHERE admin_id=1", (uid,))
            c.execute("UPDATE recipients SET admin_id=? WHERE admin_id=1", (uid,))
        meta_set("admins_inited", "1")
        clear_fail(ip)
        clear_fail(SETUP_KEY)
        sid = make_sid(uid, h)
        self._json({"ok": True, "username": username}, extra={
            "Set-Cookie": f"{COOKIE}={sid}; Path=/; Max-Age={SESSION_TTL}; "
                          f"HttpOnly; SameSite=Lax{self._cookie_tail()}"})

    def _login(self, ip: str):
        b = self._body()
        username = body_str(b, "username").strip()
        # 双 key：IP + 用户名。伪造 XFF 轮换能骗过前者，但骗不过后者
        ukey = "u:" + (username.lower() or "__owner__")
        if too_many(ip) or too_many(ukey):
            return self._err(429, "尝试次数过多，请 10 分钟后再试")
        pw = body_str(b, "password").strip()
        with db() as c:
            if username:
                row = c.execute("SELECT * FROM admins WHERE username=?",
                                (username,)).fetchone()
            else:
                # 兼容只有一个账号的情况：不填用户名 = 站长的账号
                row = c.execute("SELECT * FROM admins WHERE role='owner' "
                                "ORDER BY id LIMIT 1").fetchone()
        if not row:
            note_fail(ip); note_fail(ukey)
            return self._err(403, "账号或密码不对")
        if row["status"] != "active":
            return self._err(403, "这个账号已被停用，请联系站长")
        if not check_pw(pw, row["pw_hash"]):
            note_fail(ip); note_fail(ukey)
            return self._err(403, "账号或密码不对")
        clear_fail(ip); clear_fail(ukey)
        with _lock, db() as c:
            c.execute("UPDATE admins SET last_login=datetime('now') WHERE id=?",
                      (row["id"],))
        sid = make_sid(row["id"], row["pw_hash"])
        self._json({"ok": True, "username": row["username"], "role": row["role"]}, extra={
            "Set-Cookie": f"{COOKIE}={sid}; Path=/; Max-Age={SESSION_TTL}; "
                          f"HttpOnly; SameSite=Lax{self._cookie_tail()}"})

    def _change_pw(self, me: dict):
        b = self._body()
        new = body_str(b, "new").strip()
        with db() as c:
            row = c.execute("SELECT pw_hash FROM admins WHERE id=?", (me["id"],)).fetchone()
        if not check_pw(body_str(b, "old").strip(), row["pw_hash"]):
            return self._err(403, "原密码不对")
        if len(new) < 8:
            return self._err(400, "新密码至少 8 位")
        h = hash_pw(new)
        with _lock, db() as c:
            c.execute("UPDATE admins SET pw_hash=? WHERE id=?", (h, me["id"]))
        # 旧会话全部作废；给当前浏览器换一个新的，用户不用重新登录
        sid = make_sid(me["id"], h)
        self._json({"ok": True, "relogin": True}, extra={
            "Set-Cookie": f"{COOKIE}={sid}; Path=/; Max-Age={SESSION_TTL}; "
                          f"HttpOnly; SameSite=Lax{self._cookie_tail()}"})

    def _rotate_token(self, me: dict):
        """换一个登记链接令牌（旧链接立即失效）。"""
        t = new_token()
        with _lock, db() as c:
            c.execute("UPDATE admins SET token=? WHERE id=?", (t, me["id"]))
        self._json({"ok": True, "token": t})

    def _rotate_claim_token(self, me: dict):
        """换领取链接令牌（旧领取链接立刻失效；已下载的文件不受影响）。"""
        t = secrets.token_hex(6)
        with _lock, db() as c:
            c.execute("UPDATE admins SET claim_token=? WHERE id=?", (t, me["id"]))
        self._json({"ok": True, "claim_token": t})

    # ---------- 管理员账号（只有 owner） ----------
    def _admin_create(self, me: dict):
        b = self._body()
        username = body_str(b, "username").strip()
        pw = body_str(b, "password").strip()
        if not USER_RE.match(username):
            return self._err(400, "用户名只能用字母/数字/下划线/点/横线，3~24 位")
        if len(pw) < 8:
            return self._err(400, "密码至少 8 位")
        try:
            with _lock, db() as c:
                cur = c.execute(
                    "INSERT INTO admins(username,nickname,pw_hash,role,token,claim_token,"
                    "status,created_by) VALUES(?,?,?,'admin',?,?,'active',?)",
                    (username, (b.get("nickname") or username).strip()[:24],
                     hash_pw(pw), new_token(), secrets.token_hex(6), me["id"]))
                aid = cur.lastrowid
        except sqlite3.IntegrityError:
            return self._err(400, "这个用户名已经有人用了")
        self._json({"ok": True, "id": aid})

    def _admin_update(self, me: dict, aid: int):
        b = self._body()
        with db() as c:
            row = c.execute("SELECT id,role FROM admins WHERE id=?", (aid,)).fetchone()
        if not row:
            return self._err(404, "账号不存在")
        if row["role"] == "owner":
            return self._err(400, "站长的账号只能自己改密码")
        fields, args = [], []
        if "nickname" in b:
            fields.append("nickname=?")
            args.append(body_str(b, "nickname").strip()[:24])
        if "status" in b:
            st = b.get("status")
            if st not in ("active", "disabled"):
                return self._err(400, "状态不合法")
            fields.append("status=?")
            args.append(st)
        if "password" in b:
            pw = body_str(b, "password").strip()
            if len(pw) < 8:
                return self._err(400, "密码至少 8 位")
            fields.append("pw_hash=?")
            args.append(hash_pw(pw))
        if not fields:
            return self._json({"ok": True})
        args.append(aid)
        with _lock, db() as c:
            c.execute(f"UPDATE admins SET {','.join(fields)} WHERE id=?", args)
        self._json({"ok": True})

    def _admin_delete(self, me: dict, aid: int):
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        if (q.get("confirm") or [""])[0] != "1":
            return self._err(400, "需要确认（confirm=1）")
        if aid == me["id"]:
            return self._err(400, "不能删除自己")
        with db() as c:
            row = c.execute("SELECT id,role,username FROM admins WHERE id=?",
                            (aid,)).fetchone()
        if not row:
            return self._err(404, "账号不存在")
        if row["role"] == "owner":
            return self._err(400, "站长账号不能被删除")
        # 先把他名下的磁盘文件收集出来（DB 删完就找不到了）
        with db() as c:
            stored = [r["stored"] for r in c.execute(
                "SELECT stored FROM files WHERE admin_id=? UNION ALL "
                "SELECT stored FROM traces WHERE admin_id=? UNION ALL "
                "SELECT stored FROM wm_books WHERE admin_id=?", (aid, aid, aid))]
            n_files = c.execute("SELECT COUNT(*) c FROM files WHERE admin_id=?",
                                (aid,)).fetchone()["c"]
        with _lock, db() as c:
            n_r = c.execute("SELECT COUNT(*) c FROM recipients WHERE admin_id=?",
                            (aid,)).fetchone()["c"]
            n_g = c.execute("SELECT COUNT(*) c FROM groups WHERE admin_id=?",
                            (aid,)).fetchone()["c"]
            c.execute("DELETE FROM recipients WHERE admin_id=?", (aid,))
            c.execute("DELETE FROM groups WHERE admin_id=?", (aid,))
            # 交付/成品/工单/母本/租户密钥一起清 —— 否则账号删了，
            # 他名下的 /download?t= 链接还能一直下载（评审 P2-6）
            c.execute("DELETE FROM files WHERE admin_id=?", (aid,))
            c.execute("DELETE FROM deliveries WHERE admin_id=?", (aid,))
            c.execute("DELETE FROM traces WHERE admin_id=?", (aid,))
            c.execute("DELETE FROM wm_books WHERE admin_id=?", (aid,))
            c.execute("DELETE FROM wm_jobs WHERE admin_id=?", (aid,))
            c.execute("DELETE FROM settings WHERE admin_id=?", (aid,))
            c.execute("DELETE FROM fields WHERE admin_id=?", (aid,))
            c.execute("DELETE FROM blocklist WHERE admin_id=?", (aid,))
            c.execute("DELETE FROM admins WHERE id=?", (aid,))
        for rel in stored:
            try:
                os.remove(os.path.join(FILES_DIR, rel))
            except OSError:
                pass
        shutil.rmtree(os.path.join(TENANT_DIR, str(aid)), ignore_errors=True)
        self._json({"ok": True, "deleted_recipients": n_r, "deleted_groups": n_g,
                    "deleted_files": n_files, "username": row["username"]})

    # ---------- 公开：领取者自助登记（只能写，读不到任何名单） ----------
    def _join_admin(self) -> dict | None:
        """登记链接带 a=<token>，决定这条登记进谁名下。"""
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        token = (q.get("a") or [""])[0].strip()
        with db() as c:
            if token:
                row = c.execute("SELECT id,username,nickname,token,status FROM admins "
                                "WHERE token=?", (token,)).fetchone()
                if row and row["status"] == "active":
                    return dict(row)
                return None
            row = c.execute("SELECT id,username,nickname,token,status FROM admins "
                            "WHERE role='owner' ORDER BY id LIMIT 1").fetchone()
            return dict(row) if row else None

    def _join_info(self):
        b = self._body() if self.command == "POST" else {}
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        token = (q.get("a") or [""])[0].strip() or body_str(b, "token").strip()
        if token:
            with db() as c:
                row = c.execute("SELECT id,nickname,status FROM admins WHERE token=?",
                                (token,)).fetchone()
                if not row:
                    return self._json({"ok": False, "open": False,
                                       "error": "登记链接无效，请向管理员要最新的链接"})
                if row["status"] != "active":
                    return self._json({"ok": False, "open": False,
                                       "error": "这个登记链接已停用"})
                cfg = form_cfg(c, row["id"])
                flds = [f for f in form_fields(c, row["id"]) if f["on_join"]]
            return self._json({"ok": True, "open": True, "who": row["nickname"],
                               "cfg": cfg, "fields": flds,
                               "note": "填写后等管理员确认，不会公开你的信息"})
        return self._json({"ok": True, "open": True,
                           "note": "填写后等管理员确认，不会公开你的信息"})

    def _join_submit(self, ip: str):
        if not join_allowed(ip):
            return self._err(429, "提交太频繁了，过一会儿再试")
        b = self._body()
        token = body_str(b, "token").strip()
        target = None
        with db() as c:
            if token:
                row = c.execute("SELECT id,nickname,status FROM admins WHERE token=?",
                                (token,)).fetchone()
                if not row:
                    return self._err(404, "登记链接无效，请向管理员要最新的链接")
                if row["status"] != "active":
                    return self._err(403, "这个登记链接已停用")
                target = dict(row)
            else:
                row = c.execute("SELECT id,nickname FROM admins WHERE role='owner' "
                                "ORDER BY id LIMIT 1").fetchone()
                target = dict(row) if row else None
            if not target:
                return self._err(400, "还没有管理员账号，暂时不能登记")
            cfg = form_cfg(c, target["id"])
            all_flds = form_fields(c, target["id"])

        qq = normalize_qq(body_str(b, "qq"))
        if not QQ_RE.match(qq):
            return self._err(400, "QQ 号要 5~12 位数字")
        # 邮箱现在可以整体关掉（cfg.email_on=0）；关掉就不存、不校验
        email = ""
        if cfg["email_on"] == "1":
            email = body_str(b, "email").strip()[:120] or f"{qq}@qq.com"
            if "@" not in email:
                return self._err(400, "邮箱格式不对（也可以留空，默认用 QQ 邮箱）")
        note = body_str(b, "note").strip()[:200] if cfg["note_on"] == "1" else ""

        join_flds = [f for f in all_flds if f["on_join"]]
        extra, err = clean_extra(b.get("extra") or {}, join_flds)
        if err:
            return self._err(400, err)

        with _lock, db() as c:
            if is_blocked(c, target["id"], qq):
                return self._json({"ok": True, "already": True})
            dup = c.execute("SELECT 1 FROM recipients WHERE admin_id=? AND qq=? LIMIT 1",
                            (target["id"], qq)).fetchone()
            if dup:
                # 不给"已登记/已发过/被封禁"的区别，避免被拿来探测名单
                return self._json({"ok": True, "already": True})
            c.execute("INSERT INTO recipients(admin_id,group_id,qq,email,note,status,source,extra) "
                      "VALUES(?,NULL,?,?,?,'new','self',?)",
                      (target["id"], qq, email, note, json.dumps(extra, ensure_ascii=False)))
        self._json({"ok": True, "already": False})

    # ---------- 分组 ----------
    def _group_create(self, me: dict):
        b = self._body()
        name = body_str(b, "name").strip()
        if not name:
            return self._err(400, "分组名不能为空")
        with _lock, db() as c:
            cur = c.execute("INSERT INTO groups(admin_id,name,note,sort) VALUES(?,?,?,?)",
                            (me["id"], name[:40], body_str(b, "note")[:200],
                             to_int(b.get("sort"), 0)))
            gid = cur.lastrowid
        self._json({"ok": True, "id": gid})

    def _group_update(self, me: dict, gid: int):
        b = self._body()
        fields, args = [], []
        if "name" in b:
            name = body_str(b, "name").strip()
            if not name:
                return self._err(400, "分组名不能为空")
            fields.append("name=?")
            args.append(name[:40])
        if "note" in b:
            fields.append("note=?")
            args.append(body_str(b, "note")[:200])
        if "sort" in b:
            sv = to_int(b.get("sort"), None)
            if sv is None:
                return self._err(400, "排序值要填数字")
            fields.append("sort=?")
            args.append(sv)
        if not fields:
            return self._json({"ok": True})
        args += [gid, me["id"]]
        with _lock, db() as c:
            cur = c.execute(f"UPDATE groups SET {','.join(fields)} "
                            f"WHERE id=? AND admin_id=?", args)
            if cur.rowcount == 0:
                return self._err(404, "分组不存在")
        self._json({"ok": True})

    def _group_delete(self, me: dict, gid: int):
        mode = (urllib.parse.parse_qs(
            urllib.parse.urlparse(self.path).query).get("mode") or ["keep"])[0]
        with _lock, db() as c:
            if group_owner(c, gid) != me["id"]:
                return self._err(404, "分组不存在")
            if mode == "delete":
                c.execute("DELETE FROM recipients WHERE group_id=? AND admin_id=?",
                          (gid, me["id"]))
            else:
                c.execute("UPDATE recipients SET group_id=NULL "
                          "WHERE group_id=? AND admin_id=?", (gid, me["id"]))
            c.execute("DELETE FROM groups WHERE id=? AND admin_id=?", (gid, me["id"]))
        self._json({"ok": True})

    # ---------- 名单 ----------
    def _rec_add(self, me: dict):
        b = self._body()
        raw_gid = b.get("group_id")
        gid = None if raw_gid in (None, "", "null") else to_int(raw_gid)
        if raw_gid not in (None, "", "null") and gid is None:
            return self._err(400, "分组 id 要填数字")
        if gid is not None:
            with db() as c:
                if group_owner(c, gid) != me["id"]:
                    return self._err(403, "这个分组不属于你")
        with db() as c:
            flds = [f["fkey"] for f in form_fields(c, me["id"])]
        rows, dup = parse_bulk(b.get("text") or "", flds)
        # 只加一个人时，面板里填的字段值优先（批量粘贴走第 4 列起）
        if len(rows) == 1 and isinstance(b.get("extra"), dict):
            ex = {k: str(v)[:100] for k, v in b["extra"].items()
                  if k in flds and str(v).strip()}
            if ex:
                rows[0]["extra"] = {**(rows[0].get("extra") or {}), **ex}
        if not rows:
            one = normalize_qq(body_str(b, "qq"))
            if QQ_RE.match(one):
                ex = b.get("extra") if isinstance(b.get("extra"), dict) else {}
                rows = [{"qq": one,
                         "email": guess_email(one, b.get("email") or ""),
                         "note": body_str(b, "note")[:200],
                         "extra": {k: str(v)[:100] for k, v in ex.items()
                                   if k in flds and str(v).strip()}}]
        if not rows:
            return self._err(400, "没有识别到有效 QQ 号（5~12 位数字）")
        added, skipped = 0, dup
        blocked_n = 0
        with _lock, db() as c:
            for r in rows:
                if is_blocked(c, me["id"], r["qq"]):
                    blocked_n += 1
                    continue
                # 未分组(group_id IS NULL)时唯一索引不生效（SQLite 里 NULL != NULL），
                # 必须在应用层自己查重，否则同一个 QQ 能无限重复入库
                dup_row = c.execute(
                    "SELECT 1 FROM recipients WHERE admin_id=? AND qq=? "
                    "AND group_id IS ? LIMIT 1", (me["id"], r["qq"], gid)).fetchone()
                if dup_row:
                    skipped += 1
                    continue
                try:
                    c.execute("INSERT INTO recipients(admin_id,group_id,qq,email,note,"
                              "source,extra) VALUES(?,?,?,?,?,'admin',?)",
                              (me["id"], gid, r["qq"], r["email"], r["note"],
                               json.dumps(r.get("extra") or {}, ensure_ascii=False)))
                    added += 1
                except sqlite3.IntegrityError:
                    skipped += 1
        self._json({"ok": True, "added": added, "skipped": skipped,
                    "blocked": blocked_n})

    def _rec_update(self, me: dict, rid: int):
        b = self._body()
        fields, args = [], []
        if "qq" in b:
            qq = normalize_qq(body_str(b, "qq"))
            if not QQ_RE.match(qq):
                return self._err(400, "QQ 号格式不对")
            fields.append("qq=?")
            args.append(qq)
        if "email" in b:
            fields.append("email=?")
            args.append(body_str(b, "email").strip()[:120])
        if "note" in b:
            fields.append("note=?")
            args.append(body_str(b, "note")[:200])
        if "status" in b:
            st = b.get("status")
            if st not in ("new", "sent", "banned"):
                return self._err(400, "状态不合法")
            fields.append("status=?")
            args.append(st)
        if "group_id" in b:
            raw_g = b.get("group_id")
            g = None if raw_g in (None, "", "null") else to_int(raw_g)
            if raw_g not in (None, "", "null") and g is None:
                return self._err(400, "分组 id 要填数字")
            if g is not None:
                with db() as c:
                    if group_owner(c, g) != me["id"]:
                        return self._err(403, "这个分组不属于你")
            fields.append("group_id=?")
            args.append(g)
        if isinstance(b.get("extra"), dict):
            # 合并：只更新传进来的键；传空字符串 = 清掉这个字段
            with db() as c:
                cur = c.execute("SELECT extra FROM recipients WHERE id=? AND admin_id=?",
                                (rid, me["id"])).fetchone()
            ex = parse_extra(cur["extra"] if cur else "{}")
            for k, v in b["extra"].items():
                if v is None or str(v).strip() == "":
                    ex.pop(str(k), None)
                else:
                    ex[str(k)] = str(v)[:100]
            fields.append("extra=?")
            args.append(json.dumps(ex, ensure_ascii=False))
        if not fields:
            return self._json({"ok": True})
        fields.append("updated_at=datetime('now')")
        args += [rid, me["id"]]
        try:
            with _lock, db() as c:
                cur = c.execute(f"UPDATE recipients SET {','.join(fields)} "
                                f"WHERE id=? AND admin_id=?", args)
                if cur.rowcount == 0:
                    return self._err(404, "记录不存在")
        except sqlite3.IntegrityError:
            return self._err(400, "这个 QQ 已经在同一个分组里了，换个分组或先删掉那条")
        self._json({"ok": True})

    def _rec_delete(self, me: dict, rid: int):
        with _lock, db() as c:
            cur = c.execute("DELETE FROM recipients WHERE id=? AND admin_id=?",
                            (rid, me["id"]))
            if cur.rowcount == 0:
                # 越权删别人的记录：以前回 {"ok": true}，既假成功又泄露"这条存在"
                return self._err(404, "记录不存在")
        self._json({"ok": True})

    def _rec_bulk(self, me: dict):
        b = self._body()
        ids = [int(x) for x in (b.get("ids") or []) if str(x).isdigit()]
        action = b.get("action")
        if not ids:
            return self._err(400, "没有选中记录")
        ph = ",".join("?" * len(ids))
        with _lock, db() as c:
            if action == "delete":
                c.execute(f"DELETE FROM recipients WHERE id IN ({ph}) AND admin_id=?",
                          ids + [me["id"]])
            elif action == "status":
                st = b.get("status")
                if st not in ("new", "sent", "banned"):
                    return self._err(400, "状态不合法")
                c.execute(f"UPDATE recipients SET status=?, updated_at=datetime('now') "
                          f"WHERE id IN ({ph}) AND admin_id=?", [st] + ids + [me["id"]])
            elif action == "move":
                g = b.get("group_id")
                g = int(g) if g not in (None, "", "null") else None
                if g is not None and group_owner(c, g) != me["id"]:
                    return self._err(403, "这个分组不属于你")
                for i in ids:
                    try:
                        c.execute("UPDATE recipients SET group_id=?, "
                                  "updated_at=datetime('now') "
                                  "WHERE id=? AND admin_id=?", (g, i, me["id"]))
                    except sqlite3.IntegrityError:
                        pass
            else:
                return self._err(400, "未知操作")
        self._json({"ok": True, "count": len(ids)})

    # ---------- 回执：把"已发出"的状态 + 水印ID 回填到台账 ----------
    def _receipt(self, me: dict):
        """桌面端 generate_and_send.py 跑完后，用 push_status.py 调这里回填。

        请求：{"rows":[{"qq":"123","watermark_id":"WM-...","status":"sent"}]}
        返回：{"ok":true,"updated":n,"unmatched":[...]}
        """
        b = self._body()
        rows = b.get("rows") or []
        if not isinstance(rows, list) or not rows:
            return self._err(400, "没有要回填的记录")
        updated, unmatched = 0, []
        with _lock, db() as c:
            for r in rows[:5000]:
                qq = normalize_qq(str(r.get("qq") or ""))
                wid = str(r.get("watermark_id") or "")[:64]
                st = r.get("status") or "sent"
                if st not in ("new", "sent", "banned"):
                    st = "sent"
                if not QQ_RE.match(qq):
                    continue
                cur = c.execute(
                    "UPDATE recipients SET status=?, watermark_id=?, "
                    "sent_at=datetime('now'), updated_at=datetime('now') "
                    "WHERE admin_id=? AND qq=? AND status!='banned'",
                    (st, wid, me["id"], qq))
                if cur.rowcount:
                    updated += cur.rowcount
                else:
                    unmatched.append(qq)
        self._json({"ok": True, "updated": updated, "unmatched": unmatched[:200],
                    "unmatched_count": len(unmatched)})

    def _ret_get(self, me: dict):
        with db() as c:
            cfg = ret_cfg(c, me["id"])
            n = c.execute("SELECT COUNT(*) c, COALESCE(SUM(size),0) s FROM files "
                          "WHERE admin_id=?", (me["id"],)).fetchone()
            claimed = c.execute("SELECT COUNT(*) c FROM files WHERE admin_id=? "
                                "AND downloads>0", (me["id"],)).fetchone()["c"]
            last = c.execute("SELECT v FROM settings WHERE admin_id=? AND k='ret_last'",
                             (me["id"],)).fetchone()
        self._json({"ok": True, "cfg": cfg,
                    "stat": {"files": n["c"], "bytes": n["s"],
                             "bytes_text": human(n["s"] or 0), "claimed": claimed},
                    "last_run": last["v"] if last else "",
                    "now_bj": datetime.now(BEIJING).strftime("%Y-%m-%d %H:%M")})

    def _ret_save(self, me: dict):
        b = self._body()
        cfg = {}
        cfg["ret_on"] = "1" if str(b.get("ret_on")) in ("1", "true", "on") else "0"
        hrs = b.get("ret_hours")
        hv = to_int(hrs, None)
        if hv is None:
            # 以前 "0.5" 会被 to_int 截成 0，再被 `or 72` 悄悄变成 72 ——
            # 用户以为设了半小时，实际是三天（QA D-09）。类型错就明说。
            return self._err(400, "保留时长要填整数小时（1~8760，例如 72 = 3 天）")
        if hv < 1 or hv > 24 * 365:
            return self._err(400, "保留时长要填 1~8760 小时（例如 72 = 3 天）")
        cfg["ret_hours"] = str(hv)
        at = body_str(b, "ret_at").strip()
        if not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", at):
            return self._err(400, "执行时间要写成 HH:MM（24 小时制，如 03:00）")
        cfg["ret_at"] = at
        cfg["ret_only_claimed"] = "1" if str(b.get("ret_only_claimed")) in ("1", "true", "on") else "0"
        with _lock, db() as c:
            for k, v in cfg.items():
                c.execute("INSERT INTO settings(admin_id,k,v) VALUES(?,?,?) "
                          "ON CONFLICT(admin_id,k) DO UPDATE SET v=excluded.v",
                          (me["id"], k, v))
        self._json({"ok": True, "cfg": cfg})

    def _ret_run(self, me: dict):
        """立刻按当前规则清理一次（不等定时）。"""
        b = self._body()
        with db() as c:
            cfg = ret_cfg(c, me["id"])
        raw = b.get("ret_hours")
        if raw not in (None, ""):
            # 别把非法值悄悄回落成 72：那是"删得比用户要求的多"，属于破坏性误动作
            hours = to_int(raw, None)
            if hours is None or hours < 1:
                return self._err(400, "保留时长要填整数小时（1~8760）")
        else:
            hours = to_int(cfg.get("ret_hours"), 72) or 72
        only = (b.get("ret_only_claimed") if b.get("ret_only_claimed") is not None
                else cfg.get("ret_only_claimed", "1"))
        gone, freed = purge_files(me["id"], hours, str(only) in ("1", "true", "on"))
        self._json({"ok": True, "deleted": gone, "freed": freed,
                    "freed_text": human(freed), "hours": hours,
                    "only_claimed": str(only) in ("1", "true", "on")})

    def _storage(self, me: dict) -> dict:
        gc_expired()
        d = disk_info()
        with db() as c:
            mine = admin_usage(c, me["id"])
            allf = c.execute("SELECT COALESCE(SUM(size),0) s FROM files").fetchone()["s"]
            n_files = c.execute("SELECT COUNT(*) c FROM files").fetchone()["c"]
        return {"disk_total": d["total"], "disk_free": d["free"],
                "disk_total_text": human(d["total"]), "disk_free_text": human(d["free"]),
                "disk_free_pct": round(100.0 * d["free"] / d["total"], 1) if d["total"] else 0.0,
                "my_bytes": mine, "my_text": human(mine),
                "all_files_bytes": int(allf), "all_files_text": human(allf),
                "n_files": n_files,
                "quota_mb": QUOTA_MB, "reserve_mb": RESERVE_MB, "keep_days": KEEP_DAYS}

    # ---------- 书库：上传母本 → 云端打标 ----------
    def _wm_books_list(self, me: dict):
        with db() as c:
            rows = [dict(r) for r in c.execute(
                "SELECT id,title,fname,size,created_at FROM wm_books WHERE admin_id=? "
                "ORDER BY id DESC", (me["id"],))]
            for r in rows:
                r["size_text"] = human(r["size"])
                agg = c.execute(
                    "SELECT COUNT(*) n, SUM(status='done') done, SUM(status='failed') bad "
                    "FROM wm_jobs WHERE book_id=?", (r["id"],)).fetchone()
                r["jobs"] = agg["n"] or 0
                r["done"] = agg["done"] or 0
                r["failed"] = agg["bad"] or 0
        self._json({"ok": True, "books": rows, "queue": wm_summary(me["id"])})

    def _wm_book_upload(self, me: dict):
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        data = self._raw(limit=200 * MB)
        if data is None:
            return self._err(413, "母本太大（上限 200MB）")
        if not data:
            return self._err(400, "空文件")
        name = safe_fname(urllib.parse.unquote(
            self.headers.get("X-Filename") or "book.epub"))
        if not name.lower().endswith(".epub"):
            return self._err(400, "只收 EPUB 母本")
        if data[:2] != b"PK":
            return self._err(400, "不是有效的 EPUB（zip 结构不对）")
        with db() as c:
            code, msg = check_room(c, me["id"], len(data))
        if code:
            return self._err(code, msg)
        title = ((q.get("title") or [""])[0].strip()
                 or os.path.splitext(name)[0])[:60]
        d = os.path.join(FILES_DIR, "wm", "books")
        os.makedirs(d, exist_ok=True)
        stored = os.path.join("wm", "books", f"{me['id']}_{secrets.token_hex(4)}.epub")
        with open(os.path.join(FILES_DIR, stored), "wb") as f:
            f.write(data)
        with _lock, db() as c:
            bid = c.execute("INSERT INTO wm_books(admin_id,title,fname,stored,size,sha256) "
                            "VALUES(?,?,?,?,?,?)",
                            (me["id"], title, name, stored, len(data),
                             hashlib.sha256(data).hexdigest())).lastrowid
        self._json({"ok": True, "id": bid, "title": title, "size_text": human(len(data))})

    def _wm_book_delete(self, me: dict, bid: int):
        with db() as c:
            row = c.execute("SELECT stored,admin_id FROM wm_books WHERE id=?",
                            (bid,)).fetchone()
            if not row or row["admin_id"] != me["id"]:
                return self._err(404, "这本书不在了")
            c.execute("DELETE FROM wm_books WHERE id=?", (bid,))
        try:
            os.remove(os.path.join(FILES_DIR, row["stored"]))
        except OSError:
            pass
        self._json({"ok": True})

    def _wm_jobs_create(self, me: dict):
        b = self._body()
        # 类型错配统一回 400（QA D-08）：`book_id:[1]` 这种直接 int() 会 TypeError→500
        bid = to_int(b.get("book_id"), None)
        if bid is None:
            return self._err(400, "book_id 要填数字")
        gid_raw = b.get("group_id")
        gid = None if gid_raw in (None, "", "null") else to_int(gid_raw, None)
        if gid_raw not in (None, "", "null") and gid is None:
            return self._err(400, "group_id 要填数字")
        with db() as c:
            book = c.execute("SELECT id,title,admin_id FROM wm_books WHERE id=?",
                             (bid,)).fetchone()
            if not book or book["admin_id"] != me["id"]:
                return self._err(404, "这本书不在了")
            sql = ("SELECT r.qq FROM recipients r WHERE r.admin_id=? "
                   "AND r.status != 'banned' "
                   "AND r.qq NOT IN (SELECT qq FROM blocklist WHERE admin_id=?) ")
            args = [me["id"], me["id"]]
            if gid is not None:
                sql += "AND r.group_id=? "
                args.append(gid)
            sql += "ORDER BY r.id"
            qqs = [r["qq"] for r in c.execute(sql, args)]
            if not qqs:
                return self._err(400, "这个分组里没有可打标的人（或被拉黑/封禁了）")
            did = c.execute("INSERT INTO deliveries(admin_id,title,note) VALUES(?,?,?)",
                            (me["id"], f"{book['title']}（云端打标）",
                             f"来自书库 book#{bid}")).lastrowid
            n = 0
            for qq in qqs:
                dup = c.execute(
                    "SELECT 1 FROM wm_jobs WHERE book_id=? AND qq=? "
                    "AND status IN ('pending','running','done') LIMIT 1",
                    (bid, qq)).fetchone()
                if dup:
                    continue
                c.execute("INSERT INTO wm_jobs(admin_id,book_id,delivery_id,qq) "
                          "VALUES(?,?,?,?)", (me["id"], bid, did, qq))
                n += 1
        if n == 0:
            with _lock, db() as c:
                c.execute("DELETE FROM deliveries WHERE id=? AND admin_id=?",
                          (did, me["id"]))
            return self._json({"ok": True, "delivery_id": 0, "queued": 0,
                               "skipped": len(qqs), "total": len(qqs),
                               "queue": wm_summary(me["id"]),
                               "msg": "这些人之前都已经排过队或生成过了，没有新增任务"})
        os.makedirs(dlv_dir(did), exist_ok=True)
        _wm_wake.set()
        self._json({"ok": True, "delivery_id": did, "queued": n,
                    "skipped": len(qqs) - n, "total": len(qqs),
                    "queue": wm_summary(me["id"])})

    def _wm_jobs_list(self, me: dict):
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        did = (q.get("delivery_id") or [""])[0]
        with db() as c:
            sql = ("SELECT id,book_id,delivery_id,qq,status,watermark_id,error,"
                   "created_at,done_at FROM wm_jobs WHERE admin_id=? ")
            args: list = [me["id"]]
            if did.isdigit():
                sql += "AND delivery_id=? "
                args.append(int(did))
            sql += "ORDER BY id DESC LIMIT 300"
            rows = [dict(r) for r in c.execute(sql, args)]
        for r in rows:
            if r["error"]:
                r["error"] = r["error"][-300:]
        self._json({"ok": True, "jobs": rows, "queue": wm_summary(me["id"])})

    # ---------- 黑名单：挡住"再发/再领/再登记"，但**不删记录**（溯源要用） ----------
    def _block_list(self, me: dict):
        with db() as c:
            rows = [dict(r) for r in c.execute(
                "SELECT id,qq,reason,created_at FROM blocklist WHERE admin_id=? "
                "ORDER BY id DESC", (me["id"],))]
        self._json({"ok": True, "blocked": rows})

    def _block_add(self, me: dict):
        b = self._body()
        reason = body_str(b, "reason").strip()[:100]
        items = []
        for part in re.split(r"[\s,，;；、]+", str(body_str(b, "qq"))):
            q = normalize_qq(part)
            if QQ_RE.match(q):
                items.append(q)
        if not items:
            return self._err(400, "QQ 号要 5~12 位数字")
        added = 0
        with _lock, db() as c:
            for q in items:
                try:
                    c.execute("INSERT INTO blocklist(admin_id,qq,reason) VALUES(?,?,?)",
                              (me["id"], q, reason))
                    added += 1
                except sqlite3.IntegrityError:
                    pass
                # 台账里那条改成"封禁"，但**行不删** —— 已发出去的那份还要靠它溯源
                c.execute("UPDATE recipients SET status='banned', "
                          "updated_at=datetime('now') WHERE admin_id=? AND qq=?",
                          (me["id"], q))
        self._json({"ok": True, "added": added, "total": len(items)})

    def _block_delete(self, me: dict, bid: int):
        with db() as c:
            row = c.execute("SELECT qq,admin_id FROM blocklist WHERE id=?",
                            (bid,)).fetchone()
            if not row or row["admin_id"] != me["id"]:
                return self._err(404, "黑名单里没有这条")
            c.execute("DELETE FROM blocklist WHERE id=?", (bid,))
            c.execute("UPDATE recipients SET status='new', updated_at=datetime('now') "
                      "WHERE admin_id=? AND qq=? AND status='banned'",
                      (me["id"], row["qq"]))
        self._json({"ok": True})

    # ---------- 登记 / 领取表单的字段配置（每个账号独立） ----------
    def _form_save(self, me: dict):
        b = self._body()
        cfg = b.get("cfg") or {}
        with _lock, db() as c:
            for k in ("qq_label", "email_label", "note_label"):
                if k in cfg:
                    v = str(cfg[k] or "").strip()[:20]
                    sset(c, me["id"], k, v or FORM_DEFAULT[k])
            for k in ("email_on", "note_on"):
                if k in cfg:
                    sset(c, me["id"], k, "1" if str(cfg[k]).lower() in
                         ("1", "true", "on", "yes") else "0")
            out = form_cfg(c, me["id"])
        self._json({"ok": True, "cfg": out})

    # ---------- 暗号批量生成（按分组 / 选中 / 全部） ----------
    def _codes_generate(self, me: dict):
        b = self._body()
        # 同 D-08：`field_id:"1 OR 1=1"` 直接 int() 会 ValueError→500
        fid = to_int(b.get("field_id"), None)
        if fid is None:
            return self._err(400, "field_id 要填数字")
        scope = body_str(b, "scope", "group").strip()
        with db() as c:
            row = c.execute("SELECT * FROM fields WHERE id=? AND admin_id=?",
                            (fid, me["id"])).fetchone()
            if not row:
                return self._err(404, "字段不存在")
            f = dict(row)
            sql = ("SELECT id,qq,extra FROM recipients WHERE admin_id=? "
                   "AND status!='banned' ")
            args: list = [me["id"]]
            if scope == "selected":
                ids = [int(x) for x in (b.get("ids") or []) if str(x).isdigit()]
                if not ids:
                    return self._err(400, "没有选中任何人")
                sql += "AND id IN (%s) " % ",".join("?" * len(ids))
                args += ids
            elif scope == "group":
                gid = b.get("group_id")
                if gid in (None, "", "null"):
                    sql += "AND group_id IS NULL "
                else:
                    gnum = to_int(gid, None)
                    if gnum is None:
                        return self._err(400, "group_id 要填数字")
                    sql += "AND group_id=? "
                    args.append(gnum)
            elif scope != "all":
                return self._err(400, "范围不合法")
            sql += "AND qq NOT IN (SELECT qq FROM blocklist WHERE admin_id=?) ORDER BY id"
            args.append(me["id"])
            rows = [dict(r) for r in c.execute(sql, args)]

        fkey = f["fkey"]
        try:
            length = int(b.get("gen_len") if b.get("gen_len") not in (None, "") else f["gen_len"])
        except (TypeError, ValueError):
            length = 8
        charset = (b.get("gen_charset") or f["gen_charset"] or "alnum")
        prefix = b.get("gen_prefix")
        if prefix is None:
            prefix = f["gen_prefix"] or ""
        only_empty = b.get("only_empty") is not False

        used = set()
        for r in rows:
            v = str(parse_extra(r["extra"]).get(fkey) or "").strip()
            if v:
                used.add(v)

        out, gen, skip = [], 0, 0
        with _lock, db() as c:
            for r in rows:
                ex = parse_extra(r["extra"])
                cur = str(ex.get(fkey) or "").strip()
                if cur and only_empty:
                    skip += 1
                    out.append({"qq": r["qq"], "code": cur, "existing": True})
                    continue
                code = ""
                for _ in range(30):                      # 冲突就重抽
                    cand = gen_code(length, charset, str(prefix))
                    if cand not in used:
                        code = cand
                        break
                if not code:
                    skip += 1
                    continue
                used.add(code)
                ex[fkey] = code
                c.execute("UPDATE recipients SET extra=?, updated_at=datetime('now') "
                          "WHERE id=? AND admin_id=?",
                          (json.dumps(ex, ensure_ascii=False), r["id"], me["id"]))
                gen += 1
                out.append({"qq": r["qq"], "code": code, "existing": False})
        self._json({"ok": True, "field": f["label"], "fkey": fkey,
                    "generated": gen, "skipped": skip, "rows": out})

    def _field_create(self, me: dict):
        b = self._body()
        key = body_str(b, "fkey").strip().lower()
        if not FKEY_RE.match(key):
            return self._err(400, "内部键要小写字母开头、字母数字下划线，2~20 位（如 code）")
        label = body_str(b, "label").strip()[:20]
        if not label:
            return self._err(400, "填个显示名（如「暗号」）")
        kind = b.get("kind") if b.get("kind") in ("text", "number", "email") else "text"
        gen = b.get("gen") if b.get("gen") in ("user", "manual", "random") else "user"
        try:
            glen = max(GEN_MIN, min(GEN_MAX, int(b.get("gen_len") or 8)))
        except (TypeError, ValueError):
            glen = 8
        gcs = b.get("gen_charset") if b.get("gen_charset") in _GEN_CHARSETS else "alnum"
        gpre = body_str(b, "gen_prefix").strip()[:8]
        with _lock, db() as c:
            n = c.execute("SELECT COUNT(*) c FROM fields WHERE admin_id=?",
                          (me["id"],)).fetchone()["c"]
            if n >= MAX_FIELDS:
                return self._err(400, f"最多 {MAX_FIELDS} 个自定义字段")
            try:
                fid = c.execute(
                    "INSERT INTO fields(admin_id,fkey,label,kind,required,on_join,"
                    "on_claim,sort,gen,gen_len,gen_charset,gen_prefix) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                    (me["id"], key, label, kind,
                     1 if b.get("required") else 0,
                     0 if str(b.get("on_join")).lower() in ("0", "false", "off") else 1,
                     1 if b.get("on_claim") else 0,
                     to_int(b.get("sort"), 0),
                     gen, glen, gcs, gpre)).lastrowid
            except sqlite3.IntegrityError:
                return self._err(400, "这个内部键已经用过了")
        self._json({"ok": True, "id": fid})

    def _field_update(self, me: dict, fid: int):
        b = self._body()
        with db() as c:
            row = c.execute("SELECT admin_id FROM fields WHERE id=?", (fid,)).fetchone()
        if not row or row["admin_id"] != me["id"]:
            return self._err(404, "字段不存在")
        fields, args = [], []
        if "label" in b:
            label = body_str(b, "label").strip()[:20]
            if not label:
                return self._err(400, "显示名不能为空")
            fields.append("label=?")
            args.append(label)
        if "kind" in b and b["kind"] in ("text", "number", "email"):
            fields.append("kind=?")
            args.append(b["kind"])
        for k in ("required", "on_join", "on_claim"):
            if k in b:
                fields.append(f"{k}=?")
                args.append(1 if str(b[k]).lower() in ("1", "true", "on") else 0)
        if b.get("gen") in ("user", "manual", "random"):
            fields.append("gen=?")
            args.append(b["gen"])
        if "gen_len" in b:
            try:
                glen = max(GEN_MIN, min(GEN_MAX, int(b.get("gen_len") or 8)))
            except (TypeError, ValueError):
                glen = 8
            fields.append("gen_len=?")
            args.append(glen)
        if b.get("gen_charset") in _GEN_CHARSETS:
            fields.append("gen_charset=?")
            args.append(b["gen_charset"])
        if "gen_prefix" in b:
            fields.append("gen_prefix=?")
            args.append(body_str(b, "gen_prefix").strip()[:8])
        if "sort" in b:
            fields.append("sort=?")
            args.append(int(b["sort"] or 0))
        if not fields:
            return self._json({"ok": True})
        args.append(fid)
        with _lock, db() as c:
            c.execute(f"UPDATE fields SET {','.join(fields)} WHERE id=?", args)
        self._json({"ok": True})

    def _field_delete(self, me: dict, fid: int):
        with db() as c:
            row = c.execute("SELECT admin_id,fkey FROM fields WHERE id=?", (fid,)).fetchone()
        if not row or row["admin_id"] != me["id"]:
            return self._err(404, "字段不存在")
        with _lock, db() as c:
            c.execute("DELETE FROM fields WHERE id=?", (fid,))
        self._json({"ok": True})

    # ---------- 交付：上传成品 + 领取链接（严格按账号隔离） ----------
    def _dlv_create(self, me: dict):
        b = self._body()
        title = body_str(b, "title").strip()
        if not title:
            return self._err(400, "填个书名 / 批次名")
        with _lock, db() as c:
            did = c.execute("INSERT INTO deliveries(admin_id,title,note) VALUES(?,?,?)",
                            (me["id"], title[:60],
                             body_str(b, "note")[:200])).lastrowid
        os.makedirs(dlv_dir(did), exist_ok=True)
        self._json({"ok": True, "id": did})

    def _dlv_list(self, me: dict):
        gc_expired()
        with db() as c:
            rows = [dict(r) for r in c.execute(
                "SELECT d.id,d.title,d.note,d.created_at,"
                "(SELECT COUNT(*) FROM files f WHERE f.delivery_id=d.id) AS n_files,"
                "(SELECT COUNT(*) FROM files f WHERE f.delivery_id=d.id "
                " AND f.downloads>0) AS n_taken,"
                "(SELECT COALESCE(SUM(f.size),0) FROM files f "
                " WHERE f.delivery_id=d.id) AS bytes "
                "FROM deliveries d WHERE d.admin_id=? ORDER BY d.id DESC", (me["id"],))]
        for r in rows:
            r["size_text"] = human(r["bytes"])
        self._json({"ok": True, "deliveries": rows, "storage": self._storage(me)})

    def _dlv_delete(self, me: dict, did: int):
        with db() as c:
            row = c.execute("SELECT admin_id FROM deliveries WHERE id=?", (did,)).fetchone()
            if not row or row["admin_id"] != me["id"]:
                return self._err(404, "交付不存在")
            c.execute("DELETE FROM files WHERE delivery_id=? AND admin_id=?", (did, me["id"]))
            c.execute("DELETE FROM deliveries WHERE id=? AND admin_id=?", (did, me["id"]))
        shutil.rmtree(dlv_dir(did), ignore_errors=True)
        self._json({"ok": True})

    def _files_list(self, me: dict):
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        did = (q.get("delivery_id") or [""])[0]
        with db() as c:
            sql = ("SELECT f.id,f.qq,f.fname,f.size,f.token,f.downloads,f.last_at,"
                   "f.watermark_id,f.created_at,"
                   "(SELECT 1 FROM recipients r WHERE r.admin_id=f.admin_id "
                   " AND r.qq=f.qq LIMIT 1) AS in_roster "
                   "FROM files f WHERE f.admin_id=? ")
            args: list = [me["id"]]
            if did.isdigit():
                sql += "AND f.delivery_id=? "
                args.append(int(did))
            sql += "ORDER BY f.qq"
            rows = [dict(r) for r in c.execute(sql, args)]
        for r in rows:
            r["size_text"] = human(r["size"])
        self._json({"ok": True, "files": rows})

    def _store_file(self, me: dict, did: int, qq: str, fname: str, blob: bytes) -> str:
        """落盘 + 入库。同一交付里同一个 QQ 再上传 = 覆盖（链接不变）。"""
        st = dlv_dir(did)
        os.makedirs(st, exist_ok=True)
        ext = os.path.splitext(fname)[1].lower() or ".epub"
        digest = hashlib.sha256(blob).hexdigest()
        with db() as c:
            old = c.execute("SELECT id,token,stored FROM files WHERE delivery_id=? AND qq=?",
                            (did, qq)).fetchone()
        token = old["token"] if old else secrets.token_hex(10)
        stored_name = f"{qq}_{token[:8]}{ext}"
        path = os.path.join(st, stored_name)
        with open(path, "wb") as f:
            f.write(blob)
        rel = os.path.relpath(path, FILES_DIR)
        with _lock, db() as c:
            if old:
                c.execute("UPDATE files SET fname=?,stored=?,size=?,sha256=?,"
                          "created_at=datetime('now') WHERE id=?",
                          (fname, rel, len(blob), digest, old["id"]))
                return "replaced"
            c.execute("INSERT INTO files(admin_id,delivery_id,qq,token,fname,stored,"
                      "size,sha256) VALUES(?,?,?,?,?,?,?,?)",
                      (me["id"], did, qq, token, fname, rel, len(blob), digest))
            return "added"

    def _upload(self, me: dict):
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        did = (q.get("delivery_id") or [""])[0]
        if not did.isdigit():
            return self._err(400, "缺 delivery_id")
        did = int(did)
        with db() as c:
            row = c.execute("SELECT admin_id FROM deliveries WHERE id=?", (did,)).fetchone()
        if not row or row["admin_id"] != me["id"]:
            return self._err(404, "交付不存在")
        data = self._raw()
        if data is None:
            return self._err(413, "单次上传上限 80MB，请分批或压缩后再传")
        if not data:
            return self._err(400, "空文件")
        gc_expired()
        with db() as c:
            code, msg = check_room(c, me["id"], len(data))
        if code:
            return self._err(code, msg)
        is_zip = (q.get("zip") or [""])[0] == "1"
        qq_hint = normalize_qq((q.get("qq") or [""])[0])
        added = replaced = 0
        skipped: list[str] = []
        if is_zip:
            try:
                zf = zipfile.ZipFile(io.BytesIO(data))
            except Exception:                            # noqa: BLE001
                return self._err(400, "不是有效的 zip 包")
            total_out = 0
            for info in zf.infolist():
                if info.is_dir() or info.file_size <= 0:
                    continue
                name = safe_fname(info.filename)
                if not name.lower().endswith(FILE_EXTS):
                    continue
                qq = qq_from_name(name) or qq_hint
                if not QQ_RE.match(qq):
                    skipped.append(name)
                    continue
                # 先按 header 粗筛，再按实际读出的字节硬截断（防伪造尺寸 / 防 zip 炸弹）
                if info.file_size > MAX_ZIP_ENTRY or total_out + info.file_size > MAX_ZIP_TOTAL:
                    skipped.append(name)
                    continue
                try:
                    with zf.open(info) as fh:
                        blob = fh.read(MAX_ZIP_ENTRY + 1)     # 多读 1 字节用于判超限
                except Exception:                        # noqa: BLE001
                    skipped.append(name)
                    continue
                if len(blob) > MAX_ZIP_ENTRY:
                    skipped.append(name)
                    continue
                total_out += len(blob)
                if total_out > MAX_ZIP_TOTAL:
                    return self._err(413, "压缩包解压后太大（超过 1GB），请分几个小包传")
                if self._store_file(me, did, qq, name, blob) == "added":
                    added += 1
                else:
                    replaced += 1
        else:
            name = safe_fname(urllib.parse.unquote(self.headers.get("X-Filename") or "file.epub"))
            if not name.lower().endswith(BOOK_EXTS):
                # 之前只认文件名里的 QQ，不看扩展名 → .exe 也能入库并被公开下载
                return self._err(400, "只收书籍文件：" + "、".join(BOOK_EXTS))
            if name.lower().endswith(".epub") and data[:2] != b"PK":
                return self._err(400, "这个 .epub 不是有效的 EPUB（zip 结构不对）")
            qq = qq_hint or qq_from_name(name)
            if not QQ_RE.match(qq):
                return self._err(400, "认不出这个文件是谁的：请把文件名改成 QQ 号"
                                      "（如 123456789.epub），或在链接里带上 ?qq=")
            if self._store_file(me, did, qq, name, data) == "added":
                added = 1
            else:
                replaced = 1
        if not (added or replaced):
            return self._err(400, f"包里没找到可用的文件（需要 {', '.join(FILE_EXTS)}，"
                                  f"文件名里要带 QQ 号）")
        self._json({"ok": True, "added": added, "replaced": replaced,
                    "skipped": skipped[:20], "skipped_count": len(skipped)})

    def _file_delete(self, me: dict, fid: int):
        with db() as c:
            row = c.execute("SELECT stored,admin_id FROM files WHERE id=?", (fid,)).fetchone()
            if not row or row["admin_id"] != me["id"]:
                return self._err(404, "文件不存在")
            c.execute("DELETE FROM files WHERE id=? AND admin_id=?", (fid, me["id"]))
        try:
            os.remove(os.path.join(FILES_DIR, row["stored"]))
        except OSError:
            pass
        self._json({"ok": True})

    # ---------- 领取（公开，但只按 token / 只按该管理员的名单） ----------
    def _claim_info(self):
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        token = (q.get("a") or [""])[0].strip()
        if not token:
            return self._json({"ok": False, "open": False, "error": "领取链接不完整"})
        with db() as c:
            ad = c.execute("SELECT id,nickname,status FROM admins WHERE claim_token=?",
                           (token,)).fetchone()
            if not ad:
                return self._json({"ok": False, "open": False,
                                   "error": "领取链接无效，请向发书的人要最新的链接"})
            if ad["status"] != "active":
                return self._json({"ok": False, "open": False, "error": "这个领取链接已停用"})
            n = c.execute("SELECT COUNT(*) c FROM files WHERE admin_id=?",
                          (ad["id"],)).fetchone()["c"]
            cfg = form_cfg(c, ad["id"])
            flds = [f for f in form_fields(c, ad["id"]) if f["on_claim"]]
        self._json({"ok": True, "open": n > 0, "who": ad["nickname"],
                    "n_files": n, "cfg": cfg, "fields": flds,
                    "note": "输入你的 QQ 号就能拿到属于自己的那一份" if n
                            else "还没有放书，稍后再来"})

    def _claim(self, ip: str):
        if not join_allowed(ip, limit=20, window=3600):
            return self._err(429, "查得太频繁了，过一会儿再试")
        b = self._body()
        token = body_str(b, "a").strip()
        qq = normalize_qq(body_str(b, "qq"))
        if not token:
            return self._err(400, "领取链接不完整")
        if not QQ_RE.match(qq):
            return self._err(400, "QQ 号要 5~12 位数字")
        with db() as c:
            ad = c.execute("SELECT id,nickname,status FROM admins WHERE claim_token=?",
                           (token,)).fetchone()
            if not ad or ad["status"] != "active":
                return self._err(404, "领取链接无效，请向发书的人要最新的链接")
            f = c.execute("SELECT token,fname,size FROM files WHERE admin_id=? AND qq=? "
                          "ORDER BY id DESC LIMIT 1", (ad["id"], qq)).fetchone()
            # 需要"暗号"的字段：领取时必须与登记时填的一致
            need = [x for x in form_fields(c, ad["id"]) if x["on_claim"]]
            row = c.execute("SELECT extra FROM recipients WHERE admin_id=? AND qq=? "
                            "LIMIT 1", (ad["id"], qq)).fetchone()
            blocked = is_blocked(c, ad["id"], qq)
        if blocked:
            return self._json({"ok": True, "ready": False,
                               "msg": "这份书暂时不能领取，请联系发书的人。"})
        if f and need:
            try:
                stored = json.loads((row or {})["extra"] or "{}") if row else {}
            except Exception:                            # noqa: BLE001
                stored = {}
            got = b.get("extra") if isinstance(b.get("extra"), dict) else {}
            for x in need:
                want = str(stored.get(x["fkey"]) or "").strip()
                if not want:
                    continue                             # 名单里没有这个值，就不校验
                if str(got.get(x["fkey"]) or "").strip() != want:
                    return self._err(403, f"「{x['label']}」不对，拿不到这份书")
        if not f:
            # 不区分"没有这个人"和"还没上传"，避免被拿来探测名单
            return self._json({"ok": True, "ready": False,
                               "msg": "还没有你的书，或还没放上来。请联系发书的人。"})
        self._json({"ok": True, "ready": True, "token": f["token"],
                    "name": f["fname"], "size_text": human(f["size"])})

    def _download(self, token: str):
        token = (token or "").strip()
        if not re.fullmatch(r"[0-9a-f]{8,40}", token):
            return self._err(404, "链接无效")
        with db() as c:
            row = c.execute("SELECT * FROM files WHERE token=?", (token,)).fetchone()
        if not row:
            return self._err(404, "链接无效或已被撤销")
        path = os.path.join(FILES_DIR, row["stored"])
        if not os.path.isfile(path):
            return self._err(410, "这个文件已被删除")
        size = os.path.getsize(path)
        name = row["fname"] or "book.epub"
        ext = os.path.splitext(name)[1].lower()
        ctype = {".epub": "application/epub+zip", ".pdf": "application/pdf",
                 ".zip": "application/zip"}.get(ext, "application/octet-stream")
        with _lock, db() as c:
            c.execute("UPDATE files SET downloads=downloads+1, last_at=datetime('now') "
                      "WHERE id=?", (row["id"],))
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(size))
        self.send_header("Content-Disposition",
                         "attachment; filename*=UTF-8''" + urllib.parse.quote(name))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command == "HEAD":
            return
        with open(path, "rb") as f:
            while True:
                chunk = f.read(64 * 1024)
                if not chunk:
                    break
                self.wfile.write(chunk)

    # ---------- 溯源工单：网页上传 → 本机 worker 解码 → 结果回网页 ----------
    def _trace_create(self, me: dict):
        data = self._raw()
        if data is None:
            return self._err(413, "单次上传上限 80MB")
        if not data:
            return self._err(400, "空文件")
        gc_expired()
        with db() as c:
            code, msg = check_room(c, me["id"], len(data))
        if code:
            return self._err(code, msg)
        name = safe_fname(urllib.parse.unquote(
            self.headers.get("X-Filename") or "suspect.epub"))
        with _lock, db() as c:
            tid = c.execute("INSERT INTO traces(admin_id,stored,fname,size,status) "
                            "VALUES(?,?,?,?,'pending')",
                            (me["id"], "", name, len(data))).lastrowid
        d = trace_dir(me["id"])
        os.makedirs(d, exist_ok=True)
        path = os.path.join(d, f"{tid}.bin")
        with open(path, "wb") as f:
            f.write(data)
        with _lock, db() as c:
            c.execute("UPDATE traces SET stored=? WHERE id=?",
                      (os.path.relpath(path, FILES_DIR), tid))
        # 云端直接解码（不再需要本地 worker）
        threading.Thread(target=trace_run, args=(tid, me["id"]), daemon=True).start()
        self._json({"ok": True, "id": tid, "auto": True})

    def _trace_list(self, me: dict):
        """按角色投影：
        · 站长(owner)：全部 —— 包括命中了哪几层、清洗到什么程度
        · 管理员(admin)：只给「文件是否疑似被改过」+「这份属于谁」，**不给层信息**
          （层细节会暴露我们打在哪几层，属于不该下发的实现细节）
        """
        owner = me["role"] == "owner"
        with db() as c:
            rows = [dict(r) for r in c.execute(
                "SELECT id,fname,size,status,result,brief,watermark_id,qq,created_at,"
                "done_at,claimed_at FROM traces WHERE admin_id=? ORDER BY id DESC LIMIT 50",
                (me["id"],))]
            for r in rows:
                r["size_text"] = human(r["size"])
                # 用本地已登记的 WM-ID 反查"这是谁的"，不用等本机
                if r["watermark_id"]:
                    hit = c.execute("SELECT qq FROM recipients WHERE admin_id=? AND "
                                    "watermark_id=? LIMIT 1",
                                    (me["id"], r["watermark_id"])).fetchone()
                    if hit:
                        r["qq"] = hit["qq"]
        if not owner:
            for r in rows:
                try:
                    br = json.loads(r.get("brief") or "{}")
                except Exception:                        # noqa: BLE001
                    br = {}
                r["result"] = ""                          # 原始报告只在站长这边
                r["watermark_id"] = ""
                r["summary"] = br.get("summary") or ""
                r["tampered"] = bool(br.get("tampered"))
                r["matched"] = bool(br.get("matched"))
        self._json({"ok": True, "traces": rows, "can_see_layers": owner})

    def _trace_file(self, me: dict, tid: int):
        with db() as c:
            row = c.execute("SELECT stored,admin_id,fname,status FROM traces WHERE id=?",
                            (tid,)).fetchone()
        if not row or row["admin_id"] != me["id"]:
            return self._err(404, "工单不存在")
        path = os.path.join(FILES_DIR, row["stored"])
        if not os.path.isfile(path):
            return self._err(410, "文件已被删除")
        # 标记"已被 worker 取走"，避免多台机器重复解码
        with _lock, db() as c:
            c.execute("UPDATE traces SET claimed_at=datetime('now') WHERE id=?", (tid,))
        with open(path, "rb") as f:
            body = f.read()
        self._send(200, body, "application/octet-stream", {
            "Content-Disposition": 'attachment; filename="s' + str(tid) + '.bin"',
            "Cache-Control": "no-store"})

    def _trace_result(self, me: dict, tid: int):
        b = self._body()
        with db() as c:
            row = c.execute("SELECT admin_id FROM traces WHERE id=?", (tid,)).fetchone()
        if not row or row["admin_id"] != me["id"]:
            return self._err(404, "工单不存在")
        wid = body_str(b, "watermark_id")[:64]
        report = body_str(b, "report")[:20000]
        qq = normalize_qq(str(body_str(b, "qq")))
        brief = b.get("brief") if isinstance(b.get("brief"), dict) else {}
        brief_s = json.dumps({k: brief.get(k) for k in
                              ("matched", "tampered", "summary")},
                             ensure_ascii=False)[:600]
        status = "done" if wid else "failed"
        with _lock, db() as c:
            c.execute("UPDATE traces SET status=?,result=?,brief=?,watermark_id=?,qq=?,"
                      "done_at=datetime('now') WHERE id=?",
                      (status, report, brief_s, wid, qq, tid))
        self._json({"ok": True, "status": status})

    def _trace_delete(self, me: dict, tid: int):
        with db() as c:
            row = c.execute("SELECT stored,admin_id FROM traces WHERE id=?", (tid,)).fetchone()
            if not row or row["admin_id"] != me["id"]:
                return self._err(404, "工单不存在")
            c.execute("DELETE FROM traces WHERE id=? AND admin_id=?", (tid, me["id"]))
        try:
            os.remove(os.path.join(FILES_DIR, row["stored"]))
        except OSError:
            pass
        self._json({"ok": True})

    # ---------- 导出 ----------
    def _export_csv(self, me: dict):
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        gid = (q.get("group_id") or [""])[0]
        with db() as c:
            sql = ("SELECT r.qq, r.email, r.note, r.status, r.watermark_id, r.extra, "
                   "g.name AS gname FROM recipients r "
                   "LEFT JOIN groups g ON g.id=r.group_id WHERE r.admin_id=? ")
            args: list = [me["id"]]
            if gid.isdigit():
                sql += "AND r.group_id=? "
                args.append(int(gid))
            sql += "AND r.qq NOT IN (SELECT qq FROM blocklist WHERE admin_id=?) "
            args.append(me["id"])
            sql += "ORDER BY r.id"
            rows = [dict(r) for r in c.execute(sql, args)]
            gname = ""
            if gid.isdigit():
                row = c.execute("SELECT name FROM groups WHERE id=? AND admin_id=?",
                                (int(gid), me["id"])).fetchone()
                gname = row["name"] if row else ""
        with db() as c:
            flds = form_fields(c, me["id"])
        buf = io.StringIO()
        w = csv.writer(buf)
        # 前 4 列与 generate_and_send.load_recipients 完全兼容；后面的列会被它忽略
        w.writerow(["qq_number", "email", "note", "status", "watermark_id", "group"]
                   + [f["label"] for f in flds])
        for r in rows:
            try:
                ex = json.loads(r.get("extra") or "{}")
            except Exception:                            # noqa: BLE001
                ex = {}
            w.writerow([r["qq"], r["email"], r["note"], r["status"],
                        r["watermark_id"] or "", r["gname"] or ""]
                       + [ex.get(f["fkey"], "") for f in flds])
        body = ("\ufeff" + buf.getvalue()).encode("utf-8")   # BOM：Excel 直接打开不乱码
        name = re.sub(r'[\\/:*?"<>|]+', "_", gname) or "all"
        self._send(200, body, "text/csv; charset=utf-8", {
            "Content-Disposition":
                f"attachment; filename=\"recipients_{urllib.parse.quote(name)}.csv\"",
            "Cache-Control": "no-store"})

    def _export_json(self, me: dict):
        """默认只备份自己名下；owner 加 ?all=1 可整站备份（含账号，不含明文密码）。"""
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        whole = (q.get("all") or [""])[0] == "1" and me["role"] == "owner"
        with db() as c:
            if whole:
                admins = [dict(r) for r in c.execute(
                    "SELECT id,username,nickname,role,status,created_at,token FROM admins")]
                groups = [dict(r) for r in c.execute("SELECT * FROM groups ORDER BY sort,id")]
                recs = [dict(r) for r in c.execute("SELECT * FROM recipients ORDER BY id")]
            else:
                admins = []
                groups = [dict(r) for r in c.execute(
                    "SELECT * FROM groups WHERE admin_id=? ORDER BY sort,id", (me["id"],))]
                recs = [dict(r) for r in c.execute(
                    "SELECT * FROM recipients WHERE admin_id=? ORDER BY id", (me["id"],))]
        body = json.dumps({"version": 3, "exported_at": int(time.time()),
                           "scope": "all" if whole else "self",
                           "admin": me["username"],
                           "admins": admins, "groups": groups, "recipients": recs},
                          ensure_ascii=False, indent=1).encode("utf-8")
        self._send(200, body, "application/json; charset=utf-8", {
            "Content-Disposition": 'attachment; filename="roster-backup.json"',
            "Cache-Control": "no-store"})

    def _restore(self, me: dict):
        """恢复 = 追加到**当前账号**名下（不覆盖、不跨账号）。"""
        b = self._body()
        if not isinstance(b, dict) or not b:
            return self._err(400, "备份文件格式不对（不是合法的 JSON 对象）")
        if "groups" not in b and "recipients" not in b:
            return self._err(400, "这份文件不像是本系统的备份（缺少 groups / recipients）")
        groups = b.get("groups") or []
        recs = b.get("recipients") or []
        if not isinstance(groups, list) or not isinstance(recs, list):
            return self._err(400, "备份文件格式不对")
        gmap, n_g, n_r = {}, 0, 0
        with _lock, db() as c:
            for g in groups[:500]:
                cur = c.execute("INSERT INTO groups(admin_id,name,note,sort) "
                                "VALUES(?,?,?,?)",
                                (me["id"], str(g.get("name") or "未命名")[:40],
                                 str(g.get("note") or "")[:200],
                                 int(g.get("sort") or 0)))
                gmap[g.get("id")] = cur.lastrowid
                n_g += 1
            for r in recs[:20000]:
                qq = normalize_qq(str(r.get("qq") or ""))
                if not QQ_RE.match(qq):
                    continue
                try:
                    c.execute("INSERT INTO recipients(admin_id,group_id,qq,email,note,"
                              "status,watermark_id) VALUES(?,?,?,?,?,?,?)",
                              (me["id"], gmap.get(r.get("group_id")), qq,
                               str(r.get("email") or "")[:120],
                               str(r.get("note") or "")[:200],
                               r.get("status") if r.get("status") in
                               ("new", "sent", "banned") else "new",
                               str(r.get("watermark_id") or "")[:64]))
                    n_r += 1
                except sqlite3.IntegrityError:
                    pass
        self._json({"ok": True, "groups": n_g, "recipients": n_r})


for _m in ("do_GET", "do_POST", "do_PATCH", "do_DELETE"):
    setattr(Handler, _m, _guard(getattr(Handler, _m)))


def main() -> None:
    init_db()
    gc_expired(force=True)
    # 重启自愈：中断的任务退回队列、没出结果的工单重跑
    n_job = recover_jobs()
    n_trc = recover_traces()
    port = int(os.environ.get("PORT") or 8080)
    threading.Thread(target=wm_worker, daemon=True).start()
    threading.Thread(target=retention_worker, daemon=True).start()
    if n_job or n_trc:
        print(f"[recover] 恢复 {n_job} 个打标任务、{n_trc} 个溯源工单", flush=True)
    if n_job:
        _wm_wake.set()
    srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    srv.daemon_threads = True
    print(f"[roster] v{VERSION} listening on 0.0.0.0:{port}  db={DB_PATH}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
