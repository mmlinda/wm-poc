# -*- coding: utf-8 -*-
"""映射表存储：优先 SQLCipher 全库加密，回退 cryptography 字段加密，最后明文+警告。

加密优先级：
  1) sqlcipher3   —— AES-256 全库加密（推荐，pip install sqlcipher3）
  2) cryptography —— Fernet 字段级加密 qq_number / email
  3) 明文          —— 仅用于本地自测，会在启动时打印醒目警告
"""
from __future__ import annotations

import hashlib
import hmac
import os
import shutil
import time
import sqlite3

from config import DB_PATH, DB_KEY

_ENCRYPTION_MODE = None      # 'sqlcipher' | 'field' | 'plain'
_FERNET = None


def _init_fernet():
    global _FERNET
    try:
        from cryptography.fernet import Fernet
    except ImportError:
        return None
    key = hashlib.sha256(DB_KEY.encode()).digest()
    import base64
    return Fernet(base64.urlsafe_b64encode(key))


def encryption_mode() -> str:
    global _ENCRYPTION_MODE, _FERNET
    if _ENCRYPTION_MODE:
        return _ENCRYPTION_MODE
    try:
        import sqlcipher3  # noqa: F401
        _ENCRYPTION_MODE = "sqlcipher"
    except ImportError:
        _FERNET = _init_fernet()
        _ENCRYPTION_MODE = "field" if _FERNET else "plain"
    if _ENCRYPTION_MODE == "plain":
        print("[!] 警告：未安装 sqlcipher3 / cryptography，QQ 号与邮箱将**明文**存储。")
        print("    安装其一后再运行：pip install sqlcipher3   或   pip install cryptography")
    return _ENCRYPTION_MODE


SQLITE_HEADER = b"SQLite format 3\x00"


def _dict_factory(cursor, row):
    """通用行工厂。

    不能用 sqlite3.Row：装上 sqlcipher3 之后连接返回的是 sqlcipher3 的 Cursor，
    sqlite3.Row 会抛「argument 1 must be sqlite3.Cursor」，而这个异常在 GUI 的
    子线程里被吞掉后就表现为「溯源一直卡住」。
    """
    return {d[0]: row[i] for i, d in enumerate(cursor.description)}


def is_encrypted_file(db_path: str) -> bool | None:
    """判断数据库文件是否已加密（SQLCipher 文件头不是标准 SQLite 头）。

    返回 None 表示文件不存在。装了 sqlcipher3 之后，历史上生成的**明文库**
    会被当成加密库打开而失败，这里用来区分这两种情况。
    """
    if not os.path.isfile(db_path) or os.path.getsize(db_path) < 16:
        return None
    with open(db_path, "rb") as f:
        return f.read(16) != SQLITE_HEADER


def backup(db_path: str = DB_PATH, keep: int = 10) -> str:
    """分发前自动备份数据库，保留最近 keep 份。

    没有这个东西是会出事的：映射表里的密钥是**唯一**的溯源凭据，
    库一旦丢失，之前分发的所有文件就再也查不到人（无法从文件反推密钥，
    这是安全性设计使然）。曾经因为跑测试直接删库，导致老副本全部失联。
    """
    if not os.path.isfile(db_path):
        return ""
    bak_dir = os.path.join(os.path.dirname(os.path.abspath(db_path)), "backups")
    os.makedirs(bak_dir, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    dst = os.path.join(bak_dir, f"mapping-{stamp}.db")
    try:
        shutil.copy2(db_path, dst)
    except OSError:
        return ""
    try:
        olds = sorted(f for f in os.listdir(bak_dir)
                      if f.startswith("mapping-") and f.endswith(".db"))
        for f in olds[:-keep]:
            os.remove(os.path.join(bak_dir, f))
    except OSError:
        pass
    return dst


def connect(db_path: str = DB_PATH):
    """打开数据库（首次调用会自动建表）。

    兼容性：若本机装了 sqlcipher3 但现有库是明文（历史遗留），自动回退明文打开
    并给出迁移指引，避免"装了加密库之后什么都读不出来"。
    """
    os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
    mode = encryption_mode()

    if mode == "sqlcipher":
        encrypted = is_encrypted_file(db_path)
        if encrypted is False:
            print("[!] 检测到 sqlcipher3，但现有数据库仍是明文（历史遗留）。")
            print("    已按明文打开；执行 `python migrate_db.py` 可一键迁移为加密库。")
            conn = sqlite3.connect(db_path, timeout=15)
        else:
            from sqlcipher3 import dbapi2 as sqlcipher
            conn = sqlcipher.connect(db_path, timeout=15)
            conn.execute(f"PRAGMA key = '{DB_KEY}'")
            try:
                conn.execute("SELECT count(*) FROM sqlite_master").fetchone()
            except Exception as exc:                     # noqa: BLE001
                conn.close()
                if encrypted:
                    raise RuntimeError(
                        "数据库已加密，但 DB_KEY 不正确，无法打开。\n"
                        "请检查 .env 里的 DB_KEY 是否与创建时一致。") from exc
                raise
    else:
        conn = sqlite3.connect(db_path, timeout=15)
    conn.row_factory = _dict_factory
    init_db(conn)
    return conn


def init_db(conn) -> None:
    """建表 + 升级老库。

    **顺序很重要**：必须先 `_migrate()`（给老库 ALTER 补列）再执行 schema.sql。
    反过来的话，schema.sql 里新增的 `CREATE INDEX ... (qq_hash)` 会在列还不存在时
    执行，老库直接抛 `no such column: qq_hash` —— 即"升级后连旧库都打不开"。
    全新库无所谓（表由 schema.sql 建），老库必须走这个顺序。
    """
    schema_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "schema.sql")
    with open(schema_path, "r", encoding="utf-8") as f:
        schema_text = f.read()
    _migrate(conn)                      # 1) 老库补列（表不存在时内部静默跳过）
    conn.executescript(schema_text)     # 2) 建表/建索引（IF NOT EXISTS）
    _backfill_lookup(conn)              # 3) 历史记录补确定性检索列（索引已就位）
    conn.commit()


# 旧库补列：schema.sql 只对新建库生效，已存在的库要靠 ALTER TABLE 跟上
_ADD_COLUMNS = (
    ("trace_logs", "layers_alive", "TEXT"),
    ("trace_logs", "layers_cleared", "TEXT"),
    ("trace_logs", "clean_ops", "TEXT"),
    ("distributions", "qq_hash", "TEXT"),
    ("distributions", "email_hash", "TEXT"),
)


def _migrate(conn) -> None:
    for table, col, decl in _ADD_COLUMNS:
        try:
            cols = [r["name"] for r in conn.execute(f"PRAGMA table_info({table})")]
        except Exception:                                # noqa: BLE001
            continue
        if col not in cols:
            try:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")
            except Exception:                            # noqa: BLE001
                pass


def _backfill_lookup(conn) -> None:
    """给历史记录补上确定性检索列（一次性；之后是 no-op）。

    field 加密模式用的是 Fernet（随机 IV）：同一明文每次密文都不同，
    因此 `WHERE qq_number = enc(q)` **永远匹配不到任何行** ——
    查重（会重复发信）、按 QQ 删除（静默删 0 条）、按 QQ 检索会全部失效。
    等值查询必须有一个确定性的键，这里在连接时补齐。

    性能与失败处理（重要）：
      · **一次连接内跑完**：一条 SELECT 取全部待补行，再在同一个事务里批量 UPDATE，
        不是"每次连接补 5000 条"。20 万条约需十几秒到几十秒。
      · **失败行保持 NULL 并计数**：解密失败/字段异常的记录会跳过并打印条数，
        下次连接自动重试；不会因为中间一条坏数据就整批放弃。
      · **可跳过**：`WM_SKIP_BACKFILL=1` 时不回填（例如已知库很大、想先手动跑）。
      · 想提前做、不想在分发时踩到，可显式调用 `db.backfill_lookup()` 或
        `python migrate_db.py --backfill`。
    """
    if os.environ.get("WM_SKIP_BACKFILL") == "1":
        return
    try:
        rows = conn.execute(
            "SELECT id, qq_number, email FROM distributions "
            "WHERE qq_hash IS NULL OR email_hash IS NULL").fetchall()
    except Exception:                                    # noqa: BLE001
        return                                  # 表还不存在（全新库）
    if not rows:
        return
    failed = 0
    for r in rows:
        try:
            conn.execute(
                "UPDATE distributions SET qq_hash=?, email_hash=? WHERE id=?",
                (lookup_hash(dec(r["qq_number"])),
                 lookup_hash(dec(r["email"])), r["id"]))
        except Exception:                                # noqa: BLE001
            failed += 1
    try:
        conn.commit()
    except Exception:                                    # noqa: BLE001
        pass
    msg = f"[√] 已为 {len(rows) - failed} 条历史记录补齐检索列（qq_hash / email_hash）"
    if failed:
        msg += f"；{failed} 条失败（下次连接会重试）"
    print(msg)


def backfill_lookup(db_path: str | None = None, verbose: bool = True) -> int:
    """显式执行回填并报告结果，返回**仍未补齐**的条数（0 = 全部就绪）。

    `connect()` 本来就会自动回填（除非 `WM_SKIP_BACKFILL=1`）。本函数用于
    想在批量分发**之前**先把这一步做完、并拿到明确计数与耗时的场景：

        python -c "import db; db.backfill_lookup()"

    若返回非 0，说明有记录的解密一直失败（数据可疑），需要人工看一眼，
    而不是继续分发 —— 那些行按 QQ 查重是不生效的。
    """
    import time as _t
    t0 = _t.time()
    conn = connect(db_path or DB_PATH)          # connect 内部即完成回填
    left = conn.execute(
        "SELECT COUNT(*) c FROM distributions "
        "WHERE qq_hash IS NULL OR email_hash IS NULL").fetchone()["c"]
    conn.close()
    if verbose:
        print(f"[√] 检索列回填检查完成：剩余待补 {left} 条，耗时 {_t.time() - t0:.1f}s")
        if left:
            print("    ⚠ 仍有记录未补齐 → 那些记录的按 QQ 查重/检索不生效，"
                  "请检查其 qq_number 是否能正常解密")
    return left


def lookup_hash(value: str | None) -> str:
    """确定性检索哈希（**等值查询专用**，不用于展示）。

    必须确定性，否则 field 加密模式（Fernet 随机 IV）下无法做等值匹配。
    用 HMAC-SHA256(DB_KEY, 明文) 而不是裸哈希：QQ 号空间有限、可枚举，
    不加密钥的哈希能被彩虹表反查。
    """
    if value is None:
        value = ""
    return hmac.new(DB_KEY.encode(), str(value).strip().encode("utf-8"),
                    hashlib.sha256).hexdigest()[:32]


# ------------------------------------------------------------------ 字段加密

def enc(value: str) -> str:
    """写入前加密隐私字段（SQLCipher 模式下无需加密，原样返回）。"""
    if value is None:
        return ""
    if encryption_mode() == "field" and _FERNET is not None:
        return _FERNET.encrypt(str(value).encode()).decode()
    return str(value)


def dec(value: str) -> str:
    if not value:
        return ""
    if encryption_mode() == "field" and _FERNET is not None:
        try:
            return _FERNET.decrypt(value.encode()).decode()
        except Exception:                                # noqa: BLE001
            return value      # 早期明文记录，兼容读取
    return value


# ------------------------------------------------------------------ 常用查询

def all_keys(conn, book_id: int | None = None):
    """取出所有已分发记录的候选密钥（解码时逐个尝试）。"""
    sql = ("SELECT watermark_id, chaos_seed, chaos_mu, css_key, lsb_key "
           "FROM distributions WHERE chaos_seed IS NOT NULL")
    args: tuple = ()
    if book_id:
        sql += " AND book_id=?"
        args = (book_id,)
    rows = conn.execute(sql, args).fetchall()
    out = []
    for r in rows:
        # 必须包含各通道的派生密钥：attr / opf / zip 三层用的不是数据库里
        # 那三个基础密钥，而是 channel_key() 派生的。少了它们，真实溯源时
        # 这三层永远解不出来（测试里用 keys.all_keys() 才全中，掩盖了问题）。
        pairs = [(r["chaos_seed"], r["chaos_mu"]),
                 _pair(r["css_key"]), _pair(r["lsb_key"])]
        try:
            from core import keys as K
            kobj = K.WatermarkKeys(r["watermark_id"], r["chaos_seed"],
                                   r["chaos_mu"], r["css_key"], r["lsb_key"])
            pairs += list(kobj.all_keys())
        except Exception:                                # noqa: BLE001
            pass
        for pair in pairs:
            if pair and pair[0] is not None and pair[1] is not None \
                    and pair not in out:
                out.append(pair)
    return out


def keys_for_watermark(conn, watermark_id: str) -> list[tuple[float, float]]:
    """只取某一条记录的密钥（含各通道派生）。

    层体检要用：全量密钥随分发人数线性增长（200 人 ≈ 1200 组），
    逐层逐个尝试会让体检从 3 秒拖到 17 秒。先定位到具体水印 ID 之后，
    只需要这一条的 6 组密钥。
    """
    r = conn.execute(
        "SELECT watermark_id, chaos_seed, chaos_mu, css_key, lsb_key "
        "FROM distributions WHERE watermark_id=?", (watermark_id,)).fetchone()
    if not r:
        return []
    pairs = [(r["chaos_seed"], r["chaos_mu"]),
             _pair(r["css_key"]), _pair(r["lsb_key"])]
    try:
        from core import keys as K
        kobj = K.WatermarkKeys(r["watermark_id"], r["chaos_seed"],
                               r["chaos_mu"], r["css_key"], r["lsb_key"])
        pairs += list(kobj.all_keys())
    except Exception:                                    # noqa: BLE001
        pass
    out = []
    for p in pairs:
        if p and p[0] is not None and p[1] is not None and p not in out:
            out.append(p)
    return out


def _pair(text: str | None):
    if not text:
        return None
    try:
        a, b = str(text).split(",")[:2]
        return (float(a), float(b))
    except (ValueError, AttributeError):
        return None


def find_by_watermark(conn, watermark_id: str):
    row = conn.execute("SELECT * FROM distributions WHERE watermark_id=?",
                       (watermark_id,)).fetchone()
    if not row:
        return None
    d = dict(row)
    d["qq_number"] = dec(d.get("qq_number") or "")
    d["email"] = dec(d.get("email") or "")
    return d


def stats(conn, batch_id: str | None = None) -> dict:
    where, args = "", ()
    if batch_id:
        where, args = " WHERE batch_id=?", (batch_id,)
    out = {}
    out["total"] = conn.execute(f"SELECT COUNT(*) c FROM distributions{where}", args).fetchone()["c"]
    for st in ("pending", "sent", "failed", "revoked"):
        w = (where + " AND" if where else " WHERE") + " status=?"
        out[st] = conn.execute(f"SELECT COUNT(*) c FROM distributions{w}", args + (st,)).fetchone()["c"]
    out["zw_ok"] = conn.execute(
        f"SELECT COUNT(*) c FROM distributions{where + ' AND' if where else ' WHERE'} zero_width_ok=1",
        args).fetchone()["c"]
    out["img_ok"] = conn.execute(
        f"SELECT COUNT(*) c FROM distributions{where + ' AND' if where else ' WHERE'} image_qim_ok=1",
        args).fetchone()["c"]
    out["css_ok"] = conn.execute(
        f"SELECT COUNT(*) c FROM distributions{where + ' AND' if where else ' WHERE'} css_ok=1",
        args).fetchone()["c"]
    return out
