-- EPUB 隐形水印分发 · 映射表结构
-- 隐私字段（qq_number / email）在 SQLCipher 模式下由 AES-256 全库加密保护；
-- 未装 SQLCipher 时由 db.py 做字段级加密（需要 cryptography），否则明文 + 警告。

CREATE TABLE IF NOT EXISTS books (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    original_filename TEXT,
    file_hash TEXT,
    total_files INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS distributions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id TEXT NOT NULL,
    book_id INTEGER REFERENCES books(id),
    watermark_id TEXT UNIQUE NOT NULL,
    qq_number TEXT NOT NULL,
    -- qq_hash / email_hash：HMAC(DB_KEY, 明文)，**确定性**，专供等值检索。
    -- 不能拿 qq_number 做等值匹配：field 加密模式（Fernet 随机 IV）下密文每次
    -- 不同，`WHERE qq_number = enc(q)` 永远匹配不到（查重/删除/检索会静默失效）。
    qq_hash TEXT,
    email TEXT NOT NULL,
    email_hash TEXT,
    status TEXT DEFAULT 'pending',          -- pending/sending/sent/failed/revoked
    error_message TEXT,
    agreed_policy_version TEXT,
    zero_width_ok INTEGER DEFAULT 0,
    css_ok INTEGER DEFAULT 0,
    image_qim_ok INTEGER DEFAULT 0,
    psnr REAL,
    images INTEGER DEFAULT 0,
    form_submission_id TEXT,
    policy_hash TEXT,
    -- 水印密钥（务必保密，泄露即可去除水印）
    chaos_seed REAL,
    chaos_mu REAL,
    css_key TEXT,
    lsb_key TEXT,
    sent_at TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS trace_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    watermark_id TEXT NOT NULL,
    qq_number TEXT,
    channel TEXT,                            -- zero_width / css_reorder / image_qim
    traced_at TEXT DEFAULT (datetime('now')),
    source_note TEXT,
    -- 层体检：记录解码时各层的存活情况，用来判断对方做了哪些清洗
    layers_alive TEXT,                       -- 存活层，逗号分隔
    layers_cleared TEXT,                     -- 被清除的层，逗号分隔
    clean_ops TEXT                           -- 推断的清洗操作，分号分隔
);

CREATE INDEX IF NOT EXISTS idx_dist_wm ON distributions(watermark_id);
CREATE INDEX IF NOT EXISTS idx_dist_qq ON distributions(qq_number);
CREATE INDEX IF NOT EXISTS idx_dist_qqh ON distributions(qq_hash);
CREATE INDEX IF NOT EXISTS idx_dist_emh ON distributions(email_hash);
CREATE INDEX IF NOT EXISTS idx_dist_status ON distributions(status);
CREATE INDEX IF NOT EXISTS idx_dist_batch ON distributions(batch_id);
CREATE INDEX IF NOT EXISTS idx_trace_wm ON trace_logs(watermark_id);
