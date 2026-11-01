-- PoC schema（Turso / SQLite 方言，可直接 turso db shell 或 HTTP pipeline 执行）
-- 原则：所有热查询都走主键或索引 —— Turso 按"行"计费，一次全表扫 5000 行
-- 就吃掉 5000 次行读，轮询 7200 次能把免费额度打穿（详见架构文档 4.3）。

PRAGMA foreign_keys = ON;

-- 账号（沿用现有语义：owner 唯一，admin 由 owner 创建）
CREATE TABLE IF NOT EXISTS admins (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  username    TEXT NOT NULL UNIQUE COLLATE NOCASE,
  nickname    TEXT DEFAULT '',
  pw_hash     TEXT NOT NULL,
  role        TEXT NOT NULL DEFAULT 'admin',      -- owner | admin
  status      TEXT NOT NULL DEFAULT 'active',     -- active | disabled
  token       TEXT NOT NULL,                      -- 登记链接令牌
  claim_token TEXT NOT NULL,                      -- 领取链接令牌
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS groups (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  admin_id INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
  name     TEXT NOT NULL,
  note     TEXT DEFAULT '',
  sort     INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_groups_admin ON groups(admin_id);

CREATE TABLE IF NOT EXISTS recipients (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  admin_id INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
  group_id INTEGER REFERENCES groups(id) ON DELETE SET NULL,
  qq       TEXT NOT NULL,
  email    TEXT DEFAULT '',
  note     TEXT DEFAULT '',
  status   TEXT NOT NULL DEFAULT 'new',           -- new | sent | banned
  extra    TEXT DEFAULT '{}',                     -- JSON：自定义字段
  source   TEXT DEFAULT 'manual',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
-- 同组内 QQ 唯一（Turso 支持表达式索引，NULL 组的唯一性靠应用层兜）
CREATE UNIQUE INDEX IF NOT EXISTS ux_rec_qq
  ON recipients(admin_id, IFNULL(group_id, 0), qq);
CREATE INDEX IF NOT EXISTS ix_rec_admin_status ON recipients(admin_id, status);

-- 母本
CREATE TABLE IF NOT EXISTS books (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  admin_id INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
  title    TEXT NOT NULL,
  r2_key   TEXT NOT NULL,                         -- books/<aid>/<id>.epub
  size     INTEGER DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- 打标批次（前端轮询的就是这张表，只查主键 + 只回 2 个字段）
CREATE TABLE IF NOT EXISTS batches (
  id         TEXT PRIMARY KEY,                    -- uuid，避免自增泄漏量级
  admin_id   INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
  book_id    INTEGER REFERENCES books(id) ON DELETE SET NULL,
  group_id   INTEGER,
  total      INTEGER NOT NULL DEFAULT 0,
  done       INTEGER NOT NULL DEFAULT 0,
  failed     INTEGER NOT NULL DEFAULT 0,
  status     TEXT NOT NULL DEFAULT 'queued',      -- queued|running|done|failed
  reason     TEXT DEFAULT '',
  gh_run_id  TEXT DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS ix_batches_admin ON batches(admin_id, created_at DESC);

-- 成品（领取时按 admin+qq 点查）
CREATE TABLE IF NOT EXISTS files (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  admin_id    INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
  qq          TEXT NOT NULL,
  book_id     INTEGER,
  batch_id    TEXT,
  r2_key      TEXT NOT NULL,
  token       TEXT NOT NULL UNIQUE,               -- 领取 token
  size        INTEGER DEFAULT 0,
  downloads   INTEGER DEFAULT 0,
  watermark_id TEXT DEFAULT '',
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_files_qq_book ON files(admin_id, qq, book_id);
CREATE INDEX IF NOT EXISTS ix_files_token ON files(token);

-- 水印映射（替代 mapping.db，溯源用；PoC 的核心验证点之一）
CREATE TABLE IF NOT EXISTS wm_mapping (
  watermark_id TEXT PRIMARY KEY,
  admin_id     INTEGER NOT NULL,
  qq           TEXT NOT NULL,
  book_id      INTEGER,
  batch_id     TEXT,
  payload_sha  TEXT DEFAULT '',                   -- 载荷片段哈希，便于交叉校验
  created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS ix_map_qq ON wm_mapping(admin_id, qq);

-- 幂等/防重放：Actions 的 callback 和内部 token nonce
CREATE TABLE IF NOT EXISTS nonce (
  v   TEXT PRIMARY KEY,
  exp INTEGER NOT NULL
);

-- PoC 用：一个最小账号 + 一本书，方便 worker 端直接跑
INSERT OR IGNORE INTO admins(id, username, pw_hash, role, token, claim_token)
VALUES (1, 'poc', 'x', 'owner', 'tok-poc', 'claim-poc');
