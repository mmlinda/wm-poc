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

-- 动态短链：/s/<32位随机>
--
-- 为什么不是"把 5 分钟 token 写死进链接"：那样链接活多久 token 就活多久，
-- 一旦转发出去就是永久后门。这里存的是"谁 + 哪本书 + 什么时候失效"，
-- 每次点击才现签 5 分钟 token，所以链接能活 1 天而凭证永远只有 5 分钟。
CREATE TABLE IF NOT EXISTS short_links (
  id         TEXT PRIMARY KEY,                  -- 32 位十六进制，不可枚举
  admin_id   INTEGER NOT NULL,
  book_id    INTEGER NOT NULL,
  code_id    INTEGER NOT NULL,                  -- 绑死领取人：换个人打开也没用
  qq         TEXT NOT NULL,
  exp        TEXT NOT NULL,                     -- UTC，到期即 404
  hits       INTEGER NOT NULL DEFAULT 0,
  revoked    INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS ix_sl_code ON short_links(code_id, book_id);

-- 分组与人的多对多：一个人可以同时在多个组（并集，重复导入不覆盖已有关系）
CREATE TABLE IF NOT EXISTS group_members (
  group_id     INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  recipient_id INTEGER NOT NULL REFERENCES recipients(id) ON DELETE CASCADE,
  added_at     TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (group_id, recipient_id)
);
CREATE INDEX IF NOT EXISTS ix_gm_rec ON group_members(recipient_id);

-- 黑名单：只挡"再领/再下"，绝不删记录（已发出的那份还要靠它溯源）
CREATE TABLE IF NOT EXISTS blocklist (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  admin_id   INTEGER NOT NULL,
  qq         TEXT NOT NULL,
  reason     TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(admin_id, qq)
);
CREATE INDEX IF NOT EXISTS ix_block_qq ON blocklist(admin_id, qq);

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
--
-- 分享窗口（2026-11-22 新增）：把"这本书能不能领"和"暗号有没有过期"解耦。
-- 暗号永久有效（除非管理员主动改），失效靠这本书的窗口开关 —— 因为人只会
-- 记得"这批书发完了"，不会记得"给 200 个人各设一个过期时间"。
--   share_status  closed | open
--   share_open_at / share_close_at  UTC ISO8601，NULL = 不限制那一端
-- 判定口径：status='open' 且 now 落在 [open_at, close_at] 内。
CREATE TABLE IF NOT EXISTS books (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  admin_id INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
  title    TEXT NOT NULL,
  r2_key   TEXT NOT NULL,                         -- books/<aid>/<id>.epub
  size     INTEGER DEFAULT 0,
  share_status   TEXT NOT NULL DEFAULT 'closed',
  share_open_at  TEXT,
  share_close_at TEXT,
  mode TEXT NOT NULL DEFAULT 'single',          -- single | multi（多格式并存）
  link_ttl INTEGER NOT NULL DEFAULT 86400,     -- 短链有效期（秒），默认 1 天
  share_scope TEXT DEFAULT NULL,                      -- JSON {groups:[],qqs:[]}；NULL=不限制
  share_note     TEXT DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- 母本版本（2026-11-22 续：多版本 + 历史留存）
--
-- 为什么不全塞进 books：
--   ① 一本书会有多个版本（手机版 / Kindle 版），要同时分享；
--   ② 母本更新后旧版**不能删** —— 半年后查某个 watermark，得能回答
--      "这本书的水印是当时哪一版母本打出来的"，否则溯源就断在书这一层。
--
-- 与 books 的关系：
--   books.r2_key/size 始终指向**当前用于打标的版本**（打标链路不用改，仍读这两列）；
--   book_versions 是完整历史，每次上传新增一行，旧行永不覆盖。
CREATE TABLE IF NOT EXISTS book_versions (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  book_id     INTEGER NOT NULL,
  version_no  INTEGER NOT NULL,                   -- 1,2,3…（按书递增，不复用）
  label       TEXT NOT NULL DEFAULT '',           -- "手机版" / "Kindle 版"
  r2_key      TEXT NOT NULL,
  filename    TEXT DEFAULT '',
  size        INTEGER DEFAULT 0,
  is_current  INTEGER NOT NULL DEFAULT 0,
  kind TEXT NOT NULL DEFAULT 'revision',          -- revision=替换旧版 | variant=另一格式并存
  note        TEXT DEFAULT '',
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_ver_book_no ON book_versions(book_id, version_no);
CREATE UNIQUE INDEX IF NOT EXISTS ux_ver_key     ON book_versions(r2_key);
CREATE INDEX IF NOT EXISTS ix_ver_book ON book_versions(book_id, is_current);

-- 一次性把已有书迁成 v1（幂等：靠 ux_ver_book_no 兜住重复执行）
INSERT OR IGNORE INTO book_versions(book_id, version_no, label, r2_key, filename, size, is_current, note)
SELECT id, 1, '初始版', r2_key, '', size, 1, '从 books 迁移'
  FROM books WHERE r2_key IS NOT NULL AND r2_key <> '';

-- 修正迁移行的时间：必须用"书创建时间"，不能用迁移时刻。
-- 否则老的水印记录（早于迁移）会找不到对应母本版本，溯源直接断掉。
UPDATE book_versions
   SET created_at = (SELECT b.created_at FROM books b WHERE b.id = book_versions.book_id)
 WHERE version_no = 1 AND note = '从 books 迁移'
   AND created_at > (SELECT b.created_at FROM books b WHERE b.id = book_versions.book_id);

-- 按版本记下载次数（2026-11-22 续：额度挂版本，不挂"这本书"）
--
-- 为什么不用 claim_codes.uses 一个总计数：
--   一本书有 N 个版本时，总计数会让"手机版下 3 次"把 Kindle 版的额度也吃光。
--   额度必须按版本独立 —— 这是用户明确要求的。
--
-- 与 claim_codes 的关系：claim_codes 仍是"谁有资格领"，code_uses 记"每个版本下过几次"。
-- 校验时：某版本 remaining = max_uses - uses，只要有任一版本 remaining>0 就能领。
CREATE TABLE IF NOT EXISTS code_uses (
  code_id    INTEGER NOT NULL,
  version_id INTEGER NOT NULL,
  uses       INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (code_id, version_id)
);
CREATE INDEX IF NOT EXISTS ix_uses_code ON code_uses(code_id);

-- 打包产物（每人一个 zip，含其所有有额度的版本）
CREATE TABLE IF NOT EXISTS packs (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  code_id    INTEGER NOT NULL,
  book_id    INTEGER NOT NULL,
  r2_key     TEXT NOT NULL,
  size       INTEGER DEFAULT 0,
  version_ids TEXT DEFAULT '',          -- JSON 数组：包里装了哪几版
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT
);
CREATE INDEX IF NOT EXISTS ix_packs_code ON packs(code_id);

-- 成品按版本区分（原来 files 只有 admin+qq+book，多版本时无法区分是哪个版本的文件）
-- 老数据由 push_codes_release.py 的 ALTER + 回填补成"该书当前版本"

-- 溯源工单（可疑文件 → 本机 worker 解码 → 回写结果）
--
-- 为什么不在 Worker 里解码：7 层检测要用 Pillow/numpy 做图片频域分析，
-- Python Workers 是 Pyodide，跑不动；而且密钥不该为了这一次查询飘到边缘节点。
-- 所以走"网页收文件 → 本机取走解码 → 结果推回"，和原 trace_worker 一个思路。
CREATE TABLE IF NOT EXISTS trace_jobs (
  id         TEXT PRIMARY KEY,
  admin_id   INTEGER NOT NULL,
  r2_key     TEXT NOT NULL,
  filename   TEXT DEFAULT '',
  size       INTEGER DEFAULT 0,
  status     TEXT NOT NULL DEFAULT 'queued',   -- queued | running | done | failed
  result     TEXT DEFAULT '',                  -- JSON：身份 + 7 层体检
  reason     TEXT DEFAULT '',
  note       TEXT DEFAULT '',                  -- 发现渠道备注
  engine     TEXT DEFAULT 'local',             -- actions | local：由谁来解
  claimed_at TEXT,
  finished_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  CHECK (status IN ('queued','running','done','failed'))
);
CREATE INDEX IF NOT EXISTS ix_tj_status ON trace_jobs(status, created_at);

-- 同一 dedup_key 只允许一个"在飞"批次：并发 claim 靠它原子收敛成一条
CREATE UNIQUE INDEX IF NOT EXISTS ux_batch_inflight
  ON wm_batches(dedup_key) WHERE status IN ('queued','running');

-- 运行时可改的配置（口令 hash 等）
--
-- 为什么不放 env：口令要能在网页上改。放 env 就得改 .env + 重新部署，
-- 而"改密码"这种事必须即时生效、且改完踢掉所有旧会话。
CREATE TABLE IF NOT EXISTS app_config (
  k          TEXT PRIMARY KEY,
  v          TEXT,
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
INSERT OR IGNORE INTO app_config(k, v) VALUES('admin_pw_ver', '1');

-- 打标批次（前端轮询的就是这张表，只查主键 + 只回 3 个字段）
--
-- 三个时间戳是**测试与前端进度的硬依赖**（QA《异步架构专项预案》§二.3 / §六）：
--   queued_at   入队时刻（= INSERT 时刻，可在建批次时显式写入）
--   started_at  Actions 真正开始跑（领任务时写；排队时长 = started_at - queued_at）
--   finished_at 收敛时刻（done 或 failed 时写；恒为 NULL = 卡死，看门狗据此判定）
-- 全部用 UTC ISO8601 字符串，便于直接做字符串比较与差集扫描。
CREATE TABLE IF NOT EXISTS wm_batches (
  id          TEXT PRIMARY KEY,                   -- uuid，避免自增泄漏量级
  admin_id    INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
  book_id     INTEGER REFERENCES books(id) ON DELETE SET NULL,
  group_id    INTEGER,
  total       INTEGER NOT NULL DEFAULT 0,
  done        INTEGER NOT NULL DEFAULT 0,
  failed      INTEGER NOT NULL DEFAULT 0,
  status      TEXT NOT NULL DEFAULT 'queued',     -- queued|running|done|failed
  reason      TEXT DEFAULT '',
  gh_run_id   TEXT DEFAULT '',
  simulate    TEXT DEFAULT '',                    -- 故障注入标记（'' | crash_before | crash_after | no_callback | turso_fail）
  dedup_key   TEXT DEFAULT '',                    -- "admin:qq:book"；同一人在飞批次唯一（防重复提交建双批次）
  qqs         TEXT DEFAULT '',                    -- JSON 数组：本批次要打标的人（Actions 领任务时读这里，名册只兜底）
  version_id INTEGER,                               -- 打标用哪一版母本（NULL=当前版）
  plan_id     TEXT DEFAULT '',                    -- 一次提交可能拆成多波（每波 ≤15 本），同 plan_id 归一组
  queued_at   TEXT,                               -- 入队
  started_at  TEXT,                               -- Actions 开始跑
  finished_at TEXT,                               -- 结束（done/failed）
  created_at  TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at  TEXT NOT NULL DEFAULT (datetime('now')),
  -- started_at 只在第一次 running 时写，重放/重试不覆盖；finished_at 一旦写入不允许改（终态不可变）
  CHECK (status IN ('queued','running','done','failed'))
);
CREATE INDEX IF NOT EXISTS ix_batches_admin ON wm_batches(admin_id, created_at DESC);
-- 看门狗扫描：找"非终态且 updated_at 过旧"的行。必须走索引，否则每次扫描都是全表（Turso 按行计费）
CREATE INDEX IF NOT EXISTS ix_batches_live ON wm_batches(status, updated_at);
-- 幂等：同一 dedup_key 在非终态只允许一条 —— 领取页连点 5 次只会建 1 个批次
-- （不能用 UNIQUE 约束，因为终态行可以有无数条历史，所以是"应用层查重 + 这个索引兜性能"）
CREATE INDEX IF NOT EXISTS ix_batches_dedup ON wm_batches(dedup_key, status);

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
  -- 多版本后必须按版本区分：同一个人同一本书会有 N 条成品记录
  version_id  INTEGER,
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
-- 唯一性从"人+书"改成"人+版本"。索引本身在 push_codes_release.py 的 ALTERS 里建，
-- 因为老库要先 ALTER 加 version_id 列，顺序错了会 no such column。
CREATE INDEX IF NOT EXISTS ix_files_token ON files(token);
-- 成品按"人+版本"唯一（新库直接建；老库在 push 脚本的 ALTER 里按序建）
CREATE UNIQUE INDEX IF NOT EXISTS ux_files_qq_ver ON files(admin_id, qq, version_id);
CREATE INDEX IF NOT EXISTS ix_files_book  ON files(admin_id, book_id);

-- 取件码（2026-11-22 新增）
--
-- 为什么要有这张表：原来 /api/claim 只校验 QQ —— 知道别人 QQ 号就能把书领走。
-- 取件码把"身份"和"凭据"拆成两件事：QQ 是谁，码是凭证。
-- 四个约束（对应四道防线）：
--   ① 码与 QQ 绑定 —— 转发码给别人，对方还得知道 QQ；
--   ② 一码一书一人（ux_code_qq）—— 不能拿 A 的码领 B 的书；
--   ③ 限次（max_uses，默认 3）—— 防止链接在群里被反复刷；
--   ④ 可吊销 + 可过期 —— 发现漏了就 revoke，不用删数据。
CREATE TABLE IF NOT EXISTS claim_codes (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  admin_id    INTEGER NOT NULL,
  book_id     INTEGER NOT NULL,
  qq          TEXT NOT NULL,
  code        TEXT NOT NULL,                      -- 6 位，字符集去掉了 0/O/1/I
  status      TEXT NOT NULL DEFAULT 'active',     -- active | revoked
  uses        INTEGER NOT NULL DEFAULT 0,
  max_uses    INTEGER NOT NULL DEFAULT 3,
  expires_at  TEXT,                               -- NULL = 不过期（UTC ISO8601）
  note        TEXT DEFAULT '',
  verified_at TEXT,                             -- 首次校验通过（开过页面但可能没下）
  verify_count INTEGER NOT NULL DEFAULT 0,      -- 校验次数
  created_at  TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at  TEXT NOT NULL DEFAULT (datetime('now')),
  CHECK (status IN ('active','revoked'))
);
-- 同一本书里码不能重复；同一本书里一个人只能有一个码
CREATE UNIQUE INDEX IF NOT EXISTS ux_code_admin_book ON claim_codes(admin_id, book_id, code);
CREATE UNIQUE INDEX IF NOT EXISTS ux_code_qq         ON claim_codes(admin_id, book_id, qq);
-- 领取时的点查：先按 (qq, book) 定位行，再比对 code（走索引，不做全表扫）
CREATE INDEX IF NOT EXISTS ix_code_lookup ON claim_codes(admin_id, book_id, qq);
CREATE INDEX IF NOT EXISTS ix_code_status ON claim_codes(admin_id, status);

-- 水印映射（替代 mapping.db，溯源用；PoC 的核心验证点之一）
CREATE TABLE IF NOT EXISTS wm_mapping (
  watermark_id TEXT PRIMARY KEY,
  admin_id     INTEGER NOT NULL,
  qq           TEXT NOT NULL,
  book_id      INTEGER,
  batch_id     TEXT,
  payload_sha  TEXT DEFAULT '',                   -- 载荷片段哈希，便于交叉校验
  -- 水印密钥（溯源必需）：引擎用随机密钥，不落库就永远解不出 ID。
  -- 2026-11-22 之前只回传 watermark_id → decode 返回 None，等于溯源断裂。
  chaos_seed   REAL,
  chaos_mu     REAL,
  css_key      TEXT,
  lsb_key      TEXT,
  version_id INTEGER,                          -- 当时用的母本版本
  created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS ix_map_qq ON wm_mapping(admin_id, qq);

-- R2 用量账本（单行，id 恒为 1）
--
-- 为什么要有这张表：R2 免费额度 10GB，超一分钱就扣费 —— **不能靠"应该够用"来赌**。
-- 每次上传/删除都在同一个事务边界里改这一行，上传前用它做**硬熔断**（放不下就 507）。
-- limit_bytes 默认 8 GiB：留 2 GiB 给"正在上传但还没记账""临时调试对象"这些误差。
CREATE TABLE IF NOT EXISTS r2_usage (
  id          INTEGER PRIMARY KEY CHECK (id = 1),
  bytes       INTEGER NOT NULL DEFAULT 0,          -- 当前占用（字节）
  objects     INTEGER NOT NULL DEFAULT 0,          -- 当前对象数
  limit_bytes INTEGER NOT NULL DEFAULT 8589934592, -- 8 GiB 硬上限（超出即拒写）
  alert_60    INTEGER NOT NULL DEFAULT 0,          -- 60% 报警是否已发（1=已发，降回 55% 以下自动复位）
  alert_80    INTEGER NOT NULL DEFAULT 0,          -- 80% 报警是否已发
  updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
INSERT OR IGNORE INTO r2_usage(id) VALUES(1);

-- 成品过期索引：定期清理按 created_at 扫，没索引就是全表（Turso 按行计费）
CREATE INDEX IF NOT EXISTS ix_files_created ON files(created_at);

-- 幂等/防重放：Actions 的 callback 和内部 token nonce
CREATE TABLE IF NOT EXISTS nonce (
  v   TEXT PRIMARY KEY,
  exp INTEGER NOT NULL
);

-- PoC 用：一个最小账号 + 一本书，方便 worker 端直接跑
INSERT OR IGNORE INTO admins(id, username, pw_hash, role, token, claim_token)
VALUES (1, 'poc', 'x', 'owner', 'tok-poc', 'claim-poc');

-- 演示用母本：**必须有这一行**，否则建批次时 wm_batches.book_id 的外键会失败
-- （真实踩过：Turso 上只跑了 admin 那条，/api/wm/jobs 直接 500 FOREIGN KEY constraint failed）
INSERT OR IGNORE INTO books(id, admin_id, title, r2_key, size)
VALUES (1, 1, 'PoC 母本', 'books/1/1.epub', 0);
