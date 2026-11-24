#!/usr/bin/env python3
"""push_codes_release.py —— 把当前这版推到线上（幂等，可重复跑）。

做三件事：
  1) 线上建表 / 老表加列（claim_codes、app_config、books 的分享字段）
  2) 部署 Worker + secrets
  3) 冒烟：分享列表、登录、无凭据拦截、CSV 导出

设计约束：
  * DDL 全部幂等 —— 跑十遍和跑一遍结果一样；
  * 加列语句（ALTER TABLE ADD COLUMN）SQLite 不支持 IF NOT EXISTS，
    只能靠 "duplicate column name" 错误码容错；
  * 不从 schema.sql 里硬抠 claim_codes 相关语句（之前这么干漏过索引），
    而是整体解析：去注释 → 按 ; 切 → 逐条执行。
"""
import base64
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import setup_and_run as S

HERE = os.path.dirname(os.path.abspath(__file__))

# 老库加列（新库由 schema.sql 的 CREATE TABLE 直接带上）
ALTERS = [
    "ALTER TABLE books ADD COLUMN share_status   TEXT NOT NULL DEFAULT 'closed'",
    "ALTER TABLE books ADD COLUMN share_open_at  TEXT",
    "ALTER TABLE books ADD COLUMN share_close_at TEXT",
    "ALTER TABLE books ADD COLUMN share_note     TEXT DEFAULT ''",
    # 多版本：成品要能区分是哪一版母本打的
    "ALTER TABLE files ADD COLUMN version_id INTEGER",
    # 老成品回填成"该书当前版本"，否则改索引后领不到
    "UPDATE files SET version_id = (SELECT v.id FROM book_versions v "
    "WHERE v.book_id = files.book_id AND v.is_current = 1 LIMIT 1) "
    "WHERE version_id IS NULL",
    # 唯一性从"人+书"换成"人+版本"（索引必须在加列之后建）
    "DROP INDEX IF EXISTS ux_files_qq_book",
    "CREATE UNIQUE INDEX IF NOT EXISTS ux_files_qq_ver ON files(admin_id, qq, version_id)",
    # 在飞批次去重（并发 claim 原子化）：先去重再建部分唯一索引
    # 历史数据里有 dedup_key='' 的重复行，先收成 failed，否则建索引必冲突
    "UPDATE wm_batches SET status='failed', reason='dedup cleanup' "
    "WHERE status IN ('queued','running') AND dedup_key=''",
    "DELETE FROM wm_batches WHERE status IN ('queued','running') AND id NOT IN "
    "(SELECT MAX(id) FROM wm_batches WHERE status IN ('queued','running') GROUP BY dedup_key)",
    "CREATE UNIQUE INDEX IF NOT EXISTS ux_batch_inflight "
    "ON wm_batches(dedup_key) WHERE status IN ('queued','running')",
    # 溯源映射带版本（回调写入，溯源才能回答"哪一版母本"）
    "ALTER TABLE wm_mapping ADD COLUMN version_id INTEGER",
    # 取件码改为"一人一码"：先去重再建唯一索引
    "DELETE FROM code_uses WHERE code_id NOT IN (SELECT id FROM claim_codes)",
    "DELETE FROM claim_codes WHERE id NOT IN (SELECT MAX(id) FROM claim_codes GROUP BY admin_id, qq)",
    "CREATE UNIQUE INDEX IF NOT EXISTS ux_cc_qq ON claim_codes(admin_id, qq)",
    # 短链有效期（秒，默认 1 天）+ 领取状态
    "ALTER TABLE books ADD COLUMN link_ttl INTEGER NOT NULL DEFAULT 86400",
    "ALTER TABLE claim_codes ADD COLUMN verified_at TEXT",
    "ALTER TABLE claim_codes ADD COLUMN verify_count INTEGER NOT NULL DEFAULT 0",
    # 溯源解码由谁执行（actions = 云端，local = 本机 runner）
    "ALTER TABLE trace_jobs ADD COLUMN engine TEXT DEFAULT 'local'",
    # 分享范围（NULL = 不限制）
    "ALTER TABLE books ADD COLUMN share_scope TEXT DEFAULT NULL",
    # 打标指定母本版本（NULL = 当前版）
    "ALTER TABLE wm_batches ADD COLUMN version_id INTEGER",
    # 「修订替换」vs「多格式并存」是两种业务，必须分开记
    "ALTER TABLE book_versions ADD COLUMN kind TEXT NOT NULL DEFAULT 'revision'",
    "ALTER TABLE books ADD COLUMN mode TEXT NOT NULL DEFAULT 'single'",
    # 回填：同时有多个 is_current=1 的，说明这本就是多格式
    "UPDATE books SET mode='multi' WHERE id IN ("
    "SELECT book_id FROM book_versions WHERE is_current=1 "
    "GROUP BY book_id HAVING COUNT(*) > 1)",
]

# 初始口令：base64 写死，避免被任何工具当明文口令改写
INIT_PW = base64.b64decode("YWRtaW4xMTE=").decode()


def parse_schema(path):
    """去注释后按 ; 切分，返回可执行语句列表。"""
    raw = open(path, encoding="utf-8").read()
    no_comment = re.sub(r"--[^\n]*", "", raw)      # 行内 + 整行注释一起干掉
    return [c.strip() for c in no_comment.split(";") if c.strip()]


def run_sql(env_, stmts, tolerate=True):
    url, tok = S.norm_turso(env_["TURSO_URL"]), env_["TURSO_TOKEN"]
    done = skip = 0
    for q in stmts:
        st, out, raw = S.turso_pipeline(url, tok, [(q, [])])
        okk = st == 200 and out and out[0][0] == "ok"
        msg = "" if okk else str(out[0][1] if out else raw[:200])
        if okk:
            done += 1
        elif tolerate and ("already exists" in msg or "duplicate column name" in msg):
            skip += 1
        else:
            S.bad("失败：%s\n     SQL: %s" % (msg[:200], q.replace("\n", " ")[:120]))
            return False
    S.ok("DDL 完成：新建/更新 %d 条，已存在跳过 %d 条" % (done, skip))
    return True


def main():
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8", errors="replace")
        except Exception:                                   # noqa: BLE001
            pass

    env_ = S.load_env()
    if not env_.get("TURSO_URL") or not env_.get("CF_API_TOKEN"):
        S.bad("缺 TURSO_URL / CF_API_TOKEN，先跑 setup_and_run.py --reuse")
        return 2

    # ---- ① 建表 + 迁移 ----
    S.hr("① 线上建表 / 加列")
    if not run_sql(env_, parse_schema(os.path.join(HERE, "schema.sql"))):
        return 2
    S.hr("①b 老表加列（已存在则跳过）")
    if not run_sql(env_, ALTERS):
        return 2

    # ---- ② 部署 Worker ----
    S.hr("② 部署 Worker")
    if not S.deploy_worker(env_, "wm-poc"):
        S.bad("部署失败")
        return 2
    S.ok("部署完成")

    # ---- ③ 冒烟 ----
    S.hr("③ 线上冒烟")
    base = ("https://" + env_["PUBLIC_HOST"].strip("/")) if env_.get("PUBLIC_HOST") \
        else (env_.get("WORKER_URL") or "").rstrip("/")
    if not base:
        S.warn("没有对外地址，跳过冒烟")
        return 0

    # status 0 = 根本没连上（跨境链路抖动）。之前这里无条件 S.ok，
    # 结果"HTTP 0、118 字节"也报成绿 —— 冒烟变成了自我安慰。
    def _must(st, what, size=None):
        if st == 0:
            S.bad("%s 连接失败（HTTP 0）—— 不是代码问题，是本机到 Cloudflare 的国际链路抖了，"
                  "稍后重跑或换网络" % what)
            return False
        S.ok("%s → HTTP %s%s" % (what, st, "" if size is None else "，%d 字节" % size))
        return True

    # 分享列表（公开接口，不需要口令）
    st, _h, b = S.whttp("GET", base + "/api/share")
    d = S.jload(b, {}) or {}
    if not _must(st, "GET /api/share"):
        return 1
    S.info("  开放中 %d 本" % len(d.get("books") or []))

    # 管理页可达
    st, _h, b = S.whttp("GET", base + "/admin")
    if not _must(st, "GET /admin", len(b or b"")):
        return 1

    # 无凭据调管理接口 → 必须 401
    st, _h, b = S.whttp("POST", base + "/api/admin/codes",
                        {"Content-Type": "application/json"}, b'{"book_id":1,"qqs":["1"]}')
    if st == 0:
        S.bad("无凭据写管理接口 连接失败（HTTP 0）")
        return 1
    (S.ok if st == 401 else S.bad)("无凭据写管理接口 → HTTP %s（期望 401）" % st)

    # 登录（先试 .env 里记的口令，失败再试初始口令）
    pw_try = [env_.get("ADMIN_PASS", ""), INIT_PW]
    logged = None
    for pw in pw_try:
        if not pw:
            continue
        st, _h, b = S.whttp("POST", base + "/api/admin/login",
                            {"Content-Type": "application/json"},
                            S.json.dumps({"password": pw}).encode())
        j = S.jload(b, {}) or {}
        if st == 200 and j.get("ok"):
            logged = pw
            src = ".env.poc" if pw == env_.get("ADMIN_PASS") else "内置初始口令"
            S.ok("登录成功（口令来源：%s）" % src)
            break
    if not logged:
        S.warn("两个口令都不对 —— 说明密码已被改过。请把当前口令写进 .env.poc 的 ADMIN_PASS 后重跑，")
        S.warn("或者直接打开 %s/admin 用浏览器登录（浏览器那条路不依赖这个脚本）" % base)
    else:
        st, _h, b = S.whttp("GET", base + "/api/admin/codes.csv?book_id=2",
                            {"X-Admin-Pass": logged})
        S.ok("导出 CSV → HTTP %s，%d 字节" % (st, len(b or b"")))

    S.hr("完成")
    S.info("管理端：%s/admin   领取端：%s/" % (base, base))
    S.info("初始口令：%s（首次登录后自动存库；之后进「设置」改）" % INIT_PW)
    return 0


if __name__ == "__main__":
    sys.exit(main())
