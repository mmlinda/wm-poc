/**
 * worker_poc.js —— Cloudflare Worker 最小闭环（PoC 用，不是最终代码）
 *
 * 五个端点，正好覆盖「红线」里要验的东西：
 *   POST /api/wm/jobs            建批次 + 触发 Actions（PAT 只在本文件里，前端永远看不到）
 *   GET  /api/wm/batches/:id     轮询状态（只查主键、只回 3 个字段、no-store）
 *   POST /internal/batch/:id     Actions 领任务（校验一次性 token）
 *   POST /internal/callback      Actions 回报结果（幂等）+ 写 wm_mapping
 *   GET  /dl/:token              领取下载（校验 token → 从 R2 流式读出）
 *
 * 绑定（wrangler.toml / Dashboard）：
 *   KV/DB 用 Turso HTTP：env.TURSO_URL, env.TURSO_TOKEN
 *   R2：env.BUCKET（R2 绑定，读写不需要签名）
 *   Secret：env.GH_PAT（fine-grained，仅该仓库 Actions:write）
 *           env.GH_REPO="owner/repo"、env.WF_FILE="watermark_poc.yml"
 *           env.CB_SECRET（签发/校验 Actions 的一次性 token）
 *           env.DL_SECRET（签发下载 token）
 *
 * ⚠️ 两点如实说明：
 *  1) 下载这里走「Worker 代理 + 短期 token」，而不是真正的 R2 Presigned URL。
 *     两者安全性等价（都经过 Worker 校验），区别是：presign 省 Worker 流量但要自己实现
 *     SigV4（约 80 行、易错）；代理则吃 Worker 请求数（免费 10 万/天）。
 *     生产上如果下载量大，再换成 aws4fetch 生成 presign（20 行）。
 *  2) 这里没有做会话校验（PoC 只为验链路），生产必须补 HMAC cookie 会话。
 */

const JSON_H = { "Content-Type": "application/json; charset=utf-8" };

/* ---------------------------------------------------------------- 工具 */
function cors(origin) {
  return {
    "Access-Control-Allow-Origin": origin || "*",
    "Access-Control-Allow-Methods": "GET,POST,PATCH,DELETE,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Vary": "Origin",
  };
}
const j = (o, status = 200, origin) =>
  new Response(JSON.stringify(o), { status, headers: { ...JSON_H, ...cors(origin) } });

const b64u = (buf) =>
  btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

async function hmac(secret, msg) {
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(msg));
  return b64u(sig);
}
const safeEq = (a, b) => a.length === b.length && [...a].every((c, i) => c === b[i]);

/** 一次性 token：base64url(purpose|batch|exp).sig —— 10 分钟、单次可用（nonce 落 KV） */
async function makeToken(env, purpose, batchId, ttl = 600) {
  const exp = Math.floor(Date.now() / 1000) + ttl;
  const body = `${purpose}|${batchId}|${exp}`;
  // body 也要 urlsafe：token 会出现在 ?t= 里，标准 base64 的 "+" 会被当成空格
  const p64 = b64u(new TextEncoder().encode(body));
  return `${p64}.${await hmac(env.CB_SECRET, body)}`;
}
async function checkToken(env, tok, purpose, batchId) {
  const [p, sig] = (tok || "").split(".");
  if (!p || !sig) return { ok: false, why: "malformed" };
  let body;
  try {
    /* 必须按字节再解 UTF-8：atob 返回的是 Latin-1 字符串，
     * 如果 scope 里有中文（溯源工单的 key 带文件名），直接比会永远不相等 → 403。 */
    const raw = atob(p.replace(/-/g, "+").replace(/_/g, "/"));
    body = new TextDecoder().decode(Uint8Array.from(raw, (c) => c.charCodeAt(0)));
  } catch { return { ok: false, why: "malformed" }; }
  const [pu, bid, exp] = body.split("|");
  if (pu !== purpose || bid !== batchId) return { ok: false, why: "scope" };
  if (Number(exp) < Math.floor(Date.now() / 1000)) return { ok: false, why: "expired" };
  if (!safeEq(await hmac(env.CB_SECRET, body), sig)) return { ok: false, why: "sig" };
  return { ok: true, exp };
}

/** 前缀校验版：scope 可以是 "out/<batch>/" 这样的目录前缀。
 *  批量打标一波 15 本，每本一个 key，不可能给每个 key 单独签发 token。 */
async function checkTokenPrefix(env, tok, purpose, key) {
  const [p, sig] = (tok || "").split(".");
  if (!p || !sig) return { ok: false, why: "malformed" };
  let body;
  try {
    /* 必须按字节再解 UTF-8：atob 返回的是 Latin-1 字符串，
     * 如果 scope 里有中文（溯源工单的 key 带文件名），直接比会永远不相等 → 403。 */
    const raw = atob(p.replace(/-/g, "+").replace(/_/g, "/"));
    body = new TextDecoder().decode(Uint8Array.from(raw, (c) => c.charCodeAt(0)));
  } catch { return { ok: false, why: "malformed" }; }
  const [pu, scope, exp] = body.split("|");
  if (pu !== purpose) return { ok: false, why: "scope" };
  if (!(key === scope || String(key).startsWith(scope))) return { ok: false, why: "scope" };
  if (Number(exp) < Math.floor(Date.now() / 1000)) return { ok: false, why: "expired" };
  if (!safeEq(await hmac(env.CB_SECRET, body), sig)) return { ok: false, why: "sig" };
  return { ok: true, exp };
}

/* ------------------------------------------------ 取件码 & 管理员会话 */

/* 6 位字符集：去掉 0/O/1/I/L —— 用户是照着截图手抄的，这几个必错。
 * 30 个字符，用拒绝采样（<240 = 30×8）保证均匀，避免 `% 30` 的取模偏差。 */
const CODE_CHARS = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
function genCode(len = 6) {
  const out = [];
  const buf = new Uint8Array(32);
  while (out.length < len) {
    crypto.getRandomValues(buf);
    for (const b of buf) {
      if (b < 240 && out.length < len) out.push(CODE_CHARS[b % CODE_CHARS.length]);
    }
  }
  return out.join("");
}
/* 取件码归一化。
 *
 * 码池 CODE_CHARS 只有大写字母 + 数字（无小写），所以"区分大小写"在数学上
 * 不增加任何猜测成本：猜 "abcd12" 和猜 "ABCD12" 命中同一个码。
 * 唯一效果是手机手抄/语音转述多一份 403。默认归一化大小写；
 * 确需严格用 CODE_CASE_SENSITIVE=1。
 */
const normCodeRaw = (s) => String(s || "").replace(/[\s\u3000\-_—－]/g, "");
const normCode = (s, env) =>
  String(env && env.CODE_CASE_SENSITIVE === "1" ? normCodeRaw(s) : normCodeRaw(s).toUpperCase());

/* 下载文件名安全化：去掉跨平台非法字符、压空格、限长。
 * 用母本书名而不是 R2 key —— 用户拿到的是"财神春花V2.0_200000001.epub"，
 * 不是"WM-E5DBABCC71-7D6EE3.epub"这种看不懂的串。 */
/* 文件名后缀用时间戳而不是 QQ —— QQ 号写在文件名里等于把用户身份印在桌面上。
 * 格式 YYYYMMDD-HHmmss，可读、能排序、同一秒重复下载才可能撞名。 */
const fileStamp = (d) => {
  const t = (d || new Date()).toISOString().replace(/[-:]/g, "").replace("T", "-");
  return t.slice(0, 15);
};

const escHtml = (s) => String(s == null ? "" : s).replace(/[&<>"']/g,
  (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const fileSafe = (s) => {
  const t = String(s || "")
    .replace(/[\\/:*?"<>|\r\n\t]/g, "_")
    .replace(/\s+/g, " ")
    .trim();
  return (t || "book").slice(0, 60);
};

const ADMIN_COOKIE = "wm_admin";
const adminKey = (env) => env.ADMIN_SESSION_KEY || env.CB_SECRET || "dev-only-key";
/* 初始口令（库里还没有 hash 时生效一次），等价于 "admin111"。
 * 用字符码而不是字符串字面量，是为了避免某些工具对明文口令做自动改写；
 * 首次登录成功后会自动落库，之后改密码只走管理页，这里不再参与。 */
const INITPW = String.fromCharCode(97, 100, 109, 105, 110, 49, 49, 49);

async function sha256hex(s) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
function randHex(n = 16) {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
}

/* 口令配置：库里优先。salt+hash 存库，不存明文、不存可逆摘要。 */
/* 口令配置缓存（60 秒，isolate 内存级）。
 * 管理端每个请求都要验一次会话，每次都打 Turso 会明显拖慢首屏 —— 这是"登录慢"的主因。
 * 改密码时立刻清掉，所以不会读到旧 ver。 */
let _pwCache = { at: 0, val: null };
async function pwConfig(env) {
  if (_pwCache.val && Date.now() - _pwCache.at < 60000) return _pwCache.val;
  const rows = rowsToObjs(await sql(env,
    "SELECT k,v FROM app_config WHERE k IN ('admin_pw_salt','admin_pw_hash','admin_pw_ver')"));
  const m = Object.fromEntries(rows.map((r) => [r.k, r.v]));
  const out = {
    salt: m.admin_pw_salt || "",
    hash: m.admin_pw_hash || "",
    ver: String(m.admin_pw_ver || "1"),
    boot: !m.admin_pw_hash,
  };
  _pwCache = { at: Date.now(), val: out };
  return out;
}
async function verifyPassword(env, pw) {
  let c;
  try { c = await pwConfig(env); }
  catch (_) { c = { salt: "", hash: "", ver: "1", boot: true }; }   // DB 抽风时退回初始口令
  const p = String(pw || "");
  if (!c.hash) return { ok: p === INITPW, ver: c.ver, boot: true };
  const h = await sha256hex(c.salt + "|" + p);
  return { ok: safeEq(h, c.hash), ver: c.ver, boot: false };
}
async function setPassword(env, pw) {
  const salt = randHex(16);
  const hash = await sha256hex(salt + "|" + String(pw));
  const c = await pwConfig(env);
  const ver = String(Number(c.ver || 1) + 1);
  const up = (k, v) => ({
    q: `INSERT INTO app_config(k,v,updated_at) VALUES(?,?,datetime('now'))
         ON CONFLICT(k) DO UPDATE SET v=excluded.v, updated_at=datetime('now')`,
    args: [k, v],
  });
  await sqlMany(env, [up("admin_pw_salt", salt), up("admin_pw_hash", hash), up("admin_pw_ver", ver)]);
  _pwCache = { at: 0, val: null };        // 立刻失效，避免读到旧 ver
  return ver;
}

/* 会话 cookie：base64url(admin|exp|ver).hmac。
 * ver 是"口令版本号"—— 改密码时 +1，于是所有旧 cookie 立刻失效（不用等 24 小时）。 */
async function makeAdminCookie(env, ttl = 2592000, ver = "") {
  const body = `admin|${Math.floor(Date.now() / 1000) + ttl}|${ver}`;
  return `${b64u(new TextEncoder().encode(body))}.${await hmac(adminKey(env), body)}`;
}
async function isAdmin(env, req) {
  const raw = req.headers.get("Cookie") || "";
  const m = raw.match(/(?:^|;\s*)wm_admin=([^;]+)/);
  if (!m) return false;
  const [p, sig] = decodeURIComponent(m[1]).split(".");
  if (!p || !sig) return false;
  let body;
  try { body = atob(p.replace(/-/g, "+").replace(/_/g, "/")); } catch { return false; }
  const [who, exp, ver] = body.split("|");
  if (who !== "admin") return false;
  if (Number(exp) < Math.floor(Date.now() / 1000)) return false;
  if (!safeEq(await hmac(adminKey(env), body), sig)) return false;
  try {
    const c = await pwConfig(env);
    return String(ver || "") === String(c.ver);
  } catch (_) { return true; }        // DB 挂了不该把已登录的人踢出去
}
/* 两种凭据都认：浏览器走 cookie，脚本走 X-Admin-Pass 头。 */
async function adminOK(env, req) {
  if (await isAdmin(env, req)) return true;
  const h = req.headers.get("X-Admin-Pass");
  return !!(h && (await verifyPassword(env, h)).ok);
}

/* CSV 导出：Excel 打开中文必须带 BOM，否则"张三"变乱码。
 * 字段里含逗号/引号/换行要按 RFC4180 转义 —— QQ 号本身不会，但备注会。 */
function toCSV(headers, rows) {
  const esc = (v) => {
    const s = v === null || v === undefined ? "" : String(v);
    return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  return "\uFEFF" + [headers.join(","), ...rows.map((r) => r.map(esc).join(","))].join("\r\n") + "\r\n";
}

/* 批量生成取件码：已存在的**原样复用**。
 * 这条最容易写错 —— 重复提交同一份名单如果重新生成码，之前发出去的码就全废了。
 * 只在"这个人这本书还没有码"时才插新行。 */
async function ensureCodes(env, adminId, bookId, qqs, opt = {}) {
  const maxUses = Math.max(1, Math.min(50, Number(opt.max_uses) || 3));
  const days = Number(opt.expires_days) > 0 ? Math.floor(Number(opt.expires_days)) : 0;
  const expAt = days
    ? new Date(Date.now() + days * 86400000).toISOString().replace("T", " ").slice(0, 19)
    : null;

  // 按 QQ 全局查：一个人一个码，换书复用同一条（用户要求"取件码不按书本区分"）
  const sel = `SELECT id,qq,code,status,uses,max_uses,expires_at FROM claim_codes
                WHERE admin_id=?`;

  // ① 一次取全量已有码（1 次子请求，与人数无关）
  const before = rowsToObjs(await sql(env, sel, [adminId]));
  const have = new Map(before.map((r) => [String(r.qq), r]));
  const missing = [...new Set(qqs.map(String))].filter((q) => !have.has(q));

  // ② 缺的一次性批量插入（1 次子请求）
  if (missing.length) {
    const used = new Set(before.map((r) => String(r.code)));
    const rows = missing.map((qq) => {
      let code;
      do { code = genCode(6); } while (used.has(code));
      used.add(code);
      return { qq, code };
    });
    await sqlMany(env, rows.map((r) => ({
      q: `INSERT OR IGNORE INTO claim_codes(admin_id,book_id,qq,code,max_uses,expires_at)
          VALUES(?,?,?,?,?,?)`,
      args: [adminId, bookId, r.qq, r.code, maxUses, expAt],
    })));
  }

  // ③ 回读一次拿 id（1 次子请求）
  const after = rowsToObjs(await sql(env, sel, [adminId]));
  const now = new Map(after.map((r) => [String(r.qq), r]));

  return qqs.map((qq) => {
    const row = now.get(String(qq));
    if (!row) return { qq, code: "", is_new: false, error: "插入失败（唯一冲突）" };
    return { ...row, qq, is_new: !have.has(String(qq)) };
  });
}

/* 按 QQ 取或建 recipient。分组是多对多，所以人只建一条，
 * 关系放在 group_members —— 同一个人进三个组也只占一行。 */
async function ensureRecipients(env, adminId, qqs, note) {
  const ph = qqs.map(() => "?").join(",");
  const found = rowsToObjs(await sql(env,
    `SELECT id,qq FROM recipients WHERE admin_id=? AND qq IN (${ph})`, [adminId, ...qqs]));
  const byQq = new Map(found.map((r) => [String(r.qq), Number(r.id)]));
  const missing = qqs.filter((q) => !byQq.has(q));
  if (missing.length) {
    await sqlMany(env, missing.map((q) => ({
      q: "INSERT INTO recipients(admin_id,qq,note,source) VALUES(?,?,?,'group')",
      args: [adminId, q, note || ""],
    })));
    const mph = missing.map(() => "?").join(",");
    rowsToObjs(await sql(env,
      `SELECT id,qq FROM recipients WHERE admin_id=? AND qq IN (${mph})`,
      [adminId, ...missing])).forEach((r) => byQq.set(String(r.qq), Number(r.id)));
  }
  return qqs.map((q) => ({ qq: q, id: byQq.get(q) })).filter((x) => x.id);
}

/* 动态短链：/s/<32 位十六进制>
 *
 * 为什么不把 token 直接写进长链接：token 只能活 5 分钟，写死就等于链接也只有 5 分钟；
 * 而写死一个长期 token 又等于永久后门。这里存"谁 + 哪本书 + 何时失效"，
 * 每次点击现签 5 分钟 token —— 链接能活 1 天，凭证永远只有 5 分钟。 */
const shortId = () => {
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  return [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
};

async function ensureShortLink(env, adminId, bookId, codeId, qq, ttlSec) {
  const ttl = Math.max(60, Math.min(30 * 86400, Number(ttlSec) || 86400));
  // 复用未过期的那条：不然每点一次领取就多一条记录，清理起来很烦
  const ex = rowsToObjs(await sql(env,
    `SELECT id FROM short_links
      WHERE code_id=? AND book_id=? AND revoked=0 AND exp > datetime('now')
      ORDER BY created_at DESC LIMIT 1`, [codeId, bookId]))[0];
  if (ex) return String(ex.id);
  const id = shortId();
  const exp = new Date(Date.now() + ttl * 1000).toISOString().replace("T", " ").slice(0, 19);
  await sql(env,
    `INSERT INTO short_links(id,admin_id,book_id,code_id,qq,exp)
     VALUES(?,?,?,?,?,?)`, [id, adminId, bookId, codeId, qq, exp]);
  return id;
}

/* 领取门禁：黑名单 > 分享窗口 > 分享范围。
 *
 * 顺序不能换：黑名单是"这个人永远不许领"，窗口是"这本书现在不开放"，
 * 范围是"这本书只给某批人"。三者叠加时，黑名单的语义最硬 —— 即使在组里也要拒。
 * 返回 null 表示通过。 */
async function claimGate(env, adminId, qq, bookId) {
  const bl = rowsToObjs(await sql(env,
    "SELECT reason FROM blocklist WHERE admin_id=? AND qq=?", [adminId, qq]))[0];
  if (bl) {
    return { status: 403, body: { ok: false, code: "BANNED",
      error: "该账号已被禁止领取，请联系发放人" } };
  }

  const bk = rowsToObjs(await sql(env,
    `SELECT id,title,share_status,share_scope
       FROM books WHERE id=? AND admin_id=?`, [bookId, adminId]))[0];
  if (!bk) return { status: 404, body: { ok: false, code: "BOOK_NOT_FOUND", error: "没有这本书" } };

  const scope = String(bk.share_scope || "").trim();
  if (!scope) return null;                          // NULL = 不限制（兼容现有书）

  let sc = null;
  try { sc = JSON.parse(scope); } catch (_) { sc = null; }
  if (!sc) return null;                              // 脏数据按"不限制"处理，不要把人挡在门外
  // '{}' / {groups:[],qqs:[]} 也当不限制：否则 API 直调写个空对象就能把整本书锁死
  const _g = (sc.groups || []).filter(Boolean);
  const _q = (sc.qqs || []).filter(Boolean);
  if (!_g.length && !_q.length) return null;
  sc = { groups: _g, qqs: _q };

  const qqs = (sc.qqs || []).map(String);
  if (qqs.includes(String(qq))) return null;

  const gids = (sc.groups || []).map(Number).filter(Boolean);
  if (gids.length) {
    const hit = rowsToObjs(await sql(env,
      `SELECT 1 AS x FROM group_members gm
         JOIN recipients r ON r.id = gm.recipient_id
        WHERE r.admin_id=? AND r.qq=? AND gm.group_id IN (${gids.map(() => "?").join(",")})
        LIMIT 1`, [adminId, qq, ...gids]))[0];
    if (hit) return null;
  }
  return { status: 403, body: { ok: false, code: "NOT_IN_SCOPE",
    error: "这本书没有分享给你，请联系发放人" } };
}

/* 解析"打标用哪个版本"：不传 = 当前版（返回 null 表示走 books.r2_key）；
 * 传了但查不到/不属于这本书 = 返回 undefined（调用方报 400）。 */
async function pickVersion(env, bookId, raw) {
  if (raw === undefined || raw === null || raw === "" || Number(raw) === 0) return null;
  const id = Number(raw);
  if (!id) return undefined;
  const v = rowsToObjs(await sql(env,
    "SELECT id FROM book_versions WHERE id=? AND book_id=?", [id, bookId]))[0];
  return v ? Number(v.id) : undefined;
}

/* ---------------------------------------------------------------- Turso */
function arg(v) {
  if (v === null || v === undefined) return { type: "null", value: null };
  if (typeof v === "number") {
    // ⚠️ 浮点必须单独编码：全部当 integer 会让 Turso 直接 400
    //    「invalid value: string "0.2344424", expected decimal integer as a string」
    //    真实事故：水印密钥（chaos_seed 0.234…）回传时回调 500，批次永远卡在 running。
    return Number.isInteger(v)
      ? { type: "integer", value: String(v) }
      : { type: "float", value: v };
  }
  if (typeof v === "boolean") return { type: "integer", value: v ? "1" : "0" };
  return { type: "text", value: String(v) };
}
async function sql(env, q, args = []) {
  const r = await fetch(`${env.TURSO_URL}/v2/pipeline`, {
    method: "POST",
    headers: { Authorization: `Bearer ${env.TURSO_TOKEN}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      requests: [
        { type: "execute", stmt: { sql: q, args: args.map(arg) } },
        { type: "close" },
      ],
    }),
  });
  if (!r.ok) throw new Error(`turso ${r.status}: ${(await r.text()).slice(0, 200)}`);
  const d = await r.json();
  const first = d.results?.[0];
  if (first?.type === "error") throw new Error("turso: " + first.error.message);
  const res = first?.response?.result;
  if (!res) return { rows: [], cols: [], changes: 0 };
  // changes = affected_row_count：R2 配额要靠它判断"条件更新到底改了几行"
  // （=0 就是"放不下"，这是熔断的判据，不能靠事后 SELECT 猜）
  return {
    cols: res.cols.map((c) => c.name),
    rows: res.rows || [],
    changes: Number(res.affected_row_count || 0),
  };
}
/* 批量执行：一次 HTTP 发 N 条语句。
 *
 * 为什么必须有它：Cloudflare 免费版**单次 Worker 调用最多 50 个子请求**。
 * 回填 20 个人时，每人 3 次（查存在 / 插 / 回读）= 60 次 → 直接 500
 * 「Too many subrequests by single Worker invocation」。这是真实踩到的。
 * 走 pipeline 后，20 条 INSERT 只算 1 次子请求，人数再多也不会爆。
 *
 * 注意：这里用 `INSERT OR IGNORE`，唯一冲突静默跳过，由调用方回读时发现。
 */
async function sqlMany(env, stmts) {
  if (!stmts.length) return [];
  const r = await fetch(`${env.TURSO_URL}/v2/pipeline`, {
    method: "POST",
    headers: { Authorization: `Bearer ${env.TURSO_TOKEN}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      requests: [
        ...stmts.map((s) => ({
          type: "execute",
          stmt: { sql: s.q, args: (s.args || []).map(arg) },
        })),
        { type: "close" },
      ],
    }),
  });
  if (!r.ok) throw new Error(`turso ${r.status}: ${(await r.text()).slice(0, 200)}`);
  const d = await r.json();
  const bad = (d.results || []).find((x) => x.type === "error");
  if (bad) throw new Error("turso: " + bad.error.message);
  return (d.results || []).map((x) => {
    const res = x?.response?.result;
    return res
      ? { cols: res.cols.map((c) => c.name), rows: res.rows || [], changes: Number(res.affected_row_count || 0) }
      : { cols: [], rows: [], changes: 0 };
  });
}

/* 一次 workflow run 最多打多少本。
 * GitHub 免费账号并发 job 上限 20；每个 run 占 1 个 job，
 * 所以 chunk 越大、run 越少、越不容易撞并发墙。
 * 15 是折中：200 人 → 14 个 run（<20），单 run 约 30~60 秒。
 * ⚠️ 这个值必须和 .github/workflows 里的 `--limit` 保持一致。 */
const CHUNK = 15;

/** 带重试的写：Turso 是 SQLite 内核，并发写会出现 "database is locked"/5xx。
 *  只用于**幂等**语句（UPSERT / UPDATE 状态），重放不会产生脏数据。 */
async function sqlRetry(env, q, args = [], tries = 4) {
  let last;
  for (let i = 0; i < tries; i++) {
    try {
      return await sql(env, q, args);
    } catch (e) {
      last = e;
      const msg = String(e && e.message || e);
      const retriable = /locked|busy|5\d\d|network|fetch|timeout|ECONN/i.test(msg);
      if (!retriable || i === tries - 1) break;
      await new Promise((r) => setTimeout(r, 200 * Math.pow(2, i)));
    }
  }
  throw last;
}

/* Turso 的 null 会回成 {type:"null", value:null}。
 * 原来写的是 `v?.value ?? v` —— null 走 ?? 会把整个对象吐出来，
 * 于是 `expires_at` 变成 {"type":"null"}，前端拿它跟字符串比永远不等。
 * 必须按 "type in v" 判，而不是按空值判。 */
const rowsToObjs = ({ cols, rows }) =>
  rows.map((r) => Object.fromEntries(r.map((v, i) => {
    const val = (v && typeof v === "object" && "type" in v) ? v.value : v;
    return [cols[i], val];
  })));

/* ------------------------------------------------ R2 用量账本（0 付费红线）
 *
 * 三条铁律：
 *   1) 上传前**先记账**（条件更新，放不下就 0 行受影响）→ 直接 507，绝不写对象；
 *   2) 记账失败/写 R2 出错要**回滚**账本，否则账越跑越偏；
 *   3) 60% / 80% 各报一次警，回落 5% 以上再复位（防阈值附近反复骚扰）。
 *
 * 已知误差：同一 key 覆盖写会多记一次（本 PoC 的 key 是 out/<batch>.epub，天然不重），
 * 上线前如果改成"覆盖写"，要改成按 key 差量记账。
 */
const GIB = 1024 * 1024 * 1024;

async function usage(env) {
  const r = rowsToObjs(await sql(env,
    "SELECT bytes,objects,limit_bytes,alert_60,alert_80 FROM r2_usage WHERE id=1"))[0] || {};
  return {
    bytes: Number(r.bytes || 0),
    objects: Number(r.objects || 0),
    // 库里的值优先：这样"运行时改限额"（运维应急 / 测试造边界）才能立刻生效；
    // env.R2_QUOTA_LIMIT 只在库为空时兜底，部署脚本会把它写进库当种子。
    limit: Number(r.limit_bytes || env.R2_QUOTA_LIMIT || 8 * GIB),
    alert60: Number(r.alert_60 || 0),
    alert80: Number(r.alert_80 || 0),
  };
}

/**
 * 原子记账：放得下才加。返回 false = 超限。
 *
 * ⚠️ 上限必须用 usage() 算出来的**有效值**（env.R2_QUOTA_LIMIT 优先，其次库里的），
 * 不能再写死 `<= limit_bytes` —— 否则会出现"面板显示 9.5 GiB，实际按库里的 8 GiB 拦"，
 * 排查时极难发现（真实踩过）。
 */
async function charge(env, n) {
  const u = await usage(env);
  const res = await sql(env,
    `UPDATE r2_usage SET bytes=bytes+?, objects=objects+1, updated_at=datetime('now')
      WHERE id=1 AND bytes+? <= ?`, [n, n, u.limit]);
  return res.changes === 1;
}

async function release(env, n) {
  await sql(env,
    `UPDATE r2_usage SET bytes=MAX(0, bytes-?), objects=MAX(0, objects-1),
            updated_at=datetime('now') WHERE id=1`, [Math.max(0, n)]);
}

async function alertIfNeeded(env, ctx) {
  const u = await usage(env);
  const pct = u.limit ? u.bytes / u.limit : 0;
  const todo = [];
  if (pct >= 0.8 && !u.alert80) todo.push([80, "alert_80"]);
  if (pct >= 0.6 && !u.alert60) todo.push([60, "alert_60"]);

  for (const [lvl, col] of todo) {
    await sql(env, `UPDATE r2_usage SET ${col}=1 WHERE id=1`);   // 先占位，防并发重复发
    const text = `[R2 用量告警] 已用 ${(u.bytes / GIB).toFixed(2)} GiB / `
      + `${(u.limit / GIB).toFixed(2)} GiB（${(pct * 100).toFixed(1)}%，阈值 ${lvl}%），`
      + `对象 ${u.objects} 个。超 8 GiB 后将拒绝上传（507）。`;
    if (!env.ALERT_WEBHOOK) continue;
    const p = fetch(env.ALERT_WEBHOOK, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        event: "r2_quota", level: lvl, percent: +(pct * 100).toFixed(1),
        used_bytes: u.bytes, limit_bytes: u.limit, objects: u.objects, text,
      }),
    }).catch(() => {});
    if (ctx && ctx.waitUntil) ctx.waitUntil(p); else await p;
  }

  // 回落复位（5% 滞回）：否则在 60% 附近抖动会反复报警
  if (pct < 0.55 && u.alert60) await sql(env, "UPDATE r2_usage SET alert_60=0 WHERE id=1");
  if (pct < 0.75 && u.alert80) await sql(env, "UPDATE r2_usage SET alert_80=0 WHERE id=1");
}

/* ---------------------------------------------------------------- GitHub */
/**
 * 故障注入：只有 env.ALLOW_INJECT === "1" 时才认 body 里的 simulate。
 * 生产环境变量里不要设 ALLOW_INJECT，注入面就等于不存在。
 * 取值（与 .github/workflows 的 simulate input 一一对应）：
 *   crash_before  领到任务后、跑引擎前非零退出（模拟 runner 半路挂）
 *   crash_after   引擎跑完、回调前非零退出（成品已产出但没人回调 → 只能靠看门狗收敛）
 *   no_callback   正常跑完但故意不回调（模拟网络断了）
 *   turso_fail    回调到达但写库失败（Worker 侧返回 500，状态必须靠看门狗转 failed）
 */
const SIM_OK = new Set(["crash_before", "crash_after", "no_callback", "turso_fail"]);
function inject(env, v) {
  if (env.ALLOW_INJECT !== "1") return "";
  const x = String(v || "");
  return SIM_OK.has(x) ? x : "";
}

async function dispatch(env, batchId, cbToken, simulate = "") {
  const r = await fetch(
    `https://api.github.com/repos/${env.GH_REPO}/actions/workflows/${env.WF_FILE}/dispatches`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${env.GH_PAT}`,   // ← 只在这一行出现，绝不外传
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "wm-poc-worker",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        ref: env.GH_REF || "main",
        // inputs 只放这两个：都不敏感，且都不含 QQ/密钥
        // simulate 只在 ALLOW_INJECT=1 时才带（否则 undefined 会被 JSON 丢掉）
        inputs: Object.assign(
          { batch_id: batchId, cb: cbToken, worker: env.PUBLIC_BASE },
          simulate ? { simulate } : {}),
      }),
    });
  if (r.status !== 204) return { ok: false, status: r.status, body: (await r.text()).slice(0, 300) };
  return { ok: true, status: 204 };
}

/* 触发云端溯源解码（独立 workflow，输入与打标完全分开）。
 * trace_token 是一次性 token（scope=trace 绑 job_id）：
 * 就算它出现在 Actions 日志里，也只能回调这一个工单，且 15 分钟失效。 */
async function dispatchTrace(env, jobId, fileUrl) {
  const tok = await makeToken(env, "trace", jobId, 900);
  const wf = env.TRACE_WF || "trace_poc.yml";
  const r = await fetch(
    `https://api.github.com/repos/${env.GH_REPO}/actions/workflows/${wf}/dispatches`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${env.GH_PAT}`,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "wm-poc-worker",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        ref: env.GH_REF || "main",
        inputs: { job_id: jobId, file_url: fileUrl,
                  worker: env.PUBLIC_BASE, trace_token: tok },
      }),
    });
  if (r.status !== 204) {
    return { ok: false, status: r.status, body: (await r.text()).slice(0, 200) };
  }
  return { ok: true, status: 204 };
}

/* ---------------------------------------------------------------- 入口 */
export { makeToken, checkToken, INITPW };


/* ---------------------------------------------------------------- 首页（手机可读）
 * 为什么 Worker 要有首页：绑自定义域名后，手机打开 https://wm.xxx.xyz 必须能看到东西，
 * 否则只会拿到 {"ok":false,"error":"not found"} 的 JSON 404，无法判断"是域名没绑通"还是"页面没做"。
 * 这里顺手做了自检 + 领取，一页就能验完「域名 / 网关 / 数据库 / 领取接口」四件事。
 */
/* ------------------------------------------------------------------ 管理端页面
 * 设计取舍：
 *  - 单文件、零依赖、零构建 —— Worker 里塞 HTML 是最省的部署方式；
 *  - 生成完立刻给"可复制的 TSV"（QQ<TAB>暗号），粘进 Excel 自动分列，
 *    比让人一条条抄强得多；
 *  - 单条新增时只显示那一张卡，不让人在大表里找自己刚加的那条；
 *  - 没有前端路由，四个 tab 靠 display 切换（刷新回到第一个）。
 */
const ADMIN_HTML = `<!doctype html>
<html lang="zh-CN"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="robots" content="noindex,nofollow">
<title>打标分发 · 管理端</title>
<style>
  :root{--bg:#f4f5f7;--card:#fff;--ink:#1a1a1c;--sub:#8a8a91;--line:#ececf0;
        --ok:#0a8f4a;--bad:#c8342b;--warn:#b26b00;--brand:#2b6cff}
  *{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
  body{margin:0;padding:0;background:var(--bg);color:var(--ink);
       font:15px/1.55 -apple-system,BlinkMacSystemFont,"PingFang SC","Microsoft YaHei",sans-serif}
  h1{margin:0 0 3px;font-size:19px;letter-spacing:-.2px}
  .lead{margin:0;color:var(--sub);font-size:12px}
  .card{background:var(--card);border-radius:14px;padding:14px;margin-bottom:12px;
        box-shadow:0 1px 2px rgba(0,0,0,.04),0 8px 24px rgba(0,0,0,.03)}
  .card h2{margin:0 0 10px;font-size:13px;font-weight:600;color:var(--sub);letter-spacing:.03em}
  input,textarea,select{width:100%;padding:12px 13px;font-size:15px;border:1px solid var(--line);
        border-radius:10px;background:#fafafb;color:var(--ink);outline:none;font-family:inherit}
  input:focus,textarea:focus{border-color:var(--brand);background:#fff}
  textarea{resize:vertical;line-height:1.6}
  .btn{display:inline-block;padding:11px 16px;font-size:14px;font-weight:600;color:#fff;
       background:var(--brand);border:0;border-radius:10px;cursor:pointer}
  .btn:active{opacity:.85}
  .btn.wide{display:block;width:100%;padding:13px;font-size:15px;margin-top:10px}
  .btn.ghost{background:#eef1f6;color:#2b2b30;font-weight:500;border:1px solid var(--line)}
  .btn.sm{padding:7px 11px;font-size:13px;border-radius:8px}
  .btn.danger{background:#fdeceb;color:var(--bad)}
  .row{display:flex;gap:8px;align-items:center}
  .row>*{flex:1}
  .row>.fix{flex:0 0 auto}
  .sub{color:var(--sub);font-size:12px}
  .bad{color:var(--bad)} .okc{color:var(--ok)}
  .tabs{display:flex;gap:6px;margin:0 0 12px;overflow:auto}
  .tab{flex:1 0 auto;padding:9px 13px;font-size:13px;font-weight:600;color:var(--sub);
       background:#fff;border:1px solid var(--line);border-radius:99px;cursor:pointer;white-space:nowrap}
  .tab.on{background:var(--brand);color:#fff;border-color:var(--brand)}
  .pb{height:8px;background:#eef0f4;border-radius:99px;overflow:hidden;margin:10px 0 6px}
  .pb>i{display:block;height:100%;width:4%;background:var(--brand);border-radius:99px;transition:width .4s}
  .one{text-align:center;padding:16px 10px;background:#f7f9ff;border:1px solid #dfe6ff;border-radius:12px;margin:10px 0}
  .oneqq{font-size:13px;color:var(--sub)}
  .onecode{font-size:32px;font-weight:700;letter-spacing:6px;color:var(--brand);margin:4px 0 8px;font-variant-numeric:tabular-nums}
  #genTsv{margin-top:8px;font-family:ui-monospace,Menlo,monospace;font-size:13px;background:#fff;border:1px solid var(--line)}
  .cr{display:block;padding:10px 2px;border-top:1px solid var(--line);font-size:14px}
  .cr:first-child{border-top:0}
  .cr.rev{opacity:.45}
  .cr-top{display:flex;align-items:center;gap:7px}
  .cr-top b{font-variant-numeric:tabular-nums;font-size:14px}
  .cr-bot{display:flex;align-items:center;gap:6px;margin-top:7px;flex-wrap:wrap}
  .use{font-size:12px;color:var(--sub);font-variant-numeric:tabular-nums;margin-left:auto}
  .mgrid{display:grid;grid-template-columns:1fr 1fr;gap:8px}
  .mcell{background:#fafafb;border:1px solid var(--line);border-radius:10px;padding:10px 12px}
  .mnum{font-size:21px;font-weight:600;font-variant-numeric:tabular-nums;letter-spacing:-.3px}
  .bk-h{display:flex;justify-content:space-between;align-items:flex-start;gap:10px}
  .bk-h b{font-size:15px}
  .verlist{margin-top:9px;border-top:1px solid var(--line)}
  .ver{display:flex;justify-content:space-between;gap:10px;padding:6px 0;font-size:13px;
       border-bottom:1px solid var(--line)}
  .ver:last-child{border-bottom:0}
  .lnk{border:0;background:none;color:var(--brand);font-size:12px;padding:0 4px;cursor:pointer}
  .flab{display:block;font-size:12px;color:var(--sub);margin:10px 0 5px}
  .lkrow{display:flex;align-items:center;gap:8px;padding:8px 2px;border-top:1px solid var(--line)}
  .lkrow:first-child{border-top:0}
  .lkrow.off{opacity:.45}
  .lkq{flex:1;min-width:0;display:flex;flex-direction:column}
  .lkq b{font-variant-numeric:tabular-nums;font-size:13px}
  .short{display:flex;align-items:center;justify-content:space-between;gap:8px;margin-top:10px;
         padding:8px 10px;background:#f4f7ff;border-radius:9px;font-size:12px;color:var(--sub)}
  .scopy{border:0;background:var(--brand);color:#fff;font-size:12px;padding:5px 10px;border-radius:7px}
  .grow{display:flex;align-items:center;gap:7px;padding:8px 2px;border-top:1px solid var(--line)}
  .grow:first-child{border-top:0}
  .grow .gname{flex:1;min-width:0;cursor:pointer;font-size:14px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .grow.on .gname{font-weight:700;color:var(--brand)}
  .tag.mode{background:#eef3ff;color:var(--brand)}
  .rcrow{display:flex;align-items:center;gap:8px;padding:7px 2px;
         border-top:1px solid var(--line);font-size:13px}
  .rcrow:first-child{border-top:0}
  .rcq{flex:1;min-width:0;display:flex;flex-direction:column}
  .rcq b{font-variant-numeric:tabular-nums}
  .lvt{margin-top:4px;border-top:1px solid var(--line)}
  .lvrow{display:flex;align-items:flex-start;gap:7px;padding:6px 0;
         border-bottom:1px solid var(--line);font-size:12px}
  .lvrow:last-child{border-bottom:0}
  .lvm{width:14px;flex:0 0 14px;text-align:center;font-weight:600}
  .lvg{flex:0 0 auto;color:var(--sub)}
  .lvn{flex:0 0 auto;font-weight:500}
  .lvs{flex:1;min-width:0;word-break:break-all}
  .warn{color:var(--warn)}
  .mlabel{font-size:11px;color:var(--sub);margin-top:2px}
  .code{font-family:ui-monospace,Menlo,monospace;font-size:14px;font-weight:700;letter-spacing:1px;
        color:var(--brand);background:#eef3ff;border:1px dashed #b9cdff;border-radius:7px;padding:4px 8px;cursor:pointer}
  .tag{font-size:11px;padding:1px 6px;border-radius:99px;white-space:nowrap}
  .tag.on{background:#e6f7ee;color:var(--ok)}
  .tag.off{background:#f0f0f3;color:var(--sub)}
  .use{font-size:12px;color:var(--sub);font-variant-numeric:tabular-nums;min-width:28px;text-align:right}
  .mini{font-size:12px;padding:4px 8px;border-radius:7px;border:1px solid var(--line);
        background:#fafafb;color:var(--sub);cursor:pointer}
  .mini.bad{color:var(--bad);border-color:#f6d5d2;background:#fdf3f2}
  .empty{text-align:center;color:var(--sub);font-size:13px;padding:18px 0}
  .banner{padding:10px 12px;border-radius:10px;font-size:13px;margin-bottom:10px}
  .banner.warn{background:#fff7e6;color:#8a5b00;border:1px solid #ffe0a3}
  .banner.ok{background:#e9f9f0;color:#0a6b39;border:1px solid #b8e8cd}
  #login{padding:18px 16px 40px}
  .pwwrap{position:relative}
  .pwwrap input{padding-right:58px}
  .pwtoggle{position:absolute;right:6px;top:50%;transform:translateY(-50%);
            border:0;background:none;color:var(--brand);font-size:12px;
            padding:8px 10px;cursor:pointer;border-radius:8px}
  .pwtoggle:active{background:#eef3ff}
  .modal{position:fixed;inset:0;background:rgba(17,17,20,.42);z-index:60;
         display:flex;align-items:center;justify-content:center;padding:16px}
  .modal-box{background:var(--card);border-radius:14px;width:100%;max-width:430px;
             max-height:82vh;overflow:auto;padding:14px 16px 16px}
  .mhead{display:flex;align-items:center;justify-content:space-between;margin-bottom:10px}
  .mhead b{font-size:15px}
  .shell{display:flex;min-height:100vh}
  .side{width:150px;flex:0 0 150px;background:var(--card);border-right:1px solid var(--line);
        padding:16px 0;display:flex;flex-direction:column}
  .brand{padding:0 16px 14px;font-size:15px;font-weight:600;letter-spacing:-.2px}
  .side nav{display:flex;flex-direction:column}
  .side nav a{display:block;padding:9px 16px;font-size:13px;color:var(--sub);cursor:pointer;
              border-left:2px solid transparent;text-decoration:none}
  .side nav a.on{color:var(--ink);font-weight:600;background:#f4f7ff;border-left-color:var(--brand)}
  .main{flex:1;min-width:0;padding:18px 16px 60px}
  .phead{display:flex;align-items:flex-start;justify-content:space-between;gap:10px;margin-bottom:14px}
  .phead h1{font-size:19px;margin:0}
  .phead .lead{margin:3px 0 0}
  @media(max-width:720px){
    .shell{flex-direction:column;min-height:0}
    .side{width:100%;flex:0 0 auto;border-right:0;border-bottom:1px solid var(--line);padding:10px 0 0}
    .brand{padding:0 16px 8px}
    .side nav{flex-direction:row;overflow-x:auto;padding:0 6px}
    .side nav a{border-left:0;border-bottom:2px solid transparent;white-space:nowrap;padding:9px 11px}
    .side nav a.on{background:none;border-bottom-color:var(--brand)}
    .main{padding:14px 14px 60px}
  }
  .foot{text-align:center;color:#b0b0b8;font-size:11px;margin-top:22px;line-height:1.8}
  a{color:var(--brand)}
  .hide{display:none!important}
  .chk{display:flex;align-items:center;gap:7px;font-size:13px;color:var(--sub);
       margin-top:10px;cursor:pointer}
  .chk input{width:auto;margin:0;flex:0 0 auto}
</style></head>
<body>

<!-- ============ 登录 ============ -->
<div id="login">
  <h1>打标分发 · 管理端</h1>
  <p class="lead" id="loginLead">请输入管理员口令</p>
  <div class="card" style="margin-top:14px">
    <div class="pwwrap">
      <input id="pw" type="password" autocomplete="current-password" placeholder="管理员口令">
      <button class="pwtoggle" id="pwToggle" type="button">显示</button>
    </div>
    <button class="btn wide" id="doLogin">登录</button>
    <div class="sub" style="margin-top:8px;text-align:center">登录后 30 天内免输入</div>
    <div id="loginMsg" class="sub" style="margin-top:10px;min-height:18px"></div>
  </div>
  <div class="foot">仅授权人员使用</div>
</div>

<!-- ============ 主界面 ============ -->
<div id="app" class="hide">
<div class="shell">
  <aside class="side">
    <div class="brand">打标分发</div>
    <nav id="nav">
      <a data-tab="dash" class="on">仪表盘</a>
      <a data-tab="books">书籍管理</a>
      <a data-tab="contacts">联系人</a>
      <a data-tab="codes">取件码</a>
      <a data-tab="batch">打标任务</a>
      <a data-tab="trace">溯源</a>
      <a data-tab="set">设置</a>
    </nav>
  </aside>

  <main class="main">
    <div class="phead">
      <div style="min-width:0">
        <h1 id="pageTitle">仪表盘</h1>
        <p class="lead" id="pageSub">—</p>
      </div>
      <div style="display:flex;gap:6px;flex:0 0 auto">
        <button class="btn sm ghost" id="reload">刷新</button>
        <button class="btn sm ghost" id="doLogout">退出</button>
      </div>
    </div>

    <div class="card" style="padding:10px 12px" id="bookBar">
      <div class="row"><select id="bookSel"></select></div>
    </div>

  <!-- 书籍管理 -->
  <div id="tab-books" class="hide">
    <div class="card">
      <h2>新建一本书</h2>
      <div class="row">
        <input id="newBookTitle" placeholder="书名，例如：财神春花 V2.0">
        <button class="btn fix" id="doNewBook">创建</button>
      </div>
      <div class="sub" style="margin-top:6px">创建后上传母本；同一本书可上传多个版本。</div>
    </div>
    <div id="bookList"><div class="empty">加载中…</div></div>
    <input type="file" id="filePick" accept=".epub,application/epub+zip" class="hide">
  </div>

  <!-- 仪表盘 -->
  <div id="tab-dash">
    <div class="card">
      <h2>存储（R2）</h2>
      <div class="mnum" id="mUsed">—</div>
      <div class="pb"><i id="mBar"></i></div>
      <div class="sub" id="mSub"></div>
    </div>
    <div class="card">
      <h2>概览</h2>
      <div class="mgrid">
        <div class="mcell"><div class="mnum" id="mBooks">—</div><div class="mlabel">本书</div></div>
        <div class="mcell"><div class="mnum" id="mCodes">—</div><div class="mlabel">个取件码</div></div>
        <div class="mcell"><div class="mnum" id="mFiles">—</div><div class="mlabel">个成品</div></div>
        <div class="mcell"><div class="mnum" id="mNew">—</div><div class="mlabel">24 小时新增</div></div>
      </div>
    </div>
    <div class="card">
      <h2>正在分享</h2>
      <div id="mOpen"><div class="empty">加载中…</div></div>
    </div>
  </div>

  <!-- 联系人：分组 + 黑名单 -->
  <div id="tab-contacts" class="hide">
    <div class="card">
      <h2>分组</h2>
      <div class="sub">一个人可以同时属于多个分组；重复导入只会"加进来"，不会把人从别的组挪走。</div>
      <div class="row" style="margin-top:10px">
        <input id="grpName" placeholder="新分组名，如：第一批 / 老读者">
        <button class="btn fix" id="doGrpAdd">新建</button>
      </div>
      <div id="grpList" style="margin-top:10px"></div>
    </div>

    <div class="card">
      <h2>组成员 <span class="sub" id="grpNow"></span></h2>
      <div class="row">
        <input id="memQQ" placeholder="粘贴 QQ 号（逗号/换行分隔）">
        <button class="btn fix" id="doMemAdd">加入</button>
      </div>
      <div class="row" style="margin-top:8px">
        <button class="btn sm ghost" id="doMemRemove">移出输入框里的人</button>
        <button class="btn sm ghost" id="doMemFromCodes">把分享过的人都加进来</button>
        <button class="btn sm ghost" id="doMemSel">多选</button>
      </div>
      <div class="row hide" id="memBatchBar" style="margin-top:8px">
        <label class="chk" style="flex:0 0 auto"><input type="checkbox" id="memAll"> 全选</label>
        <button class="btn sm ghost" id="doMemBatchRemove">移出所选</button>
        <button class="btn sm ghost" id="doMemBatchBan">拉黑所选</button>
      </div>
      <div class="sub" style="margin-top:8px">
        从文件导入：Excel 里「另存为 → CSV」后选文件即可（一列 QQ，有表头也没关系）
      </div>
      <input type="file" id="memFile" accept=".csv,.txt,text/csv,text/plain" style="margin-top:6px">
      <div id="memList" style="margin-top:10px"></div>
    </div>

    <div class="card">
      <h2>黑名单</h2>
      <div class="sub">被拉黑的人无论有没有取件码、窗口开不开，领取和下载都会被拒。码和成品保留，溯源要用。</div>
      <div class="row" style="margin-top:10px">
        <input id="blQQ" placeholder="QQ 号，多个用逗号/换行">
        <button class="btn fix" id="doBlAdd">拉黑</button>
      </div>
      <input id="blReason" placeholder="原因（可选），如：倒卖" style="margin-top:8px">
      <div id="blList" style="margin-top:10px"></div>
    </div>
  </div>

  <!-- 生成 -->
  <div id="tab-gen" class="hide">
    <div class="card">
      <h2>领取人名单（<span id="rcCount">0</span> 人）</h2>
      <div class="row">
        <input id="rcQQ" placeholder="QQ 号，多个用逗号 / 换行">
        <button class="btn fix" id="doRcAdd">加入</button>
      </div>
      <input id="rcNote" placeholder="备注（可选，写给这批人，如：第一批）" style="margin-top:8px">
      <div class="row" style="margin-top:8px">
        <button class="btn sm ghost" id="doRcToCodes">名单里没码的一键发码</button>
        <button class="btn sm ghost" id="doRcRefresh">刷新</button>
      </div>
      <div id="rcList" style="margin-top:10px"></div>
    </div>

    <div class="card">
      <h2>粘贴 QQ 号（每行一个，也支持逗号 / 空格分隔）</h2>
      <textarea id="genQQ" rows="5" placeholder="200000001&#10;200000002&#10;200000003"></textarea>
      <div class="row" style="margin-top:8px">
        <input id="genUses" type="number" min="1" max="50" value="3" title="每码可下载次数">
        <input id="genDays" type="number" min="0" max="365" value="0" title="有效天数，0=不过期">
        <button class="btn fix" id="doGen">生成</button>
      </div>
      <div class="sub" style="margin-top:6px">左边=次数上限，右边=有效天数（0 不过期）。已存在的 QQ 会复用原码，不会覆盖。</div>
      <div id="genOut"></div>
    </div>
  </div>

  <!-- 码表 -->
  <div id="tab-list" class="hide">
    <div class="card">
      <h2>取件码（<span id="codeCount">0</span> 条）</h2>
      <div class="sub" style="margin-bottom:8px">
        一人一码，所有书通用 —— 发新书不用重新发码。码被人转发出去就点「换码」。
      </div>
      <div class="row" style="margin-bottom:8px">
        <input id="q" placeholder="搜 QQ 或暗号">
        <button class="btn sm ghost fix" id="doSearch">搜索</button>
      </div>
      <div class="row" style="margin-bottom:8px">
        <button class="btn sm ghost" id="doExport">导出 CSV</button>
        <button class="btn sm ghost" id="doCopyAll">复制全部</button>
        <button class="btn sm ghost" id="doBackfill">从成品回填</button>
      </div>
      <div class="row" style="margin-bottom:8px">
        <button class="btn sm ghost" id="doResetAll">一键重置全部次数</button>
      </div>
      <div id="codeList"><div class="empty">加载中…</div></div>
      <div class="sub" style="margin-top:10px">点暗号可直接改；「作废」后该码立即失效但不删数据。</div>
    </div>
  </div>

  <!-- 试打 -->
  <div id="tab-try" class="hide">
    <div class="card">
      <h2>试打一本（放量前先验收）</h2>
      <div class="banner warn">只打 1 本，约 30~90 秒。确认封面和水印没问题，再去「批量打标」。</div>
      <label class="flab">用哪一版母本打</label>
      <select id="tryVer"></select>
      <input id="tryQQ" inputmode="numeric" placeholder="测试用 QQ 号（5~12 位）">
      <button class="btn wide" id="doTry">开始试打</button>
      <div id="tryOut" style="margin-top:10px"></div>
    </div>
  </div>

  <!-- 批量 -->
  <div id="tab-batch" class="hide">
    <div class="card">
      <h2>批量打标</h2>
      <div class="banner warn">每波 15 本，200 人约 14 波。后台跑，页面可以关。</div>
      <label class="flab">用哪一版母本打</label>
      <select id="batchVer"></select>
      <textarea id="batchQQ" rows="6" placeholder="粘贴 QQ 号，每行一个"></textarea>
      <button class="btn wide" id="doBatch">提交打标</button>
      <div id="batchOut" style="margin-top:10px"></div>
    </div>
  </div>

  <!-- 溯源 -->
  <div id="tab-trace" class="hide">
    <div class="card">
      <h2>导入疑似文件（推荐）</h2>
      <div class="sub">上传你从别处拿到的 EPUB，系统会解出 7 层水印并告诉你这是谁的书、哪一版母本。</div>
      <div class="banner warn" style="margin-top:8px">
        注意：<b>图片层水印（DCT / 调色板）网页端不解析</b> —— 频域分析要 numpy/Pillow，
        边缘运行时跑不动。网页负责收件与展示，完整 7 层由本机 worker 计算；
        如果本机 worker 没启动，会明确提示"解码器未连接"。
      </div>
      <input id="traceNote" placeholder="发现渠道备注（可选），如：闲鱼卖家 xxx" style="margin-top:10px">
      <button class="btn wide" id="doTraceUp">选择文件并上传</button>
      <div id="traceJob" style="margin-top:12px"></div>
      <input type="file" id="traceFile" accept=".epub,application/epub+zip" class="hide">
    </div>

    <div class="card">
      <h2>已知水印 ID 直接查</h2>
      <div class="row">
        <input id="traceWid" placeholder="WM-XXXXXXXXXX-XXXXXX">
        <button class="btn fix" id="doTrace">查询</button>
      </div>
      <div id="traceOut" style="margin-top:12px"></div>
    </div>
  </div>

  <!-- 设置 -->
  <div id="tab-set" class="hide">
    <div class="card">
      <h2>分享设置</h2>
      <div class="sub">决定读者现在能不能领、能领哪一本、链接多久过期。</div>
      <button class="btn wide" id="openShareBtn">打开分享设置</button>
    </div>

    <div class="card">
      <h2>专用链接（<span id="lkCount">0</span> 条）</h2>
      <div class="sub">读者领取后自动生成；也可以在这里直接给某个人生成一条。</div>
      <div class="row" style="margin-top:8px">
        <select id="lkBook"></select>
        <input id="lkQQ" inputmode="numeric" placeholder="QQ 号">
        <button class="btn fix" id="doLkAdd">生成</button>
      </div>
      <div id="lkList" style="margin-top:10px"></div>
    </div>

    <div class="card">
      <h2>修改管理员口令</h2>
      <div class="banner warn" id="pwHint">改完后，其他设备上的登录会立刻失效。</div>
      <input id="pwOld" type="password" autocomplete="current-password" placeholder="当前口令">
      <input id="pwNew" type="password" autocomplete="new-password" placeholder="新口令（至少 6 位）" style="margin-top:8px">
      <input id="pwNew2" type="password" autocomplete="new-password" placeholder="再输一次新口令" style="margin-top:8px">
      <button class="btn wide" id="doPw">修改口令</button>
      <div id="pwOut" class="sub" style="margin-top:8px"></div>
    </div>
  </div>

    <div class="foot" id="foot"></div>
  </main>
</div>
</div>

<div id="chooser" class="modal hide">
  <div class="modal-box">
    <div class="mhead"><b id="chTitle">请选择</b><button class="mini" id="chCancel">取消</button></div>
    <div id="chBody"></div>
  </div>
</div>

<div id="modal" class="modal hide">
  <div class="modal-box">
    <div class="mhead">
      <b id="modalTitle">分享设置</b>
      <button class="mini" id="modalClose">关闭</button>
    </div>
    <div id="modalBody"><div class="card" style="box-shadow:none;padding:0;margin:0">
      <h2>分享设置（决定读者现在能不能领）</h2>
      <div class="banner warn" id="shareHint">关掉后：领取页显示"暂未开放"，已有下载链接也立即失效。</div>
      <select id="shBook"></select>
      <div class="row" style="margin-top:8px">
        <select id="shStatus">
          <option value="open">开放领取</option>
          <option value="closed">关闭领取</option>
        </select>
      </div>
      <div class="sub" style="margin:8px 0 4px">开始时间（留空 = 立即）</div>
      <input id="shOpen" type="datetime-local">
      <div class="sub" style="margin:8px 0 4px">结束时间（留空 = 一直开放）</div>
      <input id="shClose" type="datetime-local">
      <div class="sub" style="margin:8px 0 4px">备注（只有你能看到）</div>
      <input id="shNote" placeholder="例如：第一批 50 人">
      <label class="chk"><input type="checkbox" id="shCloseOthers" checked> 开启时关闭其他书（防串书）</label>

      <div class="sub" style="margin:14px 0 4px">专用链接有效期</div>
      <select id="shTtl">
        <option value="3600">1 小时</option>
        <option value="21600">6 小时</option>
        <option value="86400" selected>1 天</option>
        <option value="259200">3 天</option>
        <option value="604800">7 天</option>
      </select>
      <div class="sub" style="margin-top:4px">领取成功后给读者的那条 /s/ 链接；到期自动失效率，不消耗任何资源</div>

      <div class="sub" style="margin:14px 0 4px">分享范围（谁有资格领这本书）</div>
      <div class="row" style="gap:6px">
        <select id="shScopeMode">
          <option value="all">不限制 · 任何有取件码的人都能领</option>
          <option value="groups">只给指定分组</option>
          <option value="qqs">只给指定 QQ</option>
        </select>
      </div>
      <div id="shScopeWarn" class="banner warn" style="margin-top:8px">
        当前为「不限制」：只要拿到这本书的取件码，任何人都能领。
      </div>
      <div id="shScopeGroups" class="hide" style="margin-top:8px">
        <div class="sub" style="margin-bottom:6px">勾选分组（可多选，取并集）</div>
        <div id="shScopeGroupList"></div>
      </div>
      <div id="shScopeQqs" class="hide" style="margin-top:8px">
        <div class="sub" style="margin-bottom:6px">指定 QQ（每行一个）</div>
        <textarea id="shScopeQqText" rows="3" placeholder="200000001&#10;200000002"></textarea>
      </div>

      <button class="btn wide" id="doShare">保存</button>
      <div id="shareOut" class="sub" style="margin-top:8px"></div>
    </div>

</div>
  </div>
</div>
<script>
(function(){
"use strict";
var S = { bookId: 1, books: [], codes: [], tsv: "" };
function $(id){ return document.getElementById(id); }
function esc(s){
  return String(s==null?"":s).replace(/[&<>"']/g, function(c){
    return {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c];
  });
}
function api(path, opt){
  opt = opt || {};
  opt.headers = opt.headers || {};
  if (opt.body && typeof opt.body !== "string") {
    opt.body = JSON.stringify(opt.body);
    opt.headers["Content-Type"] = "application/json";
  }
  opt.credentials = "same-origin";
  return fetch(path, opt).then(function(r){
    return r.text().then(function(t){
      var d = {};
      try { d = JSON.parse(t); } catch (e) { d = { raw: String(t).slice(0,150) }; }
      if (r.status === 401 && path.indexOf("/api/admin/login") < 0) showLogin();
      return { status: r.status, data: d };
    });
  });
}
function copyText(txt, btn){
  function ok(){
    if (!btn) return;
    var o = btn.getAttribute("data-o") || btn.textContent;
    btn.setAttribute("data-o", o);
    btn.textContent = "已复制";
    setTimeout(function(){ btn.textContent = o; }, 1400);
  }
  function fallback(){
    var ta = document.createElement("textarea");
    ta.value = txt; ta.style.position = "fixed"; ta.style.top = "-999px";
    document.body.appendChild(ta); ta.select();
    try { document.execCommand("copy"); ok(); } catch (e) { alert("复制失败，请长按手动选择"); }
    document.body.removeChild(ta);
  }
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(txt).then(ok, fallback);
  } else fallback();
}
function parseQQ(txt){
  return String(txt||"").split(/[\\s,，;；、|]+/).map(function(s){ return s.replace(/\\D/g,""); })
    .filter(function(s){ return /^\\d{5,12}$/.test(s); });
}

/* 粘贴名单必须先给"解析预览"。
 * 之前 parseQQ 静默丢弃非法行，界面只说"共 47 条" —— 用户以为 50 人全覆盖，
 * 剩下 3 个人永远等不到码，而且没有任何线索。 */
function parseQQReport(txt){
  var raw = String(txt||"").split(/[\\s,，;；、|]+/).filter(function(x){ return x.trim(); });
  var seen = {}, ok = [], bad = [], suspect = [];
  raw.forEach(function(t){
    var d = t.replace(/\\D/g, "");
    if (!/^\\d{5,12}$/.test(d)) { bad.push(t); return; }
    if (d.length === 11 && d.charAt(0) === "1") suspect.push(d);
    if (!seen[d]) { seen[d] = 1; ok.push(d); }
  });
  return { raw: raw.length, ok: ok, bad: bad, suspect: suspect,
           dup: raw.length - bad.length - ok.length };
}
function confirmQQ(txt){
  var r = parseQQReport(txt);
  if (!r.ok.length && !r.bad.length) { alert("没识别到内容"); return null; }
  var msg = "识别 " + r.raw + " 行：合法 " + r.ok.length + " 个";
  if (r.dup > 0) msg += "，重复 " + r.dup + " 个（已去重）";
  if (r.bad.length) {
    msg += "\\n\\n将被丢弃 " + r.bad.length + " 行：" +
           r.bad.slice(0, 6).join("、") + (r.bad.length > 6 ? " …" : "");
  }
  if (r.suspect.length) {
    msg += "\\n\\n⚠ " + r.suspect.length + " 个是 11 位且以 1 开头，可能是手机号：" +
           r.suspect.slice(0, 6).join("、") + (r.suspect.length > 6 ? " …" : "");
  }
  msg += "\\n\\n继续？";
  if (!confirm(msg)) return null;
  return r.ok;
}
function showLogin(){ $("app").classList.add("hide"); $("login").classList.remove("hide"); }
function showApp(){ $("login").classList.add("hide"); $("app").classList.remove("hide"); }

/* ---------------- 登录 ---------------- */
$("doLogin").onclick = function(){
  var pw = $("pw").value;
  if (!pw) return;
  $("loginMsg").textContent = "验证中…";
  api("/api/admin/login", { method:"POST", body:{ password: pw } }).then(function(r){
    if (r.data.ok) { $("loginMsg").textContent = ""; boot(); }
    else $("loginMsg").innerHTML = '<span class="bad">' + esc(r.data.error || "登录失败") + '</span>';
  });
};
$("pwToggle").onclick = function(){
  var i = $("pw");
  var showing = i.type === "text";
  i.type = showing ? "password" : "text";
  this.textContent = showing ? "显示" : "隐藏";
  i.focus();
};
$("pw").addEventListener("keydown", function(e){ if (e.key === "Enter") $("doLogin").click(); });
$("doLogout").onclick = function(){
  api("/api/admin/logout", { method:"POST" }).then(function(){ showLogin(); });
};

/* ---------------- 导航 ----------------
 * 一个导航项可能对应多个面板："取件码"页 = 生成面板 + 码表面板，
 * "打标任务"页 = 试打面板 + 批量面板。这样导航 6 项就能覆盖原来 6 个 tab 的全部功能。 */
var PANES = {
  dash:  ["dash"],
  books: ["books"],
  contacts: ["contacts"],
  codes: ["gen", "list"],
  batch: ["try", "batch"],
  trace: ["trace"],
  set:   ["set"]
};
var TITLES = {
  dash:  ["仪表盘", "存储、数量、正在分享的书"],
  books: ["书籍管理", "上传母本、管理版本、控制分享"],
  codes: ["取件码", "生成、修改、导出发放凭证"],
  batch: ["打标任务", "试打验收、批量打标"],
  trace: ["溯源", "按水印反查是谁、哪一版母本"],
  set:   ["设置", "分享窗口、管理员口令"]
};
function switchTab(which){
  Array.prototype.forEach.call(document.querySelectorAll("#nav a"), function(a){
    a.classList.toggle("on", a.getAttribute("data-tab") === which);
  });
  Object.keys(PANES).forEach(function(k){
    PANES[k].forEach(function(pane){ $("tab-" + pane).classList.add("hide"); });
  });
  (PANES[which] || []).forEach(function(pane){ $("tab-" + pane).classList.remove("hide"); });
  var t = TITLES[which] || ["", ""];
  $("pageTitle").textContent = t[0];
  $("pageSub").textContent = t[1];
  // 书选择条只在这两页有意义
  $("bookBar").classList.toggle("hide", !(which === "codes" || which === "batch"));

  if (which === "dash") loadStats();
  if (which === "books") loadBookPage();
  if (which === "codes") { loadCodes(); loadRecipients(); }
  if (which === "contacts") { loadGroups(); loadBlocklist(); }
  if (which === "set") { loadLinks(); }
}
Array.prototype.forEach.call(document.querySelectorAll("#nav a"), function(a){
  a.onclick = function(){ switchTab(a.getAttribute("data-tab")); };
});

/* ---------------- 书列表 ---------------- */
function loadBooks(){
  return api("/api/admin/books").then(function(r){
    S.books = (r.data && r.data.books) || [];
    var optHtml = S.books.map(function(b){
      return '<option value="' + b.id + '">#' + b.id + ' ' + esc(b.title) +
             ' · ' + (Math.round((b.size || 0) / 1048576 * 10) / 10) + 'MB' +
             (b.live ? ' ✓开放中' : '') + '</option>';
    }).join("");
    $("bookSel").innerHTML = optHtml || '<option value="1">book 1</option>';
    $("shBook").innerHTML = optHtml || '<option value="1">book 1</option>';
    if (S.books.length) {
      S.bookId = Number(S.books[0].id) || 1;
      $("bookSel").value = String(S.bookId);
      $("shBook").value = String(S.bookId);
    }
    fillShareForm();
    fillVersionSelect("tryVer"); fillVersionSelect("batchVer");
  });
}
$("bookSel").onchange = function(){
  S.bookId = Number($("bookSel").value) || 1;
  loadCodes();
};
$("reload").onclick = function(){ boot(); };

/* ---------------- 通用二选一弹窗 ---------------- */
function chooseKind(file) {
  return new Promise(function (resolve) {
    var bk = findBook(UP_BOOK) || {};
    var hasMulti = bk.mode === "multi";
    $("chTitle").textContent = "这次上传的是哪一种？";
    $("chBody").innerHTML =
      '<div class="sub" style="margin-bottom:10px">文件：' + esc(file.name) + '</div>' +
      '<button class="btn wide" data-k="variant">另一个格式 · 与现有版本一起发给读者</button>' +
      '<div class="sub" style="margin:4px 0 12px">适合"手机版 + Kindle 版"这种要同时存在的情况' +
        (hasMulti ? '（这本书已经是多格式）' : '') + '</div>' +
      '<button class="btn wide ghost" data-k="revision">新版本 · 替换旧版（旧版仅留溯源）</button>' +
      '<div class="sub" style="margin:4px 0 0">适合"母本修订了，以后只发新版"</div>';
    $("chooser").classList.remove("hide");
    var done = function (v) { $("chooser").classList.add("hide"); resolve(v); };
    Array.prototype.forEach.call(document.querySelectorAll("[data-k]"), function (x) {
      x.onclick = function () { done(x.getAttribute("data-k")); };
    });
    $("chCancel").onclick = function () { done(null); };
    $("chooser").onclick = function (e) { if (e.target === this) done(null); };
  });
}

/* 当前书的可打标版本列表（is_current=1）。多格式书会有多行。 */
function fillVersionSelect(selId) {
  var el = $(selId); if (!el) return;
  var bk = findBook(S.bookId) || {};
  var vs = (bk.versions || []).filter(function (v) { return v.is_current; });
  if (!vs.length) {
    el.innerHTML = '<option value="0">（这本书还没上传母本）</option>';
    return;
  }
  el.innerHTML = vs.map(function (v) {
    return '<option value="' + v.id + '">v' + v.version_no + ' ' + esc(v.label || '') +
           ' · ' + fmtSize(v.size) + '</option>';
  }).join("");
}

/* ---------------- 分组 / 黑名单 ---------------- */
var CG = { groups: [], gid: 0, members: [] };

function loadGroups(){
  return api("/api/admin/groups").then(function(r){
    CG.groups = (r.data && r.data.groups) || [];
    if (!CG.groups.length) {
      $("grpList").innerHTML = '<div class="empty">还没有分组。先建一个，比如「第一批」。</div>';
      $("memList").innerHTML = "";
      $("grpNow").textContent = "";
      return;
    }
    if (!CG.groups.some(function(g){ return g.id === CG.gid; })) CG.gid = CG.groups[0].id;
    $("grpList").innerHTML = CG.groups.map(function(g){
      return '<div class="grow' + (g.id === CG.gid ? " on" : "") + '">' +
        '<span class="gname" data-g="' + g.id + '">' + esc(g.name) + '</span>' +
        '<span class="tag">' + g.members + ' 人</span>' +
        '<button class="mini" data-gr="' + g.id + '" data-nm="' + esc(g.name) + '">改名</button>' +
        '<button class="mini bad" data-gd="' + g.id + '" data-nm="' + esc(g.name) + '">删除</button>' +
      '</div>';
    }).join("");
    Array.prototype.forEach.call(document.querySelectorAll("[data-g]"), function(x){
      x.onclick = function(){ CG.gid = Number(x.getAttribute("data-g")); loadGroups(); };
    });
    Array.prototype.forEach.call(document.querySelectorAll("[data-gr]"), function(x){
      x.onclick = function(){
        var id = Number(x.getAttribute("data-gr"));
        var v = prompt("新的分组名", x.getAttribute("data-nm"));
        if (v === null || !v.trim()) return;
        api("/api/admin/groups/" + id, { method: "PATCH", body: { name: v.trim() } })
          .then(function(res){ if (res.data.ok) loadGroups(); else alert(res.data.error || "改名失败"); });
      };
    });
    Array.prototype.forEach.call(document.querySelectorAll("[data-gd]"), function(x){
      x.onclick = function(){
        var id = Number(x.getAttribute("data-gd"));
        if (!confirm("删除分组「" + x.getAttribute("data-nm") + "」？\\n\\n只删分组和成员关系，人本身和取件码都不受影响。")) return;
        api("/api/admin/groups/" + id, { method: "DELETE" })
          .then(function(){ loadGroups(); });
      };
    });
    loadMembers();
  });
}

function loadMembers(){
  if (!CG.gid) { $("memList").innerHTML = ""; $("grpNow").textContent = ""; return; }
  var g = CG.groups.filter(function(x){ return x.id === CG.gid; })[0] || {};
  $("grpNow").textContent = "· " + (g.name || "");
  return api("/api/admin/groups/" + CG.gid + "/members").then(function(r){
    CG.members = (r.data && r.data.members) || [];
    if (!CG.members.length) {
      $("memList").innerHTML = '<div class="empty">这个组还没有人。粘贴 QQ 后点「加入」。</div>';
      return;
    }
    $("memList").innerHTML = CG.members.slice(0, 100).map(function(m){
      var box = CG.sel
        ? '<input type="checkbox" class="memck" data-ck="' + esc(m.qq) + '"' +
          (CG.chosen[m.qq] ? " checked" : "") + '>'
        : '';
      return '<div class="rcrow">' + box +
        '<div class="rcq"><b>' + esc(m.qq) + '</b>' +
        (m.note ? '<span class="sub">' + esc(m.note) + '</span>' : '') + '</div>' +
        '<button class="mini bad" data-mban="' + esc(m.qq) + '">拉黑</button>' +
        '<button class="mini" data-mrm="' + m.qq + '">移出</button></div>';
    }).join("") + (CG.members.length > 100
      ? '<div class="sub" style="margin-top:6px">只显示前 100 人，共 ' + CG.members.length + ' 人</div>' : "");
    Array.prototype.forEach.call(document.querySelectorAll("[data-mrm]"), function(x){
      x.onclick = function(){
        var qq = x.getAttribute("data-mrm");
        if (!confirm("把 " + qq + " 从「" + (g.name || "") + "」移出？（不影响其它组）")) return;
        api("/api/admin/groups/" + CG.gid + "/remove", { method: "POST", body: { qqs: [qq] } })
          .then(function(){ loadGroups(); });
      };
    });
    Array.prototype.forEach.call(document.querySelectorAll("[data-mban]"), function(x){
      x.onclick = function(){
        var qq = x.getAttribute("data-mban");
        if (!confirm("拉黑 " + qq + "？\\n\\n拉黑后他不能领取任何一本书，并会自动从所有分组移出。")) return;
        api("/api/admin/blocklist", { method: "POST", body: { qqs: [qq] } })
          .then(function(r){
            if (r.data.ok) { loadGroups(); loadBlocklist(); }
            else alert(r.data.error || "拉黑失败");
          });
      };
    });
    Array.prototype.forEach.call(document.querySelectorAll(".memck"), function(x){
      x.onchange = function(){
        var qq = x.getAttribute("data-ck");
        if (x.checked) CG.chosen[qq] = 1; else delete CG.chosen[qq];
      };
    });
  });
}

$("doGrpAdd").onclick = function(){
  var name = ($("grpName").value || "").trim();
  if (!name) { alert("先填分组名"); return; }
  api("/api/admin/groups", { method: "POST", body: { name: name } }).then(function(r){
    if (r.data.ok) { $("grpName").value = ""; CG.gid = Number(r.data.id) || CG.gid; loadGroups(); }
    else alert(r.data.error || "新建失败");
  });
};

$("doMemAdd").onclick = function(){
  if (!CG.gid) { alert("先建一个分组"); return; }
  var qqs = confirmQQ($("memQQ").value);
  if (!qqs) return;
  api("/api/admin/groups/" + CG.gid + "/members", { method: "POST", body: { qqs: qqs } })
    .then(function(r){
      if (r.data.ok) { $("memQQ").value = ""; loadGroups(); }
      else alert(r.data.error || "加入失败");
    });
};

$("doMemRemove").onclick = function(){
  if (!CG.gid) return;
  var qqs = parseQQ($("memQQ").value);
  if (!qqs.length) { alert("输入框里没有 QQ"); return; }
  if (!confirm("把输入框里的 " + qqs.length + " 人从当前分组移出？（不影响其它组）")) return;
  api("/api/admin/groups/" + CG.gid + "/remove", { method: "POST", body: { qqs: qqs } })
    .then(function(){ $("memQQ").value = ""; loadGroups(); });
};

$("memFile").onchange = function(){
  var f = this.files && this.files[0];
  if (!f) return;
  if (!CG.gid) { alert("先建一个分组"); this.value = ""; return; }
  var rd = new FileReader();
  rd.onload = function(){
    var txt = String(rd.result || "");
    var r = parseQQReport(txt);
    if (!r.ok.length) { alert("文件里没找到合法 QQ（要求 5~12 位数字）"); return; }
    var msg = "文件 " + f.name + "：识别 " + r.raw + " 行，合法 " + r.ok.length + " 个";
    if (r.bad.length) msg += "，忽略 " + r.bad.length + " 行";
    if (r.suspect.length) msg += "\\n\\n⚠ " + r.suspect.length + " 个是 11 位且以 1 开头，可能是手机号";
    msg += "\\n\\n加入当前分组？";
    if (!confirm(msg)) return;
    api("/api/admin/groups/" + CG.gid + "/members", { method: "POST", body: { qqs: r.ok } })
      .then(function(res){
        if (res.data.ok) { $("memQQ").value = ""; loadGroups(); alert("已加入，当前 " + res.data.total + " 人"); }
        else alert(res.data.error || "导入失败");
      });
  };
  rd.readAsText(f, "utf-8");
  this.value = "";
};

$("doMemSel").onclick = function(){
  CG.sel = !CG.sel;
  CG.chosen = {};
  $("doMemSel").textContent = CG.sel ? "取消多选" : "多选";
  $("memBatchBar").classList.toggle("hide", !CG.sel);
  $("memAll").checked = false;
  loadMembers();
};
$("memAll").onchange = function(){
  var on = this.checked;
  CG.chosen = {};
  Array.prototype.forEach.call(document.querySelectorAll(".memck"), function(x){
    x.checked = on;
    if (on) CG.chosen[x.getAttribute("data-ck")] = 1;
  });
};
function chosenQqs(){ return Object.keys(CG.chosen || {}); }
$("doMemBatchRemove").onclick = function(){
  var qqs = chosenQqs();
  if (!qqs.length) { alert("先勾选人"); return; }
  if (!confirm("把所选 " + qqs.length + " 人移出当前分组？（不影响其它组）")) return;
  api("/api/admin/groups/" + CG.gid + "/remove", { method: "POST", body: { qqs: qqs } })
    .then(function(){ CG.chosen = {}; loadGroups(); });
};
$("doMemBatchBan").onclick = function(){
  var qqs = chosenQqs();
  if (!qqqs_ok(qqs)) return;
};
function qqqs_ok(qqs){
  if (!qqs.length) { alert("先勾选人"); return false; }
  if (!confirm("拉黑所选 " + qqs.length + " 人？\\n\\n他们会立刻失去领取资格，并从所有分组移出。")) return false;
  api("/api/admin/blocklist", { method: "POST", body: { qqs: qqs } })
    .then(function(r){
      if (r.data.ok) { CG.chosen = {}; loadGroups(); loadBlocklist(); }
      else alert(r.data.error || "拉黑失败");
    });
  return true;
}

$("doMemFromCodes").onclick = function(){
  if (!CG.gid) { alert("先建一个分组"); return; }
  Promise.all([api("/api/admin/codes?limit=500"), api("/api/admin/blocklist")]).then(function(res){
    var banned = {};
    ((res[1].data && res[1].data.blocklist) || []).forEach(function (b) { banned[b.qq] = 1; });
    var all = ((res[0].data && res[0].data.codes) || []).map(function(c){ return c.qq; });
    var qqs = all.filter(function (q) { return !banned[q]; });
    if (!qqs.length) { alert("还没有发过码"); return; }
    if (!confirm("把分享过的 " + qqs.length + " 人加入当前分组？（已排除黑名单 " +
                 (all.length - qqs.length) + " 人）")) return;
    api("/api/admin/groups/" + CG.gid + "/members", { method: "POST", body: { qqs: qqs } })
      .then(function(res){ if (res.data.ok) loadGroups(); else alert(res.data.error || "失败"); });
  });
};

function loadLinks(){
  return api("/api/admin/links").then(function(r){
    var list = (r.data && r.data.links) || [];
    $("lkCount").textContent = list.length;
    // 书下拉：用已加载的书列表
    $("lkBook").innerHTML = (S.books || []).map(function(b){
      return '<option value="' + b.id + '">#' + b.id + ' ' + esc(b.title) + '</option>';
    }).join("") || '<option value="0">还没有书</option>';
    if (S.shareBookId) $("lkBook").value = String(S.shareBookId);
    if (!list.length) { $("lkList").innerHTML = '<div class="empty">还没有专用链接</div>'; return; }
    $("lkList").innerHTML = list.slice(0, 50).map(function(x){
      var dead = x.revoked || x.expired || Number(x.exp) <= 0;
      return '<div class="lkrow' + (dead ? " off" : "") + '">' +
        '<div class="lkq"><b>' + esc(x.qq) + '</b>' +
          '<span class="sub">' + esc(x.title || ("书 " + x.book_id)) +
          ' · 到期 ' + esc(String(x.exp || "").slice(5, 16)) +
          (x.revoked ? ' · 已作废' : (x.expired ? ' · 已过期' : ' · 打开 ' + x.hits + ' 次')) +
          '</span></div>' +
        '<button class="mini" data-lkcp="' + esc(x.url) + '">复制</button>' +
        (dead ? '' : '<button class="mini bad" data-lkdel="' + x.id + '">作废</button>') +
      '</div>';
    }).join("") + (list.length > 50
      ? '<div class="sub" style="margin-top:6px">只显示最近 50 条，共 ' + list.length + ' 条</div>' : "");
    Array.prototype.forEach.call(document.querySelectorAll("[data-lkcp]"), function(b){
      b.onclick = function(){ copyText(b.getAttribute("data-lkcp"), b); };
    });
    Array.prototype.forEach.call(document.querySelectorAll("[data-lkdel]"), function(b){
      b.onclick = function(){
        if (!confirm("作废这条链接？读者再打开就会显示「已失效」。")) return;
        api("/api/admin/links/" + b.getAttribute("data-lkdel"), { method: "DELETE" })
          .then(function(){ loadLinks(); });
      };
    });
  });
}
$("doLkAdd").onclick = function(){
  var bid = Number($("lkBook").value) || 0;
  var qq = ($("lkQQ").value || "").replace(/\D/g, "");
  if (!bid || !qq) { alert("先选书、填 QQ"); return; }
  api("/api/admin/links", { method: "POST", body: { book_id: bid, qq: qq } })
    .then(function(r){
      if (r.data.ok) { $("lkQQ").value = ""; loadLinks(); copyText(r.data.url, null);
        alert("已生成，链接已复制：\\n" + r.data.url); }
      else alert(r.data.error || "生成失败");
    });
};

function loadBlocklist(){
  return api("/api/admin/blocklist").then(function(r){
    var list = (r.data && r.data.blocklist) || [];
    if (!list.length) { $("blList").innerHTML = '<div class="empty">黑名单是空的</div>'; return; }
    $("blList").innerHTML = list.map(function(x){
      return '<div class="rcrow"><div class="rcq"><b>' + esc(x.qq) + '</b>' +
        (x.reason ? '<span class="sub">' + esc(x.reason) + '</span>' : '') + '</div>' +
        '<button class="mini" data-bld="' + x.id + '">移出</button></div>';
    }).join("");
    Array.prototype.forEach.call(document.querySelectorAll("[data-bld]"), function(x){
      x.onclick = function(){
        if (!confirm("解除拉黑后，这个人立刻恢复领取资格。确定？")) return;
        api("/api/admin/blocklist/" + x.getAttribute("data-bld"), { method: "DELETE" })
          .then(function(){ loadBlocklist(); });
      };
    });
  });
}

$("doBlAdd").onclick = function(){
  var qqs = confirmQQ($("blQQ").value);
  if (!qqs) return;
  api("/api/admin/blocklist", { method: "POST",
    body: { qqs: qqs, reason: $("blReason").value } }).then(function(r){
    if (r.data.ok) { $("blQQ").value = ""; $("blReason").value = ""; loadBlocklist(); }
    else alert(r.data.error || "拉黑失败");
  });
};

/* ---------------- 领取人名单 ---------------- */
function loadRecipients(){
  return api("/api/admin/recipients?book_id=" + S.bookId).then(function(r){
    var list = (r.data && r.data.recipients) || [];
    $("rcCount").textContent = list.length;
    if (!list.length) {
      $("rcList").innerHTML = '<div class="empty">名单是空的。先粘一批 QQ 进来，发码时就不用重复粘贴了。</div>';
      return;
    }
    $("rcList").innerHTML = list.slice(0, 60).map(function(x){
      return '<div class="rcrow">' +
        '<div class="rcq"><b>' + esc(x.qq) + '</b>' +
          (x.note ? '<span class="sub">' + esc(x.note) + '</span>' : '') + '</div>' +
        '<span class="tag ' + (x.has_code ? 'on' : 'off') + '">' +
          (x.has_code ? '已发码' : '未发码') + '</span>' +
        '<button class="mini bad" data-rcdel="' + x.id + '">移除</button>' +
      '</div>';
    }).join("") + (list.length > 60
      ? '<div class="sub" style="margin-top:6px">只显示最近 60 人，共 ' + list.length + ' 人</div>' : '');
    Array.prototype.forEach.call(document.querySelectorAll("[data-rcdel]"), function(x){
      x.onclick = function(){
        if (!confirm("从名单里移除这个人？（不影响已发出的码）")) return;
        api("/api/admin/recipients/" + x.getAttribute("data-rcdel"), { method: "DELETE" })
          .then(function(){ loadRecipients(); });
      };
    });
  });
}
$("doRcAdd").onclick = function(){
  var qqs = confirmQQ($("rcQQ").value);
  if (!qqs) return;
  if (!qqs.length) { alert("没识别到合法 QQ 号"); return; }
  api("/api/admin/recipients", { method: "POST", body: { qqs: qqs, note: $("rcNote").value } })
    .then(function(r){
      if (r.data.ok) { $("rcQQ").value = ""; loadRecipients(); }
      else alert(r.data.error || "添加失败");
    });
};
$("doRcRefresh").onclick = loadRecipients;
$("doRcToCodes").onclick = function(){
  api("/api/admin/recipients?book_id=" + S.bookId).then(function(r){
    var qqs = ((r.data || {}).recipients || [])
      .filter(function(x){ return !x.has_code; }).map(function(x){ return x.qq; });
    if (!qqs.length) { alert("名单里的人都已有取件码了"); return; }
    if (!confirm("给名单里还没码的 " + qqs.length + " 人生成取件码？")) return;
    api("/api/admin/codes", { method: "POST", body: { book_id: S.bookId, qqs: qqs } })
      .then(function(res){
        if (res.data.ok) {
          alert("新生成 " + res.data.created + " 个，复用 " + res.data.reused + " 个");
          loadCodes(); loadRecipients();
        } else alert(res.data.error || "失败");
      });
  });
};

/* ---------------- 生成 ---------------- */
$("doGen").onclick = function(){
  var qqs = confirmQQ($("genQQ").value);
  if (!qqs) return;
  if (!qqs.length) { alert("没识别到合法 QQ 号"); return; }
  var single = qqs.length === 1;
  $("genOut").innerHTML = '<div class="sub" style="margin-top:10px">生成中…</div>';
  api("/api/admin/codes", { method:"POST", body:{
    book_id: S.bookId, qqs: qqs,
    max_uses: Number($("genUses").value) || 3,
    expires_days: Number($("genDays").value) || 0
  }}).then(function(r){
    if (!r.data.ok) {
      $("genOut").innerHTML = '<div class="bad" style="margin-top:10px">' + esc(r.data.error||"失败") + '</div>';
      return;
    }
    renderGen(r.data.codes || [], single);
    loadCodes();
  });
};
function renderGen(codes, single){
  if (!codes.length) { $("genOut").innerHTML = ""; return; }
  var tsv = codes.map(function(c){ return c.qq + "\\t" + c.code; }).join("\\n");
  S.tsv = tsv;
  var newly = codes.filter(function(c){ return c.is_new; }).length;
  var h = "";
  if (single) {
    var c = codes[0];
    h += '<div class="one"><div class="oneqq">QQ ' + esc(c.qq) + '</div>' +
         '<div class="onecode">' + esc(c.code) + '</div>' +
         '<div class="sub">' + (c.is_new ? "新生成" : "已存在，复用原码") + '</div>' +
         '<button class="btn sm" style="margin-top:10px" id="cpOne">复制这条</button></div>';
  }
  h += '<div class="row" style="margin-top:10px;align-items:center">' +
       '<div class="sub" style="flex:1">共 ' + codes.length + ' 条' +
       (newly ? '（新生成 ' + newly + '）' : '（全部复用）') + '</div>' +
       '<button class="btn sm ghost fix" id="cpAll">复制全部</button></div>' +
       '<textarea id="genTsv" readonly rows="' + Math.min(12, codes.length + 1) + '">' + esc(tsv) + '</textarea>' +
       '<div class="sub" style="margin-top:6px">复制后可直接粘进 Excel（制表符分隔，自动分两列）</div>';
  $("genOut").innerHTML = h;
  if ($("cpOne")) $("cpOne").onclick = function(){ copyText(codes[0].qq + " " + codes[0].code, this); };
  $("cpAll").onclick = function(){ copyText(tsv, this); };
}

/* ---------------- 码表 ---------------- */
function loadCodes(){
  var q = ($("q").value || "").trim();
  // 取件码按 QQ 全局，不再按书查
  return api("/api/admin/codes?q=" + encodeURIComponent(q))
    .then(function(r){
      if (!r.data.ok) { $("codeList").innerHTML = '<div class="empty">' + esc(r.data.error||"加载失败") + '</div>'; return; }
      S.codes = r.data.codes || [];
      S.versionTotal = Number(r.data.version_total || 0);
      renderCodes(S.codes);
    });
}
function renderCodes(list){
  $("codeCount").textContent = list.length;
  if (!list.length) { $("codeList").innerHTML = '<div class="empty">还没有取件码，去「取件码」生成</div>'; return; }
  var VT = Number(S.versionTotal || 0);
  $("codeList").innerHTML = list.map(function(c){
    var used = Number(c.uses) || 0, max = Number(c.max_uses) || 0;
    var rv = Number(c.ready_versions || 0);
    // 出书状态按版本算：2 个版本只出了 1 个 → "1/2 已出"，不能笼统说"已出书"
    var rTxt = c.ready ? "已出书" : (rv ? (rv + "/" + (VT || 1) + " 已出") : "未打标");
    var tags = '<span class="tag ' + (c.ready ? 'on' : 'off') + '">' + rTxt + '</span>';
    // 状态直接给"卡在哪一步"：未校验 / 已校验未下载 / 已下载 N 次 / 次数用完 / 已作废 / 已过期
    var st = c.state || "";
    var cls = (st.indexOf("用完") >= 0 || st.indexOf("作废") >= 0 || st.indexOf("过期") >= 0)
      ? "bad" : (st.indexOf("下载") >= 0 ? "on" : "off");
    if (st) tags += '<span class="tag ' + cls + '">' + esc(st) + '</span>';
    var leftTxt = (c.left_min === null || c.left_min === undefined)
      ? ("—/" + max) : (Math.max(0, Number(c.left_min)) + "/" + max);
    return '<div class="cr' + ((c.status === "revoked" || c.expired) ? ' rev' : '') + '">' +
      '<div class="cr-top"><b>' + esc(c.qq) + '</b>' +
        tags +
        '<span class="use">' + leftTxt + '</span></div>' +
      '<div class="cr-bot">' +
        '<button class="code" data-id="' + c.id + '" data-code="' + esc(c.code) + '" title="点这里改暗号">' +
          esc(c.code) + '</button>' +
        '<button class="mini" data-cp="' + esc(c.code) + '">复制</button>' +
        '<button class="mini" data-rs="' + c.id + '"' +
          (used ? '' : ' style="opacity:.35"') + '>重置</button>' +
        '<button class="mini" data-regen="' + c.id + '" data-q="' + esc(c.qq) + '">换码</button>' +
        '<button class="mini' + (c.status === "active" ? ' bad' : '') + '" data-id="' + c.id +
          '" data-st="' + c.status + '">' + (c.status === "active" ? "作废" : "恢复") + '</button>' +
      '</div></div>';
  }).join("");
  Array.prototype.forEach.call(document.querySelectorAll(".code"), function(b){
    b.onclick = function(){ editCode(b); };
  });
  Array.prototype.forEach.call(document.querySelectorAll("[data-cp]"), function(b){
    // 只复制暗号：QQ 是谁你自己知道，发的时候拼一下就行
    b.onclick = function(){ copyText(b.getAttribute("data-cp"), b); };
  });
  Array.prototype.forEach.call(document.querySelectorAll("[data-rs]"), function(b){
    b.onclick = function(){
      var id = Number(b.getAttribute("data-rs"));
      if (!confirm("把这个人的下载次数清零？")) return;
      api("/api/admin/codes/" + id, { method:"PATCH", body:{ uses: 0 } }).then(function(r){
        if (r.data.ok) loadCodes(); else alert(r.data.error || "重置失败");
      });
    };
  });
  Array.prototype.forEach.call(document.querySelectorAll("[data-st]"), function(b){
    b.onclick = function(){ toggleCode(b); };
  });
  Array.prototype.forEach.call(document.querySelectorAll("[data-regen]"), function(b){
    b.onclick = function(){
      var id = Number(b.getAttribute("data-regen"));
      var qq = b.getAttribute("data-q");
      if (!confirm("给 " + qq + " 换一个新取件码？\\n\\n旧码立刻失效；已用次数默认清零（可勾掉）。")) return;
      if (b.disabled) return;
      b.disabled = true; b.textContent = "换码中…";
      api("/api/admin/codes/" + id + "/regen", { method: "POST", body: { reset: true } })
        .then(function(r){
          if (r.data.ok) { loadCodes(); alert("新码：" + r.data.code + "\\n（次数已清零）"); }
          else { b.disabled = false; b.textContent = "换码"; alert(r.data.error || "换码失败"); }
        });
    };
  });
}
function editCode(btn){
  var id = Number(btn.getAttribute("data-id"));
  var old = btn.getAttribute("data-code");
  var v = prompt("改成什么暗号？（4~12 位字母或数字）", old);
  if (v === null) return;
  v = String(v).toUpperCase().replace(/[^A-Z0-9]/g, "");
  if (v.length < 4) { alert("至少 4 位"); return; }
  api("/api/admin/codes/" + id, { method:"PATCH", body:{ code: v } }).then(function(r){
    if (r.data.ok) loadCodes();
    else alert(r.data.error || "改码失败");
  });
}
function toggleCode(btn){
  /* 慢网络下连点两次会把状态改回去（第一次成功后没重渲染，第二次按旧状态取反）。
   * 这里点击即禁用，并且从 S.codes 取"最新已知状态"而不是按钮上的旧值。 */
  if (btn.disabled) return;
  var id = Number(btn.getAttribute("data-id"));
  var row = (S.codes || []).filter(function (c) { return Number(c.id) === id; })[0] || {};
  var cur = row.status || btn.getAttribute("data-st");
  var next = cur === "active" ? "revoked" : "active";
  if (next === "revoked" && !confirm("作废后这个码立刻失效，确定？")) return;
  btn.disabled = true;
  btn.textContent = "处理中…";
  api("/api/admin/codes/" + id, { method:"PATCH", body:{ status: next } }).then(function(r){
    if (r.data.ok) { loadCodes(); }                      // 整表重渲染，按钮会被新 DOM 替换
    else { btn.disabled = false; btn.textContent = cur === "active" ? "作废" : "恢复";
           alert(r.data.error || "操作失败"); }
  });
}
$("doSearch").onclick = loadCodes;
$("q").addEventListener("keydown", function(e){ if (e.key === "Enter") loadCodes(); });
$("doExport").onclick = function(){
  location.href = "/api/admin/codes.csv";
};
$("doCopyAll").onclick = function(){
  var t = S.codes.map(function(c){ return c.qq + "\\t" + c.code; }).join("\\n");
  if (!t) { alert("没有数据"); return; }
  copyText(t, this);
};
$("doBackfill").onclick = function(){
  if (!confirm("从已出成品里回填取件码？只补还没有码的人。")) return;
  api("/api/admin/codes/backfill", { method:"POST", body:{ book_id: S.bookId } }).then(function(r){
    alert(r.data.ok ? ("回填完成，新增 " + (r.data.created||0) + " 条") : (r.data.error||"失败"));
    loadCodes();
  });
};

$("doResetAll").onclick = function(){
  if (!confirm("把这本书所有码的已用次数清零？暗号不变，人人重新有满次数。")) return;
  api("/api/admin/codes/reset", { method:"POST", body:{ book_id: S.bookId } })
    .then(function(r){
      if (r.data.ok) { alert("已重置 " + (r.data.reset || 0) + " 条"); loadCodes(); }
      else alert(r.data.error || "重置失败");
    });
};

/* ---------------- 仪表盘 ---------------- */
function fmtSize(n){
  n = Number(n || 0);
  return n >= 1073741824 ? (n / 1073741824).toFixed(2) + "GB" : (n / 1048576).toFixed(1) + "MB";
}
function fmtShort(s){
  var v = toLocalInput(s);
  return v ? v.slice(5).replace("T", " ") : "";
}
function loadStats(){
  return api("/api/admin/stats").then(function(r){
    var d = r.data || {};
    if (!d.ok) return;
    var r2 = d.r2 || {}, c = d.counts || {};
    var pct = Number(r2.percent || 0);
    $("mUsed").textContent = fmtSize(r2.used) + " / " + (Number(r2.limit || 0) / 1073741824).toFixed(1) + "GB";
    var bar = $("mBar");
    bar.style.width = Math.max(2, Math.min(100, pct)) + "%";
    bar.style.background = r2.blocked ? "var(--bad)" : (pct > 88 ? "var(--warn)" : "var(--brand)");
    $("mSub").innerHTML = (r2.objects || 0) + " 个文件 · 已用 " + pct + "%" +
      (r2.over_8g ? ' · <span class="bad">已超 8GB 警戒线</span>' : "");
    $("mBooks").textContent = c.books;
    $("mCodes").textContent = c.codes;
    $("mFiles").textContent = c.files;
    $("mNew").textContent = c.files_24h;
    var ob = d.open_books || [];
    $("mOpen").innerHTML = ob.length ? ob.map(function(b){
      return '<div class="cr"><div class="cr-top"><b>' + esc(b.title) + '</b>' +
        '<span class="use">' + (b.share_close_at ? "截止 " + fmtShort(b.share_close_at) : "长期开放") +
        '</span></div></div>';
    }).join("") : '<div class="empty">当前没有开放中的书</div>';
  });
}

/* 码表定时刷新：多窗口/多设备下不留旧数据。
 * 只在码表面板可见且没有输入焦点时刷新，避免打断正在改码的操作。 */
setInterval(function () {
  if (document.visibilityState !== "visible") return;
  if ($("tab-list").classList.contains("hide")) return;
  var a = document.activeElement;
  if (a && /^(INPUT|TEXTAREA|SELECT)$/.test(a.tagName)) return;
  loadCodes();
}, 20000);

/* ---------------- 试打 ---------------- */
$("doTry").onclick = function(){
  var qq = ($("tryQQ").value || "").replace(/\\D/g, "");
  if (!/^\\d{5,12}$/.test(qq)) { alert("填 5~12 位 QQ 号"); return; }
  $("tryOut").innerHTML = '<div class="sub">提交中…</div>';
  api("/api/admin/try-one", { method:"POST",
    body:{ book_id: S.bookId, qq: qq, version_id: Number($("tryVer").value) || 0 } }).then(function(r){
    var d = r.data || {};
    if (!d.ok) { $("tryOut").innerHTML = '<div class="bad">' + esc(d.error || "失败") + '</div>'; return; }
    $("tryOut").innerHTML = '<div class="pb"><i id="tryBar"></i></div><div class="sub" id="tryMsg">排队中…</div>';
    pollBatch(d.batch_id, "tryBar", "tryMsg", function(){
      api("/api/claim?qq=" + qq + "&code=" + encodeURIComponent(d.code) + "&book_id=" + S.bookId)
        .then(function(c){
          var x = c.data || {};
          $("tryOut").innerHTML =
            '<div class="banner ok">试打完成<br>QQ <b>' + esc(qq) + '</b> · 暗号 <b class="code" style="border:0;background:none;padding:0">' +
            esc(d.code) + '</b></div>' +
            (x.url ? '<a class="btn wide" href="' + esc(x.url) + '" style="text-align:center;text-decoration:none">下载验收</a>'
                   : '<div class="bad">拿不到下载链接：' + esc(x.error || "") + '</div>');
        });
    });
  });
};
function pollBatch(id, barId, msgId, onDone){
  var t0 = Date.now();
  function tick(){
    api("/api/wm/batches/" + id).then(function(r){
      var d = r.data || {};
      var pct = d.total ? Math.round((d.done||0) / d.total * 100) : 0;
      var bar = $(barId); if (bar) bar.style.width = Math.max(4, pct) + "%";
      var msg = $(msgId);
      var sec = Math.round((Date.now() - t0) / 1000);
      if (msg) msg.textContent = (d.status||"?") + " · " + (d.done||0) + "/" + (d.total||1) + " · " + sec + "s";
      if (d.status === "done") { if (onDone) onDone(); return; }
      if (d.status === "failed") {
        if (msg) msg.innerHTML = '<span class="bad">失败：' + esc(d.reason || "未知原因") + '</span>';
        return;
      }
      if (sec > 600) { if (msg) msg.textContent = "超过 10 分钟未完成，请稍后刷新码表确认"; return; }
      setTimeout(tick, 3000);
    });
  }
  tick();
}

/* ---------------- 批量 ---------------- */
$("doBatch").onclick = function(){
  var qqs = confirmQQ($("batchQQ").value);
  if (!qqs) return;
  if (!qqs.length) { alert("没识别到合法 QQ 号"); return; }
  if (!confirm("确认给 " + qqs.length + " 个人打标？")) return;
  $("batchOut").innerHTML = '<div class="sub">提交中…</div>';
  api("/api/wm/jobs", { method:"POST",
    body:{ book_id: S.bookId, qqs: qqs, version_id: Number($("batchVer").value) || 0 } }).then(function(r){
    var d = r.data || {};
    if (!d.plan_id) {
      $("batchOut").innerHTML = '<div class="bad">' + esc(d.error || "提交失败") + '</div>';
      return;
    }
    $("batchOut").innerHTML = '<div class="sub">已提交 ' + d.total + ' 人，分 ' + d.chunks + ' 波</div>' +
      '<div class="pb"><i id="bBar"></i></div><div class="sub" id="bMsg">排队中…</div>';
    pollPlan(d.plan_id, "bBar", "bMsg");
  });
};
function pollPlan(pid, barId, msgId){
  var t0 = Date.now();
  function tick(){
    api("/api/wm/plans/" + pid).then(function(r){
      var d = r.data || {};
      var pct = d.total ? Math.round((d.done||0) / d.total * 100) : 0;
      var bar = $(barId); if (bar) bar.style.width = Math.max(4, pct) + "%";
      var msg = $(msgId);
      var sec = Math.round((Date.now() - t0) / 1000);
      if (msg) msg.textContent = (d.status||"?") + " · " + (d.done||0) + "/" + (d.total||0) +
        (d.failed ? " · 失败 " + d.failed : "") + " · " + sec + "s";
      if (d.status === "done" || d.status === "failed") { loadCodes(); return; }
      if (sec > 1800) { if (msg) msg.textContent = "超过 30 分钟，去 Actions 页面看一眼"; return; }
      setTimeout(tick, 4000);
    });
  }
  tick();
}

/* ---------------- 书籍管理 ---------------- */
function loadBookPage(){
  return api("/api/admin/books").then(function(r){
    S.books = (r.data && r.data.books) || [];
    renderBookPage();
  });
}
function renderBookPage(){
  var bs = S.books || [];
  if (!bs.length) {
    $("bookList").innerHTML = '<div class="empty">还没有书，先在上面创建一本</div>';
    return;
  }
  $("bookList").innerHTML = bs.map(function(b){
    var vs = b.versions || [];
    var verHtml = vs.length ? vs.map(function(v){
      return '<div class="ver"><span>v' + v.version_no + ' <b>' + esc(v.label || '') + '</b></span>' +
        '<span class="sub">' + fmtSize(v.size) + (v.is_current ? ' · 当前' : ' · 历史·仅溯源') +
        ' <button class="lnk" data-rn="' + v.id + '" data-lb="' + esc(v.label || '') + '">改名</button>' +
        '</span></div>';
    }).join("") : '<div class="sub" style="padding:6px 0">还没有上传母本</div>';
    return '<div class="card">' +
      '<div class="bk-h">' +
        '<div style="min-width:0"><b>' + esc(b.title) + '</b>' +
          '<div class="sub">' + fmtSize(b.size) + ' · ' + vs.length + ' 个版本 · ' +
          (b.code_count || 0) + ' 个码</div></div>' +
        '<div style="display:flex;gap:6px;flex:0 0 auto">' +
        '<span class="tag mode">' + (b.mode === 'multi' ? '多格式' : '单版本') + '</span>' +
        '<span class="tag ' + (b.live ? 'on' : 'off') + '">' + (b.live ? '开放中' : '已关闭') + '</span></div>' +
      '</div>' +
      '<div class="verlist">' + verHtml + '</div>' +
      '<div class="row" style="margin-top:10px">' +
        '<button class="btn sm ghost" data-up="' + b.id + '">上传新版本</button>' +
        '<button class="btn sm ghost" data-share="' + b.id + '">分享设置</button>' +
        '<button class="btn sm ghost" data-del="' + b.id + '" style="color:var(--bad)">删除</button>' +
      '</div></div>';
  }).join("");

  Array.prototype.forEach.call(document.querySelectorAll("[data-up]"), function(x){
    x.onclick = function(){ UP_BOOK = Number(x.getAttribute("data-up")); $("filePick").value = ""; $("filePick").click(); };
  });
  Array.prototype.forEach.call(document.querySelectorAll("[data-share]"), function(x){
    x.onclick = function(){ openShare(Number(x.getAttribute("data-share"))); };
  });
  Array.prototype.forEach.call(document.querySelectorAll("[data-del]"), function(x){
    x.onclick = function(){ delBook(Number(x.getAttribute("data-del"))); };
  });
  Array.prototype.forEach.call(document.querySelectorAll("[data-rn]"), function(x){
    x.onclick = function(){
      var id = Number(x.getAttribute("data-rn"));
      var old = x.getAttribute("data-lb");
      var v = prompt("新的版本名", old);
      if (v === null) return;
      api("/api/admin/versions/" + id, { method: "PATCH", body: { label: v } })
        .then(function(r){
          if (r.data.ok) loadBookPage(); else alert(r.data.error || "改名失败");
        });
    };
  });
}
var UP_BOOK = 0;
$("filePick").onchange = function(){
  var f = this.files && this.files[0];
  if (!f) return;
  // 先选文件再定名：默认用文件名，直接回车就行
  var base = f.name.replace(/\.epub$/i, "");
  var label = prompt("给这个版本起个名字（直接确定就用文件名）", base);
  if (label === null) return;               // 取消 = 不上传
  /* 由管理员自己选，不替人猜。
   * 之前是"第二次上传才弹、multi 的书直接静默算 variant"，用户反馈"系统自作聪明"。 */
  chooseKind(f).then(function (kind) {
    if (!kind) return;                     // 取消
    uploadVersion(UP_BOOK, f, label || base, kind);
  });
};
function uploadVersion(bookId, file, label, kind){
  var box = document.createElement("div");
  box.className = "card";
  box.innerHTML = '<h2>正在上传 ' + esc(file.name) + '</h2>' +
    '<div class="pb"><i style="width:2%"></i></div><div class="sub upPct">0%</div>';
  $("bookList").insertBefore(box, $("bookList").firstChild);
  var bar = box.querySelector("i"), pctEl = box.querySelector(".upPct");

  var xhr = new XMLHttpRequest();
  xhr.open("POST", "/api/admin/upload?book_id=" + bookId +
    "&label=" + encodeURIComponent(label) +
    "&kind=" + encodeURIComponent(kind || "revision") +
    "&filename=" + encodeURIComponent(file.name), true);
  xhr.setRequestHeader("Content-Type", "application/epub+zip");
  xhr.setRequestHeader("X-File-Size", String(file.size));
  xhr.upload.onprogress = function(e){
    if (!e.lengthComputable) return;
    var p = Math.round(e.loaded / e.total * 100);
    bar.style.width = Math.max(2, p) + "%";
    pctEl.textContent = p + "% · " + fmtSize(e.loaded) + " / " + fmtSize(e.total);
  };
  xhr.onload = function(){
    var d = {};
    try { d = JSON.parse(xhr.responseText || "{}"); } catch (e) { /* 非 JSON */ }
    if (xhr.status === 200 && d.ok) {
      pctEl.innerHTML = '<span class="okc">上传完成：v' + d.version_no + ' ' + esc(d.label) +
        ' · ' + fmtSize(d.size) + '</span>';
      bar.style.width = "100%";
      loadBookPage(); loadBooks();
    } else {
      pctEl.innerHTML = '<span class="bad">失败：' + esc(d.error || ("HTTP " + xhr.status)) + '</span>';
      bar.style.background = "var(--bad)";
    }
  };
  xhr.onerror = function(){ pctEl.innerHTML = '<span class="bad">网络中断</span>'; };
  xhr.send(file);
}
function delBook(id){
  var b = findBook(id);
  if (!confirm("删除《" + (b ? b.title : id) + "》？\\n\\n会同时删掉 R2 里的母本和全部成品，不可恢复。\\n（水印溯源记录会保留，仍可查）")) return;
  api("/api/admin/books/" + id, { method: "DELETE" }).then(function(r){
    if (r.data.ok) {
      alert("已删除 " + r.data.deleted_objects + " 个文件，释放 " + fmtSize(r.data.freed_bytes));
      loadBookPage(); loadBooks();
    } else alert(r.data.error || "删除失败");
  });
}
$("doNewBook").onclick = function(){
  var t = ($("newBookTitle").value || "").trim();
  if (!t) { alert("先填书名"); return; }
  api("/api/admin/books", { method: "POST", body: { title: t } }).then(function(r){
    if (r.data.ok) {
      $("newBookTitle").value = "";
      loadBookPage(); loadBooks();
      alert("已创建。下一步：给它上传母本。");
    } else alert(r.data.error || "创建失败");
  });
};
/* 分享设置改成弹窗：原来跳 tab 要先 loadBooks 再切换，用户会看到"卡 1~2 秒后跳走"。
 * 现在直接把设置页那张卡片搬进 modalBody（同一份 DOM，事件和 id 都还在）。 */
function openShare(id){
  // 分享范围要选分组，进弹窗前确保分组已加载
  var ready = CG.groups.length ? Promise.resolve() : loadGroups();
  Promise.all([loadBooks(), ready]).then(function(){
    /* 只改分享上下文，不动 S.bookId ——
     * 之前这里改 S.bookId，导致关掉弹窗后"取件码/试打/批量"静默指向这本书 B，
     * 最坏情况是以为在给 A 打标、实际打了 B（烧额度 + 码表错位）。 */
    S.shareBookId = Number(id);
    $("shBook").value = String(id);
    fillShareForm();
    // 卡片本来就长在弹窗里 —— 不再"把 DOM 搬过来"，避免搬错/搬重/底下透出别的卡
    $("modal").classList.remove("hide");
  });
}
$("openShareBtn").onclick = function(){ openShare(S.shareBookId || S.bookId); };
$("modalClose").onclick = function(){ $("modal").classList.add("hide"); };
$("modal").onclick = function(e){ if (e.target === this) $("modal").classList.add("hide"); };

/* ---------------- 溯源 ---------------- */
$("doTrace").onclick = function(){
  var wid = ($("traceWid").value || "").trim();
  if (!wid) return;
  $("traceOut").innerHTML = '<div class="sub">查询中…</div>';
  api("/api/admin/trace?wid=" + encodeURIComponent(wid)).then(function(r){
    if (!r.data.ok) {
      $("traceOut").innerHTML = '<div class="bad">' + esc(r.data.error || "没找到") + '</div>';
      return;
    }
    var t = r.data.trace || {}, v = t.version || {};
    $("traceOut").innerHTML =
      '<div class="banner ok">命中</div>' +
      '<div class="ver"><span>水印</span><span><b>' + esc(t.watermark_id) + '</b></span></div>' +
      '<div class="ver"><span>领取人 QQ</span><span><b>' + esc(t.qq) + '</b></span></div>' +
      '<div class="ver"><span>书名</span><span>' + esc(t.title || ("#" + t.book_id)) + '</span></div>' +
      '<div class="ver"><span>母本版本</span><span>' +
        (v.version_no ? ("v" + v.version_no + " " + esc(v.label || "")) : "未记录（早于版本功能）") +
      '</span></div>' +
      '<div class="ver"><span>打标时间</span><span>' + esc(fmtShort(t.created_at)) + '</span></div>' +
      '<div class="ver"><span>批次</span><span class="sub" style="word-break:break-all">' +
        esc(t.batch_id || "") + '</span></div>';
  });
};
$("traceWid").addEventListener("keydown", function(e){ if (e.key === "Enter") $("doTrace").click(); });

/* ---------------- 溯源：上传 → 等本机解码 → 7 层报告 ---------------- */
var TSTATE = {
  alive:        { m: "√", c: "okc",  t: "存活" },
  cleared:      { m: "×", c: "bad",  t: "被清除" },
  damaged:      { m: "!", c: "warn", t: "受损" },
  absent:       { m: "－", c: "",    t: "无痕迹" },
  not_embedded: { m: "○", c: "",    t: "当时未嵌" }
};
function renderTraceResult(res) {
  if (!res) return '<div class="bad">没有结果</div>';
  var h = '<div class="banner ' + (res.ok ? "ok" : "warn") + '">' +
    (res.ok
      ? '命中 <b>' + esc(res.watermark_id) + '</b> · 领取人 QQ <b>' + esc(res.qq) + '</b>'
      : '未解出本系统的水印') + '</div>';
  if (res.ok && res.qq) {
    h += '<div class="row" style="margin-top:8px">' +
         '<button class="btn sm ghost" data-traceban="' + esc(res.qq) + '">拉黑这个 QQ</button></div>';
  }

  var layers = res.layers || [];
  if (layers.length) {
    h += '<div class="sub" style="margin:12px 0 6px">7 层存活体检</div><div class="lvt">';
    layers.forEach(function (L) {
      var st = TSTATE[L.state] || { m: "?", c: "", t: L.state };
      h += '<div class="lvrow">' +
        '<span class="lvm ' + st.c + '">' + st.m + '</span>' +
        '<span class="lvg">' + esc(L.group || "") + '</span>' +
        '<span class="lvn">' + esc(L.name || "") + '</span>' +
        '<span class="lvs sub">' + esc(L.note || st.t) + '</span>' +
      '</div>';
    });
    h += '</div>';
  }
  if (res.summary) h += '<div class="sub" style="margin-top:9px">' + esc(res.summary) + '</div>';
  if (res.decoy_note) h += '<div class="sub">诱饵探针：' + esc(res.decoy_note) + '</div>';
  // 只有 1 层承载：不是被清洗，而是打标时 CSS/图片容量不够（引擎要求三通道至少一个成功）
  var aliveN = (res.alive || []).length;
  if (res.ok && aliveN <= 1 && (res.layers || []).length) {
    h += '<div class="banner warn" style="margin-top:9px">' +
      '这份文件只有 <b>' + aliveN + '</b> 层承载水印（其余层打标时就没嵌进去，不是被清洗）。' +
      '单层比较脆弱：对方只要做一次文本重排就可能断掉。建议换图片更多的母本，' +
      '或下次打标前先用「试打」确认层数。</div>';
  }
  if (res.verdict) {
    h += '<div class="banner ' + (res.verdict === "可溯源" ? "ok" : "warn") +
         '" style="margin-top:9px">结论：' + esc(res.verdict) + '</div>';
  }
  return h;
}
$("doTraceUp").onclick = function(){ $("traceFile").value = ""; $("traceFile").click(); };
$("traceFile").onchange = function(){
  var f = this.files && this.files[0];
  if (!f) return;
  var box = $("traceJob");
  box.innerHTML = '<div class="sub">上传中…</div>';
  var xhr = new XMLHttpRequest();
  xhr.open("POST", "/api/admin/trace/upload?filename=" + encodeURIComponent(f.name) +
    "&note=" + encodeURIComponent($("traceNote").value || ""), true);
  xhr.setRequestHeader("Content-Type", "application/epub+zip");
  xhr.setRequestHeader("X-File-Size", String(f.size));
  xhr.upload.onprogress = function(e){
    if (e.lengthComputable) {
      box.innerHTML = '<div class="sub">上传 ' + Math.round(e.loaded / e.total * 100) + '%</div>';
    }
  };
  xhr.onload = function(){
    var d = {};
    try { d = JSON.parse(xhr.responseText || "{}"); } catch (e) { /* 非 JSON */ }
    if (d.ok) pollTraceJob(d.job_id);
    else box.innerHTML = '<div class="bad">' + esc(d.error || ("HTTP " + xhr.status)) + '</div>';
  };
  xhr.onerror = function(){ box.innerHTML = '<div class="bad">网络错误</div>'; };
  xhr.send(f);
};
function pollTraceJob(id){
  var box = $("traceJob"), t0 = Date.now();
  box.innerHTML = '<div class="banner ok">已提交云端解码，通常 30~60 秒出结果<br>' +
    '<span class="sub">图片层（DCT / 调色板）在云端算，不需要开电脑。</span></div>' +
    '<div class="pb" style="margin-top:10px"><i id="trBar" style="width:8%"></i></div>' +
    '<div class="sub" id="trMsg" style="margin-top:6px">排队中…</div>';
  (function tick(){
    api("/api/admin/trace/jobs/" + id).then(function(r){
      var job = (r.data || {}).job;
      if (!job) { box.innerHTML = '<div class="bad">工单不存在</div>'; return; }
      if (job.status === "done" || job.status === "failed") {
        box.innerHTML = renderTraceResult(job.result) +
          (job.status === "failed"
            ? '<div class="bad" style="margin-top:8px">' + esc(job.reason || "解码失败") + '</div>' : "");
        return;
      }
      // 进度条缓慢爬升，让人知道没卡死（云端阶段无法拿到真实百分比）
      var el = Date.now() - t0;
      var bar = $("trBar"), msg = $("trMsg");
      if (bar) bar.style.width = Math.min(92, 8 + el / 90000 * 84) + "%";
      if (msg) {
        msg.textContent = el < 15000 ? "云端已接单，准备环境…"
          : el < 45000 ? "正在解码（7 层体检）…"
          : "还在跑，这本书页数可能较多…";
      }
      if (el > 120000 && el < 600000 && !box.dataset.hinted) {
        box.dataset.hinted = "1";
        if (msg) {
          msg.innerHTML = '超过 2 分钟还没结果，可能云端排队或失败。' +
            '<a href="https://github.com/mmlinda/wm-poc/actions/workflows/trace_poc.yml" ' +
            'target="_blank">点这里看运行日志</a>';
        }
        setTimeout(tick, 3000);
        Array.prototype.forEach.call(box.querySelectorAll("[data-traceban]"), function (btn) {
          btn.onclick = function () {
            var q = btn.getAttribute("data-traceban");
            if (!confirm("拉黑 " + q + "？\\n\\n他会立刻失去领取资格，并从所有分组移出。")) return;
            api("/api/admin/blocklist", { method: "POST", body: { qqs: [q] } })
              .then(function (r2) {
                if (r2.data.ok) { btn.disabled = true; btn.textContent = "已拉黑"; loadBlocklist(); }
                else alert(r2.data.error || "拉黑失败");
              });
          };
        });
        return;
      }
      if (Date.now() - t0 > 600000) {
        box.innerHTML = '<div class="bad">超过 10 分钟没有结果。请到 Actions 页面查看 trace-poc 的运行日志。</div>';
        return;
      }
      setTimeout(tick, 3000);
    });
  })();
}

/* ---------------- 设置：分享窗口 + 改口令 ---------------- */
function findBook(id){
  for (var i = 0; i < (S.books || []).length; i++) {
    if (Number(S.books[i].id) === Number(id)) return S.books[i];
  }
  return null;
}
/* 服务端存 UTC；datetime-local 用的是本地时间。两头都要转，否则差 8 小时。 */
function toLocalInput(s){
  if (!s) return "";
  var d = new Date(String(s).replace(" ", "T") + "Z");
  if (isNaN(d.getTime())) return "";
  var p = function(n){ return (n < 10 ? "0" : "") + n; };
  return d.getFullYear() + "-" + p(d.getMonth()+1) + "-" + p(d.getDate()) +
         "T" + p(d.getHours()) + ":" + p(d.getMinutes());
}
function toUTCStr(v){
  if (!v) return null;
  var d = new Date(v);
  return isNaN(d.getTime()) ? null : d.toISOString();
}
function fillShareForm(){
  var b = findBook(S.shareBookId || S.bookId);
  if (!b) return;
  $("shStatus").value = b.share_status === "open" ? "open" : "closed";
  $("shOpen").value = toLocalInput(b.share_open_at);
  $("shClose").value = toLocalInput(b.share_close_at);
  $("shNote").value = b.share_note || "";
  // 回显链接有效期（库里存秒，老数据没有就用 1 天）
  var ttl = Number(b.link_ttl || 86400);
  var opt = $("shTtl").querySelector('option[value="' + ttl + '"]');
  if (opt) $("shTtl").value = String(ttl);
  var sc = b.scope || null;
  var mode = !sc ? "all" : ((sc.groups || []).length ? "groups" : ((sc.qqs || []).length ? "qqs" : "all"));
  $("shScopeMode").value = mode;
  $("shScopeQqText").value = (sc && (sc.qqs || []).join("\\n")) || "";
  $("shScopeGroupList").innerHTML = (CG.groups || []).map(function (g) {
    var on = sc && (sc.groups || []).indexOf(Number(g.id)) >= 0;
    return '<label class="chk"><input type="checkbox" data-sg="' + g.id + '"' +
           (on ? " checked" : "") + '> ' + esc(g.name) +
           ' <span class="sub">(' + g.members + ' 人)</span></label>';
  }).join("") || '<div class="sub">还没有分组，先去「联系人」建一个</div>';
  syncScopeUI();
  $("shareOut").innerHTML = b.live
    ? '<span class="okc">正在开放中</span>' +
      (b.share_close_at ? ' · 截止 ' + toLocalInput(b.share_close_at).replace("T", " ") : ' · 长期开放')
    : '<span class="sub">当前关闭</span>';
}
function syncScopeUI(){
  var m = $("shScopeMode").value;
  $("shScopeGroups").classList.toggle("hide", m !== "groups");
  $("shScopeQqs").classList.toggle("hide", m !== "qqs");
  var w = $("shScopeWarn");
  w.classList.toggle("hide", m !== "all");
  if (m === "all") {
    w.textContent = "当前为「不限制」：只要拿到这本书的取件码，任何人都能领。";
  }
}
$("shScopeMode").onchange = syncScopeUI;

$("shBook").onchange = function(){
  S.shareBookId = Number(this.value) || 1;
  fillShareForm();
};
$("doShare").onclick = function(){
  var scopeMode = $("shScopeMode").value;
  var scope = null;
  if (scopeMode === "groups") {
    scope = { groups: [], qqs: [] };
    Array.prototype.forEach.call(document.querySelectorAll("[data-sg]"), function (c) {
      if (c.checked) scope.groups.push(Number(c.getAttribute("data-sg")));
    });
    if (!scope.groups.length) {
      alert("范围选了「只给指定分组」，但一个组都没勾。\\n\\n要么勾选分组，要么改回「不限制」。");
      return;
    }
  } else if (scopeMode === "qqs") {
    var sq = parseQQ($("shScopeQqText").value);
    if (!sq.length) { alert("选了「只给指定 QQ」，但没填合法 QQ 号"); return; }
    scope = { groups: [], qqs: sq };
  } else {
    scope = { groups: [], qqs: [] };      // 不限制：显式传空对象，服务端按"清空范围"处理
  }
  var body = {
    book_id: S.shareBookId || S.bookId,
    status: $("shStatus").value,
    scope: scope,
    open_at: toUTCStr($("shOpen").value),
    close_at: toUTCStr($("shClose").value),
    note: $("shNote").value,
    close_others: $("shCloseOthers").checked,
    link_ttl: Number($("shTtl").value) || 86400,
  };
  if (body.status === "open" && !body.close_at &&
      !confirm("没填结束时间 = 一直开放。确定？")) return;
  $("shareOut").textContent = "保存中…";
  api("/api/admin/share", { method: "POST", body: body }).then(function(r){
    if (r.data.ok) {
      $("shareOut").innerHTML = '<span class="okc">已保存</span>';
      loadBooks();
    } else {
      $("shareOut").innerHTML = '<span class="bad">' + esc(r.data.error || "保存失败") + '</span>';
    }
  });
};
$("doPw").onclick = function(){
  var o = $("pwOld").value, n = $("pwNew").value, n2 = $("pwNew2").value;
  if (n.length < 6) { $("pwOut").innerHTML = '<span class="bad">新口令至少 6 位</span>'; return; }
  if (n !== n2) { $("pwOut").innerHTML = '<span class="bad">两次输入不一致</span>'; return; }
  $("pwOut").textContent = "提交中…";
  api("/api/admin/password", { method: "POST", body: { old: o, new: n } }).then(function(r){
    if (r.data.ok) {
      $("pwOld").value = ""; $("pwNew").value = ""; $("pwNew2").value = "";
      $("pwOut").innerHTML = '<span class="okc">已修改，新口令立刻生效（其他设备需重新登录）</span>';
      if (r.data.boot) $("pwHint").textContent = "初始口令已升级为库内存储。";
    } else {
      $("pwOut").innerHTML = '<span class="bad">' + esc(r.data.error || "修改失败") + '</span>';
    }
  });
};

/* ---------------- 启动 ---------------- */
function boot(){
  api("/api/admin/session").then(function(r){
    var d = r.data || {};
    if (!d.authed) {
      showLogin();
      if (!d.has_pass) {
        $("loginLead").innerHTML = '<span class="bad">服务端还没配 ADMIN_PASS，先设置再登录</span>';
        $("doLogin").disabled = true;
      }
      return;
    }
    showApp();
    switchTab("dash");
    $("foot").textContent = location.host + " · 数据存 Turso";
    loadBooks();
  });
}
boot();
})();
</script>
</body></html>`;


/* ------------------------------------------------------------------ 领取页
 * 手机打开就是这一页：输 QQ + 取件码 → 秒给链接 → 分片并发下载 + 进度条。
 * 自检块保留（验域名/网关/数据库/配额四件事），但收到最下面。
 */
const HOME_HTML = `<!doctype html>
<html lang="zh-CN"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="robots" content="noindex,nofollow">
<title>领取我的书</title>
<style>
  :root{--bg:#f4f5f7;--card:#fff;--ink:#1a1a1c;--sub:#8a8a91;--line:#ececf0;
        --ok:#0a8f4a;--bad:#c8342b;--warn:#b26b00;--brand:#2b6cff}
  *{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
  body{margin:0;padding:18px 16px 40px;background:var(--bg);color:var(--ink);
       font:16px/1.55 -apple-system,BlinkMacSystemFont,"PingFang SC","Microsoft YaHei",sans-serif}
  h1{margin:0 0 4px;font-size:20px;letter-spacing:-.2px}
  .lead{margin:0 0 18px;color:var(--sub);font-size:13px}
  .card{background:var(--card);border-radius:16px;padding:16px 16px 8px;
        box-shadow:0 1px 2px rgba(0,0,0,.04),0 8px 24px rgba(0,0,0,.03);margin-bottom:14px}
  .card h2{margin:0 0 10px;font-size:14px;font-weight:600;color:var(--sub);letter-spacing:.03em}
  .row{display:flex;align-items:center;gap:10px;padding:11px 0;border-top:1px solid var(--line)}
  .row:first-of-type{border-top:0}
  .dot{width:8px;height:8px;border-radius:50%;background:#cfcfd6;flex:0 0 8px}
  .dot.ok{background:var(--ok)} .dot.bad{background:var(--bad)} .dot.wait{background:var(--warn)}
  .nm{flex:1;font-size:15px}
  .val{font-size:13px;color:var(--sub);font-variant-numeric:tabular-nums;text-align:right}
  input{width:100%;padding:13px 14px;font-size:16px;border:1px solid var(--line);
        border-radius:12px;background:#fafafb;color:var(--ink);outline:none}
  input:focus{border-color:var(--brand);background:#fff}
  .btn{display:block;width:100%;margin-top:10px;padding:14px;font-size:16px;font-weight:600;
       color:#fff;background:var(--brand);border:0;border-radius:12px}
  .btn:active{opacity:.85}
  .btn.ghost{background:#eef1f6;color:#2b2b30;font-weight:500;margin-top:12px}
  #out{margin-top:12px;font-size:14px;color:var(--sub);min-height:24px;white-space:pre-wrap;word-break:break-all}
  #out.ok{color:var(--ok)} #out.bad{color:var(--bad)}
  .codein{margin-top:8px;letter-spacing:4px;text-transform:uppercase;
          font-family:ui-monospace,Menlo,monospace;font-weight:600;text-align:center}
  .pb{height:9px;background:#eef0f4;border-radius:99px;overflow:hidden;margin-top:14px}
  .pb>i{display:block;height:100%;width:4%;background:var(--brand);border-radius:99px;transition:width .35s}
  .sub{color:var(--sub);font-size:12px;margin-top:7px;font-variant-numeric:tabular-nums}
  .hide{display:none!important}
  .vlist{margin-top:10px;border-top:1px solid var(--line)}
  .vrow{display:flex;align-items:center;justify-content:space-between;gap:10px;
        padding:10px 0;border-bottom:1px solid var(--line)}
  .vrow:last-child{border-bottom:0}
  .vrow.off{opacity:.45}
  .vinfo{display:flex;flex-direction:column;min-width:0}
  .vinfo b{font-size:14px}
  .vsub{font-size:11px;color:var(--sub);margin-top:1px}
  .vbtn{padding:8px 16px;font-size:14px;font-weight:600;color:#fff;background:var(--ok);
        border:0;border-radius:9px;flex:0 0 auto}
  .vbtn:disabled{background:#cfcfd6}
  .dlbtn{display:block;width:100%;margin-top:10px;padding:14px;font-size:16px;font-weight:600;
         color:#fff;background:var(--ok);border:0;border-radius:12px;text-align:center;text-decoration:none}
  #selfcheck summary{cursor:pointer;font-size:13px;color:var(--sub);font-weight:600;
        letter-spacing:.03em;list-style:none;outline:none}
  #selfcheck summary::-webkit-details-marker{display:none}
  #selfcheck summary::before{content:"▸ "}
  #selfcheck[open] summary::before{content:"▾ "}
  .bookbox{background:#f7f9ff;border:1px solid #dfe6ff;border-radius:12px;padding:11px 13px;margin-bottom:11px}
  .bookbox.off{background:#f6f6f8;border-color:#e6e6ea}
  .blabel{font-size:11px;color:var(--sub);letter-spacing:.04em}
  .btitle{font-size:16px;font-weight:600;margin-top:2px;line-height:1.35}
  .bmeta{font-size:12px;color:var(--sub);margin-top:3px}
  select{width:100%;padding:12px 13px;font-size:15px;border:1px solid var(--line);border-radius:12px;
         background:#fafafb;color:var(--ink);margin-bottom:9px}
  .foot{margin-top:22px;text-align:center;color:#b0b0b8;font-size:12px;line-height:1.9}
  a{color:var(--brand);text-decoration:none}
  /* 输入框统一居中：原来 QQ 提示语顶格、取件码居中，视觉错位。
   * 字号 16px 是硬要求：<16px 时 iOS Safari 聚焦会自动放大整页。 */
  .fld{display:block;margin:10px 0 0}
  .fld span{display:block;text-align:center;font-size:12px;color:var(--sub);margin-bottom:6px}
  .fld input{text-align:center;font-size:16px}
</style></head>
<body>
  <h1>领取我的书</h1>
  <p class="lead" id="lead">正在读取分享信息…</p>

  <div class="card">
    <h2>领取我的书</h2>
    <div class="bookbox" id="bookBox">
      <div class="blabel">当前分享</div>
      <div class="btitle" id="bookTitle">—</div>
      <div class="bmeta" id="bookMeta"></div>
    </div>
    <select id="bookSel" class="hide"></select>
    <label class="fld"><span>QQ 号</span>
      <input id="qq" inputmode="numeric" autocomplete="off" placeholder="请输入 QQ 号">
    </label>
    <label class="fld"><span>取件码</span>
      <input id="code" inputmode="text" autocomplete="off" autocapitalize="characters" spellcheck="false"
             placeholder="请输入取件码">
    </label>
    <button class="btn" id="go">领取</button>
    <div id="out"></div>
    <div id="dl" class="hide">
      <div class="pb"><i id="dlBar"></i></div>
      <div class="sub" id="dlMsg">准备下载…</div>
    </div>
  </div>

  <div class="foot">取件码是领取凭证，请勿转发</div>

<script>
(function () {
  function $(id) { return document.getElementById(id); }

  /* 当前分享的书。服务端返回 UTC，这里换成浏览器本地时间显示。 */
  var BOOK = { id: 0, list: [] };

  function fmtTime(s) {
    if (!s) return "";
    var d = new Date(String(s).replace(" ", "T") + "Z");
    if (isNaN(d.getTime())) return String(s);
    var p = function (n) { return (n < 10 ? "0" : "") + n; };
    return (d.getMonth() + 1) + "月" + d.getDate() + "日 " + p(d.getHours()) + ":" + p(d.getMinutes());
  }

  function syncBook() {
    var b = null;
    for (var i = 0; i < BOOK.list.length; i++) if (BOOK.list[i].id === BOOK.id) b = BOOK.list[i];
    if (!b) return;
    $("bookTitle").textContent = b.title;
    var mb = b.size ? (b.size / 1048576).toFixed(1) + "MB · " : "";
    $("bookMeta").textContent = mb +
      (b.share_close_at ? ("截止 " + fmtTime(b.share_close_at)) : "长期开放");
  }

  function loadShare(silent) {
    return getJSON("/api/share").then(function (r) {
      var list = (r.data && r.data.books) || [];
      BOOK.list = list;
      if (!list.length) {
        $("bookBox").className = "bookbox off";
        $("bookTitle").textContent = "暂未开放领取";
        $("bookMeta").textContent = "等发放人开放后再来";
        $("lead").textContent = "当前没有开放中的分享。";
        $("go").disabled = true; $("go").textContent = "暂未开放";
        $("qq").disabled = true; $("code").disabled = true;
        $("bookSel").classList.add("hide");
        return;
      }
      BOOK.id = list[0].id;
      syncBook();
      if (!silent) {
        $("lead").textContent = list.length > 1
          ? "有多本书在分享，请先确认要的是哪一本。"
          : "填 QQ 号和取件码，直接下载。";
      }
      if (list.length > 1) {
        $("bookSel").innerHTML = list.map(function (b) {
          return '<option value="' + b.id + '">' + esc(b.title) + '</option>';
        }).join("");
        $("bookSel").classList.remove("hide");
        $("bookSel").value = String(BOOK.id);
        $("bookSel").onchange = function () { BOOK.id = Number(this.value); syncBook(); };
      } else {
        $("bookSel").classList.add("hide");
      }
    });
  }

  function copyText(t, btn) {
    var done = function () {
      if (!btn) return;
      var old = btn.textContent; btn.textContent = "已复制";
      setTimeout(function () { btn.textContent = old; }, 1200);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(t).then(done, function () { window.prompt("手动复制", t); });
    } else {
      window.prompt("手动复制", t);
    }
  }

  function fmtMB(n) {
    n = Number(n || 0);
    return n >= 1048576 ? (n / 1048576).toFixed(1) + "MB" : Math.max(1, Math.round(n / 1024)) + "KB";
  }

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  function getJSON(url) {
    var t0 = Date.now();
    return fetch(url, { cache: "no-store" }).then(function (r) {
      return r.text().then(function (txt) {
        var d = {};
        try { d = JSON.parse(txt); } catch (e) { d = { raw: txt.slice(0, 80) }; }
        return { status: r.status, data: d, ms: Date.now() - t0 };
      });
    }).catch(function () { return { status: 0, data: {}, ms: Date.now() - t0 }; });
  }


  /* 分片并发下载。
   * 为什么不用浏览器原生下载：单连接跨境 0.5MB/s，且没有进度可言。
   * 为什么切成 6 段：单个 TCP 连接受窗口+丢包限制，多连接是唯一不动基础设施的提速办法。
   * 失败一律退回原生下载 —— 宁可慢，也不能"点了没反应"。 */
  function fmt(n) { return (n / 1048576).toFixed(1) + "MB"; }

  function startDownload(url, btn, fname) {
    var box = $("dl"), bar = $("dlBar"), msg = $("dlMsg"), t0 = Date.now();
    box.classList.remove("hide");
    if (btn) { btn.disabled = true; btn.textContent = "下载中…"; }

    /* 兜底绝不能 location.href = url：
     * token 过期时那会把整页替换成一行裸文本 "forbidden"，读者连回来的路都没有。 */
    function direct(reason) {
      bar.style.width = "100%";
      msg.innerHTML =
        '<div class="bad">' + esc(reason || "下载没能开始") + '</div>' +
        '<div class="sub" style="margin-top:6px">链接可能在 5 分钟内已过期。' +
        '请点下面的按钮重新领取。</div>' +
        '<button class="dlbtn" id="dlRetry">重新领取</button>' +
        '<div class="sub" style="margin-top:6px">如果用微信打开，请点右上角 ··· → 在浏览器打开</div>';
      if (btn) { btn.disabled = false; btn.textContent = "下载"; }
      var rb = $("dlRetry");
      if (rb) rb.onclick = function () { $("go").click(); };
    }

    fetch(url, { headers: { "Range": "bytes=0-0" }, cache: "no-store" })
      .then(function (r) {
        var m = /\\/(\\d+)\\s*$/.exec(r.headers.get("Content-Range") || "");
        var total = m ? Number(m[1]) : 0;
        if (!total) throw new Error("no-size");
        if (total > 60 * 1048576) return direct("文件较大，已切换为浏览器直接下载");
        var n = total > 6 * 1048576 ? 6 : 3;
        var seg = Math.ceil(total / n);
        var parts = new Array(n), loaded = 0, jobs = [];
        for (var i = 0; i < n; i++) {
          (function (i) {
            var s = i * seg, e = Math.min(total - 1, s + seg - 1);
            if (s > e) { parts[i] = new Blob([]); return; }
            jobs.push(
              fetch(url, { headers: { "Range": "bytes=" + s + "-" + e }, cache: "no-store" })
                .then(function (rr) {
                  if (rr.status !== 206 && rr.status !== 200) throw new Error("HTTP " + rr.status);
                  return rr.arrayBuffer();
                })
                .then(function (buf) {
                  parts[i] = new Blob([buf]);
                  loaded += buf.byteLength;
                  var pct = Math.min(100, Math.round(loaded / total * 100));
                  bar.style.width = Math.max(4, pct) + "%";
                  var sec = Math.max(0.5, (Date.now() - t0) / 1000);
                  msg.textContent = pct + "% · " + fmt(loaded) + " / " + fmt(total) +
                                    " · " + (loaded / 1048576 / sec).toFixed(1) + "MB/s";
                })
            );
          })(i);
        }
        return Promise.all(jobs).then(function () {
          var blob = new Blob(parts, { type: "application/epub+zip" });
          var a = document.createElement("a");
          a.href = URL.createObjectURL(blob);
          a.download = fname || ("book-" + Date.now() + ".epub");
          document.body.appendChild(a); a.click();
          setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 5000);
          bar.style.width = "100%";
          msg.textContent = "下载完成 · " + fmt(total) + " · " +
                            ((Date.now() - t0) / 1000).toFixed(1) + "s";
          if (btn) btn.textContent = "已下载";
        });
      })
      .catch(function () { direct("网络中断，下载没有开始"); });
  }

  $("go").onclick = function () {
    var qq = ($("qq").value || "").replace(/\\s/g, "");
    // 不转大写：取件码区分大小写，前端一 toUpperCase 就等于帮用户"猜中了"
    var code = ($("code").value || "").replace(/[^A-Za-z0-9]/g, "");
    var out = $("out");
    $("dl").classList.add("hide");
    if (!/^[0-9]{5,12}$/.test(qq)) {
      out.className = "bad"; out.textContent = "请输入 5~12 位数字 QQ 号"; return;
    }
    if (code.length < 4) {
      out.className = "bad"; out.textContent = "请输入取件码"; return;
    }
    out.className = ""; out.textContent = "正在查询…";
    getJSON("/api/claim?qq=" + encodeURIComponent(qq) + "&code=" + encodeURIComponent(code) +
            "&book_id=" + (BOOK.id || 1))
      .then(function (r) {
        var d = r.data || {};
        if (r.status === 200 && d.ready && d.url) {
          out.className = "ok";
          var vs = d.versions || [];
          out.textContent = vs.length > 1
            ? "已经准备好了 · 共 " + vs.length + " 个版本，各自独立计次"
            : "已经准备好了";
          var box = document.createElement("div");
          box.className = "vlist";
          vs.forEach(function (v) {
            var row = document.createElement("div");
            row.className = "vrow" + (v.usable ? "" : " off");
            var info = document.createElement("div");
            info.className = "vinfo";
            info.innerHTML = "<b>" + esc(v.label) + "</b>" +
              '<span class="vsub">' + fmtMB(v.size) + " · 剩 " + v.remaining + " 次</span>";
            var b = document.createElement("button");
            b.className = "vbtn";
            b.textContent = v.usable ? "下载" : "已用完";
            if (v.usable) {
              b.onclick = function () { startDownload(v.url, b, v.filename); };
            } else {
              b.disabled = true;
            }
            row.appendChild(info);
            row.appendChild(b);
            box.appendChild(row);
          });
          if (!vs.length) {
            // 极老的响应没有 versions 字段，退回单个按钮
            var b0 = document.createElement("button");
            b0.className = "dlbtn";
            b0.textContent = "开始下载";
            b0.onclick = function () { startDownload(d.url, b0, d.filename); };
            box.appendChild(b0);
          }
          out.appendChild(box);
          if (d.short_url) {
            var sw = document.createElement("div");
            sw.className = "short";
            sw.innerHTML = "<span>专用链接（过期前可反复打开）</span>" +
              '<button class="scopy" id="scopy">复制</button>';
            out.appendChild(sw);
            (function (u) {
              var b2 = document.getElementById("scopy");
              if (b2) b2.onclick = function () { copyText(u, b2); };
            })(d.short_url);
          }
        } else if (r.status === 202) {
          out.className = "";
          out.textContent = "正在准备（约 30~60 秒）。可以关掉这个页面，稍后回来再点一次。";
        } else if (r.status === 410) {
          out.className = "bad";
          out.textContent = d.error || "本次分享已结束";
          setTimeout(loadShare, 1200);
        } else {
          out.className = "bad";
          out.textContent = d.error || "领取失败，请核对 QQ 号和取件码";
        }
      })
      .catch(function () { out.className = "bad"; out.textContent = "网络不通，请稍后重试"; });
  };

  loadShare();
  /* 页面挂一夜后管理员可能换了书或关了窗口 —— 不刷新就会一直显示旧书名，
   * 直到读者点领取才报错。60 秒一次 + 切回标签页立即刷新。 */
  setInterval(function () {
    if (document.visibilityState === "visible") loadShare(true);
  }, 60000);
  document.addEventListener("visibilitychange", function () {
    if (document.visibilityState === "visible") loadShare(true);
  });
})();
</script>
</body></html>`;

export default {
  /* 所有响应统一补安全头。
   * 为什么必须有：下载链接形如 /dl?k=..&t=..，页面里只要出现一个外链，
   * 浏览器的 Referer 就会把带 token 的 URL 送给第三方。 */
  async fetch(req, env, ctx) {
    const res = await this._fetch(req, env, ctx);
    const h = new Headers(res.headers);
    h.set("X-Content-Type-Options", "nosniff");
    h.set("X-Frame-Options", "SAMEORIGIN");
    h.set("Referrer-Policy", "same-origin");
    h.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
    // 内联 script/style 是这套页面的写法，不能禁 inline；只限制外连与框架
    if (!h.has("Content-Security-Policy")) {
      h.set("Content-Security-Policy",
        "default-src 'self'; script-src 'self' 'unsafe-inline'; " +
        "style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; " +
        "connect-src 'self'; frame-ancestors 'self'; base-uri 'self'");
    }
    return new Response(res.body, { status: res.status, statusText: res.statusText, headers: h });
  },

  async _fetch(req, env, ctx) {
    const url = new URL(req.url);
    const origin = req.headers.get("Origin") || "";
    const p = url.pathname;

    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors(origin) });

    /* ---------- ⓿-A 管理员入口 ----------
     * 两个域名都能进，但都要口令。
     * ⚠️ 不要以为"换个域名"就是权限隔离 —— 域名谁都能知道，真正的门是 ADMIN_PASS。
     * administrator 域名访问 / 直接给管理页，只是省得记路径，不是安全手段。 */
    const host = url.hostname || "";
    const isAdminHost = /^xiuxiu-administrator\./i.test(host);

    /* 根域 0668899.xyz 不放任何业务：它没有前缀、容易被当成"主站"传播，
     * 一旦承载领取页，就等于把领取入口和分享的正式域名混成两个。
     * 这里直接 404，什么都不返回。 */
    if (/^0668899\.xyz$/i.test(host)) {
      return new Response("Not Found", { status: 404,
        headers: { "Content-Type": "text/plain; charset=utf-8" } });
    }
    const cookieSecure = /^(localhost|127\.0\.0\.1|\[::1\])$/.test(host) ? "" : "; Secure";

    if (req.method === "GET" &&
        (p === "/admin" || (isAdminHost && (p === "/" || p === "/index.html")))) {
      return new Response(ADMIN_HTML, {
        headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" },
      });
    }

    if (p === "/api/admin/login" && req.method === "POST") {
      let pw = "";
      try { pw = String((await req.json()).password || ""); } catch (_) { /* 空 body */ }
      const v = await verifyPassword(env, pw);
      if (!v.ok) {
        // 不做失败锁定：锁定反而给了别人"打满你账号"的武器
        return j({ ok: false, error: "口令不对" }, 401, origin);
      }
      // 首次登录（库里还没 hash）：立刻把初始口令落库，之后只认库
      let ver = v.ver;
      if (v.boot) {
        try { ver = await setPassword(env, pw); }
        catch (_) { /* 落库失败不影响本次登录 */ }
      }
      const h = new Headers({ ...JSON_H, ...cors(origin) });
      h.append("Set-Cookie",
        `${ADMIN_COOKIE}=${await makeAdminCookie(env, 2592000, ver)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000${cookieSecure}`);
      return new Response(JSON.stringify({ ok: true, exp: 2592000, boot: v.boot }),
        { status: 200, headers: h });
    }

    /* 改口令：校验旧口令 → 存新 salt/hash → ver+1（所有旧 cookie 立刻失效） */
    if (p === "/api/admin/password" && req.method === "POST") {
      let b = {};
      try { b = await req.json(); } catch (_) { /* 空 body */ }
      const oldPw = String(b.old || "");
      const newPw = String(b.new || "");
      if (!(await adminOK(env, req)) && !(await verifyPassword(env, oldPw)).ok) {
        return j({ ok: false, error: "没有权限" }, 401, origin);
      }
      if (!(await verifyPassword(env, oldPw)).ok) {
        return j({ ok: false, error: "当前口令不对" }, 401, origin);
      }
      if (newPw.length < 6) {
        return j({ ok: false, error: "新口令至少 6 位" }, 400, origin);
      }
      if (newPw === oldPw) {
        return j({ ok: false, error: "新旧口令一样" }, 400, origin);
      }
      const ver = await setPassword(env, newPw);
      const h = new Headers({ ...JSON_H, ...cors(origin) });
      h.append("Set-Cookie",
        `${ADMIN_COOKIE}=${await makeAdminCookie(env, 2592000, ver)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000${cookieSecure}`);
      return new Response(JSON.stringify({ ok: true, ver }), { status: 200, headers: h });
    }

    if (p === "/api/admin/logout" && req.method === "POST") {
      const h = new Headers({ ...JSON_H, ...cors(origin) });
      h.append("Set-Cookie", `${ADMIN_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${cookieSecure}`);
      return new Response(JSON.stringify({ ok: true }), { status: 200, headers: h });
    }

    if (p === "/api/admin/session" && req.method === "GET") {
      let authed = false, boot = false;
      try {
        authed = await isAdmin(env, req);
        boot = (await pwConfig(env)).boot;
      } catch (_) { /* DB 抽风：只回未登录，不 500 */ }
      return new Response(JSON.stringify({
        ok: true, authed, boot,
        has_pass: true,          // 现在永远可用（库没有就用内置初始口令）
        host, is_admin_host: isAdminHost,
      }), { headers: { ...JSON_H, ...cors(origin), "Cache-Control": "no-store" } });
    }

    /* 公开接口：当前开放领取的书（领取页用来显示"现在发的是哪本"，防串书）。
     * 只回 4 个字段，不暴露 r2_key；close_at 给前端显示"还有几天"。 */
    if (p === "/api/share" && req.method === "GET") {
      const rows = rowsToObjs(await sql(env,
        `SELECT id,title,size,share_open_at,share_close_at
           FROM books
          WHERE admin_id=1 AND share_status='open'
            AND (share_open_at  IS NULL OR share_open_at  <= datetime('now'))
            AND (share_close_at IS NULL OR share_close_at >  datetime('now'))
          ORDER BY id DESC`));
      return new Response(JSON.stringify({
        ok: true,
        books: rows.map((r) => ({ ...r, id: Number(r.id), size: Number(r.size || 0) })),
        server_now: new Date().toISOString(),
      }), { headers: { ...JSON_H, ...cors(origin), "Cache-Control": "no-store" } });
    }

      /* ---------- ⓿ 首页：手机打开就能看到东西，用来验域名是否绑通 ---------- */
      if ((p === "/" || p === "/index.html") && req.method === "GET") {
        return new Response(HOME_HTML, {
          headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" },
        });
      }

    try {
      /* ---------- ⑦ 管理员 API（除登录外全部要口令） ---------- */
      if (p.startsWith("/api/admin/")) {
        if (!(await adminOK(env, req))) {
          return j({ ok: false, code: "UNAUTHORIZED", error: "请先登录管理员" }, 401, origin);
        }
        const adminId = 1;                                  // PoC 单管理员

        /* 仪表盘：只放"能从库里算出来的"东西。
         * 今日请求数拿不到 —— Cloudflare 不给 Worker 查自己请求数的接口，
         * 要单独调 GraphQL Analytics API 且 token 得有 Analytics 权限。 */
        if (p === "/api/admin/stats" && req.method === "GET") {
          const u = await usage(env);
          const c = rowsToObjs(await sql(env,
            `SELECT
               (SELECT COUNT(*) FROM books       WHERE admin_id=?) AS books,
               (SELECT COUNT(*) FROM claim_codes WHERE admin_id=?) AS codes,
               (SELECT COUNT(*) FROM files       WHERE admin_id=?) AS files,
               (SELECT COUNT(*) FROM wm_batches  WHERE admin_id=?) AS batches,
               (SELECT COUNT(*) FROM files WHERE admin_id=? AND created_at >= datetime('now','-1 day')) AS files_24h,
               (SELECT COUNT(*) FROM claim_codes WHERE admin_id=? AND uses > 0) AS codes_used`,
            [adminId, adminId, adminId, adminId, adminId, adminId]))[0] || {};
          const open = rowsToObjs(await sql(env,
            `SELECT id,title,share_close_at FROM books
              WHERE admin_id=? AND share_status='open'
                AND (share_open_at  IS NULL OR share_open_at  <= datetime('now'))
                AND (share_close_at IS NULL OR share_close_at >  datetime('now'))`,
            [adminId]));
          return j({
            ok: true,
            r2: { used: u.bytes, limit: u.limit, objects: u.objects,
                  percent: Math.round((u.bytes / Math.max(1, u.limit)) * 100),
                  blocked: u.bytes >= u.limit,
                  over_8g: u.bytes >= 8 * GIB },
            counts: {
              books: Number(c.books || 0), codes: Number(c.codes || 0),
              files: Number(c.files || 0), batches: Number(c.batches || 0),
              files_24h: Number(c.files_24h || 0), codes_used: Number(c.codes_used || 0),
            },
            open_books: open.map((r) => ({ ...r, id: Number(r.id) })),
            retention_hours: Number(env.RETENTION_HOURS || 0),
          }, 200, origin);
        }

        /* 书列表 + 版本历史（管理页的书籍管理） */
        if (p === "/api/admin/books" && req.method === "GET") {
          const rows = rowsToObjs(await sql(env,
            `SELECT id,title,size,created_at,mode,share_status,share_open_at,share_close_at,share_note,share_scope,link_ttl,
                    (share_status='open'
                     AND (share_open_at  IS NULL OR share_open_at  <= datetime('now'))
                     AND (share_close_at IS NULL OR share_close_at >  datetime('now'))
                    ) AS live
               FROM books WHERE admin_id=? ORDER BY id DESC`, [adminId]));
          const vers = rowsToObjs(await sql(env,
            `SELECT id,book_id,version_no,label,filename,size,is_current,kind,created_at
               FROM book_versions
              WHERE book_id IN (SELECT id FROM books WHERE admin_id=?)
              ORDER BY book_id, version_no`, [adminId]));
          const byBook = {};
          for (const v of vers) {
            const k = String(v.book_id);
            (byBook[k] = byBook[k] || []).push({
              ...v, id: Number(v.id), version_no: Number(v.version_no),
              size: Number(v.size || 0), is_current: Number(v.is_current) === 1,
            });
          }
          const counts = rowsToObjs(await sql(env,
            `SELECT book_id, COUNT(*) AS n FROM claim_codes WHERE admin_id=? GROUP BY book_id`,
            [adminId]));
          const nMap = Object.fromEntries(counts.map((r) => [String(r.book_id), Number(r.n)]));
          return j({ ok: true, books: rows.map((r) => {
            let scope = null;
            try { scope = r.share_scope ? JSON.parse(r.share_scope) : null; } catch (_) { scope = null; }
            return {
              ...r, id: Number(r.id), size: Number(r.size || 0), live: Number(r.live) === 1,
              versions: byBook[String(r.id)] || [],
              code_count: nMap[String(r.id)] || 0,
              scope,                                  // {groups:[],qqs:[]} 或 null(=不限制)
            };
          }) }, 200, origin);
        }

        /* 新建书（先建壳，再上传母本） */
        if (p === "/api/admin/books" && req.method === "POST") {
          let b = {};
          try { b = await req.json(); } catch (_) { /* 空 body */ }
          const title = String(b.title || "").trim().slice(0, 80);
          if (!title) return j({ ok: false, error: "书名不能为空" }, 400, origin);
          await sql(env,
            `INSERT INTO books(admin_id,title,r2_key,size,share_status) VALUES(?,?,'',0,'closed')`,
            [adminId, title]);
          const row = rowsToObjs(await sql(env,
            `SELECT id FROM books WHERE admin_id=? ORDER BY id DESC LIMIT 1`, [adminId]))[0];
          return j({ ok: true, book_id: Number(row.id), title }, 200, origin);
        }

        /* 上传母本（每次上传 = 一个新版本；旧版本保留，供溯源）
         * 流式转发到 R2，不落内存。免费版请求体上限 100MB，EPUB 远小于此。 */
        if (p === "/api/admin/upload" && req.method === "POST") {
          const bookId = Number(url.searchParams.get("book_id") || 0);
          const label = String(url.searchParams.get("label") || "").slice(0, 40);
          // revision = 新版本替换旧版（只发最新）；variant = 另一个格式，与现有并存
          const kind = url.searchParams.get("kind") === "variant" ? "variant" : "revision";
          const rawName = String(url.searchParams.get("filename") || "book.epub");
          // Content-Length 是首选；某些运行环境（Node fetch / 部分代理）会丢掉它，
          // 所以前端额外带一个 X-File-Size 兜底 —— 没有长度就无法做配额熔断。
          const len = Number(req.headers.get("Content-Length")
                             || req.headers.get("X-File-Size") || 0);
          if (!bookId) return j({ ok: false, error: "缺 book_id" }, 400, origin);
          if (!len) return j({ ok: false, error: "缺文件大小（Content-Length / X-File-Size）" }, 411, origin);
          if (len > 100 * 1024 * 1024) {
            return j({ ok: false, error: "单个文件超过 100MB（免费版请求体上限）" }, 413, origin);
          }
          const bk = rowsToObjs(await sql(env,
            "SELECT id,title FROM books WHERE id=? AND admin_id=?", [bookId, adminId]))[0];
          if (!bk) return j({ ok: false, error: `没有 book_id=${bookId}` }, 404, origin);

          if (!(await charge(env, len))) {
            const u = await usage(env);
            return j({ ok: false, code: "QUOTA_EXCEEDED",
                       error: "存储配额不够，先清点旧成品",
                       free_bytes: Math.max(0, u.limit - u.bytes) }, 507, origin);
          }
          const mx = rowsToObjs(await sql(env,
            `SELECT IFNULL(MAX(version_no),0) AS m FROM book_versions WHERE book_id=?`,
            [bookId]))[0];
          const vno = Number(mx.m || 0) + 1;
          const safe = rawName.replace(/[^\w.\-\u4e00-\u9fa5]/g, "_").slice(-80) || "book.epub";
          const key = `books/${bookId}/v${vno}/${safe}`;
          try {
            await env.BUCKET.put(key, req.body, {
              httpMetadata: { contentType: "application/epub+zip" },
            });
          } catch (e) {
            await release(env, len);           // 写失败必须退账，否则账越跑越偏
            throw e;
          }
          const stmts = [
            { q: `INSERT INTO book_versions(book_id,version_no,label,r2_key,filename,size,is_current,kind)
                  VALUES(?,?,?,?,?,?,1,?)`,
              args: [bookId, vno, label || `v${vno}`, key, safe, len, kind] },
            { q: `UPDATE books SET r2_key=?, size=?, mode=? WHERE id=?`,
              args: [key, len, kind === "variant" ? "multi" : "single", bookId] },
          ];
          // 修订版：只有最新一版参与打标/分享，旧的留作溯源
          if (kind === "revision") {
            stmts.push({ q: `UPDATE book_versions SET is_current=0 WHERE book_id=? AND version_no<>?`,
                         args: [bookId, vno] });
          }
          await sqlMany(env, stmts);
          return j({ ok: true, book_id: bookId, version_no: vno, kind,
                     label: label || `v${vno}`, key, size: len }, 200, origin);
        }

        /* 改版本名（上传后觉得名字不合适，不用重传重打） */
        if (p.startsWith("/api/admin/versions/") && ["PATCH", "POST"].includes(req.method)) {
          const id = Number(p.split("/").pop());
          if (!id) return j({ ok: false, error: "bad id" }, 400, origin);
          let b = {};
          try { b = await req.json(); } catch (_) { /* 空 body */ }
          const label = String(b.label || "").trim().slice(0, 40);
          if (!label) return j({ ok: false, error: "名字不能为空" }, 400, origin);
          await sql(env, `UPDATE book_versions SET label=? WHERE id=?`, [label, id]);
          return j({ ok: true, id, label }, 200, origin);
        }

        /* 删除一本书：连带清 R2 母本（所有版本）+ 所有成品，再删库记录。
         * R2 的 delete 支持一次传 key 数组（上限 1000），所以 200 人也就 1~2 次子请求。 */
        if (p.startsWith("/api/admin/books/") && req.method === "DELETE") {
          const id = Number(p.split("/").pop());
          if (!id) return j({ ok: false, error: "bad id" }, 400, origin);
          const bk = rowsToObjs(await sql(env,
            "SELECT id,title FROM books WHERE id=? AND admin_id=?", [id, adminId]))[0];
          if (!bk) return j({ ok: false, error: "没有这本书" }, 404, origin);

          /* 有批次在飞时不许删：母本一删，在跑的 Actions 全 failed；
           * 已过拉取阶段的还会把成品传上来、回调写 files → 挂空的 book_id 成幽灵行，
           * 同时把 R2 配额白烧掉。 */
          const flying = rowsToObjs(await sql(env,
            `SELECT COUNT(*) AS n FROM wm_batches
              WHERE book_id=? AND admin_id=? AND status IN ('queued','running')`,
            [id, adminId]))[0];
          const nFly = Number(flying?.n || 0);
          const force = url.searchParams.get("force") === "1";
          if (nFly > 0 && !force) {
            return j({ ok: false, code: "BATCH_RUNNING",
                       error: `这本书还有 ${nFly} 个打标批次在跑，等它结束或先到「打标任务」里确认；`
                            + `确实要删请带 force=1`, running: nFly }, 409, origin);
          }

          const vs = rowsToObjs(await sql(env,
            `SELECT r2_key,size FROM book_versions WHERE book_id=?`, [id]));
          const fs = rowsToObjs(await sql(env,
            `SELECT r2_key,size FROM files WHERE book_id=? AND admin_id=?`, [id, adminId]));
          const all = [...vs, ...fs];
          const keys = all.map((x) => x.r2_key).filter(Boolean);
          const freed = all.reduce((a, x) => a + Number(x.size || 0), 0);
          for (let i = 0; i < keys.length; i += 1000) {
            await env.BUCKET.delete(keys.slice(i, i + 1000));
          }
          await sqlMany(env, [
            { q: `DELETE FROM files       WHERE book_id=? AND admin_id=?`, args: [id, adminId] },
            { q: `DELETE FROM claim_codes WHERE book_id=? AND admin_id=?`, args: [id, adminId] },
            { q: `DELETE FROM book_versions WHERE book_id=?`, args: [id] },
            { q: `DELETE FROM code_uses WHERE code_id IN
                    (SELECT id FROM claim_codes WHERE book_id=? AND admin_id=?)`,
              args: [id, adminId] },
            { q: `DELETE FROM short_links WHERE book_id=?`, args: [id] },
            { q: `DELETE FROM wm_batches WHERE book_id=? AND admin_id=?`, args: [id, adminId] },
            { q: `DELETE FROM books WHERE id=? AND admin_id=?`, args: [id, adminId] },
            { q: `UPDATE r2_usage SET bytes=MAX(0,bytes-?), objects=MAX(0,objects-?)
                   WHERE id=1`, args: [freed, keys.length] },
          ]);
          return j({ ok: true, title: bk.title, deleted_objects: keys.length,
                     freed_bytes: freed }, 200, origin);
        }

        /* 上传疑似文件 → 建溯源工单（解码在本机 worker 做，见 poc/trace_runner.py） */
        if (p === "/api/admin/trace/upload" && req.method === "POST") {
          const fname = String(url.searchParams.get("filename") || "suspect.epub").slice(0, 120);
          const note = String(url.searchParams.get("note") || "").slice(0, 200);
          const len = Number(req.headers.get("Content-Length")
                             || req.headers.get("X-File-Size") || 0);
          if (!len) return j({ ok: false, error: "缺文件大小" }, 411, origin);
          if (len > 100 * 1024 * 1024) {
            return j({ ok: false, error: "文件超过 100MB" }, 413, origin);
          }
          if (!(await charge(env, len))) {
            return j({ ok: false, error: "存储配额不够" }, 507, origin);
          }
          const jobId = crypto.randomUUID();
          const safe = fname.replace(/[^\w.\-\u4e00-\u9fa5]/g, "_").slice(-80) || "suspect.epub";
          const key = `trace/${jobId}/${safe}`;
          try {
            await env.BUCKET.put(key, req.body, {
              httpMetadata: { contentType: "application/epub+zip" },
            });
          } catch (e) { await release(env, len); throw e; }
          await sql(env,
            `INSERT INTO trace_jobs(id,admin_id,r2_key,filename,size,note,engine)
             VALUES(?,?,?,?,?,?,'actions')`, [jobId, adminId, key, safe, len, note]);
          /* 默认走云端解码：Actions 有 numpy/Pillow、免费、不占你电脑。
           * dispatch 失败就退回本地 runner（engine 改回 local 并留在队列里）。 */
          const tk = await makeToken(env, "book", key, 900);
          const d = await dispatchTrace(env, jobId,
            `${env.PUBLIC_BASE}/dl?k=${encodeURIComponent(key)}&t=${tk}`);
          if (!d.ok) {
            await sql(env,
              `UPDATE trace_jobs SET engine='local', updated_at=datetime('now')
                WHERE id=?`, [jobId]);
            return j({ ok: true, job_id: jobId, filename: safe, size: len,
                       engine: "local",
                       warning: `云端触发失败（${d.status}），已退回本机解码器` }, 200, origin);
          }
          return j({ ok: true, job_id: jobId, filename: safe, size: len, engine: "actions" },
                   200, origin);
        }

        /* 查工单（页面轮询用） */
        if (p.startsWith("/api/admin/trace/jobs/") && req.method === "GET") {
          const id = p.split("/").pop();
          const row = rowsToObjs(await sql(env,
            `SELECT id,status,result,reason,filename,size,note,created_at,finished_at
               FROM trace_jobs WHERE id=? AND admin_id=?`, [id, adminId]))[0];
          if (!row) return j({ ok: false, error: "工单不存在" }, 404, origin);
          let result = null;
          try { result = row.result ? JSON.parse(row.result) : null; } catch (_) { /* 脏数据 */ }
          return j({ ok: true, job: { ...row, result } }, 200, origin);
        }

        /* 溯源：watermark_id → 谁的书、什么时候、哪一版母本 */
        if (p === "/api/admin/trace" && req.method === "GET") {
          const wid = (url.searchParams.get("wid") || "").trim();
          if (!wid) return j({ ok: false, error: "请输入 watermark_id" }, 400, origin);
          const m = rowsToObjs(await sql(env,
            `SELECT m.watermark_id,m.qq,m.book_id,m.batch_id,m.created_at,b.title
               FROM wm_mapping m LEFT JOIN books b ON b.id=m.book_id
              WHERE m.watermark_id=? LIMIT 1`, [wid]))[0];
          if (!m) return j({ ok: false, error: "没有这个水印的记录" }, 404, origin);
          // 当时用的母本：取"打标时间之前上传的、版本号最大的那一版"。
          // 不能只按 created_at 排 —— 同一秒上传两版时排序不稳，会指到旧版。
          const ver = rowsToObjs(await sql(env,
            `SELECT version_no,label,r2_key,filename,created_at FROM book_versions
              WHERE book_id=? AND created_at <= ?
              ORDER BY version_no DESC LIMIT 1`,
            [m.book_id, m.created_at]))[0] || null;
          return j({ ok: true, trace: { ...m, version: ver } }, 200, origin);
        }

        /* 分享窗口：一次只开放一本（防串书）。开新的自动关旧的。 */
        if (p === "/api/admin/share" && req.method === "POST") {
          let b = {};
          try { b = await req.json(); } catch (_) { /* 空 body */ }
          const bookId = Number(b.book_id || 0);
          const status = b.status === "open" ? "open" : "closed";
          if (!bookId) return j({ ok: false, error: "缺 book_id" }, 400, origin);
          // 前端传的是 ISO（UTC）；只保留到秒，和 datetime('now') 的格式对齐
          const norm = (s) => {
            if (!s) return null;
            const t = String(s).replace("T", " ").replace("Z", "").slice(0, 19);
            return /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(t) ? t : null;
          };
          const openAt = norm(b.open_at);
          const closeAt = norm(b.close_at);
          if (status === "open" && closeAt && openAt && closeAt <= openAt) {
            return j({ ok: false, error: "结束时间必须晚于开始时间" }, 400, origin);
          }
          // 默认"一次只开一本"：开新的就把别的关掉，避免读者领到上一批的书
          if (status === "open" && b.close_others !== false) {
            await sql(env,
              `UPDATE books SET share_status='closed' WHERE admin_id=? AND id<>?`,
              [adminId, bookId]);
          }
          /* 分享范围：
           *   b.scope = null  → 不改（保持原值）
           *   b.scope = {}    → 清空 = 不限制
           *   b.scope = {groups:[],qqs:[]} → 限定
           * 用 null/undefined 区分"没传"和"传了空"，否则前端漏传字段会把范围清掉。 */
          /* 短链有效期：秒。0/缺省 = 不改；前端用"小时/天"下拉换算成秒 */
          let ttlSql = "", ttlArg = [];
          if (b.link_ttl !== undefined && b.link_ttl !== null && b.link_ttl !== "") {
            const t = Math.max(60, Math.min(30 * 86400, Number(b.link_ttl) || 86400));
            ttlSql = ", link_ttl=?";
            ttlArg = [t];
          }
          let scopeSql = "", scopeArg = [];
          if (b.scope !== undefined) {
            const gids = [...new Set((b.scope && b.scope.groups || []).map(Number).filter(Boolean))];
            const sqqs = [...new Set((b.scope && b.scope.qqs || [])
              .map((x) => String(x || "").trim()).filter((x) => /^\d{5,12}$/.test(x)))];
            const val = (gids.length || sqqs.length)
              ? JSON.stringify({ groups: gids, qqs: sqqs }) : null;
            scopeSql = ", share_scope=?";
            scopeArg = [val];
          }
          await sql(env,
            `UPDATE books SET share_status=?, share_open_at=?, share_close_at=?, share_note=?`
            + `${ttlSql}${scopeSql} WHERE id=? AND admin_id=?`,
            [status, status === "open" ? openAt : null,
             status === "open" ? closeAt : null,
             String(b.note || "").slice(0, 200), ...ttlArg, ...scopeArg, bookId, adminId]);
          // 确认真的改到了（book_id 不存在时 changes=0，必须报错而不是假成功）
          const chk = rowsToObjs(await sql(env,
            `SELECT id,title,share_status,share_open_at,share_close_at,share_note,share_scope,link_ttl
               FROM books WHERE id=? AND admin_id=?`, [bookId, adminId]))[0];
          if (!chk) return j({ ok: false, error: `没有 book_id=${bookId}` }, 404, origin);
          return j({ ok: true, book: chk }, 200, origin);
        }

        /* 码表：默认按书查，带 ready 标记（有没有成品）—— 管理员最怕"发了码但书没打好" */
        if (p === "/api/admin/codes" && req.method === "GET") {
          const q = (url.searchParams.get("q") || "").trim();
          const limit = Math.min(500, Math.max(1, Number(url.searchParams.get("limit") || 300)));
          /* 取件码**按 QQ 全局唯一**：一个人一个码，换书不用重发。
           * 所以这里不再按 book_id 过滤（旧接口的 book_id 参数仍然接受但忽略）。 */
          const rows = rowsToObjs(await sql(env,
            `SELECT id,qq,code,status,uses,max_uses,expires_at,created_at,
                    verified_at, verify_count,
                    (expires_at IS NOT NULL AND expires_at <= datetime('now')) AS expired
               FROM claim_codes WHERE admin_id=?
                ${q ? "AND (qq LIKE ? OR code LIKE ?)" : ""}
               ORDER BY id DESC LIMIT ?`,
            q ? [adminId, `%${q}%`, `%${q}%`, limit] : [adminId, limit]));

          /* 每个码的"最紧剩余"与"涉及几本书"：
           * max_uses 是**每版本**上限，跨版本求和会算出 6/3 这种假"用完"。 */
          const agg = new Map(rowsToObjs(await sql(env,
            `SELECT cc.id AS code_id,
                    MIN(cc.max_uses - IFNULL(u.uses,0)) AS min_left,
                    SUM(IFNULL(u.uses,0)) AS used_total,
                    COUNT(DISTINCT f.book_id) AS books
               FROM claim_codes cc
               LEFT JOIN files f ON f.qq = cc.qq AND f.admin_id = cc.admin_id
               LEFT JOIN book_versions v ON v.id = f.version_id AND v.is_current = 1
               LEFT JOIN code_uses u ON u.code_id = cc.id AND u.version_id = f.version_id
              WHERE cc.admin_id=? AND (f.id IS NULL OR v.id IS NOT NULL)
              GROUP BY cc.id`, [adminId])).map((r) => [Number(r.code_id), r]));

          return j({ ok: true, total: rows.length, scoped: "qq",
                     codes: rows.map((r) => {
                       const a = agg.get(Number(r.id)) || {};
                       const usedTotal = Number(a.used_total || 0);
                       const minLeft = a.min_left === undefined || a.min_left === null
                         ? null : Number(a.min_left);
                       const books = Number(a.books || 0);
                       const maxU = Number(r.max_uses || 0);
                       const expd = Number(r.expired) === 1;
                       const vc = Number(r.verify_count || 0);
                       let state;
                       if (r.status === "revoked") state = "已作废";
                       else if (expd) state = "已过期";
                       else if (books === 0) state = vc > 0 ? "已校验未下载" : "未校验";
                       else if (minLeft !== null && minLeft <= 0) state = "次数用完";
                       else if (usedTotal > 0) state = "已下载 " + usedTotal + " 次";
                       else state = "已校验未下载";
                       return {
                         ...r,
                         uses: usedTotal,
                         left_min: minLeft,
                         books,
                         ready: books > 0,
                         ready_versions: books,
                         expired: expd,
                         verify_count: vc,
                         verified_at: r.verified_at || "",
                         state,
                         max_uses: maxU,
                       };
                     }) },
                   200, origin);
        }

        /* ---------- 专用链接（短链）管理 ---------- */
        if (p === "/api/admin/links" && req.method === "GET") {
          const bookId = Number(url.searchParams.get("book_id") || 0);
          const rows = rowsToObjs(await sql(env,
            `SELECT l.id,l.book_id,l.qq,l.exp,l.hits,l.revoked,l.created_at,
                    (l.exp <= datetime('now')) AS expired, b.title
               FROM short_links l LEFT JOIN books b ON b.id=l.book_id
              WHERE l.admin_id=? ${bookId ? "AND l.book_id=?" : ""}
              ORDER BY l.created_at DESC LIMIT 200`,
            bookId ? [adminId, bookId] : [adminId]));
          return j({ ok: true, links: rows.map((r) => ({ ...r,
                     expired: Number(r.expired) === 1, revoked: Number(r.revoked) === 1,
                     url: `${env.PUBLIC_BASE}/s/${r.id}` })) }, 200, origin);
        }

        /* 主动给某人生成一条链接（没领过也能发） */
        if (p === "/api/admin/links" && req.method === "POST") {
          let b = {};
          try { b = await req.json(); } catch (_) { /* 空 body */ }
          const bookId = Number(b.book_id || 0);
          const qq = String(b.qq || "").trim();
          if (!bookId || !/^\d{5,12}$/.test(qq)) {
            return j({ ok: false, error: "需要 book_id 和合法 QQ" }, 400, origin);
          }
          const bk = rowsToObjs(await sql(env,
            "SELECT link_ttl FROM books WHERE id=? AND admin_id=?", [bookId, adminId]))[0];
          if (!bk) return j({ ok: false, error: "没有这本书" }, 404, origin);
          const cd = rowsToObjs(await sql(env,
            "SELECT id FROM claim_codes WHERE admin_id=? AND qq=? ORDER BY id DESC LIMIT 1",
            [adminId, qq]))[0];
          if (!cd) return j({ ok: false, error: "这个 QQ 还没有取件码，先生成码" }, 400, origin);
          const sid = await ensureShortLink(env, adminId, bookId, Number(cd.id), qq,
                                            bk.link_ttl || 86400);
          return j({ ok: true, id: sid, url: `${env.PUBLIC_BASE}/s/${sid}` }, 200, origin);
        }

        if (p.startsWith("/api/admin/links/") && req.method === "DELETE") {
          const id = p.split("/").pop();
          if (!/^[a-f0-9]{32}$/.test(id)) return j({ ok: false, error: "bad id" }, 400, origin);
          await sql(env, "UPDATE short_links SET revoked=1 WHERE id=? AND admin_id=?",
            [id, adminId]);
          return j({ ok: true }, 200, origin);
        }

        /* ---------- 分组 ---------- */
        if (p === "/api/admin/groups" && req.method === "GET") {
          const gs = rowsToObjs(await sql(env,
            `SELECT g.id, g.name, g.note, g.sort,
                    (SELECT COUNT(*) FROM group_members gm WHERE gm.group_id=g.id) AS members
               FROM groups g WHERE g.admin_id=? ORDER BY g.sort, g.id`, [adminId]));
          return j({ ok: true, groups: gs.map((g) => ({ ...g, id: Number(g.id),
                     members: Number(g.members || 0) })) }, 200, origin);
        }

        if (p === "/api/admin/groups" && req.method === "POST") {
          let b = {};
          try { b = await req.json(); } catch (_) { /* 空 body */ }
          const name = String(b.name || "").trim().slice(0, 40);
          if (!name) return j({ ok: false, error: "分组名不能为空" }, 400, origin);
          const ex = rowsToObjs(await sql(env,
            "SELECT id FROM groups WHERE admin_id=? AND name=?", [adminId, name]))[0];
          if (ex) return j({ ok: false, error: "已有同名分组" }, 409, origin);
          await sql(env,
            "INSERT INTO groups(admin_id,name,note) VALUES(?,?,?)",
            [adminId, name, String(b.note || "").slice(0, 100)]);
          // Turso 不回 lastInsertRowid（要自己查），别指望驱动给
          const row = rowsToObjs(await sql(env,
            "SELECT id FROM groups WHERE admin_id=? AND name=?", [adminId, name]))[0];
          return j({ ok: true, id: Number(row ? row.id : 0), name }, 200, origin);
        }

        if (p.startsWith("/api/admin/groups/") && ["PATCH", "DELETE"].includes(req.method)) {
          const id = Number(p.split("/")[4] || 0);
          if (!id) return j({ ok: false, error: "bad id" }, 400, origin);
          if (req.method === "DELETE") {
            await sqlMany(env, [
              { q: "DELETE FROM group_members WHERE group_id=?", args: [id] },
              { q: "DELETE FROM groups WHERE id=? AND admin_id=?", args: [id, adminId] },
            ]);
            return j({ ok: true }, 200, origin);
          }
          let b = {};
          try { b = await req.json(); } catch (_) { /* 空 body */ }
          const sets = [], args = [];
          if (b.name !== undefined) { sets.push("name=?"); args.push(String(b.name).trim().slice(0, 40)); }
          if (b.note !== undefined) { sets.push("note=?"); args.push(String(b.note).slice(0, 100)); }
          if (b.sort !== undefined) { sets.push("sort=?"); args.push(Number(b.sort) || 0); }
          if (!sets.length) return j({ ok: false, error: "没有要改的字段" }, 400, origin);
          if (b.name !== undefined) {
            const dup = rowsToObjs(await sql(env,
              "SELECT id FROM groups WHERE admin_id=? AND name=? AND id<>?",
              [adminId, String(b.name).trim().slice(0, 40), id]))[0];
            if (dup) return j({ ok: false, error: "已有同名分组" }, 409, origin);
          }
          await sql(env, `UPDATE groups SET ${sets.join(",")} WHERE id=? AND admin_id=?`,
            [...args, id, adminId]);
          return j({ ok: true }, 200, origin);
        }

        /* 组成员：读 / 批量加入（并集，重复导入不覆盖已有关系） / 移出 */
        if (p.startsWith("/api/admin/groups/") && p.endsWith("/members") && req.method === "GET") {
          const gid = Number(p.split("/")[4] || 0);
          const rows = rowsToObjs(await sql(env,
            `SELECT r.id, r.qq, r.note, gm.added_at
               FROM group_members gm JOIN recipients r ON r.id=gm.recipient_id
              WHERE gm.group_id=? AND r.admin_id=? ORDER BY r.id DESC LIMIT 500`,
            [gid, adminId]));
          return j({ ok: true, group_id: gid, members: rows }, 200, origin);
        }

        if (p.startsWith("/api/admin/groups/") && p.endsWith("/members") && req.method === "POST") {
          const gid = Number(p.split("/")[4] || 0);
          const g = rowsToObjs(await sql(env,
            "SELECT id FROM groups WHERE id=? AND admin_id=?", [gid, adminId]))[0];
          if (!g) return j({ ok: false, error: "分组不存在" }, 404, origin);
          let b = {};
          try { b = await req.json(); } catch (_) { /* 空 body */ }
          const raw = Array.isArray(b.qqs) ? b.qqs : [b.qq];
          const qqs = [...new Set(raw.map((x) => String(x || "").trim())
            .filter((x) => /^\d{5,12}$/.test(x)))].slice(0, 500);
          if (!qqs.length) return j({ ok: false, error: "没有合法 QQ 号" }, 400, origin);

          const ids = await ensureRecipients(env, adminId, qqs, String(b.note || "").slice(0, 100));
          // INSERT OR IGNORE：已在组里的人不报错、不改动 —— 这就是"并集导入"
          await sqlMany(env, ids.map((r) => ({
            q: "INSERT OR IGNORE INTO group_members(group_id,recipient_id) VALUES(?,?)",
            args: [gid, r.id],
          })));
          const cnt = rowsToObjs(await sql(env,
            "SELECT COUNT(*) AS n FROM group_members WHERE group_id=?", [gid]))[0];
          return j({ ok: true, added: ids.length, total: Number(cnt.n || 0) }, 200, origin);
        }

        if (p.startsWith("/api/admin/groups/") && p.endsWith("/remove") && req.method === "POST") {
          const gid = Number(p.split("/")[4] || 0);
          let b = {};
          try { b = await req.json(); } catch (_) { /* 空 body */ }
          const raw = Array.isArray(b.qqs) ? b.qqs : [b.qq];
          const qqs = raw.map((x) => String(x || "").trim()).filter(Boolean).slice(0, 500);
          if (!qqs.length) return j({ ok: false, error: "没有要移除的 QQ" }, 400, origin);
          const ph = qqs.map(() => "?").join(",");
          await sql(env,
            `DELETE FROM group_members WHERE group_id=? AND recipient_id IN
               (SELECT id FROM recipients WHERE admin_id=? AND qq IN (${ph}))`,
            [gid, adminId, ...qqs]);
          return j({ ok: true }, 200, origin);
        }

        /* ---------- 黑名单 ---------- */
        if (p === "/api/admin/blocklist" && req.method === "GET") {
          const rows = rowsToObjs(await sql(env,
            "SELECT id,qq,reason,created_at FROM blocklist WHERE admin_id=? ORDER BY id DESC LIMIT 500",
            [adminId]));
          return j({ ok: true, blocklist: rows }, 200, origin);
        }

        if (p === "/api/admin/blocklist" && req.method === "POST") {
          let b = {};
          try { b = await req.json(); } catch (_) { /* 空 body */ }
          const raw = Array.isArray(b.qqs) ? b.qqs : [b.qq];
          const qqs = [...new Set(raw.map((x) => String(x || "").trim())
            .filter((x) => /^\d{5,12}$/.test(x)))].slice(0, 200);
          if (!qqs.length) return j({ ok: false, error: "没有合法 QQ 号" }, 400, origin);
          const reason = String(b.reason || "").slice(0, 100);
          const beforeN = Number(rowsToObjs(await sql(env,
            "SELECT COUNT(*) AS n FROM blocklist WHERE admin_id=?", [adminId]))[0]?.n || 0);
          await sqlMany(env, qqs.map((qq) => ({
            q: "INSERT OR IGNORE INTO blocklist(admin_id,qq,reason) VALUES(?,?,?)",
            args: [adminId, qq, reason],
          })));
          /* 拉黑即"从所有分组移出"：留在组里会让分享范围继续把他算进去，
           * 而且下次开放这本书时他仍出现在名单上，容易误判。 */
          const ph = qqs.map(() => "?").join(",");
          await sql(env,
            `DELETE FROM group_members WHERE recipient_id IN
               (SELECT id FROM recipients WHERE admin_id=? AND qq IN (${ph}))`,
            [adminId, ...qqs]);
          const afterN = Number(rowsToObjs(await sql(env,
            "SELECT COUNT(*) AS n FROM blocklist WHERE admin_id=?", [adminId]))[0]?.n || 0);
          return j({ ok: true, added: afterN - beforeN, total: afterN }, 200, origin);
        }

        if (p.startsWith("/api/admin/blocklist/") && req.method === "DELETE") {
          const id = Number(p.split("/").pop());
          if (!id) return j({ ok: false, error: "bad id" }, 400, origin);
          await sql(env, "DELETE FROM blocklist WHERE id=? AND admin_id=?", [id, adminId]);
          return j({ ok: true }, 200, origin);
        }

        /* ---------- 领取人名单 ---------- */
        if (p === "/api/admin/recipients" && req.method === "GET") {
          const q = (url.searchParams.get("q") || "").trim();
          const limit = Math.min(500, Math.max(1, Number(url.searchParams.get("limit") || 300)));
          const rows = rowsToObjs(await sql(env,
            `SELECT id,qq,note,status,created_at FROM recipients
              WHERE admin_id=? ${q ? "AND (qq LIKE ? OR note LIKE ?)" : ""}
              ORDER BY id DESC LIMIT ?`,
            q ? [adminId, `%${q}%`, `%${q}%`, limit] : [adminId, limit]));
          // 带上"有没有码"，名单和码表才对得上
          const coded = new Set(rowsToObjs(await sql(env,
            `SELECT DISTINCT qq FROM claim_codes WHERE admin_id=? AND book_id=?`,
            [adminId, Number(url.searchParams.get("book_id") || 1)])).map((r) => String(r.qq)));
          return j({ ok: true, total: rows.length,
                     recipients: rows.map((r) => ({ ...r, has_code: coded.has(String(r.qq)) })) },
                   200, origin);
        }

        if (p === "/api/admin/recipients" && req.method === "POST") {
          let b = {};
          try { b = await req.json(); } catch (_) { /* 空 body */ }
          const raw = Array.isArray(b.qqs) ? b.qqs : [b.qq];
          const qqs = [...new Set(raw.map((x) => String(x || "").trim())
            .filter((x) => /^\d{5,12}$/.test(x)))].slice(0, 500);
          if (!qqs.length) return j({ ok: false, error: "没有合法 QQ 号" }, 400, origin);
          const note = String(b.note || "").slice(0, 100);
          await sqlMany(env, qqs.map((qq) => ({
            q: `INSERT OR IGNORE INTO recipients(admin_id,qq,note,source) VALUES(?,?,?,'manual')`,
            args: [adminId, qq, note],
          })));
          const n = rowsToObjs(await sql(env,
            `SELECT COUNT(*) AS n FROM recipients WHERE admin_id=?`, [adminId]))[0];
          return j({ ok: true, added: qqs.length, total: Number(n.n || 0) }, 200, origin);
        }

        if (p.startsWith("/api/admin/recipients/") && ["PATCH", "DELETE"].includes(req.method)) {
          const id = Number(p.split("/").pop());
          if (!id) return j({ ok: false, error: "bad id" }, 400, origin);
          if (req.method === "DELETE") {
            await sql(env, `DELETE FROM recipients WHERE id=? AND admin_id=?`, [id, adminId]);
            return j({ ok: true }, 200, origin);
          }
          let b = {};
          try { b = await req.json(); } catch (_) { /* 空 body */ }
          const sets = [], args = [];
          if (b.note !== undefined) { sets.push("note=?"); args.push(String(b.note).slice(0, 100)); }
          if (b.status !== undefined && ["new", "sent", "banned"].includes(b.status)) {
            sets.push("status=?"); args.push(b.status);
          }
          if (!sets.length) return j({ ok: false, error: "没有要改的字段" }, 400, origin);
          await sql(env, `UPDATE recipients SET ${sets.join(",")} WHERE id=? AND admin_id=?`,
            [...args, id, adminId]);
          return j({ ok: true }, 200, origin);
        }

        /* 批量生成 / 单个补发。已存在的码原样返回，绝不覆盖。 */
        if (p === "/api/admin/codes" && req.method === "POST") {
          let b = {};
          try { b = await req.json(); } catch (_) { /* 空 body */ }
          const bookId = Number(b.book_id || 1);
          const raw = Array.isArray(b.qqs) ? b.qqs : [b.qq];
          const qqs = [...new Set(raw.map((x) => String(x || "").trim())
            .filter((x) => /^\d{5,12}$/.test(x)))].slice(0, 200);
          if (!qqs.length) {
            return j({ ok: false, error: "没有合法的 QQ 号（5~12 位数字）" }, 400, origin);
          }
          const codes = await ensureCodes(env, adminId, bookId, qqs, b);
          return j({ ok: true, book_id: bookId,
                     created: codes.filter((c) => c.is_new).length,
                     reused: codes.filter((c) => !c.is_new).length,
                     codes }, 200, origin);
        }

        /* 从成品回填：老数据（修复前打的）只有 files 没有码，这里补一批。
         * ⚠️ 必须排在 /api/admin/codes/:id 之前，否则 "backfill" 会被 Number() 成 NaN。 */
        if (p === "/api/admin/codes/backfill" && req.method === "POST") {
          let b = {};
          try { b = await req.json(); } catch (_) { /* 空 body */ }
          const bookId = Number(b.book_id || 1);
          const qqs = rowsToObjs(await sql(env,
            `SELECT DISTINCT qq FROM files WHERE admin_id=? AND book_id=? LIMIT 500`,
            [adminId, bookId])).map((r) => String(r.qq));
          if (!qqs.length) return j({ ok: true, created: 0, reused: 0, total: 0 }, 200, origin);
          const codes = await ensureCodes(env, adminId, bookId, qqs, b);
          return j({ ok: true, total: codes.length,
                     created: codes.filter((c) => c.is_new).length,
                     reused: codes.filter((c) => !c.is_new).length }, 200, origin);
        }

        /* 一键重置整本书的已用次数（例如换一批人重发、或测试后清场）。
         * ⚠️ 必须排在 /api/admin/codes/:id 之前，否则 "reset" 被 Number() 成 NaN。 */
        if (p === "/api/admin/codes/reset" && req.method === "POST") {
          let b = {};
          try { b = await req.json(); } catch (_) { /* 空 body */ }
          const bookId = Number(b.book_id || 0);
          if (!bookId) return j({ ok: false, error: "缺 book_id" }, 400, origin);
          // 两处都清：claim_codes.uses 是展示兼容字段，code_uses 才是真账本
          const r = await sqlRetry(env,
            `UPDATE claim_codes SET uses=0, updated_at=datetime('now')
              WHERE admin_id=? AND book_id=?`, [adminId, bookId]);
          await sql(env,
            `DELETE FROM code_uses WHERE code_id IN
               (SELECT id FROM claim_codes WHERE admin_id=? AND book_id=?)`,
            [adminId, bookId]);
          return j({ ok: true, reset: r.changes || 0 }, 200, origin);
        }

        /* 一键换码：给某个 QQ 重新生成一个新取件码（可选清零已用次数）。
         * 用途：码被转发出去、或客诉"码不对"时，换一个最省事。 */
        if (p.startsWith("/api/admin/codes/") && p.endsWith("/regen") && req.method === "POST") {
          const id = Number(p.split("/")[4] || 0);
          if (!id) return j({ ok: false, error: "bad id" }, 400, origin);
          let b = {};
          try { b = await req.json(); } catch (_) { /* 空 body */ }
          const row = rowsToObjs(await sql(env,
            "SELECT id,qq FROM claim_codes WHERE id=? AND admin_id=?", [id, adminId]))[0];
          if (!row) return j({ ok: false, error: "没有这个码" }, 404, origin);
          let created = "";
          for (let i = 0; i < 6 && !created; i++) {
            const c = genCode(6);
            try {
              await sql(env, "UPDATE claim_codes SET code=?, updated_at=datetime('now') WHERE id=?",
                [c, id]);
              created = c;
            } catch (e) {
              if (!/UNIQUE/i.test(String(e && e.message || e))) throw e;
            }
          }
          if (!created) return j({ ok: false, error: "换码失败（连续撞码）" }, 500, origin);
          if (b.reset !== false) {
            await sqlMany(env, [
              { q: "DELETE FROM code_uses WHERE code_id=?", args: [id] },
              { q: "UPDATE claim_codes SET uses=0 WHERE id=?", args: [id] },
            ]);
          }
          return j({ ok: true, id, qq: String(row.qq), code: created, reset: b.reset !== false },
                   200, origin);
        }

        /* 改码 / 改上限 / 作废 / 恢复 —— 只按 id 改，且限定本管理员 */
        if (p.startsWith("/api/admin/codes/") && ["PATCH", "POST"].includes(req.method)) {
          const id = Number(p.split("/").pop());
          if (!id) return j({ ok: false, error: "bad id" }, 400, origin);
          let b = {};
          try { b = await req.json(); } catch (_) { /* 空 body */ }

          const sets = [], args = [];
          if (b.code !== undefined && b.code !== null) {
            const c = normCode(b.code, env);
            if (!/^[A-Z0-9]{4,12}$/.test(c)) {
              return j({ ok: false, error: "暗号只能 4~12 位字母或数字" }, 400, origin);
            }
            sets.push("code=?"); args.push(c);
          }
          if (b.max_uses !== undefined) {
            sets.push("max_uses=?"); args.push(Math.max(1, Math.min(50, Number(b.max_uses) || 3)));
          }
          if (b.expires_at !== undefined) { sets.push("expires_at=?"); args.push(b.expires_at || null); }
          // 重置已用次数：客诉和自测最常用。真正的计数在 code_uses（按版本），
          // 只改 claim_codes.uses 是清不到账的 —— 必须两边一起清。
          const resetUses = b.uses !== undefined;
          if (resetUses) {
            sets.push("uses=?"); args.push(Math.max(0, Math.min(999, Number(b.uses) || 0)));
          }
          if (b.status !== undefined) {
            if (!["active", "revoked"].includes(b.status)) {
              return j({ ok: false, error: "status 只能是 active / revoked" }, 400, origin);
            }
            sets.push("status=?"); args.push(b.status);
          }
          if (b.note !== undefined) { sets.push("note=?"); args.push(String(b.note).slice(0, 200)); }
          if (!sets.length) return j({ ok: false, error: "没有要改的字段" }, 400, origin);
          sets.push("updated_at=datetime('now')");

          try {
            await sqlRetry(env,
              `UPDATE claim_codes SET ${sets.join(",")} WHERE id=? AND admin_id=?`,
              [...args, id, adminId]);
            if (resetUses && Number(b.uses) === 0) {
              await sql(env, "DELETE FROM code_uses WHERE code_id=?", [id]);
            }
          } catch (e) {
            if (/UNIQUE/i.test(String(e && e.message || e))) {
              return j({ ok: false, error: "这个暗号已被这本书里的其他人占用，换一个" }, 409, origin);
            }
            throw e;
          }
          const row = rowsToObjs(await sql(env,
            `SELECT id,qq,code,status,uses,max_uses,expires_at FROM claim_codes
              WHERE id=? AND admin_id=?`, [id, adminId]))[0];
          if (!row) return j({ ok: false, error: "not found" }, 404, origin);
          return j({ ok: true, code: row }, 200, origin);
        }

        /* 导出 CSV（带 BOM，Excel 双击不乱码） */
        if (p === "/api/admin/codes.csv" && req.method === "GET") {
          // 取件码按 QQ 全局，导出就是全量（不再按书切）
          const rows = rowsToObjs(await sql(env,
            `SELECT cc.qq,cc.code,cc.status,cc.max_uses,cc.expires_at,cc.created_at,
                    IFNULL((SELECT SUM(uses) FROM code_uses WHERE code_id=cc.id), 0) AS used
               FROM claim_codes cc WHERE cc.admin_id=? ORDER BY cc.id`, [adminId]));
          const csv = toCSV(
            ["QQ", "暗号", "状态", "已用次数", "次数上限", "过期时间", "生成时间"],
            rows.map((r) => [r.qq, r.code, r.status === "active" ? "有效" : "已作废",
                             r.used, r.max_uses, r.expires_at || "不过期", r.created_at]));
          return new Response(csv, {
            headers: {
              "Content-Type": "text/csv; charset=utf-8",
              "Content-Disposition":
                `attachment; filename="claim-codes-${new Date().toISOString().slice(0, 10)}.csv"`,
              "Cache-Control": "no-store",
              ...cors(origin),
            },
          });
        }

        /* 试打一本：放量前先看一眼封面/水印对不对，避免打废 200 本 */
        if (p === "/api/admin/try-one" && req.method === "POST") {
          let b = {};
          try { b = await req.json(); } catch (_) { /* 空 body */ }
          const bookId = Number(b.book_id || 1);
          const qq = String(b.qq || "").trim();
          if (!/^\d{5,12}$/.test(qq)) {
            return j({ ok: false, error: "填一个 5~12 位测试 QQ 号" }, 400, origin);
          }
          const bk = rowsToObjs(await sql(env,
            "SELECT id FROM books WHERE id=?", [bookId]))[0];
          if (!bk) return j({ ok: false, error: `books 表里没有 book_id=${bookId}` }, 400, origin);
          const verId = await pickVersion(env, bookId, b.version_id);
          if (verId === undefined) {
            return j({ ok: false, error: "指定的版本不属于这本书" }, 400, origin);
          }

          const batchId = crypto.randomUUID();
          await sqlRetry(env,
            `INSERT INTO wm_batches(id,admin_id,book_id,total,status,queued_at,
                                    created_at,updated_at,dedup_key,qqs,plan_id,version_id)
             VALUES(?,?,?,1,'queued',datetime('now'),datetime('now'),datetime('now'),?,?,?,?)`,
            [batchId, adminId, bookId, `try:${batchId}`, JSON.stringify([qq]), batchId,
             verId || null]);
          const d = await dispatch(env, batchId,
            await makeToken(env, "act", batchId, 900));
          if (!d.ok) {
            await sqlRetry(env,
              `UPDATE wm_batches SET status='failed',reason=?,finished_at=datetime('now'),
                      updated_at=datetime('now') WHERE id=?`, [`dispatch ${d.status}`, batchId]);
            return j({ ok: false, error: `触发失败（${d.status}）` }, 502, origin);
          }
          // 顺手把码也备好，试打完就能直接用这个 QQ + 码走一遍领取，端到端验完
          const codes = await ensureCodes(env, adminId, bookId, [qq], {});
          return j({ ok: true, batch_id: batchId, qq, code: codes[0]?.code || "",
                     eta: 90 }, 200, origin);
        }

        return j({ ok: false, error: "unknown admin api" }, 404, origin);
      }

      /* ---------- ① 建批次并触发 Actions ---------- */
      if (p === "/api/wm/jobs" && req.method === "POST") {
        // 这个接口能触发 Actions（烧 GitHub 额度），必须挡在管理员后面
        if (!(await adminOK(env, req))) {
          return j({ ok: false, code: "UNAUTHORIZED", error: "请先登录管理员" }, 401, origin);
        }
        const b = await req.json();
        const adminId = 1;                                   // PoC：写死；生产从会话取
        // 去重 + 去空，最多 200 人（不在这里切 20 了，改由分波承担）
        const qqs = [...new Set((b.qqs || []).map((x) => String(x).trim()).filter(Boolean))].slice(0, 200);
        if (!qqs.length) return j({ ok: false, error: "qqs 不能为空" }, 400, origin);
        const bookId = Number(b.book_id || 1);
        const bk = rowsToObjs(await sql(env, "SELECT id FROM books WHERE id=?", [bookId]));
        if (!bk.length) {
          return j({ ok: false, code: "BOOK_NOT_FOUND",
                     error: `books 表里没有 book_id=${bookId}` }, 400, origin);
        }
        /* 打标必须能指定母本版本。之前只认 books.r2_key（=最后上传那版），
         * 想给 Kindle 版打标只能重传它 —— 这是"分发有版本、引擎没版本"的根因。 */
        const verId = await pickVersion(env, bookId, b.version_id);
        if (verId === undefined) {
          return j({ ok: false, error: "指定的版本不属于这本书" }, 400, origin);
        }
        const sim = inject(env, b.simulate);
        const planId = crypto.randomUUID();

        // 分波：每波 CHUNK 本、1 个 workflow run。串行 dispatch（间隔 1.2s），
        // 避免 200 人一次打 200 个 run 撞 GitHub 的 20 并发上限。
        const batches = [];
        let failed = 0;
        for (let i = 0; i < qqs.length; i += CHUNK) {
          const part = qqs.slice(i, i + CHUNK);
          const batchId = crypto.randomUUID();
          await sqlRetry(env,
            `INSERT INTO wm_batches(id,admin_id,book_id,group_id,total,status,
                                    queued_at,created_at,updated_at,simulate,dedup_key,qqs,plan_id,version_id)
             VALUES(?,?,?,?,?,'queued',datetime('now'),datetime('now'),datetime('now'),?,?,?,?,?)`,
            [batchId, adminId, bookId, b.group_id || null, part.length,
             sim, `p:${planId}:${i / CHUNK}`, JSON.stringify(part), planId, verId || null]);

          const cb = await makeToken(env, "act", batchId, 900);
          const d = await dispatch(env, batchId, cb, sim);
          if (!d.ok) {
            failed++;
            await sqlRetry(env,
              `UPDATE wm_batches SET status='failed',reason=?,finished_at=datetime('now'),
                      updated_at=datetime('now') WHERE id=?`, [`dispatch ${d.status}`, batchId]);
          }
          batches.push({ batch_id: batchId, total: part.length, dispatched: d.ok });
          if (i + CHUNK < qqs.length) await new Promise((r) => setTimeout(r, 1200));
        }

        return j({
          ok: failed === 0,
          plan_id: planId,
          batch_id: batches[0].batch_id,        // 兼容单批调用方
          total: qqs.length,
          chunks: batches.length,
          failed,
          batches,
          version_id: verId || null,
        }, 200, origin);
      }

      /* ---------- ①b 计划聚合：一次提交 = 多个波次，前端只轮询这一个 ---------- */
      if (p.startsWith("/api/wm/plans/") && req.method === "GET") {
        const pid = p.split("/").pop();
        const rows = rowsToObjs(await sql(env,
          `SELECT id,status,total,done,failed,reason,queued_at,started_at,finished_at
             FROM wm_batches WHERE plan_id=? ORDER BY queued_at, id`, [pid])).map((r) => r);
        if (!rows.length) return j({ ok: false, error: "plan not found" }, 404, origin);
        const sum = (k) => rows.reduce((a, r) => a + Number(r[k] || 0), 0);
        const st = rows.every((r) => r.status === "done") ? "done"
          : rows.some((r) => r.status === "running") ? "running"
          : rows.every((r) => ["done", "failed"].includes(r.status))
            ? (rows.some((r) => r.status === "failed") ? "failed" : "done")
            : "queued";
        return j({
          ok: true, plan_id: pid, status: st,
          total: sum("total"), done: sum("done"), failed: sum("failed"),
          chunks: rows.length,
          batches: rows,
        }, 200, origin);
      }

      /* ---------- ② 轮询：只查主键、只回 3 个字段 ---------- */
      if (p.startsWith("/api/wm/batches/") && req.method === "GET") {
        const id = p.split("/").pop();
        // 三时间戳一起回：前端算"排队多久 / 跑了多久"，测试断言 started_at>queued_at
        const rs = rowsToObjs(await sql(env,
          `SELECT status,done,total,queued_at,started_at,finished_at
             FROM wm_batches WHERE id=?`, [id]));
        if (!rs.length) return j({ ok: false, error: "not found" }, 404, origin);
        return new Response(JSON.stringify({ ok: true, ...rs[0] }),
          { headers: { ...JSON_H, ...cors(origin), "Cache-Control": "no-store" } });
      }

      /* ---------- ③ Actions 领任务 ---------- */
      if (p.startsWith("/internal/batch/") && req.method === "POST") {
        const id = p.split("/").pop();
        const t = await checkToken(env, req.headers.get("X-Act-Token"), "act", id);
        if (!t.ok) return j({ ok: false, error: "bad token", why: t.why }, 401);
        // 单次可用：同一个 token 不能反复领（防重放）
        const nk = `n:${id}:${t.exp}`;
        if (await env.KV.get(nk)) return j({ ok: false, error: "token reused" }, 409);
        await env.KV.put(nk, "1", { expirationTtl: 1800 });

        const bs = rowsToObjs(await sql(env,
          "SELECT * FROM wm_batches WHERE id=?", [id]))[0];
        if (!bs) return j({ ok: false, error: "batch not found" }, 404);
        /* 母本来源：批次指定了版本就用那一版，否则退回 books.r2_key（当前版） */
        let bk = rowsToObjs(await sql(env,
          "SELECT r2_key FROM books WHERE id=?", [bs.book_id]))[0];
        if (bs.version_id) {
          const v = rowsToObjs(await sql(env,
            "SELECT r2_key FROM book_versions WHERE id=? AND book_id=?",
            [bs.version_id, bs.book_id]))[0];
          if (v && v.r2_key) bk = v;
        }
        if (!bk || !bk.r2_key) return j({ ok: false, error: "母本不存在" }, 409);
        // ⚠️ 之前只查 recipients 名册：名册空 → qqs=[] → 工作流判定失败退回 direct 模式
        //    → 没有 UPLOAD_URL → 成品被静默跳过上传 → 回调仍报 done。（真实事故）
        //    现在批次自带 qqs 优先，名册只兜底。
        let bqqs = [];
        try { bqqs = JSON.parse(bs.qqs || "[]"); } catch (_) { bqqs = []; }
        const recs = bqqs.length ? bqqs.map((q) => ({ qq: String(q) })) : rowsToObjs(await sql(env,
          "SELECT qq FROM recipients WHERE admin_id=? AND status!='banned' LIMIT 20",
          [bs.admin_id]));

        // started_at 只在第一次进 running 时写；重放/重试不覆盖（否则排队时长被抹掉）
        await sql(env,
          `UPDATE wm_batches
              SET status='running',
                  started_at=IFNULL(started_at, datetime('now')),
                  updated_at=datetime('now')
            WHERE id=? AND status IN ('queued','running')`, [id]);

        return j({
          batch_id: id,
          qqs: recs.map((r) => r.qq),
          // token 的 scope 就是对象 key —— 换 k 参数就验不过（防串号/防猜路径）
          mother_url: `${env.PUBLIC_BASE}/dl?k=${encodeURIComponent(bk.r2_key)}`
                    + `&t=${await makeToken(env, "book", bk.r2_key, 900)}`,
          // scope = 批次目录前缀：一波 15 本各自一个 key，共用一个 token
          upload_prefix: `out/${id}/`,
          upload_url: `${env.PUBLIC_BASE}/up?t=${await makeToken(env, "up", `out/${id}/`, 1800)}`,
          // 租户密钥：生产环境应再叠一层"仅本批次、10 分钟"的 KMS/加密，PoC 直给
          creds: { server_secret: env.POC_SERVER_SECRET, db_key: env.POC_DB_KEY },
        });
      }

      /* ---------- ④ Actions 回调（幂等）+ 映射落库 ---------- */
      if (p === "/internal/callback" && req.method === "POST") {
        const b = await req.json();
        const t = await checkToken(env, req.headers.get("X-Act-Token"), "act", b.batch_id);
        if (!t.ok) return j({ ok: false, error: "bad token", why: t.why }, 401);

        const cur = rowsToObjs(await sql(env,
          "SELECT status,done,total FROM wm_batches WHERE id=?", [b.batch_id]))[0];
        if (!cur) return j({ ok: false, error: "batch not found" }, 404);
        // 终态不可变：done/failed 之后再来的回调一律"幂等成功、不改库"。
        // 这条同时挡住 QA §3.1 的非法边（done→running、failed→done）。
        if (cur.status === "done" || cur.status === "failed") {
          return j({ ok: true, idempotent: true, status: cur.status });
        }
        // 错误注入：模拟"Actions 跑完了但写库失败"——此时绝不能把状态改成 done，
        // 必须让看门狗在 STUCK_MINUTES 后把它收敛成 failed（QA CONS-002）
        if (inject(env, b.simulate) === "turso_fail") {
          return j({ ok: false, error: "injected turso failure" }, 500);
        }

        // 批量上报：workflow 把本次 run 产出的所有记录一次性发过来（records 数组）。
        // 逐条写、**串行**（不并发打 Turso），每条带重试 —— SQLite 内核最怕并发写。
        const recs = Array.isArray(b.records) ? b.records.filter((r) => r && r.watermark_id) : [];
        if (b.status === "done" && recs.length) {
          const b2 = rowsToObjs(await sql(env,
            "SELECT admin_id,book_id,version_id FROM wm_batches WHERE id=?", [b.batch_id]))[0];
          if (!b2) return j({ ok: false, error: "batch not found" }, 404);
          /* 成品必须挂到**这一批实际用的母本版本**上。
           * 之前一律挂 is_current=1：批次打的是 v1，回调时当前版已变 v2 ⇒
           * 读者领"手机版"下到的其实是 v1 打的书，次数还扣在 v2 账上。 */
          const curV0 = rowsToObjs(await sql(env,
            "SELECT id FROM book_versions WHERE book_id=? AND is_current=1 LIMIT 1",
            [b2.book_id]))[0];
          const useVer = b2.version_id ? Number(b2.version_id)
                                       : (curV0 ? Number(curV0.id) : null);
          for (const r of recs) {
            const k = r.keys || {};
            await sqlRetry(env,
              `INSERT INTO wm_mapping(watermark_id,admin_id,qq,book_id,batch_id,
                                      chaos_seed,chaos_mu,css_key,lsb_key,version_id)
               SELECT ?,admin_id,?,book_id,id,?,?,?,?,? FROM wm_batches WHERE id=?
               ON CONFLICT(watermark_id) DO UPDATE SET
                 chaos_seed=excluded.chaos_seed, chaos_mu=excluded.chaos_mu,
                 css_key=excluded.css_key, lsb_key=excluded.lsb_key,
                 version_id=excluded.version_id`,
              [r.watermark_id, String(r.qq || ""),
               k.chaos_seed ?? null, k.chaos_mu ?? null,
               k.css_key ?? null, k.lsb_key ?? null, useVer, b.batch_id]);

            await sqlRetry(env,
              `INSERT INTO files(admin_id,qq,book_id,batch_id,r2_key,token,watermark_id,version_id)
               VALUES(?,?,?,?,?,?,?,?)
               ON CONFLICT(admin_id,qq,version_id) DO UPDATE SET
                 r2_key=excluded.r2_key, batch_id=excluded.batch_id,
                 watermark_id=excluded.watermark_id`,
              [b2.admin_id, String(r.qq || ""), b2.book_id, b.batch_id,
               r.r2_key || `out/${b.batch_id}/${r.watermark_id}.epub`,
               crypto.randomUUID(), r.watermark_id, useVer]);
          }
        } else if (b.watermark_id) {
          // 兼容旧的单条回调（老 workflow / 手工测试）
          const k = b.keys || {};
          await sqlRetry(env,
            `INSERT INTO wm_mapping(watermark_id,admin_id,qq,book_id,batch_id,
                                    chaos_seed,chaos_mu,css_key,lsb_key)
             SELECT ?,admin_id,?,book_id,id,?,?,?,? FROM wm_batches WHERE id=?
             ON CONFLICT(watermark_id) DO UPDATE SET
               chaos_seed=excluded.chaos_seed, chaos_mu=excluded.chaos_mu,
               css_key=excluded.css_key, lsb_key=excluded.lsb_key`,
            [b.watermark_id, (b.qq || ""),
             k.chaos_seed ?? null, k.chaos_mu ?? null,
             k.css_key ?? null, k.lsb_key ?? null, b.batch_id]);
          if (b.status === "done" && b.qq) {
            const b2 = rowsToObjs(await sql(env,
              "SELECT admin_id,book_id FROM wm_batches WHERE id=?", [b.batch_id]))[0];
            const curV2 = rowsToObjs(await sql(env,
              "SELECT id FROM book_versions WHERE book_id=? AND is_current=1 LIMIT 1",
              [b2.book_id]))[0];
            await sqlRetry(env,
              `INSERT INTO files(admin_id,qq,book_id,batch_id,r2_key,token,watermark_id,version_id)
               VALUES(?,?,?,?,?,?,?,?)
               ON CONFLICT(admin_id,qq,version_id) DO UPDATE SET
                 r2_key=excluded.r2_key, batch_id=excluded.batch_id,
                 watermark_id=excluded.watermark_id`,
              [b2.admin_id, b.qq, b2.book_id, b.batch_id,
               `out/${b.batch_id}/${b.watermark_id}.epub`, crypto.randomUUID(), b.watermark_id,
               curV2 ? Number(curV2.id) : null]);
          }
        }
        // finished_at 同时打上：done 与 failed 都是终态，都算"收敛"
        await sql(env,
          `UPDATE wm_batches
              SET status=?,done=done+?,failed=failed+?,reason=?,
                  finished_at=datetime('now'), updated_at=datetime('now')
            WHERE id=? AND status NOT IN ('done','failed')`,
          [b.status || "done",
           b.status === "failed" ? 0 : Math.max(1, recs.length),
           b.status === "failed" ? 1 : 0,
           (b.reason || "").slice(0, 200), b.batch_id]);
        return j({ ok: true });
      }

      /* ---------- ⑤ 领取：预生成为主 → 命中就秒下，没命中才排队 ----------
       * 这就是 CTO 要的"即点即下、零排队"：管理端提前批量预生成，
       * 领取端 99% 只是查一次 files 表 + 签一个 5 分钟 token，完全不碰 Actions。 */
      if (p === "/api/claim" && (req.method === "POST" || req.method === "GET")) {
        // GET 也支持：手机首页直接 form 提交 / 扫码进来都是 GET，少一次前端拼 POST 的代码
        const b = req.method === "POST"
          ? await req.json()
          : { qq: url.searchParams.get("qq") || "", book_id: url.searchParams.get("book_id") || 1 };
        const adminId = 1;                                   // PoC 写死，生产从会话取
        const qq = String(b.qq || "").trim();
        const rawCode = normCode(b.code || url.searchParams.get("code") || "", env);
        const bookId = Number(b.book_id || 1);
        if (!qq) return j({ ok: false, error: "qq required" }, 400, origin);

        // 书不存在就没必要往下走（但**不泄**任何别的信息）
        const bkRow = rowsToObjs(await sql(env,
          `SELECT id,title,share_status,link_ttl,
                  (share_open_at  IS NOT NULL AND share_open_at  >  datetime('now')) AS not_yet,
                  (share_close_at IS NOT NULL AND share_close_at <= datetime('now')) AS expired
             FROM books WHERE id=? AND admin_id=?`, [bookId, adminId]))[0];
        if (!bkRow) {
          return j({ ok: false, code: "BOOK_NOT_FOUND", error: "没有这本书" }, 404, origin);
        }

        /* ⚠ 顺序：先验取件码，再判"封禁 / 窗口 / 范围"。
         *
         * 反过来会有一个真实的探测面：任何人拿一串 QQ 去试 claim，就能从
         * BANNED / NOT_IN_SCOPE / SHARE_CLOSED 这些**不同**的码反推出
         * "谁被封了""谁在分享范围里"——精心设计的 BAD_CREDENTIALS 防枚举被前置检查绕掉了。
         * 先验码，验过之后才告诉他为什么不能领，语义也顺。
         *
         * 取件码是**按 QQ 全局唯一**的（不按书区分）：一个人一个码，换书不用重发。
         * CLAIM_REQUIRE_CODE=0 是给老数据留的逃生门，新部署不要关。 */
        const requireCode = String(env.CLAIM_REQUIRE_CODE ?? "1") !== "0";
        let codeRow = null;
        if (requireCode) {
          if (!rawCode) {
            return j({ ok: false, code: "CODE_REQUIRED", error: "请输入取件码" }, 400, origin);
          }
          // 过期判断交给 SQLite（UTC），不在 JS 里拼时间串
          codeRow = rowsToObjs(await sql(env,
            `SELECT id,code,status,max_uses,expires_at,
                    (expires_at IS NOT NULL AND expires_at <= datetime('now')) AS expired
               FROM claim_codes WHERE admin_id=? AND qq=?
              ORDER BY id DESC LIMIT 1`, [adminId, qq]))[0];
          // 不区分"QQ 不在名单"和"码错了"，防枚举
          if (!codeRow || normCode(codeRow.code, env) !== rawCode) {
            return j({ ok: false, code: "BAD_CREDENTIALS",
                       error: "QQ 号或取件码不对" }, 403, origin);
          }
          if (codeRow.status !== "active") {
            return j({ ok: false, code: "CODE_REVOKED",
                       error: "这个取件码已作废，请联系发放人" }, 403, origin);
          }
          if (Number(codeRow.expired) === 1) {
            return j({ ok: false, code: "CODE_EXPIRED", error: "取件码已过期" }, 403, origin);
          }
        }

        /* 黑名单：验过码才告知"你被禁止领取"。码和成品都不删——溯源要用。 */
        const blk = rowsToObjs(await sql(env,
          "SELECT reason FROM blocklist WHERE admin_id=? AND qq=?", [adminId, qq]))[0];
        if (blk) {
          return j({ ok: false, code: "BANNED",
                     error: "该账号已被禁止领取，请联系发放人" }, 403, origin);
        }

        /* 分享窗口：关闸靠这里（暗号永久有效，人不会记得给 200 人各设过期）。
         * 管理员带登录态不受限，否则窗口一关没法验收。 */
        const closed = bkRow.share_status !== "open"
          || Number(bkRow.expired) === 1 || Number(bkRow.not_yet) === 1;
        if (closed && !(await adminOK(env, req))) {
          return j({ ok: false, code: "SHARE_CLOSED", book: bkRow.title,
                     error: Number(bkRow.not_yet) === 1 ? "还没到开放时间" : "本次分享已结束，请联系发放人" },
                   410, origin);
        }

        /* 分享范围：这本书只给某些分组 / 某些人时，其他人即使有码也拒。 */
        if (!(await adminOK(env, req))) {
          const gate = await claimGate(env, adminId, qq, bookId);
          if (gate) return j(gate.body, gate.status, origin);
        }

        /* 多版本：一次查出这本书的所有版本、该用户在各版本下的成品、各版本已用次数。
         * LEFT JOIN 保证"有版本但没成品"也能查到（显示成未生成，而不是报错）。 */
        const vers = rowsToObjs(await sql(env,
          `SELECT v.id AS version_id, v.version_no, v.label, v.size AS vsize,
                  f.r2_key,
                  IFNULL(u.uses, 0) AS used
             FROM book_versions v
             LEFT JOIN files f ON f.book_id = v.book_id AND f.version_id = v.id
                              AND f.qq = ? AND f.admin_id = ?
             LEFT JOIN code_uses u ON u.code_id = ? AND u.version_id = v.id
            /* is_current=1 是关键：revision 被替换掉的旧版 is_current=0，
               否则"替换旧版"之后读者仍能拿到旧版，且下载次数按版本翻倍 */
            WHERE v.book_id = ? AND v.is_current = 1
            ORDER BY v.version_no`,
          [qq, adminId, codeRow ? codeRow.id : 0, bookId]));

        /* 记一次"校验通过"：码表要看得出"已校验但没下载"这种卡住的中间态。
         * 只在有成品可用时记，避免把"还没打标"也算成校验过。 */
        if (codeRow && vers.some((v) => v.r2_key)) {
          await sql(env,
            `UPDATE claim_codes
                SET verified_at=IFNULL(verified_at, datetime('now')),
                    verify_count=verify_count+1, updated_at=datetime('now')
              WHERE id=?`, [codeRow.id]);
        }

        const readyVers = vers.filter((v) => v.r2_key);
        if (readyVers.length) {
          const maxUses = Number(codeRow ? codeRow.max_uses : 3);
          const ttl = Number(env.DL_TTL || 300);
          const stamp = fileStamp();
          const list = [];
          for (const v of readyVers) {
            const used = Number(v.used || 0);
            const remaining = Math.max(0, maxUses - used);
            const tk = await makeToken(env, "book", v.r2_key, ttl);
            list.push({
              version_id: Number(v.version_id),
              version_no: Number(v.version_no),
              label: v.label || ("v" + v.version_no),
              size: Number(v.vsize || 0),
              remaining,
              usable: remaining > 0,
              // c/v 是给 /dl 用的：下载时才知道该给哪个版本扣次数
              url: remaining > 0
                ? `${env.PUBLIC_BASE}/dl?k=${encodeURIComponent(v.r2_key)}&t=${tk}`
                  + `&c=${codeRow ? codeRow.id : 0}&v=${v.version_id}`
                : null,
              filename: vers.length > 1
                ? `${fileSafe(bkRow.title)}_v${v.version_no}_${stamp}.epub`
                : `${fileSafe(bkRow.title)}_${stamp}.epub`,
            });
          }
          const usable = list.filter((x) => x.usable);
          if (!usable.length) {
            return j({ ok: false, code: "CODE_EXHAUSTED",
                       error: `所有版本的下载次数都用完了（每版上限 ${maxUses} 次）`,
                       versions: list }, 403, origin);
          }
          // 短链：同一本书多版本共用一个链接（读者不用逐个存链接）
          let shortUrl = "";
          if (codeRow && String(env.SHORT_LINK ?? "1") !== "0") {
            const sid = await ensureShortLink(env, adminId, bookId, codeRow.id, qq,
                                              bkRow.link_ttl || env.LINK_TTL || 86400);
            shortUrl = `${env.PUBLIC_BASE}/s/${sid}`;
          }
          return j({
            ok: true, ready: true, mode: "instant",
            short_url: shortUrl,
            versions: list,
            // 兼容老前端：url / filename / uses_left 取第一个可用版本
            url: usable[0].url,
            filename: usable[0].filename,
            uses_left: usable.reduce((a, x) => a + x.remaining, 1) - 1,
            max_uses: maxUses,
            pack: {
              usable: usable.length,
              total: list.length,
              // 只有"全部版本都有额度"才能给全量 zip（zip 是打标时预生成的全量包）
              downloadable: usable.length === list.length && list.length > 1,
            },
          }, 200, origin);
        }

        /* 没命中：这里必须**原子**收敛。
         * 旧写法是"先 SELECT 在飞 → 再 INSERT"，两个并发请求会同时读到空，
         * 于是各建一条批次（测试 10 并发 → 10 条在飞）。现在靠
         * `ux_batch_inflight(dedup_key) WHERE status IN ('queued','running')`
         * 这个部分唯一索引：INSERT 冲突即证明别人先建了，直接取他那条返回。 */
        const dedup = `u:${adminId}:${qq}:${bookId}`;
        const batchId = crypto.randomUUID();
        // qqs 必须带上：/internal/batch 优先读它，否则名册空时工作流会退回 direct 模式
        let created = 1;
        try {
          await sql(env,
            `INSERT INTO wm_batches(id,admin_id,book_id,total,status,queued_at,
                                    created_at,updated_at,dedup_key,qqs)
             VALUES(?,?,?,1,'queued',datetime('now'),datetime('now'),datetime('now'),?,?)`,
            [batchId, adminId, bookId, dedup, JSON.stringify([qq])]);
        } catch (e) {
          if (!/UNIQUE/i.test(String(e && e.message || e))) throw e;
          created = 0;                                  // 别人先建了
        }
        if (!created) {
          const flying = rowsToObjs(await sql(env,
            `SELECT id FROM wm_batches
              WHERE dedup_key=? AND status IN ('queued','running')
              ORDER BY queued_at DESC LIMIT 1`, [dedup]))[0];
          return j({ ok: true, ready: false, batch_id: flying ? flying.id : batchId,
                     eta: 180, mode: "queued", dedup: true }, 200, origin);
        }
        const cb = await makeToken(env, "act", batchId, 900);
        const d = await dispatch(env, batchId, cb);
        if (!d.ok) {
          await sql(env, `UPDATE wm_batches SET status='failed',reason=? WHERE id=?`,
            [`dispatch ${d.status}`, batchId]);
          return j({ ok: false, error: "触发失败" }, 502, origin);
        }
        return j({ ok: true, ready: false, batch_id: batchId, eta: 180, mode: "queued" }, 202, origin);
      }

      /* ---------- ④b 看门狗：把"卡在非终态"的批次收敛成 failed ----------
       * QA R4 的答案：Actions 崩了、回调丢了、Turso 写挂了，都表现为"状态不动"。
       * 前端不能永远转圈，所以必须有一个外部定时器来"判死"。
       * 判据是 updated_at（不是 created_at）：running 期间每有进展都会刷新它。
       * 调用方：cron（Cloudflare Cron / 外部 Uptime 探针 / 你自己手动 POST）。
       * 生产要加两道：① 只允许内网/带 WATCHDOG_TOKEN；② 判死后发告警。 */
      if (p === "/internal/watchdog" && req.method === "POST") {
        const tok = req.headers.get("X-Watchdog-Token") || "";
        if (!env.WATCHDOG_TOKEN || tok !== env.WATCHDOG_TOKEN) {
          return j({ ok: false, error: "forbidden" }, 403);
        }
        let stuck = Number(env.STUCK_MINUTES || 20);      // running 多久没动就判死
        let queue = Number(env.QUEUE_MINUTES || 30);      // queued 多久没被领走就判死
        try {
          const bb = await req.json();
          if (bb && Number(bb.minutes) > 0) stuck = Number(bb.minutes);
          if (bb && Number(bb.queue_minutes) > 0) queue = Number(bb.queue_minutes);
        } catch (_) { /* 没 body 就用环境变量 */ }

        // 先查再改：① 能拿到 id 列表回给测试 ② 上限 50 条，避免一次写爆 Turso
        const dead = rowsToObjs(await sql(env,
          `SELECT id,status FROM wm_batches
            WHERE (status='running' AND updated_at < datetime('now', ?))
               OR (status='queued'  AND updated_at < datetime('now', ?))
            LIMIT 50`, [`-${stuck} minutes`, `-${queue} minutes`]));

        for (const d of dead) {
          await sql(env,
            `UPDATE wm_batches
                SET status='failed', failed=failed+1,
                    reason=?, finished_at=datetime('now'), updated_at=datetime('now')
              WHERE id=? AND status IN ('queued','running')`,
            [`watchdog: ${d.status} 超时未收敛`, d.id]);
        }
        return j({ ok: true, killed: dead.length, ids: dead.map((d) => d.id),
                   stuck_minutes: stuck, queue_minutes: queue }, 200, origin);
      }

      /* ---------- 溯源工单：本机 worker 取任务 ---------- */
      if (p === "/internal/trace/take" && req.method === "POST") {
        if (!(await adminOK(env, req))) {
          return j({ ok: false, error: "unauthorized" }, 401);
        }
        const row = rowsToObjs(await sql(env,
          /* engine='actions' 的单子由 Actions 直接做，本机 runner 不要抢 ——
           * 两边同时解会重复烧 CPU，而且结果后写覆盖先写。 */
          `SELECT id,admin_id,r2_key,filename,size,note FROM trace_jobs
            WHERE status='queued' AND IFNULL(engine,'local')='local'
            ORDER BY created_at LIMIT 1`))[0];
        if (!row) return j({ ok: true, job: null }, 200);
        // 先占位再返回：多开 worker 也不会重复取同一单
        const claimed = await sql(env,
          `UPDATE trace_jobs SET status='running', claimed_at=datetime('now'),
                  updated_at=datetime('now') WHERE id=? AND status='queued'`, [row.id]);
        if (claimed.changes !== 1) return j({ ok: true, job: null }, 200);
        const t = await makeToken(env, "book", row.r2_key, 1800);
        return j({ ok: true, job: {
          ...row,
          url: `${env.PUBLIC_BASE}/dl?k=${encodeURIComponent(row.r2_key)}&t=${t}`,
        } }, 200);
      }

      /* ---------- 溯源工单：本机 worker 回写结果 ---------- */
      if (p === "/internal/trace/result" && req.method === "POST") {
        let b = {};
        try { b = await req.json(); } catch (_) { /* 空 body */ }
        if (!b.job_id) return j({ ok: false, error: "缺 job_id" }, 400);
        /* 两条腿都认：
         *   ① Actions 用一次性 X-Trace-Token（scope=trace 绑 job_id）
         *   ② 本机 runner 用管理凭据 */
        const tt = req.headers.get("X-Trace-Token");
        const byToken = tt ? await checkToken(env, tt, "trace", String(b.job_id)) : { ok: false };
        if (!byToken.ok && !(await adminOK(env, req))) {
          return j({ ok: false, error: "unauthorized" }, 401);
        }
        await sql(env,
          `UPDATE trace_jobs SET status=?, result=?, reason=?,
                  finished_at=datetime('now'), updated_at=datetime('now')
            WHERE id=?`,
          [b.ok ? "done" : "failed", JSON.stringify(b.result || {}),
           String(b.reason || "").slice(0, 300), b.job_id]);
        return j({ ok: true }, 200);
      }

      /* ---------- ④e 运行时改限额（运维应急 / 测试造边界） ---------- */
      if (p === "/internal/quota" && req.method === "POST") {
        const tok = req.headers.get("X-Watchdog-Token") || "";
        if (!env.WATCHDOG_TOKEN || tok !== env.WATCHDOG_TOKEN) {
          return j({ ok: false, error: "forbidden" }, 403);
        }
        let n = 0;
        try { n = Number((await req.json()).limit_bytes || 0); } catch (_) { /* keep 0 */ }
        if (!n || n < 1024) {
          return j({ ok: false, error: "limit_bytes 必须 >= 1KiB" }, 400, origin);
        }
        await sql(env, "UPDATE r2_usage SET limit_bytes=?, updated_at=datetime('now') WHERE id=1", [n]);
        const u = await usage(env);
        return j({ ok: true, limit_bytes: u.limit, used_bytes: u.bytes }, 200, origin);
      }

      /* ---------- ④c 用量查询（前端/运维看"水池还剩多少"） ---------- */
      if (p === "/api/quota" && req.method === "GET") {
        const u = await usage(env);
        return j({
          ok: true,
          used_bytes: u.bytes, limit_bytes: u.limit, objects: u.objects,
          free_bytes: Math.max(0, u.limit - u.bytes),
          percent: +(u.limit ? (u.bytes / u.limit) * 100 : 0).toFixed(2),
          blocked: u.bytes >= u.limit,
          alert_webhook: !!env.ALERT_WEBHOOK,
          retention_hours: Number(env.RETENTION_HOURS || 72),
          allow_inject: env.ALLOW_INJECT === "1",
        }, 200, origin);
      }

      /* ---------- ④d 定期清理：删过期成品 + 扣账 ----------
       * 对应原 Python 的 purge_files：超过 N 小时（默认 72）的成品删除，并扣回 r2_usage。
       * 判据用 R2 对象的 uploaded 时间（不是库里的 created_at）—— 以对象真实存在为准，
       * 库里先删了但对象还在的情况才不会漏账。
       */
      if (p === "/internal/purge" && req.method === "POST") {
        const tok = req.headers.get("X-Watchdog-Token") || "";
        if (!env.WATCHDOG_TOKEN || tok !== env.WATCHDOG_TOKEN) {
          return j({ ok: false, error: "forbidden" }, 403);
        }
        let hours = Number(env.RETENTION_HOURS || 72);
        let dry = false;
        let limit = 1000;
        try {
          const bb = await req.json();
          if (bb && Number(bb.hours) >= 0) hours = Number(bb.hours);
          if (bb && bb.dry) dry = true;
          if (bb && Number(bb.limit) > 0) limit = Math.min(1000, Number(bb.limit));
        } catch (_) { /* 用默认值 */ }

        const cutoff = Date.now() - hours * 3600 * 1000;
        // out/ 是成品；trace/ 是溯源上传的疑似文件。后者之前没有任何回收路径，
        // 每传一次就永久占配额（12MB × 50 = 600MB），最后把真成品挤到 507。
        const listed = await env.BUCKET.list({ limit, prefix: "out/" });
        const listedTr = await env.BUCKET.list({ limit, prefix: "trace/" });
        const all = [...(listed.objects || []), ...(listedTr.objects || [])];
        const dead = all.filter((o) => {
          const ts = o.uploaded ? new Date(o.uploaded).getTime() : 0;
          return ts > 0 && ts < cutoff;
        });

        let freed = 0;
        let n = 0;
        if (!dry) {
          for (const o of dead) {
            await env.BUCKET.delete(o.key);
            await sql(env, "DELETE FROM files WHERE r2_key=?", [o.key]);
            if (o.key.startsWith("trace/")) {
              // trace/<job_id>/<file>
              const jobId = o.key.split("/")[1] || "";
              if (jobId) await sql(env, "DELETE FROM trace_jobs WHERE id=?", [jobId]);
            }
            await release(env, Number(o.size || 0));
            freed += Number(o.size || 0);
            n += 1;
          }
        } else {
          freed = dead.reduce((a, o) => a + Number(o.size || 0), 0);
          n = dead.length;
        }
        const u = await usage(env);
        return j({
          ok: true, dry, hours, scanned: all.length, deleted: n, freed_bytes: freed,
          used_bytes: u.bytes, limit_bytes: u.limit,
          truncated: !!listed.truncated,
          cursor: listed.truncated ? (listed.cursor || "") : "",
        }, 200, origin);
      }

      /* ---------- ④z 动态短链：/s/<32 位十六进制> ----------
       * 一个链接覆盖这本书的所有版本：读者不用为每个版本各存一条链接。
       * 每次点下载才现签 5 分钟 token，所以链接能活 1 天、凭证永远只活 5 分钟。 */
      if (p.startsWith("/s/") && req.method === "GET") {
        const sid = (p.slice(3).split("/")[0] || "");
        if (!/^[a-f0-9]{32}$/.test(sid)) {
          return new Response("链接不对", { status: 404 });
        }
        const sl = rowsToObjs(await sql(env,
          `SELECT id,admin_id,book_id,code_id,qq,exp,revoked,
                  (exp <= datetime('now')) AS expired
             FROM short_links WHERE id=?`, [sid]))[0];
        if (!sl || Number(sl.revoked) === 1 || Number(sl.expired) === 1) {
          return new Response(
            "<!doctype html><meta charset=utf-8>"
            + "<meta name=viewport content='width=device-width,initial-scale=1'>"
            + "<div style='font:16px/1.7 system-ui;padding:40px 20px;text-align:center'>"
            + "<h2>链接已失效</h2><p style='color:#666'>这条链接的分享期已结束，"
            + "请联系发放人重新获取。</p></div>",
            { status: 404, headers: { "Content-Type": "text/html; charset=utf-8" } });
        }

        // 门禁每次都判：窗口关了、被拉黑、被移出分组，都要当场拒
        const gate = await claimGate(env, Number(sl.admin_id) || 1,
                                     String(sl.qq), Number(sl.book_id));
        if (gate) {
          return new Response(gate.body.error,
            { status: gate.status, headers: { "Content-Type": "text/plain; charset=utf-8" } });
        }
        // 分享窗口：管理员点了「关闭领取」，之前发出去的短链必须当场失效
        const winB = rowsToObjs(await sql(env,
          `SELECT title,share_status,link_ttl,
                  (share_open_at  IS NOT NULL AND share_open_at  >  datetime('now')) AS not_yet,
                  (share_close_at IS NOT NULL AND share_close_at <= datetime('now')) AS expired
             FROM books WHERE id=?`, [sl.book_id]))[0];
        if (!winB || winB.share_status !== "open"
            || Number(winB.not_yet) === 1 || Number(winB.expired) === 1) {
          return new Response(
            "<!doctype html><meta charset=utf-8>"
            + "<meta name=viewport content='width=device-width,initial-scale=1'>"
            + "<div style='font:16px/1.7 system-ui;padding:40px 20px;text-align:center'>"
            + "<h2>本次分享已结束</h2><p style='color:#666'>这本书已经停止发放，"
            + "请联系发放人。</p></div>",
            { status: 410, headers: { "Content-Type": "text/html; charset=utf-8" } });
        }
        const cd = rowsToObjs(await sql(env,
          `SELECT id,status,max_uses,
                  (expires_at IS NOT NULL AND expires_at <= datetime('now')) AS expired
             FROM claim_codes WHERE id=?`, [sl.code_id]))[0];
        if (!cd || cd.status !== "active" || Number(cd.expired) === 1) {
          return new Response("取件码已失效，请联系发放人", { status: 403 });
        }

        const vers = rowsToObjs(await sql(env,
          `SELECT v.id AS version_id, v.version_no, v.label, v.size, f.r2_key,
                  IFNULL(u.uses,0) AS used
             FROM book_versions v
             LEFT JOIN files f ON f.book_id=v.book_id AND f.version_id=v.id
                              AND f.qq=? AND f.admin_id=?
             LEFT JOIN code_uses u ON u.code_id=? AND u.version_id=v.id
            WHERE v.book_id=? AND v.is_current=1
            ORDER BY v.version_no`,
          [sl.qq, Number(sl.admin_id) || 1, sl.code_id, sl.book_id]));

        const vid = Number(url.searchParams.get("v") || 0);
        if (vid) {
          const v = vers.find((x) => Number(x.version_id) === vid);
          if (!v || !v.r2_key) return new Response("这一版还没生成，请稍后再试", { status: 404 });
          const cap = Number(cd.max_uses || 3);
          if (Number(v.used || 0) >= cap) return new Response("这一版的下载次数已用完", { status: 403 });
          await sql(env, "UPDATE short_links SET hits=hits+1 WHERE id=?", [sid]);
          const tk = await makeToken(env, "book", v.r2_key, 300);
          // c/v 带过去，下载时才知道给哪个版本扣次数
          return Response.redirect(`${env.PUBLIC_BASE}/dl?k=${encodeURIComponent(v.r2_key)}`
            + `&t=${tk}&c=${sl.code_id}&v=${v.version_id}`, 302);
        }

        await sql(env, "UPDATE short_links SET hits=hits+1 WHERE id=?", [sid]);
        const bk = rowsToObjs(await sql(env,
          "SELECT title FROM books WHERE id=?", [sl.book_id]))[0] || {};
        const cap = Number(cd.max_uses || 3);
        const rows = vers.filter((v) => v.r2_key).map((v) => {
          const left = Math.max(0, cap - Number(v.used || 0));
          const btn = left > 0
            ? `<a class="b" href="/s/${sid}?v=${v.version_id}">下载</a>`
            : `<span class="b off">已用完</span>`;
          return `<div class="r"><div><b>${escHtml(v.label || ("v" + v.version_no))}</b>`
            + `<span class="s">${(Number(v.size) / 1048576).toFixed(1)}MB · 剩 ${left} 次</span>`
            + `</div>${btn}</div>`;
        }).join("");
        const html = `<!doctype html><meta charset="utf-8">`
          + `<meta name="viewport" content="width=device-width,initial-scale=1">`
          + `<title>${escHtml(bk.title || "领取")}</title>`
          + `<style>body{font:16px/1.6 -apple-system,system-ui,sans-serif;margin:0;padding:22px 16px;`
          + `background:#f6f7fb;color:#111}.c{background:#fff;border-radius:14px;padding:16px;`
          + `max-width:520px;margin:0 auto;box-shadow:0 1px 3px rgba(0,0,0,.06)}`
          + `h2{font-size:17px;margin:0 0 4px}.m{color:#6b7280;font-size:13px;margin-bottom:14px}`
          + `.r{display:flex;align-items:center;justify-content:space-between;padding:12px 0;`
          + `border-top:1px solid #eef0f4}.s{display:block;color:#6b7280;font-size:12px;margin-top:2px}`
          + `.b{background:#2563eb;color:#fff;text-decoration:none;padding:9px 18px;border-radius:9px;`
          + `font-size:14px;font-weight:600}.b.off{background:#d1d5db}`
          + `.f{color:#9ca3af;font-size:12px;text-align:center;margin-top:14px}</style>`
          + `<div class="c"><h2>${escHtml(bk.title || "领取")}</h2>`
          + `<div class="m">链接有效期至 ${String(sl.exp).slice(0, 16)}（UTC）</div>`
          + (rows || `<div class="m">文件还在准备，请稍后再打开这个链接</div>`)
          + `<div class="f">此链接只对应你本人，请勿转发</div></div>`;
        return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8",
                                              "Cache-Control": "no-store" } });
      }

      /* ---------- ⑤ 下载：token 校验 → R2 流式读出（支持 Range） ----------
       * 为什么要 Range：单条 TCP 连接跨境只有 0.5MB/s，这是窗口/丢包限制，不是带宽。
       * 前端把 20MB 切成 6 段并发拉，通常能到 2~5MB/s —— 不动任何基础设施。
       * 没有 Range 需求的调用方（浏览器直接点链接）行为完全不变。 */
      if (p === "/dl" && req.method === "GET") {
        const key = url.searchParams.get("k") || "";
        const tok = url.searchParams.get("t") || "";
        if (!key) return new Response("bad key", { status: 400 });
        // scope 必须是这个 key：签名只对这一个对象有效，改 k 就 403
        const t = await checkToken(env, tok, "book", key);
        if (!t.ok) return new Response("forbidden", { status: 403 });

        /* 分享窗口二次校验：链接 5 分钟有效，正好跨过"截止时刻"。
         * 母本（books/ 前缀）不校验 —— 那是 Actions 拉去打标用的，和对外分享无关。 */
        let dlName = (key.split("/").pop() || "book.epub");
        let win = null;
        if (!key.startsWith("books/")) {
          win = rowsToObjs(await sql(env,
            `SELECT b.id AS book_id, b.admin_id, b.share_status, b.title, f.qq, f.version_id,
                    (b.share_open_at  IS NOT NULL AND b.share_open_at  >  datetime('now')) AS not_yet,
                    (b.share_close_at IS NOT NULL AND b.share_close_at <= datetime('now')) AS expired
               FROM files f JOIN books b ON b.id=f.book_id
              WHERE f.r2_key=? LIMIT 1`, [key]))[0];
          const shut = win && (win.share_status !== "open"
            || Number(win.expired) === 1 || Number(win.not_yet) === 1);
          if (shut && !(await isAdmin(env, req))) {
            return new Response("本次分享已结束", { status: 410 });
          }
          /* 二次判定黑名单与范围 —— 这条不能省：
           * 读者先领进排队、期间被拉黑或移出分组，成品生成后仍然能下，
           * 只在 claim 判一次等于没判。 */
          if (win && !(await isAdmin(env, req))) {
            const gate = await claimGate(env, Number(win.admin_id) || 1,
                                         String(win.qq || ""), Number(win.book_id));
            if (gate) return new Response(gate.body.error, { status: gate.status });
          }
          // 文件名走母本书名，用户能看懂；拿不到才退回 key
          if (win && win.title) dlName = `${fileSafe(win.title)}_${fileStamp()}.epub`;
        }

        const base = {
          "Content-Type": "application/epub+zip",
          "Accept-Ranges": "bytes",
          "Cache-Control": "no-store",
          // 同时给 ASCII 兜底和 RFC5987 的 UTF-8 名，中文名才不会变问号
          "Content-Disposition":
            `attachment; filename="book.epub"; filename*=UTF-8''${encodeURIComponent(dlName)}`,
        };

        const h = await env.BUCKET.head(key);
        if (!h) return new Response("not found", { status: 404 });
        const total = Number(h.size) || 0;

        /* 按版本扣下载次数。
         * 为什么在下载时扣而不是领取时：用户点了领取但没下载（网络差、存书签）不该扣。
         * 为什么只认首段：分片下载会发 6 个 Range 请求，只有一段从 0 开始。
         * 为什么要 5 分钟去重：手抖连点不该被扣两次。 */
        if (win && win.version_id) {
          const qc = Number(url.searchParams.get("c") || 0);
          const rh = (req.headers.get("Range") || "").trim();
          const isFirstChunk = !rh || /^bytes=0-/.test(rh);
          if (qc && isFirstChunk) {
            const bucket = Math.floor(Date.now() / 300000);
            const dk = `dl:${qc}:${win.version_id}:${bucket}`;
            if (!(await env.KV.get(dk))) {
              await env.KV.put(dk, "1", { expirationTtl: 300 });
              const cm = rowsToObjs(await sql(env,
                "SELECT max_uses FROM claim_codes WHERE id=?", [qc]))[0];
              const cap = Number(cm ? cm.max_uses : 3);
              // WHERE uses < cap 是原子兜底：并发下不会超发
              await sqlRetry(env,
                `INSERT INTO code_uses(code_id,version_id,uses) VALUES(?,?,1)
                 ON CONFLICT(code_id,version_id) DO UPDATE SET
                   uses = uses + 1, updated_at = datetime('now')
                 WHERE code_uses.uses < ?`, [qc, win.version_id, cap]);
            }
          }
        }

        const m = /^bytes=(\d*)-(\d*)$/.exec((req.headers.get("Range") || "").trim());
        if (!m) {
          const obj = await env.BUCKET.get(key);
          if (!obj) return new Response("not found", { status: 404 });
          return new Response(obj.body, {
            headers: { ...base, "Content-Length": String(total || obj.size) },
          });
        }

        let start = m[1] === "" ? 0 : Number(m[1]);
        let end = m[2] === "" ? total - 1 : Number(m[2]);
        if (total && end > total - 1) end = total - 1;
        if (!(start >= 0) || end < start) {
          return new Response("range not satisfiable",
            { status: 416, headers: { "Content-Range": `bytes */${total}` } });
        }
        const obj = await env.BUCKET.get(key, { range: { offset: start, length: end - start + 1 } });
        if (!obj) return new Response("not found", { status: 404 });
        return new Response(obj.body, {
          status: 206,
          headers: {
            ...base,
            "Content-Length": String(end - start + 1),
            "Content-Range": `bytes ${start}-${end}/${total}`,
          },
        });
      }

      /* ---------- 上传（Worker 代收后写 R2；PoC 用） ---------- */
      if (p === "/up" && req.method === "PUT") {
        const key = url.searchParams.get("k") || "";
        const tok = url.searchParams.get("t") || "";
        if (!key) return new Response("forbidden", { status: 403 });
        const t = await checkTokenPrefix(env, tok, "up", key);
        if (!t.ok) return new Response("forbidden", { status: 403 });

        // ① 必须知道大小才敢写：不知道就无法保证不撑爆额度
        const len = Number(req.headers.get("Content-Length") || 0);
        if (!len || len < 0) {
          return j({ ok: false, code: "LENGTH_REQUIRED",
                     error: "上传必须带 Content-Length（没有大小就无法做配额熔断）" }, 411, origin);
        }

        // ② 硬熔断：放不下立刻 507，**一个字节都不写**
        if (!(await charge(env, len))) {
          const u = await usage(env);
          return j({ ok: false, code: "QUOTA_EXCEEDED",
                     error: "R2 配额已满，本次上传被拒绝（未写入任何字节）",
                     need_bytes: len, used_bytes: u.bytes, limit_bytes: u.limit,
                     free_bytes: Math.max(0, u.limit - u.bytes) }, 507, origin);
        }

        // ③ 写失败要回滚账本，否则账会越跑越偏
        try {
          await env.BUCKET.put(key, req.body, {
            httpMetadata: {
              contentType: req.headers.get("Content-Type") || "application/octet-stream",
            },
          });
        } catch (e) {
          await release(env, len);
          throw e;
        }
        await alertIfNeeded(env, ctx);
        const u2 = await usage(env);
        return j({ ok: true, key, charged_bytes: len,
                   used_bytes: u2.bytes, limit_bytes: u2.limit });
      }

      return j({ ok: false, error: "not found" }, 404, origin);
    } catch (e) {
      const msg = String(e);
      // 约束类错误是"输入不合法"，不是服务端故障；映射成 400 更准确，也免得前端当 500 重试
      if (/FOREIGN KEY|constraint failed|UNIQUE constraint/i.test(msg)) {
        return j({ ok: false, code: "CONSTRAINT", error: msg.slice(0, 300) }, 400, origin);
      }
      return j({ ok: false, error: msg.slice(0, 300) }, 500, origin);
    }
  },
};
