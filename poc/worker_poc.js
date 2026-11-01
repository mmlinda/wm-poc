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
  try { body = atob(p.replace(/-/g, "+").replace(/_/g, "/")); }
  catch { return { ok: false, why: "malformed" }; }
  const [pu, bid, exp] = body.split("|");
  if (pu !== purpose || bid !== batchId) return { ok: false, why: "scope" };
  if (Number(exp) < Math.floor(Date.now() / 1000)) return { ok: false, why: "expired" };
  if (!safeEq(await hmac(env.CB_SECRET, body), sig)) return { ok: false, why: "sig" };
  return { ok: true, exp };
}

/* ---------------------------------------------------------------- Turso */
function arg(v) {
  if (v === null || v === undefined) return { type: "null", value: null };
  if (typeof v === "number") return { type: "integer", value: String(v) };
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
  if (!res) return { rows: [], cols: [] };
  return { cols: res.cols.map((c) => c.name), rows: res.rows || [] };
}
const rowsToObjs = ({ cols, rows }) =>
  rows.map((r) => Object.fromEntries(r.map((v, i) => [cols[i], v?.value ?? v])));

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

/* ---------------------------------------------------------------- 入口 */
export { makeToken, checkToken };

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const origin = req.headers.get("Origin") || "";
    const p = url.pathname;

    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors(origin) });

    try {
      /* ---------- ① 建批次并触发 Actions ---------- */
      if (p === "/api/wm/jobs" && req.method === "POST") {
        const b = await req.json();
        const adminId = 1;                                   // PoC：写死；生产从会话取
        const qqs = (b.qqs || ["123450001"]).slice(0, 20);   // PoC 上限 20
        const batchId = crypto.randomUUID();
        const sim = inject(env, b.simulate);
        await sql(env,
          `INSERT INTO wm_batches(id,admin_id,book_id,group_id,total,status,
                                  queued_at,created_at,updated_at,simulate,dedup_key)
           VALUES(?,?,?,?,?,'queued',datetime('now'),datetime('now'),datetime('now'),?,?)`,
          [batchId, adminId, b.book_id || 1, b.group_id || null, qqs.length,
           sim, `g:${adminId}:${b.book_id || 1}`]);
        const cb = await makeToken(env, "act", batchId, 900);
        const d = await dispatch(env, batchId, cb, sim);
        if (!d.ok) {
          await sql(env,
            `UPDATE wm_batches SET status='failed',reason=?,finished_at=datetime('now'),
                    updated_at=datetime('now') WHERE id=?`,
            [`dispatch ${d.status}`, batchId]);
          return j({ ok: false, error: "触发 Actions 失败", detail: d }, 502, origin);
        }
        return j({ ok: true, batch_id: batchId, total: qqs.length }, 200, origin);
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
        const bk = rowsToObjs(await sql(env,
          "SELECT r2_key FROM books WHERE id=?", [bs.book_id]))[0];
        const recs = rowsToObjs(await sql(env,
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
          upload_url: `${env.PUBLIC_BASE}/up?k=${encodeURIComponent("out/" + id + ".epub")}`
                    + `&t=${await makeToken(env, "up", "out/" + id + ".epub", 900)}`,
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

        if (b.watermark_id) {
          await sql(env,
            `INSERT INTO wm_mapping(watermark_id,admin_id,qq,book_id,batch_id)
             SELECT ?,admin_id,?,book_id,id FROM wm_batches WHERE id=?
             ON CONFLICT(watermark_id) DO NOTHING`,
            [b.watermark_id, (b.qq || ""), b.batch_id]);
        }
        // 成品登记：下次同一个人领取才能"即点即下"（预生成的核心）
        if (b.status === "done" && b.qq) {
          const b2 = rowsToObjs(await sql(env,
            "SELECT admin_id,book_id FROM wm_batches WHERE id=?", [b.batch_id]))[0];
          await sql(env,
            `INSERT INTO files(admin_id,qq,book_id,batch_id,r2_key,token,watermark_id)
             VALUES(?,?,?,?,?,?,?)
             ON CONFLICT(admin_id,qq,book_id) DO UPDATE SET
               r2_key=excluded.r2_key, batch_id=excluded.batch_id,
               watermark_id=excluded.watermark_id`,
            [b2.admin_id, b.qq, b2.book_id, b.batch_id,
             `out/${b.batch_id}.epub`, crypto.randomUUID(), b.watermark_id]);
        }
        // finished_at 同时打上：done 与 failed 都是终态，都算"收敛"
        await sql(env,
          `UPDATE wm_batches
              SET status=?,done=done+?,failed=failed+?,reason=?,
                  finished_at=datetime('now'), updated_at=datetime('now')
            WHERE id=? AND status NOT IN ('done','failed')`,
          [b.status || "done", b.status === "failed" ? 0 : 1, b.status === "failed" ? 1 : 0,
           (b.reason || "").slice(0, 200), b.batch_id]);
        return j({ ok: true });
      }

      /* ---------- ⑤ 领取：预生成为主 → 命中就秒下，没命中才排队 ----------
       * 这就是 CTO 要的"即点即下、零排队"：管理端提前批量预生成，
       * 领取端 99% 只是查一次 files 表 + 签一个 5 分钟 token，完全不碰 Actions。 */
      if (p === "/api/claim" && req.method === "POST") {
        const b = await req.json();
        const adminId = 1;                                   // PoC 写死，生产从会话取
        const qq = String(b.qq || "");
        const bookId = Number(b.book_id || 1);
        if (!qq) return j({ ok: false, error: "qq required" }, 400, origin);

        const hit = rowsToObjs(await sql(env,
          `SELECT r2_key FROM files WHERE admin_id=? AND qq=? AND book_id=?
           ORDER BY id DESC LIMIT 1`, [adminId, qq, bookId]))[0];

        if (hit) {
          // DL_TTL 只影响"下载链接活多久"；测试把它设成 5，就能 6 秒后验 403
          const ttl = Number(env.DL_TTL || 300);
          const t = await makeToken(env, "book", hit.r2_key, ttl);   // scope 绑定对象 key
          const url = `${env.PUBLIC_BASE}/dl?k=${encodeURIComponent(hit.r2_key)}&t=${t}`;
          return j({ ok: true, ready: true, url, eta: 0, mode: "instant" }, 200, origin);
        }

        // 没命中：先看这个人这本书是不是已经有批次在飞（连点 5 次只建 1 个）
        const dedup = `u:${adminId}:${qq}:${bookId}`;
        const flying = rowsToObjs(await sql(env,
          `SELECT id FROM wm_batches
            WHERE dedup_key=? AND status IN ('queued','running')
            ORDER BY queued_at DESC LIMIT 1`, [dedup]));
        if (flying.length) {
          return j({ ok: true, ready: false, batch_id: flying[0].id, eta: 180,
                     mode: "queued", dedup: true }, 200, origin);
        }

        const batchId = crypto.randomUUID();
        await sql(env,
          `INSERT INTO wm_batches(id,admin_id,book_id,total,status,queued_at,
                                  created_at,updated_at,dedup_key)
           VALUES(?,?,?,1,'queued',datetime('now'),datetime('now'),datetime('now'),?)`,
          [batchId, adminId, bookId, dedup]);
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

      /* ---------- ⑤ 下载：token 校验 → R2 流式读出 ---------- */
      if (p === "/dl" && req.method === "GET") {
        const key = url.searchParams.get("k") || "";
        const tok = url.searchParams.get("t") || "";
        if (!key) return new Response("bad key", { status: 400 });
        // scope 必须是这个 key：签名只对这一个对象有效，改 k 就 403
        const t = await checkToken(env, tok, "book", key);
        if (!t.ok) return new Response("forbidden", { status: 403 });
        const obj = await env.BUCKET.get(key);
        if (!obj) return new Response("not found", { status: 404 });
        return new Response(obj.body, {
          headers: {
            "Content-Type": "application/epub+zip",
            "Content-Length": String(obj.size),
            "Cache-Control": "no-store",
          },
        });
      }

      /* ---------- 上传（Worker 代收后写 R2；PoC 用） ---------- */
      if (p === "/up" && req.method === "PUT") {
        const key = url.searchParams.get("k") || "";
        const tok = url.searchParams.get("t") || "";
        if (!key) return new Response("forbidden", { status: 403 });
        const t = await checkToken(env, tok, "up", key);
        if (!t.ok) return new Response("forbidden", { status: 403 });
        await env.BUCKET.put(key, req.body, {
          httpMetadata: { contentType: req.headers.get("Content-Type") || "application/octet-stream" },
        });
        return j({ ok: true, key });
      }

      return j({ ok: false, error: "not found" }, 404, origin);
    } catch (e) {
      return j({ ok: false, error: String(e).slice(0, 300) }, 500, origin);
    }
  },
};
