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
async function dispatch(env, batchId, cbToken) {
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
        inputs: { batch_id: batchId, cb: cbToken, worker: env.PUBLIC_BASE },
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
        await sql(env,
          `INSERT INTO batches(id,admin_id,book_id,group_id,total,status)
           VALUES(?,?,?,?,?,'queued')`,
          [batchId, adminId, b.book_id || 1, b.group_id || null, qqs.length]);
        const cb = await makeToken(env, "act", batchId, 900);
        const d = await dispatch(env, batchId, cb);
        if (!d.ok) {
          await sql(env, `UPDATE batches SET status='failed',reason=? WHERE id=?`,
            [`dispatch ${d.status}`, batchId]);
          return j({ ok: false, error: "触发 Actions 失败", detail: d }, 502, origin);
        }
        return j({ ok: true, batch_id: batchId, total: qqs.length }, 200, origin);
      }

      /* ---------- ② 轮询：只查主键、只回 3 个字段 ---------- */
      if (p.startsWith("/api/wm/batches/") && req.method === "GET") {
        const id = p.split("/").pop();
        const rs = rowsToObjs(await sql(env,
          "SELECT status,done,total FROM batches WHERE id=?", [id]));
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
          "SELECT * FROM batches WHERE id=?", [id]))[0];
        if (!bs) return j({ ok: false, error: "batch not found" }, 404);
        const bk = rowsToObjs(await sql(env,
          "SELECT r2_key FROM books WHERE id=?", [bs.book_id]))[0];
        const recs = rowsToObjs(await sql(env,
          "SELECT qq FROM recipients WHERE admin_id=? AND status!='banned' LIMIT 20",
          [bs.admin_id]));

        await sql(env, "UPDATE batches SET status='running',updated_at=datetime('now') WHERE id=?", [id]);

        return j({
          batch_id: id,
          qqs: recs.map((r) => r.qq),
          // token 的 scope 用空批次串；生产可换成"按对象 key"签名，更细
          mother_url: `${env.PUBLIC_BASE}/dl?k=${encodeURIComponent(bk.r2_key)}&t=${await makeToken(env, "book", "", 900)}`,
          upload_url: `${env.PUBLIC_BASE}/up?k=${encodeURIComponent("out/" + id + ".epub")}&t=${await makeToken(env, "up", "", 900)}`,
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
          "SELECT status,done,total FROM batches WHERE id=?", [b.batch_id]))[0];
        if (!cur) return j({ ok: false, error: "batch not found" }, 404);
        if (cur.status === "done") return j({ ok: true, idempotent: true });   // 重复回调只认第一次

        if (b.watermark_id) {
          await sql(env,
            `INSERT INTO wm_mapping(watermark_id,admin_id,qq,book_id,batch_id)
             SELECT ?,admin_id,?,book_id,id FROM batches WHERE id=?
             ON CONFLICT(watermark_id) DO NOTHING`,
            [b.watermark_id, (b.qq || ""), b.batch_id]);
        }
        // 成品登记：下次同一个人领取才能"即点即下"（预生成的核心）
        if (b.status === "done" && b.qq) {
          const b2 = rowsToObjs(await sql(env,
            "SELECT admin_id,book_id FROM batches WHERE id=?", [b.batch_id]))[0];
          await sql(env,
            `INSERT INTO files(admin_id,qq,book_id,batch_id,r2_key,token,watermark_id)
             VALUES(?,?,?,?,?,?,?)
             ON CONFLICT(admin_id,qq,book_id) DO UPDATE SET
               r2_key=excluded.r2_key, batch_id=excluded.batch_id,
               watermark_id=excluded.watermark_id`,
            [b2.admin_id, b.qq, b2.book_id, b.batch_id,
             `out/${b.batch_id}.epub`, crypto.randomUUID(), b.watermark_id]);
        }
        await sql(env,
          `UPDATE batches SET status=?,done=done+?,failed=failed+?,reason=?,updated_at=datetime('now')
           WHERE id=?`,
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
          const t = await makeToken(env, "book", "", 300);
          const url = `${env.PUBLIC_BASE}/dl?k=${encodeURIComponent(hit.r2_key)}&t=${t}`;
          return j({ ok: true, ready: true, url, eta: 0, mode: "instant" }, 200, origin);
        }

        // 没命中：建 1 本批次 + 触发，返回 task 让前端轮询
        const batchId = crypto.randomUUID();
        await sql(env,
          `INSERT INTO batches(id,admin_id,book_id,total,status) VALUES(?,?,?,1,'queued')`,
          [batchId, adminId, bookId]);
        const cb = await makeToken(env, "act", batchId, 900);
        const d = await dispatch(env, batchId, cb);
        if (!d.ok) {
          await sql(env, `UPDATE batches SET status='failed',reason=? WHERE id=?`,
            [`dispatch ${d.status}`, batchId]);
          return j({ ok: false, error: "触发失败" }, 502, origin);
        }
        return j({ ok: true, ready: false, batch_id: batchId, eta: 180, mode: "queued" }, 202, origin);
      }

      /* ---------- ⑤ 下载：token 校验 → R2 流式读出 ---------- */
      if (p === "/dl" && req.method === "GET") {
        const key = url.searchParams.get("k") || "";
        const tok = url.searchParams.get("t") || "";
        if (!key) return new Response("bad key", { status: 400 });
        const t = await checkToken(env, tok, "book", "");
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
        const t = await checkToken(env, tok, "up", "");
        if (!t.ok || !key) return new Response("forbidden", { status: 403 });
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
