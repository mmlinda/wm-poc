/**
 * local_run.mjs —— 在没有 Cloudflare / Turso / GitHub 账号的情况下，把 Worker 的
 * 5 个核心接口 + 领取"秒下"链路完整跑一遍。
 *
 * 它替掉的东西：
 *   - Turso      → poc/mock_turso.py（真 SQLite，跑的是同一份 schema.sql）
 *   - R2         → 内存 Map（get/put 语义一致）
 *   - KV         → 内存 Map（nonce 防重放照样生效）
 *   - GitHub API → 拦住 api.github.com，记下 dispatch 的 inputs 并回 204
 *
 * 因此它验的是"我们的逻辑对不对"，验不了"平台快不快"（t_ready 必须真跑 Actions 才有）。
 *
 * 用法： node poc/local_run.mjs http://127.0.0.1:8788
 */
import { default as worker, makeToken } from "./worker_poc.js";

const TURSO = process.argv[2] || "http://127.0.0.1:8788";
const t0 = Date.now();
const ms = (x) => Math.round(x);

/* ---------------- 假 R2 / KV ---------------- */
const bucket = new Map();
const kv = new Map();

const BUCKET = {
  async get(key) {
    const v = bucket.get(key);
    if (!v) return null;
    return { body: v.bytes, size: v.bytes.byteLength };
  },
  async put(key, body) {
    const buf = body instanceof ReadableStream
      ? new Uint8Array(await new Response(body).arrayBuffer())
      : body instanceof Uint8Array ? body : new Uint8Array(await new Response(body).arrayBuffer());
    bucket.set(key, { bytes: buf });
    return { key, size: buf.byteLength };
  },
};
const KV = {
  async get(k) { return kv.get(k) ?? null; },
  async put(k, v) { kv.set(k, v); },
};

const env = {
  TURSO_URL: TURSO,
  TURSO_TOKEN: "local-fake",
  BUCKET, KV,
  GH_PAT: "ghp_fake_for_local_run",
  GH_REPO: "owner/repo",
  WF_FILE: "watermark_poc.yml",
  GH_REF: "main",
  CB_SECRET: "cb-secret-local",
  DL_SECRET: "dl-secret-local",
  PUBLIC_BASE: "https://poc.local",
  POC_SERVER_SECRET: "a".repeat(64),
  POC_DB_KEY: "b".repeat(48),
};

/* ---------------- 拦 GitHub dispatch ---------------- */
let lastDispatch = null;
const realFetch = globalThis.fetch;
globalThis.fetch = async (input, init) => {
  const u = typeof input === "string" ? input : input.url;
  if (u.startsWith("https://api.github.com/")) {
    lastDispatch = { url: u, body: JSON.parse(init?.body || "{}") };
    return new Response(null, { status: 204 });
  }
  return realFetch(input, init);
};

/* ---------------- 小工具 ---------------- */
async function call(method, path, body, headers = {}) {
  const req = new Request("https://poc.local" + path, {
    method,
    headers: { ...(body ? { "Content-Type": "application/json" } : {}), ...headers },
    body: body ? JSON.stringify(body) : undefined,
  });
  const t = performance.now();
  const res = await worker.fetch(req, env);
  const msEl = performance.now() - t;
  let data = null;
  const ct = res.headers.get("content-type") || "";
  if (ct.includes("json")) data = await res.json();
  else data = { _bytes: (await res.arrayBuffer()).byteLength, _ct: ct };
  return { status: res.status, data, ms: msEl, headers: res.headers };
}

const rows = [];
function rec(name, ok, msEl, note) {
  rows.push({ name, ok, ms: msEl === undefined ? "" : ms(msEl), note });
  console.log(`${ok ? "✔" : "✘"} ${name.padEnd(42)} ${msEl === undefined ? "" : ms(msEl) + "ms"}  ${note || ""}`);
}
const assert = (cond, msg) => { if (!cond) throw new Error("断言失败：" + msg); };

/* ---------------- 准备数据（直接写 mock Turso 的 SQLite） ---------------- */
async function bootSql(q, args = []) {
  const r = await realFetch(TURSO + "/v2/pipeline", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: "Bearer x" },
    body: JSON.stringify({ requests: [{ type: "execute", stmt: { sql: q, args } }, { type: "close" }] }),
  });
  const d = await r.json();
  const first = d.results?.[0];
  if (first?.type === "error") throw new Error(first.error.message);
  return d;
}

console.log("== 本地闭环（mock Turso + 假 R2/GitHub）==");

// 母本对象 + books 行 + 3 个名单
const mother = new Uint8Array(153000);
bucket.set("books/1/1.epub", { bytes: mother });
await bootSql("INSERT OR REPLACE INTO books(id,admin_id,title,r2_key,size) VALUES(1,1,'PoC书','books/1/1.epub',153000)");
await bootSql("DELETE FROM recipients");
for (const qq of ["123450001", "123450002", "123450003"]) {
  await bootSql("INSERT OR REPLACE INTO recipients(admin_id,group_id,qq,email) VALUES(1,NULL,?,?)",
    [{ type: "text", value: qq }, { type: "text", value: qq + "@qq.com" }]);
}

/* ---------------- ① 建批次 ---------------- */
let r = await call("POST", "/api/wm/jobs", { qqs: ["123450001", "123450002", "123450003"], book_id: 1 });
assert(r.status === 200 && r.data.batch_id, "建批次");
const batchId = r.data.batch_id;
rec("① 建批次（Turso insert + dispatch）", true, r.ms, `total=${r.data.total}`);
assert(lastDispatch && lastDispatch.body.inputs.batch_id === batchId, "dispatch 参数");
rec("   dispatch inputs 是否干净", !JSON.stringify(lastDispatch.body.inputs).includes("12345000"),
  undefined, JSON.stringify(lastDispatch.body.inputs).slice(0, 80));

/* ---------------- ② 查状态 ---------------- */
r = await call("GET", "/api/wm/batches/" + batchId);
assert(r.status === 200 && r.data.status === "queued", "状态 queued");
rec("② 查状态（主键查 1 行）", true, r.ms, `status=${r.data.status} done=${r.data.done}/${r.data.total}`);
assert(r.headers.get("cache-control") === "no-store", "no-store");

/* 轮询延迟采样（模拟前端每 2s 一次，这里连打 20 次取 p50） */
const lat = [];
for (let i = 0; i < 20; i++) {
  const x = await call("GET", "/api/wm/batches/" + batchId);
  lat.push(x.ms);
}
lat.sort((a, b) => a - b);
rec("   轮询接口延迟 p50 / p95", true, lat[10], `p95=${ms(lat[18])}ms（含本地 HTTP 开销）`);

/* ---------------- ③ Actions 领任务 ---------------- */
const cb = lastDispatch.body.inputs.cb;
r = await call("POST", "/internal/batch/" + batchId, null, { "X-Act-Token": cb });
assert(r.status === 200 && r.data.qqs.length === 3, "领任务");
rec("③ Actions 领任务", true, r.ms, `qqs=${r.data.qqs.length} 母本URL/上传URL 都已签发`);
const spec = r.data;

r = await call("POST", "/internal/batch/" + batchId, null, { "X-Act-Token": cb });
rec("   token 单次可用（重放应 409）", r.status === 409, undefined, `HTTP ${r.status}`);

r = await call("POST", "/internal/batch/" + batchId, null, { "X-Act-Token": "bad.token" });
rec("   伪造 token（应 401）", r.status === 401, undefined, `HTTP ${r.status}`);

/* ---------------- ④ 母本下载 / 成品上传 / 回调 ---------------- */
r = await call("GET", spec.mother_url.replace("https://poc.local", ""));
rec("   母本下载（token → R2 流）", r.status === 200 && r.data._bytes === 153000, r.ms,
  `${r.data._bytes} bytes`);

const upPath = spec.upload_url.replace("https://poc.local", "");
const upReq = new Request("https://poc.local" + upPath, { method: "PUT", body: new Uint8Array(120000) });
let t = performance.now();
let upRes = await worker.fetch(upReq, env);
rec("   成品上传（PUT → R2）", upRes.status === 200, performance.now() - t, `HTTP ${upRes.status}`);

r = await call("POST", "/internal/callback",
  { batch_id: batchId, status: "done", watermark_id: "WM-POC0000001-AAAAAA", qq: "123450001" },
  { "X-Act-Token": cb });
assert(r.status === 200 && r.data.ok, "回调");
rec("④ 回调（写 wm_mapping + files）", true, r.ms);

r = await call("POST", "/internal/callback",
  { batch_id: batchId, status: "done", watermark_id: "WM-POC0000001-AAAAAA", qq: "123450001" },
  { "X-Act-Token": cb });
rec("   重复回调幂等", r.data?.idempotent === true, r.ms, `idempotent=${r.data?.idempotent}`);

r = await call("GET", "/api/wm/batches/" + batchId);
rec("   状态流转到 done", r.data.status === "done", r.ms, `done=${r.data.done}/${r.data.total}`);

/* ---------------- ⑤ 领取：预生成 → 秒下 ---------------- */
r = await call("POST", "/api/claim", { qq: "123450001", book_id: 1 });
assert(r.status === 200 && r.data.ready === true && r.data.mode === "instant", "命中秒下");
const instantMs = r.ms;
rec("⑤ 领取（命中 → 即点即下）", true, instantMs, `url 已签发，未触发 Actions`);

r = await call("GET", r.data.url.replace("https://poc.local", ""));
rec("   下载（token → R2）", r.status === 200, r.ms, `${r.data._bytes} bytes`);

/* token 过期 / 篡改 */
const expired = await makeToken(env, "book", "", -10);
r = await call("GET", "/dl?k=books%2F1%2F1.epub&t=" + expired);
rec("   过期 token（应 403）", r.status === 403, undefined, `HTTP ${r.status}`);
r = await call("GET", "/dl?k=books%2F1%2F1.epub&t=deadbeef.deadbeef");
rec("   篡改 token（应 403）", r.status === 403, undefined, `HTTP ${r.status}`);

/* 未命中 → 排队（另一本书，没生成过） */
await bootSql("INSERT OR REPLACE INTO books(id,admin_id,title,r2_key,size) VALUES(2,1,'PoC书2','books/1/1.epub',153000)");
r = await call("POST", "/api/claim", { qq: "123450001", book_id: 2 });
rec("   未命中 → 排队（ready:false）", r.data.ready === false && r.data.batch_id, r.ms,
  `mode=${r.data.mode} eta=${r.data.eta}s`);

/* ---------------- 汇总 ---------------- */
const bad = rows.filter((x) => !x.ok);
console.log(`\n==== ${rows.length} 项检查：通过 ${rows.length - bad.length}，失败 ${bad.length} ====`);
console.log(`总耗时 ${ms(Date.now() - t0)}ms`);
console.log(`\n核心数字（本地，不含云网络）：`);
console.log(`  · 建批次+dispatch  ${ms(rows[0].ms)}ms`);
console.log(`  · 轮询 p50         ${ms(lat[10])}ms`);
console.log(`  · **领取秒下**      ${ms(instantMs)}ms   ← CTO 要的"零排队"就是这个数`);
if (bad.length) { console.log("\n失败项：", bad); process.exit(1); }
