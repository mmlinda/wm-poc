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
  ALLOW_INJECT: "1",          // 只有本地/测试才开；生产不设这个变量
  WATCHDOG_TOKEN: "wd-local",
  DL_TTL: "300",
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
const expired = await makeToken(env, "book", "books/1/1.epub", -10);
r = await call("GET", "/dl?k=books%2F1%2F1.epub&t=" + expired);
rec("   过期 token（应 403）", r.status === 403, undefined, `HTTP ${r.status}`);
r = await call("GET", "/dl?k=books%2F1%2F1.epub&t=deadbeef.deadbeef");
rec("   篡改 token（应 403）", r.status === 403, undefined, `HTTP ${r.status}`);

/* 串号：拿"下载母本"的合法 token 去下成品，应 403（token 绑定对象 key） */
const motherTok = spec.mother_url.split("t=")[1];
r = await call("GET", "/dl?k=out%2F" + batchId + ".epub&t=" + motherTok);
rec("   token 换 key 串号（应 403）", r.status === 403, undefined, `HTTP ${r.status}`);

/* 未命中 → 排队（另一本书，没生成过） */
await bootSql("INSERT OR REPLACE INTO books(id,admin_id,title,r2_key,size) VALUES(2,1,'PoC书2','books/1/1.epub',153000)");
r = await call("POST", "/api/claim", { qq: "123450001", book_id: 2 });
rec("   未命中 → 排队（ready:false）", r.data.ready === false && r.data.batch_id, r.ms,
  `mode=${r.data.mode} eta=${r.data.eta}s`);

/* ---------------- ⑥ 三时间戳（QA 预案 §二.3 的硬依赖） ---------------- */
r = await call("GET", "/api/wm/batches/" + batchId);
const bRow = r.data;
rec("⑥ 轮询带回三时间戳", !!(bRow.queued_at && bRow.started_at && bRow.finished_at),
  undefined, `queued=${bRow.queued_at} started=${bRow.started_at} finished=${bRow.finished_at}`);
rec("   started_at >= queued_at（排队时长可算）",
  String(bRow.started_at) >= String(bRow.queued_at), undefined, "");

/* ---------------- ⑦ 终态不可变（非法边 done→failed） ---------------- */
r = await call("POST", "/internal/callback",
  { batch_id: batchId, status: "failed", reason: "恶意回跳" }, { "X-Act-Token": cb });
r = await call("GET", "/api/wm/batches/" + batchId);
rec("⑦ 终态不可回跳（done 收到 failed 回调仍是 done）", r.data.status === "done",
  undefined, `status=${r.data.status}`);

/* ---------------- ⑧ 领取幂等：连点 5 次只建 1 个批次 ---------------- */
await bootSql("INSERT OR REPLACE INTO books(id,admin_id,title,r2_key,size) VALUES(3,1,'PoC书3','books/1/1.epub',153000)");
r = await call("POST", "/api/claim", { qq: "123450009", book_id: 3 });
const firstId = r.data.batch_id;
let sameId = true;
for (let i = 0; i < 4; i++) {
  const x = await call("POST", "/api/claim", { qq: "123450009", book_id: 3 });
  if (x.data.batch_id !== firstId) sameId = false;
}
const inflight = await bootSql(
  "SELECT count(*) c FROM wm_batches WHERE dedup_key='u:1:123450009:3' AND status IN ('queued','running')");
const nInflight = Number(inflight.results?.[0]?.response?.result?.rows?.[0]?.[0]?.value ?? -1);
rec("⑧ 领取幂等（连点 5 次 → 同一 batch_id 且库里只 1 条在飞）",
  sameId && nInflight === 1, undefined, `batch=${firstId.slice(0, 8)}… 在飞=${nInflight}`);

/* ---------------- ⑨ 故障注入：turso_fail（模拟写库失败） ---------------- */
const failBatch = "b-fail-" + Date.now();
await bootSql("INSERT INTO wm_batches(id,admin_id,book_id,total,status,queued_at,updated_at) "
  + "VALUES(?,1,1,1,'running',datetime('now'),datetime('now'))",
  [{ type: "text", value: failBatch }]);
const cb2 = await makeToken(env, "act", failBatch, 900);
r = await call("POST", "/internal/callback",
  { batch_id: failBatch, status: "done", simulate: "turso_fail" }, { "X-Act-Token": cb2 });
rec("⑨ 注入写库失败 → 回调 500（不是假装成功）", r.status === 500, undefined, `HTTP ${r.status}`);
const after = await bootSql("SELECT status FROM wm_batches WHERE id=?",
  [{ type: "text", value: failBatch }]);
const stAfter = after.results?.[0]?.response?.result?.rows?.[0]?.[0]?.value;
rec("   写库失败后状态不得变成 done", stAfter !== "done", undefined, `status=${stAfter}`);

/* ---------------- ⑩ 看门狗：把卡死的批次收敛成 failed ---------------- */
await bootSql("UPDATE wm_batches SET updated_at=datetime('now','-2 hours') WHERE id=?",
  [{ type: "text", value: failBatch }]);
r = await call("POST", "/internal/watchdog", { minutes: 1 },
  { "X-Watchdog-Token": "wd-local" });
rec("⑩ 看门狗（无 token 应 403）",
  (await call("POST", "/internal/watchdog", { minutes: 1 })).status === 403,
  undefined, "另一个请求验的");
rec("   看门狗收敛僵尸批次", r.status === 200 && r.data.killed >= 1, r.ms,
  `killed=${r.data.killed}`);
const fin = await bootSql("SELECT status,finished_at FROM wm_batches WHERE id=?",
  [{ type: "text", value: failBatch }]);
const frow = fin.results?.[0]?.response?.result?.rows?.[0] || [];
rec("   收敛后是 failed 且 finished_at 有值",
  frow[0]?.value === "failed" && !!frow[1]?.value, undefined,
  `${frow[0]?.value} / ${frow[1]?.value}`);

/* ---------------- 汇总 ---------------- */
const bad = rows.filter((x) => !x.ok);
console.log(`\n==== ${rows.length} 项检查：通过 ${rows.length - bad.length}，失败 ${bad.length} ====`);
console.log(`总耗时 ${ms(Date.now() - t0)}ms`);
console.log(`\n核心数字（本地，不含云网络）：`);
console.log(`  · 建批次+dispatch  ${ms(rows[0].ms)}ms`);
console.log(`  · 轮询 p50         ${ms(lat[10])}ms`);
console.log(`  · **领取秒下**      ${ms(instantMs)}ms   ← CTO 要的"零排队"就是这个数`);
if (bad.length) { console.log("\n失败项：", bad); process.exit(1); }
