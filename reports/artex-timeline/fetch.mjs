#!/usr/bin/env node
// ARTEX_TIMELINE — 2 つのクラスタの AbuseIPDB 写しを取る。**ここだけが外に出る。**
//
//   ABUSEIPDB_API_KEY="k" node fetch.mjs [--plan]
//
// ## やらないこと
//
// **対象 IP への接続・走査・認証試行は一切行わない。** ポートスキャンもしない。
// HTTP も叩かない。ping も打たない。AbuseIPDB の公開情報だけを見る。
// 相手は「ペンテスト用ツールが動いている」「sub2api がある」と言われているサーバで、
// こちらから触りに行く理由が無い。触れば観測ではなく関与になる。
//
// ## 窓は 365 日で取る
//
// 時系列を作りたいので**取れるだけ長く**取る。90 日で取ると、それより前の報告が
// 見えず「いつから使われ始めたか」が分からない。短い窓は写しから切り出せるが、
// 逆はできない。
//
// 鍵は環境変数からのみ読み、コンソール・ログ・CSV・JSON・ソース・エラーに出さない。
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CACHE = path.join(HERE, ".cache", "abuseipdb");
const CFG = JSON.parse(fs.readFileSync(path.join(HERE, "config.json"), "utf8"));
const PLAN = process.argv.includes("--plan");

/** 対象の組み立て。クラスタ名を一緒に持つ */
export const targets = [];
for (const cl of CFG.CLUSTERS) {
  if (cl.explicit) for (const ip of cl.explicit) targets.push({ ip, cluster: cl.name });
  if (cl.ranges) {
    for (const r of cl.ranges) {
      const base = r.split("/")[0].split(".").slice(0, 3).join(".");
      for (let i = cl.host_range[0]; i <= cl.host_range[1]; i++) {
        targets.push({ ip: `${base}.${i}`, cluster: cl.name });
      }
    }
  }
}
const sha = (s) => crypto.createHash("sha256").update(s).digest("hex");
const slot = (ip) => {
  const h = sha("abuseipdb|" + ip);
  return path.join(CACHE, h.slice(0, 2), `${h}.json`);
};
const need = targets.filter((t) => !fs.existsSync(slot(t.ip)));
const byCluster = {};
for (const t of targets) byCluster[t.cluster] = (byCluster[t.cluster] || 0) + 1;
console.log(`対象 ${targets.length} IP ${JSON.stringify(byCluster)}`);
console.log(`  写し済み ${targets.length - need.length} / 引くのは ${need.length}`);
if (PLAN) { console.log("  → 引かずに終わります（--plan）"); process.exit(0); }
if (!need.length) { console.log("  引くものがありません。"); process.exit(0); }

const KEY = process.env.ABUSEIPDB_API_KEY
  || String(process.env.ABUSEIPDB_API_KEYS || "").split(",")[0];
if (!KEY) { console.error("ABUSEIPDB_API_KEY がありません。"); process.exit(2); }
const HEADERS = { Key: KEY, Accept: "application/json" };

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let remaining = null, done = 0, failed = 0, stop = null;
const failures = [];
const queue = [...need];
const worker = async (slotIdx) => {
  for (;;) {
    if (stop) return;
    const t = queue.shift();
    if (!t) return;
    await sleep(CFG.ABUSE_MIN_INTERVAL_MS * slotIdx);
    const u = new URL("https://api.abuseipdb.com/api/v2/check");
    u.searchParams.set("ipAddress", t.ip);
    u.searchParams.set("maxAgeInDays", String(CFG.FETCH_WINDOW_DAYS));
    u.searchParams.set("verbose", "");
    let res = null;
    try { res = await fetch(u, { headers: HEADERS }); } catch (e) {
      // **鍵を含む URL は出さない。**IP とエラーの種類だけ
      failures.push({ ip: t.ip, reason: String(e?.message || e).slice(0, 120) });
      failed++; continue;
    }
    const left = Number(res.headers.get("x-ratelimit-remaining"));
    if (Number.isFinite(left)) remaining = left;
    if (res.status === 429) { stop = "枠を使い切りました"; queue.unshift(t); return; }
    if (res.status === 401 || res.status === 403) { stop = "鍵が受け付けられませんでした"; return; }
    const body = await res.json().catch(() => null);
    if (!res.ok || !body?.data) {
      failures.push({ ip: t.ip, reason: `HTTP ${res.status}` });
      failed++; continue;
    }
    const f = slot(t.ip);
    fs.mkdirSync(path.dirname(f), { recursive: true });
    fs.writeFileSync(f, JSON.stringify({
      ip: t.ip, cluster: t.cluster, source: "abuseipdb", endpoint: "check", status: 200,
      max_age_days: CFG.FETCH_WINDOW_DAYS, fetched_at: new Date().toISOString(), body: body.data,
    }, null, 1) + "\n");
    if (++done % 50 === 0) process.stdout.write(`\r  ${done}/${need.length}  残量 ${remaining ?? "?"}    `);
  }
};
await Promise.all(Array.from({ length: CFG.ABUSE_CONCURRENCY }, (_, i) => worker(i)));
console.log(`\n取得 ${done} 件 / 失敗 ${failed} 件` + (stop ? `  — 中断: ${stop}` : "")
  + `  残量 ${remaining ?? "?"}`);
if (failures.length) {
  fs.writeFileSync(path.join(HERE, "fetch_failures.json"), JSON.stringify(failures, null, 2) + "\n");
  console.log(`  ! 失敗 ${failures.length} 件を fetch_failures.json に残しました`);
}
fs.writeFileSync(path.join(HERE, "fetch_meta.json"), JSON.stringify({
  dataset: CFG.DATASET, targets: targets.length, by_cluster: byCluster,
  fetch_window_days: CFG.FETCH_WINDOW_DAYS,
  copies: targets.filter((t) => fs.existsSync(slot(t.ip))).length,
  failures: failures.length, finished_at: new Date().toISOString(),
}, null, 2) + "\n");
