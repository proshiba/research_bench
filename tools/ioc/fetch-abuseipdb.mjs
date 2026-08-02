#!/usr/bin/env node
// AbuseIPDB の通報状況を取ってきて写しに置く。**ここは外に出る工程**。
//
//   ABUSEIPDB_API_KEY="k" node tools/ioc/fetch-abuseipdb.mjs
//                         [--in data/ioc/latest] [--cache data/ioc/.cache/abuseipdb]
//                         [--limit 1000] [--plan] [--rpm 30] [--daily 1000]
//                         [--max-age 2592000] [--max-age-days 365]
//                         [--refresh] [--include-noise]
//
// `GET /api/v2/check?ipAddress=&maxAgeInDays=365&verbose=` を IP ごとに 1 回。
// verbose を付けるのは **通報カテゴリの分布**が欲しいため（何をして通報されたか）。
//
// bogon と公開 DNS（bogon / noise の印が付いているもの）は引かない。
// VT と並行して走らせられる（鍵も枠も別。docs/ioc-enrich-plan.md §4 の段階 0）。
//
// 残り枠は応答のヘッダ（X-RateLimit-Remaining）が教えてくれるので、それに従う。

import path from "node:path";
import { parseArgs, readJsonl } from "./lib/io.mjs";
import {
  ABUSE_TARGET_TYPES, KeyPool, buildQueue, entityCounts, excluded, notableIps,
  readKeys, readRecord, sleep, stageOf, tallyStages, writeRecord,
} from "./lib/enrich.mjs";
import { REPO_ROOT } from "./lib/sources.mjs";

const args = parseArgs(process.argv.slice(2));
const IN = path.resolve(REPO_ROOT, args.in || "data/ioc/latest");
const CACHE = path.resolve(REPO_ROOT, args.cache || "data/ioc/.cache/abuseipdb");
const PLAN_ONLY = !!args.plan;
const INCLUDE_NOISE = !!args["include-noise"];
const LIMIT = args.limit === undefined ? Infinity : Number(args.limit);
const MAX_AGE = Number(args["max-age"] || 2592000) * 1000;
/** 何日ぶんの通報を見るか。既定 365 日（計画 §1.2 と同じ） */
const AGE_DAYS = Number(args["max-age-days"] || 365);

/* ---------------- 対象を決める ---------------- */

const iocs = readJsonl(path.join(IN, "iocs.jsonl"));
if (!iocs.length) {
  console.error(`${IN} に iocs.jsonl がありません。先に collect.mjs を実行してください。`);
  process.exit(1);
}
const links = readJsonl(path.join(IN, "links.jsonl"));
const fresh = new Set(readJsonl(path.join(IN, "new.jsonl")).map((r) => r.key));

const asnOf = new Map();
for (const r of readJsonl(path.join(IN, "ip-asn.jsonl"))) if (r.asn) asnOf.set(r.ioc, r.asn);
const asnInfo = new Map(readJsonl(path.join(IN, "asns.jsonl")).map((a) => [a.asn, a]));

const counts = entityCounts(links);
const notable = notableIps(iocs, links, { asnOf, asnInfo });

const targets = [];
for (const r of iocs) {
  if (!ABUSE_TARGET_TYPES.has(r.type)) continue;
  if (excluded(r, { includeNoise: INCLUDE_NOISE })) continue;
  const entities = counts.get(r.key) || 0;
  targets.push({
    ioc: r.key,
    id: r.value,
    entities,
    stage: stageOf(r, { entities, isNew: fresh.has(r.key), notable: notable.has(r.key) }),
  });
}

const now = Date.now();
const stale = (rec) => !rec || now - Date.parse(rec.fetched_at || 0) > MAX_AGE;
/**
 * 写しが消えていても、既に判定を持っている IP には枠を使い直さない。
 * 写しは追跡していないので、別の環境では最初から空になる（fetch-vt.mjs と同じ）。
 */
const alreadyKnown = args.refresh ? new Set() : new Set(readJsonl(path.join(IN, "abuseipdb.jsonl")).map((r) => r.ioc));
const queue = buildQueue(targets)
  .filter((t) => stale(readRecord(CACHE, t.ioc)) && !alreadyKnown.has(t.ioc));

console.log(`AbuseIPDB の対象 ${targets.length} IP（写し済み ${targets.length - queue.length} / 残り ${queue.length}）`);
const byStage = tallyStages(targets);
const remainByStage = tallyStages(queue);
for (const [s, n] of Object.entries(byStage)) {
  console.log(`  段階 ${s.padEnd(3)} ${String(n).padStart(6)} 件  残り ${String(remainByStage[s] || 0).padStart(6)}`);
}

if (PLAN_ONLY) {
  console.log(`  → 引かずに終わります（--plan）。写し: ${path.relative(REPO_ROOT, CACHE)}`);
  process.exit(0);
}

/* ---------------- 鍵と枠 ---------------- */

const keys = readKeys("ABUSEIPDB_API_KEY", "ABUSEIPDB_API_KEYS", "ABUSE_IP_DB");
if (!keys.length) {
  console.error([
    "AbuseIPDB の鍵がありません。環境変数から読みます（リポジトリには書きません）。",
    "",
    '  ABUSEIPDB_API_KEY="k" node tools/ioc/fetch-abuseipdb.mjs',
  ].join("\n"));
  process.exit(2);
}

const pool = new KeyPool(keys, {
  rpm: Number(args.rpm || 30),
  daily: Number(args.daily || 1000),
});

const budget = Math.min(LIMIT, pool.remaining, queue.length);
console.log(`  鍵 ${keys.length} 本。今この場で引けるのは ${budget} 件`);
if (!budget) {
  console.log("  引けるものがありません。");
  process.exit(0);
}

/* ---------------- 引く ---------------- */

const stat = { ok: 0, failed: 0 };
const started = new Date().toISOString();
let taken = 0;
let stop = false;
process.on("SIGINT", () => {
  console.log("\n  中断しました。ここまでの写しは残ります。");
  stop = true;
});

async function fetchOne(slot, item) {
  const url = new URL("https://api.abuseipdb.com/api/v2/check");
  url.searchParams.set("ipAddress", item.id);
  url.searchParams.set("maxAgeInDays", String(AGE_DAYS));
  url.searchParams.set("verbose", "");
  const res = await fetch(url, { headers: { key: slot.key, accept: "application/json" } });

  // 残り枠は取得元が数えている。手元の数より、こちらを信じる
  const left = Number(res.headers.get("x-ratelimit-remaining"));
  if (Number.isFinite(left) && left <= 0) pool.block(slot, "枠を使い切りました");

  if (res.status === 429) return { retry: "quota" };
  if (res.status === 401 || res.status === 403) return { retry: "auth" };
  if (res.status >= 500) return { retry: "server" };

  const body = await res.json().catch(() => null);
  if (!res.ok || !body?.data) return { retry: "server" };
  return { record: { ioc: item.ioc, endpoint: "check", status: 200, body: body.data } };
}

async function worker() {
  for (;;) {
    if (stop || taken >= budget) return;
    const slot = await pool.take();
    if (!slot) return;
    if (stop || taken >= budget) return;
    const item = queue[taken++];
    if (!item) return;

    let result = null;
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        result = await fetchOne(slot, item);
      } catch (e) {
        result = { retry: "network", why: e.message };
      }
      if (result.record) break;
      if (result.retry === "quota") { pool.block(slot, "枠を使い切りました"); result = null; break; }
      if (result.retry === "auth") { pool.block(slot, "鍵が受け付けられません"); result = null; break; }
      await sleep(2000 * (attempt + 1));
      pool.charge(slot);
    }

    if (!result?.record) { stat.failed++; continue; }
    writeRecord(CACHE, {
      ...result.record,
      fetched_at: new Date().toISOString(),
      // 何日ぶんの通報を見た応答かは、後から判定を読むときに要る
      max_age_days: AGE_DAYS,
      source: "abuseipdb",
    });
    stat.ok++;
    const n = stat.ok + stat.failed;
    if (n % 100 === 0 || n === budget) console.log(`  ${String(n).padStart(5)} / ${budget}`);
  }
}

await Promise.all(pool.slots.map(() => worker()));

console.log(`取得 ${stat.ok} 件${stat.failed ? `（取れず ${stat.failed}）` : ""}`);
console.log(`  期間 ${started} 〜 ${new Date().toISOString()}`);
for (const s of pool.report()) console.log(`    ${s.key}  この実行で ${s.used} 件${s.blocked ? `  ${s.blocked}` : ""}`);
console.log(`  → ${path.relative(REPO_ROOT, CACHE)}`);
