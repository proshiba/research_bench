#!/usr/bin/env node
// **生きているドメインだけ**について、そこへ通信している検体を引き直す。
// **ここは外に出る工程**（VirusTotal の枠を使う）。
//
//   VT_API_KEYS="k1,k2" node tools/ioc/fetch-tracker-samples.mjs
//                       [--tracker data/ioc/tracker] [--in data/ioc/latest]
//                       [--cache data/ioc/.cache/vt-tracker]
//                       [--limit 120] [--max-age 604800] [--plan]
//
// 生死と切り替わりは DNS だけで分かる（fetch-dns.mjs）。こちらはその先で、
// **生きている足場に新しい検体がぶら下がったか**を見るためのもの。
//
// 枠の使い方を絞る 3 つの決まり
//
//   1. **死んだドメインは引かない。** state.jsonl が `alive` と言っているものだけ。
//      索引全体の 6,245 件を毎日引いたら枠が何日あっても足りない。
//   2. **動的 DNS の下も引かない。** `foo.ddns.net` に付く検体は、その名前を
//      たまたま使った別人のものでありうる。足場としての連続性が無い。
//   3. **同じドメインは --max-age（既定 7 日）空けてから引き直す。** 毎日引いても
//      新しい検体が湧くわけではない。生死は DNS が毎日見ているので、こちらは疎で足りる。
import path from "node:path";
import { parseArgs, readJsonl, writeJson } from "./lib/io.mjs";
import { KeyPool, readKeys, readRecord, writeRecord } from "./lib/enrich.mjs";
import { REPO_ROOT } from "./lib/sources.mjs";
import { STATUS } from "./lib/tracker.mjs";

const args = parseArgs(process.argv.slice(2));
const IN = path.resolve(REPO_ROOT, args.in || "data/ioc/latest");
const TRACKER = path.resolve(REPO_ROOT, args.tracker || "data/ioc/tracker");
const CACHE = path.resolve(REPO_ROOT, args.cache || "data/ioc/.cache/vt-tracker");
const LIMIT = Number(args.limit || 120);
const MAX_AGE = Number(args["max-age"] || 604800) * 1000;
const PLAN_ONLY = !!args.plan;

const state = readJsonl(path.join(TRACKER, "state.jsonl"));
if (!state.length) {
  console.error(`${TRACKER}/state.jsonl がありません。先に fetch-dns.mjs → track-domains.mjs を。`);
  process.exit(2);
}
const iocs = new Set([...readJsonl(path.join(IN, "iocs.jsonl")),
  ...readJsonl(path.join(IN, "derived-iocs.jsonl"))].map((r) => r.key));

const now = Date.now();
const stale = (key) => {
  const r = readRecord(CACHE, key);
  if (!r) return true;
  return now - new Date(r.fetched_at || 0).getTime() >= MAX_AGE;
};

const alive = state.filter((s) => s.status === STATUS.ALIVE);
const candidates = alive.filter((s) => s.track_domain !== false)
  .filter((s) => stale(`rel|communicating_files|ioc.domain|${s.host}`))
  // 長く生きているものほど足場として本物。次に変化の多いもの
  .sort((a, b) => (b.changes - a.changes) || String(a.first_seen).localeCompare(String(b.first_seen)));
const todo = candidates.slice(0, LIMIT);

console.log(`生きているドメイン ${alive.length} / うち動的 DNS を除く ${alive.filter((s) => s.track_domain !== false).length}`);
console.log(`  ${MAX_AGE / 86400000} 日以上引いていないもの ${candidates.length} / 今回引く ${todo.length}`);
if (!todo.length) { console.log("  引くものがありません"); process.exit(0); }
if (PLAN_ONLY) { console.log("  → 引かずに終わります（--plan）"); process.exit(0); }

const keys = readKeys("VT_API_KEYS", "VT_API_KEYs");
if (!keys.length) { console.error('鍵がありません。VT_API_KEYS="k1,k2" を渡してください。'); process.exit(2); }
const pool = new KeyPool(keys, { rpm: 4, hourly: 240, daily: 500 });

const keep = (d) => ({
  sha256: d.id,
  mal: d.attributes?.last_analysis_stats?.malicious,
  name: d.attributes?.meaningful_name,
  type: d.attributes?.type_description,
  size: d.attributes?.size,
  vhash: d.attributes?.vhash,
  imphash: d.attributes?.pe_info?.imphash,
  first: d.attributes?.first_submission_date
    && new Date(d.attributes.first_submission_date * 1000).toISOString().slice(0, 10),
});

let done = 0, calls = 0, freshTotal = 0;
const freshByHost = [];
for (const s of todo) {
  const cacheKey = `rel|communicating_files|ioc.domain|${s.host}`;
  const before = new Set((readRecord(CACHE, cacheKey)?.ids || []).map((x) => x.sha256));
  let url = `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(s.host)}/communicating_files?limit=40`;
  const ids = [];
  let page = 0, status = 200;
  while (url && page < 3) {
    const slot = await pool.take();
    if (!slot) { console.log("\n枠切れ"); url = null; break; }
    let res;
    try { res = await fetch(url, { headers: { "x-apikey": slot.key, accept: "application/json" } }); }
    catch (e) { console.error(`\n${s.host}: ${String(e).slice(0, 50)}`); break; }
    calls++;
    if (res.status === 429 || res.status === 401) { pool.block(slot, String(res.status)); continue; }
    if (!res.ok) { status = res.status; break; }
    const j = await res.json();
    for (const d of j?.data || []) ids.push(keep(d));
    page++; url = j?.links?.next || null;
  }
  if (!page && status === 200) break; // 1 ページも引けていない＝枠切れ
  writeRecord(CACHE, { ioc: cacheKey, endpoint: "communicating_files", status,
    fetched_at: new Date().toISOString(), ids, pages: page }, cacheKey);
  done++;
  // 「新しい」は 2 通りある。前回の写しに無かったもの と 索引に無いもの
  const newToUs = ids.filter((x) => x.sha256 && !before.has(x.sha256));
  const newToIndex = ids.filter((x) => x.sha256 && !iocs.has("ioc.sha256|" + x.sha256));
  if (newToUs.length) freshByHost.push({ host: s.host, since_last: newToUs.length,
    not_in_index: newToIndex.length, ips: s.ips, asns: s.asns,
    samples: newToUs.slice(0, 10).map((x) => ({ sha256: x.sha256, mal: x.mal, first: x.first, name: x.name, vhash: x.vhash })) });
  freshTotal += newToUs.length;
  process.stdout.write(`\r  ${done}/${todo.length} API ${calls}  ${s.host.slice(0, 30).padEnd(30)} ${ids.length} 件（新 ${newToUs.length}）      `);
}
console.log(`\n完了 ${done} / API ${calls} 回 / 前回から増えた検体 ${freshTotal} 件`);
if (freshByHost.length) {
  console.log("\n検体が増えた生存ドメイン:");
  for (const f of freshByHost.sort((a, b) => b.since_last - a.since_last).slice(0, 20)) {
    console.log(`  +${String(f.since_last).padStart(3)}（索引に無い ${f.not_in_index}）  ${f.host.padEnd(34)} ${f.ips.join(",").slice(0, 30)}`);
    for (const x of f.samples.slice(0, 3)) {
      console.log(`        ${x.first || "?"} 検知${String(x.mal ?? "?").padStart(3)} ${x.sha256.slice(0, 16)} ${String(x.name || "").slice(0, 30)}`);
    }
  }
}
writeJson(path.join(TRACKER, "new-samples.json"), {
  tool: "tools/ioc/fetch-tracker-samples.mjs", schema: 1,
  fetched_at: new Date().toISOString(),
  alive: alive.length, asked: done, api_calls: calls,
  fresh_samples: freshTotal, hosts: freshByHost,
});
console.log(`\n  → ${path.join(TRACKER, "new-samples.json")}`);
