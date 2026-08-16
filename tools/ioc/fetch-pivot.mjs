#!/usr/bin/env node
// アクターに紐づく素性から**外へ**辿って、索引に無い検体を拾う。**ここは外に出る工程**。
//
//   VT_API_KEYS="k1,k2" node tools/ioc/fetch-pivot.mjs
//                       [--in data/ioc/latest] [--cache data/ioc/.cache/vt-pivot]
//                       [--targets 150] [--domain-ratio 0.2] [--plan]
//
// エンリッチ（既知の IOC を太らせる）とは別物で、こちらは**索引の外に出る**。
// VT の無料枠で外に出られるのは関係だけ（`intelligence/search` も `similar_files` も 403）。
//
// 実測（2026-W33 / 的 299・API 712 回）で決めた 2 つの方針
//
//   1. **ピボット元にも索引と同じ選別を掛ける。** 役割を述べられていない IOC
//      （関係語が `観測アクター` / `関連` だけ）と、正規サービスを外す。
//      これをやらずに引いたとき、`polygon-rpc.com`（検知 3・無害判定 56 の
//      正規 Polygon RPC エンドポイント）が橋を 12 本作り、全部ゴミだった。
//   2. **IP を優先する。** 的あたりの戻りが桁で違う。
//        IP     … 150 的中 140 が何かを返す（93%）／的あたり 25.8 件
//        ドメイン … 40 的中 6（15%）／的あたり 5.4 件
//      フィッシング用ドメインはページを出すだけでファイルを持たないため。
//
// 引く関係は `communicating_files` と `referrer_files` の 2 つだけ。
// `subdomains`（1.0 件/呼び出し）と `siblings`（0.6 件）は割に合わない。
// `historical_whois` は値を返すが IOC は増えない。
import path from "node:path";
import { parseArgs, readJsonl, writeJson } from "./lib/io.mjs";
import { KeyPool, readKeys, readRecord, writeRecord } from "./lib/enrich.mjs";
import { REPO_ROOT } from "./lib/sources.mjs";

const args = parseArgs(process.argv.slice(2));
const IN = path.resolve(REPO_ROOT, args.in || "data/ioc/latest");
const CACHE = path.resolve(REPO_ROOT, args.cache || "data/ioc/.cache/vt-pivot");
const N_TARGETS = Number(args.targets || 150);
/** 的に混ぜるドメインの割合。IP のほうが 5 倍効くので既定は 2 割 */
const DOMAIN_RATIO = Number(args["domain-ratio"] || 0.2);
const PLAN_ONLY = !!args.plan;
const RELS = ["communicating_files", "referrer_files"];
const PER_PAGE = 40;
const MAX_PAGES = 3;

/* ---------------- 的を選ぶ ---------------- */

const iocs = new Map([...readJsonl(path.join(IN, "iocs.jsonl")),
  ...readJsonl(path.join(IN, "derived-iocs.jsonl"))].map((r) => [r.key, r]));
const vt = new Map([...readJsonl(path.join(IN, "vt.jsonl")),
  ...readJsonl(path.join(IN, "derived-verdicts.jsonl"))].map((r) => [r.ioc, r]));
const links = [...readJsonl(path.join(IN, "links.jsonl")),
  ...readJsonl(path.join(IN, "derived-links.jsonl"))];

/** 「一緒に出てきた」しか言っていない関係語。§3.8 と同じ扱い */
const GENERIC_REL = new Set(["観測アクター", "関連"]);
const relsOf = new Map(), actorOf = new Map();
for (const l of links) {
  if (!relsOf.has(l.ioc)) relsOf.set(l.ioc, new Set());
  if (l.rel) relsOf.get(l.ioc).add(l.rel);
  if (l.kind !== "actor") continue;
  if (!actorOf.has(l.ioc)) actorOf.set(l.ioc, new Set());
  actorOf.get(l.ioc).add(l.name);
}

/** 役割を述べられているか */
const asserted = (key) => {
  const r = relsOf.get(key);
  return !!(r && [...r].some((x) => !GENERIC_REL.has(x)));
};
/** 正規サービス・人気ドメインを外す。`polygon-rpc.com` はここで落ちる */
const notPopular = (key) => {
  const i = iocs.get(key) || {};
  if (i.popular || i.noise || i.bogon || i.sample) return false;
  const v = vt.get(key) || {};
  const mal = v.malicious ?? 0, harm = v.harmless ?? 0;
  if (mal >= 5) return true;
  return mal >= 2 && harm < 40;
};

/** 検体をひとつも持たないアクター。ここが一番ピボットの効く場所 */
const hashCount = new Map();
for (const [key, actors] of actorOf) {
  if (!/^ioc\.(md5|sha1|sha256)\|/.test(key)) continue;
  for (const a of actors) hashCount.set(a, (hashCount.get(a) || 0) + 1);
}
const allActors = new Set([...actorOf.values()].flatMap((s) => [...s]));
const noSample = new Set([...allActors].filter((a) => !hashCount.has(a)));

const candidates = [];
for (const [key, actors] of actorOf) {
  const kind = /^ioc\.ipv4\|/.test(key) ? "ip" : key.startsWith("ioc.domain|") ? "domain" : null;
  if (!kind) continue;
  if (!asserted(key) || !notPopular(key)) continue;
  // 2 つの関係を両方とも引き終えている的は飛ばす
  const id = key.split("|")[1];
  if (RELS.every((rel) => readRecord(CACHE, `rel|${rel}|${key}`))) continue;
  const v = vt.get(key) || {};
  candidates.push({ kind, id, key, actors: [...actors],
    malicious: v.malicious ?? 0, harmless: v.harmless ?? 0,
    zero_sample_actor: [...actors].some((a) => noSample.has(a)) });
}
/** 検体ゼロのアクター → 検知数 の順。IP とドメインは別枠で取る */
const score = (c) => (c.zero_sample_actor ? 1000 : 0) + Math.min(40, c.malicious);
const byKind = { ip: [], domain: [] };
for (const c of candidates) byKind[c.kind].push(c);
for (const k of ["ip", "domain"]) byKind[k].sort((a, b) => score(b) - score(a) || a.id.localeCompare(b.id));
const nDomain = Math.round(N_TARGETS * DOMAIN_RATIO);
const targets = [...byKind.ip.slice(0, N_TARGETS - nDomain), ...byKind.domain.slice(0, nDomain)];

console.log(`ピボットの的（役割つき かつ 人気でない）: IP ${byKind.ip.length} / ドメイン ${byKind.domain.length}`);
console.log(`  うち検体ゼロのアクターに属する: ${candidates.filter((c) => c.zero_sample_actor).length}`);
console.log(`  今回引く: IP ${targets.filter((t) => t.kind === "ip").length} / ドメイン ${targets.filter((t) => t.kind === "domain").length}`);
if (!targets.length) { console.log("  引くものがありません"); process.exit(0); }
if (PLAN_ONLY) { console.log("  → 引かずに終わります（--plan）"); process.exit(0); }

/* ---------------- 引く ---------------- */

const keys = readKeys("VT_API_KEYS", "VT_API_KEYs");
if (!keys.length) {
  console.error('鍵がありません。VT_API_KEYS="k1,k2" を環境変数で渡してください。');
  process.exit(2);
}
const pool = new KeyPool(keys, { rpm: 4, hourly: 240, daily: 500 });

/** 使う欄だけ残す。橋を出すのに要るのは構造ハッシュと日付と検知数だけ */
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
const PATH = { ip: "ip_addresses", domain: "domains" };

let done = 0, calls = 0, empty = 0, fresh = 0;
const seenSha = new Set();
outer:
for (const t of targets) {
  for (const rel of RELS) {
    const cacheKey = `rel|${rel}|${t.key}`;
    if (readRecord(CACHE, cacheKey)) continue;
    let url = `https://www.virustotal.com/api/v3/${PATH[t.kind]}/${encodeURIComponent(t.id)}/${rel}?limit=${PER_PAGE}`;
    const ids = [];
    let page = 0, status = 200;
    while (url && page < MAX_PAGES) {
      const slot = await pool.take();
      if (!slot) { console.log("\n枠切れ。ここまでの写しは残ります"); break outer; }
      let res;
      try { res = await fetch(url, { headers: { "x-apikey": slot.key, accept: "application/json" } }); }
      catch (e) { console.error(`\n${t.id} ${rel}: ${String(e).slice(0, 60)}`); break; }
      calls++;
      if (res.status === 429 || res.status === 401) { pool.block(slot, String(res.status)); continue; }
      if (!res.ok) { status = res.status; break; }
      const j = await res.json();
      for (const d of j?.data || []) ids.push(keep(d));
      page++;
      url = j?.links?.next || null;
    }
    writeRecord(CACHE, { ioc: cacheKey, endpoint: rel, status,
      fetched_at: new Date().toISOString(), ids, pages: page }, cacheKey);
    done++;
    if (!ids.length) empty++;
    for (const x of ids) {
      if (!x.sha256 || seenSha.has(x.sha256)) continue;
      seenSha.add(x.sha256);
      if (!iocs.has("ioc.sha256|" + x.sha256)) fresh++;
    }
    process.stdout.write(`\r  ${done} / API ${calls}  ${rel.padEnd(20)} ${String(t.id).slice(0, 24).padEnd(24)} ${ids.length} 件      `);
  }
}
console.log(`\n完了 ${done} / API ${calls} 回 / 空振り ${empty} / 索引に無い検体 ${fresh}`);
writeJson(path.join(CACHE, "meta.json"), {
  tool: "tools/ioc/fetch-pivot.mjs", schema: 1,
  fetched_at: new Date().toISOString(),
  targets: targets.length, requests: done, api_calls: calls, empty, fresh_samples: fresh,
});
console.log(`  → ${CACHE}`);
