#!/usr/bin/env node
// 攻撃者ドメインを片端から名前解決して、その日の観測を残す。**ここは外に出る工程**。
//
//   node tools/ioc/fetch-dns.mjs [--in data/ioc/latest] [--out data/ioc/tracker]
//                                [--limit 0] [--concurrency 24] [--timeout 5000]
//                                [--resolver 8.8.8.8,1.1.1.1] [--date 2026-08-16]
//
// 攻撃者のサーバには触らない。**公開リゾルバに名前を聞くだけ**で、
// 解決先に接続もしない。API の鍵も要らず、枠も消費しない。
//
// 出力は 1 日 1 ファイル。
//   data/ioc/tracker/observations/<YYYY-MM-DD>.jsonl
//
// **なぜ「最新の写し」ではなく日付ごとに残すのか。** 追いたいのは現在値ではなく
// 切り替わりだから。上書きしてしまうと、いつ変わったのかが永久に分からない。
// 1 日 1 ファイルなら決定的で、git の差分としても読める。
import fs from "node:fs";
import path from "node:path";
import dns from "node:dns";
import { parseArgs, readJsonl, writeJsonl, writeJson, byKeys } from "./lib/io.mjs";
import { REPO_ROOT } from "./lib/sources.mjs";
import { dynamicSuffixOf, trackable } from "./lib/tracker.mjs";

const args = parseArgs(process.argv.slice(2));
const IN = path.resolve(REPO_ROOT, args.in || "data/ioc/latest");
const OUT = path.resolve(REPO_ROOT, args.out || "data/ioc/tracker");
const LIMIT = args.limit === undefined ? Infinity : Number(args.limit) || Infinity;
const CONCURRENCY = Number(args.concurrency || 24);
const TIMEOUT = Number(args.timeout || 5000);
const DATE = String(args.date || new Date().toISOString().slice(0, 10));

if (args.resolver) dns.setServers(String(args.resolver).split(","));
const resolver = dns.promises;

/* ---------------- 誰を追うか ---------------- */

const iocs = new Map([...readJsonl(path.join(IN, "iocs.jsonl")),
  ...readJsonl(path.join(IN, "derived-iocs.jsonl"))].map((r) => [r.key, r]));
const vt = new Map([...readJsonl(path.join(IN, "vt.jsonl")),
  ...readJsonl(path.join(IN, "derived-verdicts.jsonl"))].map((r) => [r.ioc, r]));
const links = [...readJsonl(path.join(IN, "links.jsonl")),
  ...readJsonl(path.join(IN, "derived-links.jsonl"))];
const relsOf = new Map();
for (const l of links) {
  if (!relsOf.has(l.ioc)) relsOf.set(l.ioc, new Set());
  if (l.rel) relsOf.get(l.ioc).add(l.rel);
}

const targets = [];
for (const [key, rec] of iocs) {
  if (!key.startsWith("ioc.domain|")) continue;
  if (!trackable(key, { relsOf, vt, iocs })) continue;
  targets.push({ key, host: key.slice("ioc.domain|".length), dynamic: dynamicSuffixOf(rec.key ? key.slice("ioc.domain|".length) : "") });
}
targets.sort(byKeys("host"));
const todo = targets.slice(0, LIMIT);
console.log(`追跡対象のドメイン ${targets.length} 件（役割つき または VT 検知 2 以上）`);
console.log(`  うち動的 DNS / 共用基盤の下: ${targets.filter((t) => t.dynamic).length}`);
console.log(`  今回引く: ${todo.length} 件 / 同時 ${CONCURRENCY} / リゾルバ ${dns.getServers().join(",")}`);

/* ---------------- 引く ---------------- */

const withTimeout = (p) => Promise.race([p,
  new Promise((_, rej) => setTimeout(() => rej(Object.assign(new Error("timeout"), { code: "ETIMEOUT" })), TIMEOUT))]);

/** 1 ドメインぶん。A / AAAA / CNAME / NS を引く。
 *  NS も引くのは、A が消えたときに「失効した」のか「向き先を外しただけ」なのかを
 *  分けるため。NS が残っていれば登録自体は生きている */
async function lookup(t) {
  const out = { ioc: t.key, host: t.host, date: DATE };
  if (t.dynamic) out.dynamic_suffix = t.dynamic;
  const ask = async (kind, fn) => {
    try { return await withTimeout(fn()); }
    catch (e) {
      if (!out.errors) out.errors = {};
      out.errors[kind] = e.code || String(e.message || e).slice(0, 24);
      return null;
    }
  };
  const [a, aaaa, cname, ns] = await Promise.all([
    ask("a", () => resolver.resolve4(t.host)),
    ask("aaaa", () => resolver.resolve6(t.host)),
    ask("cname", () => resolver.resolveCname(t.host)),
    ask("ns", () => resolver.resolveNs(t.host)),
  ]);
  if (a?.length) out.a = [...new Set(a)].sort();
  if (aaaa?.length) out.aaaa = [...new Set(aaaa)].sort();
  if (cname?.length) out.cname = [...new Set(cname.map((x) => x.toLowerCase()))].sort();
  if (ns?.length) out.ns = [...new Set(ns.map((x) => x.toLowerCase()))].sort();
  // 一番強い手掛かりを status にする。NXDOMAIN は A の結果だけで決める
  out.status = out.a || out.aaaa ? "answer"
    : out.errors?.a === "ENOTFOUND" ? "nxdomain"
    : out.errors?.a === "ENODATA" ? "no_answer"
    : "error";
  return out;
}

const results = [];
let done = 0;
async function worker(queue) {
  for (;;) {
    const t = queue.pop();
    if (!t) return;
    results.push(await lookup(t));
    if (++done % 200 === 0) process.stdout.write(`\r  ${done} / ${todo.length}      `);
  }
}
const queue = [...todo].reverse();
await Promise.all(Array.from({ length: CONCURRENCY }, () => worker(queue)));

results.sort(byKeys("host"));
const dir = path.join(OUT, "observations");
fs.mkdirSync(dir, { recursive: true });
const file = path.join(dir, `${DATE}.jsonl`);
writeJsonl(file, results);

const tally = results.reduce((m, r) => (m[r.status] = (m[r.status] || 0) + 1, m), {});
console.log(`\n観測 ${results.length} 件: ` + Object.entries(tally).map(([k, v]) => `${k} ${v}`).join(" / "));
writeJson(path.join(OUT, "fetch-meta.json"), {
  tool: "tools/ioc/fetch-dns.mjs", schema: 1,
  date: DATE, fetched_at: new Date().toISOString(),
  resolvers: dns.getServers(), targets: targets.length, resolved: results.length, by_status: tally,
});
console.log(`  → ${file}`);
