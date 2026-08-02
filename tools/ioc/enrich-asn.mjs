#!/usr/bin/env node
// IP の IOC に AS 番号を付ける。外部呼び出しなし（写しだけを見る）。
//
//   node tools/ioc/enrich-asn.mjs [--in data/ioc/latest] [--out <同じ場所>]
//                                 [--cache data/ioc/.cache/bgptools]
//
// 先に fetch-asn.mjs で写しを作っておくこと。同じ写しからは何度でも同じ結果になる。
//
// 出力
//   ip-asn.jsonl  IOC → AS 番号・一致した prefix・観測数。経路に無いものも印を付けて残す
//   asns.jsonl    出てきた AS の一覧。名前・国・区分と、**その AS の大きさ**
//   asn-meta.json 使った写しのハッシュと件数
//
// AS の大きさを一緒に出すのが肝。「同じ AS に居る」は、それだけでは何も言えない。
// 400 万アドレスを持つ事業者に 2 つの実体が居るのは偶然だが、1,024 アドレスしか
// 持たない AS に居るなら、同じ相手から借りているとみてよい。

import fs from "node:fs";
import path from "node:path";
import { byKeys, parseArgs, readJson, readJsonl, writeJson, writeJsonl } from "./lib/io.mjs";
import { loadTable, lookupIpv4, lookupIpv6, parseAsnCsv } from "./lib/asn.mjs";
import { REPO_ROOT } from "./lib/sources.mjs";

const args = parseArgs(process.argv.slice(2));
const IN = path.resolve(REPO_ROOT, args.in || "data/ioc/latest");
const OUT = path.resolve(REPO_ROOT, args.out || args.in || "data/ioc/latest");
const CACHE = path.resolve(REPO_ROOT, args.cache || "data/ioc/.cache/bgptools");

const iocs = readJsonl(path.join(IN, "iocs.jsonl"));
if (!iocs.length) {
  console.error(`${IN} に iocs.jsonl がありません。先に collect.mjs を実行してください。`);
  process.exit(1);
}

const source = readJson(path.join(CACHE, "source.json"));
const tableFile = path.join(CACHE, "table.jsonl");
if (!source || !fs.existsSync(tableFile)) {
  console.error([
    `${path.relative(REPO_ROOT, CACHE)} に経路表の写しがありません。`,
    '  BGPTOOLS_CONTACT="you@example.com" node tools/ioc/fetch-asn.mjs',
  ].join("\n"));
  process.exit(1);
}

/* 要る側だけ組み立てる。v6 は BigInt を使うので、無いのに作ると数秒損する */
const want = [];
if (iocs.some((r) => r.type === "ioc.ipv4")) want.push("v4");
if (iocs.some((r) => r.type === "ioc.ipv6")) want.push("v6");
if (!want.length) {
  console.log("IP の IOC がありません。何もしません。");
  process.exit(0);
}

const table = loadTable(tableFile, want);
const names = fs.existsSync(path.join(CACHE, "asns.csv"))
  ? parseAsnCsv(fs.readFileSync(path.join(CACHE, "asns.csv"), "utf8"))
  : new Map();

/* ---------------- 引く ---------------- */

const rows = [];
const seen = new Map();   // AS → その AS に居た IOC の数
let routed = 0, unrouted = 0, skipped = 0;

for (const r of iocs) {
  if (r.type !== "ioc.ipv4" && r.type !== "ioc.ipv6") continue;
  // 経路に乗らないアドレスは引くだけ無駄。印は collect が既に付けている
  if (r.malformed || r.bogon) { skipped++; continue; }

  const hit = r.type === "ioc.ipv4" ? lookupIpv4(table, r.value) : lookupIpv6(table, r.value);
  if (!hit) {
    // 経路に無い＝今は誰も出していない。割り当て前か、既に引き上げられたか
    rows.push({ ioc: r.key, routed: false });
    unrouted++;
    continue;
  }
  rows.push({ ioc: r.key, asn: hit.asn, prefix: hit.prefix, hits: hit.hits });
  seen.set(hit.asn, (seen.get(hit.asn) || 0) + 1);
  routed++;
}

rows.sort(byKeys("ioc"));

const asnRows = [...seen.entries()]
  .map(([asn, iocCount]) => {
    const meta = names.get(asn) || {};
    const size = table.asnPrefixes.get(asn) || { prefixes: 0, addresses: 0 };
    return {
      asn,
      iocs: iocCount,
      ...(meta.name ? { name: meta.name } : {}),
      ...(meta.cc ? { cc: meta.cc } : {}),
      ...(meta.class ? { class: meta.class } : {}),
      prefixes: size.prefixes,
      addresses: size.addresses,
    };
  })
  .sort(byKeys("asn"));

writeJsonl(path.join(OUT, "ip-asn.jsonl"), rows);
writeJsonl(path.join(OUT, "asns.jsonl"), asnRows);
writeJson(path.join(OUT, "asn-meta.json"), {
  tool: "tools/ioc/enrich-asn.mjs",
  schema: 1,
  source: "bgp.tools",
  // どの写しから出た結果かを固定する。写しが変われば結果も変わってよい
  table: source.files?.["table.jsonl"] || null,
  asn_names: source.files?.["asns.csv"] || null,
  table_prefixes: { v4: table.v4Count, v6: table.v6Count, skipped: table.skipped },
  counts: { routed, unrouted, skipped, asns: asnRows.length },
});

/* ---------------- 表示 ---------------- */

const small = asnRows.filter((a) => a.addresses > 0 && a.addresses <= 4096);
console.log(`IP ${routed + unrouted + skipped} 件（経路あり ${routed} / 経路なし ${unrouted} / 対象外 ${skipped}）`);
console.log(`  AS ${asnRows.length} 件。うち 4,096 アドレス以下の小さい AS が ${small.length} 件`);
for (const a of [...asnRows].sort((x, y) => y.iocs - x.iocs).slice(0, 5)) {
  console.log(`    AS${String(a.asn).padEnd(7)} IOC ${String(a.iocs).padStart(4)}  ${a.addresses.toLocaleString().padStart(11)} アドレス  ${a.name || "?"}`);
}
console.log(`  → ${path.relative(REPO_ROOT, OUT)}`);
