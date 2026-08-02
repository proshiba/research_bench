#!/usr/bin/env node
// 経路表と AS 名を取ってきて写しに置く。
//
//   BGPTOOLS_CONTACT="you@example.com" node tools/ioc/fetch-asn.mjs
//                                      [--cache data/ioc/.cache/bgptools]
//                                      [--max-age 7200] [--force]
//
// 取得元は bgp.tools。ここだけが外部に出る工程で、enrich-asn.mjs 以降は写しだけを見る。
//   table.jsonl … 全経路（prefix → AS 番号 + 観測数）約 75 MB / 147 万件
//   asns.csv    … AS 番号 → 名前・国・区分 約 12 万件
//
// bgp.tools の取り決めに合わせている。
//   ・連絡先の入った User-Agent が要る（既定の UA は塞がれることがある）
//   ・table は 30 分より短い間隔で取り直さない。2 時間ほど写しを使うのが推奨
//   ・asns.csv は 24 時間
// このscriptは写しが新しければ取りに行かない（--max-age、既定 2 時間）。
//
// なぜ経路表を丸ごと持つか
//   IP ごとに問い合わせると 3,000 回を超える外部呼び出しになり、再現もできない。
//   写しを 1 つ置けば、同じ写しからは何度でも同じ結果が出る。

import fs from "node:fs";
import path from "node:path";
import { parseArgs, sha256, writeJson } from "./lib/io.mjs";
import { REPO_ROOT } from "./lib/sources.mjs";

const args = parseArgs(process.argv.slice(2));
const CACHE = path.resolve(REPO_ROOT, args.cache || "data/ioc/.cache/bgptools");
const MAX_AGE = Number(args["max-age"] || 7200) * 1000;

const CONTACT = args.contact || process.env.BGPTOOLS_CONTACT || "";
if (!CONTACT) {
  console.error([
    "連絡先が要ります。bgp.tools は連絡先の入った User-Agent を求めています",
    "（何かあったときに連絡できないため、既定の UA は塞がれることがあります）。",
    "",
    '  BGPTOOLS_CONTACT="you@example.com" node tools/ioc/fetch-asn.mjs',
    "",
    "リポジトリに書き込まないよう、環境変数か --contact で渡してください。",
  ].join("\n"));
  process.exit(2);
}
const UA = `research_bench-ioc/1.0 bgp.tools - ${CONTACT}`;

const FILES = [
  { name: "table.jsonl", url: "https://bgp.tools/table.jsonl", maxAge: MAX_AGE },
  // AS 名は 1 日 1 回で足りる、と取得元が案内している
  { name: "asns.csv", url: "https://bgp.tools/asns.csv", maxAge: Math.max(MAX_AGE, 86400_000) },
];

const nowIso = new Date().toISOString();
const prev = fs.existsSync(path.join(CACHE, "source.json"))
  ? JSON.parse(fs.readFileSync(path.join(CACHE, "source.json"), "utf8"))
  : { files: {} };

const out = { tool: "tools/ioc/fetch-asn.mjs", schema: 1, source: "bgp.tools", files: {} };
let fetched = 0;

for (const f of FILES) {
  const dest = path.join(CACHE, f.name);
  const before = prev.files?.[f.name];
  const age = before?.fetched_at ? Date.parse(nowIso) - Date.parse(before.fetched_at) : Infinity;

  if (!args.force && fs.existsSync(dest) && age < f.maxAge) {
    console.log(`  そのまま ${f.name}（写しは ${Math.round(age / 60000)} 分前・上限 ${Math.round(f.maxAge / 60000)} 分）`);
    out.files[f.name] = before;
    continue;
  }

  const res = await fetch(f.url, { headers: { "user-agent": UA, accept: "*/*" } });
  if (!res.ok) {
    console.error(`! ${f.url} が HTTP ${res.status}`);
    process.exit(1);
  }
  const body = Buffer.from(await res.arrayBuffer());
  fs.mkdirSync(CACHE, { recursive: true });
  fs.writeFileSync(dest, body);
  fetched++;

  const lines = body.toString("utf8").split("\n").filter((l) => l.trim()).length;
  out.files[f.name] = {
    url: f.url,
    fetched_at: nowIso,
    bytes: body.length,
    lines,
    // 同じ写しから出た結果かを後から確かめられるように残す
    sha256: sha256(body),
  };
  console.log(`  取得 ${f.name}  ${(body.length / 1048576).toFixed(1)} MB / ${lines.toLocaleString()} 行`);
}

writeJson(path.join(CACHE, "source.json"), out);
console.log(`  → ${path.relative(REPO_ROOT, CACHE)}${fetched ? "" : "（取得なし）"}`);
