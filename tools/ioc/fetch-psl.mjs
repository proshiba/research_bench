#!/usr/bin/env node
// 公開接尾辞一覧（Public Suffix List）の写しを取る。**ここは外に出る工程**。
//
//   node tools/ioc/fetch-psl.mjs [--cache data/ioc/.cache/psl]
//                                [--max-age 604800] [--force]
//
// 取得元は publicsuffix.org。鍵は要らない。
// 「どこまでが接尾辞で、どこからが誰かが買った単位か」を決める唯一の出典で、
// **手書きの一覧では追いつかない**（実測: `com.br` は手書き一覧にあったが `gov.br`
// が無く、ブラジル政府のドメイン 19 件が「同じ登録者の子」に見えていた）。
//
// 一覧には 2 つの区画がある。
//   ICANN   … レジストリが公式に持つ接尾辞（`com` `co.jp` `gov.br` …）
//   PRIVATE … 誰でも子ドメインを作れる事業者（`ddns.net` `workers.dev` `duckdns.org` …）
// **どちらも「その下は別人の持ち物」を意味する**ので、既定では両方を使う。
// 区画は写しに残すので、あとから ICANN だけで数え直すこともできる。
//
// 更新は週に 1 度で足りる（既定 7 日）。写しが新しければ取りに行かない。
import fs from "node:fs";
import path from "node:path";
import { parseArgs, writeJson, sha256 } from "./lib/io.mjs";
import { REPO_ROOT } from "./lib/sources.mjs";

const args = parseArgs(process.argv.slice(2));
const CACHE = path.resolve(REPO_ROOT, args.cache || "data/ioc/.cache/psl");
const MAX_AGE = Number(args["max-age"] || 604800) * 1000;
const FORCE = !!args.force;
const URL = "https://publicsuffix.org/list/public_suffix_list.dat";

const file = path.join(CACHE, "public_suffix_list.dat");
if (!FORCE && fs.existsSync(file)) {
  const age = Date.now() - fs.statSync(file).mtimeMs;
  if (age < MAX_AGE) {
    console.log(`写しが新しいので取りに行きません（${Math.round(age / 3600000)} 時間前 / 上限 ${MAX_AGE / 3600000} 時間）`);
    console.log(`  → ${file}`);
    process.exit(0);
  }
}

const res = await fetch(URL, { headers: { accept: "text/plain" } });
if (!res.ok) {
  console.error(`取得できません: HTTP ${res.status}`);
  process.exit(1);
}
const text = await res.text();
if (!text.includes("===BEGIN ICANN DOMAINS===")) {
  console.error("中身が一覧に見えません。書き込まずに終わります");
  process.exit(1);
}
fs.mkdirSync(CACHE, { recursive: true });
fs.writeFileSync(file, text);

// 一覧に埋まっている版番号を控える。いつの一覧で数えたかが後から分かる
const version = (text.match(/^\/\/ VERSION:\s*(.+)$/m) || [])[1] || null;
const commit = (text.match(/^\/\/ COMMIT:\s*(.+)$/m) || [])[1] || null;
const lines = text.split("\n");
const icann = lines.indexOf("// ===BEGIN ICANN DOMAINS===");
const priv = lines.indexOf("// ===BEGIN PRIVATE DOMAINS===");
const count = (from, to) => lines.slice(from + 1, to).filter((l) => l.trim() && !l.startsWith("//")).length;

const meta = {
  tool: "tools/ioc/fetch-psl.mjs", schema: 1,
  fetched_at: new Date().toISOString(), url: URL,
  version, commit, bytes: text.length, sha256: sha256(Buffer.from(text, "utf8")),
  rules: { icann: count(icann, priv), private: count(priv, lines.length) },
};
writeJson(path.join(CACHE, "meta.json"), meta);
console.log(`取得 ${(text.length / 1024).toFixed(0)} KB / 版 ${version}`);
console.log(`  規則 ICANN ${meta.rules.icann} / PRIVATE ${meta.rules.private}`);
console.log(`  → ${file}`);
