#!/usr/bin/env node
// 証明書の記録の写しから、**追う価値のある兄弟だけ**を出す。
// **写しだけを見る。外には出ない。**
//
//   node tools/ioc/crtname.mjs [--in data/ioc/latest] [--cache data/ioc/.cache/crtname]
//                              [--cap 200] [--top 20]
//
// 出すもの
//   data/ioc/latest/crtname.jsonl   1 行 1 ホスト。どの apex から出たか・印つき
//   data/ioc/latest/crtname-meta.json
//
// ## 2 つの線引き
//
// ### 1. 大量に返る apex は共用基盤であって、攻撃者のドメインではない
//
// 実測（68 apex / のべ 203,694 ホスト）で、件数の並びはこうなった。
//
//   148,323  dropboxusercontent.com
//    45,915  42web.io
//     8,487  4nmn.com
//       553  cpolar.top
//   ───────  ここに大きな段差がある
//        98  iuqerfsodp9ifjaposdfjhgosurijfaewrwergwff.com
//        72  glara.info
//        17, 12, 12, 12, 11, 11, 10, 8 …
//
// **上の 4 つは誰でも子ドメインを作れる事業者**で、その子は他人のもの。
// 98 と 553 の間に段差があるので、既定の上限は 200 に置く。
//
// これは動的 DNS の判定（lib/tracker.mjs）とは**逆の結論**に見えるが、見ているものが
// 違う。あちらは「同じ登録可能ドメインに索引の IOC が何件ぶら下がるか」で、5〜9 件の
// 帯に攻撃者所有のものが混ざって分けられなかった。こちらは**証明書記録に載っている
// 総数**なので、事業者なら万に届き、攻撃者のドメインなら数十で止まる。
//
// ### 2. ホスティング事業者の既定の名前は手掛かりにならない
//
// `cpanel` `webmail` `webdisk` `cpcalendars` `cpcontacts` `whm` は cPanel が
// 契約時に必ず作るもので、**攻撃者が何をしていたかを何も語らない**。
// `ww16` `ww25` `ww38` はパーキング事業者の付ける前置き。
// 実測（108 apex）でこの手のものが 204 件あり、残った 190 件のほうに `admin` `git`
// `springboot` のような**実際に何かが動いていた跡**が集まっていた。一覧は lib/tracker.mjs。
import fs from "node:fs";
import path from "node:path";
import { parseArgs, readJsonl, writeJson, writeJsonl, byKeys } from "./lib/io.mjs";
import { REPO_ROOT } from "./lib/sources.mjs";
import { isBoilerplateLabel, statedRoles } from "./lib/tracker.mjs";

const args = parseArgs(process.argv.slice(2));
const IN = path.resolve(REPO_ROOT, args.in || "data/ioc/latest");
const CACHE = path.resolve(REPO_ROOT, args.cache || "data/ioc/.cache/crtname");
const CAP = Number(args.cap || 200);
const TOP = Number(args.top || 20);

/* ---------------- 索引が既に知っているもの ---------------- */

const known = new Set();
const iocs = new Map();
for (const f of ["iocs.jsonl", "derived-iocs.jsonl"]) {
  const p = path.join(IN, f);
  if (fs.existsSync(p)) for (const r of readJsonl(p)) {
    iocs.set(r.key, r);
    if (r.key.startsWith("ioc.domain|")) known.add(r.value);
  }
}
const rels = new Map();
for (const l of readJsonl(path.join(IN, "links.jsonl"))) {
  if (!String(l.ioc || "").startsWith("ioc.domain|") || !l.rel) continue;
  const h = l.ioc.slice("ioc.domain|".length);
  if (!rels.has(h)) rels.set(h, new Set());
  rels.get(h).add(l.rel);
}
/** その apex に役割を与えている子が持つ役割をまとめる。兄弟はこれを受け継ぐ */
const rolesOfApex = new Map();
for (const r of iocs.values()) {
  if (!String(r.key).startsWith("ioc.domain|") || !r.registrable) continue;
  const roles = statedRoles(rels.get(r.value));
  if (!roles.length) continue;
  if (!rolesOfApex.has(r.registrable)) rolesOfApex.set(r.registrable, new Set());
  for (const x of roles) rolesOfApex.get(r.registrable).add(x);
}

/* ---------------- 写しを読む ---------------- */

if (!fs.existsSync(CACHE)) {
  console.error(`${CACHE} がありません。先に fetch-crtname.mjs を実行してください。`);
  process.exit(2);
}
const files = fs.readdirSync(CACHE).filter((f) => f.endsWith(".json"));
if (!files.length) { console.error("写しがありません"); process.exit(2); }

const rows = [];
const shared = [];      // 共用基盤として中身を採らなかった apex
let seen = 0, dropBoiler = 0, dropKnown = 0, failedApex = 0;

for (const f of files) {
  let rec;
  try { rec = JSON.parse(fs.readFileSync(path.join(CACHE, f), "utf8")); } catch { continue; }
  const apex = rec.apex;
  if (rec.status !== 200) { failedApex++; continue; }
  const hosts = rec.hosts || [];
  seen += hosts.length;
  if (hosts.length > CAP) {
    // **捨てるのではなく、そういう apex だったと残す**
    shared.push({ apex, hosts: hosts.length });
    continue;
  }
  const roles = [...(rolesOfApex.get(apex) || [])].sort();
  for (const host of hosts) {
    if (host === apex) continue;
    if (!host.endsWith("." + apex)) continue;   // 応答に混ざる別 apex は採らない
    const label = host.slice(0, host.length - apex.length - 1).split(".").pop();
    const boilerplate = isBoilerplateLabel(label);
    if (boilerplate) { dropBoiler++; continue; }
    if (known.has(host)) { dropKnown++; continue; }
    rows.push({ host, apex, apex_roles: roles, label });
  }
}
rows.sort(byKeys("host"));

/* ---------------- 見せる ---------------- */

console.log(`写し ${files.length} apex（取れなかったもの ${failedApex}）/ のべ ${seen.toLocaleString()} ホスト`);
console.log(`  共用基盤として中身を採らなかった apex ${shared.length} 個（上限 ${CAP} 件）`);
for (const s of shared.sort((a, b) => b.hosts - a.hosts).slice(0, TOP)) {
  console.log(`    ${String(s.hosts).padStart(7)}  ${s.apex}`);
}
console.log(`  事業者の定型名として外した ${dropBoiler} / 索引に既にある ${dropKnown}`);
console.log(`\n追う価値のある新しい兄弟 ${rows.length} 件`);

const byApex = new Map();
for (const r of rows) byApex.set(r.apex, (byApex.get(r.apex) || 0) + 1);
for (const [apex, n] of [...byApex].sort((a, b) => b[1] - a[1]).slice(0, TOP)) {
  const roles = [...(rolesOfApex.get(apex) || [])].slice(0, 2).join("/") || "—";
  console.log(`  ${String(n).padStart(4)}  ${apex.slice(0, 34).padEnd(36)} ${roles.slice(0, 30)}`);
  for (const r of rows.filter((x) => x.apex === apex).slice(0, 6)) console.log(`          ${r.host}`);
}

writeJsonl(path.join(IN, "crtname.jsonl"), rows);
writeJson(path.join(IN, "crtname-meta.json"), {
  tool: "tools/ioc/crtname.mjs", schema: 1,
  built_at: new Date().toISOString(),
  cap: CAP,
  apexes: { read: files.length, failed: failedApex, shared_platform: shared.length },
  hosts: { seen, kept: rows.length, boilerplate: dropBoiler, already_known: dropKnown },
  shared_platform: shared.sort((a, b) => b.hosts - a.hosts),
});
console.log(`\n  → ${path.join(IN, "crtname.jsonl")}`);
