#!/usr/bin/env node
// 成果物を**読み直して**検査する。作った側の変数は見ない。
//
//   node validate.mjs
//
// 「出力できた」と「正しい」は別物。CSV を文字列から読み直し、優先度と証拠段階を
// **写しから計算し直して**一致するかを見る。列が GLOBAL_JP_VULN と同じ順であること、
// 禁止したものが混ざっていないことも見る。
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { digest, score, classify } from "../global-jp-vuln/rules.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "../..");
const CFG = JSON.parse(fs.readFileSync(path.join(HERE, "config.json"), "utf8"));

function parseCsv(text) {
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
  const rows = []; let row = [], field = "", q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) { if (c === '"') { if (text[i + 1] === '"') { field += '"'; i++; } else q = false; } else field += c; }
    else if (c === '"') q = true;
    else if (c === ",") { row.push(field); field = ""; }
    else if (c === "\n") { row.push(field); field = ""; rows.push(row); row = []; }
    else if (c === "\r") { /* CRLF */ }
    else field += c;
  }
  if (field.length || row.length) { row.push(field); rows.push(row); }
  const h = rows.shift();
  return { header: h, rows: rows.filter((r) => r.length > 1).map((r) => Object.fromEntries(h.map((k, i) => [k, r[i] ?? ""]))) };
}
const read = (f) => parseCsv(fs.readFileSync(path.join(HERE, f), "utf8"));
const num = (v) => (v === "" ? 0 : Number(v));
const bool = (v) => v === "true";

let failed = 0;
const check = (ok, label, detail = "") => {
  console.log(`  ${ok ? "ok" : "NG"}  ${label}${ok || !detail ? "" : "  — " + detail}`);
  if (!ok) failed++;
};

const S = JSON.parse(fs.readFileSync(path.join(HERE, "abuseipdb_ioc_jp_summary.json"), "utf8"));
const A = read("abuseipdb_ioc_jp_all_90d.csv");
const P1 = read("abuseipdb_ioc_jp_priority_p1.csv");
const P2 = read("abuseipdb_ioc_jp_priority_p2.csv");
const P3 = read("abuseipdb_ioc_jp_reference_p3.csv");
const EX = read("abuseipdb_ioc_jp_excluded.csv");
const all = A.rows;

console.log("== 件数の突き合わせ");
check(all.length === S.population.included, "採用の件数が summary と一致",
  `CSV ${all.length} / summary ${S.population.included}`);
check(P1.rows.length === S.population.P1, "P1 の件数が一致", `${P1.rows.length} / ${S.population.P1}`);
check(P2.rows.length === S.population.P2, "P2 の件数が一致", `${P2.rows.length} / ${S.population.P2}`);
check(P3.rows.length === S.population.P3, "P3 の件数が一致", `${P3.rows.length} / ${S.population.P3}`);
check(EX.rows.length === S.population.excluded, "除外の件数が一致",
  `${EX.rows.length} / ${S.population.excluded}`);
check(P1.rows.length + P2.rows.length + P3.rows.length === all.length,
  "P1+P2+P3 が採用の総数に等しい");
check(all.length + EX.rows.length === S.population.copies_read,
  "採用 + 除外 = 読んだ写しの数（**どれも捨てていない**）",
  `${all.length} + ${EX.rows.length} / ${S.population.copies_read}`);

console.log("\n== 列が GLOBAL_JP_VULN と同じ順か");
const G = parseCsv(fs.readFileSync(path.join(HERE, "../global-jp-vuln/global_jp_vuln_all_90d.csv"), "utf8"));
const gh = G.header.map((h) => h.replace(/^﻿/, ""));
const ah = A.header.map((h) => h.replace(/^﻿/, ""));
check(ah.slice(0, gh.length).join(",") === gh.join(","),
  `前 ${gh.length} 列が GLOBAL_JP_VULN と同一・同順`);
check(ah.length > gh.length, `索引の文脈が後ろに足されている（+${ah.length - gh.length} 列）`);
check(ah.slice(gh.length).every((h) => h.startsWith("ioc_")),
  "足した列はすべて ioc_ で始まる");

console.log("\n== 禁止したものが混ざっていないか");
const body = fs.readFileSync(path.join(HERE, "abuseipdb_ioc_jp_all_90d.csv"), "utf8")
  + fs.readFileSync(path.join(HERE, "abuseipdb_ioc_jp_excluded.csv"), "utf8")
  + JSON.stringify(S);
check(!/reporter_?id/i.test(ah.join(",")), "reporterId の列が無い");
check(!/\breporterId\b/.test(body), "reporterId という語が成果物に無い");
// 鍵は 80 文字の 16 進。AbuseIPDB の鍵の形で引っかけておく
check(!/\b[0-9a-f]{64,}\b/.test(ah.join(",") + JSON.stringify(S.config)), "設定と列名に鍵らしい文字列が無い");
check(!all.some((r) => /^=|^\+|^@/.test(r.isp) || /^=|^\+|^@/.test(r.evidence_example_1 || "")),
  "外部由来の列が表計算の式として始まっていない");
check(all.every((r) => !/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(
  [r.evidence_example_1, r.evidence_example_2, r.evidence_example_3, r.isp].join(""))),
  "コメント由来の列に制御文字が残っていない");

console.log("\n== 写しから計算し直して一致するか");
const COPIES = path.resolve(ROOT, CFG.COPIES_DIR);
const copies = new Map();
for (const d of fs.readdirSync(COPIES)) {
  const sub = path.join(COPIES, d);
  if (!fs.statSync(sub).isDirectory()) continue;
  for (const f of fs.readdirSync(sub)) {
    if (!f.endsWith(".json")) continue;
    let rec = null;
    try { rec = JSON.parse(fs.readFileSync(path.join(sub, f), "utf8")); } catch { continue; }
    if (rec?.ioc && rec.endpoint === "check" && rec.body) copies.set(rec.ioc.slice(rec.ioc.indexOf("|") + 1), rec);
  }
}
check(copies.size === S.population.copies_read, "写しの数が summary と一致",
  `${copies.size} / ${S.population.copies_read}`);
const NOW = new Date(S.collected_at_utc).getTime();
const SINCE = NOW - CFG.REPORT_WINDOW_DAYS * 86400000;
let mismatch = [];
for (const r of all.concat(EX.rows)) {
  const c = copies.get(r.ip_address);
  if (!c) { mismatch.push(`${r.ip_address} 写しが無い`); continue; }
  const rec = digest(r.ip_address, { data: c.body }, CFG.COHORT, { checkedAt: c.fetched_at, since: SINCE });
  const { priority } = classify(rec, NOW);
  const { score: ps } = score(rec, NOW);
  if (priority !== r.priority) mismatch.push(`${r.ip_address} 優先度 ${r.priority} ≠ ${priority}`);
  else if (ps !== num(r.priority_score)) mismatch.push(`${r.ip_address} 点 ${r.priority_score} ≠ ${ps}`);
  else if (String(rec.evidence_level_max) !== String(r.evidence_level_max)) {
    mismatch.push(`${r.ip_address} 証拠段階 ${r.evidence_level_max} ≠ ${rec.evidence_level_max}`);
  } else if (rec.jp_vuln_report_count_90d !== num(r.jp_vuln_report_count_90d)) {
    mismatch.push(`${r.ip_address} 日本の脆弱性報告数が違う`);
  }
  if (mismatch.length >= 5) break;
}
check(!mismatch.length, "優先度・点数・証拠段階・日本の報告数が写しから再現できる",
  mismatch.slice(0, 3).join(" / "));

console.log("\n== 窓が効いているか");
check(all.every((r) => !r.latest_jp_vuln_reported_at_90d
  || new Date(r.latest_jp_vuln_reported_at_90d).getTime() >= SINCE),
  `採用行の最新報告がすべて窓の中（${S.window.start_utc} 以降）`);
check(all.every((r) => num(r.jp_vuln_report_count_90d) <= num(r.jp_report_count_90d)),
  "日本の脆弱性報告 ≦ 日本の報告");
check(all.every((r) => num(r.jp_report_count_90d) <= num(r.total_reports_90d)),
  "日本の報告 ≦ 窓の中の全報告");
check(all.every((r) => num(r.jp_vuln_distinct_reporters_90d) <= num(r.jp_vuln_report_count_90d)),
  "レポーター数 ≦ 報告数");

console.log("\n== 定義どおりの振り分けか");
check(all.every((r) => num(r.jp_vuln_report_count_90d) > 0),
  "採用行はすべて日本の脆弱性報告が 1 件以上");
check(EX.rows.every((r) => bool(r.excluded_from_primary_population)),
  "除外行にはすべて除外の印が付いている");
check(EX.rows.every((r) => r.exclusion_reason),
  "除外行にはすべて理由が書かれている");
check(all.every((r) => !bool(r.research_scanner_flag) || r.research_scanner_confidence !== "high"),
  "高確度の研究スキャナは採用に残っていない");
check(S.marks.research_scanner === all.concat(EX.rows).filter((r) => bool(r.research_scanner_flag)).length,
  "研究スキャナの判定数が summary と一致");
check(S.marks.tor === all.filter((r) => bool(r.is_tor)).length, "Tor 出口の数が summary と一致");

console.log("\n== 並び順");
const PRI = { P1: 1, P2: 2, P3: 3 };
let ordered = true;
for (let i = 1; i < all.length; i++) {
  const a = all[i - 1], b = all[i];
  if (PRI[a.priority] > PRI[b.priority]) { ordered = false; break; }
  if (PRI[a.priority] === PRI[b.priority] && num(a.priority_score) < num(b.priority_score)) { ordered = false; break; }
}
check(ordered, "優先度→点数の降順に並んでいる");
check(all.every((r, i) => num(r.rank) === i + 1), "rank が 1 から連番");

console.log("\n== レポートが CSV と食い違っていないか");
const md = fs.readFileSync(path.join(HERE, "abuseipdb_ioc_jp_report_ja.md"), "utf8");
check(md.includes(`採用 ${S.population.included} 件のうち ${S.marks.tor} 件`),
  "Tor の件数がレポート冒頭と一致");
check(/API も呼んでいません/.test(md), "API を呼んでいないと明記している");
check(/レポーターが日本に所在することは/.test(md), "解釈の注意が書かれている");
check(!/日本向け攻撃元/.test(md.replace(/という列は作/g, "")), "「日本向け攻撃元」と断定していない");

console.log(failed ? `\n${failed} 件 NG` : "\nすべて通りました");
process.exit(failed ? 1 : 0);
