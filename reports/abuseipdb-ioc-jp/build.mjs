#!/usr/bin/env node
// ABUSEIPDB_IOC_JP — **脅威情報の索引が持っている送信元 IP** のうち、日本のレポーターが
// 報告したものを抽出する。防御目的の受動調査のみ。
//
//   node build.mjs [--in data/ioc/.cache/abuseipdb] [--index data/ioc/latest]
//
// ## GLOBAL_JP_VULN との違い
//
// | | GLOBAL_JP_VULN | これ |
// | --- | --- | --- |
// | 母集団 | AbuseIPDB の Blacklist 10 万件 | **索引が持っている IP 4,801 件** |
// | 索引の文脈 | 無い | **アクター名・役割・マルウェア・出典記事が付く** |
// | 取得 | この場で API を呼ぶ | **写しを読むだけ。API は呼ばない** |
//
// 判定規則（カテゴリの分け方・コメントの無害化・証拠の段階・研究スキャナの見分け）は
// `../global-jp-vuln/rules.mjs` を**そのまま**使う。列も揃える。並べて比較するため。
//
// ## 窓の合わせ方
//
// 索引側の写しは 365 日ぶんで取っている。GLOBAL_JP_VULN は 90 日なので、
// **写しの報告 1 件ずつの日時で 90 日に絞り直す**（`digest` の `since`）。
// このとき `total_reports_90d` は AbuseIPDB の `totalReports`（365 日ぶん）ではなく
// 絞ったあとの件数になる。`abuse_confidence_score` だけは AbuseIPDB 自身が
// 出す値で窓を切れないので、**365 日ぶんのまま**である。列の意味が違うので注意。
//
// 窓の終わりは**写しの取得時刻のうち最も新しいもの**にする。`new Date()` を使うと
// 同じ写しから違うものが出てしまう。
//
// ## コメントは信用できない外部入力
//
// 命令として読まない。URL を開かない。実行しない。rules.mjs の `sanitize` が
// HTML と制御文字を落としてメールアドレスを伏せ、`forDisplay` が短く切る。
// 原文は残さず SHA-256 だけ残す。
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  CATEGORIES, digest, score, classify, tsOf, iso, uniq,
} from "../global-jp-vuln/rules.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "../..");
const CFG = JSON.parse(fs.readFileSync(path.join(HERE, "config.json"), "utf8"));
const args = process.argv.slice(2);
const argOf = (f) => { const i = args.indexOf(f); return i >= 0 ? args[i + 1] : null; };
const COPIES = path.resolve(ROOT, argOf("--in") || CFG.COPIES_DIR);
const INDEX = path.resolve(ROOT, argOf("--index") || CFG.INDEX_DIR);

/* ================= 写しを読む ================= */

if (!fs.existsSync(COPIES)) {
  console.error(`${COPIES} に写しがありません。先に tools/ioc/fetch-abuseipdb.mjs を実行してください。`);
  process.exit(1);
}
const files = [];
for (const d of fs.readdirSync(COPIES)) {
  const sub = path.join(COPIES, d);
  if (!fs.statSync(sub).isDirectory()) continue;
  for (const f of fs.readdirSync(sub)) if (f.endsWith(".json")) files.push(path.join(sub, f));
}
files.sort();

const copies = [];
for (const f of files) {
  let rec = null;
  try { rec = JSON.parse(fs.readFileSync(f, "utf8")); } catch { continue; }
  if (!rec?.ioc || rec.endpoint !== "check" || !rec.body) continue;
  copies.push(rec);
}
if (!copies.length) {
  console.error(`${COPIES} に check の写しが 1 件もありません。`);
  process.exit(1);
}
// **窓の終わりは写しから決める。**同じ写しからは何度でも同じものが出るように
const anchorIso = copies.map((c) => c.fetched_at).filter(Boolean).sort().pop();
const NOW = new Date(anchorIso).getTime();
const SINCE = NOW - CFG.REPORT_WINDOW_DAYS * 86400000;
console.log(`写し ${copies.length} 件（取得の最新 ${anchorIso}）`);
console.log(`窓 ${iso(new Date(SINCE))} 〜 ${iso(new Date(NOW))}（${CFG.REPORT_WINDOW_DAYS} 日）`);

/* ================= 索引が何と言っているか ================= */

const readJsonl = (f) => {
  const p = path.join(INDEX, f);
  if (!fs.existsSync(p)) return [];
  return fs.readFileSync(p, "utf8").split("\n").filter(Boolean).map((l) => {
    try { return JSON.parse(l); } catch { return null; }
  }).filter(Boolean);
};
const iocByKey = new Map(readJsonl("iocs.jsonl").map((r) => [r.key, r]));
const actorsOf = new Map(), rolesOf = new Map(), malwareOf = new Map(), articlesOf = new Map();
/** 索引の帳簿にすぎない辺。役割として読むと「ホスト」「収集元」が役割になってしまう */
const BOOKKEEPING = new Set(["収集元", "ホスト", "url", "提出検体", "case.ファミリ",
  "resolves_to", "contacted", "resolved_at", "suggested_threat_label", "観測アクター", "関連"]);
for (const l of readJsonl("links.jsonl")) {
  if (!l.ioc) continue;
  const add = (m, v) => { if (!v) return; if (!m.has(l.ioc)) m.set(l.ioc, new Set()); m.get(l.ioc).add(v); };
  if (l.kind === "actor") add(actorsOf, l.name);
  if (l.kind === "malware") add(malwareOf, l.name);
  if (l.kind === "article") add(articlesOf, l.name);
  if (l.rel && !BOOKKEEPING.has(l.rel) && !String(l.rel).startsWith("attrs.")) add(rolesOf, l.rel);
}
const certsOf = new Map();
for (const c of readJsonl("derived-certs.jsonl")) {
  if (!c.shared || !c.thumbprint) continue;
  for (const k of c.iocs || []) {
    if (!certsOf.has(k)) certsOf.set(k, new Set());
    certsOf.get(k).add(c.thumbprint);
  }
}
const list = (m, k) => [...(m.get(k) || [])].sort().join(";");

/* ================= 畳んで優先度を付ける ================= */

const rows = [];
for (const c of copies) {
  const ip = c.ioc.slice(c.ioc.indexOf("|") + 1);
  // digest は body.data を見るので、写しの形（body が data そのもの）に合わせて包む
  const rec = digest(ip, { data: c.body }, CFG.COHORT, { checkedAt: c.fetched_at, since: SINCE });
  const { priority, reason } = classify(rec, NOW);
  const { score: ps, reasons } = score(rec, NOW);
  const excluded = priority === "EXCLUDED_PRIMARY";
  const ioc = iocByKey.get(c.ioc);
  rows.push({
    ...rec,
    dataset_name: CFG.DATASET, collected_at_utc: anchorIso,
    // Blacklist を母集団にしていないので、この列は空になる
    blacklist_generated_at: "",
    priority, priority_score: ps, priority_reasons: reasons,
    global_jp_vuln_eligible: rec.jp_vuln_report_count_90d > 0,
    excluded_from_primary_population: excluded, exclusion_reason: reason,
    likely_compromised_source: rec.jp_exploited_host_report_count_90d > 0,
    sanitized_evidence_summary:
      `日本の脆弱性報告 ${rec.jp_vuln_report_count_90d} 件（レポーター ${rec.jp_vuln_distinct_reporters_90d} 人）。`
      + `証拠段階 E${rec.evidence_level_max || 0}`
      + `${rec.evidence_terms ? "（" + rec.evidence_terms.split(";").slice(0, 4).join(",") + "）" : ""}。`,
    assessment: excluded ? `主対象から除外: ${reason}`
      : priority === "P1" ? "日本の複数観測者または具体的証拠あり。優先確認を推奨"
        : priority === "P2" ? "日本から脆弱性攻撃として報告。確認を推奨"
          : "日本からの報告はあるが根拠が弱い。参考情報",
    confidence: Number(rec.evidence_level_max || 0) >= 3 ? "高"
      : Number(rec.evidence_level_max || 0) === 2 ? "中" : "低",
    analysis_tags: (() => {
      const t = [];
      if (rec.jp_vuln_report_count_90d > 0) t.push("jp_vuln_observed");
      if (rec.jp_strict_vuln_distinct_reporters_90d >= 2) t.push("jp_strict_reporters_2plus");
      const lv = Number(rec.evidence_level_max || 0);
      if (lv >= 3) t.push("evidence_e3");
      else if (lv === 2) t.push("evidence_e2");
      else if (lv === 1) t.push("evidence_e1");
      else if (rec.jp_vuln_report_count_90d > 0) t.push("evidence_e0");
      if (rec.jp_exploited_host_report_count_90d > 0) t.push("exploited_host");
      if (rec.research_scanner_flag) t.push("research_scanner_" + (rec.research_scanner_confidence || "low"));
      if (rec.reports_truncated) t.push("reports_truncated");
      if (tsOf(rec.latest_jp_vuln_reported_at_90d) >= NOW - 7 * 86400000) t.push("jp_vuln_within_7d");
      if (rec.is_tor) t.push("tor");
      // **索引側の文脈もタグにする。**ここがこのデータセットの存在理由
      if (actorsOf.has(c.ioc)) t.push("ioc_actor_named");
      if (certsOf.has(c.ioc)) t.push("ioc_shared_certificate");
      if (ioc?.noise) t.push("ioc_noise");
      for (const n of String(rec.jp_vuln_category_ids || "").split(";").filter(Boolean))
        t.push("category_" + String(CATEGORIES[Number(n)] || n).toLowerCase().replace(/[^a-z0-9]+/g, "_"));
      return uniq(t).join(";");
    })(),
    /* ---- ここから下が GLOBAL_JP_VULN に無い列。索引が言っていること ---- */
    ioc_key: c.ioc,
    ioc_actors: list(actorsOf, c.ioc),
    ioc_roles: list(rolesOf, c.ioc),
    ioc_malware: list(malwareOf, c.ioc),
    ioc_source_articles: list(articlesOf, c.ioc),
    ioc_shared_certificates: list(certsOf, c.ioc),
    ioc_first_sources: (ioc?.sources || []).slice().sort().join(";"),
    ioc_confidence: (ioc?.confidence || []).slice().sort().join(";"),
    ioc_subnet: ioc?.subnet || "",
    ioc_noise_mark: ioc?.noise || "",
  });
}

const PRI = { P1: 1, P2: 2, P3: 3, EXCLUDED_PRIMARY: 9 };
const ipNum = (ip) => ip.split(".").reduce((a, b) => a * 256 + Number(b), 0);
/**
 * 並びは GLOBAL_JP_VULN と同じ基準に、**アクター名が付いているか**を 1 段だけ足す。
 * 索引の文脈があることがこのデータセットの価値なので、同点ならそちらを上に出す。
 */
rows.sort((a, b) => PRI[a.priority] - PRI[b.priority]
  || b.priority_score - a.priority_score
  || (b.ioc_actors ? 1 : 0) - (a.ioc_actors ? 1 : 0)
  || String(b.latest_jp_vuln_reported_at_90d).localeCompare(String(a.latest_jp_vuln_reported_at_90d))
  || ipNum(a.ip_address) - ipNum(b.ip_address));
rows.forEach((r, i) => { r.rank = i + 1; });

/* ================= 出力 ================= */

const BOM = "﻿";
const deFormula = (s) => (/^[=+\-@\t\r\n]/.test(s) ? "'" + s : s);
const cell = (v, ext) => {
  if (v === null || v === undefined) return "";
  let s = String(v);
  if (ext) s = deFormula(s);
  return /[",\r\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
};
/** GLOBAL_JP_VULN と同じ 59 列。並べて比較できるように順番も変えない */
const SHARED = ["rank", "ip_address", "priority", "priority_score", "priority_reasons", "selection_cohort",
  "dataset_name", "collected_at_utc", "blacklist_generated_at",
  "abuse_confidence_score", "ip_country_code", "usage_type", "isp", "domain", "hostnames",
  "is_tor", "is_whitelisted", "total_reports_90d", "distinct_reporters_90d", "latest_reported_at_90d", "reports_truncated",
  "jp_report_count_90d", "jp_distinct_reporters_90d", "latest_jp_reported_at_90d",
  "jp_vuln_report_count_90d", "jp_vuln_distinct_reporters_90d", "latest_jp_vuln_reported_at_90d",
  "jp_strict_vuln_report_count_90d", "jp_strict_vuln_distinct_reporters_90d", "jp_broad_vuln_report_count_90d",
  "jp_auth_attack_report_count_90d", "jp_scan_only_report_count_90d", "jp_exploited_host_report_count_90d",
  "jp_vuln_category_ids", "jp_vuln_category_names", "jp_vuln_report_ratio",
  "evidence_level_max", "evidence_terms", "sanitized_evidence_summary",
  "evidence_example_1", "evidence_example_2", "evidence_example_3",
  "evidence_comment_sha256", "evidence_latest_at", "evidence_reporter_count",
  "research_scanner_flag", "research_scanner_name", "research_scanner_confidence", "research_scanner_evidence",
  "likely_compromised_source", "global_jp_vuln_eligible", "excluded_from_primary_population", "exclusion_reason",
  "assessment", "confidence", "analysis_tags", "api_status", "http_status", "error_message"];
/** 索引の文脈。**後ろに足す**ので、前 59 列だけ見れば GLOBAL_JP_VULN と同じ */
const INDEX_COLS = ["ioc_key", "ioc_actors", "ioc_roles", "ioc_malware", "ioc_source_articles",
  "ioc_shared_certificates", "ioc_first_sources", "ioc_confidence", "ioc_subnet", "ioc_noise_mark"];
const HEADER = [...SHARED, ...INDEX_COLS];
/** 外部由来の文字列。表計算が式として読まないように先頭へ `'` を足す */
const EXT = new Set(["isp", "domain", "hostnames", "usage_type", "ip_country_code", "research_scanner_evidence",
  "evidence_example_1", "evidence_example_2", "evidence_example_3", "evidence_terms",
  "jp_vuln_category_names", "sanitized_evidence_summary", "error_message",
  "ioc_actors", "ioc_roles", "ioc_malware", "ioc_source_articles", "ioc_noise_mark"]);
const writeCsv = (file, rs) => fs.writeFileSync(path.join(HERE, file),
  BOM + [HEADER.join(","), ...rs.map((r) => HEADER.map((h) => cell(r[h], EXT.has(h))).join(","))].join("\r\n") + "\r\n");

const included = rows.filter((r) => !r.excluded_from_primary_population);
writeCsv("abuseipdb_ioc_jp_all_90d.csv", included);
writeCsv("abuseipdb_ioc_jp_priority_p1.csv", rows.filter((r) => r.priority === "P1"));
writeCsv("abuseipdb_ioc_jp_priority_p2.csv", rows.filter((r) => r.priority === "P2"));
writeCsv("abuseipdb_ioc_jp_reference_p3.csv", rows.filter((r) => r.priority === "P3"));
writeCsv("abuseipdb_ioc_jp_excluded.csv", rows.filter((r) => r.excluded_from_primary_population));

const pri = (p) => rows.filter((r) => r.priority === p).length;
const tally = (rs, f) => {
  const m = new Map();
  for (const r of rs) for (const v of [].concat(f(r))) if (v) m.set(v, (m.get(v) || 0) + 1);
  return [...m].sort((a, b) => (b[1] - a[1]) || (a[0] < b[0] ? -1 : 1));
};
const jpAny = rows.filter((r) => r.jp_report_count_90d > 0);
const summary = {
  dataset: CFG.DATASET,
  generated_from: "写しのみ。API は呼んでいない",
  collected_at_utc: anchorIso,
  window: { start_utc: iso(new Date(SINCE)), end_utc: iso(new Date(NOW)), days: CFG.REPORT_WINDOW_DAYS },
  config: CFG,
  population: {
    copies_read: copies.length,
    jp_reported: jpAny.length,
    eligible_jp_vuln: rows.filter((r) => r.jp_vuln_report_count_90d > 0).length,
    included: included.length,
    P1: pri("P1"), P2: pri("P2"), P3: pri("P3"), excluded: pri("EXCLUDED_PRIMARY"),
  },
  evidence_levels: Object.fromEntries(tally(included, (r) => `E${r.evidence_level_max || 0}`)),
  jp_vuln_categories: Object.fromEntries(tally(included, (r) => String(r.jp_vuln_category_names || "").split(";"))),
  jp_vuln_reporter_distribution: Object.fromEntries(
    tally(included, (r) => (r.jp_vuln_distinct_reporters_90d >= 5 ? "5+" : String(r.jp_vuln_distinct_reporters_90d)))),
  top_countries: tally(included, (r) => r.ip_country_code).slice(0, 12),
  top_isp: tally(included, (r) => r.isp).slice(0, 12),
  top_usage_type: tally(included, (r) => r.usage_type),
  ioc_context: {
    actor_named: included.filter((r) => r.ioc_actors).length,
    with_role: included.filter((r) => r.ioc_roles).length,
    with_malware: included.filter((r) => r.ioc_malware).length,
    with_shared_certificate: included.filter((r) => r.ioc_shared_certificates).length,
    top_actors: tally(included, (r) => String(r.ioc_actors || "").split(";")).slice(0, 20),
  },
  marks: {
    tor: included.filter((r) => r.is_tor).length,
    whitelisted: included.filter((r) => r.is_whitelisted).length,
    research_scanner: rows.filter((r) => r.research_scanner_flag).length,
    reports_truncated: included.filter((r) => r.reports_truncated).length,
  },
  exploited_host_ips: included.filter((r) => r.likely_compromised_source).length,
  exclusion_reasons: Object.fromEntries(tally(rows.filter((r) => r.excluded_from_primary_population),
    (r) => r.exclusion_reason)),
};
const stable = (v) => JSON.stringify(v, (k, x) =>
  (x && typeof x === "object" && !Array.isArray(x)
    ? Object.fromEntries(Object.entries(x).sort(([a], [b]) => (a < b ? -1 : 1)))
    : x), 2);
fs.writeFileSync(path.join(HERE, "abuseipdb_ioc_jp_summary.json"), stable(summary) + "\n");

console.log(`\n日本からの報告あり ${jpAny.length} 件 / 脆弱性カテゴリあり ${summary.population.eligible_jp_vuln} 件`);
console.log(`P1 ${pri("P1")} / P2 ${pri("P2")} / P3 ${pri("P3")} / 除外 ${pri("EXCLUDED_PRIMARY")}`);
console.log(`索引がアクター名を付けている採用 IP: ${summary.ioc_context.actor_named} 件`);
console.log(`印: Tor 出口 ${summary.marks.tor} / 除外一覧 ${summary.marks.whitelisted}`
  + ` / 研究スキャナ ${summary.marks.research_scanner}`);
