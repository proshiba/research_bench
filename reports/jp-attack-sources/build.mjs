#!/usr/bin/env node
// JP_ATTACK_SOURCES — AbuseIPDB をもとに、**日本のレポーターが攻撃として報告した
// 送信元 IP** を集める。GLOBAL_JP_VULN より広い切り口（脆弱性だけに限らない）。
//
//   node build.mjs
//
// **写しだけを見る。API は呼ばない。** 同じ写しからは何度でも同じものが出る。
// 取得は `../global-jp-vuln/build.mjs --resume` が担う。
//
// ## GLOBAL_JP_VULN との違い
//
// GLOBAL_JP_VULN は **脆弱性カテゴリ（16,21,23,15）だけ**を採った。そのため
// DDoS・フィッシング・詐称・詐欺で日本から報告されている IP が落ちていた。
// ここは `tiers.mjs` の A1〜A4 を攻撃として採る。
//
// ## 「攻撃」をどこで切るかは tiers.mjs にある
//
// VPN を使っていることは攻撃ではない。オープンプロキシも攻撃ではない。
// 走査しただけも攻撃と呼ばない。**まとめて「通報あり」と数えると、VPN を
// 使っているだけの IP が攻撃元の一覧に入る。** 段に分けて、どの段も数えて出す。
//
// ## 分からないものを負に数えない
//
// `jp_all_categories` を持たない古い行は、**カテゴリの内訳をまだ数えていない**
// という意味で「該当なし」ではない。分母を分けて数え、レポートに出す。
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { CATEGORIES, iso, uniq } from "../global-jp-vuln/rules.mjs";
import { TIERS, ATTACK_TIERS, COVERED, tierCounts, isAttack, worstTier } from "./tiers.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "../..");
const CFG = JSON.parse(fs.readFileSync(path.join(HERE, "config.json"), "utf8"));

if (!COVERED.ok) {
  console.error(`tiers.mjs が ${COVERED.missing.join(",")} を取りこぼしています。段に入れてください。`);
  process.exit(1);
}

/* ================= 写しを読む ================= */

const checksFile = path.resolve(ROOT, CFG.CHECKS);
if (!fs.existsSync(checksFile)) {
  console.error(`${checksFile} がありません。先に ../global-jp-vuln/build.mjs を実行してください。`);
  process.exit(1);
}
/** 同じ IP が複数回出たら**新しい方を採る**（引き直しているので） */
const byIp = new Map();
let broken = 0;
for (const line of fs.readFileSync(checksFile, "utf8").split("\n")) {
  if (!line) continue;
  let r = null;
  try { r = JSON.parse(line); } catch { broken++; continue; }
  if (!r?.ip_address) { broken++; continue; }
  const prev = byIp.get(r.ip_address);
  if (!prev || String(r.checked_at_utc || "") >= String(prev.checked_at_utc || "")) byIp.set(r.ip_address, r);
}
const checks = [...byIp.values()];
const ok = checks.filter((r) => r.api_status === "ok");
console.log(`写し ${checks.length} IP（成功 ${ok.length} / 失敗 ${checks.length - ok.length}`
  + `${broken ? ` / 壊れた行 ${broken}` : ""}）`);

/** 窓の終わり。**写しから決める。**`new Date()` を使うと同じ写しから違うものが出る */
const anchorIso = ok.map((r) => r.checked_at_utc).filter(Boolean).sort().pop();
const NOW = new Date(anchorIso).getTime();

/* ================= 母集団の素性 ================= */

const snapFile = path.resolve(ROOT, CFG.BLACKLIST_SNAPSHOT);
let snap = null;
if (fs.existsSync(snapFile)) {
  const j = JSON.parse(fs.readFileSync(snapFile, "utf8"));
  snap = { generated_at: j.generatedAt, entries: (j.entries || []).length, fetched_at: j.fetched_at };
}

/* ================= 索引が何か言っているか ================= */

const readJsonl = (f) => {
  const p = path.join(ROOT, CFG.INDEX_DIR, f);
  if (!fs.existsSync(p)) return [];
  return fs.readFileSync(p, "utf8").split("\n").filter(Boolean)
    .map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
};
const inIndex = new Set();
for (const r of [...readJsonl("iocs.jsonl"), ...readJsonl("derived-iocs.jsonl")]) {
  if (String(r.key || "").startsWith("ioc.ipv4|")) inIndex.add(r.key.slice(9));
}
const actorsOf = new Map();
for (const l of readJsonl("links.jsonl")) {
  if (l.kind !== "actor" || !String(l.ioc || "").startsWith("ioc.ipv4|")) continue;
  const ip = l.ioc.slice(9);
  if (!actorsOf.has(ip)) actorsOf.set(ip, new Set());
  actorsOf.get(ip).add(l.name);
}

/* ================= 1 IP ずつ ================= */

/**
 * **分母を 2 段に分ける。**
 *
 * `jp_report_count_90d` は古い畳み方にも入っているので、「日本からの報告があるか」は
 * **写し全件で数えられる**。一方 `jp_all_categories` は新しい畳み方にしか無いので、
 * **段の内訳は引き直した写しに限られる**。
 *
 * この 2 つを同じ分母で語ると、引き直していない IP を「攻撃ではない」に数えてしまう。
 */
const measured = ok.filter((r) => r.jp_all_categories_measured);
const unmeasured = ok.filter((r) => !r.jp_all_categories_measured);
/** 写し全件での「日本からの報告あり」。段の判定はできないが件数は言える */
const jpAnyAll = ok.filter((r) => (r.jp_report_count_90d || 0) > 0);
/** 段まで判定できるもの。以降の行はここからしか作らない */
const jpAny = measured.filter((r) => (r.jp_report_count_90d || 0) > 0);

const rows = [];
for (const r of jpAny) {
  const { tiers, unknown } = tierCounts(r.jp_all_categories);
  const worst = worstTier(r.jp_all_categories);
  const attack = isAttack(r.jp_all_categories);
  const catIds = String(r.jp_all_categories || "").split(";").filter(Boolean)
    .map((p) => Number(p.split(":")[0])).sort((a, b) => a - b);
  rows.push({
    ip_address: r.ip_address,
    /** **攻撃として数えたか。**段は tiers.mjs で決めている */
    is_jp_attack_source: attack,
    worst_tier: worst,
    worst_tier_label: worst ? TIERS[worst].label : "",
    /* ---- 日本の報告 ---- */
    jp_report_count_90d: r.jp_report_count_90d ?? 0,
    jp_distinct_reporters_90d: r.jp_distinct_reporters_90d ?? 0,
    latest_jp_reported_at_90d: r.latest_jp_reported_at_90d || "",
    jp_uncategorized_report_count_90d: r.jp_uncategorized_report_count_90d ?? "",
    jp_category_ids: catIds.join(";"),
    jp_category_names: catIds.map((c) => CATEGORIES[c] || `unknown(${c})`).join(";"),
    jp_all_categories_raw: r.jp_all_categories || "",
    /* ---- 段ごとのカテゴリ付与回数（報告件数ではない） ---- */
    tier_A1_intrusion: tiers.A1, tier_A2_auth: tiers.A2, tier_A3_dos: tiers.A3,
    tier_A4_fraud: tiers.A4, tier_A5_scan_only: tiers.A5, tier_B_spam_bot: tiers.B,
    tier_C_attribute: tiers.C,
    unknown_category_ids: unknown.sort((a, b) => a - b).join(";"),
    /* ---- GLOBAL_JP_VULN が見ていた狭い切り口 ---- */
    jp_vuln_report_count_90d: r.jp_vuln_report_count_90d ?? 0,
    jp_vuln_distinct_reporters_90d: r.jp_vuln_distinct_reporters_90d ?? 0,
    jp_strict_vuln_report_count_90d: r.jp_strict_vuln_report_count_90d ?? 0,
    jp_exploited_host_report_count_90d: r.jp_exploited_host_report_count_90d ?? 0,
    evidence_level_max: r.evidence_level_max === "" || r.evidence_level_max === undefined
      ? "" : r.evidence_level_max,
    evidence_terms: r.evidence_terms || "",
    /** **GLOBAL_JP_VULN では落ちていたか。**この列がこのデータセットの存在理由 */
    missed_by_global_jp_vuln: attack && (r.jp_vuln_report_count_90d ?? 0) === 0,
    /* ---- 全体（日本に限らない） ---- */
    abuse_confidence_score: r.abuse_confidence_score ?? "",
    total_reports_90d: r.total_reports_90d ?? "",
    distinct_reporters_90d: r.distinct_reporters_90d ?? "",
    reports_truncated: r.reports_truncated === true,
    /* ---- 所在と印 ---- */
    ip_country_code: r.ip_country_code || "",
    usage_type: r.usage_type || "",
    isp: r.isp || "",
    domain: r.domain || "",
    is_tor: r.is_tor === true,
    is_whitelisted: r.is_whitelisted === true,
    research_scanner_flag: r.research_scanner_flag === true,
    research_scanner_name: r.research_scanner_name || "",
    research_scanner_confidence: r.research_scanner_confidence || "",
    /* ---- 索引 ---- */
    in_threat_index: inIndex.has(r.ip_address),
    index_actors: [...(actorsOf.get(r.ip_address) || [])].sort().join(";"),
    checked_at_utc: r.checked_at_utc || "",
  });
}

/**
 * **日本の観測者数で上から並べてはいけない。**
 *
 * 実測（2026-10-14）: 日本の観測者数は **45 人で天井**になり、分布は 34〜45 人に
 * 滑らかに向かう。つまりこの数が測っているのは「どれだけ狙われたか」ではなく
 * **「日本にある AbuseIPDB のセンサーのうち何台が見たか」**である。
 *
 * 45 人ということは「日本のほぼ全センサーが見た」で、それは
 * **インターネット全域を騒がしく走査している先**を意味する。標的型の逆だ。
 * 実際この上位は全件 E0（具体的な攻撃証跡なし）だった。
 *
 * そこで**証拠の具体性を観測者数より先に見る**。E3/E2 が付いているものは
 * コメントに攻撃の中身が書かれており、そちらが人の確認に値する。
 */
const TIER_ORDER = { A1: 1, A2: 2, A3: 3, A4: 4, A5: 5, B: 6, C: 7, "": 8 };
const ipNum = (ip) => (ip.includes(":") ? Number.MAX_SAFE_INTEGER
  : ip.split(".").reduce((a, b) => a * 256 + Number(b), 0));
const evOf = (r) => (r.evidence_level_max === "" ? -1 : Number(r.evidence_level_max));
rows.sort((a, b) => (a.is_jp_attack_source === b.is_jp_attack_source ? 0 : a.is_jp_attack_source ? -1 : 1)
  // 高確度の研究スキャナは主対象から外すので最後に回す
  || (a.research_scanner_confidence === "high" ? 1 : 0) - (b.research_scanner_confidence === "high" ? 1 : 0)
  || TIER_ORDER[a.worst_tier] - TIER_ORDER[b.worst_tier]
  || evOf(b) - evOf(a)
  || b.jp_distinct_reporters_90d - a.jp_distinct_reporters_90d
  || b.jp_report_count_90d - a.jp_report_count_90d
  || ipNum(a.ip_address) - ipNum(b.ip_address));
rows.forEach((r, i) => { r.rank = i + 1; });

/**
 * 観測者数の天井を**測って残す**。これを出さないと、上位が騒がしい走査器で
 * 埋まっている理由が読む側に分からない。
 */
const reporterCeiling = (() => {
  const vals = rows.filter((r) => r.is_jp_attack_source).map((r) => r.jp_distinct_reporters_90d);
  const hist = new Map();
  for (const v of vals) hist.set(v, (hist.get(v) || 0) + 1);
  const max = Math.max(0, ...vals);
  return {
    max_jp_reporters: max,
    ips_at_90pct_of_max: vals.filter((v) => v >= Math.floor(max * 0.9)).length,
    top_values: [...hist].sort((a, b) => b[0] - a[0]).slice(0, 12).map(([v, n]) => `${v}人:${n}`),
    note: "観測者数は日本のセンサー台数で上限が決まる。狙われ度ではない",
  };
})();

/* ================= 出力 ================= */

const BOM = "﻿";
const deFormula = (s) => (/^[=+\-@\t\r\n]/.test(s) ? "'" + s : s);
const cell = (v, ext) => {
  if (v === null || v === undefined) return "";
  let s = String(v);
  if (ext) s = deFormula(s);
  return /[",\r\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
};
const HEADER = ["rank", ...Object.keys(rows[0] || {}).filter((k) => k !== "rank")];
const EXT = new Set(["isp", "domain", "usage_type", "ip_country_code", "jp_category_names",
  "evidence_terms", "index_actors", "research_scanner_name", "worst_tier_label"]);
const writeCsv = (file, rs) => fs.writeFileSync(path.join(HERE, file),
  BOM + [HEADER.join(","), ...rs.map((r) => HEADER.map((h) => cell(r[h], EXT.has(h))).join(","))].join("\r\n") + "\r\n");

/**
 * **高確度の研究スキャナは主対象から外す。消さずに別の表に出す。**
 *
 * 実測では攻撃集合 4,967 件のうち 568 件（11%）が Stretchoid・Shadowserver・
 * Censys・BinaryEdge などだった。これらはインターネット全域を計測している
 * 正規のプロジェクトで、日本のセンサーが「攻撃」として通報するのは自然だが、
 * **攻撃元の一覧に混ぜると母集団が汚れる**。GLOBAL_JP_VULN も同じ規則で外している。
 *
 * 判定は hostname・domain・ISP の**名乗り**で行う。クラウドの AS に属するという
 * だけでは判定しない。
 */
const allAttacks = rows.filter((r) => r.is_jp_attack_source);
const scanners = allAttacks.filter((r) => r.research_scanner_confidence === "high");
const attacks = allAttacks.filter((r) => r.research_scanner_confidence !== "high");
const nonAttacks = rows.filter((r) => !r.is_jp_attack_source);
const missed = attacks.filter((r) => r.missed_by_global_jp_vuln);
writeCsv("jp_attack_sources_all.csv", attacks);
writeCsv("jp_attack_sources_tier_a1.csv", attacks.filter((r) => r.worst_tier === "A1"));
writeCsv("jp_attack_sources_missed_by_vuln_cut.csv", missed);
writeCsv("jp_attack_sources_excluded_scanners.csv", scanners);
writeCsv("jp_reported_not_attack.csv", nonAttacks);

const tally = (rs, f) => {
  const m = new Map();
  for (const r of rs) for (const v of [].concat(f(r))) {
    if (v === "" || v === undefined || v === null) continue;
    m.set(String(v), (m.get(String(v)) || 0) + 1);
  }
  return [...m].sort((a, b) => (b[1] - a[1]) || (a[0] < b[0] ? -1 : 1));
};
const summary = {
  dataset: CFG.DATASET,
  generated_from: "写しのみ。API は呼んでいない",
  collected_through_utc: anchorIso,
  window_days: CFG.REPORT_WINDOW_DAYS,
  blacklist_snapshot: snap,
  /** **分母。**引けていない IP を「報告なし」に数えないため */
  coverage: {
    checks_in_cache: checks.length,
    api_ok: ok.length,
    api_failed: checks.length - ok.length,
    broken_lines: broken,
    jp_categories_measured: measured.length,
    jp_categories_unmeasured: unmeasured.length,
    unmeasured_with_jp_report: unmeasured.filter((r) => (r.jp_report_count_90d || 0) > 0).length,
    blacklist_entries: snap?.entries ?? null,
    unchecked_candidates: snap ? Math.max(0, snap.entries - checks.length) : null,
  },
  population: {
    /** 写し全件が分母。古い畳み方でもこの数は出せる */
    with_jp_report_all_copies: jpAnyAll.length,
    with_jp_report_ratio: ok.length ? Number((jpAnyAll.length / ok.length).toFixed(4)) : 0,
    /** ここから下は**段まで判定できた写しだけ**が分母 */
    tier_judgeable: measured.length,
    with_jp_report: jpAny.length,
    /** A1〜A4 に当たったもの全部（研究スキャナを含む） */
    attack_tier_matched: allAttacks.length,
    /** そこから高確度の研究スキャナを外した主対象 */
    jp_attack_sources: attacks.length,
    excluded_research_scanners: scanners.length,
    jp_reported_not_attack: nonAttacks.length,
    missed_by_global_jp_vuln: missed.length,
  },
  jp_reporter_ceiling: reporterCeiling,
  excluded_scanner_names: Object.fromEntries(tally(scanners, (r) => r.research_scanner_name)),
  tier_definition: Object.fromEntries(Object.entries(TIERS).map(([k, t]) =>
    [k, { label: t.label, categories: t.ids.map((i) => `${i} ${CATEGORIES[i]}`), counted_as_attack: t.attack }])),
  attack_tiers: ATTACK_TIERS,
  by_worst_tier: Object.fromEntries(tally(rows, (r) => `${r.worst_tier} ${r.worst_tier_label}`)),
  jp_categories: Object.fromEntries(tally(attacks, (r) => String(r.jp_category_names || "").split(";"))),
  jp_reporter_distribution: Object.fromEntries(
    tally(attacks, (r) => (r.jp_distinct_reporters_90d >= 5 ? "5+" : String(r.jp_distinct_reporters_90d)))),
  evidence_levels: Object.fromEntries(tally(attacks, (r) => (r.evidence_level_max === "" ? "" : `E${r.evidence_level_max}`))),
  top_countries: tally(attacks, (r) => r.ip_country_code).slice(0, 15),
  top_isp: tally(attacks, (r) => r.isp).slice(0, 15),
  top_usage_type: tally(attacks, (r) => r.usage_type),
  marks: {
    tor: attacks.filter((r) => r.is_tor).length,
    whitelisted: attacks.filter((r) => r.is_whitelisted).length,
    research_scanner: attacks.filter((r) => r.research_scanner_flag).length,
    research_scanner_high: attacks.filter((r) => r.research_scanner_confidence === "high").length,
    reports_truncated: attacks.filter((r) => r.reports_truncated).length,
    exploited_host: attacks.filter((r) => r.jp_exploited_host_report_count_90d > 0).length,
  },
  threat_index: {
    already_present: attacks.filter((r) => r.in_threat_index).length,
    with_actor: attacks.filter((r) => r.index_actors).length,
    top_actors: tally(attacks, (r) => String(r.index_actors || "").split(";")).slice(0, 20),
  },
  unknown_categories: uniq(rows.flatMap((r) => String(r.unknown_category_ids || "").split(";")).filter(Boolean)).sort(),
};
const stable = (v) => JSON.stringify(v, (k, x) =>
  (x && typeof x === "object" && !Array.isArray(x)
    ? Object.fromEntries(Object.entries(x).sort(([a], [b]) => (a < b ? -1 : 1)))
    : x), 2);
fs.writeFileSync(path.join(HERE, "jp_attack_sources_summary.json"), stable(summary) + "\n");

console.log(`写し全件での「日本からの報告あり」: ${jpAnyAll.length} / ${ok.length} IP`
  + `（${Math.round(summary.population.with_jp_report_ratio * 100)}%）`);
console.log(`段まで判定できた写し ${measured.length} 件 → 日本からの報告がある IP ${jpAny.length} 件`);
console.log(`  A1〜A4 に当たった: ${allAttacks.length} 件`);
console.log(`  うち**主対象**（高確度の研究スキャナ ${scanners.length} 件を除く）: ${attacks.length} 件`);
console.log(`  攻撃ではない（偵察のみ・スパム・属性）: ${nonAttacks.length} 件`);
console.log(`  **GLOBAL_JP_VULN の脆弱性限定では落ちていた: ${missed.length} 件**`);
for (const [k, v] of Object.entries(summary.by_worst_tier)) console.log(`    ${k.padEnd(18)} ${String(v).padStart(5)}`);
if (summary.coverage.jp_categories_unmeasured) {
  console.log(`  覚え書き: カテゴリの内訳をまだ数えていない IP ${summary.coverage.jp_categories_unmeasured} 件`
    + `（うち日本の報告あり ${summary.coverage.unmeasured_with_jp_report} 件）`);
}
