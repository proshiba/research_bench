#!/usr/bin/env node
// 成果物を**読み直して**検査する。作った側の変数は見ない。
//
//   node validate.mjs
//
// このデータセットは「どこで攻撃と切るか」が結論を決めるので、
// **段の判定を写しから計算し直して一致するか**を重く見る。
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { TIERS, ATTACK_TIERS, COVERED, tierCounts, isAttack, worstTier } from "./tiers.mjs";

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
  const h = rows.shift().map((x) => x.replace(/^﻿/, ""));
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

const S = JSON.parse(fs.readFileSync(path.join(HERE, "jp_attack_sources_summary.json"), "utf8"));
const A = read("jp_attack_sources_all.csv");
const A1 = read("jp_attack_sources_tier_a1.csv");
const M = read("jp_attack_sources_missed_by_vuln_cut.csv");
const N = read("jp_reported_not_attack.csv");
const md = fs.readFileSync(path.join(HERE, "jp_attack_sources_report_ja.md"), "utf8");
const attacks = A.rows;

console.log("== 段の定義そのもの");
check(COVERED.ok, "23 カテゴリすべてがどこかの段に入っている（抜けると黙って数え落とす）",
  COVERED.missing.join(","));
const allIds = Object.values(TIERS).flatMap((t) => t.ids);
check(new Set(allIds).size === allIds.length, "同じカテゴリが 2 つの段に入っていない");
check(ATTACK_TIERS.length > 0 && ATTACK_TIERS.every((k) => TIERS[k].attack),
  "攻撃として数える段が攻撃印と一致");
check(!ATTACK_TIERS.includes("A5") && !ATTACK_TIERS.includes("C"),
  "**走査のみと属性を攻撃に数えていない**（VPN が攻撃元の一覧に入らないため）");
check(!TIERS.C.attack && TIERS.C.ids.includes(13), "VPN(13) が攻撃に数えられていない");
check(!TIERS.A5.attack && TIERS.A5.ids.includes(14), "ポートスキャン(14) が攻撃に数えられていない");

console.log("\n== 件数の突き合わせ");
check(attacks.length === S.population.jp_attack_sources, "攻撃 CSV の行数が summary と一致",
  `${attacks.length} / ${S.population.jp_attack_sources}`);
check(N.rows.length === S.population.jp_reported_not_attack, "非攻撃 CSV の行数が一致");
check(M.rows.length === S.population.missed_by_global_jp_vuln, "新規分 CSV の行数が一致");
const SC = read("jp_attack_sources_excluded_scanners.csv");
check(SC.rows.length === S.population.excluded_research_scanners,
  "除外した研究スキャナの CSV の行数が一致");
check(attacks.length + SC.rows.length === S.population.attack_tier_matched,
  "主対象 + 除外した研究スキャナ = 攻撃段に当たった数");
check(attacks.length + SC.rows.length + N.rows.length === S.population.with_jp_report,
  "主対象 + 研究スキャナ + 非攻撃 = 日本からの報告がある IP（**どれも捨てていない**）",
  `${attacks.length} + ${SC.rows.length} + ${N.rows.length} / ${S.population.with_jp_report}`);
check(!attacks.some((r) => r.research_scanner_confidence === "high"),
  "**主対象に高確度の研究スキャナが残っていない**");
check(SC.rows.every((r) => r.research_scanner_confidence === "high" && bool(r.is_jp_attack_source)),
  "除外した行はすべて高確度の研究スキャナかつ攻撃段");
check(A1.rows.length === attacks.filter((r) => r.worst_tier === "A1").length, "A1 の CSV の行数が一致");
const ips = new Set(attacks.map((r) => r.ip_address));
check(ips.size === attacks.length, "攻撃 CSV に IP の重複が無い");
check(!attacks.some((r) => N.rows.some((x) => x.ip_address === r.ip_address)),
  "攻撃と非攻撃に同じ IP が入っていない");

console.log("\n== 段の判定を写しから計算し直す");
const checksFile = path.resolve(ROOT, CFG.CHECKS);
const byIp = new Map();
for (const line of fs.readFileSync(checksFile, "utf8").split("\n")) {
  if (!line) continue;
  try {
    const r = JSON.parse(line);
    if (!r?.ip_address) continue;
    const p = byIp.get(r.ip_address);
    if (!p || String(r.checked_at_utc || "") >= String(p.checked_at_utc || "")) byIp.set(r.ip_address, r);
  } catch { /* 壊れた行は無視 */ }
}
check(byIp.size === S.coverage.checks_in_cache, "写しの固有 IP 数が summary と一致",
  `${byIp.size} / ${S.coverage.checks_in_cache}`);
let bad = [];
for (const r of attacks.concat(SC.rows, N.rows)) {
  const c = byIp.get(r.ip_address);
  if (!c) { bad.push(`${r.ip_address} 写しが無い`); continue; }
  if (!c.jp_all_categories_measured) { bad.push(`${r.ip_address} 段を数えていない写しから行が出ている`); continue; }
  if ((c.jp_all_categories || "") !== r.jp_all_categories_raw) { bad.push(`${r.ip_address} カテゴリの生値が違う`); continue; }
  const t = tierCounts(c.jp_all_categories).tiers;
  if (t.A1 !== num(r.tier_A1_intrusion) || t.A2 !== num(r.tier_A2_auth)
    || t.A3 !== num(r.tier_A3_dos) || t.A4 !== num(r.tier_A4_fraud)
    || t.A5 !== num(r.tier_A5_scan_only) || t.B !== num(r.tier_B_spam_bot)
    || t.C !== num(r.tier_C_attribute)) { bad.push(`${r.ip_address} 段の数が違う`); continue; }
  if (worstTier(c.jp_all_categories) !== r.worst_tier) { bad.push(`${r.ip_address} 最も重い段が違う`); continue; }
  if (isAttack(c.jp_all_categories) !== bool(r.is_jp_attack_source)) { bad.push(`${r.ip_address} 攻撃判定が違う`); continue; }
  if (num(r.jp_report_count_90d) !== (c.jp_report_count_90d ?? 0)) { bad.push(`${r.ip_address} 日本の報告数が違う`); continue; }
  if (bad.length >= 5) break;
}
check(!bad.length, "段・最も重い段・攻撃判定・日本の報告数が写しから再現できる", bad.slice(0, 3).join(" / "));

console.log("\n== 攻撃判定が定義どおりか");
check(attacks.every((r) => ATTACK_TIERS.some((k) => num(r[{
  A1: "tier_A1_intrusion", A2: "tier_A2_auth", A3: "tier_A3_dos", A4: "tier_A4_fraud" }[k]]) > 0)),
  "攻撃 CSV の全行に A1〜A4 のいずれかが 1 以上ある");
check(N.rows.every((r) => ATTACK_TIERS.every((k) => num(r[{
  A1: "tier_A1_intrusion", A2: "tier_A2_auth", A3: "tier_A3_dos", A4: "tier_A4_fraud" }[k]]) === 0)),
  "非攻撃 CSV の全行に A1〜A4 がひとつも無い");
check(attacks.every((r) => bool(r.is_jp_attack_source)), "攻撃 CSV の全行に攻撃印が付いている");
check(M.rows.every((r) => num(r.jp_vuln_report_count_90d) === 0 && bool(r.is_jp_attack_source)),
  "**新規分は全行が「脆弱性報告 0 かつ攻撃」**（脆弱性限定なら落ちていたもの）");

console.log("\n== 部分集合として筋が通っているか");
check(attacks.every((r) => num(r.jp_report_count_90d) > 0), "全行が日本の報告 1 件以上");
check(attacks.every((r) => num(r.jp_distinct_reporters_90d) <= num(r.jp_report_count_90d)),
  "日本の観測者数 ≦ 日本の報告数");
check(attacks.every((r) => num(r.jp_report_count_90d) <= num(r.total_reports_90d) || bool(r.reports_truncated)),
  "日本の報告 ≦ 全報告（配列が切れた行は除く）");
check(attacks.every((r) => num(r.jp_vuln_report_count_90d) <= num(r.jp_report_count_90d)),
  "日本の脆弱性報告 ≦ 日本の報告");
check(!S.unknown_categories.length, "どの段にも入らないカテゴリが出ていない",
  S.unknown_categories.join(","));

console.log("\n== 標準の窓（30 日）");
const P = S.primary_window;
const TH = S.thresholds_30d;
const C30 = read("jp_attack_sources_30d_confirmed.csv");
const PEND = read("jp_attack_sources_30d_pending_refetch.csv");
const NA30 = read("jp_attack_sources_30d_not_attack.csv");
const STALE = read("jp_attack_sources_90d_only.csv");
check(P.days === CFG.PRIMARY_WINDOW_DAYS, "標準の窓が設定と一致", `${P.days} / ${CFG.PRIMARY_WINDOW_DAYS}`);
check(C30.rows.length === P.confirmed, "確定 CSV の行数が summary と一致");
check(PEND.rows.length === P.pending_refetch, "引き直し待ち CSV の行数が一致");
check(STALE.rows.length === P.no_jp_report_in_window, "窓の外 CSV の行数が一致");
check(NA30.rows.length === P.reported_but_not_attack_in_window,
  "窓内だが攻撃でない CSV の行数が一致");
check(C30.rows.length + PEND.rows.length + NA30.rows.length + STALE.rows.length === attacks.length,
  "確定 + 待ち + 窓内だが攻撃でない + 窓の外 = 主対象（**どれも捨てていない**）",
  `${C30.rows.length} + ${PEND.rows.length} + ${NA30.rows.length} + ${STALE.rows.length} / ${attacks.length}`);
check(NA30.rows.every((r) => r.jp_30d_method === "counted" && num(r.jp_attack_report_count_30d) === 0
  && r.jp_has_report_30d === "true"),
  "窓内だが攻撃でない行は、数えてあり・攻撃 0 件・窓内に報告ありのすべてを満たす");
check(C30.rows.every((r) => r.jp_30d_method === "counted"),
  "**確定 CSV は全行が counted**（推定を混ぜていない）");
check(C30.rows.every((r) => num(r.jp_attack_report_count_30d) > 0),
  "確定 CSV は全行が 30 日以内の攻撃報告 1 件以上");
check(PEND.rows.every((r) => r.jp_30d_method === "latest_only"),
  "引き直し待ちは全行が latest_only");
check(PEND.rows.every((r) => r.jp_report_count_30d === ""),
  "**引き直し待ちの 30 日件数は空欄**（0 と書いて負に数えていない）");
check(TH.denominator === C30.rows.length, "しきい値の分母が確定 CSV の行数と一致");
// しきい値は単調減少でなければならない
let mono = true;
const ns = [1, 2, 3, 5, 10];
for (let i = 1; i < ns.length; i++) {
  if (TH[`attack_reports_ge_${ns[i]}`] > TH[`attack_reports_ge_${ns[i - 1]}`]) { mono = false; break; }
  if (TH[`reporters_ge_${ns[i]}`] > TH[`reporters_ge_${ns[i - 1]}`]) { mono = false; break; }
}
check(mono, "しきい値が単調に減っている（N 件以上は N+1 件以上を含む）");
check(TH.attack_reports_ge_1 === C30.rows.length, "1 件以上 = 確定 CSV の全行");
// 30 日 <= 90 日
check(C30.rows.every((r) => num(r.jp_report_count_30d) <= num(r.jp_report_count_90d)),
  "30 日の日本の報告 <= 90 日の日本の報告");
check(C30.rows.every((r) => num(r.jp_report_count_7d) <= num(r.jp_report_count_30d)),
  "7 日 <= 30 日");
check(C30.rows.every((r) => num(r.jp_attack_report_count_30d) <= num(r.jp_report_count_30d)),
  "30 日の攻撃報告 <= 30 日の報告");
check(S.digest_generations.short_windows_measured >= attacks.filter((r) => r.jp_30d_method === "counted").length,
  "30 日を数えた写しの数が、主対象のうち counted な行の数以上");
check(/標準の窓は/.test(md) && /30 日/.test(md), "レポートが標準の窓を書いている");
check(/引き直していない IP を「該当なし」に数えてはいけない/.test(md),
  "**未測定を該当なしに数えない方針を書いている**");
check(/母集団そのものが絞られています/.test(md),
  "**83% の主因が母集団の選び方であることを書いている**");

console.log("\n== マルチ / シングルの区分");
const RC = S.report_class_30d;
const MULTI = read("jp_30d_multi_report.csv");
const SINGLE = read("jp_30d_single_report.csv");
check(MULTI.rows.length === RC.multi, "マルチ CSV の行数が summary と一致",
  `${MULTI.rows.length} / ${RC.multi}`);
check(SINGLE.rows.length === RC.single, "シングル CSV の行数が一致");
check(MULTI.rows.length + SINGLE.rows.length === C30.rows.length,
  "マルチ + シングル = 30日確定（**取りこぼしが無い**）",
  `${MULTI.rows.length} + ${SINGLE.rows.length} / ${C30.rows.length}`);
check(MULTI.rows.every((r) => num(r.jp_attack_report_count_30d) >= 2),
  "**マルチは全行が 2 件以上**");
check(SINGLE.rows.every((r) => num(r.jp_attack_report_count_30d) === 1),
  "**シングルは全行がちょうど 1 件**");
check(MULTI.rows.every((r) => r.jp_report_class_30d === "マルチレポート"),
  "マルチ CSV の区分列が一致");
check(SINGLE.rows.every((r) => r.jp_report_class_30d === "シングルレポート"),
  "シングル CSV の区分列が一致");
check(!MULTI.rows.some((r) => SINGLE.rows.some((x) => x.ip_address === r.ip_address)),
  "マルチとシングルに同じ IP が無い");
check(PEND.rows.every((r) => r.jp_report_class_30d === "判定不能"),
  "**引き直し待ちは「判定不能」**（シングルや「なし」に落としていない）");
check(RC.multi_with_2plus_reporters + RC.multi_single_reporter_only === RC.multi,
  "マルチの観測者 2 人以上 + 1 人 = マルチ全体");
check(RC.multi_with_2plus_reporters === MULTI.rows.filter((r) => num(r.jp_distinct_reporters_30d) >= 2).length,
  "観測者 2 人以上の数が CSV と一致");
check(RC.multi === TH.attack_reports_ge_2, "マルチの数が「2 件以上」のしきい値と一致",
  `${RC.multi} / ${TH.attack_reports_ge_2}`);
check(RC.multi + RC.single === TH.attack_reports_ge_1,
  "マルチ + シングル = 「1 件以上」のしきい値");
check(/マルチレポート/.test(md) && /シングルレポート/.test(md),
  "レポートにマルチ・シングルの区分が書かれている");
check(/引き直していないので分からない/.test(md),
  "**判定不能を 0 と書いていないことがレポートに明記されている**");

console.log("\n== 観測者数の天井（上位の意味を決める）");
const C = S.jp_reporter_ceiling;
const maxSeen = Math.max(0, ...attacks.concat(SC.rows).map((r) => num(r.jp_distinct_reporters_90d)));
check(C.max_jp_reporters === maxSeen, "観測者数の最大が CSV と一致", `${C.max_jp_reporters} / ${maxSeen}`);
check(C.top_values.length > 0, "上位の値と件数が残っている");
check(/狙われ度ではない/.test(C.note || ""), "天井の意味が summary に書かれている");
// 並びが観測者数の降順になっていたら、天井の罠に落ちている
const evOf = (r) => (r.evidence_level_max === "" ? -1 : num(r.evidence_level_max));
const a1 = attacks.filter((r) => r.worst_tier === "A1");
let evDesc = true;
for (let i = 1; i < Math.min(a1.length, 200); i++) if (evOf(a1[i]) > evOf(a1[i - 1])) { evDesc = false; break; }
check(evDesc, "**同じ段の中で証拠段階の降順に並んでいる**（観測者数の降順ではない）");

console.log("\n== 分母を取り違えていないか");
check(S.population.with_jp_report_all_copies >= S.population.with_jp_report,
  "写し全件の「日本からの報告あり」が、段を判定できた分以上");
check(S.coverage.jp_categories_measured + S.coverage.jp_categories_unmeasured === S.coverage.api_ok,
  "段を数えた分 + まだ数えていない分 = API 成功数");
check(S.population.tier_judgeable === S.coverage.jp_categories_measured,
  "段を判定できた分母が一致");
check(S.coverage.unmeasured_with_jp_report > 0 ? /分からない/.test(md) : true,
  "**未測定を「攻撃ではない」と言い換えていない**");

console.log("\n== レポートが前提を書いているか");
check(/絞り込みの条件として機能しません/.test(md),
  "**「日本から報告あり」が絞り込みにならないことを書いている**");
check(/VPN を使っていることは攻撃ではありません/.test(md), "VPN を攻撃と扱わない理由を書いている");
check(/レポーターが日本に所在することは/.test(md) && /意味しません/.test(md),
  "日本のレポーター＝日本向け攻撃と断定していない");
check(/自己申告/.test(md), "カテゴリが自己申告であることを書いている");
check(/カテゴリの付与回数/.test(md), "段の数が報告件数でないことを書いている");
check(/new-only/.test(md), "母集団を広げる手段に触れている");
check(/多いほど重要、ではありません/.test(md),
  "**観測者数が多いほど重要ではないことを書いている**");
check(/天井/.test(md) && /センサーのうち何台が見たか/.test(md),
  "観測者数の天井とその意味を書いている");
check(/インターネット全域を計測している正規のプロジェクト/.test(md),
  "研究スキャナを外した理由を書いている");
check(/能動調査は行っていません/.test(md), "能動調査をしていないと明記している");
check(!/日本向け攻撃元/.test(md), "「日本向け攻撃元」と断定していない");

console.log("\n== 禁止したものが混ざっていないか");
const body = fs.readFileSync(path.join(HERE, "jp_attack_sources_all.csv"), "utf8") + JSON.stringify(S) + md;
check(!/reporter_?id/i.test(A.header.join(",")), "reporterId の列が無い");
check(!/reporterId["'\s]*[:=]\s*\d/.test(body), "reporterId に値が付いた形が無い");
check(!/\b[0-9a-f]{64}\b/.test(JSON.stringify(S.config || {}) + A.header.join(",")),
  "設定と列名に鍵らしい文字列が無い");
check(!attacks.some((r) => /^[=+@]/.test(r.isp) || /^[=+@]/.test(r.jp_category_names || "")),
  "外部由来の列が表計算の式として始まっていない");

console.log(failed ? `\n${failed} 件 NG` : "\nすべて通りました");
process.exit(failed ? 1 : 0);
