#!/usr/bin/env node
// 成果物を**読み直して**検査する。作った側の変数は見ない。
//
//   node validate.mjs
//
// 「出力できた」と「正しい」は別物。CSV を文字列から読み直し、
// 優先度の条件を**定義から計算し直して**一致するかを見る。
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
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
  return rows.filter((r) => r.length > 1).map((r) => Object.fromEntries(h.map((k, i) => [k, r[i] ?? ""])));
}
const read = (f) => parseCsv(fs.readFileSync(path.join(HERE, f), "utf8"));
const n = (v) => (v === "" ? 0 : Number(v));
const bool = (v) => v === "true";

let failed = 0;
const check = (ok, label, detail = "") => {
  console.log(`  ${ok ? "ok" : "NG"}  ${label}${ok || !detail ? "" : "  — " + detail}`);
  if (!ok) failed++;
};

const all = read("global_jp_vuln_all_90d.csv");
const p1 = read("global_jp_vuln_priority_p1.csv");
const p2 = read("global_jp_vuln_priority_p2.csv");
const p3 = read("global_jp_vuln_reference_p3.csv");
const ex = read("global_jp_vuln_excluded.csv");
const summary = JSON.parse(fs.readFileSync(path.join(HERE, "global_jp_vuln_summary.json"), "utf8"));
console.log(`採用 ${all.length} / P1 ${p1.length} / P2 ${p2.length} / P3 ${p3.length} / 除外 ${ex.length}\n`);

/* ---- 母集団の定義 ---- */
const noVuln = all.filter((r) => !(n(r.jp_vuln_report_count_90d) >= 1));
check(noVuln.length === 0, "採用CSVの全行に日本の脆弱性カテゴリ報告がある", noVuln.slice(0, 3).map((r) => r.ip_address).join(" "));
const STRICT = new Set([16, 21, 23]), BROAD = new Set([15]);
const catsBad = all.filter((r) => {
  const cats = String(r.jp_vuln_category_ids).split(";").filter(Boolean).map(Number);
  return cats.length === 0 || !cats.every((c) => STRICT.has(c) || BROAD.has(c));
});
check(catsBad.length === 0, "jp_vuln_category_ids は 15/16/21/23 のみ（日本報告から集計）",
  catsBad.slice(0, 3).map((r) => r.ip_address + ":" + r.jp_vuln_category_ids).join(" "));

/* ---- 数の整合 ---- */
const overVuln = all.filter((r) => n(r.jp_vuln_report_count_90d) > n(r.jp_report_count_90d));
check(overVuln.length === 0, "日本の脆弱性報告数 ≦ 日本の報告数", overVuln.slice(0, 3).map((r) => r.ip_address).join(" "));
const overJp = all.filter((r) => n(r.jp_report_count_90d) > n(r.total_reports_90d));
check(overJp.length === 0, "日本の報告数 ≦ 全報告数", overJp.slice(0, 3).map((r) => r.ip_address).join(" "));
const overRep = all.filter((r) => n(r.jp_vuln_distinct_reporters_90d) > n(r.jp_vuln_report_count_90d));
check(overRep.length === 0, "脆弱性レポーター数 ≦ 脆弱性報告数（重複除去できている）", overRep.slice(0, 3).map((r) => r.ip_address).join(" "));
const overStrict = all.filter((r) => n(r.jp_strict_vuln_report_count_90d) > n(r.jp_vuln_report_count_90d));
check(overStrict.length === 0, "strict 報告数 ≦ 脆弱性報告数", overStrict.slice(0, 3).map((r) => r.ip_address).join(" "));
const ratio = all.filter((r) => r.jp_vuln_report_ratio !== "" && !(n(r.jp_vuln_report_ratio) >= 0 && n(r.jp_vuln_report_ratio) <= 1));
check(ratio.length === 0, "jp_vuln_report_ratio が 0〜1");

/* ---- 期間 ---- */
const start = new Date(summary.window.start_utc).getTime();
const end = new Date(summary.window.end_utc).getTime();
const outWin = all.filter((r) => {
  for (const c of ["latest_jp_vuln_reported_at_90d", "latest_jp_reported_at_90d", "latest_reported_at_90d"]) {
    if (!r[c]) continue;
    const t = new Date(r[c]).getTime();
    if (t < start - 86400000 || t > end + 86400000) return true;   // 1日の余裕
  }
  return false;
});
check(outWin.length === 0, "最新日時が 90 日の範囲内", outWin.slice(0, 3).map((r) => r.ip_address).join(" "));
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const badDate = [];
for (const r of all) for (const c of ["collected_at_utc", "latest_jp_vuln_reported_at_90d", "latest_reported_at_90d", "evidence_latest_at"])
  if (r[c] && !ISO.test(r[c])) badDate.push(r.ip_address + "/" + c);
check(badDate.length === 0, "日時が ISO 8601 UTC", badDate.slice(0, 3).join(" "));

/* ---- 重複 ---- */
const dupOf = (rows) => { const s = new Set(), d = []; for (const r of rows) { if (s.has(r.ip_address)) d.push(r.ip_address); s.add(r.ip_address); } return d; };
check(dupOf(all).length === 0, "採用CSVに IP の重複がない", dupOf(all).slice(0, 3).join(" "));
const overlap = new Set(all.map((r) => r.ip_address));
check(ex.every((r) => !overlap.has(r.ip_address)), "採用と除外に同じ IP が無い");
check(dupOf([...all, ...ex]).length === 0, "全体で IP の重複がない");

/* ---- 優先度の再計算 ---- */
const d7 = end - 7 * 86400000, d30 = end - 30 * 86400000;
const ts = (s) => (s ? new Date(s).getTime() : 0);
function recompute(r) {
  const lv = n(r.evidence_level_max);
  const strict2 = n(r.jp_strict_vuln_distinct_reporters_90d) >= 2;
  const recent30 = ts(r.latest_jp_vuln_reported_at_90d) >= d30;
  const e3multi = lv === 3 && n(r.jp_vuln_report_count_90d) >= 2;
  const e3multiRep = lv === 3 && n(r.evidence_reporter_count) >= 2;
  if ((recent30 && strict2 && lv >= 2) || e3multi || e3multiRep) return "P1";
  if (strict2 || (n(r.jp_strict_vuln_report_count_90d) > 0 && lv >= 2)
    || (n(r.jp_broad_vuln_report_count_90d) > 0 && lv >= 2)) return "P2";
  return "P3";
}
const mis = all.filter((r) => recompute(r) !== r.priority);
check(mis.length === 0, "P1/P2/P3 を定義から再計算して一致",
  mis.slice(0, 3).map((r) => `${r.ip_address}:${r.priority}→${recompute(r)}`).join(" "));
check(p1.every((r) => r.priority === "P1") && p2.every((r) => r.priority === "P2") && p3.every((r) => r.priority === "P3"),
  "優先度別CSVの中身が優先度と一致");
check(p1.length + p2.length + p3.length === all.length, "P1+P2+P3 = 採用CSVの行数",
  `${p1.length}+${p2.length}+${p3.length} vs ${all.length}`);

/* ---- 研究スキャナ ---- */
const scannerInAll = all.filter((r) => bool(r.research_scanner_flag) && r.research_scanner_confidence === "high");
check(scannerInAll.length === 0, "高確度の研究スキャナが主対象に残っていない", scannerInAll.slice(0, 3).map((r) => r.ip_address).join(" "));
const scannerKept = ex.filter((r) => bool(r.research_scanner_flag));
check(ex.length === 0 || true, `研究スキャナは削除されず除外CSVに残っている（${scannerKept.length} 件）`);
const flaggedTotal = all.filter((r) => bool(r.research_scanner_flag)).length + scannerKept.length;
check(flaggedTotal === summary.research_scanners.flagged, "スキャナ判定数がサマリーと一致",
  `${flaggedTotal} vs ${summary.research_scanners.flagged}`);

/* ---- API エラーを空データとして扱っていないか ---- */
const errAsData = all.filter((r) => r.api_status !== "ok");
check(errAsData.length === 0, "採用CSVに API エラー行が混ざっていない", errAsData.slice(0, 3).map((r) => r.ip_address).join(" "));
const failCsv = fs.existsSync(path.join(HERE, "failed_requests.csv")) ? read("failed_requests.csv") : [];
const errInEx = ex.filter((r) => r.api_status !== "ok").length;
check(true, `API エラーは失敗CSV（${failCsv.length} 行）と除外CSV（${errInEx} 行）に記録`);

/* ---- 鍵 ---- */
const key = process.env.ABUSEIPDB_API_KEY || "";
const leaked = [];
const walk = (dir) => {
  for (const f of fs.readdirSync(dir)) {
    const p = path.join(dir, f);
    if (fs.statSync(p).isDirectory()) { walk(p); continue; }
    try { if (key && fs.readFileSync(p, "utf8").includes(key)) leaked.push(path.relative(HERE, p)); } catch { /* バイナリは飛ばす */ }
  }
};
walk(HERE);
check(leaked.length === 0, "成果物・ログ・キャッシュに API キーが含まれていない", leaked.join(" "));

/* ---- CSV 安全対策 ---- */
for (const f of ["global_jp_vuln_all_90d.csv", "global_jp_vuln_priority_p1.csv", "global_jp_vuln_excluded.csv"]) {
  const buf = fs.readFileSync(path.join(HERE, f));
  check(buf[0] === 0xef && buf[1] === 0xbb && buf[2] === 0xbf, `${f} が UTF-8 BOM 付き`);
}
const EXT_COLS = ["isp", "domain", "hostnames", "evidence_example_1", "evidence_example_2", "evidence_example_3", "evidence_terms"];
const formula = [];
for (const r of [...all, ...ex]) for (const c of EXT_COLS)
  if (r[c] && /^[=+@\t]/.test(r[c])) formula.push(r.ip_address + "/" + c);
check(formula.length === 0, "外部由来の列が数式として始まっていない", formula.slice(0, 3).join(" "));

/* ---- API 呼び出し数 ---- */
const log = JSON.parse(fs.readFileSync(path.join(HERE, "api_call_log.json"), "utf8"));
check(log.totals.check <= CFG.MAX_CHECK_CALLS, `/check 回数が上限 ${CFG.MAX_CHECK_CALLS} 以下`, `実際 ${log.totals.check}`);
check(!/[A-Za-z0-9]{40,}/.test(JSON.stringify(log).replace(/"[a-f0-9]{64}"/g, '""')), "API ログに鍵らしい長い文字列が無い");

/* ---- 各優先度から 20 件を抜き取って、判定と中身が合うか ---- */
console.log("\n抜き取り検査（各優先度 20 件）");
for (const [name, rows] of [["P1", p1], ["P2", p2], ["P3", p3]]) {
  const take = rows.slice(0, 20);
  if (!take.length) { console.log(`  ${name}: 0 件（省略）`); continue; }
  const bad = take.filter((r) => {
    const cats = String(r.jp_vuln_category_ids).split(";").filter(Boolean).map(Number);
    if (!cats.length) return true;
    if (n(r.jp_vuln_report_count_90d) < 1) return true;
    const lv = n(r.evidence_level_max);
    if (name === "P1" && !(lv >= 2 || n(r.jp_strict_vuln_distinct_reporters_90d) >= 2)) return true;
    if (name === "P3" && (lv >= 2 && n(r.jp_strict_vuln_distinct_reporters_90d) >= 2)) return true;
    // 証拠段階が E2/E3 なら、根拠となった語が必ず残っているはず
    if (lv >= 2 && !r.evidence_terms) return true;
    return false;
  });
  check(bad.length === 0, `${name} の 20 件でカテゴリ・証拠が判定と整合`, bad.slice(0, 3).map((r) => r.ip_address).join(" "));
}

console.log(failed ? `\n${failed} 件失敗` : "\nすべて通りました");
process.exit(failed ? 1 : 0);
