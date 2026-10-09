#!/usr/bin/env node
// 成果物を**読み直して**機械的に検査する。作った側の変数は一切見ない。
//
//   node validate.mjs
//
// 「作れた」と「正しい」は別。CSV を文字列から読み直し、仕様の条件を 1 つずつ当てる。
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CFG = JSON.parse(fs.readFileSync(path.join(HERE, "config.json"), "utf8"));

/** RFC 4180 の読み取り。引用符の中の改行・カンマ・二重引用符を正しく扱う */
function parseCsv(text) {
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
  const rows = []; let row = [], field = "", q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) {
      if (c === '"') { if (text[i + 1] === '"') { field += '"'; i++; } else q = false; }
      else field += c;
    } else if (c === '"') q = true;
    else if (c === ",") { row.push(field); field = ""; }
    else if (c === "\n") { row.push(field); field = ""; rows.push(row); row = []; }
    else if (c === "\r") { /* CRLF の CR は捨てる */ }
    else field += c;
  }
  if (field.length || row.length) { row.push(field); rows.push(row); }
  const header = rows.shift();
  return rows.filter((r) => r.length > 1).map((r) => Object.fromEntries(header.map((h, i) => [h, r[i] ?? ""])));
}
const read = (f) => parseCsv(fs.readFileSync(path.join(HERE, f), "utf8"));

let failed = 0;
const check = (ok, label, detail = "") => {
  console.log(`  ${ok ? "ok" : "NG"}  ${label}${ok || !detail ? "" : "  — " + detail}`);
  if (!ok) failed++;
};
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const n = (v) => (v === "" ? null : Number(v));

const all = read("abuseipdb_jp_hk_checked_all_90d.csv");
const pick = read("abuseipdb_jp_hk_jp_reporters_prioritized_90d.csv");
const cand = read("abuseipdb_jp_hk_blacklist_candidates.csv");
console.log(`候補 ${cand.length} 行 / 全件 ${all.length} 行 / 優先抽出 ${pick.length} 行\n`);

/* ---- 重複 ---- */
const dup = (rows) => { const s = new Set(), d = []; for (const r of rows) { if (s.has(r.ip_address)) d.push(r.ip_address); s.add(r.ip_address); } return d; };
check(dup(all).length === 0, "全件CSVに IP の重複がない", dup(all).slice(0, 3).join(" "));
check(dup(pick).length === 0, "優先抽出CSVに IP の重複がない", dup(pick).slice(0, 3).join(" "));
check(dup(cand).length === 0, "候補CSVに IP の重複がない", dup(cand).slice(0, 3).join(" "));

/* ---- 優先抽出の中身 ---- */
const badPri = pick.filter((r) => !["P1", "P2", "P3", "P4"].includes(r.priority));
check(badPri.length === 0, "優先抽出CSVは P1〜P4 だけ", badPri.slice(0, 3).map((r) => r.ip_address + ":" + r.priority).join(" "));
const badLoc = pick.filter((r) => !["JP", "HK"].includes(r.abuseipdb_country_code));
check(badLoc.length === 0, "優先抽出CSVの所在地は JP か HK", badLoc.slice(0, 3).map((r) => r.ip_address + ":" + r.abuseipdb_country_code).join(" "));
const noJp = pick.filter((r) => !(n(r.jp_report_count_90d) >= 1));
check(noJp.length === 0, "優先抽出CSVは日本からの報告が1件以上", noJp.slice(0, 3).map((r) => r.ip_address).join(" "));

/* ---- 優先順位の条件 ---- */
const p1 = all.filter((r) => r.priority === "P1");
const p2 = all.filter((r) => r.priority === "P2");
const p3 = all.filter((r) => r.priority === "P3");
check(p1.every((r) => n(r.jp_distinct_reporters_90d) >= 2), "P1 は日本の独立レポーター2人以上",
  p1.filter((r) => !(n(r.jp_distinct_reporters_90d) >= 2)).slice(0, 3).map((r) => r.ip_address).join(" "));
check(p2.every((r) => n(r.jp_distinct_reporters_90d) >= 2), "P2 は日本の独立レポーター2人以上",
  p2.filter((r) => !(n(r.jp_distinct_reporters_90d) >= 2)).slice(0, 3).map((r) => r.ip_address).join(" "));
const clean = (r) => n(r.non_jp_report_count_90d) === 0 && n(r.unknown_country_report_count_90d) === 0;
check([...p1, ...p3].every(clean), "P1 と P3 は日本以外・国不明の報告が0件",
  [...p1, ...p3].filter((r) => !clean(r)).slice(0, 3).map((r) => r.ip_address).join(" "));
check([...p1, ...p3].every((r) => r.data_complete === "true"), "P1 と P3 は data_complete=true",
  [...p1, ...p3].filter((r) => r.data_complete !== "true").slice(0, 3).map((r) => r.ip_address).join(" "));
check(p3.every((r) => n(r.jp_distinct_reporters_90d) <= 1), "P3 は日本の独立レポーター1人以下");
check(all.filter((r) => r.priority === "P8").every((r) => !["JP", "HK"].includes(r.abuseipdb_country_code)),
  "P8 は所在地が範囲外");
check(all.filter((r) => r.priority === "P5").every((r) => n(r.jp_report_count_90d) === 0),
  "P5 は日本からの報告が0件");

/* ---- 数の整合 ---- */
const over = all.filter((r) => r.api_status === "ok" && n(r.jp_report_count_90d) > n(r.returned_report_count_90d));
check(over.length === 0, "日本の報告数が確認報告数を超えていない", over.slice(0, 3).map((r) => r.ip_address).join(" "));
const split = all.filter((r) => r.api_status === "ok"
  && n(r.jp_report_count_90d) + n(r.non_jp_report_count_90d) + n(r.unknown_country_report_count_90d) !== n(r.returned_report_count_90d));
check(split.length === 0, "日本＋日本以外＋国不明 = 確認報告数", split.slice(0, 3).map((r) => r.ip_address).join(" "));
const ratio = all.filter((r) => r.jp_report_ratio_90d !== "" && !(n(r.jp_report_ratio_90d) >= 0 && n(r.jp_report_ratio_90d) <= 1));
check(ratio.length === 0, "報告比率が 0〜1 の範囲", ratio.slice(0, 3).map((r) => r.ip_address).join(" "));
const reporters = all.filter((r) => r.api_status === "ok" && n(r.jp_distinct_reporters_90d) > n(r.distinct_reporters_returned_90d));
check(reporters.length === 0, "日本の独立レポーター数が全体の独立レポーター数以下", reporters.slice(0, 3).map((r) => r.ip_address).join(" "));

/* ---- 日時の形 ---- */
const DATE_COLS = ["window_start_utc", "window_end_utc", "checked_at_utc",
  "latest_jp_reported_at_90d", "latest_reported_at_90d", "api_last_reported_at",
  "blacklist_generated_at", "blacklist_last_reported_at"];
const badDate = [];
for (const r of all) for (const c of DATE_COLS) if (r[c] && !ISO.test(r[c])) badDate.push(`${r.ip_address}/${c}=${r[c]}`);
check(badDate.length === 0, "日時が ISO 8601 UTC（末尾 Z）", badDate.slice(0, 3).join(" "));

/* ---- 鍵が混ざっていないか ---- */
const key = process.env.ABUSEIPDB_API_KEY || "";
const files = fs.readdirSync(HERE).filter((f) => fs.statSync(path.join(HERE, f)).isFile());
let leaked = [];
for (const f of files) {
  const body = fs.readFileSync(path.join(HERE, f), "utf8");
  if (key && body.includes(key)) leaked.push(f);
}
check(leaked.length === 0, "成果物・スクリプト・ログに API キーが含まれていない", leaked.join(" "));
// 状態ファイルも見る
for (const f of fs.existsSync(path.join(HERE, ".state")) ? fs.readdirSync(path.join(HERE, ".state")) : []) {
  const body = fs.readFileSync(path.join(HERE, ".state", f), "utf8");
  if (key && body.includes(key)) leaked.push(".state/" + f);
}
check(leaked.length === 0, "チェックポイントにも API キーが含まれていない", leaked.join(" "));

/* ---- 呼び出し数 ---- */
const okRows = all.filter((r) => r.api_status === "ok").length;
check(all.length <= CFG.MAX_CHECK_CALLS, `/check の行数が設定上限 ${CFG.MAX_CHECK_CALLS} を超えていない`, `実際 ${all.length}`);

/* ---- BOM と改行 ---- */
for (const f of ["abuseipdb_jp_hk_checked_all_90d.csv", "abuseipdb_jp_hk_jp_reporters_prioritized_90d.csv",
  "abuseipdb_jp_hk_blacklist_candidates.csv"]) {
  const buf = fs.readFileSync(path.join(HERE, f));
  check(buf[0] === 0xef && buf[1] === 0xbb && buf[2] === 0xbf, `${f} が UTF-8 BOM 付き`);
}

/* ---- 優先抽出が全件CSVと矛盾しないか ---- */
const byIp = new Map(all.map((r) => [r.ip_address, r]));
const mismatch = pick.filter((r) => JSON.stringify(byIp.get(r.ip_address)) !== JSON.stringify(r));
check(mismatch.length === 0, "優先抽出CSVの行が全件CSVと一致", mismatch.slice(0, 3).map((r) => r.ip_address).join(" "));
const shouldPick = all.filter((r) => r.selected_for_prioritized_output === "true");
check(shouldPick.length === pick.length, "selected_for_prioritized_output=true の件数と優先抽出CSVの行数が一致",
  `${shouldPick.length} vs ${pick.length}`);

console.log(failed ? `\n${failed} 件失敗` : "\nすべて通りました");
process.exit(failed ? 1 : 0);
