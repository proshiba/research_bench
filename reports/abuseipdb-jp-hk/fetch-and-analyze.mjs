#!/usr/bin/env node
// AbuseIPDB Basic で「日本・香港に所在する悪性 IP 候補」を集め、
// 過去 90 日の **日本のレポーターによる報告状況**を集計して並べ替える。
//
//   node fetch-and-analyze.mjs [--blacklist-only] [--resume] [--snapshot <id>]
//
// 鍵は環境変数 ABUSEIPDB_API_KEY からだけ読む。**どこにも書き出さない。**
//
// ## 混同してはいけない 2 つの国
//
//   data.countryCode              … 悪性 IP 自体の推定所在地（JP / HK で絞る）
//   reports[].reporterCountryCode … 報告した人の所在地（JP を数える）
//
// **レポーターが日本に居ることは、日本向けの攻撃であることを意味しない。**
// 日本の観測者がたまたま多い、というだけの可能性が常に残る。
//
// ## 途中で止まっても続きから
//
// 取得した 1 件ごとに .state/checks-<snapshot>.jsonl へ追記する。429 や残量不足では
// そこで安全に止め、翌日 --resume で未処理だけを引き直す。Blacklist の写しは
// スナップショットとして固定し、同じ母集団で続けられるようにする。
import fs from "node:fs";
import path from "node:path";
import net from "node:net";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const STATE = path.join(HERE, ".state");
const CFG = JSON.parse(fs.readFileSync(path.join(HERE, "config.json"), "utf8"));
const args = process.argv.slice(2);
const has = (f) => args.includes(f);
const argOf = (f) => { const i = args.indexOf(f); return i >= 0 ? args[i + 1] : null; };

/* ---------------- 鍵 ---------------- */

const KEY = process.env.ABUSEIPDB_API_KEY;
if (!KEY) {
  console.error("ABUSEIPDB_API_KEY がありません。API を呼ばずに終了します。");
  process.exit(2);
}
const HEADERS = { Key: KEY, Accept: "application/json" };

/* ---------------- 公式のカテゴリ定義 ----------------
 * https://www.abuseipdb.com/categories を実行時に確認して書き写したもの（2026-10-09）。
 * **推測しない。** 増えたら上の頁を見て直すこと。 */
const CATEGORIES = {
  1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders", 4: "DDoS Attack",
  5: "FTP Brute-Force", 6: "Ping of Death", 7: "Phishing", 8: "Fraud VoIP",
  9: "Open Proxy", 10: "Web Spam", 11: "Email Spam", 12: "Blog Spam",
  13: "VPN IP", 14: "Port Scan", 15: "Hacking", 16: "SQL Injection",
  17: "Spoofing", 18: "Brute-Force", 19: "Bad Web Bot", 20: "Exploited Host",
  21: "Web App Attack", 22: "SSH", 23: "IoT Targeted",
};
const catTag = (id) => "category_" + String(CATEGORIES[id] || ("unknown_" + id))
  .toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_|_$/g, "");

/* ---------------- 小物 ---------------- */

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
/** ISO 8601 UTC（末尾 Z）に揃える。API は +00:00 で返してくる */
const iso = (v) => { if (!v) return ""; const d = new Date(v); return isNaN(d) ? "" : d.toISOString().replace(/\.\d{3}Z$/, "Z"); };
const isV4 = (s) => net.isIPv4(s);

/** 残量の監視。ヘッダが真実で、手元の数えより優先する */
const quota = { limit: null, remaining: null, reset: null, retryAfter: null };
function readQuota(res) {
  const n = (h) => { const v = res.headers.get(h); return v == null ? null : Number(v); };
  const l = n("x-ratelimit-limit"); if (l != null) quota.limit = l;
  const r = n("x-ratelimit-remaining"); if (r != null) quota.remaining = r;
  const s = n("x-ratelimit-reset"); if (s != null) quota.reset = s;
  const a = res.headers.get("retry-after"); if (a != null) quota.retryAfter = Number(a);
}

async function callApi(url, { retries = CFG.MAX_RETRIES } = {}) {
  let wait = 1000;
  for (let attempt = 0; ; attempt++) {
    let res;
    try {
      res = await fetch(url, { headers: HEADERS });
    } catch (e) {
      if (attempt >= retries) return { ok: false, httpStatus: null, error: "network: " + String(e.message || e).slice(0, 80) };
      await sleep(wait); wait *= 2; continue;
    }
    readQuota(res);
    if (res.status === 429) return { ok: false, httpStatus: 429, rateLimited: true, error: "rate limited" };
    if (res.status >= 500) {
      if (attempt >= retries) return { ok: false, httpStatus: res.status, error: "server error " + res.status };
      await sleep(wait); wait *= 2; continue;
    }
    if (!res.ok) {
      let detail = "";
      try { detail = ((await res.json()).errors || []).map((e) => e.detail).join("; ").slice(0, 120); } catch { /* 本文が読めなくても status は残す */ }
      return { ok: false, httpStatus: res.status, error: ("HTTP " + res.status + (detail ? ": " + detail : "")).slice(0, 160) };
    }
    try { return { ok: true, httpStatus: res.status, body: await res.json() }; }
    catch (e) { return { ok: false, httpStatus: res.status, error: "応答を解析できません" }; }
  }
}

/* ---------------- フェーズ 1: Blacklist で候補を作る ---------------- */

fs.mkdirSync(STATE, { recursive: true });
const runStart = new Date();

async function getBlacklist() {
  const wanted = argOf("--snapshot");
  if (wanted || has("--resume")) {
    const files = fs.readdirSync(STATE).filter((f) => /^blacklist-.*\.json$/.test(f)).sort();
    const pick = wanted ? `blacklist-${wanted}.json` : files[files.length - 1];
    if (pick && fs.existsSync(path.join(STATE, pick))) {
      const snap = JSON.parse(fs.readFileSync(path.join(STATE, pick), "utf8"));
      console.log(`既存のスナップショットを使います: ${pick}（候補 ${snap.candidates.length} 件 / 生成 ${snap.generatedAt}）`);
      return snap;
    }
    if (wanted) { console.error(`スナップショット ${wanted} が見つかりません`); process.exit(2); }
    console.log("スナップショットが無いので新しく取得します");
  }
  const q = new URLSearchParams({
    confidenceMinimum: String(CFG.BLACKLIST_CONFIDENCE_MINIMUM),
    limit: String(CFG.BLACKLIST_LIMIT),
    onlyCountries: CFG.LOCATION_COUNTRIES,
    ipVersion: String(CFG.IP_VERSION),
  });
  console.log(`Blacklist を取得します（${CFG.LOCATION_COUNTRIES} / 信頼度 ${CFG.BLACKLIST_CONFIDENCE_MINIMUM} 以上 / IPv${CFG.IP_VERSION}）`);
  const r = await callApi(`https://api.abuseipdb.com/api/v2/blacklist?${q}`);
  if (!r.ok) { console.error("Blacklist を取得できません: " + r.error); process.exit(1); }
  const generatedAt = iso(r.body?.meta?.generatedAt);
  const seen = new Set();
  const candidates = [];
  let dup = 0, invalid = 0;
  for (const row of r.body?.data || []) {
    const ip = String(row.ipAddress || "").trim();
    if (!isV4(ip)) { invalid++; continue; }
    if (seen.has(ip)) { dup++; continue; }
    seen.add(ip);
    const cc = row.countryCode || "";
    candidates.push({
      blacklist_rank: candidates.length + 1,
      ip_address: ip,
      blacklist_country_code: cc,
      blacklist_abuse_confidence_score: row.abuseConfidenceScore ?? "",
      blacklist_last_reported_at: iso(row.lastReportedAt),
      // 国コードが返るなら、対象外のものは詳細確認に進めない（監査用には残す）
      blacklist_location_scope: cc ? (cc === "JP" || cc === "HK") : true,
    });
  }
  const snapshotId = (generatedAt || runStart.toISOString()).replace(/[^0-9]/g, "").slice(0, 14);
  const snap = {
    snapshot_id: snapshotId, generatedAt, fetched_at: iso(runStart),
    query: { onlyCountries: CFG.LOCATION_COUNTRIES, confidenceMinimum: CFG.BLACKLIST_CONFIDENCE_MINIMUM,
      limit: CFG.BLACKLIST_LIMIT, ipVersion: CFG.IP_VERSION },
    dropped: { duplicate: dup, invalid },
    candidates,
  };
  fs.writeFileSync(path.join(STATE, `blacklist-${snapshotId}.json`), JSON.stringify(snap));
  console.log(`  候補 ${candidates.length} 件（重複 ${dup} / 不正 ${invalid} を除外）/ 生成 ${generatedAt}`);
  return snap;
}

const snap = await getBlacklist();
const byCountry = {};
for (const c of snap.candidates) byCountry[c.blacklist_country_code || "?"] = (byCountry[c.blacklist_country_code || "?"] || 0) + 1;
console.log("  国別:", Object.entries(byCountry).sort((a, b) => b[1] - a[1]).map(([k, v]) => `${k} ${v}`).join(" / "));

/* ---------------- 候補一覧 CSV ---------------- */

const BOM = "﻿";
/** 表計算ソフトが数式として実行しうる先頭文字を無害化する。
 *  **外から来た文字列にだけ掛ける**（こちらで作った数値には掛けない）。 */
const deFormula = (s) => (/^[=+\-@\t\r\n]/.test(s) ? "'" + s : s);
const cell = (v, external = false) => {
  if (v === null || v === undefined) return "";
  let s = typeof v === "boolean" ? String(v) : String(v);
  if (external) s = deFormula(s);
  return /[",\r\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
};
const writeCsv = (file, header, rows, externalCols = new Set()) => {
  const out = [header.join(",")];
  for (const r of rows) out.push(header.map((h) => cell(r[h], externalCols.has(h))).join(","));
  fs.writeFileSync(file, BOM + out.join("\r\n") + "\r\n");
};

const CAND_HEADER = ["blacklist_rank", "ip_address", "blacklist_country_code",
  "blacklist_abuse_confidence_score", "blacklist_last_reported_at", "blacklist_generated_at",
  "blacklist_query", "blacklist_fetched_at", "blacklist_location_scope"];
writeCsv(path.join(HERE, "abuseipdb_jp_hk_blacklist_candidates.csv"), CAND_HEADER,
  snap.candidates.map((c) => ({ ...c,
    blacklist_generated_at: snap.generatedAt, blacklist_fetched_at: snap.fetched_at,
    blacklist_query: `onlyCountries=${snap.query.onlyCountries};confidenceMinimum=${snap.query.confidenceMinimum};limit=${snap.query.limit};ipVersion=${snap.query.ipVersion}`,
  })), new Set(["blacklist_country_code"]));
console.log(`  → abuseipdb_jp_hk_blacklist_candidates.csv（${snap.candidates.length} 行）`);

if (has("--blacklist-only")) { console.log("候補一覧だけ作って終わります（--blacklist-only）"); process.exit(0); }

/* ---------------- フェーズ 2: 何件まで引けるか ---------------- */

// 残量はヘッダで分かっている（Blacklist の呼び出しで読んだ）。
// **設定上限と、実際の残量から安全余裕を引いた数の、小さいほうを採る。**
const fromHeader = quota.remaining == null ? Infinity : quota.remaining - CFG.CHECK_RATE_SAFETY_MARGIN;
const budget = Math.min(CFG.MAX_CHECK_CALLS, fromHeader);
console.log(`\n枠: 上限 ${quota.limit ?? "?"} / 残り ${quota.remaining ?? "?"} → 今回引けるのは ${budget} 件`);
if (budget <= 0) {
  console.log("枠がありません。候補一覧だけ保存して終わります。");
  process.exit(0);
}

const ckFile = path.join(STATE, `checks-${snap.snapshot_id}.jsonl`);
const done = new Map();
if (fs.existsSync(ckFile)) {
  for (const line of fs.readFileSync(ckFile, "utf8").split("\n")) {
    if (!line.trim()) continue;
    try { const r = JSON.parse(line); done.set(r.ip_address, r); } catch { /* 壊れた行は飛ばす */ }
  }
  console.log(`チェックポイントに ${done.size} 件あります（再取得しません）`);
}
const ck = fs.createWriteStream(ckFile, { flags: "a" });
const save = (rec) => new Promise((r) => ck.write(JSON.stringify(rec) + "\n", r));

const todo = snap.candidates
  .filter((c) => c.blacklist_location_scope)   // Blacklist 側で対象外と分かるものは引かない
  .filter((c) => !done.has(c.ip_address))
  .slice(0, budget);
console.log(`詳細確認の対象 ${todo.length} 件`);

/* ---------------- フェーズ 3: /check で 90 日ぶんを引く ---------------- */

const windowEnd = runStart;
const windowStart = new Date(runStart.getTime() - CFG.REPORT_WINDOW_DAYS * 86400000);
let used = 0, stopped = null;
const reserve = () => {
  if (stopped) return false;
  if (used >= budget) { stopped = stopped || "予算に達しました"; return false; }
  if (quota.remaining != null && quota.remaining <= CFG.CHECK_RATE_SAFETY_MARGIN) { stopped = "残量が安全余裕に達しました"; return false; }
  used++; return true;
};

function summarise(ip, body, httpStatus) {
  const d = body?.data || {};
  const reports = Array.isArray(d.reports) ? d.reports : [];
  const jp = reports.filter((r) => r.reporterCountryCode === "JP");
  const unknown = reports.filter((r) => !r.reporterCountryCode);
  const nonJp = reports.filter((r) => r.reporterCountryCode && r.reporterCountryCode !== "JP");
  const uniq = (xs) => [...new Set(xs)];
  const jpReporters = uniq(jp.map((r) => r.reporterId).filter((x) => x != null));
  const allReporters = uniq(reports.map((r) => r.reporterId).filter((x) => x != null));
  const catCount = {};
  for (const r of reports) for (const c of r.categories || []) catCount[c] = (catCount[c] || 0) + 1;
  const catIds = Object.keys(catCount).map(Number).sort((a, b) => a - b);
  const latest = (xs) => xs.map((r) => r.reportedAt).filter(Boolean).sort().pop() || "";
  const returned = reports.length;
  const total = d.totalReports ?? 0;
  return {
    ip_address: ip,
    http_status: httpStatus,
    api_status: "ok",
    error_message: "",
    ip_version: d.ipVersion ?? 4,
    abuseipdb_country_code: d.countryCode || "",
    check_abuse_confidence_score: d.abuseConfidenceScore ?? "",
    api_last_reported_at: iso(d.lastReportedAt),
    total_reports_90d: total,
    returned_report_count_90d: returned,
    jp_report_count_90d: jp.length,
    non_jp_report_count_90d: nonJp.length,
    unknown_country_report_count_90d: unknown.length,
    distinct_reporters_90d_api: d.numDistinctUsers ?? "",
    distinct_reporters_returned_90d: allReporters.length,
    jp_distinct_reporters_90d: jpReporters.length,
    jp_report_ratio_90d: returned ? Number((jp.length / returned).toFixed(4)) : 0,
    latest_jp_reported_at_90d: iso(latest(jp)),
    latest_reported_at_90d: iso(latest(reports)),
    reporter_country_codes: uniq(reports.map((r) => r.reporterCountryCode).filter(Boolean)).sort().join(";"),
    non_jp_reporter_country_codes: uniq(nonJp.map((r) => r.reporterCountryCode)).sort().join(";"),
    abuse_category_ids: catIds.join(";"),
    abuse_category_names: catIds.map((c) => CATEGORIES[c] || `unknown(${c})`).join(";"),
    abuse_category_counts: catIds.map((c) => `${c}:${catCount[c]}`).join(";"),
    usage_type: d.usageType || "",
    isp: d.isp || "",
    domain: d.domain || "",
    hostnames: (d.hostnames || []).join(";"),
    is_tor: d.isTor === true,
    is_whitelisted: d.isWhitelisted === true,
    data_complete: returned === total,
  };
}

const queue = [...todo];
let progressed = 0;
async function worker() {
  for (;;) {
    const c = queue.shift();
    if (!c || stopped) return;
    if (!reserve()) return;
    const q = new URLSearchParams({ ipAddress: c.ip_address, maxAgeInDays: String(CFG.REPORT_WINDOW_DAYS), verbose: "" });
    const r = await callApi(`https://api.abuseipdb.com/api/v2/check?${q}`);
    let rec;
    if (r.rateLimited) {
      stopped = `429（Retry-After ${quota.retryAfter ?? "?"} 秒 / リセット ${quota.reset ? iso(new Date(quota.reset * 1000)) : "?"}）`;
      queue.unshift(c); used--;   // 引けていないので戻す
      return;
    }
    if (!r.ok) {
      rec = { ip_address: c.ip_address, api_status: "error", http_status: r.httpStatus ?? "",
        error_message: String(r.error || "").slice(0, 200) };
    } else {
      rec = summarise(c.ip_address, r.body, r.httpStatus);
    }
    rec.checked_at_utc = iso(new Date());
    await save(rec);
    done.set(c.ip_address, rec);
    if (++progressed % 100 === 0) {
      process.stdout.write(`\r  ${progressed}/${todo.length}  残量 ${quota.remaining ?? "?"}      `);
    }
  }
}
await Promise.all(Array.from({ length: Math.max(1, CFG.CHECK_CONCURRENCY) }, worker));
ck.end();
console.log(`\n詳細確認 ${progressed} 件 / API ${used} 回` + (stopped ? `  — 中断: ${stopped}` : ""));

/* ---------------- 優先順位を付ける ---------------- */

const inScope = (cc) => cc === "JP" || cc === "HK";
function classify(r) {
  if (r.api_status !== "ok") return ["P9", "unavailable"];
  const cc = r.abuseipdb_country_code;
  if (!inScope(cc)) return ["P8", "location_out_of_scope"];
  const jpOnly = r.returned_report_count_90d > 0 && r.data_complete === true
    && r.non_jp_report_count_90d === 0 && r.unknown_country_report_count_90d === 0
    && r.jp_report_count_90d === r.returned_report_count_90d;
  const twoPlus = r.jp_distinct_reporters_90d >= 2;
  if (jpOnly && twoPlus) return ["P1", "jp_only_and_2plus"];
  if (twoPlus) return ["P2", "jp_2plus_mixed_or_incomplete"];
  if (jpOnly) return ["P3", "jp_only_single_reporter"];
  if (r.jp_report_count_90d > 0) return ["P4", "jp_observed_single_mixed"];
  return ["P5", "no_jp_report"];
}

function tagsOf(r) {
  const t = [];
  if (r.api_status !== "ok") return "";
  if (r.abuseipdb_country_code === "JP") t.push("ip_location_jp");
  if (r.abuseipdb_country_code === "HK") t.push("ip_location_hk");
  const jpOnly = r.returned_report_count_90d > 0 && r.data_complete === true
    && r.non_jp_report_count_90d === 0 && r.unknown_country_report_count_90d === 0
    && r.jp_report_count_90d === r.returned_report_count_90d;
  if (jpOnly) t.push("jp_only_90d");
  if (r.jp_distinct_reporters_90d >= 2) t.push("jp_reporters_2plus");
  if (r.jp_report_count_90d > 0) t.push("jp_observed");
  if (r.jp_report_count_90d > 0 && r.non_jp_report_count_90d > 0) t.push("mixed_reporter_countries");
  if (r.unknown_country_report_count_90d > 0) t.push("unknown_reporter_country");
  if (r.data_complete === false) t.push("incomplete_data");
  const latest = r.latest_reported_at_90d ? new Date(r.latest_reported_at_90d).getTime() : 0;
  const ago = (d) => runStart.getTime() - d * 86400000;
  if (latest && latest >= ago(7)) t.push("reported_within_7d");
  if (latest && latest >= ago(30)) t.push("reported_within_30d");
  if (Number(r.check_abuse_confidence_score || 0) >= CFG.HIGH_ABUSE_CONFIDENCE_MIN) t.push("high_abuse_confidence");
  if (r.is_tor === true) t.push("tor_exit");
  for (const c of String(r.abuse_category_ids || "").split(";").filter(Boolean)) t.push(catTag(Number(c)));
  return [...new Set(t)].join(";");
}

function descOf(r, pri) {
  if (r.api_status !== "ok") return `取得できませんでした（${r.error_message || "理由不明"}）。`;
  const where = r.abuseipdb_country_code === "JP" ? "日本所在" : r.abuseipdb_country_code === "HK" ? "香港所在"
    : `${r.abuseipdb_country_code || "所在不明"}所在（対象外）`;
  const parts = [`${where}の悪性IP候補。`];
  if (r.returned_report_count_90d === 0) { parts.push("過去90日の報告は確認できませんでした。"); return parts.join(""); }
  parts.push(`過去90日に${r.returned_report_count_90d}件の報告を確認し、日本から${r.jp_report_count_90d}件、異なる日本レポーター${r.jp_distinct_reporters_90d}人`);
  parts.push(r.non_jp_report_count_90d ? `、日本以外から${r.non_jp_report_count_90d}件。` : "、日本以外からの報告なし。");
  if (r.unknown_country_report_count_90d) parts.push(`レポーター国不明が${r.unknown_country_report_count_90d}件。`);
  if (r.latest_jp_reported_at_90d) parts.push(`日本からの最新報告は${r.latest_jp_reported_at_90d.slice(0, 10)}。`);
  if (r.data_complete === false) parts.push(`API上の全報告数${r.total_reports_90d}件に対し取得は${r.returned_report_count_90d}件で、確認数は下限値です。`);
  return parts.join("");
}

const rankOf = new Map(snap.candidates.map((c) => [c.ip_address, c]));
const rows = [];
for (const [ip, rec] of done) {
  const c = rankOf.get(ip) || {};
  const [priority, pattern] = classify(rec);
  const jpOnlySel = priority === "P1" || priority === "P3";
  const twoPlus = (rec.jp_distinct_reporters_90d || 0) >= 2;
  rows.push({
    blacklist_rank: c.blacklist_rank ?? "",
    ip_address: ip,
    ip_version: rec.ip_version ?? 4,
    priority, priority_pattern: pattern,
    selected_jp_only_90d: jpOnlySel,
    selected_jp_reporters_2plus_90d: twoPlus,
    selected_for_prioritized_output: ["P1", "P2", "P3", "P4"].includes(priority)
      && inScope(rec.abuseipdb_country_code) && (rec.jp_report_count_90d || 0) > 0,
    blacklist_country_code: c.blacklist_country_code ?? "",
    abuseipdb_country_code: rec.abuseipdb_country_code ?? "",
    location_scope: rec.api_status === "ok" ? inScope(rec.abuseipdb_country_code) : "",
    location_match: rec.api_status === "ok" && c.blacklist_country_code
      ? c.blacklist_country_code === rec.abuseipdb_country_code : "",
    blacklist_generated_at: snap.generatedAt,
    blacklist_last_reported_at: c.blacklist_last_reported_at ?? "",
    blacklist_abuse_confidence_score: c.blacklist_abuse_confidence_score ?? "",
    check_abuse_confidence_score: rec.check_abuse_confidence_score ?? "",
    window_start_utc: iso(windowStart), window_end_utc: iso(windowEnd),
    checked_at_utc: rec.checked_at_utc ?? "",
    latest_jp_reported_at_90d: rec.latest_jp_reported_at_90d ?? "",
    latest_reported_at_90d: rec.latest_reported_at_90d ?? "",
    api_last_reported_at: rec.api_last_reported_at ?? "",
    total_reports_90d: rec.total_reports_90d ?? "",
    returned_report_count_90d: rec.returned_report_count_90d ?? "",
    jp_report_count_90d: rec.jp_report_count_90d ?? "",
    non_jp_report_count_90d: rec.non_jp_report_count_90d ?? "",
    unknown_country_report_count_90d: rec.unknown_country_report_count_90d ?? "",
    distinct_reporters_90d_api: rec.distinct_reporters_90d_api ?? "",
    distinct_reporters_returned_90d: rec.distinct_reporters_returned_90d ?? "",
    jp_distinct_reporters_90d: rec.jp_distinct_reporters_90d ?? "",
    jp_report_ratio_90d: rec.jp_report_ratio_90d ?? "",
    reporter_country_codes: rec.reporter_country_codes ?? "",
    non_jp_reporter_country_codes: rec.non_jp_reporter_country_codes ?? "",
    abuse_category_ids: rec.abuse_category_ids ?? "",
    abuse_category_names: rec.abuse_category_names ?? "",
    abuse_category_counts: rec.abuse_category_counts ?? "",
    analysis_tags: tagsOf(rec),
    usage_type: rec.usage_type ?? "", isp: rec.isp ?? "",
    domain: rec.domain ?? "", hostnames: rec.hostnames ?? "",
    is_tor: rec.is_tor ?? "", is_whitelisted: rec.is_whitelisted ?? "",
    description_ja: descOf(rec, priority),
    data_complete: rec.data_complete ?? "",
    api_status: rec.api_status ?? "", http_status: rec.http_status ?? "",
    error_message: rec.error_message ?? "",
  });
}

const PRI_ORDER = { P1: 1, P2: 2, P3: 3, P4: 4, P5: 5, P8: 8, P9: 9 };
const ipNum = (ip) => ip.split(".").reduce((a, b) => a * 256 + Number(b), 0);
const num = (v) => (v === "" || v == null ? -1 : Number(v));
rows.sort((a, b) =>
  PRI_ORDER[a.priority] - PRI_ORDER[b.priority]
  || num(b.jp_distinct_reporters_90d) - num(a.jp_distinct_reporters_90d)
  || String(b.latest_jp_reported_at_90d).localeCompare(String(a.latest_jp_reported_at_90d))
  || num(b.jp_report_ratio_90d) - num(a.jp_report_ratio_90d)
  || num(b.jp_report_count_90d) - num(a.jp_report_count_90d)
  || num(b.check_abuse_confidence_score) - num(a.check_abuse_confidence_score)
  || num(a.blacklist_rank) - num(b.blacklist_rank)
  || ipNum(a.ip_address) - ipNum(b.ip_address));

const HEADER = ["blacklist_rank", "ip_address", "ip_version", "priority", "priority_pattern",
  "selected_jp_only_90d", "selected_jp_reporters_2plus_90d", "selected_for_prioritized_output",
  "blacklist_country_code", "abuseipdb_country_code", "location_scope", "location_match",
  "blacklist_generated_at", "blacklist_last_reported_at", "blacklist_abuse_confidence_score",
  "check_abuse_confidence_score", "window_start_utc", "window_end_utc", "checked_at_utc",
  "latest_jp_reported_at_90d", "latest_reported_at_90d", "api_last_reported_at",
  "total_reports_90d", "returned_report_count_90d", "jp_report_count_90d",
  "non_jp_report_count_90d", "unknown_country_report_count_90d", "distinct_reporters_90d_api",
  "distinct_reporters_returned_90d", "jp_distinct_reporters_90d", "jp_report_ratio_90d",
  "reporter_country_codes", "non_jp_reporter_country_codes", "abuse_category_ids",
  "abuse_category_names", "abuse_category_counts", "analysis_tags", "usage_type", "isp",
  "domain", "hostnames", "is_tor", "is_whitelisted", "description_ja", "data_complete",
  "api_status", "http_status", "error_message"];
// 外から来る文字列だけ無害化する
const EXTERNAL = new Set(["isp", "domain", "hostnames", "usage_type", "abuseipdb_country_code",
  "blacklist_country_code", "reporter_country_codes", "non_jp_reporter_country_codes",
  "abuse_category_names", "error_message"]);

writeCsv(path.join(HERE, "abuseipdb_jp_hk_checked_all_90d.csv"), HEADER, rows, EXTERNAL);
const picked = rows.filter((r) => r.selected_for_prioritized_output);
writeCsv(path.join(HERE, "abuseipdb_jp_hk_jp_reporters_prioritized_90d.csv"), HEADER, picked, EXTERNAL);

/* ---------------- サマリー ---------------- */

const count = (f) => rows.filter(f).length;
const pri = (p) => count((r) => r.priority === p);
const unprocessed = snap.candidates.filter((c) => c.blacklist_location_scope).length - done.size;
const sum = `# AbuseIPDB — 日本・香港所在の悪性IP候補における日本レポーター観測（過去90日）

> **この文書は Claude（AI）が自動生成したものです。人の確認を前提としてください。**

## 実行

| | |
| --- | --- |
| 実行日時 | ${iso(runStart)} |
| 調査期間 | ${iso(windowStart)} 〜 ${iso(windowEnd)}（実行時刻から遡るローリング${CFG.REPORT_WINDOW_DAYS}日） |
| Blacklist 取得条件 | \`onlyCountries=${snap.query.onlyCountries}\` \`confidenceMinimum=${snap.query.confidenceMinimum}\` \`limit=${snap.query.limit}\` \`ipVersion=${snap.query.ipVersion}\` |
| Blacklist 生成日時 | ${snap.generatedAt} |
| スナップショット ID | ${snap.snapshot_id} |

## 件数

| | 件数 |
| --- | --- |
| Blacklist 候補 | ${snap.candidates.length} |
| 詳細確認の対象（所在地が範囲内） | ${snap.candidates.filter((c) => c.blacklist_location_scope).length} |
| 詳細確認を試行 | ${done.size} |
| うち成功 | ${count((r) => r.api_status === "ok")} |
| うち API エラー | ${count((r) => r.api_status !== "ok")} |
| 未処理 | ${Math.max(0, unprocessed)} |

### 所在地（\`/check\` の \`data.countryCode\`）

| | 件数 |
| --- | --- |
| JP | ${count((r) => r.abuseipdb_country_code === "JP")} |
| HK | ${count((r) => r.abuseipdb_country_code === "HK")} |
| 範囲外 | ${count((r) => r.api_status === "ok" && r.location_scope === false)} |
| Blacklist と不一致 | ${count((r) => r.location_match === false)} |

### 優先順位

| | 意味 | 件数 |
| --- | --- | --- |
| **P1** | 日本のみ かつ 日本レポーター2人以上 | **${pri("P1")}** |
| **P2** | 日本レポーター2人以上（混在または不完全） | **${pri("P2")}** |
| P3 | 日本のみ・単一レポーター | ${pri("P3")} |
| P4 | 日本からの報告あり・2人未満 | ${pri("P4")} |
| P5 | 日本からの報告なし | ${pri("P5")} |
| P8 | 所在地が範囲外 | ${pri("P8")} |
| P9 | 判定不能 | ${pri("P9")} |

| | 件数 |
| --- | --- |
| 日本のみ（\`selected_jp_only_90d\`） | ${count((r) => r.selected_jp_only_90d === true)} |
| 日本レポーター2人以上 | ${count((r) => r.selected_jp_reporters_2plus_90d === true)} |
| 両方（= P1） | ${pri("P1")} |
| 取得不完全（\`incomplete_data\`） | ${count((r) => r.data_complete === false)} |
| 優先抽出CSVの行数 | ${picked.length} |

## API

| | |
| --- | --- |
| \`/blacklist\` 呼び出し | 1 |
| \`/check\` 呼び出し | ${used} |
| 上限（ヘッダ） | ${quota.limit ?? "?"} |
| 残量（最後に見た値） | ${quota.remaining ?? "?"} |
| リセット | ${quota.reset ? iso(new Date(quota.reset * 1000)) : "?"} |
| 中断 | ${stopped || "なし"} |

## 設定値

\`\`\`
${Object.entries(CFG).map(([k, v]) => `${k}=${v}`).join("\n")}
\`\`\`

## 制約と注意

- **レポーターの所在地は、攻撃対象の地域を直接示しません。** 「日本のレポーターから報告されている」ことは、日本向けの攻撃や日本企業への攻撃を証明しません。日本に観測者が多い、監視機器の分布が偏っている、といった理由でも同じ結果になります。
- **IP の所在地は現在の推定値**であり、報告が行われた時点の所在地や、攻撃者本人の所在地とは限りません。
- **Blacklist に載っていることは悪性の確定ではありません。** AbuseIPDB 上の候補として扱ってください。
- \`/check\` が返す報告配列は最大 10,000 件です。\`total_reports_90d\` を下回る場合は \`data_complete=false\` とし、確認できた数は**下限値**です。この実行では \`/reports\` による全件補完は行っていません。
- 独立レポーター数は、返却された報告のうち \`reporterId\` が null でないもののユニーク数です。**レポーター ID 自体は保存していません。**
- 報告本文（コメント）は CSV に保存していません。
- 対象 IP への直接アクセス・走査は一切行っていません。AbuseIPDB の公開情報のみです。
`;
fs.writeFileSync(path.join(HERE, "abuseipdb_jp_hk_jp_reporters_summary_90d.md"), sum);

console.log(`\nP1 ${pri("P1")} / P2 ${pri("P2")} / P3 ${pri("P3")} / P4 ${pri("P4")} / P5 ${pri("P5")} / P8 ${pri("P8")} / P9 ${pri("P9")}`);
console.log(`優先抽出 ${picked.length} 行 / 全件 ${rows.length} 行 / 未処理 ${Math.max(0, unprocessed)} 件`);
console.log(`API: /blacklist 1 回 + /check ${used} 回 / 残量 ${quota.remaining ?? "?"}`);
