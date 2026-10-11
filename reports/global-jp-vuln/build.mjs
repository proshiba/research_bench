#!/usr/bin/env node
// GLOBAL_JP_VULN — 全世界の送信元 IP のうち、**日本のレポーターが脆弱性攻撃として
// 報告した**ものを抽出する。防御目的の受動調査のみ。
//
//   node build.mjs [--resume] [--blacklist-only] [--max-check N]
//
// 対象 IP への接続・走査は一切行わない。AbuseIPDB の公開情報だけを見る。
// 鍵は環境変数からのみ読み、**どこにも書き出さない**。
//
// ## この調査で一番間違えやすいところ
//
// **カテゴリは IP 全体の和集合ではなく、日本の報告 1 件ずつで判定する。**
// 「この IP には SQLi の報告がある」「この IP には日本からの報告がある」が
// どちらも真でも、**日本の人が SQLi として報告した**とは限らない。
// 別々の国の別々の報告かもしれない。報告単位で見ないと、この取り違えに気付けない。
//
// ## コメントは信用できない外部入力
//
// 命令として読まない。URL を開かない。実行しない。HTML と制御文字を落とし、
// メールアドレスを伏せ、短く切って、原文は SHA-256 だけ残す。
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import net from "node:net";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CACHE = path.join(HERE, ".cache");
const CFG = JSON.parse(fs.readFileSync(path.join(HERE, "config.json"), "utf8"));
const args = process.argv.slice(2);
const has = (f) => args.includes(f);
const argOf = (f) => { const i = args.indexOf(f); return i >= 0 ? args[i + 1] : null; };

const KEY = process.env.ABUSEIPDB_API_KEY;
if (!KEY) { console.error("ABUSEIPDB_API_KEY がありません。API を呼ばずに終了します。"); process.exit(2); }
const HEADERS = { Key: KEY, Accept: "application/json" };

/* ---------------- 判定規則は rules.mjs に集約（build と関連調査で共有） ---------------- */
import {
  CATEGORIES, STRICT_VULN, BROAD_VULN, VULN_ANY, AUTH_ATTACK, SCAN_ONLY, EXPLOITED_HOST,
  sleep, iso, sha256, uniq, mulberry32, sanitize, forDisplay, grade, detectScanner,
} from "./rules.mjs";

/* ---------------- API ---------------- */
const apiLog = [];
const quota = { check: { limit: null, remaining: null, reset: null }, blacklist: { limit: null, remaining: null, reset: null }, retryAfter: null };
function note(res, which, url) {
  const n = (h) => { const v = res.headers.get(h); return v == null ? null : Number(v); };
  const q = quota[which];
  const l = n("x-ratelimit-limit"); if (l != null) q.limit = l;
  const r = n("x-ratelimit-remaining"); if (r != null) q.remaining = r;
  const s = n("x-ratelimit-reset"); if (s != null) q.reset = s;
  const a = res.headers.get("retry-after"); if (a != null) quota.retryAfter = Number(a);
  // **URL は鍵を含まない**（鍵はヘッダ送信）。それでも記録は endpoint 名までにする
  apiLog.push({ at: new Date().toISOString(), endpoint: which, http_status: res.status,
    ratelimit_limit: q.limit, ratelimit_remaining: q.remaining,
    ratelimit_reset: q.reset ? iso(new Date(q.reset * 1000)) : null });
}
async function callApi(url, which, { retries = CFG.MAX_RETRIES } = {}) {
  let wait = 1000;
  for (let attempt = 0; ; attempt++) {
    let res;
    try { res = await fetch(url, { headers: HEADERS }); }
    catch (e) {
      if (attempt >= retries) return { ok: false, httpStatus: null, error: "network: " + String(e.message || e).slice(0, 80) };
      await sleep(wait); wait *= 2; continue;
    }
    note(res, which, url);
    if (res.status === 429) return { ok: false, httpStatus: 429, rateLimited: true, error: `429 (Retry-After ${quota.retryAfter ?? "?"})` };
    if (res.status >= 500) {
      if (attempt >= retries) return { ok: false, httpStatus: res.status, error: "server error " + res.status };
      await sleep(wait); wait *= 2; continue;
    }
    if (!res.ok) {
      let detail = "";
      try { detail = ((await res.json()).errors || []).map((e) => e.detail).join("; ").slice(0, 120); } catch { /* 本文が無くても status は残る */ }
      return { ok: false, httpStatus: res.status, error: ("HTTP " + res.status + (detail ? ": " + detail : "")).slice(0, 160) };
    }
    try { return { ok: true, httpStatus: res.status, body: await res.json() }; }
    catch { return { ok: false, httpStatus: res.status, error: "応答を解析できません" }; }
  }
}

/* ================= フェーズ 1: Blacklist ================= */
fs.mkdirSync(CACHE, { recursive: true });
const runStart = new Date();
const STATE_FILE = path.join(HERE, "state.json");

let snap;
const snapFile = path.join(CACHE, "blacklist-snapshot.json");
const rawFile = path.join(CACHE, "blacklist-raw.json");
if ((has("--resume") || fs.existsSync(snapFile)) && fs.existsSync(snapFile)) {
  snap = JSON.parse(fs.readFileSync(snapFile, "utf8"));
  console.log(`既存スナップショットを使います（${snap.entries.length} 件 / 生成 ${snap.generatedAt}）`);
} else {
  let body;
  if (fs.existsSync(rawFile)) {
    body = JSON.parse(fs.readFileSync(rawFile, "utf8"));
    console.log("取得済みの Blacklist 生データを使います");
  } else {
    const q = new URLSearchParams({ confidenceMinimum: String(CFG.BLACKLIST_CONFIDENCE_MINIMUM),
      limit: String(CFG.BLACKLIST_LIMIT), ipVersion: String(CFG.IP_VERSION) });
    const r = await callApi(`https://api.abuseipdb.com/api/v2/blacklist?${q}`, "blacklist");
    if (!r.ok) { console.error("Blacklist を取得できません: " + r.error); process.exit(1); }
    body = r.body;
    fs.writeFileSync(rawFile, JSON.stringify(body));
  }
  const seen = new Set();
  const entries = [];
  for (const row of body.data || []) {
    const ip = String(row.ipAddress || "").trim();
    if (!net.isIPv4(ip) || seen.has(ip)) continue;
    seen.add(ip);
    entries.push({ ip, cc: row.countryCode || "", score: row.abuseConfidenceScore ?? null, last: row.lastReportedAt || "" });
  }
  snap = { generatedAt: iso(body.meta?.generatedAt), fetched_at: iso(runStart),
    query: { confidenceMinimum: CFG.BLACKLIST_CONFIDENCE_MINIMUM, limit: CFG.BLACKLIST_LIMIT, ipVersion: CFG.IP_VERSION },
    truncated_at_tier_max: (body.data || []).length >= CFG.BLACKLIST_LIMIT, entries };
  fs.writeFileSync(snapFile, JSON.stringify(snap));
}
console.log(`Blacklist ${snap.entries.length} 件 / 生成 ${snap.generatedAt}`);
if (has("--blacklist-only")) process.exit(0);

/* ================= フェーズ 2: Check 対象の選定 ================= */
const cutoff30 = runStart.getTime() - 30 * 86400000;
const eligible = snap.entries.filter((e) => e.score >= 75 && e.last && new Date(e.last).getTime() >= cutoff30);
console.log(`候補（30日以内 かつ 信頼度75以上）: ${eligible.length} 件`);

// 残量はヘッダが正。先に 1 回だけ /check を叩いて今日の残りを知る
const probe = await callApi("https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=1", "check");
const remaining = quota.check.remaining;
const hardMax = Number(argOf("--max-check") || CFG.MAX_CHECK_CALLS);
const budget = Math.max(0, Math.min(hardMax, (remaining ?? hardMax) - CFG.CHECK_RESERVE));
console.log(`/check 残量 ${remaining ?? "?"} / 上限 ${quota.check.limit ?? "?"} → 今回使うのは最大 ${budget} 件`);
if (budget <= 0) { console.log("枠がありません。終了します。"); process.exit(0); }

const cacheIdx = path.join(CACHE, "checks.jsonl");
const cached = new Map();
if (fs.existsSync(cacheIdx)) {
  for (const line of fs.readFileSync(cacheIdx, "utf8").split("\n")) {
    if (!line.trim()) continue;
    try { const r = JSON.parse(line); if (runStart.getTime() - new Date(r.checked_at_utc).getTime() <= CFG.CACHE_TTL_HOURS * 3600000) cached.set(r.ip_address, r); } catch { /* 壊れた行は無視 */ }
  }
  console.log(`24時間以内の有効キャッシュ ${cached.size} 件（再取得しません）`);
}

const fresh = eligible.filter((e) => !cached.has(e.ip));
const byRecent = [...fresh].sort((a, b) => String(b.last).localeCompare(String(a.last)));
let selected = [];
if (byRecent.length <= budget) {
  selected = byRecent.map((e) => ({ ...e, cohort: "recent_core" }));
} else {
  const coreN = Math.min(CFG.RECENT_CORE, budget);
  const sampleN = Math.max(0, budget - coreN);
  const core = byRecent.slice(0, coreN).map((e) => ({ ...e, cohort: "recent_core" }));
  const rest = byRecent.slice(coreN);
  const bands = { "75-84": [], "85-94": [], "95-100": [] };
  for (const e of rest) bands[e.score >= 95 ? "95-100" : e.score >= 85 ? "85-94" : "75-84"].push(e);
  const rnd = mulberry32(CFG.RANDOM_SEED);
  const per = Math.floor(sampleN / 3);
  const sample = [];
  for (const k of Object.keys(bands)) {
    const pool = bands[k];
    // 再現できるよう、決まった順に並べてから種つき乱数で引く
    pool.sort((a, b) => (a.ip < b.ip ? -1 : 1));
    const take = Math.min(per, pool.length);
    const idx = new Set();
    while (idx.size < take) idx.add(Math.floor(rnd() * pool.length));
    for (const i of idx) sample.push({ ...pool[i], cohort: "confidence_audit_sample" });
  }
  // 端数は最近順から足す
  let i = coreN;
  while (core.length + sample.length < budget && i < byRecent.length) {
    const e = byRecent[i++];
    if (!sample.some((s) => s.ip === e.ip)) core.push({ ...e, cohort: "recent_core" });
  }
  selected = [...core, ...sample];
}
console.log(`今回 /check する: ${selected.length} 件（recent_core ${selected.filter((s) => s.cohort === "recent_core").length} / confidence_audit_sample ${selected.filter((s) => s.cohort === "confidence_audit_sample").length}）`);

/* ================= フェーズ 3: Check ================= */
const ck = fs.createWriteStream(cacheIdx, { flags: "a" });
const failures = [];
let used = 1, stopped = null, doneN = 0;   // probe で 1 回使っている
const cohortOf = new Map(selected.map((s) => [s.ip, s.cohort]));

function digest(ip, body, cohort) {
  const d = body?.data || {};
  const reports = Array.isArray(d.reports) ? d.reports : [];
  const jp = reports.filter((r) => r.reporterCountryCode === "JP");
  const catOf = (r) => (r.categories || []).map(Number);
  const hasAny = (r, set) => catOf(r).some((c) => set.has(c));

  // **日本の報告 1 件ずつで判定する**（IP 全体の和集合ではない）
  const jpVuln = jp.filter((r) => hasAny(r, VULN_ANY));
  const jpStrict = jp.filter((r) => hasAny(r, STRICT_VULN));
  const jpBroad = jp.filter((r) => hasAny(r, BROAD_VULN));
  const jpAuth = jp.filter((r) => hasAny(r, AUTH_ATTACK));
  const jpExploited = jp.filter((r) => catOf(r).includes(EXPLOITED_HOST));
  const jpScanOnly = jp.filter((r) => !hasAny(r, VULN_ANY) && (hasAny(r, SCAN_ONLY) || catOf(r).length === 0));

  // 証拠は **日本の脆弱性報告のコメントからだけ**取る
  const graded = jpVuln.map((r) => {
    const clean = sanitize(r.comment);
    const g = grade(clean);
    return { level: g.level, terms: g.terms, clean, at: iso(r.reportedAt),
      reporter: r.reporterId ?? null, sha: r.comment ? sha256(String(r.comment)) : "" };
  }).sort((a, b) => b.level - a.level || String(b.at).localeCompare(String(a.at)));
  const top = graded.filter((g) => g.level === (graded[0]?.level ?? 0)).slice(0, 3);

  const vulnCats = uniq(jpVuln.flatMap(catOf).filter((c) => VULN_ANY.has(c))).sort((a, b) => a - b);
  const latest = (xs) => xs.map((r) => r.reportedAt).filter(Boolean).sort().pop() || "";
  const distinct = (xs) => uniq(xs.map((r) => r.reporterId).filter((x) => x != null)).length;
  const sc = detectScanner(d);

  return {
    ip_address: ip, selection_cohort: cohort, api_status: "ok", http_status: 200, error_message: "",
    checked_at_utc: iso(new Date()),
    abuse_confidence_score: d.abuseConfidenceScore ?? "", ip_country_code: d.countryCode || "",
    usage_type: d.usageType || "", isp: d.isp || "", domain: d.domain || "",
    hostnames: (d.hostnames || []).join(";"), is_tor: d.isTor === true, is_whitelisted: d.isWhitelisted === true,
    total_reports_90d: d.totalReports ?? 0, distinct_reporters_90d: d.numDistinctUsers ?? "",
    latest_reported_at_90d: iso(latest(reports)), reports_truncated: reports.length >= 10000,
    returned_reports: reports.length,
    jp_report_count_90d: jp.length, jp_distinct_reporters_90d: distinct(jp),
    latest_jp_reported_at_90d: iso(latest(jp)),
    jp_vuln_report_count_90d: jpVuln.length, jp_vuln_distinct_reporters_90d: distinct(jpVuln),
    latest_jp_vuln_reported_at_90d: iso(latest(jpVuln)),
    jp_strict_vuln_report_count_90d: jpStrict.length, jp_strict_vuln_distinct_reporters_90d: distinct(jpStrict),
    jp_broad_vuln_report_count_90d: jpBroad.length,
    jp_auth_attack_report_count_90d: jpAuth.length,
    jp_scan_only_report_count_90d: jpScanOnly.length,
    jp_exploited_host_report_count_90d: jpExploited.length,
    jp_vuln_category_ids: vulnCats.join(";"),
    jp_vuln_category_names: vulnCats.map((c) => CATEGORIES[c] || `unknown(${c})`).join(";"),
    jp_vuln_report_ratio: jp.length ? Number((jpVuln.length / jp.length).toFixed(4)) : 0,
    jp_vuln_days: uniq(jpVuln.map((r) => iso(r.reportedAt).slice(0, 10)).filter(Boolean)).length,
    evidence_level_max: graded.length ? graded[0].level : "",
    evidence_terms: uniq(graded.flatMap((g) => g.terms)).join(";"),
    evidence_example_1: top[0] ? forDisplay(top[0].clean) : "",
    evidence_example_2: top[1] ? forDisplay(top[1].clean) : "",
    evidence_example_3: top[2] ? forDisplay(top[2].clean) : "",
    evidence_comment_sha256: top.map((g) => g.sha).filter(Boolean).join(";"),
    evidence_latest_at: graded.find((g) => g.at)?.at || "",
    evidence_reporter_count: uniq(graded.map((g) => g.reporter).filter((x) => x != null)).length,
    evidence_reporter_concentration: (() => {
      const c = {}; for (const g of graded) if (g.reporter != null) c[g.reporter] = (c[g.reporter] || 0) + 1;
      const vals = Object.values(c); return vals.length ? Math.max(...vals) / graded.length : 0;
    })(),
    research_scanner_flag: sc.flag, research_scanner_name: sc.name,
    research_scanner_confidence: sc.confidence, research_scanner_evidence: sc.evidence,
  };
}

const queue = [...selected];
async function worker() {
  for (;;) {
    const e = queue.shift();
    if (!e || stopped) return;
    if (used >= budget + 1) { stopped = stopped || "予算に達しました"; return; }
    if (quota.check.remaining != null && quota.check.remaining <= CFG.CHECK_RESERVE) { stopped = "残量が予備枠に達しました"; return; }
    used++;
    const q = new URLSearchParams({ ipAddress: e.ip, maxAgeInDays: String(CFG.REPORT_WINDOW_DAYS), verbose: "" });
    const r = await callApi(`https://api.abuseipdb.com/api/v2/check?${q}`, "check");
    if (r.rateLimited) { stopped = r.error; queue.unshift(e); used--; return; }
    let rec;
    if (!r.ok) {
      failures.push({ ip_address: e.ip, endpoint: "check", http_status: r.httpStatus ?? "", error_message: String(r.error).slice(0, 200), at_utc: iso(new Date()) });
      rec = { ip_address: e.ip, selection_cohort: e.cohort, api_status: "error",
        http_status: r.httpStatus ?? "", error_message: String(r.error).slice(0, 200), checked_at_utc: iso(new Date()) };
    } else rec = digest(e.ip, r.body, e.cohort);
    await new Promise((res) => ck.write(JSON.stringify(rec) + "\n", res));
    cached.set(e.ip, rec);
    if (++doneN % 200 === 0) process.stdout.write(`\r  ${doneN}/${selected.length}  残量 ${quota.check.remaining ?? "?"}      `);
  }
}
await Promise.all(Array.from({ length: CFG.CONCURRENCY }, worker));
ck.end();
console.log(`\n/check ${doneN} 件 / API ${used} 回` + (stopped ? `  — 中断: ${stopped}` : ""));

/* ================= 評価と優先度 ================= */
const d7 = runStart.getTime() - 7 * 86400000;
const d30 = runStart.getTime() - 30 * 86400000;
const tsOf = (s) => (s ? new Date(s).getTime() : 0);

function score(r) {
  const why = [], add = (p, t) => { why.push(`${p > 0 ? "+" : ""}${p} ${t}`); return p; };
  let s = 0;
  const lv = Number(r.evidence_level_max || 0);
  if (tsOf(r.latest_jp_vuln_reported_at_90d) >= d7) s += add(20, "日本の脆弱性報告が7日以内");
  else if (tsOf(r.latest_jp_vuln_reported_at_90d) >= d30) s += add(12, "30日以内");
  if (r.jp_strict_vuln_distinct_reporters_90d >= 2) s += add(20, "strictの日本レポーター2人以上");
  if (r.jp_strict_vuln_distinct_reporters_90d >= 5) s += add(10, "同5人以上");
  if (lv === 3) s += add(25, "E3 具体的な攻撃証拠");
  else if (lv === 2) s += add(15, "E2 製品・脆弱性固有の探索");
  const cats = String(r.jp_vuln_category_ids || "").split(";").filter(Boolean).map(Number);
  if (cats.includes(16) || cats.includes(23)) s += add(8, "SQLi または IoT Targeted");
  if (cats.includes(21)) s += add(5, "Web App Attack");
  if (r.jp_vuln_days >= 2) s += add(5, "複数日に分散");
  if (r.jp_exploited_host_report_count_90d > 0) s += add(3, "Exploited Host");
  if (r.research_scanner_flag && r.research_scanner_confidence === "high") s += add(-50, "研究スキャナ（高確度）");
  if (lv === 0) s += add(-15, "E0 のみ");
  if (cats.length === 1 && cats[0] === 15) s += add(-10, "Hacking(15) のみ");
  if (Number(r.evidence_reporter_concentration || 0) >= 0.9 && r.jp_vuln_report_count_90d >= 3) s += add(-10, "単一レポーターへ極端に集中");
  return { score: Math.max(0, Math.min(100, s)), reasons: why.join(" / ") };
}

function classify(r) {
  if (r.api_status !== "ok") return { priority: "EXCLUDED_PRIMARY", reason: "APIエラー" };
  if (r.jp_vuln_report_count_90d === 0) {
    if (r.jp_report_count_90d === 0) return { priority: "EXCLUDED_PRIMARY", reason: "日本からの報告なし" };
    if (r.jp_auth_attack_report_count_90d > 0 || r.jp_scan_only_report_count_90d > 0)
      return { priority: "EXCLUDED_PRIMARY", reason: "日本報告が走査・総当たりのみで脆弱性カテゴリなし" };
    return { priority: "EXCLUDED_PRIMARY", reason: "日本報告に脆弱性カテゴリなし" };
  }
  if (r.research_scanner_flag && r.research_scanner_confidence === "high")
    return { priority: "EXCLUDED_PRIMARY", reason: `既知研究スキャナ（${r.research_scanner_name}）` };

  const lv = Number(r.evidence_level_max || 0);
  const recent30 = tsOf(r.latest_jp_vuln_reported_at_90d) >= d30;
  const strict2 = r.jp_strict_vuln_distinct_reporters_90d >= 2;
  const e3multi = lv === 3 && r.jp_vuln_report_count_90d >= 2;
  const e3multiReporter = lv === 3 && r.evidence_reporter_count >= 2;
  if ((recent30 && strict2 && lv >= 2) || e3multi || e3multiReporter) return { priority: "P1", reason: "" };
  if (strict2 || (r.jp_strict_vuln_report_count_90d > 0 && lv >= 2)
    || (r.jp_broad_vuln_report_count_90d > 0 && lv >= 2)) return { priority: "P2", reason: "" };
  return { priority: "P3", reason: "" };
}

const rows = [];
for (const [ip, rec] of cached) {
  if (!cohortOf.has(ip) && !rec.selection_cohort) continue;
  const { priority, reason } = classify(rec);
  const { score: ps, reasons } = rec.api_status === "ok" ? score(rec) : { score: 0, reasons: "" };
  const excluded = priority === "EXCLUDED_PRIMARY";
  rows.push({
    ...rec,
    dataset_name: "GLOBAL_JP_VULN", collected_at_utc: iso(runStart), blacklist_generated_at: snap.generatedAt,
    priority, priority_score: ps, priority_reasons: reasons,
    global_jp_vuln_eligible: rec.api_status === "ok" && rec.jp_vuln_report_count_90d > 0,
    excluded_from_primary_population: excluded, exclusion_reason: reason,
    likely_compromised_source: rec.jp_exploited_host_report_count_90d > 0,
    sanitized_evidence_summary: rec.api_status !== "ok" ? "" :
      `日本の脆弱性報告 ${rec.jp_vuln_report_count_90d} 件（レポーター ${rec.jp_vuln_distinct_reporters_90d} 人）。証拠段階 E${rec.evidence_level_max || 0}${rec.evidence_terms ? "（" + rec.evidence_terms.split(";").slice(0, 4).join(",") + "）" : ""}。`,
    assessment: rec.api_status !== "ok" ? "判定不能" : excluded ? `主対象から除外: ${reason}`
      : priority === "P1" ? "日本の複数観測者または具体的証拠あり。優先確認を推奨"
      : priority === "P2" ? "日本から脆弱性攻撃として報告。確認を推奨"
      : "日本からの報告はあるが根拠が弱い。参考情報",
    confidence: rec.api_status !== "ok" ? "低" : Number(rec.evidence_level_max || 0) >= 3 ? "高"
      : Number(rec.evidence_level_max || 0) === 2 ? "中" : "低",
    analysis_tags: (() => {
      const t = [];
      if (rec.jp_vuln_report_count_90d > 0) t.push("jp_vuln_observed");
      if (rec.jp_strict_vuln_distinct_reporters_90d >= 2) t.push("jp_strict_reporters_2plus");
      if (Number(rec.evidence_level_max || 0) >= 3) t.push("evidence_e3");
      else if (Number(rec.evidence_level_max || 0) === 2) t.push("evidence_e2");
      else if (Number(rec.evidence_level_max || 0) === 1) t.push("evidence_e1");
      else if (rec.jp_vuln_report_count_90d > 0) t.push("evidence_e0");
      if (rec.jp_exploited_host_report_count_90d > 0) t.push("exploited_host");
      if (rec.research_scanner_flag) t.push("research_scanner_" + (rec.research_scanner_confidence || "low"));
      if (rec.reports_truncated) t.push("reports_truncated");
      if (tsOf(rec.latest_jp_vuln_reported_at_90d) >= d7) t.push("jp_vuln_within_7d");
      if (rec.is_tor) t.push("tor");
      for (const c of String(rec.jp_vuln_category_ids || "").split(";").filter(Boolean))
        t.push("category_" + String(CATEGORIES[Number(c)] || c).toLowerCase().replace(/[^a-z0-9]+/g, "_"));
      return uniq(t).join(";");
    })(),
  });
}

const PRI = { P1: 1, P2: 2, P3: 3, EXCLUDED_PRIMARY: 9 };
const ipNum = (ip) => ip.split(".").reduce((a, b) => a * 256 + Number(b), 0);
rows.sort((a, b) => PRI[a.priority] - PRI[b.priority] || b.priority_score - a.priority_score
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
const HEADER = ["rank", "ip_address", "priority", "priority_score", "priority_reasons", "selection_cohort",
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
const EXT = new Set(["isp", "domain", "hostnames", "usage_type", "ip_country_code", "research_scanner_evidence",
  "evidence_example_1", "evidence_example_2", "evidence_example_3", "evidence_terms",
  "jp_vuln_category_names", "sanitized_evidence_summary", "error_message"]);
const writeCsv = (file, rs) => fs.writeFileSync(path.join(HERE, file),
  BOM + [HEADER.join(","), ...rs.map((r) => HEADER.map((h) => cell(r[h], EXT.has(h))).join(","))].join("\r\n") + "\r\n");

const included = rows.filter((r) => !r.excluded_from_primary_population);
writeCsv("global_jp_vuln_all_90d.csv", included);
writeCsv("global_jp_vuln_priority_p1.csv", rows.filter((r) => r.priority === "P1"));
writeCsv("global_jp_vuln_priority_p2.csv", rows.filter((r) => r.priority === "P2"));
writeCsv("global_jp_vuln_reference_p3.csv", rows.filter((r) => r.priority === "P3"));
writeCsv("global_jp_vuln_excluded.csv", rows.filter((r) => r.excluded_from_primary_population));

fs.writeFileSync(path.join(HERE, "failed_requests.csv"), BOM +
  ["ip_address,endpoint,http_status,error_message,at_utc",
    ...failures.map((f) => [f.ip_address, f.endpoint, f.http_status, cell(f.error_message, true), f.at_utc].join(","))].join("\r\n") + "\r\n");
fs.writeFileSync(path.join(HERE, "api_call_log.json"), JSON.stringify({
  run_started_at: iso(runStart), run_finished_at: iso(new Date()),
  totals: { blacklist: apiLog.filter((a) => a.endpoint === "blacklist").length, check: apiLog.filter((a) => a.endpoint === "check").length },
  final_quota: quota, stopped_reason: stopped, calls: apiLog,
}, null, 1));

const tally = (f) => rows.reduce((m, r) => { const k = f(r); if (k != null && k !== "") m[k] = (m[k] || 0) + 1; return m; }, {});
const top = (o, n) => Object.entries(o).sort((a, b) => b[1] - a[1]).slice(0, n);
const pri = (p) => rows.filter((r) => r.priority === p).length;
const evLevels = included.reduce((m, r) => { const k = "E" + (r.evidence_level_max || 0); m[k] = (m[k] || 0) + 1; return m; }, {});
const jpCats = {};
for (const r of included) for (const c of String(r.jp_vuln_category_ids).split(";").filter(Boolean))
  jpCats[`${c} ${CATEGORIES[Number(c)]}`] = (jpCats[`${c} ${CATEGORIES[Number(c)]}`] || 0) + 1;
const reporterDist = included.reduce((m, r) => { const k = r.jp_vuln_distinct_reporters_90d >= 5 ? "5+" : String(r.jp_vuln_distinct_reporters_90d); m[k] = (m[k] || 0) + 1; return m; }, {});

const summary = {
  dataset: "GLOBAL_JP_VULN", generated_at_utc: iso(runStart),
  window: { days: CFG.REPORT_WINDOW_DAYS, start_utc: iso(new Date(runStart.getTime() - CFG.REPORT_WINDOW_DAYS * 86400000)), end_utc: iso(runStart) },
  blacklist: { ...snap.query, generated_at: snap.generatedAt, entries: snap.entries.length,
    truncated_at_tier_max: snap.truncated_at_tier_max, eligible_30d: eligible.length },
  checks: { selected: selected.length, succeeded: rows.filter((r) => r.api_status === "ok").length,
    failed: failures.length, cache_reused: cached.size - doneN, api_calls_check: used,
    quota_remaining: quota.check.remaining, stopped_reason: stopped },
  population: { eligible_jp_vuln: rows.filter((r) => r.global_jp_vuln_eligible).length,
    included: included.length, P1: pri("P1"), P2: pri("P2"), P3: pri("P3"), excluded: pri("EXCLUDED_PRIMARY") },
  evidence_levels: evLevels, jp_vuln_categories: jpCats, jp_vuln_reporter_distribution: reporterDist,
  research_scanners: { flagged: rows.filter((r) => r.research_scanner_flag).length,
    high_confidence_excluded: rows.filter((r) => r.research_scanner_flag && r.research_scanner_confidence === "high").length,
    by_name: tally((r) => (r.research_scanner_flag ? r.research_scanner_name : "")) },
  exploited_host_ips: included.filter((r) => r.jp_exploited_host_report_count_90d > 0).length,
  top_countries: top(included.reduce((m, r) => { m[r.ip_country_code || "?"] = (m[r.ip_country_code || "?"] || 0) + 1; return m; }, {}), 15),
  top_isp: top(included.reduce((m, r) => { m[r.isp || "?"] = (m[r.isp || "?"] || 0) + 1; return m; }, {}), 15),
  top_usage_type: top(included.reduce((m, r) => { m[r.usage_type || "?"] = (m[r.usage_type || "?"] || 0) + 1; return m; }, {}), 10),
  exclusion_reasons: tally((r) => r.exclusion_reason),
  config: CFG,
};
fs.writeFileSync(path.join(HERE, "global_jp_vuln_summary.json"), JSON.stringify(summary, null, 1));

fs.writeFileSync(STATE_FILE, JSON.stringify({
  updated_at_utc: iso(new Date()), blacklist_generated_at: snap.generatedAt,
  blacklist_entries: snap.entries.length, eligible_30d: eligible.length,
  checked_total: cached.size, remaining_unchecked: Math.max(0, eligible.length - cached.size),
  last_run: { selected: selected.length, api_calls_check: used, stopped_reason: stopped,
    quota_remaining: quota.check.remaining, quota_reset_utc: quota.check.reset ? iso(new Date(quota.check.reset * 1000)) : null },
}, null, 1));

console.log(`\nP1 ${pri("P1")} / P2 ${pri("P2")} / P3 ${pri("P3")} / 除外 ${pri("EXCLUDED_PRIMARY")}`);
console.log(`採用 ${included.length} 行 / 日本の脆弱性報告あり ${rows.filter((r) => r.global_jp_vuln_eligible).length} 件`);
console.log(`API: blacklist ${summary.checks ? apiLog.filter((a) => a.endpoint === "blacklist").length : 0} 回 + check ${used} 回 / 残量 ${quota.check.remaining ?? "?"}`);
