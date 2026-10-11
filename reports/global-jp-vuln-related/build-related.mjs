#!/usr/bin/env node
// GLOBAL_JP_VULN の P1/P2 を**種**として、そこから関連する IP を出す。
// 昨日の一覧に無いものだけを返す（差分）。判定規則は ../global-jp-vuln/rules.mjs と共有。
//
//   node build-related.mjs [--max-check 2000] [--plan]
//
// 対象 IP への接続・走査は行わない。AbuseIPDB の公開情報だけを見る。
//
// ## 何を「関連」と呼ぶか、呼ばないか
//
// **呼ぶ: 種が濃く集まっている /24 に同居していること。**
// 密度（種 ÷ その /24 にある Blacklist の総数）で見る。172.236.228.0/24 は
// Blacklist 17 件中 14 件が種で、ひとつの持ち主の帯とみてよい。
// 一方 69.5.169.0/24 は 253 件中 7 件（2.8%）で、これは単に大きな汚れた帯。
// **同じ /24 に居るというだけでは関連と言えない。**
//
// **呼ばない: コメント本文が一致すること。** 実測で、2 IP 以上に同じ本文が付く
// 151 通りの中身は `Shield: Layer4 Port 9 Trap` `Knock-Knock honeypot brute-force: HTTP`
// `port=80, indicator_type=info-leak` のような**通報者の検知器が吐く定型文**だった。
// これが結ぶのは攻撃者ではなく観測者で、829 件の「関連」はすべて偽物だった。
//
// **補助: 証拠の語の組み合わせが一致すること。** 語 2 つ以上が一致する組だけを見る。
// ただし dotenv や offensive-wording のような一般的な語は誰にでも付くので、
// 単独では根拠にせず印として残す。
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  CATEGORIES, STRICT_VULN, VULN_ANY, AUTH_ATTACK, SCAN_ONLY, EXPLOITED_HOST,
  iso, sha256, uniq, sanitize, forDisplay, grade, detectScanner,
} from "../global-jp-vuln/rules.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SRC = path.join(HERE, "..", "global-jp-vuln");
const CACHE = path.join(HERE, ".cache");
const args = process.argv.slice(2);
const argOf = (f) => { const i = args.indexOf(f); return i >= 0 ? args[i + 1] : null; };
const MAX_CHECK = Number(argOf("--max-check") || 2000);
const RESERVE = 200;
const MIN_SEEDS = 3;        // /24 に種が何件あれば候補にするか
const MIN_DENSITY = 0.10;   // 種 ÷ その /24 の Blacklist 数

const KEY = process.env.ABUSEIPDB_API_KEY;
if (!KEY) { console.error("ABUSEIPDB_API_KEY がありません。終了します。"); process.exit(2); }

/* ---------------- 種と母集団を読む ---------------- */
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
const seed = [...parseCsv(fs.readFileSync(path.join(SRC, "global_jp_vuln_priority_p1.csv"), "utf8")),
  ...parseCsv(fs.readFileSync(path.join(SRC, "global_jp_vuln_priority_p2.csv"), "utf8"))];
const seedIps = new Set(seed.map((r) => r.ip_address));
const snap = JSON.parse(fs.readFileSync(path.join(SRC, ".cache", "blacklist-snapshot.json"), "utf8"));
const prior = new Map();
for (const line of fs.readFileSync(path.join(SRC, ".cache", "checks.jsonl"), "utf8").split("\n")) {
  if (!line.trim()) continue;
  try { const r = JSON.parse(line); prior.set(r.ip_address, r); } catch { /* 壊れた行は飛ばす */ }
}
console.log(`種（P1+P2）${seed.length} 件 / Blacklist ${snap.entries.length} 件 / 昨日 check 済み ${prior.size} 件`);

/* ---------------- 関連の候補を作る ---------------- */
const s24 = (ip) => ip.split(".").slice(0, 3).join(".");
const nets = new Map();
for (const e of snap.entries) { const n = s24(e.ip); if (!nets.has(n)) nets.set(n, { all: [], seeds: [] }); nets.get(n).all.push(e); }
for (const r of seed) { const n = s24(r.ip_address); if (nets.has(n)) nets.get(n).seeds.push(r); }

const dense = [...nets].map(([n, v]) => ({ net: n, seeds: v.seeds.length, total: v.all.length,
  density: v.all.length ? v.seeds.length / v.all.length : 0, all: v.all, seedRows: v.seeds }))
  .filter((d) => d.seeds >= MIN_SEEDS && d.density >= MIN_DENSITY)
  .sort((a, b) => b.density - a.density || b.seeds - a.seeds);
console.log(`\n関連の候補となる /24: ${dense.length} 網（種 ${MIN_SEEDS} 件以上 かつ 密度 ${MIN_DENSITY * 100}% 以上）`);

const candidates = [];
for (const d of dense) for (const e of d.all) {
  if (seedIps.has(e.ip)) continue;
  candidates.push({ ip: e.ip, cc: e.cc, score: e.score, last: e.last,
    relation: "same_dense_24", net: d.net + ".0/24", net_seeds: d.seeds, net_total: d.total,
    net_density: Number(d.density.toFixed(3)),
    related_seed_ips: d.seedRows.slice(0, 5).map((s) => s.ip_address).join(";"),
    related_seed_priority: uniq(d.seedRows.map((s) => s.priority)).sort().join(";") });
}

/* 補助の関連: 証拠の語の組み合わせが種と一致（語 2 つ以上） */
const sigOf = (r) => {
  const t = String(r.evidence_terms || "").split(";").filter(Boolean).sort();
  const c = String(r.jp_vuln_category_ids || "").split(";").filter(Boolean).sort();
  return t.length >= 2 ? t.join(",") + "|" + c.join(",") : null;
};
const seedSigs = new Map();
for (const r of seed) { const s = sigOf(r); if (s) { if (!seedSigs.has(s)) seedSigs.set(s, []); seedSigs.get(s).push(r.ip_address); } }
const known = new Set(candidates.map((c) => c.ip));
let sigAdded = 0;
for (const [ip, r] of prior) {
  if (seedIps.has(ip) || known.has(ip)) continue;
  const s = sigOf(r);
  if (!s || !seedSigs.has(s)) continue;
  candidates.push({ ip, cc: r.ip_country_code, score: r.abuse_confidence_score, last: r.latest_reported_at_90d,
    relation: "same_evidence_signature", net: s24(ip) + ".0/24", net_seeds: 0, net_total: 0, net_density: 0,
    related_seed_ips: seedSigs.get(s).slice(0, 5).join(";"), related_seed_priority: "",
    signature: s });
  known.add(ip); sigAdded++;
}
console.log(`候補: 同じ濃い /24 に居る ${candidates.length - sigAdded} 件 + 証拠の組み合わせ一致 ${sigAdded} 件 = ${candidates.length} 件`);
const needCheck = candidates.filter((c) => !prior.has(c.ip));
console.log(`  うち昨日 check 済み ${candidates.length - needCheck.length} 件 / 今回引く必要があるもの ${needCheck.length} 件`);
if (args.includes("--plan")) { console.log("引かずに終わります（--plan）"); process.exit(0); }

/* ---------------- /check ---------------- */
fs.mkdirSync(CACHE, { recursive: true });
const ckFile = path.join(CACHE, "checks.jsonl");
const fresh = new Map();
if (fs.existsSync(ckFile)) for (const line of fs.readFileSync(ckFile, "utf8").split("\n")) {
  if (!line.trim()) continue;
  try { const r = JSON.parse(line); fresh.set(r.ip_address, r); } catch { /* 飛ばす */ }
}
const quota = { limit: null, remaining: null, reset: null, retryAfter: null };
const apiLog = [];
async function callApi(url) {
  for (let attempt = 0; ; attempt++) {
    let res;
    try { res = await fetch(url, { headers: { Key: KEY, Accept: "application/json" } }); }
    catch (e) { if (attempt >= 2) return { ok: false, error: "network" }; await new Promise((r) => setTimeout(r, 1000 * 2 ** attempt)); continue; }
    const n = (h) => { const v = res.headers.get(h); return v == null ? null : Number(v); };
    quota.limit = n("x-ratelimit-limit") ?? quota.limit;
    quota.remaining = n("x-ratelimit-remaining") ?? quota.remaining;
    quota.reset = n("x-ratelimit-reset") ?? quota.reset;
    quota.retryAfter = res.headers.get("retry-after") ? Number(res.headers.get("retry-after")) : quota.retryAfter;
    apiLog.push({ at: new Date().toISOString(), http_status: res.status, ratelimit_remaining: quota.remaining });
    if (res.status === 429) return { ok: false, rateLimited: true, error: `429 (Retry-After ${quota.retryAfter ?? "?"})` };
    if (res.status >= 500) { if (attempt >= 2) return { ok: false, error: "server " + res.status }; await new Promise((r) => setTimeout(r, 1000 * 2 ** attempt)); continue; }
    if (!res.ok) return { ok: false, httpStatus: res.status, error: "HTTP " + res.status };
    try { return { ok: true, body: await res.json() }; } catch { return { ok: false, error: "parse" }; }
  }
}

/** 昨日と同じ数え方。**日本の報告 1 件ずつ**でカテゴリを見る */
function digest(ip, body) {
  const d = body?.data || {};
  const reports = Array.isArray(d.reports) ? d.reports : [];
  const jp = reports.filter((r) => r.reporterCountryCode === "JP");
  const cat = (r) => (r.categories || []).map(Number);
  const any = (r, s) => cat(r).some((c) => s.has(c));
  const jpVuln = jp.filter((r) => any(r, VULN_ANY));
  const jpStrict = jp.filter((r) => any(r, STRICT_VULN));
  const graded = jpVuln.map((r) => { const clean = sanitize(r.comment); const g = grade(clean);
    return { ...g, clean, at: iso(r.reportedAt), reporter: r.reporterId ?? null, sha: r.comment ? sha256(String(r.comment)) : "" }; })
    .sort((a, b) => b.level - a.level || String(b.at).localeCompare(String(a.at)));
  const cats = uniq(jpVuln.flatMap(cat).filter((c) => VULN_ANY.has(c))).sort((a, b) => a - b);
  const distinct = (xs) => uniq(xs.map((r) => r.reporterId).filter((x) => x != null)).length;
  const latest = (xs) => xs.map((r) => r.reportedAt).filter(Boolean).sort().pop() || "";
  const sc = detectScanner(d);
  return { ip_address: ip, api_status: "ok", checked_at_utc: iso(new Date()),
    abuse_confidence_score: d.abuseConfidenceScore ?? "", ip_country_code: d.countryCode || "",
    usage_type: d.usageType || "", isp: d.isp || "", domain: d.domain || "",
    hostnames: (d.hostnames || []).join(";"), is_tor: d.isTor === true,
    total_reports_90d: d.totalReports ?? 0, distinct_reporters_90d: d.numDistinctUsers ?? "",
    latest_reported_at_90d: iso(latest(reports)),
    jp_report_count_90d: jp.length, jp_distinct_reporters_90d: distinct(jp),
    jp_vuln_report_count_90d: jpVuln.length, jp_vuln_distinct_reporters_90d: distinct(jpVuln),
    jp_strict_vuln_report_count_90d: jpStrict.length, jp_strict_vuln_distinct_reporters_90d: distinct(jpStrict),
    jp_auth_attack_report_count_90d: jp.filter((r) => any(r, AUTH_ATTACK)).length,
    jp_scan_only_report_count_90d: jp.filter((r) => !any(r, VULN_ANY) && (any(r, SCAN_ONLY) || cat(r).length === 0)).length,
    jp_exploited_host_report_count_90d: jp.filter((r) => cat(r).includes(EXPLOITED_HOST)).length,
    latest_jp_vuln_reported_at_90d: iso(latest(jpVuln)),
    jp_vuln_category_ids: cats.join(";"), jp_vuln_category_names: cats.map((c) => CATEGORIES[c]).join(";"),
    evidence_level_max: graded.length ? graded[0].level : "",
    evidence_terms: uniq(graded.flatMap((g) => g.terms)).join(";"),
    evidence_example_1: graded[0] ? forDisplay(graded[0].clean) : "",
    evidence_comment_sha256: graded.slice(0, 3).map((g) => g.sha).filter(Boolean).join(";"),
    research_scanner_flag: sc.flag, research_scanner_name: sc.name, research_scanner_confidence: sc.confidence,
  };
}

const probe = await callApi("https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=1");
const budget = Math.max(0, Math.min(MAX_CHECK, (quota.remaining ?? MAX_CHECK) - RESERVE));
console.log(`\n/check 残量 ${quota.remaining ?? "?"} → 今回の上限 ${budget} 件`);
const todo = needCheck.filter((c) => !fresh.has(c.ip)).slice(0, budget);
const ck = fs.createWriteStream(ckFile, { flags: "a" });
let used = 1, done = 0, stopped = null;
const queue = [...todo];
async function worker() {
  for (;;) {
    const c = queue.shift();
    if (!c || stopped) return;
    if (used >= budget + 1 || (quota.remaining != null && quota.remaining <= RESERVE)) { stopped = stopped || "枠の上限"; return; }
    used++;
    const q = new URLSearchParams({ ipAddress: c.ip, maxAgeInDays: "90", verbose: "" });
    const r = await callApi(`https://api.abuseipdb.com/api/v2/check?${q}`);
    if (r.rateLimited) { stopped = r.error; queue.unshift(c); used--; return; }
    const rec = r.ok ? digest(c.ip, r.body)
      : { ip_address: c.ip, api_status: "error", error_message: String(r.error).slice(0, 120), checked_at_utc: iso(new Date()) };
    await new Promise((res) => ck.write(JSON.stringify(rec) + "\n", res));
    fresh.set(c.ip, rec);
    if (++done % 100 === 0) process.stdout.write(`\r  ${done}/${todo.length}  残量 ${quota.remaining ?? "?"}      `);
  }
}
await Promise.all(Array.from({ length: 8 }, worker));
ck.end();
console.log(`\n/check ${done} 件 / API ${used} 回` + (stopped ? ` — 中断: ${stopped}` : ""));

/* ---------------- まとめる ---------------- */
const rows = [];
for (const c of candidates) {
  const r = fresh.get(c.ip) || prior.get(c.ip);
  if (!r) continue;
  const from = fresh.has(c.ip) ? "today" : "yesterday_cache";
  const jpVuln = Number(r.jp_vuln_report_count_90d || 0);
  const lv = Number(r.evidence_level_max || 0);
  const scanner = r.research_scanner_flag === true && r.research_scanner_confidence === "high";
  // 関連の強さ。**種との近さ**と**それ自身の性質**を分けて持つ
  let verdict, why;
  if (r.api_status !== "ok") { verdict = "判定不能"; why = r.error_message || ""; }
  else if (scanner) { verdict = "除外（研究スキャナ）"; why = r.research_scanner_name; }
  else if (jpVuln > 0 && (Number(r.jp_strict_vuln_distinct_reporters_90d || 0) >= 2 || lv >= 2)) {
    verdict = "関連・強"; why = "種と同じ濃い帯に居り、かつ自身も日本から脆弱性攻撃として報告されている";
  } else if (jpVuln > 0) { verdict = "関連・中"; why = "自身も日本から脆弱性攻撃として報告されているが根拠は弱い"; }
  else if (Number(r.jp_report_count_90d || 0) > 0) { verdict = "関連・弱"; why = "日本からの報告はあるが脆弱性カテゴリではない"; }
  else { verdict = "同居のみ"; why = "種と同じ帯に居るが、日本からの報告は確認できない"; }
  rows.push({ ...c, ...r, relation_source: from, relation_verdict: verdict, relation_reason: why,
    is_new_vs_yesterday: !seedIps.has(c.ip) });
}
const ORDER = { "関連・強": 1, "関連・中": 2, "関連・弱": 3, "同居のみ": 4, "除外（研究スキャナ）": 8, "判定不能": 9 };
rows.sort((a, b) => ORDER[a.relation_verdict] - ORDER[b.relation_verdict]
  || Number(b.net_density) - Number(a.net_density)
  || Number(b.jp_vuln_report_count_90d || 0) - Number(a.jp_vuln_report_count_90d || 0)
  || a.ip.localeCompare(b.ip));
rows.forEach((r, i) => { r.rank = i + 1; });

const BOM = "﻿";
const deF = (s) => (/^[=+\-@\t\r\n]/.test(s) ? "'" + s : s);
const cell = (v, ext) => { if (v == null) return ""; let s = String(v); if (ext) s = deF(s);
  return /[",\r\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };
const HEADER = ["rank", "ip", "relation", "relation_verdict", "relation_reason", "relation_source",
  "net", "net_seeds", "net_total", "net_density", "related_seed_ips", "related_seed_priority", "signature",
  "abuse_confidence_score", "ip_country_code", "usage_type", "isp", "domain", "hostnames", "is_tor",
  "total_reports_90d", "distinct_reporters_90d", "latest_reported_at_90d",
  "jp_report_count_90d", "jp_distinct_reporters_90d", "jp_vuln_report_count_90d",
  "jp_vuln_distinct_reporters_90d", "jp_strict_vuln_report_count_90d", "jp_strict_vuln_distinct_reporters_90d",
  "jp_auth_attack_report_count_90d", "jp_scan_only_report_count_90d", "jp_exploited_host_report_count_90d",
  "latest_jp_vuln_reported_at_90d", "jp_vuln_category_ids", "jp_vuln_category_names",
  "evidence_level_max", "evidence_terms", "evidence_example_1", "evidence_comment_sha256",
  "research_scanner_flag", "research_scanner_name", "research_scanner_confidence",
  "checked_at_utc", "api_status", "error_message"];
const EXT = new Set(["isp", "domain", "hostnames", "usage_type", "evidence_example_1", "evidence_terms",
  "jp_vuln_category_names", "relation_reason", "error_message", "signature"]);
const write = (f, rs) => fs.writeFileSync(path.join(HERE, f),
  BOM + [HEADER.join(","), ...rs.map((r) => HEADER.map((h) => cell(r[h], EXT.has(h))).join(","))].join("\r\n") + "\r\n");

write("related_ips_all.csv", rows);
write("related_ips_strong.csv", rows.filter((r) => r.relation_verdict === "関連・強"));
write("related_ips_excluded.csv", rows.filter((r) => ORDER[r.relation_verdict] >= 8));

const n = (v) => rows.filter((r) => r.relation_verdict === v).length;
const summary = {
  dataset: "GLOBAL_JP_VULN_RELATED", generated_at_utc: iso(new Date()),
  seed: { source: "global_jp_vuln P1+P2", count: seed.length },
  method: { dense_24: { min_seeds: MIN_SEEDS, min_density: MIN_DENSITY, networks: dense.length },
    evidence_signature: { added: sigAdded, note: "語 2 つ以上の一致のみ" },
    rejected: { comment_sha256: "通報者の定型文だったため不採用（実測 829 件が偽の関連）" } },
  candidates: candidates.length,
  checked: { today: done, from_yesterday_cache: candidates.length - needCheck.length, api_calls: used,
    quota_remaining: quota.remaining, stopped },
  verdicts: { "関連・強": n("関連・強"), "関連・中": n("関連・中"), "関連・弱": n("関連・弱"),
    "同居のみ": n("同居のみ"), "除外（研究スキャナ）": n("除外（研究スキャナ）"), "判定不能": n("判定不能") },
  networks: dense.map((d) => ({ net: d.net + ".0/24", seeds: d.seeds, total: d.total, density: Number(d.density.toFixed(3)) })),
};
fs.writeFileSync(path.join(HERE, "related_summary.json"), JSON.stringify(summary, null, 1));
fs.writeFileSync(path.join(HERE, "api_call_log.json"), JSON.stringify({ calls: apiLog.length, quota, log: apiLog }, null, 1));

console.log(`\n関連・強 ${n("関連・強")} / 中 ${n("関連・中")} / 弱 ${n("関連・弱")} / 同居のみ ${n("同居のみ")} / 除外 ${n("除外（研究スキャナ）")} / 不能 ${n("判定不能")}`);
console.log(`合計 ${rows.length} 件（すべて昨日の一覧に無い IP）`);
