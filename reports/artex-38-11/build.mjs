#!/usr/bin/env node
// ARTEX_38_11 — 写しから CSV と summary.json を組む。
// **写しだけを見る。API は呼ばない。** 同じ写しからは何度でも同じものが出る。
//
//   node build.mjs
//
// ## このデータセットの答えは「負」である可能性が高い
//
// 負の答えを出すときに一番やってはいけないのは、**計測器が壊れていたのを
// 「汚れが無い」と読むこと**である。そこで次を必ず出す。
//
//   - 分母（引けた写しの数）と、引けなかった数
//   - 対照実験の結果（既知の汚い IP を同じ経路で引いて通報が出ること）
//   - 「通報 0」は **誰も通報していない**という意味であって、
//     **無害**という意味ではないという明示
//
// 新しく立てたばかりの攻撃基盤は、まさにこの見た目になる。
//
// 日本向けの観測は `reporterCountryCode === "JP"` で数える。これが言えるのは
// 「通報した人が日本に居る」ことだけで、攻撃先が日本であることは意味しない。
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  CATEGORIES, VULN_ANY, STRICT_VULN, AUTH_ATTACK, SCAN_ONLY, EXPLOITED_HOST,
  sanitize, forDisplay, grade, sha256, uniq, iso, detectScanner,
} from "../global-jp-vuln/rules.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "../..");
const CACHE = path.join(HERE, ".cache");
const CFG = JSON.parse(fs.readFileSync(path.join(HERE, "config.json"), "utf8"));

/* ---------------- 対象と写し ---------------- */

const targets = [];
for (const r of CFG.RANGES) {
  const base = r.split("/")[0].split(".").slice(0, 3).join(".");
  for (let i = CFG.HOST_RANGE[0]; i <= CFG.HOST_RANGE[1]; i++) targets.push(`${base}.${i}`);
}
const loadCopies = (kind) => {
  const dir = path.join(CACHE, kind);
  const m = new Map();
  if (!fs.existsSync(dir)) return m;
  for (const d of fs.readdirSync(dir)) {
    const sub = path.join(dir, d);
    if (!fs.statSync(sub).isDirectory()) continue;
    for (const f of fs.readdirSync(sub)) {
      if (!f.endsWith(".json")) continue;
      let rec = null;
      try { rec = JSON.parse(fs.readFileSync(path.join(sub, f), "utf8")); } catch { continue; }
      if (rec?.ip) m.set(rec.ip, rec);
    }
  }
  return m;
};
const abuse = loadCopies("abuseipdb");
const vt = loadCopies("virustotal");
if (!abuse.size) {
  console.error(`${CACHE}/abuseipdb に写しがありません。先に fetch.mjs --abuse を実行してください。`);
  process.exit(1);
}
const anchorIso = [...abuse.values()].map((c) => c.fetched_at).filter(Boolean).sort().pop();
const NOW = new Date(anchorIso).getTime();
const SINCE = NOW - CFG.REPORT_WINDOW_DAYS * 86400000;

/* ---------------- 索引が何か言っているか ---------------- */

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
/** 前回の ARTEX 調査で索引に残った痕跡。今回のものと比べるための控え */
const artexCerts = readJsonl("derived-certs.jsonl")
  .filter((c) => /artex/i.test(JSON.stringify(c)))
  .map((c) => ({ thumbprint: c.thumbprint, issuer: c.issuer, subject: c.subject, iocs: c.iocs }));

/* ---------------- 1 IP ずつ畳む ---------------- */

const rows = [];
for (const ip of targets) {
  const a = abuse.get(ip), v = vt.get(ip);
  const b = a?.body || null;
  const va = v?.body?.attributes || null;
  const reports = Array.isArray(b?.reports) ? b.reports : [];
  const inWindow = reports.filter((r) => r.reportedAt && new Date(r.reportedAt).getTime() >= SINCE);
  const jpAll = reports.filter((r) => r.reporterCountryCode === "JP");
  const jp = inWindow.filter((r) => r.reporterCountryCode === "JP");
  const catOf = (r) => (r.categories || []).map(Number);
  const hasAny = (r, s) => catOf(r).some((c) => s.has(c));
  const jpVuln = jp.filter((r) => hasAny(r, VULN_ANY));
  const distinct = (xs) => uniq(xs.map((r) => r.reporterId).filter((x) => x != null)).length;
  const graded = jpVuln.map((r) => {
    const clean = sanitize(r.comment);
    return { ...grade(clean), clean, at: iso(r.reportedAt), sha: r.comment ? sha256(String(r.comment)) : "" };
  }).sort((x, y) => y.level - x.level || String(y.at).localeCompare(String(x.at)));
  const jpCats = uniq(jp.flatMap(catOf)).sort((x, y) => x - y);
  const sc = b ? detectScanner({ hostnames: b.hostnames, domain: b.domain, isp: b.isp }) : { flag: false, name: "", confidence: "", evidence: "" };
  const st = va?.last_analysis_stats || {};

  rows.push({
    ip_address: ip,
    range: `${ip.split(".").slice(0, 3).join(".")}.0/24`,
    /* ---- AbuseIPDB ---- */
    abuse_checked: !!b,
    abuse_confidence_score: b ? (b.abuseConfidenceScore ?? 0) : "",
    abuse_total_reports_365d: b ? (b.totalReports ?? 0) : "",
    abuse_distinct_reporters_365d: b ? (b.numDistinctUsers ?? 0) : "",
    abuse_last_reported_at: b?.lastReportedAt ? iso(b.lastReportedAt) : "",
    abuse_reports_in_90d: b ? inWindow.length : "",
    /* ---- 日本向けの観測（ここが主眼） ---- */
    jp_report_count_365d: b ? jpAll.length : "",
    jp_report_count_90d: b ? jp.length : "",
    jp_distinct_reporters_90d: b ? distinct(jp) : "",
    jp_vuln_report_count_90d: b ? jpVuln.length : "",
    jp_vuln_distinct_reporters_90d: b ? distinct(jpVuln) : "",
    latest_jp_reported_at: jp.length ? iso(jp.map((r) => r.reportedAt).sort().pop()) : "",
    jp_category_ids: jpCats.join(";"),
    jp_category_names: jpCats.map((c) => CATEGORIES[c] || `unknown(${c})`).join(";"),
    jp_strict_vuln_report_count_90d: b ? jp.filter((r) => hasAny(r, STRICT_VULN)).length : "",
    jp_auth_attack_report_count_90d: b ? jp.filter((r) => hasAny(r, AUTH_ATTACK)).length : "",
    jp_scan_only_report_count_90d: b ? jp.filter((r) => !hasAny(r, VULN_ANY) && (hasAny(r, SCAN_ONLY) || !catOf(r).length)).length : "",
    jp_exploited_host_report_count_90d: b ? jp.filter((r) => catOf(r).includes(EXPLOITED_HOST)).length : "",
    jp_evidence_level_max: graded.length ? graded[0].level : "",
    jp_evidence_terms: uniq(graded.flatMap((g) => g.terms)).join(";"),
    jp_evidence_example_1: graded[0] ? forDisplay(graded[0].clean) : "",
    jp_evidence_comment_sha256: graded.slice(0, 3).map((g) => g.sha).filter(Boolean).join(";"),
    /* ---- 所在と素性 ---- */
    ip_country_code: b?.countryCode || va?.country || "",
    usage_type: b?.usageType || "",
    isp: b?.isp || "",
    domain: b?.domain || "",
    hostnames: (b?.hostnames || []).join(";"),
    is_tor: b ? b.isTor === true : "",
    is_whitelisted: b ? b.isWhitelisted === true : "",
    /* ---- VirusTotal ---- */
    vt_checked: !!v,
    vt_known: v ? v.status === 200 : "",
    vt_malicious: va ? (st.malicious ?? 0) : "",
    vt_suspicious: va ? (st.suspicious ?? 0) : "",
    vt_harmless: va ? (st.harmless ?? 0) : "",
    vt_undetected: va ? (st.undetected ?? 0) : "",
    vt_reputation: va ? (va.reputation ?? 0) : "",
    vt_votes_malicious: va?.total_votes?.malicious ?? "",
    vt_asn: va?.asn ?? "",
    vt_as_owner: va?.as_owner || "",
    vt_network: va?.network || "",
    vt_tags: (va?.tags || []).join(";"),
    vt_first_seen: va?.first_seen_date ? iso(new Date(va.first_seen_date * 1000)) : "",
    vt_last_analysis: va?.last_analysis_date ? iso(new Date(va.last_analysis_date * 1000)) : "",
    /* ---- 証明書（前回の ARTEX はここから見つかった） ---- */
    cert_issuer: va?.last_https_certificate
      ? Object.values(va.last_https_certificate.issuer || {}).join(" ") : "",
    cert_subject_cn: va?.last_https_certificate?.subject?.CN || "",
    cert_not_after: va?.last_https_certificate?.validity?.not_after || "",
    cert_sans: (va?.last_https_certificate?.extensions?.subject_alternative_name || []).join(";"),
    cert_mentions_artex: va?.last_https_certificate
      ? /artex/i.test(JSON.stringify(va.last_https_certificate)) : "",
    /* ---- 研究スキャナと索引 ---- */
    research_scanner_flag: sc.flag,
    research_scanner_name: sc.name,
    in_threat_index: inIndex.has(ip),
    index_actors: [...(actorsOf.get(ip) || [])].sort().join(";"),
    /* ---- 評定 ---- */
    reputation_verdict: !b ? "未取得"
      : (b.abuseConfidenceScore ?? 0) === 0 && (b.totalReports ?? 0) === 0
        && (!va || (st.malicious ?? 0) + (st.suspicious ?? 0) === 0)
        ? "通報・検知なし（無害の証明ではない）"
        : jpVuln.length ? "日本から脆弱性攻撃として報告あり"
          : jp.length ? "日本からの報告あり（脆弱性カテゴリ以外）"
            : "日本以外からの通報・検知あり",
  });
}
const ipNum = (ip) => ip.split(".").reduce((a, b) => a * 256 + Number(b), 0);
rows.sort((a, b) => ipNum(a.ip_address) - ipNum(b.ip_address));

/* ---------------- 出力 ---------------- */

const BOM = "﻿";
const deFormula = (s) => (/^[=+\-@\t\r\n]/.test(s) ? "'" + s : s);
const cell = (v, ext) => {
  if (v === null || v === undefined) return "";
  let s = String(v);
  if (ext) s = deFormula(s);
  return /[",\r\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
};
const HEADER = Object.keys(rows[0]);
/** 外部由来の文字列。表計算が式として読まないように先頭へ `'` を足す */
const EXT = new Set(["isp", "domain", "hostnames", "usage_type", "vt_as_owner", "vt_tags",
  "cert_issuer", "cert_subject_cn", "cert_sans", "jp_evidence_example_1", "jp_evidence_terms",
  "jp_category_names", "index_actors", "research_scanner_name", "reputation_verdict"]);
const writeCsv = (file, rs) => fs.writeFileSync(path.join(HERE, file),
  BOM + [HEADER.join(","), ...rs.map((r) => HEADER.map((h) => cell(r[h], EXT.has(h))).join(","))].join("\r\n") + "\r\n");

const jpObserved = rows.filter((r) => Number(r.jp_report_count_365d) > 0);
const anyReport = rows.filter((r) => Number(r.abuse_total_reports_365d) > 0);
const anyDetect = rows.filter((r) => Number(r.vt_malicious) + Number(r.vt_suspicious) > 0);
writeCsv("artex_38_11_all.csv", rows);
writeCsv("artex_38_11_jp_observed.csv", jpObserved);
writeCsv("artex_38_11_flagged.csv", uniq([...anyReport, ...anyDetect]));

const tally = (rs, f) => {
  const m = new Map();
  for (const r of rs) for (const v of [].concat(f(r))) if (v !== "" && v !== undefined && v !== null) m.set(String(v), (m.get(String(v)) || 0) + 1);
  return [...m].sort((a, b) => (b[1] - a[1]) || (a[0] < b[0] ? -1 : 1));
};
const summary = {
  dataset: CFG.DATASET,
  ranges: CFG.RANGES,
  host_range: CFG.HOST_RANGE,
  generated_from: "写しのみ。API は呼んでいない",
  collected_at_utc: anchorIso,
  fetch_window_days: CFG.FETCH_WINDOW_DAYS,
  report_window: { start_utc: iso(new Date(SINCE)), end_utc: iso(new Date(NOW)), days: CFG.REPORT_WINDOW_DAYS },
  coverage: {
    targets: targets.length,
    abuseipdb_checked: rows.filter((r) => r.abuse_checked).length,
    abuseipdb_missing: rows.filter((r) => !r.abuse_checked).length,
    virustotal_checked: rows.filter((r) => r.vt_checked).length,
    virustotal_missing: rows.filter((r) => !r.vt_checked).length,
    virustotal_unknown_404: rows.filter((r) => r.vt_checked && r.vt_known === false).length,
  },
  /** **主眼。日本からの観測** */
  japan: {
    ips_with_any_jp_report_365d: jpObserved.length,
    ips_with_jp_report_90d: rows.filter((r) => Number(r.jp_report_count_90d) > 0).length,
    ips_with_jp_vuln_report_90d: rows.filter((r) => Number(r.jp_vuln_report_count_90d) > 0).length,
    total_jp_reports_365d: rows.reduce((s, r) => s + (Number(r.jp_report_count_365d) || 0), 0),
  },
  abuseipdb: {
    ips_with_any_report_365d: anyReport.length,
    ips_with_score_above_0: rows.filter((r) => Number(r.abuse_confidence_score) > 0).length,
    max_score: Math.max(0, ...rows.map((r) => Number(r.abuse_confidence_score) || 0)),
    total_reports_365d: rows.reduce((s, r) => s + (Number(r.abuse_total_reports_365d) || 0), 0),
    tor: rows.filter((r) => r.is_tor === true).length,
    whitelisted: rows.filter((r) => r.is_whitelisted === true).length,
    research_scanner: rows.filter((r) => r.research_scanner_flag).length,
  },
  virustotal: {
    ips_with_detection: anyDetect.length,
    max_malicious: Math.max(0, ...rows.map((r) => Number(r.vt_malicious) || 0)),
    ips_with_certificate: rows.filter((r) => r.cert_issuer).length,
    ips_with_artex_in_certificate: rows.filter((r) => r.cert_mentions_artex === true).length,
    reputation_below_0: rows.filter((r) => Number(r.vt_reputation) < 0).length,
  },
  infrastructure: {
    isp: Object.fromEntries(tally(rows, (r) => r.isp)),
    usage_type: Object.fromEntries(tally(rows, (r) => r.usage_type)),
    country: Object.fromEntries(tally(rows, (r) => r.ip_country_code)),
    vt_as: Object.fromEntries(tally(rows, (r) => (r.vt_asn ? `AS${r.vt_asn} ${r.vt_as_owner}` : ""))),
    vt_network: Object.fromEntries(tally(rows, (r) => r.vt_network)),
    with_rdns: rows.filter((r) => r.hostnames).length,
    cert_issuers: Object.fromEntries(tally(rows, (r) => r.cert_issuer)),
  },
  threat_index: {
    already_present: rows.filter((r) => r.in_threat_index).length,
    with_actor: rows.filter((r) => r.index_actors).length,
    /** 前回の ARTEX 調査の痕跡。今回の 250 件とは別物 */
    prior_artex_certificates: artexCerts,
  },
  verdicts: Object.fromEntries(tally(rows, (r) => r.reputation_verdict)),
  by_range: Object.fromEntries(CFG.RANGES.map((rg) => {
    const sub = rows.filter((r) => r.range === rg);
    return [rg, {
      ips: sub.length,
      with_report: sub.filter((r) => Number(r.abuse_total_reports_365d) > 0).length,
      with_jp_report: sub.filter((r) => Number(r.jp_report_count_365d) > 0).length,
      with_detection: sub.filter((r) => Number(r.vt_malicious) + Number(r.vt_suspicious) > 0).length,
      with_certificate: sub.filter((r) => r.cert_issuer).length,
    }];
  })),
};
const stable = (v) => JSON.stringify(v, (k, x) =>
  (x && typeof x === "object" && !Array.isArray(x)
    ? Object.fromEntries(Object.entries(x).sort(([a], [b]) => (a < b ? -1 : 1)))
    : x), 2);
fs.writeFileSync(path.join(HERE, "artex_38_11_summary.json"), stable(summary) + "\n");

console.log(`対象 ${targets.length} IP / AbuseIPDB ${summary.coverage.abuseipdb_checked} 件 `
  + `/ VirusTotal ${summary.coverage.virustotal_checked} 件`);
console.log(`**日本からの通報があった IP: ${summary.japan.ips_with_any_jp_report_365d} 件**`
  + `（うち脆弱性カテゴリ ${summary.japan.ips_with_jp_vuln_report_90d} 件）`);
console.log(`AbuseIPDB で通報が 1 件以上: ${summary.abuseipdb.ips_with_any_report_365d} 件 `
  + `/ 最大スコア ${summary.abuseipdb.max_score}`);
console.log(`VirusTotal で検知が 1 以上: ${summary.virustotal.ips_with_detection} 件 `
  + `/ 証明書あり ${summary.virustotal.ips_with_certificate} 件 `
  + `/ 証明書に ARTEX ${summary.virustotal.ips_with_artex_in_certificate} 件`);
for (const [k, v] of Object.entries(summary.verdicts)) console.log(`  ${k}  ${v}`);
