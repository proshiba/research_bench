#!/usr/bin/env node
// ARTEX_TIMELINE — 写しから時系列を組む。**写しだけを見る。API は呼ばない。**
//
//   node build.mjs
//
// ## このデータで一番間違えやすいところ
//
// 「複数の IP が攻撃元として報告されている」は、**通報の件数ではなく通報者の数**で
// 見ないと意味を取り違える。実測では 46 件のうち 44 件が**単一の通報者**で、
// しかも同じ定型文・同じカテゴリだった。これは**脅威情報フィードの一括登録**で、
// 被害者が「攻撃された」と通報したものではない。
//
// そこで時系列には必ず「何人の通報者が」を付ける。1 人なら 1 人と書く。
//
// ## カテゴリ 20（Exploited Host）は攻撃手法ではない
//
// 「この送信元自体が侵害されている可能性」を示す補助情報で、「この IP が攻撃してきた」
// とは違う。踏み台にされた正規ホストなら、送信元の持ち主も被害者である。
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { CATEGORIES, sanitize, forDisplay, sha256, uniq, iso } from "../global-jp-vuln/rules.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "../..");
const CFG = JSON.parse(fs.readFileSync(path.join(HERE, "config.json"), "utf8"));

const load = (base) => {
  const m = new Map();
  if (!fs.existsSync(base)) return m;
  for (const d of fs.readdirSync(base)) {
    const sub = path.join(base, d);
    if (!fs.statSync(sub).isDirectory()) continue;
    for (const f of fs.readdirSync(sub)) {
      if (!f.endsWith(".json")) continue;
      try {
        const r = JSON.parse(fs.readFileSync(path.join(sub, f), "utf8"));
        const ip = r.ip || r.body?.ipAddress;
        if (ip) m.set(ip, r);
      } catch { /* 壊れた写しは数えない */ }
    }
  }
  return m;
};
const now = load(path.join(HERE, ".cache", "abuseipdb"));
/** 2026-10-14 の調査で取った写し。**比較の基準**になる */
const baseline = load(path.resolve(ROOT, CFG.BASELINE));
if (!now.size) {
  console.error("写しがありません。先に fetch.mjs を実行してください。");
  process.exit(1);
}
const anchorIso = [...now.values()].map((r) => r.fetched_at).filter(Boolean).sort().pop();
const baseIso = [...baseline.values()].map((r) => r.fetched_at).filter(Boolean).sort().pop() || null;

/* ---- 索引との突き合わせ ---- */
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

/* ================= 通報を 1 件ずつ並べる ================= */

/**
 * 通報者は**番号を伏せて識別子に置き換える**。同じ人かどうかだけが分かればよい。
 * `reporterId` の値は保存しない。
 */
const ridLabel = new Map();
const labelOf = (cc, rid) => {
  const k = cc + "|" + rid;
  if (!ridLabel.has(k)) ridLabel.set(k, `${cc}-R${String(ridLabel.size + 1).padStart(2, "0")}`);
  return ridLabel.get(k);
};

const events = [];
for (const r of now.values()) {
  for (const x of (r.body.reports || [])) {
    const cats = (x.categories || []).map(Number).sort((a, b) => a - b);
    const clean = sanitize(x.comment);
    events.push({
      reported_at: x.reportedAt,
      day: String(x.reportedAt).slice(0, 10),
      ip_address: r.ip,
      cluster: r.cluster,
      reporter: labelOf(x.reporterCountryCode, x.reporterId),
      reporter_country: x.reporterCountryCode,
      category_ids: cats.join(";"),
      category_names: cats.map((c) => CATEGORIES[c] || `unknown(${c})`).join(";"),
      /** 本文は無害化して短く切る。**原文は保存せず SHA-256 だけ残す** */
      comment_excerpt: forDisplay(clean, 120),
      comment_sha256: x.comment ? sha256(String(x.comment)) : "",
      comment_empty: !x.comment,
    });
  }
}
const ipNum = (ip) => ip.split(".").reduce((a, b) => a * 256 + Number(b), 0);
events.sort((a, b) => String(a.reported_at).localeCompare(String(b.reported_at))
  || ipNum(a.ip_address) - ipNum(b.ip_address));
events.forEach((e, i) => { e.seq = i + 1; });

/* ================= IP ごとの状態と、基準との差 ================= */

const rows = [];
for (const r of [...now.values()].sort((a, b) => ipNum(a.ip) - ipNum(b.ip))) {
  const b = r.body;
  const mine = events.filter((e) => e.ip_address === r.ip);
  const base = baseline.get(r.ip)?.body;
  rows.push({
    ip_address: r.ip,
    cluster: r.cluster,
    /* ---- 今回（基準日との差が本題） ---- */
    reports_now: b.totalReports ?? 0,
    reporters_now: b.numDistinctUsers ?? 0,
    score_now: b.abuseConfidenceScore ?? 0,
    first_reported_at: mine.length ? mine[0].reported_at : "",
    last_reported_at: b.lastReportedAt || "",
    /* ---- 基準（2026-10-14 の ARTEX 調査） ---- */
    baseline_available: !!base,
    reports_baseline: base ? (base.totalReports ?? 0) : "",
    score_baseline: base ? (base.abuseConfidenceScore ?? 0) : "",
    /** **新しく通報が付いたか。**これが時系列の主役 */
    newly_reported: !!base && (base.totalReports ?? 0) === 0 && (b.totalReports ?? 0) > 0,
    /* ---- 誰がどう通報したか ---- */
    distinct_reporters_seen: uniq(mine.map((e) => e.reporter)).length,
    reporters: uniq(mine.map((e) => e.reporter)).sort().join(";"),
    reporter_countries: uniq(mine.map((e) => e.reporter_country)).sort().join(";"),
    category_ids: uniq(mine.flatMap((e) => e.category_ids.split(";"))).filter(Boolean)
      .sort((a, b2) => Number(a) - Number(b2)).join(";"),
    category_names: uniq(mine.flatMap((e) => e.category_names.split(";"))).filter(Boolean).sort().join(";"),
    /* ---- 素性 ---- */
    ip_country_code: b.countryCode || "",
    isp: b.isp || "",
    domain: b.domain || "",
    hostnames: (b.hostnames || []).join(";"),
    usage_type: b.usageType || "",
    is_tor: b.isTor === true,
    is_whitelisted: b.isWhitelisted === true,
    in_threat_index: inIndex.has(r.ip),
  });
}

/* ================= 通報者ごとの素性 ================= */

/**
 * 本文の「形」を数えるときは**日付と数字を畳む**。
 *
 * 定型文は日付だけが違うことが多く、素のまま数えると
 * `... Last observed 2026-10-17 UTC.` と `... 2026-10-24 UTC.` が
 * 別の本文に見えてしまう。**日付が違うだけの定型文は 1 通りと数える。**
 * これを畳まずに数えて、44 件 1 人の一括登録を取り逃がした。
 */
const shapeOf = (s) => String(s || "")
  .replace(/\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2})?)?/g, "<date>")
  .replace(/\b\d+\b/g, "<n>")
  .replace(/\s+/g, " ").trim();

const reporters = [];
for (const label of uniq(events.map((e) => e.reporter)).sort()) {
  const mine = events.filter((e) => e.reporter === label);
  const texts = uniq(mine.map((e) => shapeOf(e.comment_excerpt)));
  reporters.push({
    reporter: label,
    country: mine[0].reporter_country,
    reports: mine.length,
    distinct_ips: uniq(mine.map((e) => e.ip_address)).length,
    distinct_days: uniq(mine.map((e) => e.day)).length,
    days: uniq(mine.map((e) => e.day)).sort().join(";"),
    clusters: uniq(mine.map((e) => e.cluster)).sort().join(";"),
    category_names: uniq(mine.flatMap((e) => e.category_names.split(";"))).filter(Boolean).sort().join(";"),
    /** **1 通りなら定型文。**その通報者は 1 件ずつ見ていない */
    distinct_comment_shapes: texts.length,
    comment_shape: forDisplay(texts[0] || "", 120),
    comment_excerpt: forDisplay(mine[0].comment_excerpt || "", 120),
    /** フィードの一括登録らしいか。**判定ではなく印** */
    looks_like_bulk_feed: mine.length >= 10 && texts.length === 1,
  });
}

/* ================= 日ごと ================= */

const byDay = [];
for (const day of uniq(events.map((e) => e.day)).sort()) {
  const mine = events.filter((e) => e.day === day);
  byDay.push({
    day,
    reports: mine.length,
    distinct_ips: uniq(mine.map((e) => e.ip_address)).length,
    distinct_reporters: uniq(mine.map((e) => e.reporter)).length,
    clusters: uniq(mine.map((e) => e.cluster)).sort().join(";"),
    category_names: uniq(mine.flatMap((e) => e.category_names.split(";"))).filter(Boolean).sort().join(";"),
    artex_ips: uniq(mine.filter((e) => e.cluster === "ARTEX").map((e) => e.ip_address)).length,
    sub2api_ips: uniq(mine.filter((e) => e.cluster === "sub2api").map((e) => e.ip_address)).length,
  });
}

/* ================= 出力 ================= */

const BOM = "﻿";
const deFormula = (s) => (/^[=+\-@\t\r\n]/.test(s) ? "'" + s : s);
const cell = (v, ext) => {
  if (v === null || v === undefined) return "";
  let s = String(v);
  if (ext) s = deFormula(s);
  return /[",\r\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
};
const EXT = new Set(["isp", "domain", "hostnames", "usage_type", "category_names",
  "comment_excerpt", "ip_country_code", "reporter_country"]);
const writeCsv = (file, rs, head) => {
  const H = head || Object.keys(rs[0] || {});
  fs.writeFileSync(path.join(HERE, file),
    BOM + [H.join(","), ...rs.map((r) => H.map((h) => cell(r[h], EXT.has(h))).join(","))].join("\r\n") + "\r\n");
};
writeCsv("artex_timeline_events.csv", events,
  ["seq", "reported_at", "day", "ip_address", "cluster", "reporter", "reporter_country",
    "category_ids", "category_names", "comment_empty", "comment_excerpt", "comment_sha256"]);
writeCsv("artex_timeline_by_ip.csv", rows);
writeCsv("artex_timeline_by_reporter.csv", reporters);
writeCsv("artex_timeline_by_day.csv", byDay);

const tally = (rs, f) => {
  const m = new Map();
  for (const r of rs) for (const v of [].concat(f(r))) {
    if (v === "" || v === undefined || v === null) continue;
    m.set(String(v), (m.get(String(v)) || 0) + 1);
  }
  return [...m].sort((a, b) => (b[1] - a[1]) || (a[0] < b[0] ? -1 : 1));
};
const perCluster = {};
for (const c of uniq(rows.map((r) => r.cluster))) {
  const mine = rows.filter((r) => r.cluster === c);
  const rep = mine.filter((r) => r.reports_now > 0);
  perCluster[c] = {
    ips: mine.length,
    with_reports_now: rep.length,
    with_reports_baseline: mine.filter((r) => r.baseline_available && r.reports_baseline > 0).length,
    newly_reported: mine.filter((r) => r.newly_reported).length,
    baseline_available: mine.filter((r) => r.baseline_available).length,
    total_reports_now: mine.reduce((s, r) => s + (r.reports_now || 0), 0),
    max_score_now: Math.max(0, ...mine.map((r) => r.score_now || 0)),
    distinct_reporters: uniq(events.filter((e) => e.cluster === c).map((e) => e.reporter)).length,
    jp_reports: events.filter((e) => e.cluster === c && e.reporter_country === "JP").length,
    with_rdns: mine.filter((r) => r.hostnames).length,
    in_threat_index: mine.filter((r) => r.in_threat_index).length,
    isp: Object.fromEntries(tally(mine, (r) => r.isp)),
    rdns_domains: Object.fromEntries(tally(mine, (r) => {
      const h = String(r.hostnames || "").split(";")[0];
      return h ? h.split(".").slice(-2).join(".") : "";
    })),
  };
}
const summary = {
  dataset: CFG.DATASET,
  generated_from: "写しのみ。API は呼んでいない",
  collected_at_utc: anchorIso,
  baseline_collected_at_utc: baseIso,
  fetch_window_days: CFG.FETCH_WINDOW_DAYS,
  clusters: CFG.CLUSTERS.map((c) => ({ name: c.name, note: c.note,
    ranges: c.ranges || null, explicit: c.explicit || null })),
  per_cluster: perCluster,
  reports: {
    total: events.length,
    distinct_ips: uniq(events.map((e) => e.ip_address)).length,
    distinct_reporters: uniq(events.map((e) => e.reporter)).length,
    first: events[0]?.reported_at || null,
    last: events[events.length - 1]?.reported_at || null,
    by_reporter_country: Object.fromEntries(tally(events, (e) => e.reporter_country)),
    by_category: Object.fromEntries(tally(events, (e) => e.category_names.split(";"))),
    empty_comments: events.filter((e) => e.comment_empty).length,
  },
  /**
   * **一括登録らしい通報者。**ここが大きいと「複数 IP が報告されている」の意味が変わる。
   * 件数ではなく通報者の数で見るための印。
   */
  bulk_feeds: reporters.filter((r) => r.looks_like_bulk_feed)
    .map((r) => ({ reporter: r.reporter, country: r.country, reports: r.reports,
      distinct_ips: r.distinct_ips, days: r.days, category_names: r.category_names,
      comment_excerpt: r.comment_excerpt })),
  by_day: byDay,
  reporters,
};
const stable = (v) => JSON.stringify(v, (k, x) =>
  (x && typeof x === "object" && !Array.isArray(x)
    ? Object.fromEntries(Object.entries(x).sort(([a], [b]) => (a < b ? -1 : 1)))
    : x), 2);
fs.writeFileSync(path.join(HERE, "artex_timeline_summary.json"), stable(summary) + "\n");

console.log(`写し ${now.size} IP（基準 ${baseline.size} IP / ${baseIso?.slice(0, 10) ?? "なし"}）`);
for (const [c, v] of Object.entries(perCluster)) {
  console.log(`  ${c}: ${v.ips} IP / 通報あり ${v.with_reports_now}`
    + `（基準日は ${v.baseline_available ? v.with_reports_baseline : "—"}）`
    + ` / 新しく付いた ${v.newly_reported} / 通報者 ${v.distinct_reporters} 人 / 日本から ${v.jp_reports}`);
}
console.log(`通報 ${events.length} 件 / ${summary.reports.distinct_ips} IP / 通報者 ${summary.reports.distinct_reporters} 人`);
if (summary.bulk_feeds.length) {
  for (const f of summary.bulk_feeds) {
    console.log(`  ! 一括登録らしい通報者: ${f.reporter} が ${f.reports} 件 / ${f.distinct_ips} IP`
      + `（同じ本文 1 通り、${f.category_names}）`);
  }
}
