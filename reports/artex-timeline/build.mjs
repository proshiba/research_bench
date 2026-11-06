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
//
// ## `reportedAt` は観測日、`lastReportedAt` は投稿日（2026-11-06 に実測）
//
// この 2 つを同じ「通報日時」として扱うと時系列を取り違える。実測:
//
// - フィードの本文 `... Last observed <日付> UTC.` の日付が `reportedAt` の日付と
//   **58/58 件一致**した。つまり `reportedAt` は**通報者が申告した観測時刻**で、
//   AbuseIPDB が受け取った時刻ではない。さかのぼって投稿できる。
// - `lastReportedAt` は 57/65 件で `reports[]` の最新より**後ろ**にあり、前になった
//   例は 0 件。さかのぼり日数は中央 1.04 日・最大 7.32 日。
// - 投稿時刻は 56 件中 40 件が 01 時台（UTC）に固まる。夜間バッチの投稿窓。
//   観測時刻は 00/04/16/18 時に散る。**別の時計で動いている。**
//
// ここから 2 つ出てくる。
//
// 1. **`lastReportedAt` を活動日として図に載せてはいけない。**それは投稿日で、
//    その日に攻撃があったことを意味しない。
// 2. **同じ IP を後日引き直すと、過去の日付の通報が増える。**10-30 の取得では
//    通報ゼロだった 14 IP が、11-06 には「10-27 観測」の通報を持っていた。
//    これは API の遅延ではなく、フィードが 6〜8 日さかのぼって投稿したため。
//    10-30 の取得は正しかった。**過去の集計は確定しない。**
//
// ## 「同じ通報者の再通報は 1 行に畳まれる」は誤り
//
// この 65 IP では `totalReports == numDistinctUsers` が例外なく成り立ち、畳み込みを
// 疑ったが、`jp_attack_sources_all.csv` の 3,972 件で見ると 99.5% が
// `totalReports > numDistinctUsers`（最大 209,403 件 / 1,012 人 = 1 人あたり 207 件）。
// **畳まれてはいない。**この 65 IP は 1 人あたり 1 件しか出していないだけ。
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

/* ---- 前回との比較は「git に残った CSV」を基準にする ----
 *
 * `.cache/` は git 管理外で容器も使い捨てなので、**前回の写しは次の調査では無い**。
 * 実際 11-06 の容器には 10-14 の写し（CFG.BASELINE）が無く、基準が消えていた。
 * そこで前回の成果 CSV を `snapshots/` に残し、そこを基準にする。
 * 写しは消えても CSV は残る。
 */
const parseCsv = (text) => {
  if (!text) return [];
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
  const rows = []; let row = [], field = "", q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) { if (c === '"') { if (text[i + 1] === '"') { field += '"'; i++; } else q = false; } else field += c; }
    else if (c === '"') q = true;
    else if (c === ",") { row.push(field); field = ""; }
    else if (c === "\n") { row.push(field); field = ""; rows.push(row); row = []; }
    else if (c !== "\r") field += c;
  }
  if (field.length || row.length) { row.push(field); rows.push(row); }
  const h = (rows.shift() || []).map((x) => String(x).replace(/^﻿/, ""));
  return rows.filter((r) => r.length > 1).map((r) => Object.fromEntries(h.map((k, i) => [k, r[i] ?? ""])));
};
/**
 * **今回ぶんのスナップショットを「前回」に選んではいけない。**
 *
 * スナップショットは今回の成果をそのまま写すので、置いた後にもう一度 build を
 * 回すと自分自身と比べ始め、差分が全部 0 になる。2 回実行して md5 が変わる形で
 * 現れた（by_ip / events / summary / report の 4 つが不一致）。
 * **取得日より前のものだけを候補にする。**
 */
const anchorDay = String(anchorIso || "").slice(0, 10);
const snapshots = (() => {
  const dir = path.join(HERE, "snapshots");
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir).filter((f) => f.endsWith("_by_ip.csv")).sort()
    .map((f) => ({ date: f.slice(0, 10), rows: parseCsv(fs.readFileSync(path.join(dir, f), "utf8")) }))
    .filter((s) => s.rows.length && (!anchorDay || s.date < anchorDay));
})();
/** 一番新しいスナップショット。これが「前回」 */
const prevSnap = snapshots.length ? snapshots[snapshots.length - 1] : null;
const prev = new Map((prevSnap?.rows || []).map((r) => [r.ip_address, r]));
/** 前回の通報 1 件ずつ。`IP|観測時刻` で突き合わせ、**今回初めて見えた通報**を印にする */
const prevEventKeys = (() => {
  const f = prevSnap ? path.join(HERE, "snapshots", `${prevSnap.date}_events.csv`) : null;
  if (!f || !fs.existsSync(f)) return null; // **無ければ「新しくない」ではなく「分からない」**
  return new Set(parseCsv(fs.readFileSync(f, "utf8")).map((r) => r.ip_address + "|" + r.reported_at));
})();
const numOr = (v, d = null) => { const n = Number(v); return v === "" || v === undefined || !Number.isFinite(n) ? d : n; };

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
      /** **通報者が申告した観測時刻。**投稿時刻ではない（最大 7.32 日さかのぼる） */
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
      /** **前回のスナップショットに無かった通報か。**さかのぼり投稿があるので、
       *  観測日が前回より古くてもここが true になりうる。それが見どころ */
      new_since_prev: prevEventKeys ? !prevEventKeys.has(r.ip + "|" + x.reportedAt) : "",
      new_since_prev_measured: !!prevEventKeys,
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
    /* ---- 日付は 2 種類ある。混ぜない ----
     * observed = 通報者の申告（reportedAt）/ submitted = AbuseIPDB 受領（lastReportedAt） */
    first_observed_at: mine.length ? mine[0].reported_at : "",
    last_observed_at: mine.length ? mine[mine.length - 1].reported_at : "",
    last_submitted_at: b.lastReportedAt || "",
    /** さかのぼり日数。**通報が 1 件のときだけ通報と投稿が一対一に決まる。**
     *  複数件ある IP では `lastReportedAt` が最新の 1 件のものなので算出しない */
    backdate_days: (() => {
      if ((b.totalReports ?? 0) !== 1 || !b.lastReportedAt || !mine.length) return "";
      const d = (Date.parse(b.lastReportedAt) - Date.parse(mine[0].reported_at)) / 86400000;
      return Number.isFinite(d) ? d.toFixed(2) : "";
    })(),
    backdate_derivable: (b.totalReports ?? 0) === 1 && !!b.lastReportedAt && mine.length > 0,
    /* ---- 前回のスナップショット（git に残っている CSV） ---- */
    prev_snapshot_date: prevSnap ? prevSnap.date : "",
    prev_available: prev.has(r.ip),
    reports_prev: prev.has(r.ip) ? numOr(prev.get(r.ip).reports_now, 0) : "",
    score_prev: prev.has(r.ip) ? numOr(prev.get(r.ip).score_now, 0) : "",
    /** **前回ゼロで今回付いたか。**これが再調査の主役 */
    newly_reported_since_prev: prev.has(r.ip)
      && numOr(prev.get(r.ip).reports_now, 0) === 0 && (b.totalReports ?? 0) > 0,
    /* ---- 基準（2026-10-14 の ARTEX 調査。写しが残っていれば） ---- */
    baseline_available: !!base,
    reports_baseline: base ? (base.totalReports ?? 0) : "",
    score_baseline: base ? (base.abuseConfidenceScore ?? 0) : "",
    /** **新しく通報が付いたか。**写しが無ければ false ではなく「分からない」 */
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
    /* ---- さかのぼりの度合い ----
     *
     * フィードの一括登録と、被害者側の観測を分けるのに一番効く印。
     * フィードは手元の台帳をまとめて流すので観測日をさかのぼる（中央 1.04 日・
     * 最大 7.32 日）。被害者の検知器は見たその場で出すのでずれが 0 になる。
     * **件数や定型文だけでは両者が同じ形に見える。** */
    ...(() => {
      const ds = rows.filter((w) => w.backdate_derivable && w.reporters.split(";").includes(label))
        .map((w) => Number(w.backdate_days)).filter(Number.isFinite).sort((a, b) => a - b);
      return {
        backdate_measurable_ips: ds.length,
        backdate_days_median: ds.length ? ds[Math.floor(ds.length / 2)].toFixed(2) : "",
        backdate_days_max: ds.length ? ds[ds.length - 1].toFixed(2) : "",
        /** **見てすぐ出しているか。**ずれが全部 1 時間未満なら、台帳の流し込みではない。
         *  通報が複数ある IP では投稿時刻が一対一に決まらないので測れない。
         *  **測れていない false と、測って否だった false を混ぜない。** */
        files_immediately: ds.length > 0 && ds[ds.length - 1] < 1 / 24,
        files_immediately_measured: ds.length > 0,
      };
    })(),
    /** 対象 255 IP のうち何 % を通報したか。**無差別かどうかの印。**
     *  フィードは 22.7%、被害者側の検知器は 3.1% だった */
    share_of_targets_pct: Number((100 * uniq(mine.map((e) => e.ip_address)).length / now.size).toFixed(1)),
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
    /** この観測日の通報のうち、前回のスナップショットに無かったもの。
     *  **古い日付の行が後から増えるのが、さかのぼり投稿の見え方** */
    new_since_prev: prevEventKeys ? mine.filter((e) => e.new_since_prev === true).length : "",
    /** フィード以外の通報者によるものか */
    independent_reports: mine.filter((e) =>
      !reporters.find((p) => p.reporter === e.reporter)?.looks_like_bulk_feed).length,
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
    "category_ids", "category_names", "new_since_prev", "new_since_prev_measured",
    "comment_empty", "comment_excerpt", "comment_sha256"]);
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
    /* ---- 前回のスナップショットとの差 ---- */
    prev_available: mine.filter((r) => r.prev_available).length,
    with_reports_prev: mine.filter((r) => r.prev_available && r.reports_prev > 0).length,
    newly_reported_since_prev: mine.filter((r) => r.newly_reported_since_prev).length,
    /** **フィード以外の通報者から通報が付いた IP。**ここが効く */
    with_independent_report: uniq(events.filter((e) => e.cluster === c
      && !reporters.find((p) => p.reporter === e.reporter)?.looks_like_bulk_feed)
      .map((e) => e.ip_address)).length,
    new_reports_since_prev: prevEventKeys
      ? events.filter((e) => e.cluster === c && e.new_since_prev === true).length : "",
    new_independent_reports_since_prev: prevEventKeys
      ? events.filter((e) => e.cluster === c && e.new_since_prev === true
        && !reporters.find((p) => p.reporter === e.reporter)?.looks_like_bulk_feed).length : "",
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
/** 一括登録らしい通報者の識別子。2 箇所から使う */
const S_bulkNames = reporters.filter((r) => r.looks_like_bulk_feed).map((r) => r.reporter);
const summary = {
  dataset: CFG.DATASET,
  generated_from: "写しのみ。API は呼んでいない",
  collected_at_utc: anchorIso,
  baseline_collected_at_utc: baseIso,
  fetch_window_days: CFG.FETCH_WINDOW_DAYS,
  prev_snapshot_date: prevSnap ? prevSnap.date : null,
  snapshot_dates: snapshots.map((s) => s.date),
  clusters: CFG.CLUSTERS.map((c) => ({ name: c.name, note: c.note,
    ranges: c.ranges || null, explicit: c.explicit || null })),
  per_cluster: perCluster,
  /**
   * **2 つの日付の意味。**ここを混ぜると時系列が壊れるので成果物に書き出す。
   * 数字はこの写しから毎回測り直すので、古い値が残ることはない。
   */
  date_field_semantics: (() => {
    const ds = rows.filter((r) => r.backdate_derivable)
      .map((r) => Number(r.backdate_days)).filter(Number.isFinite).sort((a, b) => a - b);
    const ahead = rows.filter((r) => r.last_observed_at && r.last_submitted_at
      && Date.parse(r.last_submitted_at) > Date.parse(r.last_observed_at) + 1000).length;
    const behind = rows.filter((r) => r.last_observed_at && r.last_submitted_at
      && Date.parse(r.last_submitted_at) < Date.parse(r.last_observed_at) - 1000).length;
    return {
      reported_at: "通報者が申告した観測時刻。さかのぼれる。活動日として読むのはこちら",
      last_reported_at: "AbuseIPDB が最後に通報を受け取った時刻（投稿日）。活動日ではない",
      ips_with_reports: rows.filter((r) => r.reports_now > 0).length,
      submitted_after_observed: ahead,
      submitted_before_observed: behind,
      backdate_measurable_ips: ds.length,
      backdate_days_median: ds.length ? Number(ds[Math.floor(ds.length / 2)].toFixed(2)) : null,
      backdate_days_max: ds.length ? Number(ds[ds.length - 1].toFixed(2)) : null,
      /** 観測日が取得時刻より先の通報。**あれば通報者の申告が壊れている。** */
      observed_in_future: rows.filter((r) => r.last_observed_at
        && Date.parse(r.last_observed_at) > Date.parse(anchorIso)).length,
      caveat: "さかのぼり投稿があるので、過去の日付の集計は確定しない。"
        + "同じ日を後日引き直すと通報が増えうる（10-30 に 0 件だった 14 IP が 11-06 には 10-27 観測の通報を持っていた）",
    };
  })(),
  reports: {
    total: events.length,
    distinct_ips: uniq(events.map((e) => e.ip_address)).length,
    distinct_reporters: uniq(events.map((e) => e.reporter)).length,
    /** 観測時刻の範囲。投稿時刻の範囲とは別物なので両方出す */
    first_observed: events[0]?.reported_at || null,
    last_observed: events[events.length - 1]?.reported_at || null,
    last_submitted: rows.map((r) => r.last_submitted_at).filter(Boolean).sort().pop() || null,
    new_since_prev: prevEventKeys ? events.filter((e) => e.new_since_prev === true).length : null,
    new_since_prev_measured: !!prevEventKeys,
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
  /**
   * **フィード以外の通報者。**「複数 IP が攻撃元として報告されている」が
   * フィードの一括登録なのか被害者の観測なのかは、ここだけが答える。
   */
  independent_reporters: reporters.filter((r) => !r.looks_like_bulk_feed)
    .map((r) => ({ reporter: r.reporter, country: r.country, reports: r.reports,
      distinct_ips: r.distinct_ips, days: r.days, clusters: r.clusters,
      category_names: r.category_names, share_of_targets_pct: r.share_of_targets_pct,
      files_immediately: r.files_immediately,
      files_immediately_measured: r.files_immediately_measured,
      backdate_days_max: r.backdate_days_max,
      comment_excerpt: r.comment_excerpt })),
  /**
   * **フィードに載っていることは、被害者の通報を予測するか。**
   *
   * 「フィードの一括登録だから割り引く」と書いたことへの問いに答えるための測定。
   * フィード掲載を予測子、フィード以外の通報の有無を結果として 2×2 で数える。
   * **この 255 IP の中だけの話で、分母が小さい。**差を論じるには足りない。
   */
  feed_listing_vs_independent: (() => {
    const feedNames = new Set(S_bulkNames);
    const listed = new Set(events.filter((e) => feedNames.has(e.reporter)).map((e) => e.ip_address));
    const indepIps = new Set(events.filter((e) => !feedNames.has(e.reporter)).map((e) => e.ip_address));
    const all = [...now.keys()];
    const notListed = all.filter((ip) => !listed.has(ip));
    const a = [...listed].filter((ip) => indepIps.has(ip)).length;
    const b = notListed.filter((ip) => indepIps.has(ip)).length;
    const pct = (x, n) => (n ? Number((100 * x / n).toFixed(1)) : null);
    return {
      feed_listed_ips: listed.size,
      feed_listed_with_independent: a,
      feed_listed_pct: pct(a, listed.size),
      not_listed_ips: notListed.length,
      not_listed_with_independent: b,
      not_listed_pct: pct(b, notListed.length),
      independent_ips_total: indepIps.size,
      /** **検定力が足りているか。**正例が 2 桁無いなら差は読めない */
      underpowered: indepIps.size < 10,
      note: "この母集団だけの測定。他の母集団では別の結果が出うる",
    };
  })(),
  by_day: byDay,
  reporters,
};
const stable = (v) => JSON.stringify(v, (k, x) =>
  (x && typeof x === "object" && !Array.isArray(x)
    ? Object.fromEntries(Object.entries(x).sort(([a], [b]) => (a < b ? -1 : 1)))
    : x), 2);
fs.writeFileSync(path.join(HERE, "artex_timeline_summary.json"), stable(summary) + "\n");

console.log(`写し ${now.size} IP（前回 ${prevSnap ? prevSnap.date + " の CSV" : "なし"}`
  + ` / 10-14 の写し ${baseline.size} IP）`);
for (const [c, v] of Object.entries(perCluster)) {
  console.log(`  ${c}: ${v.ips} IP / 通報あり ${v.with_reports_now}`
    + `（前回 ${v.prev_available ? v.with_reports_prev : "—"}）`
    + ` / 前回ゼロから付いた ${v.prev_available ? v.newly_reported_since_prev : "—"}`
    + ` / 通報者 ${v.distinct_reporters} 人 / フィード以外の通報がある IP ${v.with_independent_report}`
    + ` / 日本から ${v.jp_reports}`);
}
const dfs = summary.date_field_semantics;
console.log(`日付: 観測より投稿が後 ${dfs.submitted_after_observed} 件 / 前 ${dfs.submitted_before_observed} 件`
  + ` / さかのぼり 中央 ${dfs.backdate_days_median} 日・最大 ${dfs.backdate_days_max} 日`
  + (dfs.observed_in_future ? `  ! 未来日付の観測 ${dfs.observed_in_future} 件` : ""));
console.log(`通報 ${events.length} 件 / ${summary.reports.distinct_ips} IP / 通報者 ${summary.reports.distinct_reporters} 人`);
if (summary.bulk_feeds.length) {
  for (const f of summary.bulk_feeds) {
    console.log(`  ! 一括登録らしい通報者: ${f.reporter} が ${f.reports} 件 / ${f.distinct_ips} IP`
      + `（同じ本文 1 通り、${f.category_names}）`);
  }
}
