#!/usr/bin/env node
// 監視の観測を畳んで、現況と「変化」を出す。**観測だけを見る。外には出ない。**
//
//   node tools/ioc/track-watch.mjs [--watch data/ioc/watch] [--days 0]
//
// 出すもの
//   data/ioc/watch/state.jsonl   1 IP 1 行の現況
//   data/ioc/watch/events.jsonl  変化だけ（いつ・どの IP が・何が変わったか）
//   data/ioc/watch/shapes.jsonl  本文の形ごとの広がり（一括登録の印）
//   data/ioc/watch/watch-meta.json
//
// **状態は観測から毎回作り直す。** 前回の state を読んで更新する作りにすると、
// 一度おかしくなった状態が永久に残る。`observations/*.jsonl` だけが真実で、
// state と events はそこから何度でも同じものが再生される（track-domains と同じ規則）。
//
// ## 何を「変化」と呼ぶか
//
// いちばん重いのは **`first_independent_report`** — その IP に初めて
// フィードの一括登録以外の通報が付いた日。ARTEX では 10-31 にこれが起き、
// 気付くまで 6 日かかった。この仕組みはそこを翌日に出すためにある。
//
// ## 何を「変化」と呼ばないか
//
//   1. **スコアの減衰。** AbuseIPDB のスコアは通報が増えなくても時間で下がる。
//      実測で 198.200.59.85 が 18 → 16 になった（通報は 3 件のまま）。
//      **下がりは変化として出さない。**上がりだけを見る。
//   2. **投稿時刻（`lastReportedAt`）だけが動いた日。** フィードが同じ観測日を
//      再投稿すると投稿時刻は進むが、観測は増えていない。別の印として出す
//      （`resubmitted`）が、攻撃の観測ではない。
//   3. **引けなかった日。** 観測に入っていない IP は「通報なし」ではなく
//      「分からない」。前後の観測だけを繋いで比べる。
import fs from "node:fs";
import path from "node:path";
import { parseArgs, readJson, writeJson, writeJsonl, readJsonl } from "./lib/io.mjs";
import { REPO_ROOT } from "./lib/sources.mjs";
import { CATEGORIES } from "../../reports/global-jp-vuln/rules.mjs";
import { bulkShapes, reportKey, ipNum, expandWatchlist } from "./lib/watch.mjs";

const args = parseArgs(process.argv.slice(2));
const WATCH = path.resolve(REPO_ROOT, args.watch || "data/ioc/watch");
const DAYS = Number(args.days || 0);

const wl = readJson(path.join(WATCH, "watchlist.json")) || {};
const obsDir = path.join(WATCH, "observations");
if (!fs.existsSync(obsDir)) {
  console.error(`${obsDir} がありません。先に fetch-watch.mjs を実行してください。`);
  process.exit(1);
}
let dayFiles = fs.readdirSync(obsDir).filter((f) => /^\d{4}-\d{2}-\d{2}\.jsonl$/.test(f)).sort();
if (DAYS > 0) dayFiles = dayFiles.slice(-DAYS);
if (!dayFiles.length) {
  console.error("観測がありません。");
  process.exit(1);
}
/** 日付順の観測。**ここだけが真実** */
const days = dayFiles.map((f) => ({
  day: f.slice(0, 10),
  rows: readJsonl(path.join(obsDir, f)),
}));

/**
 * クラスタと役割は**宣言から結合する**。観測には入っていない。
 *
 * 観測に書き込むと、宣言を訂正した途端に過去の観測が嘘になる。実際
 * 2026-11-06 に「ARTEX と sub2api は別クラスタ」から「全 255 IP が同じ
 * sub2api クラスタで、うち 250 IP で ARTEX も動いている」へ訂正が入った。
 * 結合にしてあれば履歴を触らずに済む。
 *
 * 宣言から外れた IP の観測は残るが、`cluster` が付かない。**捨てずに印を付ける。**
 */
const decl = new Map(expandWatchlist(wl).map((t) => [t.ip, t]));
const clusterOf = (ip) => decl.get(ip)?.cluster || "(宣言から外れた)";
const rolesOf = (ip) => decl.get(ip)?.roles || [];

/* ---------------- 本文の形ごとの広がり（一括登録の印） ---------------- */

const allReports = [];
/**
 * さかのぼり日数を形に結び付けられる観測だけを拾う。
 * **通報がちょうど 1 件の観測**のみ。そのとき `lastReportedAt` はその 1 件の
 * 投稿時刻で、形も 1 つに決まる。複数件ある IP では帰属が決まらないので使わない。
 */
const soleBackdates = [];
for (const d of days) {
  for (const r of d.rows) {
    for (const x of (r.by_report || [])) allReports.push({ ip: r.ip, ...x });
    if (r.reports === 1 && (r.by_report || []).length === 1
      && typeof r.backdate_days === "number") {
      soleBackdates.push({ ip: r.ip, day: d.day, shape: r.by_report[0].shape, days: r.backdate_days });
    }
  }
}
const shapes = bulkShapes(allReports, {
  minIps: Number(wl.bulk_min_ips || 10),
  declared: wl.feed_shapes || [],
  soleBackdates,
});
const isBulk = (shape) => !!shapes.get(shape)?.bulk;
/** その通報がフィードの一括登録らしいか。**印であって判定ではない** */
const independentOf = (rows) => (rows || []).filter((x) => !isBulk(x.shape));

/* ---------------- IP ごとに日を追って変化を拾う ---------------- */

const SCORE_JUMP = Number(wl.score_jump || 10);
const events = [];
const state = [];
/** IP → その IP が現れた観測の列（引けなかった日は飛ばす） */
const seriesOf = new Map();
for (const d of days) {
  for (const r of d.rows) {
    if (!seriesOf.has(r.ip)) seriesOf.set(r.ip, []);
    seriesOf.get(r.ip).push({ day: d.day, ...r });
  }
}

for (const [ip, series] of seriesOf) {
  let prev = null;
  const seenCats = new Set();
  const seenKeys = new Set();
  let firstIndepDay = "";
  let firstReportDay = "";
  for (const cur of series) {
    const curIndep = independentOf(cur.by_report);
    const add = (kind, detail) => events.push({
      day: cur.day, ip, cluster: clusterOf(ip), roles: rolesOf(ip).join(";"), kind,
      /** 前回の観測日。**連日とは限らない**ので明示する */
      since: prev ? prev.day : "",
      ...detail,
    });

    if (!firstReportDay && cur.reports > 0) {
      firstReportDay = cur.day;
      // 初回の観測で既に通報があった IP は「その日に付いた」とは言えない
      if (prev) add("first_report", { reports: cur.reports, categories: cur.categories.join(";") });
      else add("already_reported_at_first_sight",
        { reports: cur.reports, categories: cur.categories.join(";") });
    }
    if (!firstIndepDay && curIndep.length) {
      firstIndepDay = cur.day;
      const d0 = { reports: curIndep.length,
        countries: [...new Set(curIndep.map((x) => x.cc))].sort().join(";"),
        categories: [...new Set(curIndep.flatMap((x) => x.cats))].sort((a, b) => a - b).join(";"),
        observed_at: curIndep.map((x) => x.observed_at).sort()[0] };
      // **これがいちばん重い変化。**フィードの転載ではない通報が初めて付いた
      if (prev) add("first_independent_report", d0);
      else add("already_independent_at_first_sight", d0);
    }
    /**
     * **1 つの事実に 3 行出さない。**
     *
     * 通報が 0 件から付いた日は、`first_report` と `reporters_up` と
     * `new_category` が必ず同時に立つ。中身は同じ事実なので、最初の通報が
     * 付いた日は `first_report` だけを出す（件数とカテゴリはその行に入れてある）。
     * 雑音を削って、本当の変化が埋もれないようにする。
     */
    const justFirst = firstReportDay === cur.day;
    if (prev) {
      if (!justFirst && cur.reporters > prev.reporters) {
        add("reporters_up", { from: prev.reporters, to: cur.reporters });
      }
      const fresh = cur.categories.filter((c) => !seenCats.has(c));
      if (!justFirst && fresh.length) {
        add("new_category", { categories: fresh.join(";"),
          category_names: fresh.map((c) => CATEGORIES[c] || `unknown(${c})`).join(";") });
      }
      if (cur.jp_reports > prev.jp_reports) {
        add("jp_report_up", { from: prev.jp_reports, to: cur.jp_reports });
      }
      // **上がりだけ。**減衰は変化として出さない
      if (cur.score - prev.score >= SCORE_JUMP) {
        add("score_up", { from: prev.score, to: cur.score });
      }
      /* 通報 1 件ずつの差分。**さかのぼり投稿はここで見える** */
      const newRows = (cur.by_report || []).filter((x) => !seenKeys.has(reportKey(ip, x)));
      for (const x of newRows) {
        // 観測日が前回の取得日より前なら、さかのぼって投稿されたもの
        if (x.observed_at && x.observed_at.slice(0, 10) < prev.day) {
          add("backdated_report", { observed_at: x.observed_at, cc: x.cc,
            categories: (x.cats || []).join(";"), bulk: isBulk(x.shape),
            backdate_days: Number(((Date.parse(cur.last_submitted_at || cur.fetched_at)
              - Date.parse(x.observed_at)) / 86400000).toFixed(2)) });
        }
      }
      // 観測は増えていないのに投稿時刻だけ進んだ
      if (!newRows.length && cur.last_submitted_at && prev.last_submitted_at
        && cur.last_submitted_at > prev.last_submitted_at) {
        add("resubmitted", { from: prev.last_submitted_at, to: cur.last_submitted_at });
      }
    }
    for (const c of cur.categories) seenCats.add(c);
    for (const x of (cur.by_report || [])) seenKeys.add(reportKey(ip, x));
    prev = cur;
  }

  const last = series[series.length - 1];
  const lastIndep = independentOf(last.by_report);
  state.push({
    ioc: last.ioc, ip, cluster: clusterOf(ip), roles: rolesOf(ip).join(";"),
    observed_days: series.length,
    first_seen_day: series[0].day,
    last_seen_day: last.day,
    score: last.score,
    reports: last.reports,
    reporters: last.reporters,
    /** **フィードの一括登録以外の通報。**ここが 0 から動いた日が勘所 */
    independent_reports: lastIndep.length,
    independent_countries: [...new Set(lastIndep.map((x) => x.cc))].sort().join(";"),
    first_independent_report_day: firstIndepDay,
    first_report_day: firstReportDay,
    jp_reports: last.jp_reports,
    first_observed_at: last.first_observed_at,
    last_observed_at: last.last_observed_at,
    last_submitted_at: last.last_submitted_at,
    backdate_days: last.backdate_days,
    categories: last.categories.join(";"),
    category_names: last.categories.map((c) => CATEGORIES[c] || `unknown(${c})`).join(";"),
    countries: last.countries.join(";"),
    country_code: last.country_code,
    isp: last.isp,
    usage_type: last.usage_type,
    hostnames: (last.hostnames || []).join(";"),
    is_tor: last.is_tor,
    is_whitelisted: last.is_whitelisted,
  });
}

state.sort((a, b) => ipNum(a.ip) - ipNum(b.ip));
events.sort((a, b) => a.day.localeCompare(b.day) || ipNum(a.ip) - ipNum(b.ip)
  || a.kind.localeCompare(b.kind));

/* ---------------- 書き出す ---------------- */

writeJsonl(path.join(WATCH, "state.jsonl"), state);
writeJsonl(path.join(WATCH, "events.jsonl"), events);
writeJsonl(path.join(WATCH, "shapes.jsonl"),
  [...shapes.values()].sort((a, b) => b.distinct_ips - a.distinct_ips || a.shape.localeCompare(b.shape)));

const tally = (rs, f) => {
  const m = new Map();
  for (const r of rs) for (const v of [].concat(f(r))) {
    if (v === "" || v === undefined || v === null) continue;
    m.set(String(v), (m.get(String(v)) || 0) + 1);
  }
  return Object.fromEntries([...m].sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1)));
};
const slice = (mine) => ({
  ips: mine.length,
  with_reports: mine.filter((r) => r.reports > 0).length,
  with_independent_report: mine.filter((r) => r.independent_reports > 0).length,
  with_jp_report: mine.filter((r) => r.jp_reports > 0).length,
  max_score: Math.max(0, ...mine.map((r) => r.score)),
  total_reports: mine.reduce((s, r) => s + r.reports, 0),
  /** 母数つきで出す。**割合だけだと 1/5 と 50/250 が同じに見える** */
  reported_pct: mine.length ? Number((100 * mine.filter((r) => r.reports > 0).length / mine.length).toFixed(1)) : null,
  categories: tally(mine, (r) => r.category_names.split(";")),
});
const perCluster = {};
for (const c of [...new Set(state.map((r) => r.cluster))].sort()) {
  perCluster[c] = slice(state.filter((r) => r.cluster === c));
}
/**
 * **役割ごとの切り口。**クラスタを 1 つにした代わりに、ここで比べる。
 *
 * 「ARTEX も動いているホスト」と「リチャージ URL のホスト」で通報のされ方が
 * 違うのか、という問いはクラスタを分けずに答えられる。**母数が小さい役割では
 * 割合を読まないこと**（`recharge_host` は 1 IP しかない）。
 */
const perRole = {};
for (const role of [...new Set(state.flatMap((r) => r.roles.split(";").filter(Boolean)))].sort()) {
  perRole[role] = slice(state.filter((r) => r.roles.split(";").includes(role)));
}
/** 役割の組み合わせごと。どの IP がどの組か分かるように */
const perRoleSet = {};
for (const rs of [...new Set(state.map((r) => r.roles))].sort()) {
  perRoleSet[rs || "(役割なし)"] = slice(state.filter((r) => r.roles === rs));
}
const lastDay = days[days.length - 1].day;
const meta = readJson(path.join(WATCH, "fetch-meta.json")) || {};
writeJson(path.join(WATCH, "watch-meta.json"), {
  generated_from: "observations/*.jsonl のみ。API も写しも見ていない",
  days: days.length,
  day_range: [days[0].day, lastDay],
  /** **連日でない可能性を隠さない。**抜けた日は events の `since` に出る */
  observed_days: days.map((d) => ({ day: d.day, ips: d.rows.length })),
  ips: state.length,
  per_cluster: perCluster,
  per_role: perRole,
  per_role_set: perRoleSet,
  events: { total: events.length, by_kind: tally(events, (e) => e.kind) },
  events_on_last_day: events.filter((e) => e.day === lastDay).length,
  bulk_shapes: [...shapes.values()].filter((s) => s.bulk).length,
  not_observed_last_fetch: meta.not_observed ?? null,
  built_at: new Date().toISOString(),
});

console.log(`観測 ${days.length} 日（${days[0].day}〜${lastDay}） / ${state.length} IP`);
for (const [c, v] of Object.entries(perCluster)) {
  console.log(`  ${c}: ${v.ips} IP / 通報あり ${v.with_reports}`
    + ` / **フィード以外の通報あり ${v.with_independent_report}**`
    + ` / 日本から ${v.with_jp_report} / 最大スコア ${v.max_score}`);
}
console.log("  役割ごと（母数が小さい役割の割合は読まない）:");
for (const [r, v] of Object.entries(perRole)) {
  console.log(`    ${r.padEnd(14)} ${String(v.ips).padStart(3)} IP / 通報あり ${String(v.with_reports).padStart(3)}`
    + `（${v.reported_pct}%）/ フィード以外 ${v.with_independent_report} / 最大スコア ${v.max_score}`);
}
console.log(`変化 ${events.length} 件 ${JSON.stringify(tally(events, (e) => e.kind))}`);
const today = events.filter((e) => e.day === lastDay);
if (today.length) {
  console.log(`  ${lastDay} の変化 ${today.length} 件:`);
  for (const e of today.slice(0, 20)) {
    console.log(`    ${e.kind.padEnd(34)} ${e.ip.padEnd(16)} ${e.roles}`);
  }
  if (today.length > 20) console.log(`    … 他 ${today.length - 20} 件`);
} else {
  console.log(`  ${lastDay} の変化はありません`);
}
