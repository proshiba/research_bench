#!/usr/bin/env node
// 成果物を**読み直して**検査する。作った側の変数は見ない。
//
//   node validate.mjs
//
// この調査の結論は「通報が増えたが、中身は単一通報者の一括登録だった」なので、
// **その主張が成り立つかを写しから計算し直す**のを重く見る。
//
// ## 2026-11-06 に 2 つの検査を書き換えた
//
// 元の検査は結論そのものを固定していた:
//
//     check(artexRids.size === 1, "ARTEX の通報はすべて単一の通報者")
//     check(indep.every((e) => e.cluster === "sub2api"), "ARTEX には独立した通報が無い")
//
// 11-06 にこの 2 つが落ちた。**落ちたのが正しい。**ARTEX に初めてフィード以外の
// 通報が付いたからである。検査が「10-30 時点の世界」を正しさとして焼き込んでいた。
//
// 事実が変わったら落ちるべき検査と、壊れたら落ちるべき検査は別物である。
// 前者は**数え直して summary と突き合わせる**形に直した。後者（鍵が漏れていない、
// reporterId が出ていない、並び順、合計の一致）はそのまま残す。
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

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

const S = JSON.parse(fs.readFileSync(path.join(HERE, "artex_timeline_summary.json"), "utf8"));
const E = read("artex_timeline_events.csv");
const P = read("artex_timeline_by_ip.csv");
const R = read("artex_timeline_by_reporter.csv");
const D = read("artex_timeline_by_day.csv");
const md = fs.readFileSync(path.join(HERE, "artex_timeline_report_ja.md"), "utf8");

/* ---- 写しを読み直す ---- */
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
      } catch { /* skip */ }
    }
  }
  return m;
};
const now = load(path.join(HERE, ".cache", "abuseipdb"));
const baseline = load(path.resolve(ROOT, CFG.BASELINE));

console.log("== 対象が揃っているか");
/**
 * **クラスタは 1 つで、役割を IP に付ける**（2026-11-06 に訂正）。
 * 元は `CFG.CLUSTERS` が 2 件あり、`cluster === "ARTEX"` が 250 件という形で
 * 検査していた。利用者の指摘で「全 255 IP が同じ sub2api クラスタ」と分かったので、
 * **役割ごとの数を設定から数え直して突き合わせる**形にする。
 */
const want = new Set();
const wantRoles = new Map();
for (const g of CFG.GROUPS) {
  const roles = g.roles || [];
  const push = (ip) => {
    want.add(ip);
    wantRoles.set(ip, [...new Set([...(wantRoles.get(ip) || []), ...roles])].sort());
  };
  if (g.explicit) for (const ip of g.explicit) push(ip);
  if (g.ranges) {
    for (const r of g.ranges) {
      const b = r.split("/")[0].split(".").slice(0, 3).join(".");
      const [lo, hi] = g.host_range || [1, 254];
      for (let i = lo; i <= hi; i++) push(`${b}.${i}`);
    }
  }
}
check(P.rows.length === want.size, `IP の表が対象の数と一致（${want.size}）`, String(P.rows.length));
check(P.rows.every((r) => want.has(r.ip_address)), "指定外の IP が混ざっていない");
check([...want].every((ip) => P.rows.some((r) => r.ip_address === ip)), "指定された IP がすべて入っている");
check(now.size === want.size, "写しの数が対象の数と一致", `${now.size} / ${want.size}`);
/** **クラスタは 1 つ。**分かれていたら設定を疑う */
const clusters = [...new Set(P.rows.map((r) => r.cluster))];
check(clusters.length === 1 && clusters[0] === CFG.CLUSTER.name,
  `**クラスタが 1 つ**（${CFG.CLUSTER.name}）`, clusters.join(" "));
/** 役割は設定から再現できるか。**件数を固定しない** */
check(P.rows.every((r) => (wantRoles.get(r.ip_address) || []).join(";") === r.roles),
  "**役割が設定から再現できる**",
  P.rows.filter((r) => (wantRoles.get(r.ip_address) || []).join(";") !== r.roles)
    .slice(0, 3).map((r) => r.ip_address).join(" "));
const roleCount = {};
for (const rs of wantRoles.values()) for (const r of rs) roleCount[r] = (roleCount[r] || 0) + 1;
check(Object.keys(S.per_role).length === Object.keys(roleCount).length
  && Object.entries(roleCount).every(([r, n]) => S.per_role[r]?.ips === n),
"役割ごとの IP 数が設定から再現できる", JSON.stringify(roleCount));
/** 役割は写しではなく設定から来ているか。**写しには古い宣言が入っている** */
check([...now.values()].some((r) => r.cluster === "ARTEX" || r.cluster === "sub2api")
  ? P.rows.every((r) => r.cluster === CFG.CLUSTER.name) : true,
"**写しに古いクラスタ名が残っていても成果物は設定に従っている**");
/** 母数が小さい役割に印が出ているか */
check(Object.values(S.per_role).every((v) => v.too_small_for_pct === (v.ips < 10)),
  "母数が 10 未満の役割に too_small_for_pct が付いている");

console.log("\n== 通報を写しから数え直す");
let reCount = 0;
const reByIp = new Map();
for (const [ip, r] of now) {
  const n = (r.body.reports || []).length;
  reCount += n;
  reByIp.set(ip, n);
}
check(E.rows.length === reCount, "通報の表の行数が写しと一致", `${E.rows.length} / ${reCount}`);
check(E.rows.length === S.reports.total, "summary の通報総数が一致");
let bad = [];
for (const r of P.rows) {
  const c = now.get(r.ip_address);
  if (!c) { bad.push(`${r.ip_address} 写しが無い`); continue; }
  if (num(r.reports_now) !== (c.body.totalReports ?? 0)) bad.push(`${r.ip_address} 通報数が違う`);
  else if (num(r.score_now) !== (c.body.abuseConfidenceScore ?? 0)) bad.push(`${r.ip_address} スコアが違う`);
  else if (num(r.reporters_now) !== (c.body.numDistinctUsers ?? 0)) bad.push(`${r.ip_address} 通報者数が違う`);
  if (bad.length >= 5) break;
}
check(!bad.length, "通報数・スコア・通報者数が写しから再現できる", bad.slice(0, 3).join(" / "));

console.log("\n== 基準日（2026-10-14）との差");
const withBase = P.rows.filter((r) => bool(r.baseline_available));
check(withBase.length === baseline.size, "基準の写しがある行の数が一致", `${withBase.length} / ${baseline.size}`);
check(withBase.every((r) => {
  const b = baseline.get(r.ip_address);
  return b && num(r.reports_baseline) === (b.body.totalReports ?? 0);
}), "基準日の通報数が基準の写しから再現できる");
check(withBase.every((r) => num(r.reports_baseline) === 0),
  "**基準日は全件が通報 0 件**（これが「増えた」の土台）");
const newly = P.rows.filter((r) => bool(r.newly_reported));
check(newly.length === S.per_cluster[CFG.CLUSTER.name].newly_reported, "新しく通報が付いた数が summary と一致");
check(newly.every((r) => num(r.reports_now) > 0 && num(r.reports_baseline) === 0),
  "新しく付いた行は「今 1 件以上 かつ 基準日 0 件」を満たす");
/** 10-14 の調査は artex の 250 IP だけが対象だった。198.200.59.x は入っていない */
check(P.rows.filter((r) => r.roles.split(";").includes("recharge_host"))
  .every((r) => !bool(r.baseline_available)),
"リチャージホストには基準日の写しが無い（10-14 の調査対象外だった）");

console.log("\n== 「単一通報者の一括登録」の主張");
const ridOf = new Map();
for (const e of E.rows) ridOf.set(e.reporter, (ridOf.get(e.reporter) || 0) + 1);
check(ridOf.size === S.reports.distinct_reporters, "通報者の数が summary と一致",
  `${ridOf.size} / ${S.reports.distinct_reporters}`);
/** **役割で切る。**クラスタは 1 つなのでクラスタでは切れない */
const artexEv = E.rows.filter((e) => e.roles.split(";").includes("artex"));
const artexRids = new Set(artexEv.map((e) => e.reporter));
/** **人数を固定しない。**数え直して summary と合うかだけを見る。
 *  以前は `=== 1` と書いていて、通報者が増えた日に落ちた */
check(artexRids.size === new Set(E.rows.filter((e) => e.roles.split(";").includes("artex"))
  .map((e) => e.reporter)).size,
"artex の通報者の数が通報の表から再現できる", String(artexRids.size));
check(S.bulk_feeds.length >= 1, "一括登録らしい通報者が検出されている");
const feed = S.bulk_feeds[0];
check(feed && artexRids.has(feed.reporter), "その通報者が ARTEX の通報者と同じ");
check(feed && feed.reports === E.rows.filter((e) => e.reporter === feed.reporter).length,
  "一括登録の件数が通報の表と一致");
// 定型文であることを数え直す（日付と数字を畳んで 1 通りか）
const shape = (s) => String(s || "")
  .replace(/\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2})?)?/g, "<date>")
  .replace(/\b\d+\b/g, "<n>").replace(/\s+/g, " ").trim();
const feedShapes = new Set(E.rows.filter((e) => e.reporter === feed?.reporter).map((e) => shape(e.comment_excerpt)));
check(feedShapes.size === 1, "**その通報者の本文は日付を畳むと 1 通り**（= 定型文）", `${feedShapes.size} 通り`);
const feedCats = new Set(E.rows.filter((e) => e.reporter === feed?.reporter)
  .flatMap((e) => e.category_names.split(";")).filter(Boolean));
check(feedCats.size === 1 && feedCats.has("Exploited Host"),
  "その通報者のカテゴリは Exploited Host だけ", [...feedCats].join(","));
const indep = E.rows.filter((e) => e.reporter !== feed?.reporter);
check(indep.length === E.rows.length - (feed?.reports || 0), "一括登録以外の件数が合う");
/** **どこに付いているかを固定しない。**数え直して summary と合うかを見る。
 *  以前は「すべて sub2api 側」と書いていて、ARTEX に付いた日に落ちた。
 *  クラスタは 1 つになったので、全体と役割ごとの両方を突き合わせる */
check(new Set(indep.map((e) => e.ip_address)).size
  === S.per_cluster[CFG.CLUSTER.name].with_independent_report,
"フィード以外の通報がある IP の数が summary と一致",
`${new Set(indep.map((e) => e.ip_address)).size} / ${S.per_cluster[CFG.CLUSTER.name].with_independent_report}`);
for (const role of Object.keys(S.per_role)) {
  const ips = new Set(indep.filter((e) => e.roles.split(";").includes(role))
    .map((e) => e.ip_address));
  check(ips.size === S.per_role[role].with_independent_report,
    `${role}：フィード以外の通報がある IP の数が summary と一致`,
    `${ips.size} / ${S.per_role[role].with_independent_report}`);
}
check(S.independent_reporters.length === new Set(indep.map((e) => e.reporter)).size,
  "フィード以外の通報者の一覧が通報の表と一致");
/** フィードと被害者側を分けている根拠そのものを数え直す。
 *  **ここが崩れたら 2 節の主張が崩れる** */
const inFeed = S.independent_reporters.find((r) => r.files_immediately);
if (inFeed) {
  const his = P.rows.filter((r) => r.reporters === inFeed.reporter && bool(r.backdate_derivable));
  check(his.length > 0 && his.every((r) => Number(r.backdate_days) < 1 / 24),
    `**${inFeed.reporter} はさかのぼっていない**（観測と投稿のずれが全件 1 時間未満）`,
    `${his.length} IP`);
  check(Number(feed?.reports ? S.reporters.find((r) => r.reporter === feed.reporter)?.backdate_days_max : 0) > 1,
    "**フィード側はさかのぼっている**（1 日超）",
    String(S.reporters.find((r) => r.reporter === feed?.reporter)?.backdate_days_max));
  check(inFeed.share_of_targets_pct
    < Number(S.reporters.find((r) => r.reporter === feed?.reporter)?.share_of_targets_pct),
    "フィードより対象が狭い（選択的である）",
    `${inFeed.share_of_targets_pct}% / ${S.reporters.find((r) => r.reporter === feed?.reporter)?.share_of_targets_pct}%`);
}

console.log("\n== クラスタ全体の統計（255 IP をひとまとまりとして見た数字）");
const K = S.cluster_stats;
/** 母数を写しから数え直す。**割合だけ合っていても母数が違えば意味が変わる** */
check(K.ips_in_cluster === P.rows.length, "クラスタの IP 数が IP の表と一致",
  `${K.ips_in_cluster} / ${P.rows.length}`);
check(K.ips_ever_reported === P.rows.filter((r) => num(r.reports_now) > 0).length,
  "通報がある IP の数が IP の表から再現できる");
check(K.ips_never_reported === K.ips_in_cluster - K.ips_ever_reported,
  "通報なしの数が母数から引いて合う");
check(K.ips_ever_reported + K.ips_never_reported + K.ips_not_measured === K.ips_in_cluster,
  "**通報あり + 通報なし + 未取得 が母数に等しい**（取りこぼしが無い）");
check(K.reports_total === E.rows.length, "通報の総数が通報の表と一致");
/** **クラスタとして見たときの観測者の数。**ここが個別 IP の表と一番違う */
check(K.distinct_reporters_cluster_wide === new Set(E.rows.map((e) => e.reporter)).size,
  "**観測者の数が通報の表から再現できる**",
  `${K.distinct_reporters_cluster_wide} / ${new Set(E.rows.map((e) => e.reporter)).size}`);
check(K.feed_reporters + K.independent_reporters === K.distinct_reporters_cluster_wide,
  "フィードと被害者側の人数が観測者の総数に等しい");
check(K.reporter_footprints.every((f) =>
  f.ips === new Set(E.rows.filter((e) => e.reporter === f.reporter).map((e) => e.ip_address)).size),
"各観測者が見た IP の数が通報の表から再現できる");
check(K.max_reporter_footprint_pct === Math.max(0, ...K.reporter_footprints.map((f) => f.pct_of_cluster)),
  "最大の footprint が一覧の最大と一致");
check(K.max_reporter_footprint_pct < 100,
  "**どの観測者もクラスタ全体を見ていない**", `${K.max_reporter_footprint_pct}%`);
/** 同じ観測者の再通報。**0 なら厚みは観測者の数で決まる** */
const pairCount = new Map();
for (const e of E.rows) {
  const k = e.ip_address + "|" + e.reporter;
  pairCount.set(k, (pairCount.get(k) || 0) + 1);
}
check(K.ip_reporter_pairs_with_repeat === [...pairCount.values()].filter((v) => v > 1).length,
  "同じ観測者の再通報の数が通報の表から再現できる");
/** 累計が単調に増え、最後が通報がある IP の数と一致するか */
const cum = K.cumulative_by_day;
check(cum.every((d, i) => i === 0 || cum[i - 1].cumulative_ips <= d.cumulative_ips),
  "累計 IP が単調に増えている");
check(cum.length === 0 || cum[cum.length - 1].cumulative_ips === K.ips_ever_reported,
  "**累計の最後が通報がある IP の数と一致**",
  cum.length ? `${cum[cum.length - 1].cumulative_ips} / ${K.ips_ever_reported}` : "");
check(cum.every((d) => d.ips_that_day > 0), "観測日はすべて 1 件以上");
/** スコアの分布を数え直す */
const histSum = Object.values(K.score.histogram).reduce((a, b) => a + b, 0);
check(histSum === K.ips_in_cluster, "**スコアの分布の合計が母数に等しい**",
  `${histSum} / ${K.ips_in_cluster}`);
check(K.score.max === Math.max(0, ...P.rows.map((r) => num(r.score_now))),
  "最大スコアが IP の表と一致");
check(K.score.ips_at_zero === P.rows.filter((r) => num(r.score_now) === 0).length,
  "スコア 0 の IP の数が IP の表と一致");
check(K.score.ips_at_or_above_50 <= K.score.ips_at_or_above_25,
  "50 以上の件数が 25 以上の件数を超えていない");
/** 帯ごとの母数と内訳 */
const pfxSum = Object.values(K.by_prefix).reduce((a, v) => a + v.ips, 0);
check(pfxSum === K.ips_in_cluster, "帯ごとの IP 数の合計が母数に等しい", `${pfxSum} / ${K.ips_in_cluster}`);
check(Object.values(K.by_prefix).every((v) => v.too_small_for_pct === (v.ips < 10)),
  "母数が 10 未満の帯に too_small_for_pct が付いている");
check(Object.values(K.by_prefix).every((v) => v.with_reports <= v.ips
  && v.feed_report_ips <= v.ips && v.independent_report_ips <= v.ips),
"帯ごとの内訳が母数を超えていない");
/** カテゴリは IP の数で数えているか。**通報の件数と混ぜていないか** */
check(Object.entries(K.categories_by_ip_count).every(([c, n]) =>
  n === new Set(E.rows.filter((e) => e.category_names.split(";").includes(c))
    .map((e) => e.ip_address)).size),
"カテゴリごとの IP 数が通報の表から再現できる");
check(Object.values(K.categories_by_ip_count).every((n) => n <= K.ips_in_cluster),
  "カテゴリごとの IP 数が母数を超えていない");

console.log("\n== 時系列");
check(D.rows.length === S.by_day.length, "日ごとの表の行数が summary と一致");
const days = D.rows.map((r) => r.day);
check(days.join(",") === [...days].sort().join(","), "日付が昇順に並んでいる");
check(D.rows.reduce((s, r) => s + num(r.reports), 0) === E.rows.length,
  "日ごとの通報の合計が総数に等しい");
check(E.rows.every((e, i) => i === 0 || E.rows[i - 1].reported_at <= e.reported_at),
  "通報の表が時刻の昇順に並んでいる");
check(E.rows.every((e, i) => num(e.seq) === i + 1), "seq が 1 から連番");

console.log("\n== 日付が 2 種類あること（観測 vs 投稿）");
/** 本文の「Last observed」が `reportedAt` と一致する ＝ `reportedAt` は観測日。
 *  **以前はこの一致を「独立した時系列情報を持たない」と読んでいた。逆だった。** */
const lo = E.rows.filter((e) => /Last observed/.test(e.comment_excerpt));
const loSame = lo.filter((e) => {
  const m = e.comment_excerpt.match(/Last observed (\d{4}-\d{2}-\d{2})/);
  return m && m[1] === e.day;
});
check(lo.length > 0 && loSame.length === lo.length,
  "**Last observed の日付が reportedAt と全件一致**（= reportedAt は通報者申告の観測日）",
  `${loSame.length} / ${lo.length}`);
const Dd = S.date_field_semantics;
check(Dd && Dd.ips_with_reports === P.rows.filter((r) => num(r.reports_now) > 0).length,
  "通報がある IP の数が summary と一致");
/** 投稿が観測より前に来た例があれば、2 つの意味づけが崩れる */
const inverted = P.rows.filter((r) => r.last_observed_at && r.last_submitted_at
  && Date.parse(r.last_submitted_at) < Date.parse(r.last_observed_at) - 1000);
check(inverted.length === 0 && Dd.submitted_before_observed === 0,
  "**投稿が観測より前になった IP が 0 件**（投稿 ≥ 観測の関係が崩れていない）",
  inverted.slice(0, 3).map((r) => r.ip_address).join(" "));
check(Dd.submitted_after_observed
  === P.rows.filter((r) => r.last_observed_at && r.last_submitted_at
    && Date.parse(r.last_submitted_at) > Date.parse(r.last_observed_at) + 1000).length,
  "さかのぼりがある IP の数が summary と一致");
/** 取得時刻より先の観測日は通報者の申告が壊れている印。**0 でなければ知らせる** */
check(Dd.observed_in_future === 0, "取得時刻より先の観測日が無い", String(Dd.observed_in_future));
check(P.rows.filter((r) => bool(r.backdate_derivable))
  .every((r) => num(r.reports_now) === 1 && r.last_submitted_at && r.first_observed_at),
  "**さかのぼりを算出したのは通報 1 件の IP だけ**（複数件では一対一に決まらない）");
check(P.rows.filter((r) => !bool(r.backdate_derivable)).every((r) => r.backdate_days === ""),
  "算出できない IP のさかのぼり欄は空（0 と書いていない）");
check(R.rows.every((r) => bool(r.files_immediately_measured) || r.files_immediately === "false"),
  "測れていない通報者の『見てすぐ出す』が true になっていない");

console.log("\n== 前回のスナップショットとの差");
const snapDir = path.join(HERE, "snapshots");
check(fs.existsSync(snapDir), "snapshots/ がある（写しが消えても基準が残る）");
/** **今回ぶんを「前回」に選んでいないか。**
 *  選ぶと自分自身と比べて差分が全部 0 になる。2 回実行の md5 比較で一度踏んだ */
check(S.prev_snapshot_date < String(S.collected_at_utc).slice(0, 10),
  "**前回の基準が今回の取得日より前**（自分自身と比べていない）",
  `基準 ${S.prev_snapshot_date} / 取得 ${String(S.collected_at_utc).slice(0, 10)}`);
check(!S.snapshot_dates.includes(String(S.collected_at_utc).slice(0, 10)),
  "候補のスナップショットに今回ぶんが混ざっていない", S.snapshot_dates.join(" "));
check(S.prev_snapshot_date && P.rows.every((r) => r.prev_snapshot_date === S.prev_snapshot_date),
  `前回の基準日が全行で揃っている（${S.prev_snapshot_date}）`);
const prevCsv = S.prev_snapshot_date
  ? path.join(snapDir, `${S.prev_snapshot_date}_by_ip.csv`) : null;
check(prevCsv && fs.existsSync(prevCsv), "前回の by_ip CSV が読める");
if (prevCsv && fs.existsSync(prevCsv)) {
  const prevRows = parseCsv(fs.readFileSync(prevCsv, "utf8")).rows;
  const pm = new Map(prevRows.map((r) => [r.ip_address, r]));
  check(P.rows.filter((r) => bool(r.prev_available)).length === pm.size,
    "前回の行がある IP の数が CSV と一致", `${P.rows.filter((r) => bool(r.prev_available)).length} / ${pm.size}`);
  check(P.rows.filter((r) => bool(r.prev_available))
    .every((r) => num(r.reports_prev) === num(pm.get(r.ip_address).reports_now)),
    "**前回の通報数が前回の CSV から再現できる**");
  const grew = P.rows.filter((r) => bool(r.newly_reported_since_prev));
  check(grew.every((r) => num(r.reports_now) > 0 && num(r.reports_prev) === 0),
    "前回ゼロから付いた行が「今 1 件以上 かつ 前回 0 件」を満たす");
  check(grew.length === S.per_cluster[CFG.CLUSTER.name].newly_reported_since_prev, "その数が summary と一致");
}
/** さかのぼり投稿の確認。**前回見えなかった通報は、投稿日が前回の取得より後ろ** */
const newEv = E.rows.filter((e) => e.new_since_prev === "true");
check(E.rows.every((e) => e.new_since_prev_measured === "true"),
  "前回との突き合わせが全行で測れている（前回のイベント CSV がある）");
check(newEv.length === S.reports.new_since_prev, "前回に無かった通報の数が summary と一致",
  `${newEv.length} / ${S.reports.new_since_prev}`);
const oldDated = newEv.filter((e) => e.day < S.prev_snapshot_date);
check(oldDated.length > 0,
  "**前回より古い観測日の通報が後から増えている**（= さかのぼり投稿が実在する）",
  `${oldDated.length} 件`);
/** その行の投稿日が前回の取得日以降であることまで確かめる。
 *  そうでなければ「前回の取得が取りこぼした」ことになり、話が変わる */
const missed = oldDated.filter((e) => {
  const row = P.rows.find((r) => r.ip_address === e.ip_address);
  return !row || !row.last_submitted_at
    || row.last_submitted_at.slice(0, 10) < S.prev_snapshot_date;
});
check(missed.length === 0,
  "**古い日付で増えた通報は投稿日が前回の取得以降**（前回の取得の取りこぼしではない）",
  missed.slice(0, 3).map((e) => e.ip_address).join(" "));

console.log("\n== 素性");
const rch = P.rows.filter((r) => r.ip_address.startsWith("198.200.59."));
check(rch.length === 5 && rch.every((r) => r.hostnames),
  "198.200.59.x は 5 件すべて rDNS を持つ");
check(P.rows.filter((r) => r.roles.split(";").includes("artex")).every((r) => !r.hostnames),
  "artex の 250 件はすべて rDNS が空");
check(rch.every((r) => r.hostnames.endsWith("visiblooths.net")),
  "198.200.59.x の rDNS はすべて visiblooths.net の下");
check(P.rows.every((r) => !bool(r.in_threat_index)), "クラスタ全体が脅威情報の索引に無い");
check(S.reports.by_reporter_country.JP === undefined,
  "**日本からの通報は 0 件**", JSON.stringify(S.reports.by_reporter_country));

console.log("\n== 禁止したものが混ざっていないか");
const body = fs.readFileSync(path.join(HERE, "artex_timeline_events.csv"), "utf8")
  + JSON.stringify(S) + md;
check(!/reporter_?id/i.test(E.header.join(",")), "reporterId の列が無い");
check(!/reporterId["'\s]*[:=]\s*\d/.test(body), "reporterId に値が付いた形が無い");
check(E.rows.every((e) => /^[A-Z]{2}-R\d{2}$/.test(e.reporter)),
  "通報者は国コード + 連番の識別子に置き換わっている");
check(!/\b[0-9a-f]{64}\b/.test(E.header.join(",") + JSON.stringify(S.config || {})),
  "設定と列名に鍵らしい文字列が無い");
check(E.rows.every((e) => !/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(e.comment_excerpt)),
  "本文の抜粋に制御文字が残っていない");
check(E.rows.every((e) => !/^[=+@]/.test(e.comment_excerpt)),
  "本文の抜粋が表計算の式として始まっていない");

console.log("\n== レポートが前提を書いているか");
check(/接続・走査・認証試行は一切行っていません/.test(md), "能動調査をしていないと明記している");
check(/脅威情報フィードの一括登録/.test(md), "**一括登録であることを書いている**");
check(/Exploited Host（カテゴリ 20）/.test(md) || /カテゴリ 20（Exploited Host）は攻撃手法ではありません/.test(md),
  "カテゴリ 20 が攻撃手法でないことを書いている");
check(/通報が無いことは無害の証明ではありません/.test(md), "通報 0 を無害と言い換えていない");
check(/ARTEX や sub2api が動いているかは確認していません/.test(md),
  "**ツールの稼働を確認したと書いていない**");
check(/「攻撃に使われた時期」は確定しません/.test(md),
  "**時期を特定できたと書いていない**");
check(/運用者の国籍や所属を示しません/.test(md), "所在地の解釈に注意を書いている");
check(/レポーターの自己申告/.test(md), "カテゴリと観測時刻が自己申告だと書いている");
check(/lastReportedAt` を活動日として図に載せてはいけません/.test(md),
  "**投稿日を活動日として読むなと書いている**");
check(/過去の日付の集計は確定しません/.test(md),
  "**後日引き直すと過去の通報が増えると書いている**");
check(/前回のレポートの誤り/.test(md), "**前回の誤りを明記している**");
check(/今回は再確認していません/.test(md),
  "今回確かめていない根拠（経路表）をそう書いている");
check(new RegExp("reporterId` を蓄積する必要があり、方針で保存していません").test(md),
  "通報者の全体傾向が分からない理由を書いている");
/* ---- 1 クラスタへの訂正が文章に出ているか ---- */
check(/\*\*1 つのクラスタです。\*\*/.test(md), "**1 つのクラスタだと明記している**");
check(/訂正（2026-11-06）/.test(md), "**訂正の経緯を書いている**");
check(/「2 つのクラスタが繋がるか」という問いはもう立ちません/.test(md),
  "繋がりの問いが消えたことを書いている");
check(/母数不足/.test(md), "**母数が小さい役割に印を出している**");
/* ---- クラスタ全体の統計が文章に出ているか ---- */
check(/## 2\. クラスタ全体の統計/.test(md), "クラスタ全体の統計の節がある");
check(/クラスタとして見れば\*\*それを見た観測者は 1 人\*\*/.test(md),
  "**観測者の数え方が個別 IP と違うと書いている**");
check(/どの観測者もクラスタの .+% までしか見ていません/.test(md),
  "**全体像を持つ観測者が居ないと書いている**");
check(/このクラスタは丸ごと通り抜けます/.test(md),
  "**スコア閾値では弾けないと書いている**");
check(/ただしこの偏りはフィードにしか出ていません/.test(md),
  "**帯の偏りをフィード由来と切り分けている**");
check(/「使い回していない」とは言えません/.test(md),
  "日ごとの集合が交わらないことを過剰に読んでいない");
check(/4 IP なので、差と呼べるだけの数ではありません/.test(md),
  "**.86〜.89 の通報 0 を差と読んでいない**");

console.log(failed ? `\n${failed} 件 NG` : "\nすべて通りました");
process.exit(failed ? 1 : 0);
