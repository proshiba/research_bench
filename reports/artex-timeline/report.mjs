#!/usr/bin/env node
// 出来上がった CSV と summary.json から日本語レポートを組む。
// **写しだけを見る。API は呼ばない。** 何度走らせても同じものが出る。
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
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
  return rows.filter((r) => r.length > 1).map((r) => Object.fromEntries(h.map((k, i) => [k, r[i] ?? ""])));
}
const read = (f) => parseCsv(fs.readFileSync(path.join(HERE, f), "utf8"));
const S = JSON.parse(fs.readFileSync(path.join(HERE, "artex_timeline_summary.json"), "utf8"));
const byIp = read("artex_timeline_by_ip.csv");
const events = read("artex_timeline_events.csv");
const byReporter = read("artex_timeline_by_reporter.csv");

const bt = String.fromCharCode(96);
const code = (s) => bt + s + bt;
const safe = (s, n = 40) => String(s || "").replace(/\|/g, "／").replace(/\s+/g, " ").slice(0, n);
const T = (head, body) => [
  "| " + head.join(" | ") + " |",
  "| " + head.map(() => "---").join(" | ") + " |",
  ...body.map((r) => "| " + r.join(" | ") + " |"),
].join("\n");

/** **クラスタは 1 つ。**内訳は役割で見る */
const C = S.per_cluster[S.cluster.name];
const R = S.per_role;
const ART = R.artex, RCH = R.recharge_host;
/** sub2api だけ（ARTEX もリチャージホストでもない）= .86〜.89 */
const ONLY = Object.entries(S.per_role_set || {}).length ? null : null;
const D = S.date_field_semantics;
const PREV = S.prev_snapshot_date;
const feedReports = S.bulk_feeds.reduce((s, f) => s + f.reports, 0);
const indepAll = S.independent_reporters;
const newEvents = events.filter((e) => e.new_since_prev === "true");
const newIndep = newEvents.filter((e) => !S.bulk_feeds.some((f) => f.reporter === e.reporter));

const L = [];
L.push("# " + S.cluster.name + " — AbuseIPDB 上の通報の時系列", "");
L.push("> **この文書は Claude（AI）が自動生成したものです。人の確認を前提としてください。**", "");
L.push("取得 " + String(S.collected_at_utc).slice(0, 16) + " UTC"
  + (PREV ? " ／ 前回 " + PREV + " との差を主に見ています。" : "") , "");
L.push("**1 つのクラスタです。** " + safe(S.cluster.note, 160), "");
L.push(T(["役割", "対象", "利用者の観測"], S.groups.map((g) => [
  g.roles.map(code).join(" "),
  g.ranges ? g.ranges.map(code).join(" と ") + " の " + code(".1〜.125")
    : g.explicit.map(code).join(" "),
  safe(g.note, 70)])), "");
if (S.correction_note) {
  L.push("> **訂正（2026-11-06）** — " + safe(S.correction_note, 240), "");
}
L.push("**対象 IP への接続・走査・認証試行は一切行っていません。** AbuseIPDB の公開情報と");
L.push("手元の索引だけを見ています。この集計自体は API も呼んでいません。", "");

/* ---- 前回からの差 ---- */
L.push("## 0. 前回（" + PREV + "）から変わったこと", "");
L.push(T(["", PREV, S.collected_at_utc.slice(0, 10), "差"], [
  ["通報がある IP（255 中）", String(C.with_reports_prev), String(C.with_reports_now),
    "**+" + (C.with_reports_now - C.with_reports_prev) + "**"],
  ["**フィード以外の通報がある IP**", "**1**", "**" + C.with_independent_report + "**",
    "**+" + (C.with_independent_report - 1) + "**"],
  ["うち " + code("artex") + " の 250 IP", String(ART.with_reports_prev), String(ART.with_reports_now),
    "**+" + (ART.with_reports_now - ART.with_reports_prev) + "**"],
  ["うち " + code("recharge_host") + "（" + code("198.200.59.85") + "）",
    String(RCH.with_reports_prev), String(RCH.with_reports_now), "0"],
  ["日本からの通報", "0", String(C.jp_reports), "0"],
]), "");
L.push("**一番大きい変化は 2 行目です。** 前回は ARTEX 250 IP の通報が**全部フィードの");
L.push("一括登録**で、被害者側の観測は " + code("198.200.59.85") + " の 1 IP だけでした。");
L.push("今回は " + C.with_independent_report + " IP に付いています。", "");
L.push("前回に無かった通報は " + newEvents.length + " 件で、内訳は**フィード "
  + (newEvents.length - newIndep.length) + " 件 / フィード以外 " + newIndep.length + " 件**です。", "");

/* ---- 結論 ---- */
L.push("## 1. 結論", "");
L.push(T(["問い", "答え"], [
  ["ARTEX は「複数の観測者が攻撃を見た」状態になったか",
    "**部分的にそう言えるようになった。**" + C.with_independent_report + " / " + C.ips
    + " IP にフィード以外の通報。ただし通報者は 1 人"],
  ["それは何として通報されたか",
    "**Web App Attack（カテゴリ 21）**。前回まで ARTEX に付いていたのは Exploited Host（20）だけだった"],
  ["その通報はフィードの転載ではないと言えるか",
    "**言える。**観測時刻と投稿時刻のずれが 0 秒で、対象は 255 IP の 3.1% だけ（フィードは最大 7.32 日ずれ・22.7%）"],
  ["攻撃に使われた時期は特定できたか",
    "**観測日ベースでは " + S.reports.first_observed.slice(0, 10) + " 〜 " + S.reports.last_observed.slice(0, 10)
    + "。**ただしさかのぼり投稿があるので確定しない（4 節）"],
  ["リチャージ URL のホストは",
    "**" + code("198.200.59.85") + " が最初（09-30）で最多**（通報 3 件 / 通報者 3 人）。"
    + "前回から変化なし。隣の " + code(".86〜.89") + " は**一度も通報されていない**"],
  ["日本からの通報は", "**0 件**"],
]), "");

/* ---- フィードと被害者側の区別 ---- */
/* ---- クラスタ全体の統計 ---- */
const K = S.cluster_stats;
L.push("## 2. クラスタ全体の統計", "");
L.push("**255 IP をひとまとまりとして見た数字です。**個別 IP の表とは数え方が違います。");
L.push("いちばん変わるのは**観測者の数え方**で、IP ごとに見れば「58 IP が通報されている」");
L.push("ですが、クラスタとして見れば**それを見た観測者は 1 人**です。", "");

L.push("### 規模と広がり", "");
L.push(T(["項目", "値", "母数"], [
  ["クラスタの IP", "**" + K.ips_in_cluster + "**", "—"],
  ["一度でも通報された IP", "**" + K.ips_ever_reported + "**（" + K.ips_ever_reported_pct + "%）",
    String(K.ips_in_cluster)],
  ["一度も通報されていない IP", String(K.ips_never_reported), String(K.ips_in_cluster)],
  ["引けていない IP（= 分からない）", String(K.ips_not_measured), String(K.ips_in_cluster)],
  ["通報の総数", "**" + K.reports_total + "**", "—"],
  ["フィード以外の通報がある IP", "**" + K.ips_with_independent_report + "**（"
    + K.ips_with_independent_report_pct + "%）", String(K.ips_in_cluster)],
  ["フィード以外の通報の総数", String(K.independent_reports_total), "—"],
  ["日本からの通報", "**" + K.jp_reports + "**", "—"],
]), "");

L.push("### 観測者（クラスタとして見るとここが一番変わる）", "");
L.push(T(["観測者", "所在", "見た IP", "クラスタの", "1 IP あたりの通報", "フィード"],
  K.reporter_footprints.map((r) => [
    code(r.reporter), r.country, String(r.ips), r.pct_of_cluster + "%",
    String(r.reports_per_ip), r.bulk_feed ? "**はい**" : "—"])), "");
L.push("- **このクラスタ全体を通報した観測者は " + K.distinct_reporters_cluster_wide
  + " 人しか居ません。** うち " + K.feed_reporters + " 人がフィードの一括登録で、");
L.push("  被害者側は " + K.independent_reporters + " 人です");
L.push("- **どの観測者もクラスタの " + K.max_reporter_footprint_pct + "% までしか見ていません。**");
L.push("  全体像を持っている観測者は居ません");
L.push("- **1 IP あたりの通報はどの観測者も 1.0 です。**");
L.push("  同じ観測者が同じ IP を 2 回以上通報した例は " + K.ip_reporter_pairs_with_repeat + " 件");
L.push("");
L.push("ここから、**クラスタの通報の厚みは観測者の数で決まっています**。");
L.push("通報 " + K.reports_total + " 件は「IP と観測者の組の数」とほぼ同じで（1 IP あたり "
  + K.reports_per_reported_ip + " 件）、");
L.push("通報が 2 件以上ある IP は " + K.ips_with_more_than_one_report + " 件、最大でも "
  + K.max_reports_on_one_ip + " 件です。", "");

L.push("### 時間の構造", "");
L.push(T(["項目", "値"], [
  ["最初の観測", K.first_observed],
  ["最後の観測", "**" + K.last_observed + "**"],
  ["観測の窓", K.observation_window_days + " 日"],
  ["観測があった日", "**" + K.days_with_any_observation + " 日**（窓の "
    + K.days_with_any_observation_pct + "%）"],
  ["最後の観測から", "**" + K.days_quiet_since_last_observation + " 日**"],
  ["2 日以上に跨って通報された IP", K.ips_reported_on_multiple_days + " 件"],
]), "");
L.push("**プールの消費のしかた**（その日までに通報された IP の累計）:", "");
L.push(T(["観測日", "その日の IP", "累計 IP", "クラスタの"],
  K.cumulative_by_day.map((d) => [d.day, String(d.ips_that_day),
    String(d.cumulative_ips), d.cumulative_pct + "%"])), "");
L.push("- **累計は " + K.cumulative_by_day[K.cumulative_by_day.length - 1].cumulative_pct
  + "% で止まっています。** 32 日の窓で、クラスタの 1/4 までしか通報に現れていません");
L.push("- **日ごとの集合はほぼ交わりません**（2 日以上に跨る IP は "
  + K.ips_reported_on_multiple_days + " 件だけ）。");
L.push("  ただし**同じ観測者の再通報が 1 行に増えない**ので、「使い回していない」とは言えません");
L.push("- 10-24 の 32 IP のように**一日に固まる**ことがあります。");
L.push("  10-31 の 8 IP は 10 秒間に収まっており、1 台の検知器がまとめて出した形です");
L.push("");

L.push("### カテゴリ（IP の数で数える）", "");
L.push(T(["カテゴリ", "付いている IP", "クラスタの"],
  Object.entries(K.categories_by_ip_count).sort((a, b) => b[1] - a[1]).map(([c, n]) => [
    c, String(n), Number((100 * n / K.ips_in_cluster).toFixed(1)) + "%"])), "");
L.push("**この表は足せません。** 1 つの IP に複数のカテゴリが付きます");
L.push("（" + code("198.200.59.85") + " には 14・15・20・21 の 4 つ）。");
L.push("足すと 11 になりますが、**重複しない IP は " + K.category_partition_by_ip.attack_technique_ips
  + " 件**です。", "");
L.push("重複しない区分で数え直すと:", "");
L.push(T(["区分", "IP", "クラスタの"], [
  ["**攻撃手法が付いている**（Web App Attack / Hacking など）",
    "**" + K.category_partition_by_ip.attack_technique_ips + "**",
    Number((100 * K.category_partition_by_ip.attack_technique_ips / K.ips_in_cluster).toFixed(1)) + "%"],
  ["偵察のみ（Port Scan だけ）", String(K.category_partition_by_ip.reconnaissance_only_ips), "—"],
  ["Exploited Host だけ", String(K.category_partition_by_ip.exploited_host_only_ips),
    Number((100 * K.category_partition_by_ip.exploited_host_only_ips / K.ips_in_cluster).toFixed(1)) + "%"],
  ["合計（= 通報がある IP）", String(K.category_partition_by_ip.sum), K.ips_ever_reported_pct + "%"],
]), "");
L.push("**Exploited Host（20）は攻撃手法ではありません**（3 節）。それだけが付いている "
  + K.category_partition_by_ip.exploited_host_only_ips + " IP は");
L.push("「この送信元自体が侵害されている可能性」を言っているだけで、攻撃を観測した記録ではありません。", "");

L.push("### スコア（255 IP 全体の分布）", "");
L.push(T(["スコア", "IP の数"], Object.entries(K.score.histogram).map(([v, n]) =>
  [v, String(n)])), "");
L.push(T(["項目", "値"], [
  ["最大", "**" + K.score.max + "**"],
  ["中央値（255 全体）", String(K.score.median_all_255)],
  ["中央値（通報がある 65 件）", String(K.score.median_reported_only)],
  ["スコア 0 の IP", String(K.score.ips_at_zero) + " / " + K.ips_in_cluster],
  ["25 以上の IP", "**" + K.score.ips_at_or_above_25 + "**"],
  ["50 以上の IP", "**" + K.score.ips_at_or_above_50 + "**"],
]), "");
L.push("**クラスタの最大スコアは " + K.score.max + " で、25 以上の IP は 1 件もありません。**");
L.push("AbuseIPDB のスコアだけを閾値にして弾く運用では、**このクラスタは丸ごと通り抜けます**。");
L.push("スコアは通報が増えなくても時間で下がるので、横に比べるときは取得日を揃えてください。", "");

L.push("### アドレス空間の使われ方", "");
L.push(T(["帯", "IP", "通報あり", "割合", "フィード", "被害者側", "連続区間", "ホスト番号"],
  Object.entries(K.by_prefix).sort().map(([p, v]) => [
    code(p + ".x"), String(v.ips), String(v.with_reports),
    v.too_small_for_pct ? "**母数不足**" : v.pct + "%",
    String(v.feed_report_ips), String(v.independent_report_ips),
    String(v.contiguous_runs),
    v.host_min === null ? "—" : v.host_min + "〜" + v.host_max])), "");
(() => {
  const a = K.by_prefix["38.11.173"], b = K.by_prefix["38.11.221"];
  if (!a || !b) return;
  L.push("- " + code("38.11.173.x") + " が " + code("38.11.221.x") + " の **"
    + (b.with_reports ? (a.with_reports / b.with_reports).toFixed(1) : "—")
    + " 倍**通報されています（" + a.with_reports + " / " + b.with_reports + "、母数は同じ 125）");
  L.push("- **ただしこの偏りはフィードにしか出ていません。** フィードは "
    + a.feed_report_ips + " 対 " + b.feed_report_ips + " で偏っていますが、");
  L.push("  被害者側は **" + a.independent_report_ips + " 対 "
    + b.independent_report_ips + " で均等**です。");
  L.push("  **「" + code("38.11.173") + " のほうが多く使われている」とは読めません。**");
  L.push("  フィードの集め方の偏りである可能性が残ります（被害者側は 8 IP しかないので、");
  L.push("  均等であること自体も強い証拠ではありません）");
  L.push("- 連続区間が " + a.contiguous_runs + " / " + b.contiguous_runs
    + " と多く、**まとまったブロックではなく散っています**");
})();
L.push("");

L.push("## 3. 「複数 IP が報告されている」の中身", "");
L.push("通報 " + S.reports.total + " 件のうち **" + feedReports + " 件が単一の通報者**で、");
L.push("日付以外は同じ定型文です。残り " + (S.reports.total - feedReports) + " 件が他の "
  + indepAll.length + " 人によるものです。", "");
/** 通報者ごとの比較表。**右 2 列が一括登録と被害者側の観測を分ける。**
 *  測れていない欄は空欄ではなく「測れず」と書く。false と混ぜないため */
L.push(T(["通報者", "所在", "通報", "IP", "255 IP の", "観測日", "カテゴリ", "さかのぼり最大", "見てすぐ出す"],
  byReporter.map((r) => [
    "`" + r.reporter + "`" + (r.looks_like_bulk_feed === "true" ? "（フィード）" : ""),
    r.country, r.reports, r.distinct_ips, r.share_of_targets_pct + "%",
    r.days.split(";").join(" "), safe(r.category_names, 24),
    r.backdate_measurable_ips === "0" ? "測れず" : "**" + r.backdate_days_max + " 日**",
    r.files_immediately_measured === "true"
      ? (r.files_immediately === "true" ? "**はい**" : "いいえ") : "測れず",
  ])), "");
L.push("**`BR-R01` の 58 件は脅威情報フィードの一括登録で、被害者が「攻撃された」と");
L.push("通報したものではありません。** 前回からこの部分の読み方は変わっていません。", "");
L.push("**この表の右 2 列が、フィードの一括登録と被害者側の観測を分けます。**", "");
L.push("- **フィードは手元の台帳をまとめて流す**ので、観測日をさかのぼって投稿します");
L.push("  （中央 " + D.backdate_days_median + " 日・最大 " + D.backdate_days_max + " 日）。");
L.push("  対象も広く、255 IP の 22.7% に及びます");
L.push("- **被害者側の検知器は見たその場で出す**ので、ずれが 0 になります。");
L.push("  対象も自分に来たものだけなので 3.1% に留まります");
L.push("");
L.push("**件数と定型文だけでは両者は同じ形に見えます。** " + code("IN-R04")
  + " も 8 件を 10 秒間に同じ本文で");
L.push("出しており、定型文は 1 通りです。それでも**転載ではない**と言えるのは、上の 2 列があるからです。", "");
L.push("### 「フィードだから割り引く」はどこまで言えるか", "");
const F = S.feed_listing_vs_independent;
L.push("「フィードに載っているということは、攻撃に使われているのではないか」という問いに");
L.push("この母集団で答えると、**フィード掲載は被害者側の通報を予測しませんでした**。", "");
L.push(T(["", "IP", "フィード以外の通報がある", "割合"], [
  ["フィードに載っている", String(F.feed_listed_ips), String(F.feed_listed_with_independent), F.feed_listed_pct + "%"],
  ["載っていない", String(F.not_listed_ips), String(F.not_listed_with_independent), F.not_listed_pct + "%"],
]), "");
if (F.underpowered) {
  L.push("**ただしこれは差を論じるには足りません。** フィード以外の通報がある IP が");
  L.push("全体で " + F.independent_ips_total + " 件しかなく、どちらの割合も数件の上下で逆転します。");
  L.push("**「予測しない」と結論づけるのではなく、「この母集団では分からない」が正確です。**", "");
}
L.push("言えるのは次の 2 つです。", "");
L.push("- **フィード掲載は「誰かがこの IP を悪性と判断した」という情報であって、無価値ではありません**");
L.push("- **ただし「被害者が攻撃を観測した」とは別の情報です。**両者を足して");
L.push("  「" + C.with_reports_now + " IP が攻撃元として報告されている」と読むと、中身を取り違えます", "");
L.push("### カテゴリ 20（Exploited Host）は攻撃手法ではありません", "");
L.push("「この送信元自体が侵害されている可能性」を示す補助情報です。踏み台にされた");
L.push("正規ホストであれば、**送信元の持ち主も被害者**です。「この IP が攻撃してきた」とは違います。");
L.push("今回新しく出た **カテゴリ 21（Web App Attack）は攻撃手法そのもの**で、意味が違います。", "");
if (newIndep.length) {
  L.push("### 今回新しく出たフィード以外の通報", "");
  L.push(T(["観測時刻", "IP", "役割", "通報者", "カテゴリ", "本文"],
    newIndep.map((e) => [e.reported_at.slice(0, 19), code(e.ip_address), e.roles,
      "`" + e.reporter + "`", safe(e.category_names, 24),
      e.comment_empty === "true" ? "（空）" : code(safe(e.comment_excerpt, 40))])), "");
  L.push("**8 件が 10 秒間に収まっています。** 1 台の検知器が、同じ窓で来た 8 つの送信元を");
  L.push("まとめて出した形です。8 IP は両方の /25 に跨っており、連番ではありません。", "");
}

/* ---- 日付が 2 種類ある ---- */
L.push("## 4. 日付が 2 種類あります（今回判明。前回のレポートは誤っていました）", "");
L.push(T(["フィールド", "意味", "活動日として読めるか"], [
  [code("reportedAt"), "通報者が申告した**観測**時刻", "**読める**"],
  [code("lastReportedAt"), "AbuseIPDB が最後に通報を**受け取った**時刻（投稿）", "**読めない**"],
]), "");
L.push("実測した根拠:", "");
L.push("- フィードの本文 " + code("... Last observed <日付> UTC.") + " の日付が "
  + code("reportedAt") + " の日付と **" + feedReports + "/" + feedReports + " 件一致**。");
L.push("  つまり " + code("reportedAt") + " はフィード側の観測日で、AbuseIPDB の受領日ではない");
L.push("- " + code("lastReportedAt") + " は " + D.submitted_after_observed + "/" + D.ips_with_reports
  + " 件で観測時刻より**後ろ**にあり、前になった例は " + D.submitted_before_observed + " 件");
L.push("- さかのぼり日数は中央 " + D.backdate_days_median + " 日・最大 " + D.backdate_days_max + " 日");
L.push("  （" + code("totalReports") + " が 1 件で、通報と投稿が一対一に決まる " + D.backdate_measurable_ips + " IP で測定）");
L.push("- 未来日付の観測は " + D.observed_in_future + " 件");
L.push("");
L.push("### ここから出てくること", "");
L.push("1. **" + code("lastReportedAt") + " を活動日として図に載せてはいけません。**");
L.push("   投稿日なので、その日に攻撃があったことを意味しません");
L.push("2. **過去の日付の集計は確定しません。** 同じ IP を後日引き直すと、");
L.push("   **過去の日付の通報が増えます**");
L.push("");
L.push("実際に起きていました。" + PREV + " の取得では通報 0 件だった 14 IP が、今回は");
L.push("**「10-27 観測」の通報を持っています**。投稿日は 11-02〜11-04 で、");
L.push("6〜8 日さかのぼっていました。**" + PREV + " の取得は間違っていません。** 当時まだ投稿されていなかったのです。", "");
/** 観測日 → 投稿日の対。**通報 1 件の IP だけ**（一対一に決まるのはそこだけ）。
 *  前回見えなかった行が、投稿日が前回の取得より後ろのものと一致するかを示す */
const pairs = new Map();
for (const r of byIp.filter((x) => x.backdate_derivable === "true")) {
  const k = r.first_observed_at.slice(0, 10) + "|" + r.last_submitted_at.slice(0, 10);
  if (!pairs.has(k)) pairs.set(k, { ips: 0, seen: 0, days: [] });
  const v = pairs.get(k);
  v.ips++;
  v.days.push(Number(r.backdate_days));
  if (r.prev_available === "true" && Number(r.reports_prev) > 0) v.seen++;
}
L.push(T(["観測日", "投稿日", "IP", "さかのぼり", PREV + " に見えたか"],
  [...pairs].sort().map(([k, v]) => {
    const [o, s] = k.split("|");
    const ds = v.days.filter(Number.isFinite).sort((a, b) => a - b);
    const span = ds.length && ds[0].toFixed(2) !== ds[ds.length - 1].toFixed(2)
      ? ds[0].toFixed(2) + "〜" + ds[ds.length - 1].toFixed(2) : (ds[0] ?? 0).toFixed(2);
    return [o, s, String(v.ips), span + " 日",
      v.seen === v.ips ? "見えた" : v.seen === 0 ? "**見えなかった**" : v.seen + " / " + v.ips];
  })), "");
L.push("**投稿日が " + PREV + " より後ろの行だけが「見えなかった」になっています。**");
L.push("API の遅延ではなく、当時まだ投稿されていなかっただけです。", "");
L.push("### 前回のレポートの誤り", "");
L.push("前回は「定型文の " + code("Last observed") + " の日付は通報日と常に同一だったので、");
L.push("フィード側の観測時刻を別に教えてくれるものでもありませんでした」と書きました。");
L.push("**逆です。** " + code("reportedAt") + " 自体がフィードの観測日であり、投稿日は");
L.push(code("lastReportedAt") + " が別に持っていました。一致は「情報が無い」ではなく");
L.push("「" + code("reportedAt") + " の正体が分かる」手がかりでした。", "");

/* ---- 時系列 ---- */
L.push("## 5. 時系列（観測日ベース）", "");
L.push(T(["観測日", "通報", "IP", "通報者", "ARTEX", "sub2api", "前回に無かった", "フィード以外", "カテゴリ"],
  S.by_day.map((d) => [d.day, String(d.reports), String(d.distinct_ips),
    String(d.distinct_reporters), String(d.artex_ips), String(d.sub2api_ips),
    String(d.new_since_prev), String(d.independent_reports), safe(d.category_names, 30)])), "");
L.push("読み方:", "");
L.push("- **2026-09-30** — " + code("198.200.59.85") + " に最初の通報（NL、Port Scan + Hacking）。");
L.push("  **ARTEX が動いているホストより 2 週間以上早い。**クラスタの中心が先に通報された");
L.push("- **2026-10-14** — この日に ARTEX 250 件を調べた時点では**通報 0 件**");
L.push("  （出典 " + code("reports/artex-38-11/artex_38_11_report_ja.md") + "。当時の写しは");
L.push("  git 管理外で残っていないため、今回の集計では再確認していません）");
L.push("- **2026-10-17 / 10-20 / 10-24 / 10-27** — フィードが 11 → 1 → 32 → 14 件と段階的に登録");
L.push("- **2026-10-23** — " + code("198.200.59.85") + " に MY から通報（Hacking + Web App Attack）");
L.push("- **2026-10-31** — **ARTEX に初めてフィード以外の通報。**IN から 8 IP、Web App Attack");
L.push("");
L.push("**10-27 の行の「前回に無かった」が 14 件です。** 前回より古い日付の行が後から");
L.push("増えるのが、さかのぼり投稿の見え方です。", "");
L.push("**フィードの観測は 10-27 で止まっています**（投稿は 11-04 まで続いた）。");
L.push("フィード以外の観測も 10-31 が最後で、それ以降 " + code("reports[]")
  + " に新しい観測日はありません。", "");

/* ---- 役割ごとの素性 ---- */
L.push("## 6. 役割ごとの素性", "");
L.push("**クラスタは 1 つなので、「2 つのクラスタが繋がるか」という問いはもう立ちません。**");
L.push("全 255 IP が同じリチャージ URL (" + code("198.200.59.85") + ") を指しているという");
L.push("利用者の観測が、そのまま繋がりの根拠です。比べるのは役割ごとの違いです。", "");
L.push(T(["役割", "IP", "通報あり", "割合", "**フィード以外**", "最大スコア", "rDNS を持つ"],
  Object.entries(R).map(([role, v]) => [
    code(role), String(v.ips), String(v.with_reports_now),
    v.too_small_for_pct ? "**母数不足**" : v.reported_pct + "%",
    "**" + v.with_independent_report + "**", String(v.max_score_now),
    String(v.with_rdns) + " / " + v.ips])), "");
L.push("**母数が小さい役割の割合は読めません。** " + code("recharge_host") + " は 1 IP なので、");
L.push("「1 件中 1 件」という意味しかありません。", "");
const sub = byIp.filter((r) => r.ip_address.startsWith("198.200.59."));
L.push("### リチャージ URL のホストとその隣", "");
L.push(T(["IP", "役割", "rDNS", "通報", "通報者", "スコア", "最終観測", "最終投稿"], sub.map((r) => [
  code(r.ip_address), r.roles, code(r.hostnames || "—"), r.reports_now, r.reporters_now, r.score_now,
  r.last_observed_at.slice(0, 10) || "—", r.last_submitted_at.slice(0, 10) || "—"])), "");
L.push("- **" + code("198.200.59.85") + " がこのクラスタで最初に通報された IP です**（2026-09-30）。");
L.push("  ARTEX が動いているホストより 2 週間以上早く、**フィード以外の通報者が 2 人**付いています");
L.push("- **隣の " + code(".86〜.89") + " は一度も通報されていません。**");
L.push("  同じ /29 に並び、同じ命名規則の rDNS を持ち、同じ sub2api が動いているのに差が出ています。");
L.push("  **ただし 4 IP なので、差と呼べるだけの数ではありません**");
L.push("- スコアは前回 18 から " + (byIp.find((r) => r.ip_address === "198.200.59.85")?.score_now)
  + " に下がりました。通報は 3 件のままです。**時間が経つとスコアは減衰します**", "");
L.push("### rDNS の出方が役割で割れています", "");
L.push("5 件すべてが " + code("visiblooths.net") + " の下で、" + code("murves") + " "
  + code("moxley") + " " + code("dyres") + " " + code("sozel") + " " + code("olarm"));
L.push("という 5 文字の無意味な名前です。一方 **" + code("artex") + " の "
  + ART.ips + " 件はすべて rDNS が空**で、素性を出していません。", "");
L.push("AbuseIPDB の ISP の答えも割れています（" + code("artex") + " 側は Cogent、");
L.push(code("198.200.59.x") + " は PEG TECH）。これは食い違いではなく、ARIN RDAP に");
L.push("下位割当（SWIP）の登録が無いためです（10-14 に確認）。経路表ではどちらも");
L.push("AS54600 PEG TECH INC でしたが、**今回は再確認していません**（手元の索引に 3 帯とも 0 件）。", "");

/* ---- 通報された ARTEX の IP ---- */
const rep = byIp.filter((r) => r.roles.split(";").includes("artex") && Number(r.reports_now) > 0);
if (rep.length) {
  L.push("## 7. 通報が付いた " + code("artex") + " の " + rep.length + " IP", "");
  const ind = new Set(newIndep.map((e) => e.ip_address));
  for (const pfx of ["38.11.173", "38.11.221"]) {
    const h = rep.filter((r) => r.ip_address.startsWith(pfx + "."))
      .map((r) => Number(r.ip_address.split(".")[3])).sort((a, b) => a - b);
    const hi = h.filter((n) => ind.has(pfx + "." + n));
    L.push("- " + code(pfx + ".x") + " — " + h.length + " 件: " + h.join(", "));
    if (hi.length) L.push("  - うち**フィード以外の通報があるもの**: " + hi.join(", "));
  }
  L.push("");
  L.push("フィードぶんは全件が同じ通報者・同じカテゴリ・1 件ずつなので、IP ごとの差は");
  L.push("ありません。**番号の偏りはフィードの登録順の反映かもしれないので、**");
  L.push("攻撃者側の使い方を示すとは言えません。", "");
}

/* ---- 言えないこと ---- */
L.push("## 8. この調査で言えないこと", "");
L.push("- **ARTEX や sub2api が動いているかは確認していません。** 能動調査をしていないので、");
L.push("  待ち受けているサービスも見ていません。利用者から渡された前提のままです");
L.push("- **「攻撃に使われた時期」は確定しません。** さかのぼり投稿があるので、");
L.push("  今日の集計は明日増えます。" + code("reports[]") + " は観測の下限しか示しません");
L.push("- **フィード以外の通報者は " + indepAll.length + " 人しか居ません。** ARTEX については 1 人です。");
L.push("  「複数の被害者が独立に観測した」とまでは言えません");
L.push("- **" + code("IN-R04") + " がどういう通報者かは分かりません。** 全体での通報傾向を");
L.push("  調べるには " + code("reporterId") + " を蓄積する必要があり、方針で保存していません。");
L.push("  言えるのは**この 255 IP の中での選択性（3.1%）**だけです");
L.push("- **通報が無いことは無害の証明ではありません。** 誰も通報していないだけで、");
L.push("  立てたばかりの基盤や、通報しない被害者しか居ない基盤は同じ見た目になります");
L.push("- AbuseIPDB のカテゴリと観測時刻は**レポーターの自己申告**です");
L.push("- IP の所在地・ISP・AS は、運用者の国籍や所属を示しません");
L.push("- 母集団は**渡された 255 IP だけ**です。同じ AS の他の帯は見ていません");
L.push("- **" + code(".86〜.89") + " に通報が無いことに意味があるとは言えません。** 4 IP では");
L.push("  差と呼べる数になりません");
L.push("- 経路表（AS54600）の確認は 10-14 のもので、**今回再確認していません**。");
L.push("  ただしクラスタの繋がりは利用者の観測（同じリチャージ URL）が根拠なので、これには依りません");
L.push("");
L.push("## 9. 次に打てる手（提案）", "");
L.push("- ~~索引に登録して毎日追う~~ → **2026-11-06 に実装しました**（"
  + code("data/ioc/watch/") + "）。");
L.push("  " + code("IN-R04") + " の通報に気付くまで 6 日かかったので、翌日に出るようにしました");
L.push("- **" + code("lastReportedAt") + " の動きを毎日記録する。** 投稿が続いている間は");
L.push("  フィードがまだこの帯を追っています。" + code("reports[]") + " だけ見ていると止まったように見えます");
L.push("- **" + code("198.200.59.85") + " を重点的に見る。** クラスタの中心で、最初に通報され、");
L.push("  フィード以外の通報者が 2 人付いています。**ここが落ちるとクラスタ全体のリチャージが止まります**");
L.push("- **" + code("visiblooths.net") + " を証明書の記録（CT ログ）で追う。** 同じ命名規則の");
L.push("  兄弟ホストが他の帯にも居るなら、クラスタの広がりが分かります。");
L.push("  " + code(".85〜.89") + " の 5 件が同じ命名規則なので、他にも並んでいる可能性があります");
L.push("- 同じ AS54600 の他の帯を同じ手順で調べ、この 3 帯が特別かどうかを確かめる");
L.push("");
L.push("## 10. 残していないもの", "");
L.push("- " + code("reporterId") + " の値は保存していません（" + code("BR-R01") + " のような識別子に置き換え、");
L.push("  同じ人かどうかだけが分かるようにしています）");
L.push("- 通報コメントの原文は保存せず、無害化して短く切ったものと SHA-256 だけ残しています");
L.push("- API キーはコンソール・ログ・CSV・JSON・ソース・エラーにも出していません");
L.push("- 写し（" + code(".cache/") + "）は git 管理外です。**比較の基準は "
  + code("snapshots/") + " の CSV**で、写しが消えても残ります");
L.push("");
fs.writeFileSync(path.join(HERE, "artex_timeline_report_ja.md"), L.join("\n"));
console.log("→ artex_timeline_report_ja.md（通報 " + S.reports.total + " 件 / フィード以外 "
  + (S.reports.total - feedReports) + " 件 / 前回に無かった " + newEvents.length + " 件）");
