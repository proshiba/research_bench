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

const A = S.per_cluster.ARTEX, U = S.per_cluster.sub2api;
const D = S.date_field_semantics;
const PREV = S.prev_snapshot_date;
const feedReports = S.bulk_feeds.reduce((s, f) => s + f.reports, 0);
const indepAll = S.independent_reporters;
const newEvents = events.filter((e) => e.new_since_prev === "true");
const newIndep = newEvents.filter((e) => !S.bulk_feeds.some((f) => f.reporter === e.reporter));

const L = [];
L.push("# ARTEX / sub2api クラスタ — AbuseIPDB 上の通報の時系列", "");
L.push("> **この文書は Claude（AI）が自動生成したものです。人の確認を前提としてください。**", "");
L.push("取得 " + String(S.collected_at_utc).slice(0, 16) + " UTC"
  + (PREV ? " ／ 前回 " + PREV + " との差を主に見ています。" : "") , "");
L.push(T(["クラスタ", "対象", "利用者の観測"], S.clusters.map((c) => [
  "**" + c.name + "**",
  c.ranges ? c.ranges.map(code).join(" と ") + " の " + code(".1〜.125")
    : c.explicit.map(code).join(" "),
  safe(c.note, 70)])), "");
L.push("**対象 IP への接続・走査・認証試行は一切行っていません。** AbuseIPDB の公開情報と");
L.push("手元の索引だけを見ています。この集計自体は API も呼んでいません。", "");

/* ---- 前回からの差 ---- */
L.push("## 0. 前回（" + PREV + "）から変わったこと", "");
L.push(T(["", PREV, S.collected_at_utc.slice(0, 10), "差"], [
  ["ARTEX：通報がある IP", String(A.with_reports_prev), String(A.with_reports_now),
    "**+" + (A.with_reports_now - A.with_reports_prev) + "**"],
  ["ARTEX：フィード以外の通報がある IP", "**0**", "**" + A.with_independent_report + "**",
    "**+" + A.with_independent_report + "**"],
  ["sub2api：通報がある IP", String(U.with_reports_prev), String(U.with_reports_now),
    String(U.with_reports_now - U.with_reports_prev)],
  ["日本からの通報", "0", String(A.jp_reports + U.jp_reports), "0"],
]), "");
L.push("**一番大きい変化は 2 行目です。** 前回は ARTEX 250 IP の通報が**全部フィードの");
L.push("一括登録**で、被害者側の観測が 1 件もありませんでした。今回は " + A.with_independent_report + " IP に付いています。", "");
L.push("前回に無かった通報は " + newEvents.length + " 件で、内訳は**フィード "
  + (newEvents.length - newIndep.length) + " 件 / フィード以外 " + newIndep.length + " 件**です。", "");

/* ---- 結論 ---- */
L.push("## 1. 結論", "");
L.push(T(["問い", "答え"], [
  ["ARTEX は「複数の観測者が攻撃を見た」状態になったか",
    "**部分的にそう言えるようになった。**" + A.with_independent_report + " / " + A.ips
    + " IP にフィード以外の通報。ただし通報者は 1 人"],
  ["それは何として通報されたか",
    "**Web App Attack（カテゴリ 21）**。前回まで ARTEX に付いていたのは Exploited Host（20）だけだった"],
  ["その通報はフィードの転載ではないと言えるか",
    "**言える。**観測時刻と投稿時刻のずれが 0 秒で、対象は 255 IP の 3.1% だけ（フィードは最大 7.32 日ずれ・22.7%）"],
  ["攻撃に使われた時期は特定できたか",
    "**観測日ベースでは " + S.reports.first_observed.slice(0, 10) + " 〜 " + S.reports.last_observed.slice(0, 10)
    + "。**ただしさかのぼり投稿があるので確定しない（3 節）"],
  ["sub2api は", "**5 IP のうち " + U.with_reports_now + " 件だけ**（" + code("198.200.59.85")
    + "）。前回から変化なし。通報 3 件 / 通報者 " + U.distinct_reporters + " 人"],
  ["日本からの通報は", "**両クラスタとも 0 件**"],
]), "");

/* ---- フィードと被害者側の区別 ---- */
L.push("## 2. 「複数 IP が報告されている」の中身", "");
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
L.push("  「" + A.with_reports_now + " IP が攻撃元として報告されている」と読むと、中身を取り違えます", "");
L.push("### カテゴリ 20（Exploited Host）は攻撃手法ではありません", "");
L.push("「この送信元自体が侵害されている可能性」を示す補助情報です。踏み台にされた");
L.push("正規ホストであれば、**送信元の持ち主も被害者**です。「この IP が攻撃してきた」とは違います。");
L.push("今回新しく出た **カテゴリ 21（Web App Attack）は攻撃手法そのもの**で、意味が違います。", "");
if (newIndep.length) {
  L.push("### 今回新しく出たフィード以外の通報", "");
  L.push(T(["観測時刻", "IP", "クラスタ", "通報者", "カテゴリ", "本文"],
    newIndep.map((e) => [e.reported_at.slice(0, 19), code(e.ip_address), e.cluster,
      "`" + e.reporter + "`", safe(e.category_names, 24),
      e.comment_empty === "true" ? "（空）" : code(safe(e.comment_excerpt, 40))])), "");
  L.push("**8 件が 10 秒間に収まっています。** 1 台の検知器が、同じ窓で来た 8 つの送信元を");
  L.push("まとめて出した形です。8 IP は両方の /25 に跨っており、連番ではありません。", "");
}

/* ---- 日付が 2 種類ある ---- */
L.push("## 3. 日付が 2 種類あります（今回判明。前回のレポートは誤っていました）", "");
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
L.push("## 4. 時系列（観測日ベース）", "");
L.push(T(["観測日", "通報", "IP", "通報者", "ARTEX", "sub2api", "前回に無かった", "フィード以外", "カテゴリ"],
  S.by_day.map((d) => [d.day, String(d.reports), String(d.distinct_ips),
    String(d.distinct_reporters), String(d.artex_ips), String(d.sub2api_ips),
    String(d.new_since_prev), String(d.independent_reports), safe(d.category_names, 30)])), "");
L.push("読み方:", "");
L.push("- **2026-09-30** — " + code("198.200.59.85") + " に最初の通報（NL、Port Scan + Hacking）。");
L.push("  **ARTEX クラスタより 2 週間以上早い**");
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

/* ---- クラスタの素性 ---- */
L.push("## 5. 2 つのクラスタの素性", "");
L.push(T(["観点", "ARTEX（" + A.ips + " IP）", "sub2api（" + U.ips + " IP）"], [
  ["AbuseIPDB の ISP", Object.keys(A.isp).map((s) => safe(s, 30)).join(" / "),
    Object.keys(U.isp).map((s) => safe(s, 30)).join(" / ")],
  ["rDNS を持つ", String(A.with_rdns) + " / " + A.ips, "**" + U.with_rdns + " / " + U.ips + "**"],
  ["rDNS の登録ドメイン", Object.keys(A.rdns_domains).filter(Boolean).join(" ") || "—",
    Object.keys(U.rdns_domains).filter(Boolean).map(code).join(" ")],
  ["脅威情報の索引に既出", String(A.in_threat_index), String(U.in_threat_index)],
]), "");
L.push("**AbuseIPDB だけでは 2 つのクラスタは繋がりません。** ISP の答えが Cogent と PEG TECH で");
L.push("割れています。繋がりの根拠は 10-14 に確認した経路表（どちらも AS54600 PEG TECH INC）で、");
L.push("**今回は再確認していません**（手元の索引に 3 帯とも 0 件のため）。", "");
L.push("ARTEX 側の ISP が Cogent と出るのは食い違いではなく、ARIN RDAP に下位割当（SWIP）の");
L.push("登録が無いためです（10-14 に確認）。", "");
const sub = byIp.filter((r) => r.cluster === "sub2api");
L.push("### sub2api の rDNS は機械が付けた形です（今回も同じ）", "");
L.push(T(["IP", "rDNS", "通報", "スコア", "最終観測", "最終投稿"], sub.map((r) => [
  code(r.ip_address), code(r.hostnames || "—"), r.reports_now, r.score_now,
  r.last_observed_at.slice(0, 10) || "—", r.last_submitted_at.slice(0, 10) || "—"])), "");
L.push("5 件すべてが " + code("visiblooths.net") + " の下で、5 文字の無意味な名前です。");
L.push("**リチャージ URL の共有とは別の筋で、同じ持ち主であることを裏づけます。**", "");
L.push("一方 **ARTEX 側は " + A.ips + " 件すべて rDNS が空**で、素性を出していません。", "");
L.push(code("198.200.59.85") + " のスコアは前回 18 から " + (byIp.find((r) => r.ip_address === "198.200.59.85")?.score_now)
  + " に下がりました。通報は 3 件のままです。**時間が経つとスコアは減衰します。**", "");

/* ---- 通報された ARTEX の IP ---- */
const rep = byIp.filter((r) => r.cluster === "ARTEX" && Number(r.reports_now) > 0);
if (rep.length) {
  L.push("## 6. 通報が付いた ARTEX の " + rep.length + " IP", "");
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
L.push("## 7. この調査で言えないこと", "");
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
L.push("- 2 クラスタを繋ぐ経路の根拠は 10-14 のもので、**今回再確認していません**");
L.push("");
L.push("## 8. 次に打てる手（提案）", "");
L.push("- **索引に登録して毎日追う。** 両クラスタとも索引に 0 件なので、今は新しい通報が");
L.push("  付いても気付けません。今回 " + code("IN-R04") + " の通報に気付くまで 6 日かかりました");
L.push("- **" + code("lastReportedAt") + " の動きを毎日記録する。** 投稿が続いている間は");
L.push("  フィードがまだこの帯を追っています。" + code("reports[]") + " だけ見ていると止まったように見えます");
L.push("- **" + code("198.200.59.85") + " だけを重点監視する。** 利用者が特定したリチャージ URL の");
L.push("  ホストで、フィード以外の通報が 2 人分付いている唯一の IP です");
L.push("- **" + code("visiblooths.net") + " を証明書の記録（CT ログ）で追う。** 同じ命名規則の");
L.push("  兄弟ホストが他の帯にも居るなら、クラスタの広がりが分かります");
L.push("- 同じ AS54600 の他の帯を同じ手順で調べ、この 3 帯が特別かどうかを確かめる");
L.push("");
L.push("## 9. 残していないもの", "");
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
