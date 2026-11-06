#!/usr/bin/env node
// 監視の現況と変化を日本語レポートにする。**観測と state/events だけを見る。**
//
//   node tools/ioc/watch-report.mjs [--watch data/ioc/watch] [--out data/ioc/reports]
//
// 「今日何を見ればいいか」が先頭に来るようにする。変化が無ければ「無い」と書く。
// **無かった日に何も出さないと、動いていないのか静かなのか分からなくなる。**
import fs from "node:fs";
import path from "node:path";
import { parseArgs, readJson, readJsonl } from "./lib/io.mjs";
import { REPO_ROOT } from "./lib/sources.mjs";
import { CATEGORIES } from "../../reports/global-jp-vuln/rules.mjs";
import { ipNum } from "./lib/watch.mjs";

const args = parseArgs(process.argv.slice(2));
const WATCH = path.resolve(REPO_ROOT, args.watch || "data/ioc/watch");
const OUT = path.resolve(REPO_ROOT, args.out || "data/ioc/reports");

const M = readJson(path.join(WATCH, "watch-meta.json"));
const wl = readJson(path.join(WATCH, "watchlist.json")) || {};
if (!M) { console.error("watch-meta.json がありません。先に track-watch.mjs を実行してください。"); process.exit(1); }
const state = readJsonl(path.join(WATCH, "state.jsonl"));
const events = readJsonl(path.join(WATCH, "events.jsonl"));
const shapes = readJsonl(path.join(WATCH, "shapes.jsonl"));
const day = M.day_range[1];

const bt = String.fromCharCode(96);
const code = (s) => bt + s + bt;
const safe = (s, n = 60) => String(s || "").replace(/\|/g, "／").replace(/\s+/g, " ").slice(0, n);
const T = (head, body) => [
  "| " + head.join(" | ") + " |",
  "| " + head.map(() => "---").join(" | ") + " |",
  ...body.map((r) => "| " + r.join(" | ") + " |"),
].join("\n");

/** 変化の種類ごとの説明。**名前だけでは何が起きたか分からない** */
const KIND = {
  first_independent_report: "**初めてフィード以外の通報が付いた**（いちばん重い）",
  already_independent_at_first_sight: "監視を始めた時点で既にフィード以外の通報があった",
  first_report: "初めて通報が付いた",
  already_reported_at_first_sight: "監視を始めた時点で既に通報があった",
  reporters_up: "通報者の数が増えた",
  new_category: "これまで無かったカテゴリが付いた",
  jp_report_up: "**日本からの通報が増えた**",
  score_up: "スコアが上がった（下がりは出さない）",
  backdated_report: "過去の日付の通報が後から増えた（さかのぼり投稿）",
  resubmitted: "観測は増えていないが投稿時刻だけ進んだ",
};

const today = events.filter((e) => e.day === day);
const L = [];
L.push("# 監視クラスタの現況 — " + day, "");
L.push("> **この文書は Claude（AI）が自動生成したものです。人の確認を前提としてください。**", "");
L.push("**対象 IP への接続・走査・認証試行は一切行っていません。** AbuseIPDB の公開情報だけを見ています。", "");

/* ---- 今日の変化 ---- */
L.push("## 今日の変化", "");
if (!today.length) {
  L.push("**変化はありません。** 監視は動いており、"
    + M.ips + " IP ぶんの観測を取っています（" + day + "）。", "");
} else {
  const byKind = new Map();
  for (const e of today) {
    if (!byKind.has(e.kind)) byKind.set(e.kind, []);
    byKind.get(e.kind).push(e);
  }
  // 重い順に並べる
  const order = Object.keys(KIND);
  const sorted = [...byKind].sort((a, b) => order.indexOf(a[0]) - order.indexOf(b[0]));
  L.push(T(["変化", "件数", "意味"], sorted.map(([k, list]) =>
    [code(k), String(list.length), KIND[k] || "—"])), "");
  for (const [k, list] of sorted) {
    if (k === "already_reported_at_first_sight" || k === "already_independent_at_first_sight") continue;
    L.push("### " + code(k) + " — " + list.length + " 件", "");
    L.push(KIND[k] || "", "");
    const head = ["IP", "クラスタ", "前回の観測", "内容"];
    L.push(T(head, list.sort((a, b) => ipNum(a.ip) - ipNum(b.ip)).slice(0, 60).map((e) => {
      const rest = Object.entries(e).filter(([kk]) =>
        !["day", "ip", "cluster", "kind", "since"].includes(kk))
        .map(([kk, v]) => kk + "=" + safe(v, 34)).join(" / ");
      return [code(e.ip), e.cluster, e.since || "—", rest || "—"];
    })), "");
    if (list.length > 60) L.push("（他 " + (list.length - 60) + " 件は " + code("events.jsonl") + " に）", "");
  }
}

/* ---- クラスタの現況 ---- */
L.push("## クラスタの現況", "");
L.push(T(["クラスタ", "IP", "通報あり", "**フィード以外の通報あり**", "日本から", "最大スコア", "通報の総数"],
  Object.entries(M.per_cluster).map(([c, v]) => [
    "**" + c + "**", String(v.ips), String(v.with_reports),
    "**" + v.with_independent_report + "**", String(v.with_jp_report),
    String(v.max_score), String(v.total_reports)])), "");
for (const cl of wl.clusters || []) {
  L.push("- **" + cl.name + "** — " + safe(cl.note, 90)
    + (cl.ranges ? "（" + cl.ranges.map(code).join(" ") + "）" : "")
    + (cl.since ? " / 追跡開始 " + cl.since : ""));
}
L.push("");

/* ---- フィード以外の通報が付いている IP ---- */
const indep = state.filter((r) => r.independent_reports > 0)
  .sort((a, b) => ipNum(a.ip) - ipNum(b.ip));
L.push("## フィード以外の通報が付いている IP（" + indep.length + " 件）", "");
L.push("**ここが「被害者が攻撃を観測した」に最も近い行です。** フィードの一括登録は");
L.push("「誰かが悪性と判断した」情報で、別種のものです。", "");
if (indep.length) {
  L.push(T(["IP", "クラスタ", "初めて付いた日", "通報", "通報者", "国", "カテゴリ", "スコア"],
    indep.slice(0, 80).map((r) => [
      code(r.ip), r.cluster, r.first_independent_report_day || "監視開始前",
      String(r.independent_reports) + " / " + r.reports, String(r.reporters),
      r.independent_countries || "—", safe(r.category_names, 30), String(r.score)])), "");
} else {
  L.push("**ありません。** 通報があるのはフィードの一括登録だけです。", "");
}

/* ---- 本文の形 ---- */
L.push("## 本文の形（一括登録の印）", "");
L.push("同じ形が多数の IP に付いていれば、1 件ずつ見て出したものではありません。");
L.push("**ただし件数だけでは決めません。** さかのぼって投稿しているかを併せて見ます。");
L.push("フィードは手元の台帳をまとめて流すので観測日をさかのぼり、被害者側の検知器は");
L.push("見たその場で出すのでずれが 0 になります。", "");
L.push(T(["一括登録の印", "宣言済み", "IP", "さかのぼり最大", "見てすぐ出す", "形"],
  shapes.slice(0, 20).map((s) => [
    s.bulk ? "**はい**" : "いいえ", s.declared ? "はい" : "—",
    String(s.distinct_ips),
    s.backdate_days_max === null ? "測れず" : s.backdate_days_max + " 日",
    s.backdate_measurements ? (s.files_immediately ? "**はい**" : "いいえ") : "測れず",
    code(safe(s.shape, 56))])), "");
L.push("**ずれが 0 なら、IP の数が閾値を超えても一括登録とは呼びません。**");
L.push("ARTEX では被害者側の通報が 8 IP で、閾値 " + (wl.bulk_min_ips || 10) + " を");
L.push("ぎりぎり下回っただけでした。数だけで切ると取り違えます。", "");

/* ---- 観測の抜け ---- */
L.push("## 観測の記録", "");
L.push(T(["日", "観測できた IP"], M.observed_days.map((d) => [d.day, String(d.ips)])), "");
if (M.not_observed_last_fetch) {
  L.push("**直近の取得で " + M.not_observed_last_fetch + " IP が引けていません。**");
  L.push("引けなかった IP は観測に入れていないので、**「通報なし」ではなく「分からない」**です。", "");
}
L.push("連日とは限りません。変化の行の「前回の観測」が、その変化をどれだけの");
L.push("間隔で見たかを示します。", "");

/* ---- 言えないこと ---- */
L.push("## この監視で言えないこと", "");
L.push("- **対象のサービスが動いているかは確認していません。** 能動調査をしていません");
L.push("- **通報が無いことは無害の証明ではありません。** 誰も通報していないだけです");
L.push("- **" + code("reportedAt") + " は通報者が申告した観測時刻**で、さかのぼれます。");
L.push("  実測で中央 1.04 日・最大 7.32 日。**今日の集計は明日増えます**");
L.push("- **" + code("lastReportedAt") + " は投稿時刻**で、活動日ではありません");
L.push("- AbuseIPDB のカテゴリと観測時刻は**レポーターの自己申告**です");
L.push("- IP の所在地・ISP・AS は、運用者の国籍や所属を示しません");
L.push("- **通報者がどういう人かは分かりません。** " + code("reporterId") + " を保存しない方針なので、");
L.push("  この監視対象の中での選択性しか見ていません");
L.push("");
L.push("## 残していないもの", "");
L.push("- " + code("reporterId") + " は保存していません。「同じ通報者か」は通報者の数の増減で見ています");
L.push("- 通報コメントの原文は保存せず、**日付と数字を畳んだ「形」だけ**を残しています");
L.push("- API キーはコンソール・ログ・観測・ソース・エラーにも出していません");
L.push("- 写し（" + code("data/ioc/.cache/watch-abuseipdb/") + "）は git 管理外です。");
L.push("  **残るのは " + code("observations/") + " で、state と events はそこから毎回作り直します**");
L.push("");

fs.mkdirSync(OUT, { recursive: true });
const out = path.join(OUT, `watch-${day}.md`);
fs.writeFileSync(out, L.join("\n"));
// 最新版も置く。日付を知らなくても読めるように
fs.writeFileSync(path.join(WATCH, "watch-report-ja.md"), L.join("\n"));
console.log(`→ ${path.relative(REPO_ROOT, out)}（変化 ${today.length} 件`
  + ` / フィード以外の通報がある IP ${indep.length} 件）`);
