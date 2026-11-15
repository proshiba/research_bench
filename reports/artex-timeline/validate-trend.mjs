#!/usr/bin/env node
// `trend.mjs` の成果物を検算する。**写しだけを読む。API は呼ばない。**
//
//   node reports/artex-timeline/validate-trend.mjs
//
// ## 方針
//
// **昨日の世界を固定値で書かない。** これまで検査を 4 回壊した原因は全部これだった
// （「artex は 250 件」「rDNS はすべて空」など、翌日の事実で落ちる書き方）。
// ここでは**内部の整合**と**出してはいけないもの**だけを見る。
// 数が変わること自体は異常ではない。
//
// 窓からの脱落（365 日を過ぎた通報が消える）は**正当に起こりうる**ので、
// 減少は WARN にとどめて FAIL にしない。
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "../..");
const HTML = path.join(HERE, "artex_timeline_trend.html");
const GEN = path.join(HERE, "trend.mjs");

let fail = 0, warn = 0, ok = 0;
const check = (cond, msg, detail = "") => {
  if (cond) { ok++; console.log(`  ok   ${msg}`); }
  else { fail++; console.log(`  FAIL ${msg}${detail ? `\n       ${detail}` : ""}`); }
};
const caution = (cond, msg, detail = "") => {
  if (cond) { ok++; console.log(`  ok   ${msg}`); }
  else { warn++; console.log(`  WARN ${msg}${detail ? `\n       ${detail}` : ""}`); }
};

const J = JSON.parse(execFileSync("node", [GEN, "--json"], { encoding: "utf8", maxBuffer: 64e6 }));
const html = fs.readFileSync(HTML, "utf8");

console.log(`検算: ${path.relative(ROOT, HTML)}（基準日 ${J.anchor}）\n`);

/* ---------------- 1. 内部の整合 ---------------- */
console.log("1. 数が互いに合っているか");

const last = J.view[J.view.length - 1];
const actTotal = J.activity.reduce((a, d) => a + d.feed + d.indep, 0);
check(actTotal === last.reports,
  `活動の合計 = 最新取得の通報数（${actTotal} = ${last.reports}）`);
check(J.activity.every((d) => d.feed + d.indep > 0), "通報 0 件の観測日が混ざっていない");
check(J.view.every((v) => v.feed + v.indep === v.reports), "各取得日で フィード + それ以外 = 通報数");
check(J.view.every((v) => v.reported_ips <= v.ips), "通報のある IP が母数を超えていない");
check(J.view.every((v) => v.ips === J.ips), `どの取得日も母数が同じ（${J.ips} IP）`);

const matrixFinal = J.matrix.rows.reduce((a, r) => a + r.final, 0);
check(matrixFinal === last.reports,
  `さかのぼり行列の確定列 = 最新取得の通報数（${matrixFinal} = ${last.reports}）`);
check(J.matrix.rows.every((r) => r.counts.length === J.matrix.fetch_days.length),
  "行列の各行が取得日の数だけ列を持つ");
check(J.matrix.rows.every((r) => r.counts[r.counts.length - 1] === r.final),
  "行列の最後の列が確定列と一致する");
check(J.matrix.fetch_days.length === J.view.length, "行列の列数 = 取得日の数");

// 理由。**1 件が複数の理由を持つので合計は通報数を超えてよい**
const reasonSum = J.reasons.all.rows.reduce((a, r) => a + r.value, 0);
check(reasonSum >= J.reasons.all.reports,
  `理由の合計 ≥ 通報数（${reasonSum} ≥ ${J.reasons.all.reports}）`
  + "：1 件が複数の理由を持つため");
check(J.reason_by_source.every((r) => {
  const m = J.reasons.all.rows.find((x) => x.cat === r.cat);
  return m && m.value === r.feed + r.indep;
}), "理由ごとの フィード + それ以外 = その理由の件数");
const srcFeed = J.reason_by_source.reduce((a, r) => a + r.feed, 0);
const srcIndep = J.reason_by_source.reduce((a, r) => a + r.indep, 0);
check(srcFeed + srcIndep === reasonSum, `出所別の合計が理由の合計と一致（${srcFeed} + ${srcIndep}）`);

check(J.reasons.w14.reports <= J.reasons.all.reports, "直近 14 日の件数 ≤ 全体");
check(J.reasons.w7.reports <= J.reasons.w14.reports, "直近 7 日の件数 ≤ 直近 14 日");

const repReports = J.reporters.reduce((a, r) => a + r.reports, 0);
check(repReports === last.reports, `通報者の内訳の合計 = 通報数（${repReports}）`);

// 遅れ。**通報が 1 件の IP でしか測れない**
check(J.lag.measurable === J.lag.feed.n + J.lag.indep.n, "遅れの母数 = フィード + それ以外");
check(J.lag.measurable <= J.lag.reported_ips,
  `遅れを測れた IP ≤ 通報のある IP（${J.lag.measurable} ≤ ${J.lag.reported_ips}）`);
check(J.lag.bins.reduce((a, b) => a + b.feed, 0) === J.lag.feed.n, "遅れの階級（フィード）の合計が母数と一致");
check(J.lag.bins.reduce((a, b) => a + b.indep, 0) === J.lag.indep.n, "遅れの階級（それ以外）の合計が母数と一致");

/* ---------------- 2. 増減の向き ---------------- */
console.log("\n2. 推移の向き（減少は窓からの脱落で起こりうるので WARN）");
const drops = [];
for (let i = 1; i < J.view.length; i++) {
  if (J.view[i].reports < J.view[i - 1].reports) {
    drops.push(`${J.view[i - 1].fetch} ${J.view[i - 1].reports} → ${J.view[i].fetch} ${J.view[i].reports}`);
  }
}
caution(drops.length === 0, "取得日をまたいで通報数が減っていない",
  drops.length ? `減少: ${drops.join(" / ")}（365 日の窓から外れた可能性。確認すること）` : "");
caution(J.view.every((v, i) => i === 0 || v.latest_obs >= J.view[i - 1].latest_obs),
  "最後の観測日が後退していない");

/* ---------------- 3. 出してはいけないもの ---------------- */
console.log("\n3. 出してはいけないもの");
// **API キーは成果物にもソースにも出さない。**値そのものは読まない（存在だけ見る）
const SECRET_SHAPES = [
  [/\b[0-9a-f]{64}\b/g, "64 桁の 16 進（AbuseIPDB のキーの形）"],
  [/VT_API_KEY|ABUSEIPDB_KEY|ABUSE_KEY/g, "キーの環境変数名"],
  [/reporterId["'\s:=]+\d/g, "reporterId の値"],
];
for (const [re, name] of SECRET_SHAPES) {
  const hits = html.match(re) || [];
  check(hits.length === 0, `成果物に ${name} が出ていない`,
    hits.length ? `${hits.length} 件（値は出さない）` : "");
}
const src = fs.readFileSync(GEN, "utf8");
for (const [re, name] of SECRET_SHAPES) {
  check(!(src.match(re) || []).length, `生成器に ${name} が書かれていない`);
}
// 通報コメントの原文を貼っていないこと。`shape` は畳んだ形で、本文ではない
check(!/data-tip="[^"]*Last observed 20/.test(html), "コメント原文を吹き出しに入れていない");

/* ---------------- 4. 言い過ぎていないか ---------------- */
console.log("\n4. 言い過ぎていないか");
check(/対象 IP への接続・走査・認証試行は一切していない/.test(html), "能動調査をしていないことを書いている");
check(/Claude（AI）が自動生成/.test(html), "AI 生成であることを書いている");
check(/日本向けではない」という意味ではない/.test(html), "日本からの通報 0 件の読み方を限定している");
check(/利用者の観測/.test(html) && /こちらが確認したものではない/.test(html),
  "ARTEX / sub2api の起動が利用者の観測であることを書いている");
check(/この窓はまだ埋まっていない/.test(html), "直近の窓が確定していないと書いている");
check(/攻撃が増えたのではなく/.test(html), "視界の増加を活動の増加と読まないよう書いている");
// **フィードの一括登録を観測と呼んでいないこと**
check(/「誰かが悪性と判断した」情報で、<strong>観測ではない/.test(html)
  || /「誰かが悪性と判断した」/.test(html), "フィードの一括登録を観測と呼んでいない");

// 最も多い理由が 1 つの出所に偏っているなら、それを本文で断っているか
const top = J.reasons.all.rows[0];
const topSrc = J.reason_by_source.find((r) => r.cat === top.cat);
if (topSrc && topSrc.feed > 0 && topSrc.indep === 0) {
  check(new RegExp(`${top.value} 件`).test(html) && /フィードの一括登録/.test(html),
    `最も多い理由（${top.label}）が全件フィード由来であることを書いている`);
} else {
  console.log(`  --   最も多い理由（${top.label}）は単一出所ではないので、この検査は当てはまらない`);
}

/* ---------------- 5. 同じ写しなら同じバイト ---------------- */
console.log("\n5. 決定性");
const before = fs.readFileSync(HTML);
execFileSync("node", [GEN], { stdio: "ignore" });
check(Buffer.compare(before, fs.readFileSync(HTML)) === 0, "2 回作って同じバイトになる");
const a = execFileSync("node", [GEN, "--json"], { encoding: "utf8", maxBuffer: 64e6 });
const b = execFileSync("node", [GEN, "--json"], { encoding: "utf8", maxBuffer: 64e6 });
check(a === b, "--json も 2 回で同じ");
check(!/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z/.test(html),
  "成果物に実行時刻が埋まっていない（日付は写し由来のものだけ）");

/* ---------------- 6. 色 ---------------- */
console.log("\n6. 色（dataviz の検証器に通した値から動いていないか）");
const PALETTE = {
  light: ["#2a78d6", "#eb6834", "#1baf7a", "#eda100"],
  dark: ["#3987e5", "#d95926", "#199e70", "#c98500"],
};
for (const [mode, hexes] of Object.entries(PALETTE)) {
  check(hexes.every((h) => html.includes(h)), `${mode} の 4 色がそのまま入っている`);
}
check(/@media \(prefers-color-scheme: dark\)/.test(html) && /\[data-theme="dark"\]/.test(html),
  "暗色を OS 設定と切り替えの両方で定義している");
check(/<details class="tbl">/.test(html), "どの図にも数字の表が付いている（色だけに頼らせない）");

console.log(`\n${fail ? "FAILED" : "PASS"}  ok ${ok} / warn ${warn} / fail ${fail}`);
process.exit(fail ? 1 : 0);
