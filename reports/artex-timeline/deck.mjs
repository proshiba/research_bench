#!/usr/bin/env node
// クラスタ全体の統計を pptx にする。**成果物しか読まない。API も写しも見ない。**
//
//   node reports/artex-timeline/deck.mjs [--out artex_timeline_deck.pptx]
//
// 数字は `artex_timeline_summary.json` と CSV から読む。**ここで数え直さない。**
// 数え直すと、レポートと食い違ったときにどちらが正しいか分からなくなる。
// データが更新されたら build.mjs → report.mjs → deck.mjs の順で作り直す。
//
// ## この成果物だけはバイト一致しない
//
// 他の成果物は同じ写しから同じバイト列が出るが、**pptx は出ない**。
// 2 回生成して中を比べると、違うのは次の 2 つだけだった:
//
//   docProps/core.xml の dcterms:created / modified（生成時刻）
//   ppt/presentation.xml の p14:section の id（毎回ランダムな GUID）
//
// スライドの中身・グラフのデータ・文言はすべて一致する。pptxgenjs 側の作りで、
// こちらからは止められない。**中身は再現する。ファイルのハッシュは再現しない。**
// 検査でハッシュを比べないこと。比べるならパートごとの中身を見る。
//
// ## PowerPoint でグラフが出ないことがある（2026-11-06 に判明）
//
// **利用者の環境で、グラフがほとんど描かれなかった。**
// こちらの QA は LibreOffice での描画と XSD 検査しか見ておらず、
// そこでは正しく描けていたので捕まえられなかった。pptxgenjs のネイティブ
// グラフは PowerPoint が受け付けても中身を描かないことがある。
//
// **グラフを確実に見せたいときは `page.mjs`（HTML）を使うこと。**
// あちらは自前のインライン SVG で、描画そのものをこちらで確認できる。
//
// ## 色の決め方
//
// グラフの系列色は 2 色だけ使う: **フィードの一括登録**と**被害者側の観測**。
// この 2 つを分けることがこの調査の要点なので、色もそこに使う。
//
//   被害者側 #B3202C / フィード #2E6B9E
//
// dataviz の検証器（scripts/validate_palette.js）に通してある:
// 明度帯・彩度の下限・CVD 分離（最悪 ΔE 18.5 deutan）・通常視の下限（ΔE 26.5）・
// 地に対するコントラスト、すべて PASS。
//
// 「通報なし」は系列ではなく**軌道（track）**として薄い灰で描く。灰を系列に
// すると彩度の下限を割り、色覚の分離も測れなくなる。
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

/**
 * `pptxgenjs` と `apply_theme.js` の在り処。
 *
 * この容器では `pptxgenjs` がグローバル（`npm root -g`）にしか無く、リポジトリに
 * `package.json` を置いていないので素の `require` では見つからない。
 * **見つからなければ理由を言って止まる。**黙って体裁なしの pptx を吐くより良い。
 *
 *   npm install -g pptxgenjs
 */
const require = createRequire(import.meta.url);
const tryRequire = (names) => {
  const tried = [];
  for (const n of names) {
    try { return require(n); } catch (e) { tried.push(`${n}: ${String(e.code || e.message).slice(0, 40)}`); }
  }
  return { __failed: tried };
};
const globalRoot = (() => {
  try {
    return require("node:child_process").execSync("npm root -g", { encoding: "utf8" }).trim();
  } catch { return ""; }
})();
const PptxGenJS = tryRequire([
  "pptxgenjs",
  ...(globalRoot ? [path.join(globalRoot, "pptxgenjs")] : []),
  "/opt/node22/lib/node_modules/pptxgenjs",
]);
if (PptxGenJS.__failed) {
  console.error("pptxgenjs が見つかりません。`npm install -g pptxgenjs` を実行してください。");
  console.error("  試した場所: " + PptxGenJS.__failed.join(" / "));
  process.exit(2);
}
/** 配色（theme）を pptx に書き込む。pptxgenjs 自身はテーマ色を書けない */
const themeMod = tryRequire([
  ...fs.existsSync("/root/.claude/skills/synced")
    ? fs.readdirSync("/root/.claude/skills/synced")
      .map((d) => `/root/.claude/skills/synced/${d}/pptx/scripts/apply_theme.js`)
      .filter((p) => fs.existsSync(p))
    : [],
]);
if (themeMod.__failed) {
  console.error("apply_theme.js が見つかりません。配色が Office の既定色になるので止めます。");
  process.exit(2);
}
const { applyTheme } = themeMod;

const HERE = path.dirname(fileURLToPath(import.meta.url));
const argv = process.argv.slice(2);
const outArg = argv.indexOf("--out");
const OUT = path.join(HERE, outArg >= 0 ? argv[outArg + 1] : "artex_timeline_deck.pptx");

/* ---------------- 成果物を読む ---------------- */

const S = JSON.parse(fs.readFileSync(path.join(HERE, "artex_timeline_summary.json"), "utf8"));
const K = S.cluster_stats;
const CP = K.category_partition_by_ip;

function parseCsv(text) {
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
  const h = rows.shift().map((x) => x.replace(/^﻿/, ""));
  return rows.filter((r) => r.length > 1).map((r) => Object.fromEntries(h.map((k, i) => [k, r[i] ?? ""])));
}
const byIp = parseCsv(fs.readFileSync(path.join(HERE, "artex_timeline_by_ip.csv"), "utf8"));
const events = parseCsv(fs.readFileSync(path.join(HERE, "artex_timeline_events.csv"), "utf8"));
const feedNames = new Set(S.bulk_feeds.map((f) => f.reporter));
const isFeed = (e) => feedNames.has(e.reporter);

/** さかのぼり日数の区分。**通報 1 件の IP でだけ測れる** */
const BACKDATE_BUCKETS = (() => {
  const vals = byIp.map((r) => r.backdate_days).filter((v) => v !== "").map(Number);
  const b = [
    { label: "即日\n(1 時間未満)", test: (v) => v < 1 / 24 },
    { label: "1 日未満", test: (v) => v >= 1 / 24 && v < 1 },
    { label: "1〜2 日", test: (v) => v >= 1 && v < 2 },
    { label: "2〜4 日", test: (v) => v >= 2 && v < 4 },
    { label: "4 日以上", test: (v) => v >= 4 },
  ];
  return { labels: b.map((x) => x.label), values: b.map((x) => vals.filter(x.test).length),
    measured: vals.length };
})();

/** 日ごとのフィード / 被害者側の通報件数 */
const BY_DAY = (() => {
  const days = [...new Set(events.map((e) => e.day))].sort();
  return {
    days,
    feed: days.map((d) => events.filter((e) => e.day === d && isFeed(e)).length),
    indep: days.map((d) => events.filter((e) => e.day === d && !isFeed(e)).length),
    cumulative: days.map((d) => K.cumulative_by_day.find((x) => x.day === d)?.cumulative_ips ?? 0),
  };
})();

/* ---------------- 体裁 ---------------- */

const THEME = {
  name: "ARTEX Cluster Report",
  headFontFace: "Cambria",
  bodyFontFace: "Calibri",
  colors: {
    dk1: "14181F",   // 本文の濃い字
    lt1: "FFFFFF",   // 明るい地
    dk2: "1A2230",   // 暗い地（表題・区切り・結び）
    lt2: "F2F4F6",   // 薄い面
    accent1: "B3202C", // 被害者側の観測 ＝ この調査の要点
    accent2: "2E6B9E", // フィードの一括登録
    accent3: "5C6673", // 控えめな字
    accent4: "E8EAED", // 軌道（通報なし）。系列ではない
    accent5: "8A94A3",
    accent6: "C49A2C",
    hlink: "2E6B9E",
    folHlink: "6250D6",
  },
};
const IND = THEME.colors.accent1;   // 被害者側
const FEED = THEME.colors.accent2;  // フィード
const MUTED = THEME.colors.accent3;
const TRACK = THEME.colors.accent4;

const pres = new PptxGenJS();
pres.layout = "LAYOUT_WIDE";          // 13.3in x 7.5in。**スライドを足す前に決める**
pres.theme = { headFontFace: THEME.headFontFace, bodyFontFace: THEME.bodyFontFace };
pres.author = "Claude Code";
pres.title = "sub2api-198.200.59.85 クラスタの通報統計";
pres.subject = "AbuseIPDB 上の通報（2026-11-06 取得）";
const C = pres.SchemeColor;

/** グラフの枠は全スライドで同じ見た目にする */
const CHART_FRAME = {
  showLegend: false,
  catAxisLabelColor: MUTED, catAxisLabelFontSize: 11, catAxisLabelFontFace: "+mn-lt",
  valAxisLabelColor: MUTED, valAxisLabelFontSize: 11, valAxisLabelFontFace: "+mn-lt",
  catGridLine: { style: "none" },
  valGridLine: { color: THEME.colors.lt2, size: 1 },
  catAxisLineShow: false, valAxisLineShow: false,
  dataLabelColor: THEME.colors.dk1, dataLabelFontSize: 11, dataLabelFontFace: "+mn-lt",
  showTitle: false,
};
const LEGEND = {
  showLegend: true, legendPos: "t", legendColor: MUTED,
  legendFontSize: 11, legendFontFace: "+mn-lt",
};

/* ---------------- レイアウト ---------------- */

pres.defineSlideMaster({
  title: "DARK_TITLE", background: { color: C.text2 },
  objects: [
    { placeholder: { options: { name: "eyebrow", type: "body", x: 0.9, y: 2.0, w: 11.5, h: 0.4,
      fontSize: 14, color: "C9CED6", charSpacing: 2, isTextBox: true } } },
    { placeholder: { options: { name: "title", type: "title", x: 0.9, y: 2.45, w: 11.5, h: 1.6,
      fontSize: 42, bold: true, color: C.background1, align: "left", isTextBox: true } } },
    { placeholder: { options: { name: "body", type: "body", x: 0.9, y: 4.2, w: 11.5, h: 2.0,
      fontSize: 16, color: "C9CED6", isTextBox: true } } },
  ],
});
/**
 * 暗い地の**内容**スライド。見出しは明るい内容スライドと同じ高さに置く。
 * 元は見出しを中ほどに置く区切り用のレイアウトを使っていたが、
 * 項目が多いスライドで**本文が下にはみ出した**。見出しの高さも揃わない。
 */
pres.defineSlideMaster({
  title: "DARK_CONTENT", background: { color: C.text2 },
  objects: [
    { placeholder: { options: { name: "title", type: "title", x: 0.65, y: 0.45, w: 12.0, h: 0.75,
      fontSize: 30, bold: true, color: C.background1, align: "left", isTextBox: true } } },
    { placeholder: { options: { name: "kicker", type: "body", x: 0.65, y: 1.18, w: 12.0, h: 0.42,
      fontSize: 14, color: "9BA3AF", isTextBox: true } } },
    { placeholder: { options: { name: "body", type: "body", x: 0.65, y: 1.8, w: 12.0, h: 4.9,
      fontSize: 15, color: "C9CED6", isTextBox: true } } },
  ],
  slideNumber: { x: 12.6, y: 7.0, color: "6B7480", fontSize: 10, fontFace: "Calibri" },
});
pres.defineSlideMaster({
  title: "LIGHT_TITLE_ONLY", background: { color: C.background1 },
  objects: [
    { placeholder: { options: { name: "title", type: "title", x: 0.65, y: 0.45, w: 12.0, h: 0.75,
      fontSize: 30, bold: true, color: C.text1, align: "left", isTextBox: true } } },
    { placeholder: { options: { name: "kicker", type: "body", x: 0.65, y: 1.18, w: 12.0, h: 0.42,
      fontSize: 14, color: MUTED, isTextBox: true } } },
  ],
  slideNumber: { x: 12.6, y: 7.0, color: "A8AEB8", fontSize: 10, fontFace: "Calibri" },
});
pres.defineSlideMaster({
  title: "LIGHT_CHART", background: { color: C.background1 },
  objects: [
    { placeholder: { options: { name: "title", type: "title", x: 0.65, y: 0.45, w: 12.0, h: 0.75,
      fontSize: 30, bold: true, color: C.text1, align: "left", isTextBox: true } } },
    { placeholder: { options: { name: "kicker", type: "body", x: 0.65, y: 1.18, w: 12.0, h: 0.42,
      fontSize: 14, color: MUTED, isTextBox: true } } },
    { placeholder: { options: { name: "chart", type: "chart", x: 0.65, y: 1.8, w: 7.25, h: 4.5,
      color: C.text1 } } },
    { placeholder: { options: { name: "body", type: "body", x: 8.2, y: 1.85, w: 4.45, h: 4.5,
      fontSize: 14, color: C.text1, isTextBox: true } } },
  ],
  slideNumber: { x: 12.6, y: 7.0, color: "A8AEB8", fontSize: 10, fontFace: "Calibri" },
});

/* ---------------- 部品 ---------------- */

/**
 * 日付の中のハイフンを**改行しないハイフン**（U+2011）に替える。
 *
 * `2026-10-31` や `10-27` が行末に来ると `2026-10-` と `31` に割れる。
 * 本文は 14pt が下限なので縮めて逃げられない。文字を替えて割れないようにする。
 */
const nb = (t) => String(t)
  .replace(/(\d{4})-(\d{2})-(\d{2})/g, "$1\u2011$2\u2011$3")
  .replace(/(?<![\d\u2011])(\d{2})-(\d{2})(?![\d\u2011])/g, "$1\u2011$2");

const bullets = (lines) => lines.map((t, i) => ({
  text: nb(t), options: { bullet: true, breakLine: i < lines.length - 1, paraSpaceAfter: 10 },
}));

/**
 * 「N / 母数」の札。**母数を必ず見せる**のがこの資料の通した型。
 * 割合だけだと 1/5 と 50/250 が同じに見える。
 */
const statCard = (slide, { x, y, w, value, denom, label, color = C.text1, note }) => {
  slide.addShape(pres.ShapeType.roundRect, { x, y, w, h: 1.85, fill: { color: C.background2 },
    rectRadius: 0.06, line: { color: C.background2 }, objectName: `card-${label}` });
  slide.addText([
    { text: String(value), options: { fontSize: 46, bold: true, color } },
    ...(denom ? [{ text: ` / ${denom}`, options: { fontSize: 18, color: MUTED } }] : []),
  ], { x: x + 0.22, y: y + 0.2, w: w - 0.44, h: 0.85, isTextBox: true, margin: 0, align: "left" });
  slide.addText(label, { x: x + 0.22, y: y + 1.0, w: w - 0.44, h: 0.35,
    fontSize: 13, bold: true, color: C.text1, isTextBox: true, margin: 0 });
  if (note) {
    slide.addText(note, { x: x + 0.22, y: y + 1.34, w: w - 0.44, h: 0.4,
      fontSize: 11, color: MUTED, isTextBox: true, margin: 0 });
  }
};

/** 比率の帯。通報なしは**軌道**で、系列色を使わない */
const proportionBar = (slide, { x, y, w, h, parts, total, label }) => {
  slide.addText(label, { x, y: y - 0.35, w, h: 0.3, fontSize: 13, bold: true,
    color: C.text1, isTextBox: true, margin: 0 });
  slide.addShape(pres.ShapeType.rect, { x, y, w, h, fill: { color: TRACK },
    line: { color: TRACK }, objectName: `track-${label}` });
  let cx = x;
  for (const p of parts) {
    const pw = (w * p.value) / total;
    if (pw <= 0) continue;
    slide.addShape(pres.ShapeType.rect, { x: cx, y, w: pw, h, fill: { color: p.color },
      line: { color: C.background1, width: 1.5 }, objectName: `seg-${label}-${p.label}` });
    cx += pw;
  }
};

/* ================= 1. 表題 ================= */

pres.addSection({ title: "表題" });
let s = pres.addSlide({ masterName: "DARK_TITLE", sectionTitle: "表題" });
s.addText("AbuseIPDB 上の通報 — クラスタ全体の統計", { placeholder: "eyebrow" });
s.addText("sub2api-198.200.59.85", { placeholder: "title" });
s.addText([
  { text: `${K.ips_in_cluster} IP を 1 つのクラスタとして見た数字`,
    options: { fontSize: 18, color: "FFFFFF", breakLine: true, paraSpaceAfter: 8 } },
  { text: "全 IP に sub2api があり、同じリチャージ URL (198.200.59.85) がセットされている。"
    + "うち 250 IP では ARTEX も起動している（利用者の観測）",
    options: { fontSize: 14, color: "C9CED6", breakLine: true, paraSpaceAfter: 8 } },
  { text: `取得 ${String(S.collected_at_utc).slice(0, 10)} ／ 対象 IP への接続・走査・認証試行は一切していない`,
    options: { fontSize: 12, color: "9BA3AF", italic: true } },
], { placeholder: "body" });
s.addNotes("255 IP をひとまとまりとして見た統計。個別 IP の表とは数え方が違い、"
  + "とくに観測者の数え方が変わる。能動調査はしていない。");

/* ================= 2. 結論 ================= */

pres.addSection({ title: "結論" });
s = pres.addSlide({ masterName: "LIGHT_TITLE_ONLY", sectionTitle: "結論" });
s.addText("クラスタ全体で見ると、観測者は 4 人しかいない", { placeholder: "title" });
s.addText("個別 IP の表では「58 IP が通報されている」。クラスタとして見れば、それを見た観測者は 1 人",
  { placeholder: "kicker" });
statCard(s, { x: 0.65, y: 1.95, w: 2.9, value: K.ips_ever_reported, denom: K.ips_in_cluster,
  label: "一度でも通報された IP", note: `${K.ips_ever_reported_pct}%。32 日の窓での累計` });
statCard(s, { x: 3.75, y: 1.95, w: 2.9, value: K.distinct_reporters_cluster_wide,
  label: "クラスタ全体の観測者", color: IND,
  note: `フィード ${K.feed_reporters} 人 / 被害者側 ${K.independent_reporters} 人` });
statCard(s, { x: 6.85, y: 1.95, w: 2.9, value: K.ips_with_independent_report, denom: K.ips_in_cluster,
  label: "フィード以外の通報がある IP", color: IND,
  note: `${K.ips_with_independent_report_pct}%。被害者の観測に最も近い行` });
statCard(s, { x: 9.95, y: 1.95, w: 2.7, value: K.score.max,
  label: "最大スコア", note: `25 以上は ${K.score.ips_at_or_above_25} 件` });
s.addText([
  { text: "読みどころ", options: { fontSize: 15, bold: true, color: C.text1, breakLine: true, paraSpaceAfter: 10 } },
  ...bullets([
    `通報の厚みは観測者の数で決まっている — 通報 ${K.reports_total} 件は「IP と観測者の組の数」とほぼ同じ`
    + `（1 IP あたり ${K.reports_per_reported_ip} 件）。同じ観測者が同じ IP を 2 回以上通報した例は ${K.ip_reporter_pairs_with_repeat} 件`,
    `全体像を持っている観測者はいない — どの観測者もクラスタの ${K.max_reporter_footprint_pct}% までしか見ていない`,
    `スコア閾値では弾けない — 最大 ${K.score.max} で、25 以上は 1 件もない。スコアだけを閾値にする運用では丸ごと通り抜ける`,
    `日本からの通報は ${K.jp_reports} 件`,
  ]),
], { x: 0.65, y: 4.15, w: 12.0, h: 2.6, isTextBox: true, color: C.text1, fontSize: 13 });
s.addNotes("4 枚の札はすべて母数つき。割合だけだと 1/5 と 50/250 が同じに見えるため。");

/* ================= 3. 観測者 ================= */

pres.addSection({ title: "観測者" });
s = pres.addSlide({ masterName: "LIGHT_CHART", sectionTitle: "観測者" });
s.addText("観測者ごとに、クラスタのどれだけを見たか", { placeholder: "title" });
s.addText(`母数は ${K.ips_in_cluster} IP。最大の観測者でも ${K.max_reporter_footprint_pct}%`,
  { placeholder: "kicker" });
/**
 * **1 系列にして棒ごとに色を付ける。**
 *
 * 2 系列の積み上げにすると `dataLabelPosition: "outEnd"` が使えず
 * （PowerPoint が積み上げ棒では ctr / inEnd / inBase しか許さない）、
 * 1 や 8 の棒では内側に入れた数字が読めない。1 系列なら外に出せる。
 * 代わりに凡例は自分で描く（dataviz の規則でも 1 系列に凡例の箱は不要）。
 */
s.addChart([{
  type: pres.ChartType.bar,
  data: [{ name: "見た IP の数",
    labels: K.reporter_footprints.map((f) => `${f.reporter} (${f.country})`),
    values: K.reporter_footprints.map((f) => f.ips) }],
}], { placeholder: "chart", ...CHART_FRAME,
  barDir: "bar",
  chartColors: K.reporter_footprints.map((f) => (f.bulk_feed ? FEED : IND)),
  showValue: true, dataLabelPosition: "outEnd",
  valAxisMaxVal: K.ips_in_cluster, valAxisMajorUnit: 51,
  catAxisLabelFontSize: 12, barGapWidthPct: 60 });
/* 凡例は手描き。色が何を指すかだけ示す */
(() => {
  const keys = [["フィードの一括登録", FEED], ["被害者側の観測", IND]];
  let lx = 0.9;
  for (const [label, color] of keys) {
    s.addShape(pres.ShapeType.ellipse, { x: lx, y: 6.42, w: 0.14, h: 0.14,
      fill: { color }, line: { color }, objectName: `key-${label}` });
    s.addText(label, { x: lx + 0.22, y: 6.33, w: 2.3, h: 0.3, fontSize: 12,
      color: MUTED, isTextBox: true, margin: 0 });
    lx += 2.7;
  }
})();
s.addText([
  { text: "4 人の内訳", options: { fontSize: 15, bold: true, color: C.text1, breakLine: true, paraSpaceAfter: 10 } },
  ...bullets([
    `BR-R01 は脅威情報フィードの一括登録。${K.reporter_footprints[0].ips} IP に同じ定型文・同じカテゴリで付いている`,
    "IN-R04 は被害者側の検知器。8 IP を 10 秒間に、観測日をさかのぼらずに出している",
    "MY-R02 と NL-R03 は 198.200.59.85 だけ。クラスタの中心が最初に通報された",
    `1 IP あたりの通報はどの観測者も 1.0。厚みは観測者の数で決まる`,
  ]),
], { placeholder: "body" });
s.addNotes("クラスタとして見ると観測者の数え方が変わるのがこのスライドの主旨。"
  + "reporterId は保存していないので、識別子は国コード + 連番に置き換えている。");

/* ================= 4. カバレッジ ================= */

s = pres.addSlide({ masterName: "LIGHT_TITLE_ONLY", sectionTitle: "観測者" });
s.addText("255 のうち、通報に現れたのは 4 分の 1", { placeholder: "title" });
s.addText("薄い帯が母数。色が付いた部分だけが通報に現れた分", { placeholder: "kicker" });
proportionBar(s, { x: 0.65, y: 2.15, w: 11.95, h: 0.8, total: K.ips_in_cluster,
  label: `一度でも通報された IP — ${K.ips_ever_reported} / ${K.ips_in_cluster}（${K.ips_ever_reported_pct}%）`,
  parts: [
    { label: "feed", value: K.ips_ever_reported - K.ips_with_independent_report, color: FEED },
    { label: "indep", value: K.ips_with_independent_report, color: IND },
  ] });
proportionBar(s, { x: 0.65, y: 4.0, w: 11.95, h: 0.8, total: K.ips_in_cluster,
  label: `フィード以外の通報がある IP — ${K.ips_with_independent_report} / ${K.ips_in_cluster}（${K.ips_with_independent_report_pct}%）`,
  parts: [{ label: "indep", value: K.ips_with_independent_report, color: IND }] });
s.addText([
  { text: "フィードだけ", options: { fontSize: 12, bold: true, color: FEED } },
], { x: 0.65, y: 3.05, w: 2.0, h: 0.3, isTextBox: true, margin: 0 });
s.addText([
  { text: "被害者側の観測", options: { fontSize: 12, bold: true, color: IND } },
], { x: 3.3, y: 3.05, w: 2.2, h: 0.3, isTextBox: true, margin: 0 });
s.addText([
  { text: "通報なし（母数の残り）", options: { fontSize: 12, bold: true, color: MUTED } },
], { x: 6.0, y: 3.05, w: 3.0, h: 0.3, isTextBox: true, margin: 0 });
s.addText([
  ...bullets([
    `${K.ips_never_reported} IP は一度も通報されていない。引けていない IP は ${K.ips_not_measured} 件なので、`
    + "これは「分からない」ではなく「通報が無い」",
    "ただし通報が無いことは無害の証明ではない。誰も通報していないだけで、"
    + "立てたばかりの基盤や、通報しない被害者しかいない基盤は同じ見た目になる",
    `フィードの一括登録を除くと ${K.ips_with_independent_report} IP（${K.ips_with_independent_report_pct}%）まで落ちる。`
    + "「攻撃元として報告されている」をこの 2 つを足して読むと、中身を取り違える",
  ]),
], { x: 0.65, y: 5.15, w: 11.95, h: 1.7, isTextBox: true, color: C.text1, fontSize: 13 });
s.addNotes("帯の薄い部分は軌道（母数）で、系列色ではない。"
  + "灰を系列にすると彩度の下限を割り、色覚の分離が測れなくなる。");

/* ================= 5. 時間 ================= */

pres.addSection({ title: "時間" });
s = pres.addSlide({ masterName: "LIGHT_CHART", sectionTitle: "時間" });
s.addText("プールの消費は 25.5% で止まっている", { placeholder: "title" });
s.addText(nb(`観測日ベース（${K.first_observed} 〜 ${K.last_observed}）。`
  + "棒がその日の通報、線がその日までに通報された IP の累計。単位はどちらも件数"),
{ placeholder: "kicker" });
s.addChart([
  { type: pres.ChartType.bar,
    data: [
      { name: "フィードの通報", labels: BY_DAY.days, values: BY_DAY.feed },
      { name: "被害者側の通報", labels: BY_DAY.days, values: BY_DAY.indep },
    ],
    options: { barGrouping: "stacked", chartColors: [FEED, IND], barGapWidthPct: 55 } },
  { type: pres.ChartType.line,
    data: [{ name: "通報された IP の累計", labels: BY_DAY.days, values: BY_DAY.cumulative }],
    options: { chartColors: [THEME.colors.dk1], lineSize: 2, lineSmooth: false,
      lineDataSymbol: "circle", lineDataSymbolSize: 8 } },
], { placeholder: "chart", ...CHART_FRAME, ...LEGEND, catAxisLabelRotate: 45 });
s.addText([
  { text: "32 日の窓で 7 日だけ", options: { fontSize: 15, bold: true, color: C.text1, breakLine: true, paraSpaceAfter: 10 } },
  ...bullets([
    `観測の窓は ${K.observation_window_days} 日。`
    + `そのうち観測があったのは ${K.days_with_any_observation} 日（${K.days_with_any_observation_pct}%）だけ`,
    `最後の観測から ${K.days_quiet_since_last_observation} 日。フィードの観測は 10-27 で止まっている`
    + "（投稿は 11-04 まで続いた）",
    "10-24 の 32 件のように一日に固まる。10-31 の 8 件は 10 秒間に収まっており、"
    + "1 台の検知器がまとめて出した形",
    `2 日以上に跨って通報された IP は ${K.ips_reported_on_multiple_days} 件。`
    + "ただし同じ観測者の再通報が行として増えないので、「使い回していない」とは言えない",
  ]),
], { placeholder: "body" });
s.addNotes("棒と線は同じ単位（件数と IP 数）なので 1 つの軸に載せている。"
  + "単位が違う 2 本を別の軸で重ねるのは避ける。");

/* ================= 6. さかのぼり投稿 ================= */

s = pres.addSlide({ masterName: "LIGHT_CHART", sectionTitle: "時間" });
s.addText("観測日は通報者の申告で、さかのぼれる", { placeholder: "title" });
s.addText(`投稿までの遅れ。通報が 1 件の ${BACKDATE_BUCKETS.measured} IP でだけ測れる`,
  { placeholder: "kicker" });
s.addChart([{
  type: pres.ChartType.bar,
  data: [{ name: "IP の数", labels: BACKDATE_BUCKETS.labels, values: BACKDATE_BUCKETS.values }],
}], { placeholder: "chart", ...CHART_FRAME,
  barDir: "col",
  // **即日だけ色を変える。**その 7 件は被害者側の検知器で、ここが話の要点
  chartColors: BACKDATE_BUCKETS.labels.map((_, i) => (i === 0 ? IND : FEED)),
  showValue: true, dataLabelPosition: "outEnd", barGapWidthPct: 50 });
s.addText([
  { text: "2 つの日付を混ぜない", options: { fontSize: 15, bold: true, color: C.text1, breakLine: true, paraSpaceAfter: 10 } },
  ...bullets([
    "reportedAt は通報者が申告した観測時刻。活動日として読むのはこちら",
    "lastReportedAt は AbuseIPDB が受け取った時刻（投稿）。活動日ではない",
    `さかのぼりは中央 ${S.date_field_semantics.backdate_days_median} 日・`
    + `最大 ${S.date_field_semantics.backdate_days_max} 日。`
    + `投稿が観測より前になった例は ${S.date_field_semantics.submitted_before_observed} 件`,
    "だから過去の日付の集計は確定しない。10-30 に通報 0 件だった 14 IP が、"
    + "11-06 には「10-27 観測」の通報を持っていた",
    "即日の 7 件は被害者側の検知器。見たその場で出している",
  ]),
], { placeholder: "body" });
s.addNotes("この性質に気づいたのは 11-06。前回のレポートは Last observed の一致を"
  + "「独立した時系列情報を持たない」と読んでいたが、逆だった。");

/* ================= 7. スコア ================= */

pres.addSection({ title: "見え方" });
s = pres.addSlide({ masterName: "LIGHT_CHART", sectionTitle: "見え方" });
s.addText("スコア閾値では、このクラスタは丸ごと通り抜ける", { placeholder: "title" });
s.addText(`${K.ips_in_cluster} IP 全体の分布。最大 ${K.score.max}、25 以上は ${K.score.ips_at_or_above_25} 件`,
  { placeholder: "kicker" });
s.addChart([{
  type: pres.ChartType.bar,
  data: [{ name: "IP の数",
    labels: Object.keys(K.score.histogram).map((v) => `スコア ${v}`),
    values: Object.values(K.score.histogram) }],
}], { placeholder: "chart", ...CHART_FRAME,
  barDir: "col", chartColors: [FEED], invertedColors: [FEED],
  showValue: true, dataLabelPosition: "outEnd", barGapWidthPct: 45 });
s.addText([
  { text: "弾けない理由", options: { fontSize: 15, bold: true, color: C.text1, breakLine: true, paraSpaceAfter: 10 } },
  ...bullets([
    `スコア 0 が ${K.score.ips_at_zero} / ${K.ips_in_cluster} 件。中央値は ${K.score.median_all_255}`,
    `通報がある ${K.ips_ever_reported} 件に絞っても中央値は ${K.score.median_reported_only}`,
    `25 以上は ${K.score.ips_at_or_above_25} 件、50 以上は ${K.score.ips_at_or_above_50} 件`,
    "スコアは通報が増えなくても時間で下がる。実測で 198.200.59.85 が 18 → 16 に"
    + "（通報は 3 件のまま）。横に比べるときは取得日を揃えること",
  ]),
], { placeholder: "body" });
s.addNotes("スコアだけを閾値にする運用では検知できない、というのがこのスライドの含意。");

/* ================= 8. 帯の偏り ================= */

s = pres.addSlide({ masterName: "LIGHT_CHART", sectionTitle: "見え方" });
s.addText("帯の偏りは、フィードにしか出ていない", { placeholder: "title" });
s.addText("母数は /25 ごとに 125 IP ずつ。通報があった IP の数", { placeholder: "kicker" });
(() => {
  const pfx = Object.keys(K.by_prefix).sort();
  s.addChart([{
    type: pres.ChartType.bar,
    data: [
      { name: "フィードの一括登録", labels: pfx.map((p) => `${p}.x`),
        values: pfx.map((p) => K.by_prefix[p].feed_report_ips) },
      { name: "被害者側の観測", labels: pfx.map((p) => `${p}.x`),
        values: pfx.map((p) => K.by_prefix[p].independent_report_ips) },
    ],
  }], { placeholder: "chart", ...CHART_FRAME, ...LEGEND,
    barDir: "col", barGrouping: "clustered", chartColors: [FEED, IND],
    showValue: true, dataLabelPosition: "outEnd", barGapWidthPct: 40 });
  const a = K.by_prefix["38.11.173"], b = K.by_prefix["38.11.221"];
  s.addText([
    { text: "2.4 倍差は読めない", options: { fontSize: 15, bold: true, color: C.text1, breakLine: true, paraSpaceAfter: 10 } },
    ...bullets([
      `38.11.173 が 38.11.221 の 2.4 倍（${a.with_reports} 対 ${b.with_reports}、母数は同じ 125）`,
      `ところがフィードは ${a.feed_report_ips} 対 ${b.feed_report_ips} で偏り、`
      + `被害者側は ${a.independent_report_ips} 対 ${b.independent_report_ips} で均等`,
      "つまり偏りはフィードの集め方由来の可能性が残る。"
      + "「173 のほうが多く使われている」とは読めない",
      `被害者側は ${K.ips_with_independent_report} IP しかないので、均等であること自体も強い証拠ではない`,
      `連続区間は ${a.contiguous_runs} / ${b.contiguous_runs} と多く、`
      + "まとまったブロックではなく散っている",
    ]),
  ], { placeholder: "body" });
})();
s.addNotes("観測を 1 つにまとめて割合だけ見ると「173 が多い」と読み違える。"
  + "観測者ごとに割って初めて分かる。");

/* ================= 9. カテゴリ ================= */

s = pres.addSlide({ masterName: "LIGHT_CHART", sectionTitle: "見え方" });
s.addText("攻撃手法が付いているのは 9 IP", { placeholder: "title" });
s.addText("重複しない区分。1 つの IP に複数のカテゴリが付くので、カテゴリごとの数は足せない",
  { placeholder: "kicker" });
s.addChart([{
  type: pres.ChartType.bar,
  data: [
    { name: "攻撃手法が付いている",
      labels: ["攻撃手法\n(Web App Attack など)", "偵察のみ\n(Port Scan)", "Exploited Host だけ"],
      values: [CP.attack_technique_ips, CP.reconnaissance_only_ips, null] },
    { name: "補助情報だけ",
      labels: ["攻撃手法\n(Web App Attack など)", "偵察のみ\n(Port Scan)", "Exploited Host だけ"],
      values: [null, null, CP.exploited_host_only_ips] },
  ],
}], { placeholder: "chart", ...CHART_FRAME, ...LEGEND,
  barDir: "col", barGrouping: "stacked", chartColors: [IND, FEED],
  showValue: true, dataLabelPosition: "ctr", barGapWidthPct: 55 });
s.addText([
  { text: "カテゴリ 20 は攻撃手法ではない", options: { fontSize: 15, bold: true, color: C.text1, breakLine: true, paraSpaceAfter: 10 } },
  ...bullets([
    `Exploited Host（20）だけが付いている ${CP.exploited_host_only_ips} IP は`
    + "「この送信元自体が侵害されている可能性」を言っているだけで、攻撃を観測した記録ではない",
    "踏み台にされた正規ホストなら、送信元の持ち主も被害者",
    `攻撃手法が付いているのは ${CP.attack_technique_ips} IP`
    + `（クラスタの ${Number((100 * CP.attack_technique_ips / K.ips_in_cluster).toFixed(1))}%）`,
    `カテゴリごとに数えると 11 になるが、198.200.59.85 には 14・15・20・21 の 4 つが付いている。`
    + "足して読むと取り違える",
  ]),
], { placeholder: "body" });
s.addNotes("カテゴリはレポーターの自己申告。区分の合計が「通報がある IP」65 に一致することを"
  + "検査で確かめている。");

/* ================= 10. 言えないこと ================= */

pres.addSection({ title: "限界" });
s = pres.addSlide({ masterName: "DARK_CONTENT", sectionTitle: "限界" });
s.addText("この統計で言えないこと", { placeholder: "title" });
s.addText("母数と観測者の数を押さえたうえで、それでも言えないこと", { placeholder: "kicker" });
s.addText([
  ...bullets([
    "対象のサービスが動いているかは確認していない — 接続・走査・認証試行を一切していないので、"
    + "待ち受けているサービスも見ていない。利用者から渡された前提のまま",
    "攻撃に使われた時期は確定しない — さかのぼり投稿があるので、今日の集計は明日増える。"
    + "reports[] は観測の下限しか示さない",
    `フィード以外の観測者は ${K.independent_reporters} 人しかいない — `
    + "「複数の被害者が独立に観測した」とまでは言えない",
    "通報者がどういう人かは分からない — reporterId を保存しない方針なので、"
    + "このクラスタの中での選択性しか見ていない",
    "通報が無いことは無害の証明ではない",
    "カテゴリと観測時刻はレポーターの自己申告。IP の所在地・ISP・AS は運用者の国籍や所属を示さない",
    `母集団は渡された ${K.ips_in_cluster} IP だけ。同じ AS の他の帯は見ていない`,
  ]),
], { placeholder: "body" });
s.addNotes("この資料は Claude（AI）が自動生成したもので、人の確認を前提とする。");

/* ================= 11. 次に打てる手 ================= */

pres.addSection({ title: "次の手" });
s = pres.addSlide({ masterName: "LIGHT_TITLE_ONLY", sectionTitle: "次の手" });
s.addText("次に打てる手", { placeholder: "title" });
s.addText("クラスタ全体として見たときに効くもの", { placeholder: "kicker" });
(() => {
  const items = [
    ["済", "毎日追う仕組みを入れた",
      "data/ioc/watch/ に 255 IP を登録。IN-R04 の通報に気づくまで 6 日かかったので、"
      + "初めてフィード以外の通報が付いた日を翌日に出す", IND],
    ["1", "198.200.59.85 を重点的に見る",
      "クラスタの中心。最初に通報され（09-30）、フィード以外の観測者が 2 人付いている。"
      + "ここが落ちるとクラスタ全体のリチャージが止まる", FEED],
    ["2", "lastReportedAt の動きを毎日記録する",
      "投稿が続いている間はフィードがまだこの帯を追っている。"
      + "reports[] だけ見ていると止まったように見える", FEED],
    ["3", "visiblooths.net を証明書の記録（CT ログ）で追う",
      ".85〜.89 の 5 件が同じ命名規則なので、他の帯にも兄弟ホストが並んでいる可能性がある", FEED],
    ["4", "同じ AS の他の帯を同じ手順で調べる",
      "この 3 帯が特別なのか、もっと広いのかを確かめる", FEED],
  ];
  let y = 1.85;
  for (const [n, head, body, color] of items) {
    // 丸の中心を見出しの行の中心に合わせる
    s.addShape(pres.ShapeType.ellipse, { x: 0.65, y: y + 0.03, w: 0.44, h: 0.44,
      fill: { color }, line: { color }, objectName: `step-${n}` });
    s.addText(n, { x: 0.65, y: y + 0.03, w: 0.44, h: 0.44, fontSize: n === "済" ? 10 : 15,
      bold: true, color: "FFFFFF", align: "center", valign: "middle", isTextBox: true, margin: 0 });
    s.addText([
      { text: head, options: { fontSize: 15, bold: true, color: C.text1,
        breakLine: true, paraSpaceAfter: 4 } },
      { text: nb(body), options: { fontSize: 12, color: MUTED } },
    ], { x: 1.28, y, w: 11.35, h: 0.92, isTextBox: true, margin: 0 });
    y += 1.0;
  }
})();
s.addNotes("1 つ目は 2026-11-06 に実装済み。残りは未着手。");

/* ---------------- 書き出す ---------------- */

await pres.writeFile({ fileName: OUT });
await applyTheme(OUT, THEME);
console.log(`→ ${path.relative(path.resolve(HERE, "../.."), OUT)}`);
console.log(`  ${K.ips_in_cluster} IP / 通報 ${K.reports_total} 件 / 観測者 ${K.distinct_reporters_cluster_wide} 人`);
console.log("  数字は artex_timeline_summary.json と CSV から読んでいる（ここで数え直していない）");
