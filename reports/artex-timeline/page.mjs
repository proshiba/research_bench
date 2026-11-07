#!/usr/bin/env node
// クラスタ全体の統計を 1 枚の HTML にする。**成果物しか読まない。API も写しも見ない。**
//
//   node reports/artex-timeline/page.mjs [--out artex_timeline_cluster_stats.html]
//
// 数字は `artex_timeline_summary.json` と CSV から読む。**ここで数え直さない。**
//
// ## なぜ pptx ではなく HTML なのか
//
// pptx のネイティブグラフは LibreOffice では描けても **PowerPoint 側で中身が
// 空になることがある**（2026-11-06 に利用者の環境で発生）。こちらの QA は
// LibreOffice 描画と XSD 検査しか見ていなかったので捕まえられなかった。
//
// HTML なら**描画そのものを自分で確認できる**（Playwright で開いて画を撮る）。
// 外部の読み込みも無いので、ファイル 1 つで閉じている。
//
// ## 図の作り
//
// グラフは**自前のインライン SVG**。CDN もライブラリも使わない。
// 系列色は 2 色だけ: 被害者側の観測とフィードの一括登録。
// dataviz の検証器に通してある（明色 地 #ffffff / 暗色 地 #14181F の両方）。
//
//   明色  被害者側 #B3202C / フィード #2E6B9E  （CVD 最悪 ΔE 18.5・通常視 26.5）
//   暗色  被害者側 #D9544E / フィード #4E9AD6  （CVD 最悪 ΔE 19.9・通常視 27.3）
//
// 「通報なし」は系列ではなく**軌道**。灰を系列にすると彩度の下限を割る。
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const argv = process.argv.slice(2);
const outArg = argv.indexOf("--out");
const OUT = path.join(HERE, outArg >= 0 ? argv[outArg + 1] : "artex_timeline_cluster_stats.html");

/* ---------------- 成果物を読む ---------------- */

const S = JSON.parse(fs.readFileSync(path.join(HERE, "artex_timeline_summary.json"), "utf8"));
const K = S.cluster_stats;
const CP = K.category_partition_by_ip;
const D = S.date_field_semantics;

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

const BACKDATE = (() => {
  const vals = byIp.map((r) => r.backdate_days).filter((v) => v !== "").map(Number);
  const b = [
    { label: "即日", sub: "1 時間未満", test: (v) => v < 1 / 24, independent: true },
    { label: "1 日未満", test: (v) => v >= 1 / 24 && v < 1 },
    { label: "1〜2 日", test: (v) => v >= 1 && v < 2 },
    { label: "2〜4 日", test: (v) => v >= 2 && v < 4 },
    { label: "4 日以上", test: (v) => v >= 4 },
  ];
  return { rows: b.map((x) => ({ label: x.label, sub: x.sub, independent: !!x.independent,
    value: vals.filter(x.test).length })), measured: vals.length };
})();

const BY_DAY = (() => {
  const days = [...new Set(events.map((e) => e.day))].sort();
  return days.map((d) => ({
    day: d,
    feed: events.filter((e) => e.day === d && isFeed(e)).length,
    indep: events.filter((e) => e.day === d && !isFeed(e)).length,
    cumulative: K.cumulative_by_day.find((x) => x.day === d)?.cumulative_ips ?? 0,
  }));
})();

/* ---------------- SVG の部品 ---------------- */

const esc = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;")
  .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
/** 棒の先だけ丸める。**底は軸に付けたままにする** */
const barPathH = (x, y, w, h, r) => {
  const rr = Math.min(r, w, h / 2);
  if (w <= 0.5) return `M${x} ${y} h${Math.max(w, 0.5)} v${h} h${-Math.max(w, 0.5)} Z`;
  return `M${x} ${y} h${w - rr} a${rr} ${rr} 0 0 1 ${rr} ${rr} v${h - 2 * rr}`
    + ` a${rr} ${rr} 0 0 1 ${-rr} ${rr} h${-(w - rr)} Z`;
};
const barPathV = (x, y, w, h, r) => {
  const rr = Math.min(r, h, w / 2);
  if (h <= 0.5) return `M${x} ${y + h} h${w} v${-Math.max(h, 0.5)} h${-w} Z`;
  return `M${x} ${y + h} v${-(h - rr)} a${rr} ${rr} 0 0 1 ${rr} ${-rr} h${w - 2 * rr}`
    + ` a${rr} ${rr} 0 0 1 ${rr} ${rr} v${h - rr} Z`;
};
/**
 * 目盛りの数値。**「読める数」に丸め、最後の目盛りは必ず最大値以上にする。**
 *
 * 最初の版は `v <= max` で止めていたので、最大 190 のとき目盛りが 0/50/100/150 で
 * 終わり、**上限 150 に対して 190 の棒を描いて枠を突き抜けた**（見出しに重なった）。
 * 目盛りの上端を棒の尺度に使うので、ここが最大値を下回ってはいけない。
 */
const niceTicks = (max, count = 4) => {
  if (!(max > 0)) return [0, 1];
  const raw = max / count;
  const mag = Math.pow(10, Math.floor(Math.log10(raw)));
  const step = [1, 2, 2.5, 5, 10].map((m) => m * mag).find((s) => s >= raw) || mag * 10;
  const top = Math.ceil(max / step - 1e-9) * step;
  const out = [];
  for (let v = 0; v <= top + step * 0.001; v += step) out.push(Math.round(v * 1000) / 1000);
  return out;
};
const tip = (label, value) => ` data-tip="${esc(label)}" data-val="${esc(value)}"`;

/**
 * 横棒。**母数いっぱいまで軌道を引く**ので、どれだけ見ていないかが分かる。
 */
function chartHBar({ rows, total, unit = "IP" }) {
  const W = 760, rowH = 54, padL = 150, padR = 60, padT = 10;
  const H = padT + rows.length * rowH + 34;
  const plotW = W - padL - padR;
  const ticks = niceTicks(total, 6);
  let g = "";
  for (const t of ticks) {
    const x = padL + (plotW * t) / total;
    g += `<line class="grid" x1="${x}" y1="${padT}" x2="${x}" y2="${padT + rows.length * rowH}"/>`
      + `<text class="axis" x="${x}" y="${padT + rows.length * rowH + 20}" text-anchor="middle">${t}</text>`;
  }
  rows.forEach((r, i) => {
    const y = padT + i * rowH + 11;
    const bh = rowH - 26;
    const w = (plotW * r.value) / total;
    g += `<text class="cat" x="${padL - 12}" y="${y + bh / 2 + 4}" text-anchor="end">${esc(r.label)}</text>`
      + `<rect class="track" x="${padL}" y="${y}" width="${plotW}" height="${bh}" rx="4"/>`
      + `<path class="mark ${r.independent ? "ind" : "feed"}" d="${barPathH(padL, y, w, bh, 4)}"`
      + tip(r.label, `${r.value} / ${total} ${unit}（${((100 * r.value) / total).toFixed(1)}%）`) + "/>"
      + `<text class="val" x="${padL + w + 8}" y="${y + bh / 2 + 4}">${r.value}</text>`;
  });
  return `<svg viewBox="0 0 ${W} ${H}" role="img" preserveAspectRatio="xMidYMid meet">${g}</svg>`;
}

/** 比率の帯。軌道の上に色を置く。**軌道は系列ではない** */
function chartTrack({ parts, total, unit = "IP" }) {
  const W = 760, H = 46, r = 5;
  let g = `<rect class="track" x="0" y="0" width="${W}" height="${H}" rx="${r}"/>`;
  let cx = 0;
  parts.forEach((p) => {
    const w = (W * p.value) / total;
    if (w <= 0) return;
    g += `<rect class="mark ${p.independent ? "ind" : "feed"}" x="${cx}" y="0" width="${Math.max(w - 2, 1)}"`
      + ` height="${H}" rx="${r}"` + tip(p.label, `${p.value} / ${total} ${unit}`) + "/>";
    cx += w;
  });
  return `<svg viewBox="0 0 ${W} ${H}" role="img" preserveAspectRatio="none" class="trackbar">${g}</svg>`;
}

/** 積み上げ棒 + 累計の線。**単位が同じなので 1 つの軸に載せる** */
function chartDays({ rows }) {
  const W = 760, H = 330, padL = 44, padR = 16, padT = 24, padB = 62;
  const plotW = W - padL - padR, plotH = H - padT - padB;
  const max = Math.max(...rows.map((r) => Math.max(r.feed + r.indep, r.cumulative)));
  const ticks = niceTicks(max, 4);
  const top = ticks[ticks.length - 1];
  const yOf = (v) => padT + plotH - (plotH * v) / top;
  const bw = Math.min(46, (plotW / rows.length) * 0.56);
  let g = "";
  for (const t of ticks) {
    g += `<line class="grid" x1="${padL}" y1="${yOf(t)}" x2="${W - padR}" y2="${yOf(t)}"/>`
      + `<text class="axis" x="${padL - 10}" y="${yOf(t) + 4}" text-anchor="end">${t}</text>`;
  }
  const cx = (i) => padL + (plotW / rows.length) * (i + 0.5);
  rows.forEach((r, i) => {
    const x = cx(i) - bw / 2;
    const hf = (plotH * r.feed) / top, hi = (plotH * r.indep) / top;
    // **積み上げの間に 2px の隙間**を空ける
    if (r.feed > 0) {
      g += `<path class="mark feed" d="${barPathV(x, yOf(r.feed), bw, hf, 4)}"`
        + tip(`${r.day} フィード`, `${r.feed} 件`) + "/>";
    }
    if (r.indep > 0) {
      const y0 = yOf(r.feed + r.indep);
      g += `<path class="mark ind" d="${barPathV(x, y0, bw, Math.max(hi - 2, 1), 4)}"`
        + tip(`${r.day} 被害者側`, `${r.indep} 件`) + "/>";
    }
    g += `<text class="axis tilt" x="${cx(i)}" y="${padT + plotH + 18}" text-anchor="end"`
      + ` transform="rotate(-38 ${cx(i)} ${padT + plotH + 18})">${esc(r.day.slice(5))}</text>`;
  });
  const pts = rows.map((r, i) => `${cx(i)},${yOf(r.cumulative)}`).join(" ");
  g += `<polyline class="line" points="${pts}"/>`;
  rows.forEach((r, i) => {
    g += `<circle class="dot" cx="${cx(i)}" cy="${yOf(r.cumulative)}" r="5"`
      + tip(`${r.day} までの累計`, `${r.cumulative} IP`) + "/>";
  });
  return `<svg viewBox="0 0 ${W} ${H}" role="img" preserveAspectRatio="xMidYMid meet">${g}</svg>`;
}

/** 縦棒。1 系列で、棒ごとに色を変えられる */
function chartVBar({ rows, unit = "IP", maxOverride }) {
  const W = 760, H = 310, padL = 44, padR = 16, padT = 28, padB = 58;
  const plotW = W - padL - padR, plotH = H - padT - padB;
  const max = maxOverride || Math.max(...rows.map((r) => r.value));
  const ticks = niceTicks(max, 4);
  const top = ticks[ticks.length - 1] || 1;
  const yOf = (v) => padT + plotH - (plotH * v) / top;
  const bw = Math.min(84, (plotW / rows.length) * 0.6);
  let g = "";
  for (const t of ticks) {
    g += `<line class="grid" x1="${padL}" y1="${yOf(t)}" x2="${W - padR}" y2="${yOf(t)}"/>`
      + `<text class="axis" x="${padL - 10}" y="${yOf(t) + 4}" text-anchor="end">${t}</text>`;
  }
  rows.forEach((r, i) => {
    const cx = padL + (plotW / rows.length) * (i + 0.5);
    const x = cx - bw / 2;
    const h = (plotH * r.value) / top;
    g += `<path class="mark ${r.independent ? "ind" : "feed"}" d="${barPathV(x, yOf(r.value), bw, h, 4)}"`
      + tip(r.label, `${r.value} ${unit}`) + "/>"
      + `<text class="val" x="${cx}" y="${yOf(r.value) - 8}" text-anchor="middle">${r.value}</text>`
      + `<text class="axis" x="${cx}" y="${padT + plotH + 20}" text-anchor="middle">${esc(r.label)}</text>`;
    if (r.sub) {
      g += `<text class="axis sub" x="${cx}" y="${padT + plotH + 36}" text-anchor="middle">${esc(r.sub)}</text>`;
    }
  });
  return `<svg viewBox="0 0 ${W} ${H}" role="img" preserveAspectRatio="xMidYMid meet">${g}</svg>`;
}

/** 並べた縦棒。2 系列を隣に置く */
function chartGrouped({ groups, unit = "IP" }) {
  const W = 760, H = 310, padL = 44, padR = 16, padT = 28, padB = 50;
  const plotW = W - padL - padR, plotH = H - padT - padB;
  const max = Math.max(...groups.flatMap((g0) => g0.values.map((v) => v.value)));
  const ticks = niceTicks(max, 4);
  const top = ticks[ticks.length - 1] || 1;
  const yOf = (v) => padT + plotH - (plotH * v) / top;
  const slot = plotW / groups.length;
  const bw = Math.min(56, (slot * 0.66) / 2);
  let g = "";
  for (const t of ticks) {
    g += `<line class="grid" x1="${padL}" y1="${yOf(t)}" x2="${W - padR}" y2="${yOf(t)}"/>`
      + `<text class="axis" x="${padL - 10}" y="${yOf(t) + 4}" text-anchor="end">${t}</text>`;
  }
  groups.forEach((grp, i) => {
    const cx = padL + slot * (i + 0.5);
    grp.values.forEach((v, j) => {
      // **隣り合う塗りの間に 2px**
      const x = cx - bw - 1 + j * (bw + 2);
      const h = (plotH * v.value) / top;
      g += `<path class="mark ${v.independent ? "ind" : "feed"}" d="${barPathV(x, yOf(v.value), bw, h, 4)}"`
        + tip(`${grp.label} ${v.label}`, `${v.value} ${unit}`) + "/>"
        + `<text class="val" x="${x + bw / 2}" y="${yOf(v.value) - 8}" text-anchor="middle">${v.value}</text>`;
    });
    g += `<text class="axis" x="${cx}" y="${padT + plotH + 22}" text-anchor="middle">${esc(grp.label)}</text>`;
  });
  return `<svg viewBox="0 0 ${W} ${H}" role="img" preserveAspectRatio="xMidYMid meet">${g}</svg>`;
}

/* ---------------- 頁の部品 ---------------- */

const legend = (items) => `<div class="legend">` + items.map((i) =>
  `<span class="key"><i class="sw ${i.cls}"></i>${esc(i.label)}</span>`).join("") + `</div>`;

/** 図の下に必ず表を置く。**色だけに頼らせない** */
const table = (head, rows) => `<details class="tbl"><summary>数字で見る</summary>`
  + `<table><thead><tr>${head.map((h) => `<th>${esc(h)}</th>`).join("")}</tr></thead><tbody>`
  + rows.map((r) => `<tr>${r.map((c, i) => (i === 0 ? `<th scope="row">${esc(c)}</th>` : `<td>${esc(c)}</td>`)).join("")}</tr>`).join("")
  + `</tbody></table></details>`;

const figure = ({ id, title, note, svg, keys, tbl }) => `
<figure class="fig" id="${id}">
  <figcaption><h3>${title}</h3>${note ? `<p class="note">${note}</p>` : ""}</figcaption>
  ${keys ? legend(keys) : ""}
  <div class="plot">${svg}</div>
  ${tbl || ""}
</figure>`;

const stat = ({ value, denom, label, note, ind }) => `
<div class="stat">
  <div class="num ${ind ? "ind" : ""}">${esc(value)}${denom ? `<span class="den"> / ${esc(denom)}</span>` : ""}</div>
  <div class="lab">${esc(label)}</div>
  ${note ? `<div class="sub">${esc(note)}</div>` : ""}
</div>`;

const KEYS = [
  { cls: "feed", label: "フィードの一括登録" },
  { cls: "ind", label: "被害者側の観測" },
];

/* ---------------- 組み立てる ---------------- */

const pct = (n, d) => Number(((100 * n) / d).toFixed(1));
const body = `
<header class="hd">
  <p class="eyebrow">AbuseIPDB 上の通報 — クラスタ全体の統計</p>
  <h1>sub2api-198.200.59.85</h1>
  <p class="lead">${K.ips_in_cluster} IP を 1 つのクラスタとして見た数字。全 IP に sub2api があり、
    同じリチャージ URL (198.200.59.85) がセットされている。うち 250 IP では ARTEX も起動している（利用者の観測）。</p>
  <p class="meta">取得 ${String(S.collected_at_utc).slice(0, 10)} ／
    <strong>対象 IP への接続・走査・認証試行は一切していない</strong>／
    この文書は Claude（AI）が自動生成したもので、人の確認を前提とする</p>
</header>

<section>
  <h2>1. 結論</h2>
  <p class="lead">個別 IP の表では「58 IP が通報されている」。
    <strong>クラスタとして見れば、それを見た観測者は 1 人。</strong></p>
  <div class="stats">
    ${stat({ value: K.ips_ever_reported, denom: K.ips_in_cluster, label: "一度でも通報された IP",
    note: `${K.ips_ever_reported_pct}%。32 日の窓での累計` })}
    ${stat({ value: K.distinct_reporters_cluster_wide, label: "クラスタ全体の観測者", ind: true,
    note: `フィード ${K.feed_reporters} 人 / 被害者側 ${K.independent_reporters} 人` })}
    ${stat({ value: K.ips_with_independent_report, denom: K.ips_in_cluster,
    label: "フィード以外の通報がある IP", ind: true,
    note: `${K.ips_with_independent_report_pct}%。被害者の観測に最も近い行` })}
    ${stat({ value: K.score.max, label: "最大スコア",
    note: `25 以上は ${K.score.ips_at_or_above_25} 件` })}
  </div>
  <ul class="pts">
    <li><strong>通報の厚みは観測者の数で決まっている。</strong>通報 ${K.reports_total} 件は
      「IP と観測者の組の数」とほぼ同じ（1 IP あたり ${K.reports_per_reported_ip} 件）。
      同じ観測者が同じ IP を 2 回以上通報した例は ${K.ip_reporter_pairs_with_repeat} 件。</li>
    <li><strong>全体像を持っている観測者はいない。</strong>どの観測者もクラスタの
      ${K.max_reporter_footprint_pct}% までしか見ていない。</li>
    <li><strong>スコア閾値では弾けない。</strong>最大 ${K.score.max} で、25 以上は 1 件もない。</li>
    <li>日本からの通報は ${K.jp_reports} 件。</li>
  </ul>
</section>

<section>
  <h2>2. 観測者</h2>
  ${figure({
    id: "fig-reporters",
    title: "観測者ごとに、クラスタのどれだけを見たか",
    note: `薄い帯が母数 ${K.ips_in_cluster} IP。最大の観測者でも ${K.max_reporter_footprint_pct}%`,
    keys: KEYS,
    svg: chartHBar({
      total: K.ips_in_cluster,
      rows: K.reporter_footprints.map((f) => ({
        label: `${f.reporter} (${f.country})`, value: f.ips, independent: !f.bulk_feed })),
    }),
    tbl: table(["観測者", "所在", "見た IP", "クラスタの", "1 IP あたりの通報", "フィード"],
      K.reporter_footprints.map((f) => [f.reporter, f.country, f.ips,
        `${f.pct_of_cluster}%`, f.reports_per_ip, f.bulk_feed ? "はい" : "—"])),
  })}
  <ul class="pts">
    <li><code>BR-R01</code> は脅威情報フィードの一括登録。${K.reporter_footprints[0].ips} IP に
      同じ定型文・同じカテゴリで付いている。</li>
    <li><code>IN-R04</code> は被害者側の検知器。8 IP を 10 秒間に、観測日をさかのぼらずに出している。</li>
    <li><code>MY-R02</code> と <code>NL-R03</code> は <code>198.200.59.85</code> だけ。
      クラスタの中心が最初に通報された。</li>
  </ul>

  ${figure({
    id: "fig-coverage",
    title: "255 のうち、通報に現れたのは 4 分の 1",
    note: "薄い帯が母数。色が付いた部分だけが通報に現れた分",
    keys: [...KEYS, { cls: "track", label: "通報なし（母数の残り）" }],
    svg: `<div class="tracks">
      <p class="tlab">一度でも通報された IP — <strong>${K.ips_ever_reported} / ${K.ips_in_cluster}</strong>（${K.ips_ever_reported_pct}%）</p>
      ${chartTrack({ total: K.ips_in_cluster, parts: [
    { label: "フィードだけ", value: K.ips_ever_reported - K.ips_with_independent_report },
    { label: "被害者側の観測", value: K.ips_with_independent_report, independent: true },
  ] })}
      <p class="tlab">フィード以外の通報がある IP — <strong>${K.ips_with_independent_report} / ${K.ips_in_cluster}</strong>（${K.ips_with_independent_report_pct}%）</p>
      ${chartTrack({ total: K.ips_in_cluster, parts: [
    { label: "被害者側の観測", value: K.ips_with_independent_report, independent: true },
  ] })}
    </div>`,
    tbl: table(["区分", "IP", "クラスタの"], [
      ["フィードだけ", K.ips_ever_reported - K.ips_with_independent_report,
        `${pct(K.ips_ever_reported - K.ips_with_independent_report, K.ips_in_cluster)}%`],
      ["被害者側の観測がある", K.ips_with_independent_report, `${K.ips_with_independent_report_pct}%`],
      ["通報なし", K.ips_never_reported, `${pct(K.ips_never_reported, K.ips_in_cluster)}%`],
      ["合計", K.ips_in_cluster, "100%"],
    ]),
  })}
  <ul class="pts">
    <li>${K.ips_never_reported} IP は一度も通報されていない。引けていない IP は ${K.ips_not_measured} 件なので、
      これは「分からない」ではなく「通報が無い」。</li>
    <li><strong>ただし通報が無いことは無害の証明ではない。</strong>誰も通報していないだけで、
      立てたばかりの基盤や、通報しない被害者しかいない基盤は同じ見た目になる。</li>
  </ul>
</section>

<section>
  <h2>3. 時間</h2>
  ${figure({
    id: "fig-days",
    title: "プールの消費は 25.5% で止まっている",
    note: `観測日ベース（${K.first_observed} 〜 ${K.last_observed}）。棒がその日の通報、`
      + `黒い線がその日までに通報された IP の累計。単位はどちらも件数なので 1 つの軸に載せている`,
    keys: [...KEYS, { cls: "cum", label: "通報された IP の累計" }],
    svg: chartDays({ rows: BY_DAY }),
    tbl: table(["観測日", "フィード", "被害者側", "累計 IP", "クラスタの"],
      BY_DAY.map((r) => [r.day, r.feed, r.indep, r.cumulative, `${pct(r.cumulative, K.ips_in_cluster)}%`])),
  })}
  <ul class="pts">
    <li>観測の窓は ${K.observation_window_days} 日。そのうち観測があったのは
      <strong>${K.days_with_any_observation} 日（${K.days_with_any_observation_pct}%）</strong>だけ。
      最後の観測から ${K.days_quiet_since_last_observation} 日。</li>
    <li>フィードの観測は 10-27 で止まっている（投稿は 11-04 まで続いた）。</li>
    <li>2 日以上に跨って通報された IP は ${K.ips_reported_on_multiple_days} 件。
      <strong>ただし同じ観測者の再通報が行として増えないので、「使い回していない」とは言えない。</strong></li>
  </ul>

  ${figure({
    id: "fig-backdate",
    title: "観測日は通報者の申告で、さかのぼれる",
    note: `投稿までの遅れ。通報が 1 件の ${BACKDATE.measured} IP でだけ測れる`,
    keys: KEYS,
    svg: chartVBar({ rows: BACKDATE.rows }),
    tbl: table(["投稿までの遅れ", "IP"], BACKDATE.rows.map((r) => [r.label, r.value])),
  })}
  <div class="cols">
    <div>
      <h4>2 つの日付を混ぜない</h4>
      <ul class="pts">
        <li><code>reportedAt</code> は通報者が申告した<strong>観測</strong>時刻。活動日として読むのはこちら。</li>
        <li><code>lastReportedAt</code> は AbuseIPDB が受け取った時刻（<strong>投稿</strong>）。活動日ではない。</li>
      </ul>
    </div>
    <div>
      <h4>だから過去の集計は確定しない</h4>
      <ul class="pts">
        <li>さかのぼりは中央 ${D.backdate_days_median} 日・最大 ${D.backdate_days_max} 日。
          投稿が観測より前になった例は ${D.submitted_before_observed} 件。</li>
        <li>10-30 に通報 0 件だった 14 IP が、11-06 には「10-27 観測」の通報を持っていた。</li>
      </ul>
    </div>
  </div>
</section>

<section>
  <h2>4. 見え方</h2>
  ${figure({
    id: "fig-score",
    title: "スコア閾値では、このクラスタは丸ごと通り抜ける",
    note: `${K.ips_in_cluster} IP 全体の分布。最大 ${K.score.max}、25 以上は ${K.score.ips_at_or_above_25} 件`,
    svg: chartVBar({ rows: Object.entries(K.score.histogram).map(([v, n]) =>
      ({ label: `スコア ${v}`, value: n })) }),
    tbl: table(["スコア", "IP"], Object.entries(K.score.histogram).map(([v, n]) => [v, n])),
  })}
  <ul class="pts">
    <li>スコア 0 が ${K.score.ips_at_zero} / ${K.ips_in_cluster} 件。中央値は ${K.score.median_all_255}。
      通報がある ${K.ips_ever_reported} 件に絞っても中央値は ${K.score.median_reported_only}。</li>
    <li><strong>25 以上は ${K.score.ips_at_or_above_25} 件、50 以上は ${K.score.ips_at_or_above_50} 件。</strong>
      スコアだけを閾値にする運用では検知できない。</li>
    <li>スコアは通報が増えなくても時間で下がる（実測で <code>198.200.59.85</code> が 18 → 16、
      通報は 3 件のまま）。横に比べるときは取得日を揃えること。</li>
  </ul>

  ${figure({
    id: "fig-prefix",
    title: "帯の偏りは、フィードにしか出ていない",
    note: "母数は /25 ごとに 125 IP ずつ。通報があった IP の数",
    keys: KEYS,
    svg: chartGrouped({
      groups: Object.keys(K.by_prefix).sort().map((p) => ({
        label: `${p}.x`,
        values: [
          { label: "フィード", value: K.by_prefix[p].feed_report_ips },
          { label: "被害者側", value: K.by_prefix[p].independent_report_ips, independent: true },
        ],
      })),
    }),
    tbl: table(["帯", "IP", "通報あり", "割合", "フィード", "被害者側", "連続区間"],
      Object.keys(K.by_prefix).sort().map((p) => {
        const v = K.by_prefix[p];
        return [`${p}.x`, v.ips, v.with_reports, v.too_small_for_pct ? "母数不足" : `${v.pct}%`,
          v.feed_report_ips, v.independent_report_ips, v.contiguous_runs];
      })),
  })}
  <ul class="pts">
    <li><code>38.11.173</code> が <code>38.11.221</code> の 2.4 倍
      （${K.by_prefix["38.11.173"].with_reports} 対 ${K.by_prefix["38.11.221"].with_reports}、母数は同じ 125）。</li>
    <li><strong>ところがフィードは ${K.by_prefix["38.11.173"].feed_report_ips} 対
      ${K.by_prefix["38.11.221"].feed_report_ips} で偏り、被害者側は
      ${K.by_prefix["38.11.173"].independent_report_ips} 対
      ${K.by_prefix["38.11.221"].independent_report_ips} で均等。</strong>
      「173 のほうが多く使われている」とは読めない。</li>
    <li>被害者側は ${K.ips_with_independent_report} IP しかないので、均等であること自体も強い証拠ではない。</li>
    <li>連続区間が ${K.by_prefix["38.11.173"].contiguous_runs} / ${K.by_prefix["38.11.221"].contiguous_runs} と多く、
      まとまったブロックではなく散っている。</li>
  </ul>

  ${figure({
    id: "fig-category",
    title: `攻撃手法が付いているのは ${CP.attack_technique_ips} IP`,
    note: "重複しない区分。1 つの IP に複数のカテゴリが付くので、カテゴリごとの数は足せない",
    keys: [{ cls: "ind", label: "攻撃手法が付いている" }, { cls: "feed", label: "補助情報だけ" }],
    svg: chartVBar({ rows: [
      { label: "攻撃手法", sub: "Web App Attack など", value: CP.attack_technique_ips, independent: true },
      { label: "偵察のみ", sub: "Port Scan", value: CP.reconnaissance_only_ips, independent: true },
      { label: "Exploited Host だけ", value: CP.exploited_host_only_ips },
    ] }),
    tbl: table(["区分", "IP", "クラスタの"], [
      ["攻撃手法が付いている", CP.attack_technique_ips, `${pct(CP.attack_technique_ips, K.ips_in_cluster)}%`],
      ["偵察のみ", CP.reconnaissance_only_ips, "—"],
      ["Exploited Host だけ", CP.exploited_host_only_ips, `${pct(CP.exploited_host_only_ips, K.ips_in_cluster)}%`],
      ["合計（= 通報がある IP）", CP.sum, `${K.ips_ever_reported_pct}%`],
    ]),
  })}
  <ul class="pts">
    <li><strong>Exploited Host（20）は攻撃手法ではない。</strong>それだけが付いている
      ${CP.exploited_host_only_ips} IP は「この送信元自体が侵害されている可能性」を言っているだけで、
      攻撃を観測した記録ではない。踏み台にされた正規ホストなら、送信元の持ち主も被害者。</li>
    <li>カテゴリごとに数えると 11 になるが、<code>198.200.59.85</code> には 14・15・20・21 の 4 つが付いている。
      <strong>足して読むと取り違える。</strong></li>
  </ul>
</section>

<section class="limits">
  <h2>5. この統計で言えないこと</h2>
  <ul class="pts">
    <li><strong>対象のサービスが動いているかは確認していない。</strong>接続・走査・認証試行を一切していないので、
      待ち受けているサービスも見ていない。利用者から渡された前提のまま。</li>
    <li><strong>攻撃に使われた時期は確定しない。</strong>さかのぼり投稿があるので、今日の集計は明日増える。
      <code>reports[]</code> は観測の下限しか示さない。</li>
    <li>フィード以外の観測者は ${K.independent_reporters} 人しかいない。
      「複数の被害者が独立に観測した」とまでは言えない。</li>
    <li>通報者がどういう人かは分からない。<code>reporterId</code> を保存しない方針なので、
      このクラスタの中での選択性しか見ていない。</li>
    <li>通報が無いことは無害の証明ではない。</li>
    <li>カテゴリと観測時刻はレポーターの自己申告。IP の所在地・ISP・AS は運用者の国籍や所属を示さない。</li>
    <li>母集団は渡された ${K.ips_in_cluster} IP だけ。同じ AS の他の帯は見ていない。</li>
  </ul>
</section>

<section>
  <h2>6. 次に打てる手</h2>
  <ol class="steps">
    <li><span class="done">済</span><div><strong>毎日追う仕組みを入れた</strong>
      <p><code>data/ioc/watch/</code> に 255 IP を登録。<code>IN-R04</code> の通報に気づくまで 6 日かかったので、
        初めてフィード以外の通報が付いた日を翌日に出す。</p></div></li>
    <li><span class="n">1</span><div><strong><code>198.200.59.85</code> を重点的に見る</strong>
      <p>クラスタの中心。最初に通報され（09-30）、フィード以外の観測者が 2 人付いている。
        ここが落ちるとクラスタ全体のリチャージが止まる。</p></div></li>
    <li><span class="n">2</span><div><strong><code>lastReportedAt</code> の動きを毎日記録する</strong>
      <p>投稿が続いている間はフィードがまだこの帯を追っている。
        <code>reports[]</code> だけ見ていると止まったように見える。</p></div></li>
    <li><span class="n">3</span><div><strong><code>visiblooths.net</code> を証明書の記録（CT ログ）で追う</strong>
      <p><code>.85</code> 〜 <code>.89</code> の 5 件が同じ命名規則なので、他の帯にも兄弟ホストが並んでいる可能性がある。</p></div></li>
    <li><span class="n">4</span><div><strong>同じ AS の他の帯を同じ手順で調べる</strong>
      <p>この 3 帯が特別なのか、もっと広いのかを確かめる。</p></div></li>
  </ol>
</section>

<footer class="ft">
  <p><strong>残していないもの</strong>　<code>reporterId</code> の値は保存していない
    （<code>BR-R01</code> のような識別子に置換し、同じ人かどうかだけが分かる）。
    通報コメントの原文は保存せず、無害化して短く切ったものと SHA-256 だけ残している。
    API キーはコンソール・ログ・CSV・JSON・ソース・エラーにも出していない。</p>
  <p class="meta">数字は <code>artex_timeline_summary.json</code> と CSV から読んでいる（この頁で数え直していない）。
    作り直すには <code>node reports/artex-timeline/page.mjs</code>。</p>
</footer>`;

const html = `<!doctype html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>クラスタ全体の統計 — sub2api-198.200.59.85</title>
<style>
/* 系列色は 2 色だけ。dataviz の検証器に明色・暗色の両方で通してある。
   「通報なし」は系列ではなく軌道なので、--track は系列色に数えない。 */
:root{
  color-scheme: light;
  --bg:#ffffff; --surface:#f4f6f8; --ink:#14181f; --ink-2:#5c6673; --ink-3:#8a94a3;
  --rule:#e3e7ec; --grid:#eceff3; --track:#e8eaed;
  --ind:#B3202C; --feed:#2E6B9E; --cum:#14181f;
  --maxw:1080px;
}
@media (prefers-color-scheme: dark){
  :root:not([data-theme="light"]){
    color-scheme: dark;
    --bg:#14181f; --surface:#1b2029; --ink:#eef1f5; --ink-2:#b4bdc9; --ink-3:#8a94a3;
    --rule:#2a313c; --grid:#232933; --track:#2a313c;
    --ind:#D9544E; --feed:#4E9AD6; --cum:#eef1f5;
  }
}
:root[data-theme="dark"]{
  color-scheme: dark;
  --bg:#14181f; --surface:#1b2029; --ink:#eef1f5; --ink-2:#b4bdc9; --ink-3:#8a94a3;
  --rule:#2a313c; --grid:#232933; --track:#2a313c;
  --ind:#D9544E; --feed:#4E9AD6; --cum:#eef1f5;
}
*{box-sizing:border-box}
body{
  margin:0; background:var(--bg); color:var(--ink);
  font:16px/1.75 "Hiragino Kaku Gothic ProN","Hiragino Sans","Noto Sans JP",
    "Yu Gothic","Meiryo",system-ui,-apple-system,"Segoe UI",sans-serif;
  -webkit-text-size-adjust:100%;
}
.wrap{max-width:var(--maxw); margin:0 auto; padding:0 16px 72px}
h1{font-size:2.3rem; line-height:1.25; margin:.1em 0 .3em; letter-spacing:.01em}
h2{font-size:1.45rem; margin:2.6em 0 .2em; padding-bottom:.35em; border-bottom:1px solid var(--rule)}
h3{font-size:1.12rem; margin:0 0 .15em}
h4{font-size:1rem; margin:1.4em 0 .3em}
p{margin:.5em 0}
code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; font-size:.92em;
  background:var(--surface); padding:.1em .35em; border-radius:4px}
.hd{padding:48px 0 8px}
.eyebrow{color:var(--ink-2); font-size:.85rem; letter-spacing:.14em; margin:0}
.lead{font-size:1.05rem; color:var(--ink); max-width:72ch}
.meta{color:var(--ink-2); font-size:.86rem; max-width:80ch}
.pts{margin:.6em 0 0; padding-left:1.25em; max-width:80ch}
.pts li{margin:.4em 0}
/* 数の札。**母数を必ず見せる** */
.stats{display:grid; gap:12px; grid-template-columns:repeat(auto-fit,minmax(210px,1fr)); margin:18px 0 6px}
.stat{background:var(--surface); border-radius:10px; padding:16px 18px}
.num{font-size:2.6rem; font-weight:700; line-height:1.1; letter-spacing:-.01em}
.num.ind{color:var(--ind)}
.den{font-size:1rem; font-weight:400; color:var(--ink-2)}
.lab{font-weight:700; font-size:.95rem; margin-top:.2em}
.sub{color:var(--ink-2); font-size:.84rem}
/* 図 */
.fig{margin:28px 0 8px; padding:0}
.fig figcaption{margin-bottom:.4em}
.fig .note{color:var(--ink-2); font-size:.88rem; margin:.1em 0 0; max-width:80ch}
.plot{margin-top:10px}
.plot svg{width:100%; height:auto; display:block}
.legend{display:flex; flex-wrap:wrap; gap:16px; margin-top:10px}
.key{display:inline-flex; align-items:center; gap:7px; font-size:.86rem; color:var(--ink-2)}
.sw{width:12px; height:12px; border-radius:3px; display:inline-block}
.sw.ind{background:var(--ind)} .sw.feed{background:var(--feed)}
.sw.track{background:var(--track)} .sw.cum{background:var(--cum); border-radius:50%}
/* 印。細く、先だけ丸める */
.mark.ind{fill:var(--ind)} .mark.feed{fill:var(--feed)}
.mark{transition:opacity .12s}
.plot:hover .mark{opacity:.55}
.plot .mark:hover{opacity:1}
.track{fill:var(--track)}
.grid{stroke:var(--grid); stroke-width:1}
.line{fill:none; stroke:var(--cum); stroke-width:2; stroke-linejoin:round}
.dot{fill:var(--cum); stroke:var(--bg); stroke-width:2}
text{font-family:inherit}
.axis{fill:var(--ink-3); font-size:12px}
.axis.sub{font-size:11px}
.cat{fill:var(--ink-2); font-size:13px}
.val{fill:var(--ink); font-size:12px; font-weight:600}
.trackbar{height:46px}
.tracks .tlab{margin:14px 0 6px; font-size:.92rem}
/* 表。色だけに頼らせない */
.tbl{margin-top:12px}
.tbl summary{cursor:pointer; color:var(--ink-2); font-size:.86rem; width:max-content}
.tbl table{border-collapse:collapse; margin-top:8px; font-size:.88rem; width:100%}
.tbl th,.tbl td{border-bottom:1px solid var(--rule); padding:6px 10px; text-align:right}
.tbl thead th{color:var(--ink-2); font-weight:600; border-bottom:1px solid var(--ink-3)}
.tbl th[scope=row], .tbl thead th:first-child{text-align:left}
.cols{display:grid; gap:24px; grid-template-columns:repeat(auto-fit,minmax(280px,1fr)); margin-top:10px}
.limits{background:var(--surface); border-radius:12px; padding:4px 24px 20px; margin-top:2.4em}
.limits h2{border-bottom:none; margin-top:1.2em}
/* 次の手 */
.steps{list-style:none; margin:14px 0 0; padding:0}
.steps li{display:flex; gap:14px; align-items:flex-start; margin:0 0 18px}
.steps span{flex:0 0 auto; width:28px; height:28px; border-radius:50%; display:grid; place-items:center;
  color:#fff; font-size:.82rem; font-weight:700; margin-top:2px}
.steps .done{background:var(--ind); font-size:.72rem}
.steps .n{background:var(--feed)}
.steps p{margin:.15em 0 0; color:var(--ink-2); font-size:.92rem; max-width:78ch}
.ft{margin-top:3em; padding-top:1.2em; border-top:1px solid var(--rule); color:var(--ink-2); font-size:.88rem}
/* 当たり判定は印より大きく */
#tip{position:fixed; z-index:9; pointer-events:none; background:var(--ink); color:var(--bg);
  padding:6px 10px; border-radius:6px; font-size:.82rem; line-height:1.4; opacity:0;
  transition:opacity .1s; max-width:280px}
#tip b{display:block; font-weight:600}
.themer{position:fixed; top:12px; right:12px; z-index:10; background:var(--surface); color:var(--ink-2);
  border:1px solid var(--rule); border-radius:999px; padding:6px 14px; font:inherit; font-size:.8rem; cursor:pointer}
@media print{
  .themer,#tip{display:none}
  .tbl[open] summary{display:none}
  body{background:#fff; color:#000}
  section{break-inside:avoid-page}
}
@media (max-width:640px){
  h1{font-size:1.7rem} h2{font-size:1.2rem} .num{font-size:2.1rem}
  .wrap{padding:0 16px 48px}
}
</style>
</head>
<body>
<button class="themer" id="themer" type="button">明暗を切り替え</button>
<div class="wrap">${body}</div>
<div id="tip" role="status" aria-live="polite"></div>
<script>
(function(){
  // 明暗の切り替え。OS の設定を既定にし、押したらその選択が勝つ
  var b=document.getElementById("themer");
  b.addEventListener("click",function(){
    var dark=matchMedia("(prefers-color-scheme: dark)").matches;
    var cur=document.documentElement.getAttribute("data-theme")||(dark?"dark":"light");
    document.documentElement.setAttribute("data-theme",cur==="dark"?"light":"dark");
  });
  // 図の当たり判定。印そのものより広く取る
  var tip=document.getElementById("tip");
  function show(e){
    var t=e.target.closest("[data-tip]"); if(!t){hide();return;}
    tip.innerHTML="<b>"+t.getAttribute("data-tip")+"</b>"+t.getAttribute("data-val");
    tip.style.opacity="1";
    var x=e.clientX+14,y=e.clientY+14;
    var r=tip.getBoundingClientRect();
    if(x+r.width>innerWidth-8)x=e.clientX-r.width-14;
    if(y+r.height>innerHeight-8)y=e.clientY-r.height-14;
    tip.style.left=x+"px"; tip.style.top=y+"px";
  }
  function hide(){tip.style.opacity="0";}
  document.querySelectorAll(".plot").forEach(function(p){
    p.addEventListener("mousemove",show);
    p.addEventListener("mouseleave",hide);
  });
})();
</script>
</body>
</html>`;

fs.writeFileSync(OUT, html);
console.log(`→ ${path.relative(path.resolve(HERE, "../.."), OUT)}`
  + `（${(Buffer.byteLength(html) / 1024).toFixed(0)} KB / 外部読み込みなし）`);
console.log(`  ${K.ips_in_cluster} IP / 通報 ${K.reports_total} 件 / 観測者 ${K.distinct_reporters_cluster_wide} 人`);
