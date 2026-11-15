#!/usr/bin/env node
// 255 IP クラスタの**推移**と**通報理由**を 1 枚の HTML にする。
//
//   node reports/artex-timeline/trend.mjs [--out artex_timeline_trend.html]
//
// **写しだけを読む。API は呼ばない。対象 IP への接続・走査・認証試行もしない。**
//
// ## なぜ page.mjs と別なのか
//
// `page.mjs` は `artex_timeline_summary.json`（**2026-11-06 の取得**）を読む。
// あれはあの日のクラスタ統計として正しいが、**推移は見られない**。
// 推移を見るには複数の取得日が要る。それを持っているのは毎日の監視のほう:
//
//   data/ioc/watch/observations/<取得日>.jsonl   255 IP × 9 日ぶん
//
// **1 つの頁に 2 つの基準日を混ぜない。** だから別ファイルにして、
// この頁は監視の写しだけを出所にする。
//
// ## 「推移」には 2 つの意味があり、混ぜてはいけない
//
//   (A) 活動の推移      通報者が申告した観測日（reported_at）ごとの通報数
//   (B) 視界の推移      取得日ごとに「こちらに見えていた」量
//
// (B) は (A) の遅れた像でしかない。AbuseIPDB の投稿は**さかのぼれる**ので、
// 過去の日の集計は確定しない（実測: フィードの投稿は中央 1.49 日・最大 7.32 日
// 遅れて届く）。**(B) の増加を「攻撃が増えた」と読むのが最も多い誤り。**
// 両方を別の図にして、間に遅れの分布を挟む。
//
// ## 色
//
// dataviz の参照カテゴリ順（スロット 1〜4）をそのまま使い、検証器に通してある。
// 地は明色 #ffffff / 暗色 #14181f。**隣接対のリストで全項目 PASS。**
//
//   明色  1 #2a78d6  2 #eb6834  3 #1baf7a  4 #eda100
//         隣接最悪 CVD ΔE 9.1・通常視 22.9 ／ 1-2 は全対でも ΔE 24.7・33.6
//   暗色  1 #3987e5  2 #d95926  3 #199e70  4 #c98500
//         隣接最悪 CVD ΔE 8.4・通常視 19.8 ／ 1-2 は全対でも ΔE 26.8・31.8
//
// 明色のスロット 3・4 は地とのコントラストが 3:1 を割る（2.82 / 2.17）。
// **救済規則**に従い、値の直接ラベルと表を必ず添える。
//
// 色は**理由と出所に固定**し、順位では決めない。並べ替えや窓の切り替えで
// 色が塗り替わらないようにするため。
//   スロット1 = フィードの一括登録 / Exploited Host(20)
//   スロット2 = フィード以外の通報 / Web App Attack(21)
//   スロット3 = Hacking(15)   スロット4 = Port Scan(14)
// これ以外のカテゴリが現れたら「その他」に畳む（5 色目は検証していない）。
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { CATEGORIES } from "../global-jp-vuln/rules.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "../..");
const argv = process.argv.slice(2);
const outArg = argv.indexOf("--out");
const OUT = path.join(HERE, outArg >= 0 ? argv[outArg + 1] : "artex_timeline_trend.html");
const AS_JSON = argv.includes("--json");

/* ---------------- 写しを読む ---------------- */

const OBS_DIR = path.join(ROOT, "data/ioc/watch/observations");
const WATCHLIST = path.join(ROOT, "data/ioc/watch/watchlist.json");

const readJsonl = (p) => fs.readFileSync(p, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));

const wl = JSON.parse(fs.readFileSync(WATCHLIST, "utf8"));
const cluster = wl.clusters[0];
/** 一括フィードの見分けは**宣言から読む**。ここに書き写さない */
const feedShapes = wl.feed_shapes || [];
const isFeed = (shape) => feedShapes.some((f) => String(shape || "").includes(f));

const files = fs.readdirSync(OBS_DIR).filter((f) => /^\d{4}-\d{2}-\d{2}\.jsonl$/.test(f)).sort();
if (!files.length) {
  console.error(`${path.relative(ROOT, OBS_DIR)} に観測の写しがありません。`
    + "先に node tools/ioc/fetch-watch.mjs を実行してください。");
  process.exit(1);
}
/** 取得日 → その日の 255 IP ぶんのレコード */
const fetches = files.map((f) => ({ day: f.slice(0, 10), rows: readJsonl(path.join(OBS_DIR, f)) }));
const LATEST = fetches[fetches.length - 1];
const ANCHOR = LATEST.day;
/** **10-30 の写しだけは当時の CSV からの復元**。形の畳み方が取得ぶんと厳密には一致しない */
const reconstructed = new Set(fetches.filter((f) => f.rows.some((r) => r.source === "reconstructed_from_snapshot"))
  .map((f) => f.day));

/* ---------------- 数える ---------------- */

/** 1 通報 = 1 行に開く。`by_report` は AbuseIPDB の reports[] 由来 */
const reportsOf = (f) => f.rows.flatMap((r) => (r.by_report || []).map((b) => ({
  ip: r.ip, day: String(b.observed_at).slice(0, 10), cats: (b.cats || []).slice().sort((a, c) => a - c),
  cc: b.cc || "", feed: isFeed(b.shape), shape: b.shape || "",
})));

const LATEST_REPORTS = reportsOf(LATEST);

/** (A) 活動の推移。**reported_at（申告された観測日）で数える** */
const ACTIVITY = (() => {
  const by = new Map();
  for (const r of LATEST_REPORTS) {
    if (!by.has(r.day)) by.set(r.day, { day: r.day, feed: 0, indep: 0, ips: new Set(), ccs: new Set() });
    const d = by.get(r.day);
    d[r.feed ? "feed" : "indep"] += 1;
    d.ips.add(r.ip); d.ccs.add(r.cc);
  }
  return [...by.values()].sort((a, b) => a.day.localeCompare(b.day))
    .map((d) => ({ ...d, ips: d.ips.size, ccs: [...d.ccs].sort().join(",") }));
})();

/** (B) 視界の推移。取得日ごとに**その時点で見えていた**量 */
const VIEW = fetches.map((f) => {
  const rs = reportsOf(f);
  const days = [...new Set(rs.map((r) => r.day))].sort();
  return {
    fetch: f.day,
    ips: f.rows.length,
    reported_ips: f.rows.filter((r) => (r.reports || 0) > 0).length,
    feed: rs.filter((r) => r.feed).length,
    indep: rs.filter((r) => !r.feed).length,
    reports: rs.length,
    indep_ips: new Set(rs.filter((r) => !r.feed).map((r) => r.ip)).size,
    obs_days: days.length,
    latest_obs: days[days.length - 1] || "",
    max_score: f.rows.reduce((a, r) => Math.max(a, r.score || 0), 0),
    reconstructed: reconstructed.has(f.day),
  };
});

/** さかのぼり行列。観測日 × 取得日。**過去の日の集計が確定しないことの証拠** */
const MATRIX = (() => {
  const perFetch = fetches.map((f) => {
    const m = new Map();
    for (const r of reportsOf(f)) m.set(r.day, (m.get(r.day) || 0) + 1);
    return { fetch: f.day, m };
  });
  const days = [...new Set(LATEST_REPORTS.map((r) => r.day))].sort();
  return {
    fetch_days: perFetch.map((p) => p.fetch),
    rows: days.map((d) => ({
      day: d, counts: perFetch.map((p) => p.m.get(d) ?? null),
      final: perFetch[perFetch.length - 1].m.get(d) ?? 0,
    })),
  };
})();

/** 投稿の遅れ。**通報が 1 件の IP でしか測れない**（2 件以上だとどちらの投稿か分からない） */
const LAG = (() => {
  const bins = [
    { label: "1 時間未満", lo: 0, hi: 1 / 24 },
    { label: "1 日未満", lo: 1 / 24, hi: 1 },
    { label: "1〜2 日", lo: 1, hi: 2 },
    { label: "2〜4 日", lo: 2, hi: 4 },
    { label: "4 日以上", lo: 4, hi: Infinity },
  ];
  const take = (wantFeed) => LATEST.rows
    .filter((r) => (r.by_report || []).length === 1 && typeof r.backdate_days === "number"
      && isFeed(r.by_report[0].shape) === wantFeed)
    .map((r) => r.backdate_days).sort((a, b) => a - b);
  const feed = take(true), indep = take(false);
  const q = (a, p) => (a.length ? a[Math.floor((a.length - 1) * p)] : null);
  return {
    bins: bins.map((b) => ({
      label: b.label,
      feed: feed.filter((v) => v >= b.lo && v < b.hi).length,
      indep: indep.filter((v) => v >= b.lo && v < b.hi).length,
    })),
    feed: { n: feed.length, median: q(feed, 0.5), max: feed[feed.length - 1] ?? null },
    indep: { n: indep.length, median: q(indep, 0.5), max: indep[indep.length - 1] ?? null },
    measurable: feed.length + indep.length,
    reported_ips: LATEST.rows.filter((r) => (r.reports || 0) > 0).length,
  };
})();

/**
 * 通報理由。**1 件が複数の理由を持つので、理由の合計は通報数を超える。**
 * 窓は取得日（ANCHOR）から数える。
 */
const SLOT = { 20: 1, 21: 2, 15: 3, 14: 4 };
const nameOf = (c) => CATEGORIES[c] || `unknown(${c})`;
const tallyReasons = (rs) => {
  const m = new Map(); let other = 0;
  for (const r of rs) {
    for (const c of r.cats) {
      if (SLOT[c]) m.set(c, (m.get(c) || 0) + 1);
      else other += 1;
    }
  }
  const rows = [...m].sort((a, b) => b[1] - a[1] || a[0] - b[0])
    .map(([c, n]) => ({ cat: c, label: nameOf(c), slot: SLOT[c], value: n }));
  if (other) rows.push({ cat: null, label: "その他", slot: 0, value: other });
  return { rows, reports: rs.length, other };
};
const windowFrom = (days) => {
  const cut = new Date(Date.parse(ANCHOR) - days * 86400000).toISOString().slice(0, 10);
  return { cut, rs: LATEST_REPORTS.filter((r) => r.day > cut) };
};
const W14 = windowFrom(14), W7 = windowFrom(7);
const REASONS = {
  all: tallyReasons(LATEST_REPORTS),
  w14: { ...tallyReasons(W14.rs), cut: W14.cut, days: 14 },
  w7: { ...tallyReasons(W7.rs), cut: W7.cut, days: 7 },
};

/** 理由 × 出所。**「最も多い理由」が誰の言い分なのかを分ける** */
const REASON_BY_SOURCE = (() => {
  const m = new Map();
  for (const r of LATEST_REPORTS) {
    for (const c of r.cats) {
      if (!m.has(c)) m.set(c, { cat: c, label: nameOf(c), slot: SLOT[c] || 0, feed: 0, indep: 0 });
      m.get(c)[r.feed ? "feed" : "indep"] += 1;
    }
  }
  return [...m.values()].sort((a, b) => (b.feed + b.indep) - (a.feed + a.indep) || a.cat - b.cat);
})();

const REPORTERS = (() => {
  const m = new Map();
  for (const r of LATEST_REPORTS) {
    const k = `${r.cc}|${r.feed}`;
    if (!m.has(k)) m.set(k, { cc: r.cc, feed: r.feed, reports: 0, ips: new Set(), cats: new Set(), days: new Set() });
    const v = m.get(k);
    v.reports += 1; v.ips.add(r.ip); v.days.add(r.day);
    for (const c of r.cats) v.cats.add(c);
  }
  return [...m.values()].sort((a, b) => b.reports - a.reports)
    .map((v) => ({ ...v, ips: v.ips.size, days: v.days.size,
      cats: [...v.cats].sort((a, b) => a - b).map(nameOf).join("・") }));
})();

const FACTS = {
  generated_from: "data/ioc/watch/observations/*.jsonl（写しのみ。API は呼んでいない）",
  anchor: ANCHOR, fetch_days: VIEW.length, ips: LATEST.rows.length,
  cluster: cluster.name, service_port: cluster.service_port,
  activity: ACTIVITY, view: VIEW, matrix: MATRIX, lag: LAG,
  reasons: REASONS, reason_by_source: REASON_BY_SOURCE, reporters: REPORTERS,
  jp_reports: LATEST.rows.reduce((a, r) => a + (r.jp_reports || 0), 0),
};

if (AS_JSON) {
  const stable = (v) => (v && typeof v === "object" && !Array.isArray(v)
    ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, stable(v[k])]))
    : Array.isArray(v) ? v.map(stable) : v);
  console.log(JSON.stringify(stable(FACTS), null, 2));
  process.exit(0);
}

/* ---------------- SVG の部品 ---------------- */

const esc = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;")
  .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
const barPathV = (x, y, w, h, r) => {
  const rr = Math.min(r, h, w / 2);
  if (h <= 0.5) return `M${x} ${y + h} h${w} v${-Math.max(h, 0.5)} h${-w} Z`;
  return `M${x} ${y + h} v${-(h - rr)} a${rr} ${rr} 0 0 1 ${rr} ${-rr} h${w - 2 * rr}`
    + ` a${rr} ${rr} 0 0 1 ${rr} ${rr} v${h - rr} Z`;
};
const barPathH = (x, y, w, h, r) => {
  const rr = Math.min(r, w, h / 2);
  if (w <= 0.5) return `M${x} ${y} h${Math.max(w, 0.5)} v${h} h${-Math.max(w, 0.5)} Z`;
  return `M${x} ${y} h${w - rr} a${rr} ${rr} 0 0 1 ${rr} ${rr} v${h - 2 * rr}`
    + ` a${rr} ${rr} 0 0 1 ${-rr} ${rr} h${-(w - rr)} Z`;
};
/** 目盛り。**最後の目盛りは必ず最大値以上**（下回ると棒が枠を突き抜ける） */
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
const svg = (W, H, g, ratio = "xMidYMid meet") =>
  `<svg viewBox="0 0 ${W} ${H}" role="img" preserveAspectRatio="${ratio}">${g}</svg>`;

const DAY = 86400000;
const dnum = (d) => Date.parse(d) / DAY;

/**
 * 積み上げ縦棒を**実時間軸**に置く。
 *
 * 日付の間隔が空いているのに等幅のカテゴリ軸で並べると、**間が詰まって見えて
 * 推移を誤読させる**（09-30 の次が 10-17 でも隣に見える）。横の位置は必ず日付。
 *
 * 値のラベルは**選んで付ける**。隣の日と重なるときは落とし、表と吹き出しに任せる。
 */
function chartStackedTime({ rows, dayOf, labelOf, unit = "件", tickEvery = 7 }) {
  const W = 760, H = 320, padL = 40, padR = 16, padT = 26, padB = 60;
  const plotW = W - padL - padR, plotH = H - padT - padB;
  const days = rows.map((r) => dnum(dayOf(r)));
  const d0 = Math.min(...days), d1 = Math.max(...days);
  const span = Math.max(d1 - d0, 1);
  const xOf = (d) => padL + (plotW * (dnum(d) - d0)) / span;
  const bw = Math.max(6, Math.min(40, (plotW / (span + 1)) * 0.78));
  const ticks = niceTicks(Math.max(...rows.map((r) => r.feed + r.indep)), 4);
  const top = ticks[ticks.length - 1] || 1;
  const yOf = (v) => padT + plotH - (plotH * v) / top;
  let g = "";
  for (const t of ticks) {
    g += `<line class="grid" x1="${padL}" y1="${yOf(t)}" x2="${W - padR}" y2="${yOf(t)}"/>`
      + `<text class="axis" x="${padL - 9}" y="${yOf(t) + 4}" text-anchor="end">${t}</text>`;
  }
  // 日付の目盛り。**最初の観測日から等間隔**に置き、最後の日は必ず出す
  const tickDays = [];
  for (let d = d0; d <= d1 + 1e-9; d += tickEvery) tickDays.push(d);
  if (d1 - tickDays[tickDays.length - 1] > tickEvery * 0.35) tickDays.push(d1);
  else tickDays[tickDays.length - 1] = d1;
  for (const d of tickDays) {
    const iso = new Date(d * DAY).toISOString().slice(0, 10);
    const x = padL + (plotW * (d - d0)) / span;
    g += `<text class="axis" x="${x}" y="${padT + plotH + 17}" text-anchor="end"`
      + ` transform="rotate(-42 ${x} ${padT + plotH + 17})">${esc(iso.slice(5))}</text>`;
  }
  const sorted = rows.slice().sort((a, b) => dnum(dayOf(a)) - dnum(dayOf(b)));
  for (const r of sorted) {
    const cx = xOf(dayOf(r));
    const x = cx - bw / 2;
    const tot = r.feed + r.indep;
    if (r.feed > 0) {
      g += `<path class="mark c1" d="${barPathV(x, yOf(r.feed), bw, (plotH * r.feed) / top, 4)}"`
        + tip(`${labelOf(r)} フィードの一括登録`, `${r.feed} ${unit}`) + "/>";
    }
    if (r.indep > 0) {
      const h = Math.max((plotH * r.indep) / top - (r.feed > 0 ? 2 : 0), 1);
      g += `<path class="mark c2" d="${barPathV(x, yOf(tot), bw, h, 4)}"`
        + tip(`${labelOf(r)} フィード以外の通報`, `${r.indep} ${unit}`) + "/>";
    }
  }
  // **全部には付けない。**大きいものから置き、先に置いたラベルと重なるものだけ落とす
  // （左から順に置くと、小さい棒が隣の最大の棒のラベルを押し出す）
  // 重なったら 1 段上げて置き直す。それでも重なるものだけ落とす
  const claimed = [[], []];
  for (const r of rows.slice().sort((a, b) => (b.feed + b.indep) - (a.feed + a.indep)
    || dnum(dayOf(a)) - dnum(dayOf(b)))) {
    const tot = r.feed + r.indep;
    const cx = xOf(dayOf(r));
    const half = (String(tot).length * 7) / 2 + 4;
    const lane = claimed.findIndex((row) => !row.some((c) => Math.abs(c - cx) < half * 2));
    if (lane < 0) continue;
    claimed[lane].push(cx);
    const y = yOf(tot) - 7 - lane * 15;
    // 左端の棒のラベルが**縦軸の目盛りに被る**ので、枠の内側へ寄せる
    const lx = Math.min(Math.max(cx, padL + half), W - padR - half);
    g += `<text class="val" x="${lx}" y="${Math.max(y, padT + 9)}" text-anchor="middle">${tot}</text>`;
  }
  return svg(W, H, g);
}

/** 並べた縦棒。**母数が違う 2 系列なので、割合ではなく件数を出す** */
function chartGroupedBins({ bins, unit = "IP" }) {
  const W = 760, H = 290, padL = 40, padR = 14, padT = 26, padB = 44;
  const plotW = W - padL - padR, plotH = H - padT - padB;
  const ticks = niceTicks(Math.max(...bins.flatMap((b) => [b.feed, b.indep])), 4);
  const top = ticks[ticks.length - 1] || 1;
  const yOf = (v) => padT + plotH - (plotH * v) / top;
  const slot = plotW / bins.length;
  const bw = Math.min(54, (slot * 0.62) / 2);
  let g = "";
  for (const t of ticks) {
    g += `<line class="grid" x1="${padL}" y1="${yOf(t)}" x2="${W - padR}" y2="${yOf(t)}"/>`
      + `<text class="axis" x="${padL - 9}" y="${yOf(t) + 4}" text-anchor="end">${t}</text>`;
  }
  bins.forEach((b, i) => {
    const cx = padL + slot * (i + 0.5);
    [["c1", "フィード", b.feed], ["c2", "フィード以外", b.indep]].forEach(([cls, nm, v], j) => {
      const x = cx - bw - 1 + j * (bw + 2);
      if (v > 0) {
        g += `<path class="mark ${cls}" d="${barPathV(x, yOf(v), bw, (plotH * v) / top, 4)}"`
          + tip(`${b.label} ${nm}`, `${v} ${unit}`) + "/>";
      }
      g += `<text class="val" x="${x + bw / 2}" y="${yOf(v) - 7}" text-anchor="middle">${v}</text>`;
    });
    g += `<text class="axis" x="${cx}" y="${padT + plotH + 21}" text-anchor="middle">${esc(b.label)}</text>`;
  });
  return svg(W, H, g);
}

/** 理由の横棒。**色は理由に固定**。順位で塗り替えない */
function chartReasons({ rows, total, scale, unit = "件" }) {
  const W = 760, rowH = 46, padL = 170, padR = 72, padT = 8;
  const H = padT + Math.max(rows.length, 1) * rowH + 32;
  const plotW = W - padL - padR;
  // **横に並べる 2 枚は目盛りを揃える。**別々だと 56 と 114 が同じ長さに見える
  const ticks = niceTicks(scale || total, 5);
  const top = ticks[ticks.length - 1] || 1;
  let g = "";
  for (const t of ticks) {
    const x = padL + (plotW * t) / top;
    g += `<line class="grid" x1="${x}" y1="${padT}" x2="${x}" y2="${padT + rows.length * rowH}"/>`
      + `<text class="axis" x="${x}" y="${padT + rows.length * rowH + 19}" text-anchor="middle">${t}</text>`;
  }
  rows.forEach((r, i) => {
    const y = padT + i * rowH + 9;
    const bh = rowH - 22;
    const w = (plotW * r.value) / top;
    g += `<text class="cat" x="${padL - 12}" y="${y + bh / 2 + 4}" text-anchor="end">${esc(r.label)}</text>`
      + `<rect class="track" x="${padL}" y="${y}" width="${plotW}" height="${bh}" rx="4"/>`
      + `<path class="mark c${r.slot}" d="${barPathH(padL, y, w, bh, 4)}"`
      + tip(r.label, `${r.value} / ${total} ${unit}（${((100 * r.value) / total).toFixed(1)}%）`) + "/>"
      + `<text class="val" x="${padL + w + 8}" y="${y + bh / 2 + 4}">${r.value}`
      + `<tspan class="pct"> (${((100 * r.value) / total).toFixed(0)}%)</tspan></text>`;
  });
  if (!rows.length) {
    g += `<text class="cat" x="${padL}" y="${padT + 24}">この窓には通報がない</text>`;
  }
  return svg(W, H, g);
}

/** 理由 × 出所の帯。**軌道は系列ではない** */
function chartSourceSplit({ rows }) {
  const W = 760, rowH = 42, padL = 170, padR = 90, padT = 6;
  const H = padT + rows.length * rowH + 6;
  const plotW = W - padL - padR;
  const top = Math.max(...rows.map((r) => r.feed + r.indep));
  let g = "";
  rows.forEach((r, i) => {
    const y = padT + i * rowH + 7;
    const bh = rowH - 18;
    const wf = (plotW * r.feed) / top, wi = (plotW * r.indep) / top;
    g += `<text class="cat" x="${padL - 12}" y="${y + bh / 2 + 4}" text-anchor="end">${esc(r.label)}</text>`
      + `<rect class="track" x="${padL}" y="${y}" width="${plotW}" height="${bh}" rx="4"/>`;
    if (r.feed > 0) {
      g += `<path class="mark c1" d="${barPathH(padL, y, wf, bh, 4)}"`
        + tip(`${r.label} フィードの一括登録`, `${r.feed} 件`) + "/>";
    }
    if (r.indep > 0) {
      g += `<path class="mark c2" d="${barPathH(padL + wf + (r.feed > 0 ? 2 : 0), y, Math.max(wi - (r.feed > 0 ? 2 : 0), 1), bh, 4)}"`
        + tip(`${r.label} フィード以外の通報`, `${r.indep} 件`) + "/>";
    }
    g += `<text class="val" x="${padL + wf + wi + 8}" y="${y + bh / 2 + 4}">`
      + `${r.feed} / ${r.indep}</text>`;
  });
  return svg(W, H, g);
}

/* ---------------- 頁の部品 ---------------- */

const legend = (items) => `<div class="legend">` + items.map((i) =>
  `<span class="key"><i class="sw ${i.cls}"></i>${esc(i.label)}</span>`).join("") + `</div>`;
const table = (head, rows) => `<details class="tbl"><summary>数字で見る</summary>`
  + `<table><thead><tr>${head.map((h) => `<th>${esc(h)}</th>`).join("")}</tr></thead><tbody>`
  + rows.map((r) => `<tr>${r.map((c, i) => (i === 0 ? `<th scope="row">${esc(c)}</th>`
    : `<td>${esc(c)}</td>`)).join("")}</tr>`).join("")
  + `</tbody></table></details>`;
const figure = ({ id, title, note, svg: s, keys, tbl }) => `
<figure class="fig" id="${id}">
  <figcaption><h3>${title}</h3>${note ? `<p class="note">${note}</p>` : ""}</figcaption>
  ${keys ? legend(keys) : ""}
  <div class="plot">${s}</div>
  ${tbl || ""}
</figure>`;
const stat = ({ value, denom, label, note, alt }) => `
<div class="stat">
  <div class="num ${alt ? "alt" : ""}">${esc(value)}${denom ? `<span class="den"> / ${esc(denom)}</span>` : ""}</div>
  <div class="lab">${esc(label)}</div>
  ${note ? `<div class="sub">${esc(note)}</div>` : ""}
</div>`;

const SRC_KEYS = [
  { cls: "c1", label: "フィードの一括登録（ICS Labs）" },
  { cls: "c2", label: "フィード以外の通報" },
];
const reasonKeys = (rows) => rows.map((r) => ({ cls: `c${r.slot}`, label: r.label }));

/* ---------------- 組み立てる ---------------- */

const A = ACTIVITY, V = VIEW;
const first = V[0], last = V[V.length - 1];
const totalReports = last.reports;
const pct = (n, d) => (d ? ((100 * n) / d).toFixed(1) : "—");
const dayMd = (d) => d.slice(5);
const topReason = REASONS.all.rows[0];
const topRecent = REASONS.w14.rows[0];
const ehSplit = REASON_BY_SOURCE.find((r) => r.cat === 20);
const lastActivity = A[A.length - 1].day;
const quietDays = Math.round((Date.parse(ANCHOR) - Date.parse(lastActivity)) / 86400000);
/** 取得していない日。**「棒が無い＝0 件」ではない**ことを図の注に書くため */
const MISSING_FETCH = (() => {
  const have = new Set(V.map((v) => v.fetch));
  const out = [];
  for (let d = Date.parse(V[0].fetch); d <= Date.parse(ANCHOR); d += 86400000) {
    const iso = new Date(d).toISOString().slice(0, 10);
    if (!have.has(iso)) out.push(iso.slice(5));
  }
  return out;
})();

const body = `
<header class="hd">
  <p class="eyebrow">AbuseIPDB 上の通報 — 推移と通報理由</p>
  <h1>${esc(cluster.name)}</h1>
  <p class="lead">${LATEST.rows.length} IP を 1 つのクラスタとして見た推移。
    全 IP で ${cluster.service_port}/tcp に ARTEX が上がっており、sub2api があり、
    同じリチャージ URL (198.200.59.85) がセットされている（利用者が個別に確認済み）。</p>
  <p class="meta">出所 <code>data/ioc/watch/observations/</code>（${V.length} 取得日 ×
    ${LATEST.rows.length} IP、${first.fetch}〜${ANCHOR}）／
    <strong>対象 IP への接続・走査・認証試行は一切していない</strong>／
    この文書は Claude（AI）が自動生成したもので、人の確認を前提とする</p>
</header>

<section>
  <h2>1. 要点</h2>
  <div class="stats">
    ${stat({ value: totalReports, label: "通報の総数",
    note: `${ANCHOR} 時点。フィード ${last.feed} / それ以外 ${last.indep}` })}
    ${stat({ value: last.reported_ips, denom: LATEST.rows.length, label: "通報のある IP",
    note: `${pct(last.reported_ips, LATEST.rows.length)}%。${first.fetch} は ${first.reported_ips} IP だった` })}
    ${stat({ value: `${topReason.value}`, denom: `${totalReports} 件`, alt: true,
    label: `最も多い理由: ${topReason.label}`,
    note: ehSplit ? `うち ${ehSplit.feed} 件がフィードの一括登録` : "" })}
    ${stat({ value: last.indep, label: "フィード以外の通報", alt: true,
    note: `${last.indep_ips} IP。被害者の観測に最も近い行` })}
  </div>
  <ul class="pts">
    <li><strong>「推移」には 2 つの意味があり、混ぜてはいけない。</strong>
      活動の推移（図 1、申告された観測日ごと）と、こちらに見えていた量の推移（図 2、取得日ごと）は別物。
      図 2 の増加（${first.reported_ips} → ${last.reported_ips} IP）は
      <strong>攻撃が増えたのではなく、さかのぼり投稿が届いたぶん</strong>が大半。</li>
    <li><strong>最も多い理由は ${esc(topReason.label)}（${topReason.value} / ${totalReports} 件）だが、
      ${ehSplit ? `そのうち ${ehSplit.value ?? ehSplit.feed} 件` : ""}
      ${ehSplit && ehSplit.indep === 0 ? "すべて" : ""}が 1 つのフィードの一括登録。</strong>
      理由の分布は「このホストが何をしたか」ではなく<strong>そのフィードの分類語彙</strong>を映している。</li>
    <li><strong>直近 ${REASONS.w14.days} 日（観測日 ${REASONS.w14.cut} より後）の通報
      ${REASONS.w14.reports} 件は ${topRecent ? esc(topRecent.label) : "—"} だけ。</strong>
      被害者側の理由（Web App Attack など）が付いたのは ${A.filter((d) => d.indep > 0).map((d) => d.day).join("・")} で止まっている。</li>
    <li>申告された観測の最後は <strong>${lastActivity}</strong>（${quietDays} 日前）。
      ただし投稿は遅れて届くので、<strong>直近の窓はまだ埋まっていない</strong>。</li>
    <li>日本からの通報は ${FACTS.jp_reports} 件。<strong>これは「日本向けではない」という意味ではない</strong>
      — AbuseIPDB に登録がないことしか言えない。</li>
  </ul>
</section>

<section>
  <h2>2. 活動の推移（申告された観測日ごと）</h2>
  <p class="lead">通報者が「いつ観測したか」と申告した日で数えたもの。
    <strong>活動の形として読むのはこちら。</strong></p>
  ${figure({
    id: "fig-activity",
    title: `観測日ごとの通報数 — ${A.length} 日に ${totalReports} 件`,
    note: "縦軸は通報の件数。色は出所。"
      + "<strong>フィードの一括登録は「誰かが悪性と判断した」情報で、観測ではない。</strong>"
      + "日付が飛んでいるのは、その間の観測が申告されていないという意味。",
    keys: SRC_KEYS,
    svg: chartStackedTime({ rows: A, dayOf: (r) => r.day, labelOf: (r) => r.day, tickEvery: 7 }),
    tbl: table(["観測日", "通報", "うちフィード", "うちフィード以外", "IP", "通報者の国"],
      A.map((d) => [d.day, d.feed + d.indep, d.feed, d.indep, d.ips, d.ccs])),
  })}
  <p class="meta">山は ${A.slice().sort((a, b) => (b.feed + b.indep) - (a.feed + a.indep))[0].day}
    （${Math.max(...A.map((d) => d.feed + d.indep))} 件）。
    フィード以外の通報があった日は ${A.filter((d) => d.indep > 0).length} 日しかない。</p>
</section>

<section>
  <h2>3. こちらに見えていた量の推移（取得日ごと）</h2>
  <p class="lead">同じ 255 IP を取得日ごとに引き直したもの。
    <strong>これは活動ではなく、こちらの視界。</strong></p>
  ${figure({
    id: "fig-view",
    title: `取得日ごとに見えていた通報数 — ${first.reports} → ${last.reports} 件`,
    note: "母数はどの日も " + LATEST.rows.length + " IP で同じ。"
      + "<strong>増えたのは対象が増えたからではない。</strong>"
      + (MISSING_FETCH.length ? `棒が無い日（${MISSING_FETCH.join("・")}）は取得していない日。`
        + "0 件ではない。" : "")
      + (reconstructed.size ? `${[...reconstructed].join("・")} の写しは当時の CSV からの復元で、`
        + "形の畳み方が取得ぶんと厳密には一致しない。" : ""),
    keys: SRC_KEYS,
    svg: chartStackedTime({ rows: V, dayOf: (r) => r.fetch, labelOf: (r) => `${r.fetch} 取得`, tickEvery: 3 }),
    tbl: table(["取得日", "通報", "通報のある IP", `${LATEST.rows.length} IP 中`, "観測日の数",
      "最後の観測日", "最大スコア", "備考"],
      V.map((v) => [v.fetch, v.reports, v.reported_ips, `${pct(v.reported_ips, v.ips)}%`,
        v.obs_days, v.latest_obs, v.max_score, v.reconstructed ? "CSV から復元" : ""])),
  })}
  <p class="meta"><strong>最大スコアは ${first.max_score} → ${last.max_score} と下がっている。</strong>
    通報が増えてもスコアは時間で減衰するので、横に比べるときは取得日を揃えること。</p>

  ${figure({
    id: "fig-lag",
    title: `投稿の遅れ — フィードは中央 ${LAG.feed.median?.toFixed(2)} 日・最大 ${LAG.feed.max?.toFixed(2)} 日`,
    note: `通報が 1 件の IP でしか測れない（${LAG.measurable} / ${LAG.reported_ips} IP）。`
      + "<strong>母数が違う 2 系列なので割合ではなく件数で出している</strong>"
      + `（フィード ${LAG.feed.n} / それ以外 ${LAG.indep.n}）。`,
    keys: SRC_KEYS,
    svg: chartGroupedBins({ bins: LAG.bins }),
    tbl: table(["遅れ", "フィード", "フィード以外"],
      LAG.bins.map((b) => [b.label, b.feed, b.indep])
        .concat([["合計", LAG.feed.n, LAG.indep.n],
          ["中央値（日）", LAG.feed.median?.toFixed(3) ?? "—", LAG.indep.median?.toFixed(3) ?? "—"],
          ["最大（日）", LAG.feed.max?.toFixed(3) ?? "—", LAG.indep.max?.toFixed(3) ?? "—"]])),
  })}
  <p class="meta">これが図 1 と図 2 の差の正体。<strong>フィード以外の通報は
    ${LAG.indep.n} 件すべて遅れ 0.00 日（即日）</strong>で、フィードは
    ${LAG.bins[LAG.bins.length - 1].feed} 件が 4 日以上遅れている。
    遅れの分布そのものが、一括登録と一次観測を分ける材料になっている。</p>

  <h3 id="matrix">同じ観測日が、取得日ごとに何件に見えていたか</h3>
  <p class="meta"><strong>過去の日の集計は確定しない。</strong><code>·</code> はその取得日にまだ無かったという意味。</p>
  ${table(["観測日", ...MATRIX.fetch_days.map(dayMd), "確定（現時点）"],
    MATRIX.rows.map((r) => [r.day, ...r.counts.map((c) => (c === null ? "·" : String(c))), r.final]))}
</section>

<section>
  <h2>4. 通報理由 — 全体と直近</h2>
  <p class="lead"><strong>1 件の通報が複数の理由を持つことがあるので、理由の合計は通報数を超える。</strong>
    割合の分母は通報数。</p>
  <div class="cols">
    <div>
      ${figure({
        id: "fig-reason-all",
        title: `全体 — ${A[0].day}〜${lastActivity} の ${REASONS.all.reports} 件`,
        note: "色は理由に固定していて、順位では塗り替えない。",
        keys: reasonKeys(REASONS.all.rows),
        svg: chartReasons({ rows: REASONS.all.rows, total: REASONS.all.reports,
          scale: REASONS.all.reports }),
        tbl: table(["理由", "件数", "通報数に対する割合"],
          REASONS.all.rows.map((r) => [r.label, r.value, `${pct(r.value, REASONS.all.reports)}%`])),
      })}
    </div>
    <div>
      ${figure({
        id: "fig-reason-recent",
        title: `直近 ${REASONS.w14.days} 日 — 観測日 ${REASONS.w14.cut} より後の ${REASONS.w14.reports} 件`,
        note: "<strong>この窓はまだ埋まっていない。</strong>さかのぼり投稿があるので、後日引き直すと増えうる。"
          + "横軸は左の図と同じ目盛り（括弧内はこの窓に対する割合）。",
        keys: reasonKeys(REASONS.w14.rows),
        svg: chartReasons({ rows: REASONS.w14.rows, total: REASONS.w14.reports,
          scale: REASONS.all.reports }),
        tbl: table(["理由", "件数", "通報数に対する割合"],
          REASONS.w14.rows.map((r) => [r.label, r.value, `${pct(r.value, REASONS.w14.reports)}%`])
            .concat([[`直近 ${REASONS.w7.days} 日（${REASONS.w7.cut} より後）`,
              REASONS.w7.reports, REASONS.w7.rows.map((r) => `${r.label} ${r.value}`).join(" / ")]])),
      })}
    </div>
  </div>

  ${figure({
    id: "fig-reason-source",
    title: "その理由を付けたのは誰か",
    note: "<strong>ここがこの節の要。</strong>"
      + "「最も多い理由」は、1 つのフィードが全対象に同じ語を貼った結果になりうる。"
      + "右の数字は フィード / フィード以外。",
    keys: SRC_KEYS,
    svg: chartSourceSplit({ rows: REASON_BY_SOURCE }),
    tbl: table(["理由", "フィードの一括登録", "フィード以外", "合計"],
      REASON_BY_SOURCE.map((r) => [r.label, r.feed, r.indep, r.feed + r.indep])),
  })}

  <h3>通報者の内訳</h3>
  <p class="meta">通報者 ID そのものは保存していない。国と出所だけで束ねている。</p>
  ${table(["通報者の国", "出所", "通報", "対象 IP", "観測日の数", "付けた理由"],
    REPORTERS.map((r) => [r.cc, r.feed ? "フィードの一括登録" : "フィード以外",
      r.reports, r.ips, r.days, r.cats]))}
</section>

<section class="limits">
  <h2>5. この頁から言えないこと</h2>
  <ul class="pts">
    <li><strong>通報の有無は「攻撃したか」ではない。</strong>通報は第三者の申告で、
      こちらが検証したものではない。フィードの一括登録はとくに、
      「誰かが悪性と判断した」という情報であって観測ではない。</li>
    <li><strong>直近の窓は確定していない。</strong>投稿は中央
      ${LAG.feed.median?.toFixed(2)} 日・最大 ${LAG.feed.max?.toFixed(2)} 日さかのぼって届く。
      ${lastActivity} 以降に通報が無いことは、活動が止まった証拠にならない。</li>
    <li><strong>理由（カテゴリ）は通報者が選んだ語。</strong>定義はそろっていない。
      とくに Exploited Host は「送信元が侵害されている」という補助情報で、攻撃手法ではない。</li>
    <li><strong>遅れが測れるのは通報が 1 件の IP だけ</strong>（${LAG.measurable} / ${LAG.reported_ips} IP）。
      2 件以上あるとどの投稿がどの観測に対応するか決められない。</li>
    <li><strong>フィード以外の通報は ${LAG.indep.n} 件しか遅れを測れていない。</strong>
      「0.00 日」はその ${LAG.indep.n} 件についての事実で、一次観測一般の性質ではない。</li>
    <li><strong>日本からの通報 0 件は「日本向け攻撃元ではない」ではない。</strong>
      日本の被害者が通報していない・窓の外・公開していない、どれも区別できない。</li>
    <li><strong>ARTEX と sub2api の起動は利用者の観測</strong>で、こちらが確認したものではない
      （${esc(cluster.observed_by)}）。この頁は対象 IP に一切接続していない。</li>
    <li>スコアは時間で減衰する。取得日の違う数字を横に比べてはいけない。</li>
  </ul>
</section>

<footer class="ft">
  <p>通報者 ID・コメント原文は保存していない。API キーはコンソール・ログ・CSV・JSON・ソース・エラーにも出していない。</p>
  <p class="meta">作り直すには <code>node reports/artex-timeline/trend.mjs</code>。
    数字だけ機械で読むには <code>--json</code>。
    出所は <code>data/ioc/watch/observations/*.jsonl</code> の写しのみで、API は呼んでいない。</p>
</footer>`;

const html = `<!doctype html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>推移と通報理由 — ${esc(cluster.name)}</title>
<style>
/* 系列色は dataviz の参照カテゴリ順スロット 1〜4。検証器に明色・暗色の両方で通してある。
   「通報なし」は系列ではなく軌道なので --track は系列色に数えない。 */
:root{
  color-scheme: light;
  --bg:#ffffff; --surface:#f4f6f8; --ink:#14181f; --ink-2:#5c6673; --ink-3:#8a94a3;
  --rule:#e3e7ec; --grid:#eceff3; --track:#e8eaed;
  --c1:#2a78d6; --c2:#eb6834; --c3:#1baf7a; --c4:#eda100; --c0:#8a94a3;
  --maxw:1080px;
}
@media (prefers-color-scheme: dark){
  :root:not([data-theme="light"]){
    color-scheme: dark;
    --bg:#14181f; --surface:#1b2029; --ink:#eef1f5; --ink-2:#b4bdc9; --ink-3:#8a94a3;
    --rule:#2a313c; --grid:#232933; --track:#2a313c;
    --c1:#3987e5; --c2:#d95926; --c3:#199e70; --c4:#c98500; --c0:#8a94a3;
  }
}
:root[data-theme="dark"]{
  color-scheme: dark;
  --bg:#14181f; --surface:#1b2029; --ink:#eef1f5; --ink-2:#b4bdc9; --ink-3:#8a94a3;
  --rule:#2a313c; --grid:#232933; --track:#2a313c;
  --c1:#3987e5; --c2:#d95926; --c3:#199e70; --c4:#c98500; --c0:#8a94a3;
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
p{margin:.5em 0}
code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; font-size:.92em;
  background:var(--surface); padding:.1em .35em; border-radius:4px}
.hd{padding:48px 0 8px}
.eyebrow{color:var(--ink-2); font-size:.85rem; letter-spacing:.14em; margin:0}
.lead{font-size:1.05rem; max-width:72ch}
.meta{color:var(--ink-2); font-size:.86rem; max-width:80ch}
.pts{margin:.6em 0 0; padding-left:1.25em; max-width:80ch}
.pts li{margin:.45em 0}
.stats{display:grid; gap:12px; grid-template-columns:repeat(auto-fit,minmax(210px,1fr)); margin:18px 0 6px}
.stat{background:var(--surface); border-radius:10px; padding:16px 18px}
.num{font-size:2.6rem; font-weight:700; line-height:1.1; letter-spacing:-.01em}
.num.alt{color:var(--c2)}
.den{font-size:1rem; font-weight:400; color:var(--ink-2)}
.lab{font-weight:700; font-size:.95rem; margin-top:.2em}
.sub{color:var(--ink-2); font-size:.84rem}
.fig{margin:28px 0 8px; padding:0}
.fig figcaption{margin-bottom:.4em}
.fig .note{color:var(--ink-2); font-size:.88rem; margin:.1em 0 0; max-width:80ch}
.plot{margin-top:10px}
.plot svg{width:100%; height:auto; display:block}
.legend{display:flex; flex-wrap:wrap; gap:16px; margin-top:10px}
.key{display:inline-flex; align-items:center; gap:7px; font-size:.86rem; color:var(--ink-2)}
.sw{width:12px; height:12px; border-radius:3px; display:inline-block}
.sw.c1{background:var(--c1)} .sw.c2{background:var(--c2)}
.sw.c3{background:var(--c3)} .sw.c4{background:var(--c4)} .sw.c0{background:var(--c0)}
.mark.c1{fill:var(--c1)} .mark.c2{fill:var(--c2)}
.mark.c3{fill:var(--c3)} .mark.c4{fill:var(--c4)} .mark.c0{fill:var(--c0)}
.mark{transition:opacity .12s}
.plot:hover .mark{opacity:.55}
.plot .mark:hover{opacity:1}
.track{fill:var(--track)}
.grid{stroke:var(--grid); stroke-width:1}
text{font-family:inherit}
.axis{fill:var(--ink-3); font-size:12px}
.cat{fill:var(--ink-2); font-size:13px}
.val{fill:var(--ink); font-size:12px; font-weight:600}
.val .pct{fill:var(--ink-2); font-weight:400}
.tbl{margin-top:12px}
.tbl summary{cursor:pointer; color:var(--ink-2); font-size:.86rem; width:max-content}
.tbl table{border-collapse:collapse; margin-top:8px; font-size:.88rem; width:100%}
.tbl th,.tbl td{border-bottom:1px solid var(--rule); padding:6px 10px; text-align:right}
.tbl thead th{color:var(--ink-2); font-weight:600; border-bottom:1px solid var(--ink-3)}
.tbl th[scope=row], .tbl thead th:first-child{text-align:left}
.cols{display:grid; gap:24px; grid-template-columns:repeat(auto-fit,minmax(330px,1fr)); margin-top:10px}
.limits{background:var(--surface); border-radius:12px; padding:4px 24px 20px; margin-top:2.6em}
.limits h2{border-bottom:none; margin-top:1.2em}
.ft{margin-top:3em; padding-top:1.2em; border-top:1px solid var(--rule); color:var(--ink-2); font-size:.88rem}
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
  var b=document.getElementById("themer");
  b.addEventListener("click",function(){
    var dark=matchMedia("(prefers-color-scheme: dark)").matches;
    var cur=document.documentElement.getAttribute("data-theme")||(dark?"dark":"light");
    document.documentElement.setAttribute("data-theme",cur==="dark"?"light":"dark");
  });
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
console.log(`→ ${path.relative(ROOT, OUT)}（${(Buffer.byteLength(html) / 1024).toFixed(0)} KB / 外部読み込みなし）`);
console.log(`  取得日 ${V.length}（${first.fetch}〜${ANCHOR}）／ ${LATEST.rows.length} IP`);
console.log(`  活動: ${A.length} 観測日 / 通報 ${totalReports} 件（${A[0].day}〜${lastActivity}）`);
console.log(`  視界: 通報のある IP ${first.reported_ips} → ${last.reported_ips}`);
console.log(`  理由: 全体 ${REASONS.all.rows.map((r) => `${r.label} ${r.value}`).join(" / ")}`);
console.log(`  　　  直近${REASONS.w14.days}日 ${REASONS.w14.rows.map((r) => `${r.label} ${r.value}`).join(" / ") || "なし"}`);
