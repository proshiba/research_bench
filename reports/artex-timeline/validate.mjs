#!/usr/bin/env node
// 成果物を**読み直して**検査する。作った側の変数は見ない。
//
//   node validate.mjs
//
// この調査の結論は「通報が増えたが、中身は単一通報者の一括登録だった」なので、
// **その主張が成り立つかを写しから計算し直す**のを重く見る。
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
const want = new Set();
for (const cl of CFG.CLUSTERS) {
  if (cl.explicit) for (const ip of cl.explicit) want.add(ip);
  if (cl.ranges) {
    for (const r of cl.ranges) {
      const b = r.split("/")[0].split(".").slice(0, 3).join(".");
      for (let i = cl.host_range[0]; i <= cl.host_range[1]; i++) want.add(`${b}.${i}`);
    }
  }
}
check(P.rows.length === want.size, `IP の表が対象の数と一致（${want.size}）`, String(P.rows.length));
check(P.rows.every((r) => want.has(r.ip_address)), "指定外の IP が混ざっていない");
check([...want].every((ip) => P.rows.some((r) => r.ip_address === ip)), "指定された IP がすべて入っている");
check(now.size === want.size, "写しの数が対象の数と一致", `${now.size} / ${want.size}`);
check(P.rows.filter((r) => r.cluster === "ARTEX").length === 250, "ARTEX が 250 IP");
check(P.rows.filter((r) => r.cluster === "sub2api").length === 5, "sub2api が 5 IP");

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
check(newly.length === S.per_cluster.ARTEX.newly_reported, "新しく通報が付いた数が summary と一致");
check(newly.every((r) => num(r.reports_now) > 0 && num(r.reports_baseline) === 0),
  "新しく付いた行は「今 1 件以上 かつ 基準日 0 件」を満たす");
check(S.per_cluster.sub2api.baseline_available === 0,
  "sub2api には基準日の写しが無い（10-14 の調査対象外だった）");

console.log("\n== 「単一通報者の一括登録」の主張");
const ridOf = new Map();
for (const e of E.rows) ridOf.set(e.reporter, (ridOf.get(e.reporter) || 0) + 1);
check(ridOf.size === S.reports.distinct_reporters, "通報者の数が summary と一致",
  `${ridOf.size} / ${S.reports.distinct_reporters}`);
const artexEv = E.rows.filter((e) => e.cluster === "ARTEX");
const artexRids = new Set(artexEv.map((e) => e.reporter));
check(artexRids.size === 1, "**ARTEX の通報はすべて単一の通報者**", `${artexRids.size} 人`);
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
check(indep.every((e) => e.cluster === "sub2api"),
  "**一括登録以外の通報はすべて sub2api 側**（= ARTEX には独立した通報が無い）");

console.log("\n== 時系列");
check(D.rows.length === S.by_day.length, "日ごとの表の行数が summary と一致");
const days = D.rows.map((r) => r.day);
check(days.join(",") === [...days].sort().join(","), "日付が昇順に並んでいる");
check(D.rows.reduce((s, r) => s + num(r.reports), 0) === E.rows.length,
  "日ごとの通報の合計が総数に等しい");
check(E.rows.every((e, i) => i === 0 || E.rows[i - 1].reported_at <= e.reported_at),
  "通報の表が時刻の昇順に並んでいる");
check(E.rows.every((e, i) => num(e.seq) === i + 1), "seq が 1 から連番");
// 「Last observed が通報日と同じ」の確認
const lo = E.rows.filter((e) => /Last observed/.test(e.comment_excerpt));
const loSame = lo.filter((e) => {
  const m = e.comment_excerpt.match(/Last observed (\d{4}-\d{2}-\d{2})/);
  return m && m[1] === e.day;
});
check(lo.length > 0 && loSame.length === lo.length,
  "**Last observed の日付が通報日と全件一致**（独立した時系列情報を持たない）",
  `${loSame.length} / ${lo.length}`);

console.log("\n== 素性");
check(P.rows.filter((r) => r.cluster === "sub2api").every((r) => r.hostnames),
  "sub2api は 5 件すべて rDNS を持つ");
check(P.rows.filter((r) => r.cluster === "ARTEX").every((r) => !r.hostnames),
  "ARTEX は 250 件すべて rDNS が空");
check(P.rows.filter((r) => r.cluster === "sub2api")
  .every((r) => r.hostnames.endsWith("visiblooths.net")),
  "sub2api の rDNS はすべて visiblooths.net の下");
check(P.rows.every((r) => !bool(r.in_threat_index)), "両クラスタとも脅威情報の索引に無い");
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
check(/攻撃に使われた時期」は特定できていません/.test(md),
  "**時期を特定できたと書いていない**");
check(/運用者の国籍や所属を示しません/.test(md), "所在地の解釈に注意を書いている");

console.log(failed ? `\n${failed} 件 NG` : "\nすべて通りました");
process.exit(failed ? 1 : 0);
