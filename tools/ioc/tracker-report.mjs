#!/usr/bin/env node
// トラッカーの 1 週間ぶんを、**人が判断するものだけ**に絞って出す。
// **写しだけを見る。外には出ない。**
//
//   node tools/ioc/tracker-report.mjs [--tracker data/ioc/tracker] [--in data/ioc/latest]
//                                     [--days 7] [--json <書き出し先>] [--top 20]
//
// 週次レポートを書くときの材料。events.jsonl をそのまま読むと、
// **何が攻撃者の動きで何がそうでないか**が分からないので、ここで印を付ける。
//
// ## 何を落とすのではなく、何に印を付けるか
//
// 落とさない。**並べ替えて印を付ける**。判断の材料を隠すと、
// 「出てこなかったから無かった」と読まれてしまう。
//
//   役割        索引がその IOC に何と言っているか（c2 / phishing など）。
//               **述べられていないものは弱い** —— 記事に出てきただけかもしれない
//   毎日組      観測日の半分以上で動いているもの。切り替わりではなく **そういう構成**。
//               実測: business-data-leaks.com の一族は 7〜9 の AS を毎日入れ替える
//   事業者      service_like。t.me や gist.github.com の類（lib/tracker.mjs）
//   CDN         その上での IP 移動は既に数えていないが、AS が動いた分は出る
//
// ## 生死の変化は「落ちた」より「生き返った」を上に置く
//
// 失効は毎日それなりに出るが、**死んでいたものが生き返るのは珍しい**。
// 珍しいほうが人の目を要するので、並びを分ける。
import fs from "node:fs";
import path from "node:path";
import { parseArgs, readJsonl, writeJson } from "./lib/io.mjs";
import { REPO_ROOT } from "./lib/sources.mjs";
import { statedRoles, STATUS } from "./lib/tracker.mjs";

const args = parseArgs(process.argv.slice(2));
const IN = path.resolve(REPO_ROOT, args.in || "data/ioc/latest");
const TRACKER = path.resolve(REPO_ROOT, args.tracker || "data/ioc/tracker");
const DAYS = Number(args.days || 7);
const TOP = Number(args.top || 20);

/** 観測日の何割以上で動いていたら「そういう構成」とみなすか。
 *  半分にしてあるのは、週 7 日のうち 4 日動けば切り替わりとは呼べないという線。
 *  **落とすためではなく印を付けるための閾値**なので、緩くてよい。 */
const CHURN_RATIO = Number(args["churn-ratio"] || 0.5);

const statePath = path.join(TRACKER, "state.jsonl");
if (!fs.existsSync(statePath)) {
  console.error(`${statePath} がありません。先に fetch-dns.mjs → track-domains.mjs を。`);
  process.exit(2);
}
const state = new Map(readJsonl(statePath).map((r) => [r.host, r]));
const events = readJsonl(path.join(TRACKER, "events.jsonl"));
const fresh = fs.existsSync(path.join(TRACKER, "new-samples.json"))
  ? JSON.parse(fs.readFileSync(path.join(TRACKER, "new-samples.json"), "utf8")) : null;

/* ---------------- 索引が何と言っているか ---------------- */

const rels = new Map();      // host -> Set(rel)
const actors = new Map();    // host -> Set(実体名)
for (const f of ["links.jsonl", "derived-links.jsonl"]) {
  const p = path.join(IN, f);
  if (!fs.existsSync(p)) continue;
  for (const l of readJsonl(p)) {
    if (!String(l.ioc || "").startsWith("ioc.domain|")) continue;
    const host = l.ioc.slice("ioc.domain|".length);
    if (l.rel) (rels.get(host) || rels.set(host, new Set()).get(host)).add(l.rel);
    if (l.kind === "actor" && l.name) (actors.get(host) || actors.set(host, new Set()).get(host)).add(l.name);
  }
}
/** 「これは何をするものか」を誰かが述べているか。lib/tracker.mjs の線引きを使う。
 *  こちらが VT から生やした observation（resolves_to / contacted）は役割ではない。 */
const assertedRel = (host) => statedRoles(rels.get(host));

/* ---------------- 期間を切る ---------------- */

const dates = [...new Set(events.map((e) => e.date))].sort();
const allDates = fs.existsSync(path.join(TRACKER, "observations"))
  ? fs.readdirSync(path.join(TRACKER, "observations"))
      .filter((f) => /^\d{4}-\d{2}-\d{2}\.jsonl$/.test(f)).map((f) => f.slice(0, 10)).sort()
  : dates;
const window = allDates.slice(-DAYS);
const from = window[0], to = window[window.length - 1];
const inWindow = events.filter((e) => e.date >= from && e.date <= to);

console.log(`トラッカー ${from} 〜 ${to}（観測 ${window.length} 日 / 全 ${allDates.length} 日）`);
console.log(`  変化 ${inWindow.length} 件 / 追跡 ${state.size} ドメイン`);

/* ---------------- 毎日動いているものに印を付ける ---------------- */

const daysMoved = new Map();
for (const e of inWindow) {
  if (e.kind === "status") continue;   // 生死は「毎日組」の判定に入れない
  if (!daysMoved.has(e.host)) daysMoved.set(e.host, new Set());
  daysMoved.get(e.host).add(e.date);
}
const churnFloor = Math.max(2, Math.ceil(window.length * CHURN_RATIO));
const churn = new Set([...daysMoved].filter(([, d]) => d.size >= churnFloor).map(([h]) => h));

/* ---------------- 1 件ぶんの見え方 ---------------- */

const marksOf = (host) => {
  const s = state.get(host) || {};
  const m = [];
  if (churn.has(host)) m.push("毎日組");
  if (s.service_like) m.push("事業者");
  if (s.dynamic_suffix) m.push("動的DNS");
  if (s.cdn) m.push("CDN");
  if (!assertedRel(host).length) m.push("役割なし");
  return m;
};
/** 人の目を要する順。役割つきで、印が少ないものほど上 */
const weightOf = (host) => {
  const marks = marksOf(host);
  return (assertedRel(host).length ? 0 : 100) + marks.length * 10;
};
const shape = (e) => ({
  date: e.date, host: e.host, kind: e.kind,
  rel: assertedRel(e.host),
  actors: [...(actors.get(e.host) || [])],
  marks: marksOf(e.host),
  from: e.from, to: e.to,
  from_names: e.from_names, to_names: e.to_names,
  asn_names: (state.get(e.host) || {}).asn_names,
});
const bySignal = (a, b) => weightOf(a.host) - weightOf(b.host)
  || (a.date < b.date ? 1 : a.date > b.date ? -1 : a.host < b.host ? -1 : 1);

/* ---------------- 並べる ---------------- */

const moved = inWindow.filter((e) => e.kind === "ip_change" || e.kind === "as_change").map(shape).sort(bySignal);
const renamed = inWindow.filter((e) => e.kind === "cname_change").map(shape).sort(bySignal);
const statuses = inWindow.filter((e) => e.kind === "status").map(shape);
const revived = statuses.filter((e) => e.to === STATUS.ALIVE).sort(bySignal);
const died = statuses.filter((e) => e.to !== STATUS.ALIVE).sort(bySignal);

const line = (e) => {
  const marks = e.marks.length ? `  [${e.marks.join(" ")}]` : "";
  const who = e.rel.length ? e.rel.slice(0, 2).join("/") : "—";
  const arrow = e.from !== undefined
    ? `${String(e.from || "（無し）").slice(0, 32)} → ${String(e.to || "（無し）").slice(0, 32)}` : "";
  return `  ${e.date}  ${e.host.slice(0, 38).padEnd(40)} ${who.slice(0, 22).padEnd(24)} ${arrow}${marks}`;
};
const section = (title, rows) => {
  console.log(`\n${title} ${rows.length} 件`);
  if (!rows.length) { console.log("  なし"); return; }
  for (const e of rows.slice(0, TOP)) console.log(line(e));
  if (rows.length > TOP) console.log(`  … 残り ${rows.length - TOP} 件`);
};

section("■ 行き先が変わった", moved);
section("■ 別名の向き先が変わった", renamed);
section("■ 生き返った（珍しいほう）", revived);
section("■ 落ちた", died);

if (churn.size) {
  console.log(`\n■ 毎日組（${window.length} 日中 ${churnFloor} 日以上動いている）${churn.size} 件`);
  console.log("  切り替わりではなく、そういう構成。所見にする前に必ず疑うこと");
  for (const h of [...churn].sort().slice(0, TOP)) {
    console.log(`  ${h.slice(0, 40).padEnd(42)} ${daysMoved.get(h).size} 日 / 役割 ${assertedRel(h).join("/") || "—"}`);
  }
}

/* ---------------- 生きている足場に付いた新しい検体 ---------------- */

const newSamples = (fresh?.hosts || [])
  .filter((h) => h.not_in_index > 0)
  .map((h) => ({ ...h, rel: assertedRel(h.host), marks: marksOf(h.host) }))
  .sort((a, b) => weightOf(a.host) - weightOf(b.host) || b.not_in_index - a.not_in_index);
console.log(`\n■ 生存ドメインに付いた索引外の検体 ${newSamples.length} ドメイン`);
if (!newSamples.length) console.log("  なし");
for (const h of newSamples.slice(0, TOP)) {
  const marks = h.marks.length ? `  [${h.marks.join(" ")}]` : "";
  console.log(`  ${h.host.slice(0, 38).padEnd(40)} 索引に無い ${String(h.not_in_index).padStart(3)} 件  ${(h.rel.join("/") || "—").slice(0, 20)}${marks}`);
  for (const s of (h.samples || []).slice(0, 3)) {
    console.log(`        ${s.first || "?"}  検知 ${String(s.mal ?? "?").padStart(2)}  ${s.sha256.slice(0, 16)}  ${String(s.name || "").slice(0, 34)}`);
  }
}

/* ---------------- 現況 ---------------- */

const rows = [...state.values()];
const tally = rows.reduce((m, r) => (m[r.status] = (m[r.status] || 0) + 1, m), {});
const alive = rows.filter((r) => r.status === STATUS.ALIVE);
console.log(`\n現況 ${rows.length} ドメイン: ` + Object.entries(tally).sort().map(([k, v]) => `${k} ${v}`).join(" / "));
console.log(`  生存 ${alive.length}（CDN ${alive.filter((r) => r.cdn).length} / 動的DNS ${alive.filter((r) => r.dynamic_suffix).length} / 事業者 ${alive.filter((r) => r.service_like).length}）`);
if (tally[STATUS.ERROR]) {
  const ratio = tally[STATUS.ERROR] / rows.length;
  console.log(`  判定保留 ${tally[STATUS.ERROR]}（${(ratio * 100).toFixed(1)}%）` +
    (ratio > 0.05 ? "  ← 5% を超えている。こちら側の問題を疑うこと" : ""));
}

if (args.json) {
  const out = path.resolve(REPO_ROOT, args.json);
  writeJson(out, {
    tool: "tools/ioc/tracker-report.mjs", schema: 1,
    built_at: new Date().toISOString(),
    from, to, days: window.length,
    churn_floor: churnFloor,
    counts: { events: inWindow.length, moved: moved.length, renamed: renamed.length,
      revived: revived.length, died: died.length, churn: churn.size,
      new_sample_hosts: newSamples.length },
    status: tally,
    alive: { total: alive.length, cdn: alive.filter((r) => r.cdn).length,
      dynamic: alive.filter((r) => r.dynamic_suffix).length,
      service_like: alive.filter((r) => r.service_like).length },
    moved, renamed, revived, died,
    churn: [...churn].sort(),
    new_samples: newSamples,
  });
  console.log(`\n  → ${out}`);
}
