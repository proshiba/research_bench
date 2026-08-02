#!/usr/bin/env node
// 日次で「昨日から何が変わったか」を出す。外部呼び出しなし。
//
//   node tools/ioc/daily-report.mjs [--in data/ioc/latest] [--prev <前回の一式>]
//                                   [--json <書き出し先>] [--top 15]
//
// なぜ要るか
//   毎日 1,500 件ずつ埋まっていくので、`stats.json` を毎日全部読むのは現実的でない。
//   **人（や AI）が見るべきなのは「今日増えた分」だけ**で、それを選ぶのは機械の仕事。
//   ここで差分を出しきり、判断だけを人に渡す。
//
// 出すもの
//   1. カバレッジが今日どれだけ進んだか（分母つき）
//   2. 新しく出た重なり — **強い根拠のものだけ**。弱い根拠だけの組は数だけ
//   3. 新しく生えたもの — 実体・別名・共有証明書・解決先
//   4. **見に行くべきもの** — 索引の主張と食い違った IOC、VT が知らない IOC、
//      AS が経路表と食い違った IP。どれも「機械では決められない」ものだけを残す
//
// --prev が無ければ差分は出さず、今の姿だけを出す（初回や写しが無い環境）。
// --json を渡すと同じ中身をファイルにも残す。daily.sh は
// data/ioc/reports/<日付>.json に置く（出すだけだと経過が追えないため）。

import path from "node:path";
import { byKeys, parseArgs, readJson, readJsonl, writeJson } from "./lib/io.mjs";
import { REPO_ROOT } from "./lib/sources.mjs";

const args = parseArgs(process.argv.slice(2));
const IN = path.resolve(REPO_ROOT, args.in || "data/ioc/latest");
const PREV = args.prev ? path.resolve(REPO_ROOT, args.prev) : null;
const TOP = Number(args.top || 15);

const load = (dir, name) => (dir ? readJsonl(path.join(dir, name)) : []);
const now = {
  stats: readJson(path.join(IN, "stats.json"), {}),
  overlaps: load(IN, "overlaps.jsonl"),
  vt: load(IN, "vt.jsonl"),
  abuse: load(IN, "abuseipdb.jsonl"),
  entities: load(IN, "derived-entities.jsonl"),
  aliases: load(IN, "derived-aliases.jsonl"),
  certs: load(IN, "derived-certs.jsonl"),
  derivedIocs: load(IN, "derived-iocs.jsonl"),
  iocs: load(IN, "iocs.jsonl"),
};
const prev = PREV ? {
  stats: readJson(path.join(PREV, "stats.json"), {}),
  overlaps: load(PREV, "overlaps.jsonl"),
  vt: load(PREV, "vt.jsonl"),
  abuse: load(PREV, "abuseipdb.jsonl"),
  entities: load(PREV, "derived-entities.jsonl"),
  aliases: load(PREV, "derived-aliases.jsonl"),
  certs: load(PREV, "derived-certs.jsonl"),
  derivedIocs: load(PREV, "derived-iocs.jsonl"),
} : null;

const iocByKey = new Map(now.iocs.map((r) => [r.key, r]));
const pairKey = (o) => `${o.kind}\t${o.a}\t${o.b}`;

/* ---------------- 1. カバレッジ ---------------- */

const cov = now.stats.coverage || {};
const prevCov = prev?.stats?.coverage || {};
const delta = (a, b) => (Number(a || 0) - Number(b || 0));

const coverage = {};
for (const svc of ["virustotal", "abuseipdb"]) {
  const c = cov[svc] || {};
  coverage[svc] = {
    done: c.done ?? 0,
    target: c.target ?? 0,
    ratio: c.ratio ?? 0,
    added: delta(c.done, prevCov[svc]?.done),
    ...(c.known !== undefined ? { known: c.known, unknown: c.unknown } : {}),
    by_stage: Object.fromEntries(Object.entries(c.by_stage || {}).map(([s, v]) => [s, {
      done: v.done, target: v.target,
      added: delta(v.done, prevCov[svc]?.by_stage?.[s]?.done),
    }])),
  };
}

/* ---------------- 2. 新しく出た重なり ---------------- */

const prevPairs = new Map((prev?.overlaps || []).map((o) => [pairKey(o), o]));
const newPairs = prev ? now.overlaps.filter((o) => !prevPairs.has(pairKey(o))) : [];
/** 根拠が増えた組。組そのものは前からあったが、強さが上がったもの。 */
const grew = prev ? now.overlaps.filter((o) => {
  const p = prevPairs.get(pairKey(o));
  return p && o.strength > p.strength;
}).map((o) => ({ ...o, was: prevPairs.get(pairKey(o)).strength })) : [];

const strong = (list) => list.filter((o) => !o.weak_only).sort((a, b) => b.strength - a.strength || b.shared - a.shared);
const slim = (o) => ({
  kind: o.kind, a: o.a, b: o.b, shared: o.shared, strength: o.strength, via: o.via,
  ...(o.was !== undefined ? { was: o.was } : {}),
});

/* ---------------- 3. 新しく生えたもの ---------------- */

const diffBy = (key, a, b) => {
  const seen = new Set((b || []).map(key));
  return (a || []).filter((x) => !seen.has(key(x)));
};
const newEntities = prev ? diffBy((e) => `${e.kind}\t${e.name}`, now.entities, prev.entities) : now.entities;
const newAliases = prev ? diffBy((a) => a.name, now.aliases, prev.aliases) : now.aliases;
const newDerivedIocs = prev ? diffBy((r) => r.key, now.derivedIocs, prev.derivedIocs) : now.derivedIocs;
/** 根拠に使える共有証明書だけ。共用ホスティングのものは数に入れない */
const sharedCerts = now.certs.filter((c) => c.shared && !c.weak);
const prevShared = new Set((prev?.certs || []).filter((c) => c.shared && !c.weak).map((c) => c.thumbprint));
const newSharedCerts = prev ? sharedCerts.filter((c) => !prevShared.has(c.thumbprint)) : sharedCerts;

/* ---------------- 4. 見に行くべきもの ---------------- */

const prevVt = new Set((prev?.vt || []).map((r) => r.ioc));
const freshVt = prev ? now.vt.filter((r) => !prevVt.has(r.ioc)) : now.vt;
const prevAbuse = new Set((prev?.abuse || []).map((r) => r.ioc));
const freshAbuse = prev ? now.abuse.filter((r) => !prevAbuse.has(r.ioc)) : now.abuse;

/**
 * 索引が「C2」「マルウェア」と言っているのに VT の検知が 0 のもの。
 * 索引側の誤りか、まだ知られていないかのどちらかで、**どちらでも見る価値がある**。
 * ここは機械では決められないので、そのまま人に渡す。
 */
const CLAIMED = new Set(["c2", "malware", "phishing-site"]);
const disagreement = freshVt
  .filter((r) => r.known && r.malicious === 0 && r.suspicious === 0)
  .filter((r) => (iocByKey.get(r.ioc)?.classes || []).some((c) => CLAIMED.has(c)))
  .map((r) => ({ ioc: r.ioc, classes: iocByKey.get(r.ioc)?.classes, sources: iocByKey.get(r.ioc)?.sources }))
  .sort(byKeys("ioc"));

/** VT が知らない IOC。失敗ではなく結果で、索引の独自性の指標になる。 */
const unknown = freshVt.filter((r) => !r.known).map((r) => r.ioc).sort();

/** 経路表と VT で AS が食い違った IP。時点差なので、どちらかが誤りとは言えない。 */
const asnDiffers = freshVt.filter((r) => r.asn_differs).map((r) => r.ioc).sort();

/** 検知が多い新顔。今日いちばん「濃い」ものから見る。 */
const topMalicious = [...freshVt]
  .filter((r) => r.known && r.malicious > 0)
  .sort((a, b) => b.malicious - a.malicious || (a.ioc < b.ioc ? -1 : 1))
  .slice(0, TOP)
  .map((r) => ({ ioc: r.ioc, malicious: r.malicious, ...(r.label ? { label: r.label } : {}) }));

/** スコアの高い新顔の IP。**通報数ではなくスコアで見る**。 */
const topAbuse = [...freshAbuse]
  .filter((r) => r.score >= 25)
  .sort((a, b) => b.score - a.score || (a.ioc < b.ioc ? -1 : 1))
  .slice(0, TOP)
  .map((r) => ({ ioc: r.ioc, score: r.score, reports: r.reports, reporters: r.reporters,
    ...(r.usage_type ? { usage_type: r.usage_type } : {}) }));

/* ---------------- まとめ ---------------- */

const report = {
  tool: "tools/ioc/daily-report.mjs",
  schema: 1,
  compared_with: PREV ? path.relative(REPO_ROOT, PREV) : null,
  coverage,
  overlaps: {
    total: now.overlaps.length,
    new: newPairs.length,
    new_strong: strong(newPairs).length,
    grew: grew.length,
    top_new: strong(newPairs).slice(0, TOP).map(slim),
    top_grew: strong(grew).slice(0, TOP).map(slim),
  },
  grown: {
    entities: newEntities.map((e) => ({ name: e.name, ioc_count: e.ioc_count })),
    aliases: newAliases.map((a) => ({ name: a.name, aliases: a.aliases })),
    iocs: newDerivedIocs.length,
    shared_certs: newSharedCerts.map((c) => ({
      thumbprint: c.thumbprint, issuer: c.issuer ?? null, subject: c.subject ?? null, iocs: c.iocs,
    })),
  },
  // ここから下は「機械では決められないので人が見るもの」
  to_check: {
    disagreement: { total: disagreement.length, samples: disagreement.slice(0, TOP) },
    unknown: { total: unknown.length, samples: unknown.slice(0, TOP) },
    asn_differs: { total: asnDiffers.length, samples: asnDiffers.slice(0, TOP) },
    top_malicious: topMalicious,
    top_abuse: topAbuse,
    // 大きさとアクター数では根拠になるのに、事業者の網と言われて外れた AS
    hosting_excluded: now.stats.asns?.hosting_excluded ?? [],
  },
};

if (args.json) writeJson(path.resolve(REPO_ROOT, args.json), report);

/* ---------------- 表示 ---------------- */

const pct = (x) => `${(Number(x || 0) * 100).toFixed(1)}%`;
const plus = (n) => (n > 0 ? `+${n}` : `${n}`);

console.log("── 日次レポート ──");
if (!PREV) console.log("  前回の一式がありません。今の姿だけを出します（差分なし）。");
for (const [svc, c] of Object.entries(coverage)) {
  console.log(`  ${svc.padEnd(11)} ${String(c.done).padStart(6)} / ${String(c.target).padEnd(6)} ${pct(c.ratio).padStart(6)}`
    + `  今日 ${plus(c.added)}`
    + (c.known !== undefined ? `（判定あり ${c.known} / VT が知らない ${c.unknown}）` : ""));
  for (const [s, v] of Object.entries(c.by_stage)) {
    if (!v.added && v.done === v.target) continue;
    console.log(`      段階 ${s.padEnd(3)} ${String(v.done).padStart(6)} / ${String(v.target).padEnd(6)} 今日 ${plus(v.added)}`);
  }
}

console.log(`  重なり ${report.overlaps.total} 組`
  + (PREV ? `（新しく出た ${report.overlaps.new} / うち強い根拠 ${report.overlaps.new_strong} / 根拠が増えた ${report.overlaps.grew}）` : ""));
for (const o of report.overlaps.top_new.slice(0, 8)) {
  console.log(`    + ${String(o.strength).padStart(3)} ${o.kind.padEnd(9)} ${o.a} ↔ ${o.b}  [${o.via.join(" ")}]`);
}
for (const o of report.overlaps.top_grew.slice(0, 5)) {
  console.log(`    ↑ ${String(o.was).padStart(3)}→${String(o.strength).padEnd(3)} ${o.kind.padEnd(9)} ${o.a} ↔ ${o.b}  [${o.via.join(" ")}]`);
}

console.log(`  生えた: IOC ${report.grown.iocs} / 実体 ${report.grown.entities.length}`
  + ` / 別名 ${report.grown.aliases.length} / 共有証明書 ${report.grown.shared_certs.length}`);
for (const e of report.grown.entities.slice(0, 8)) console.log(`    + ${e.name}（IOC ${e.ioc_count}）`);
for (const a of report.grown.aliases.slice(0, 5)) console.log(`    ~ ${a.name} = ${a.aliases.join(" / ")}`);
for (const c of report.grown.shared_certs.slice(0, 5)) {
  console.log(`    # ${c.thumbprint.slice(0, 12)} ${c.issuer || "?"} / ${c.subject || "?"}  ${c.iocs.join(" ")}`);
}

console.log("  見に行くもの:");
console.log(`    索引が C2 などと言うのに検知 0 … ${report.to_check.disagreement.total} 件`);
for (const d of report.to_check.disagreement.samples.slice(0, 5)) {
  console.log(`      ${d.ioc}  [${(d.classes || []).join(" ")}]  ${(d.sources || []).join(" ")}`);
}
console.log(`    VT が知らない … ${report.to_check.unknown.total} 件`);
console.log(`    経路表と AS が食い違う … ${report.to_check.asn_differs.total} 件`);
if (topMalicious.length) {
  console.log("    検知が多い新顔:");
  for (const r of topMalicious.slice(0, 5)) console.log(`      ${String(r.malicious).padStart(3)} ${r.ioc}  ${r.label || ""}`);
}
if (topAbuse.length) {
  console.log("    スコアの高い新顔の IP:");
  for (const r of topAbuse.slice(0, 5)) console.log(`      ${String(r.score).padStart(3)} ${r.ioc}  通報 ${r.reports}/${r.reporters} 人  ${r.usage_type || ""}`);
}
if (args.json) console.log(`  → ${args.json}`);
