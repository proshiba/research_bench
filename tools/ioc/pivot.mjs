#!/usr/bin/env node
// ピボットの写しから、アクターとアクターを結ぶ「橋」を出す。**写しだけを見る**。
//
//   node tools/ioc/pivot.mjs [--in data/ioc/latest] [--cache data/ioc/.cache/vt-pivot]
//                            [--out data/ioc/latest/pivot-bridges.jsonl]
//
// 同じ写しからは何度でも同じ結果が出る。外には出ない。
//
// ## なぜガードが 5 つも要るのか
//
// 索引に無い検体を拾ってきて、その構造ハッシュが既知のアクターの検体と一致したら
// 「橋」と呼ぶ——という素朴なやり方は**まったく使い物にならない**。
// 2026-W33 の実測では、生の橋 62 組のうち 37 組が下のどれかに引っかかった。
// 引っかかった中身は、汎用のインストーラ・スタブ、10 年離れた検体、検知 0 の
// ファイル、5 年前の別の借り手が残した痕跡だった。
//
// 閾値はすべて**外れ値と本体の間に隙間があることを確かめてから**引いている。
// 勘で決めた数字はひとつも無い。
import path from "node:path";
import { parseArgs, readJsonl, writeJsonl, writeJson } from "./lib/io.mjs";
import { readAllRecords } from "./lib/enrich.mjs";
import { REPO_ROOT } from "./lib/sources.mjs";

const args = parseArgs(process.argv.slice(2));
const IN = path.resolve(REPO_ROOT, args.in || "data/ioc/latest");
const CACHE = path.resolve(REPO_ROOT, args.cache || "data/ioc/.cache/vt-pivot");
const OUT = path.resolve(REPO_ROOT, args.out || path.join(IN, "pivot-bridges.jsonl"));

/** ガード 1: この数以上のアクターにまたがる値は根拠にしない。
 *  実測: imphash は 24 アクター（432 IOC）と 12 アクターの 2 値だけが飛び抜け、
 *  残りは全部 3 以下。vhash は最大 4。5 で切ると隙間の真ん中を通る */
const FANOUT_CAP = Number(args["fanout-cap"] || 5);
/** ガード 2: 両側の検体の初出がこれ以上離れていたら却下。
 *  実測: `APT29 ↔ shinyenigma` が 10.2 年（CozyDuke 2015 と Umbral Stealer 2025）。
 *  残りは全部 0.4 年以下 */
const ERA_GAP_YEARS = Number(args["era-gap"] || 5);
/** ガード 3: 索引がその素性を観測した日から検体がこれ以上ずれていたら却下。
 *  実測: `103.27.108.55` は索引が 2026-05 に観測、拾えた検体は 2021 年。
 *  IP は借り手が変わるので、5 年前の痕跡を今の持ち主の根拠にはできない */
const OBSERVED_DRIFT_YEARS = Number(args["drift"] || 2);
/** ガード 4: 検知数がこれ未満の検体は根拠にしない。
 *  実測: 検知 0 のファイルが `Gorgon Group ↔ Void Balaur` を作っていた */
const MIN_MALICIOUS = Number(args["min-malicious"] || 2);
/** ガード 5: 汎用スタブの判定。検体がこの数以上あり、かつ別名の種類数の比が
 *  この値以上なら「1 検体ごとに違う名前」＝ 配布基盤の共通スタブとみなす。
 *  実測: `d42595b6` は 92 検体 / 86 種 = 0.93（`CapCut_Desktop[Pro].exe`
 *  `FL_Studio_Activator.exe` …割れソフト配布）。一方 ValleyRAT の偽インストーラ
 *  `9be4f90f` は 118 検体 / 71 種 = 0.60 でブランド雛形なので残る。
 *  **件数だけで切ると作戦固有の値まで落ちる**ので、名前の多様性で判別する */
const GENERIC_MIN_SAMPLES = Number(args["generic-min"] || 20);
const GENERIC_NAME_RATIO = Number(args["generic-ratio"] || 0.8);

const YEAR_MS = 31557600000;
const years = (a, b) => (a && b) ? Math.abs(new Date(a) - new Date(b)) / YEAR_MS : null;

/* ---------------- 索引側 ---------------- */

const iocs = new Map([...readJsonl(path.join(IN, "iocs.jsonl")),
  ...readJsonl(path.join(IN, "derived-iocs.jsonl"))].map((r) => [r.key, r]));
const vt = new Map([...readJsonl(path.join(IN, "vt.jsonl")),
  ...readJsonl(path.join(IN, "derived-verdicts.jsonl"))].map((r) => [r.ioc, r]));
const links = [...readJsonl(path.join(IN, "links.jsonl")),
  ...readJsonl(path.join(IN, "derived-links.jsonl"))];
const knownPairs = new Set(readJsonl(path.join(IN, "overlaps.jsonl"))
  .filter((o) => o.kind === "actor").map((o) => [o.a, o.b].sort().join("\u0000")));

const actorOf = new Map(), relsOf = new Map();
for (const l of links) {
  if (!relsOf.has(l.ioc)) relsOf.set(l.ioc, new Set());
  if (l.rel) relsOf.get(l.ioc).add(l.rel);
  if (l.kind !== "actor") continue;
  if (!actorOf.has(l.ioc)) actorOf.set(l.ioc, new Set());
  actorOf.get(l.ioc).add(l.name);
}

/** ガード 0: ピボット**元**にも索引と同じ選別を掛ける。
 *  fetch-pivot.mjs が的を選ぶときにも同じ判定をするが、**写しは残り続ける**ので
 *  解析側でもやり直す。選別を入れる前に引いた写しが混ざると、`polygon-rpc.com`
 *  （検知 3・無害判定 56 の正規 Polygon RPC エンドポイント）のような素性が
 *  橋を量産する。実測ではそれだけで 12 組のゴミが出た。 */
const GENERIC_REL = new Set(["観測アクター", "関連"]);
const goodSource = (key) => {
  const r = relsOf.get(key);
  if (!(r && [...r].some((x) => !GENERIC_REL.has(x)))) return false;
  const i = iocs.get(key) || {};
  if (i.popular || i.noise || i.bogon || i.sample) return false;
  const v = vt.get(key) || {};
  const mal = v.malicious ?? 0, harm = v.harmless ?? 0;
  return mal >= 5 || (mal >= 2 && harm < 40);
};

/* ---------------- 値ごとの広がりを数える（ガード 1・5 の材料） ---------------- */

const spread = new Map(); // 値 -> { iocs, actors, names }
const note = (v, key, name) => {
  if (!v) return;
  if (!spread.has(v)) spread.set(v, { iocs: new Set(), actors: new Set(), names: new Set() });
  const b = spread.get(v);
  b.iocs.add(key);
  for (const a of actorOf.get(key) || []) b.actors.add(a);
  if (name) b.names.add(String(name).replace(/[0-9a-f]{12,}/gi, "<h>"));
};
for (const [key, r] of vt) {
  const name = (r.names || [])[0] || r.label;
  note(r.vhash, key, name);
  note(r.imphash, key, name);
}
const cacheRecords = readAllRecords(CACHE);
for (const rec of cacheRecords) {
  for (const x of rec.ids || []) {
    if (!x.sha256) continue;
    note(x.vhash, "ioc.sha256|" + x.sha256, x.name);
    note(x.imphash, "ioc.sha256|" + x.sha256, x.name);
  }
}
const generic = (v) => {
  const b = spread.get(v);
  return !!(b && b.iocs.size >= GENERIC_MIN_SAMPLES && b.names.size / b.iocs.size >= GENERIC_NAME_RATIO);
};
const tooWide = (v) => (spread.get(v)?.actors.size || 0) >= FANOUT_CAP;

/** 使える値だけを「値 -> 既知の検体たち」に畳む */
const byValue = { vhash: new Map(), imphash: new Map() };
for (const [key, r] of vt) {
  const actors = actorOf.get(key);
  if (!actors) continue;
  for (const lay of ["vhash", "imphash"]) {
    const v = r[lay];
    if (!v || tooWide(v) || generic(v)) continue;
    if (!byValue[lay].has(v)) byValue[lay].set(v, []);
    byValue[lay].get(v).push({ key, actors, mal: r.malicious, first: r.first_submission, type: r.type_description });
  }
}

/* ---------------- 橋を出す ---------------- */

const bridges = new Map();
let rows = 0, dropped = 0;
for (const rec of cacheRecords) {
  const m = String(rec.ioc || "").match(/^rel\|[a-z_]+\|(ioc\.[a-z0-9]+\|.+)$/);
  if (!m) continue;
  const srcKey = m[1];
  const srcActors = actorOf.get(srcKey);
  if (!srcActors || !goodSource(srcKey)) continue;
  const observed = iocs.get(srcKey)?.observed_first;
  for (const x of rec.ids || []) {
    if (!x.sha256) continue;
    for (const lay of ["vhash", "imphash"]) {
      const v = x[lay];
      if (!v || !byValue[lay].has(v)) continue;
      for (const hit of byValue[lay].get(v)) {
        for (const a of srcActors) for (const b of hit.actors) {
          if (a === b) continue;
          rows++;
          const why = [];
          if ((x.mal ?? 0) < MIN_MALICIOUS) why.push(`拾った検体の検知が ${x.mal ?? 0}`);
          if ((hit.mal ?? 0) < MIN_MALICIOUS) why.push(`既知側の検知が ${hit.mal ?? 0}`);
          const era = years(x.first, hit.first);
          if (era !== null && era >= ERA_GAP_YEARS) why.push(`年代差 ${era.toFixed(1)} 年`);
          const drift = years(x.first, observed);
          if (drift !== null && drift >= OBSERVED_DRIFT_YEARS) why.push(`索引の観測から ${drift.toFixed(1)} 年ずれ`);
          if (x.type && hit.type && x.type !== hit.type) why.push("型が違う");
          const pair = [a, b].sort().join("\u0000");
          if (!bridges.has(pair)) bridges.set(pair, { ok: [], ng: new Set() });
          if (why.length) { bridges.get(pair).ng.add(why.join(" / ")); dropped++; continue; }
          bridges.get(pair).ok.push({ layer: lay, value: v, via: srcKey,
            sample: x.sha256, sample_first: x.first, sample_malicious: x.mal,
            known: hit.key, known_first: hit.first, known_malicious: hit.mal });
        }
      }
    }
  }
}

const out = [];
for (const [pair, v] of bridges) {
  if (!v.ok.length) continue;
  const [a, b] = pair.split("\u0000");
  const e = v.ok[0];
  out.push({ a, b, known_pair: knownPairs.has(pair), support: v.ok.length,
    layer: e.layer, value: e.value, via: e.via,
    sample: e.sample, sample_first: e.sample_first, sample_malicious: e.sample_malicious,
    known: e.known, known_first: e.known_first, known_malicious: e.known_malicious,
    value_spread: { iocs: spread.get(e.value)?.iocs.size ?? 0, actors: spread.get(e.value)?.actors.size ?? 0 } });
}
out.sort((x, y) => y.support - x.support || x.a.localeCompare(y.a) || x.b.localeCompare(y.b));
writeJsonl(OUT, out);

const dropOnly = [...bridges].filter(([, v]) => !v.ok.length);
console.log(`写し ${cacheRecords.length} 件 / 値の照合 ${rows} 回`);
console.log(`橋: ${bridges.size} 組 → ガードを通った ${out.length} 組（全部落ちた ${dropOnly.length} 組 / 落とした照合 ${dropped} 回）`);
console.log(`  うち索引に既にある組: ${out.filter((o) => o.known_pair).length} / 新規 ${out.filter((o) => !o.known_pair).length}`);
console.log("\n通った組:");
for (const o of out.slice(0, 30)) {
  console.log(`  ${o.known_pair ? "既知" : "★新規"}  ${o.a} ↔ ${o.b}`);
  console.log(`        ${o.layer} ${o.value.slice(0, 18)}  ${o.via.split("|")[1]} 経由  根拠 ${o.support} 件  値の広がり ${o.value_spread.iocs} IOC / ${o.value_spread.actors} アクター`);
}
if (dropOnly.length) {
  console.log("\n落ちた組（理由）:");
  for (const [pair, v] of dropOnly.slice(0, 20)) {
    console.log(`  ${pair.replace("\u0000", " ↔ ").padEnd(46)} ${[...v.ng][0]}`);
  }
}
writeJson(path.join(IN, "pivot-meta.json"), {
  tool: "tools/ioc/pivot.mjs", schema: 1,
  built_at: new Date().toISOString(),
  guards: { fanout_cap: FANOUT_CAP, era_gap_years: ERA_GAP_YEARS,
    observed_drift_years: OBSERVED_DRIFT_YEARS, min_malicious: MIN_MALICIOUS,
    generic_min_samples: GENERIC_MIN_SAMPLES, generic_name_ratio: GENERIC_NAME_RATIO },
  cache_records: cacheRecords.length, checks: rows,
  bridges: { total: bridges.size, passed: out.length, dropped: dropOnly.length,
    known: out.filter((o) => o.known_pair).length, fresh: out.filter((o) => !o.known_pair).length },
});
console.log(`\n  → ${OUT}`);
