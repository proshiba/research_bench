#!/usr/bin/env node
// 集めた IOC から「重なり」を計算する。外部呼び出しなし。
//
//   node tools/ioc/stats.mjs [--in data/ioc/latest] [--out <同じ場所>]
//                            [--since <前回のスナップショット>] [--include-noise]
//
// 重なりの見方を 3 つ出す。どれも「共有している IOC の数」を根拠にする。
//   ioc        … 同じ IOC を指している（最も強い）
//   subnet     … 同じ /24 に IP がある（インフラの共有。API 不要で出せる）
//   registrable… 同じ登録可能ドメインを使っている
//
// 既定では bogon と noise（公開 DNS など）を除く。これらは誰にでも現れるので、
// 入れると重なりの上位が意味の無いもので埋まる。--include-noise で戻せる。
//
// 出力
//   stats.json      件数・種別内訳・重なりの要約
//   overlaps.jsonl  実体の組ごとの重なり（根拠つき）
//   graph.json      実体と重なりのグラフ（そのまま描ける形）
//   new.jsonl       --since を渡したときだけ。前回に無かった IOC

import path from "node:path";
import { byKeys, parseArgs, readJson, readJsonl, writeJson, writeJsonl } from "./lib/io.mjs";
import { REPO_ROOT } from "./lib/sources.mjs";

const args = parseArgs(process.argv.slice(2));
const IN = path.resolve(REPO_ROOT, args.in || "data/ioc/latest");
const OUT = path.resolve(REPO_ROOT, args.out || args.in || "data/ioc/latest");
const INCLUDE_NOISE = !!args["include-noise"];
/** これ以上の実体に付いている IOC は「ありふれている」として重なりの根拠から外す。 */
const UBIQUITY_CAP = Number(args["ubiquity-cap"] || 8);

const iocs = readJsonl(path.join(IN, "iocs.jsonl"));
const links = readJsonl(path.join(IN, "links.jsonl"));
const entities = readJsonl(path.join(IN, "entities.jsonl"));
const meta = readJson(path.join(IN, "meta.json"), {});
if (!iocs.length) {
  console.error(`${IN} に iocs.jsonl がありません。先に collect.mjs を実行してください。`);
  process.exit(1);
}

const iocById = new Map(iocs.map((r) => [r.key, r]));
const usable = (key) => {
  const r = iocById.get(key);
  if (!r) return false;
  if (r.malformed) return false;
  if (!INCLUDE_NOISE && (r.bogon || r.noise)) return false;
  return true;
};

/* ---------------- 実体 ↔ IOC ---------------- */

const KINDS = ["actor", "malware", "campaign", "case"];
/** kind → (実体名 → IOC 鍵の集合) */
const owned = new Map(KINDS.map((k) => [k, new Map()]));
for (const l of links) {
  if (!KINDS.includes(l.kind)) continue;
  if (!usable(l.ioc)) continue;
  const m = owned.get(l.kind);
  if (!m.has(l.name)) m.set(l.name, new Set());
  m.get(l.name).add(l.ioc);
}

/**
 * 組ごとの共有数を数える。
 *
 * 総当たりだと実体数の 2 乗になるので、IOC 側から「その IOC を共有する実体」を
 * 見て、実際に共有がある組だけを起こす。ありふれた IOC（多数の実体に付くもの）は
 * 根拠として弱いうえに組を大量に生むので、上限を超えたら数えない。
 */
function pairsFor(kind, groups) {
  const pairCount = new Map();  // "a\tb" → { n, via:Set }
  for (const [via, byValue] of groups) {
    for (const [, names] of byValue) {
      const list = [...names].sort();
      if (list.length < 2 || list.length > UBIQUITY_CAP) continue;
      for (let i = 0; i < list.length; i++) {
        for (let j = i + 1; j < list.length; j++) {
          const k = `${list[i]}\t${list[j]}`;
          if (!pairCount.has(k)) pairCount.set(k, { n: 0, via: new Set() });
          const p = pairCount.get(k);
          p.n++;
          p.via.add(via);
        }
      }
    }
  }
  const sizes = owned.get(kind);
  return [...pairCount.entries()].map(([k, v]) => {
    const [a, b] = k.split("\t");
    const sa = sizes.get(a)?.size || 0;
    const sb = sizes.get(b)?.size || 0;
    return {
      kind,
      a,
      b,
      shared: v.n,
      via: [...v.via].sort(),
      a_iocs: sa,
      b_iocs: sb,
      // 小さいほうに対する割合。件数だけだと大きい実体が常に上位に来る
      ratio: Math.round((v.n / Math.max(1, Math.min(sa, sb))) * 1000) / 1000,
    };
  });
}

/** 根拠ごとの「値 → その値を共有する実体名の集合」。 */
function groupsFor(kind) {
  const byIoc = new Map();
  const bySubnet = new Map();
  const byDomain = new Map();
  const m = owned.get(kind);
  for (const [name, keys] of m) {
    for (const key of keys) {
      const rec = iocById.get(key);
      const put = (map, k) => {
        if (!k) return;
        if (!map.has(k)) map.set(k, new Set());
        map.get(k).add(name);
      };
      put(byIoc, key);
      put(bySubnet, rec.subnet);
      put(byDomain, rec.registrable);
    }
  }
  return [["ioc", byIoc], ["subnet", bySubnet], ["registrable", byDomain]];
}

const overlaps = [];
for (const kind of KINDS) {
  if (!owned.get(kind).size) continue;
  overlaps.push(...pairsFor(kind, groupsFor(kind)));
}
overlaps.sort(byKeys("kind", "a", "b"));

/* ---------------- /24 の同居 ---------------- */

const subnetOwners = new Map();   // /24 → { ips:Set, actors:Set, malware:Set }
for (const r of iocs) {
  if (r.type !== "ioc.ipv4" || !r.subnet) continue;
  if (!INCLUDE_NOISE && (r.bogon || r.noise)) continue;
  if (!subnetOwners.has(r.subnet)) {
    subnetOwners.set(r.subnet, { ips: new Set(), actors: new Set(), malware: new Set() });
  }
  subnetOwners.get(r.subnet).ips.add(r.value);
}
for (const l of links) {
  if (l.kind !== "actor" && l.kind !== "malware") continue;
  const r = iocById.get(l.ioc);
  if (!r?.subnet || !subnetOwners.has(r.subnet)) continue;
  subnetOwners.get(r.subnet)[l.kind === "actor" ? "actors" : "malware"].add(l.name);
}
const subnets = [...subnetOwners.entries()]
  .map(([net, v]) => ({
    subnet: net,
    ips: v.ips.size,
    actors: [...v.actors].sort(),
    malware: [...v.malware].sort(),
  }))
  .filter((s) => s.ips > 1 || s.actors.length > 1)
  .sort(byKeys("subnet"));

/* ---------------- 前回との差分 ---------------- */

let added = [];
if (args.since) {
  const prevDir = path.resolve(REPO_ROOT, args.since);
  const prev = new Set(readJsonl(path.join(prevDir, "iocs.jsonl")).map((r) => r.key));
  added = iocs.filter((r) => !prev.has(r.key)).sort(byKeys("type", "value"));
  writeJsonl(path.join(OUT, "new.jsonl"), added);
}

/* ---------------- グラフ ---------------- */

const MIN_SHARED = Number(args["min-shared"] || 1);
const graphPairs = overlaps.filter((o) => o.shared >= MIN_SHARED);
const usedNames = new Set();
for (const o of graphPairs) { usedNames.add(`${o.kind}\t${o.a}`); usedNames.add(`${o.kind}\t${o.b}`); }
const entityByKey = new Map(entities.map((e) => [`${e.kind}\t${e.name}`, e]));

writeJson(path.join(OUT, "graph.json"), {
  schema: 1,
  generated_from: meta.collected_at || null,
  week: meta.week || null,
  nodes: [...usedNames].sort().map((k) => {
    const [kind, name] = k.split("\t");
    const e = entityByKey.get(k);
    return { id: k.replace("\t", ":"), kind, name, ioc_count: e?.ioc_count ?? 0 };
  }),
  edges: graphPairs
    .map((o) => ({
      source: `${o.kind}:${o.a}`,
      target: `${o.kind}:${o.b}`,
      kind: o.kind,
      shared: o.shared,
      ratio: o.ratio,
      via: o.via,
    }))
    .sort(byKeys("kind", "source", "target")),
});

writeJsonl(path.join(OUT, "overlaps.jsonl"), overlaps);

/* ---------------- 要約 ---------------- */

const top = (kind, n = 10) => overlaps
  .filter((o) => o.kind === kind)
  .sort((a, b) => b.shared - a.shared || b.ratio - a.ratio || (a.a < b.a ? -1 : 1))
  .slice(0, n)
  .map((o) => ({ a: o.a, b: o.b, shared: o.shared, ratio: o.ratio, via: o.via }));

const byType = {};
for (const r of iocs) byType[r.type] = (byType[r.type] || 0) + 1;

const stats = {
  tool: "tools/ioc/stats.mjs",
  schema: 1,
  from: { collected_at: meta.collected_at || null, week: meta.week || null },
  options: { include_noise: INCLUDE_NOISE, ubiquity_cap: UBIQUITY_CAP, min_shared: MIN_SHARED },
  iocs: {
    total: iocs.length,
    usable: iocs.filter((r) => usable(r.key)).length,
    by_type: byType,
    excluded: {
      bogon: iocs.filter((r) => r.bogon).length,
      noise: iocs.filter((r) => r.noise).length,
      malformed: iocs.filter((r) => r.malformed).length,
    },
    dated: iocs.filter((r) => r.observed_first).length,
  },
  entities: Object.fromEntries(KINDS.map((k) => [k, owned.get(k).size])),
  overlaps: Object.fromEntries(KINDS.map((k) => [k, {
    pairs: overlaps.filter((o) => o.kind === k).length,
    by_via: ["ioc", "subnet", "registrable"].reduce((acc, v) => {
      acc[v] = overlaps.filter((o) => o.kind === k && o.via.includes(v)).length;
      return acc;
    }, {}),
    top: top(k),
  }])),
  subnets: {
    total: subnets.length,
    multi_actor: subnets.filter((s) => s.actors.length > 1).length,
    top: subnets
      .filter((s) => s.actors.length > 1)
      .sort((a, b) => b.actors.length - a.actors.length || b.ips - a.ips)
      .slice(0, 15),
  },
  ...(args.since ? { new_since: { dir: args.since, count: added.length } } : {}),
};
writeJson(path.join(OUT, "stats.json"), stats);

console.log(`IOC ${iocs.length}（分析対象 ${stats.iocs.usable}）`);
for (const k of KINDS) {
  const n = stats.overlaps[k].pairs;
  if (n) console.log(`  ${k.padEnd(9)} 実体 ${String(owned.get(k).size).padStart(4)} / 重なり ${n} 組`);
}
console.log(`  /24 で別アクターが同居: ${stats.subnets.multi_actor} 網`);
if (args.since) console.log(`  前回から増えた IOC: ${added.length} 件`);
console.log(`  → ${path.relative(REPO_ROOT, OUT)}`);
