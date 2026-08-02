#!/usr/bin/env node
// 集めた IOC から「重なり」を計算する。外部呼び出しなし。
//
//   node tools/ioc/stats.mjs [--in data/ioc/latest] [--out <同じ場所>]
//                            [--since <前回のスナップショット>] [--include-noise]
//
// 重なりの見方を 4 つ出す。どれも「共有している IOC の数」を根拠にする。
//   ioc        … 同じ IOC を指している（最も強い）
//   subnet     … 同じ /24 に IP がある（インフラの共有。API 不要で出せる）
//   registrable… 同じ登録可能ドメインを使っている
//   asn        … 同じ AS に IP がある。**小さい AS に限る**（enrich-asn.mjs が要る）
//
// asn を大きさで絞るのは、絞らないと意味を持たないため。400 万アドレスを持つ事業者に
// 2 つの実体が居るのは偶然だが、1,024 アドレスしか持たない AS なら同じ相手から
// 借りているとみてよい。境目は --asn-max-addresses（既定 65,536 = /16 相当）。
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
/**
 * AS を根拠に使う条件。どちらも満たすものだけ。
 *   大きさ    … これより多くのアドレスを持つ AS は事業者規模で、同居に意味が無い
 *   アクター数… 多くの実体が居る AS は、実測として「みんなが借りる所」＝相乗り
 * 大きさだけで決めると、5 万アドレス程度の VPS 事業者が残ってしまう（実測で確認）。
 */
const ASN_MAX_ADDRESSES = Number(args["asn-max-addresses"] || 4096);
const ASN_MAX_ACTORS = Number(args["asn-max-actors"] || args["ubiquity-cap"] || 8);

const iocs = readJsonl(path.join(IN, "iocs.jsonl"));
const links = readJsonl(path.join(IN, "links.jsonl"));
const entities = readJsonl(path.join(IN, "entities.jsonl"));
const meta = readJson(path.join(IN, "meta.json"), {});
if (!iocs.length) {
  console.error(`${IN} に iocs.jsonl がありません。先に collect.mjs を実行してください。`);
  process.exit(1);
}

/* AS の情報は enrich-asn.mjs があれば使う。無くても他は全部出る */
const asnInfo = new Map(readJsonl(path.join(IN, "asns.jsonl")).map((a) => [a.asn, a]));
const asnOf = new Map();
for (const r of readJsonl(path.join(IN, "ip-asn.jsonl"))) if (r.asn) asnOf.set(r.ioc, r.asn);
const HAS_ASN = asnOf.size > 0;

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

/** AS ごとに、そこで見えたアクターの数。相乗り（事業者）かどうかの実測。 */
const actorsPerAsn = new Map();
for (const l of links) {
  if (l.kind !== "actor" || !usable(l.ioc)) continue;
  const asn = asnOf.get(l.ioc);
  if (!asn) continue;
  if (!actorsPerAsn.has(asn)) actorsPerAsn.set(asn, new Set());
  actorsPerAsn.get(asn).add(l.name);
}
/** 小さく、かつ多くのアクターが居ない AS だけを根拠に使う。 */
const asnUsable = (asn) => {
  const a = asnInfo.get(asn);
  if (!a || !(a.addresses > 0) || a.addresses > ASN_MAX_ADDRESSES) return false;
  return (actorsPerAsn.get(asn)?.size ?? 0) <= ASN_MAX_ACTORS;
};

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
  const byAsn = new Map();
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
      const asn = asnOf.get(key);
      if (asn && asnUsable(asn)) put(byAsn, `AS${asn}`);
    }
  }
  return [
    ["ioc", byIoc], ["subnet", bySubnet], ["registrable", byDomain],
    ...(HAS_ASN ? [["asn", byAsn]] : []),
  ];
}

const overlaps = [];
for (const kind of KINDS) {
  if (!owned.get(kind).size) continue;
  overlaps.push(...pairsFor(kind, groupsFor(kind)));
}
overlaps.sort(byKeys("kind", "a", "b"));

/* ---------------- /24 の同居 ---------------- */

/**
 * 「同じ入れ物に複数の実体が居る」を数える。/24 と AS で同じ形をとる。
 * 入れ物の鍵の作り方だけを差し替える。
 */
function coTenancy(binOf) {
  const bins = new Map();   // 鍵 → { ips:Set, actors:Set, malware:Set }
  for (const r of iocs) {
    if (r.type !== "ioc.ipv4" && r.type !== "ioc.ipv6") continue;
    if (!INCLUDE_NOISE && (r.bogon || r.noise)) continue;
    const bin = binOf(r);
    if (bin === null || bin === undefined) continue;
    if (!bins.has(bin)) bins.set(bin, { ips: new Set(), actors: new Set(), malware: new Set() });
    bins.get(bin).ips.add(r.value);
  }
  for (const l of links) {
    if (l.kind !== "actor" && l.kind !== "malware") continue;
    const r = iocById.get(l.ioc);
    if (!r) continue;
    const bin = binOf(r);
    if (bin === null || bin === undefined || !bins.has(bin)) continue;
    bins.get(bin)[l.kind === "actor" ? "actors" : "malware"].add(l.name);
  }
  return bins;
}

const subnetOwners = coTenancy((r) => (r.type === "ioc.ipv4" ? r.subnet : null));
const subnets = [...subnetOwners.entries()]
  .map(([net, v]) => {
    // その /24 を出している AS も添える。小さい AS なら同居の意味が強い
    const asns = new Set();
    for (const ip of v.ips) {
      const asn = asnOf.get(`ioc.ipv4|${ip}`);
      if (asn) asns.add(asn);
    }
    return {
      subnet: net,
      ips: v.ips.size,
      actors: [...v.actors].sort(),
      malware: [...v.malware].sort(),
      ...(asns.size ? {
        asns: [...asns].sort((a, b) => a - b).map((asn) => ({
          asn,
          name: asnInfo.get(asn)?.name ?? null,
          addresses: asnInfo.get(asn)?.addresses ?? 0,
        })),
      } : {}),
    };
  })
  .filter((s) => s.ips > 1 || s.actors.length > 1)
  .sort(byKeys("subnet"));

/* ---------------- AS の同居 ---------------- */

const asnOwners = HAS_ASN ? coTenancy((r) => asnOf.get(r.key) ?? null) : new Map();
const asnCoTenancy = [...asnOwners.entries()]
  .map(([asn, v]) => {
    const info = asnInfo.get(asn) || {};
    return {
      asn,
      name: info.name ?? null,
      cc: info.cc ?? null,
      addresses: info.addresses ?? 0,
      ips: v.ips.size,
      actors: [...v.actors].sort(),
      malware: [...v.malware].sort(),
      // 相乗りかどうか。根拠に使うかどうかと同じ判定にする
      shared_hosting: !asnUsable(asn),
    };
  })
  .filter((a) => a.actors.length > 1 || a.malware.length > 1)
  .sort(byKeys("asn"));

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
// 要約には上位しか載らないので、同居は全件を別に残す
writeJsonl(path.join(OUT, "subnets.jsonl"), subnets);
if (HAS_ASN) writeJsonl(path.join(OUT, "asn-cotenancy.jsonl"), asnCoTenancy);

/* ---------------- 要約 ---------------- */

const top = (kind, n = 10) => overlaps
  .filter((o) => o.kind === kind)
  .sort((a, b) => b.shared - a.shared || b.ratio - a.ratio || (a.a < b.a ? -1 : 1))
  .slice(0, n)
  .map((o) => ({ a: o.a, b: o.b, shared: o.shared, ratio: o.ratio, via: o.via }));

const byType = {};
for (const r of iocs) byType[r.type] = (byType[r.type] || 0) + 1;

const VIA = ["ioc", "subnet", "registrable", ...(HAS_ASN ? ["asn"] : [])];

const stats = {
  tool: "tools/ioc/stats.mjs",
  schema: 1,
  from: { collected_at: meta.collected_at || null, week: meta.week || null },
  options: {
    include_noise: INCLUDE_NOISE,
    ubiquity_cap: UBIQUITY_CAP,
    min_shared: MIN_SHARED,
    ...(HAS_ASN ? { asn_max_addresses: ASN_MAX_ADDRESSES } : {}),
  },
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
    by_via: VIA.reduce((acc, v) => {
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
  ...(HAS_ASN ? {
    asns: {
      total: asnInfo.size,
      small: [...asnInfo.values()].filter((a) => a.addresses > 0 && a.addresses <= ASN_MAX_ADDRESSES).length,
      multi_actor: asnCoTenancy.filter((a) => a.actors.length > 1).length,
      // 相乗りを除いた分。ここに出るものは「同じ相手から借りている」とみてよい
      multi_actor_small: asnCoTenancy.filter((a) => a.actors.length > 1 && !a.shared_hosting).length,
      top: asnCoTenancy
        .filter((a) => a.actors.length > 1 && !a.shared_hosting)
        .sort((a, b) => b.actors.length - a.actors.length || a.addresses - b.addresses)
        .slice(0, 15),
      // 除いたほうも捨てない。「多くのアクターが買っている事業者」は
      // 結び付きの根拠にはならないが、それ自体が知りたいことになる
      hosting_like: asnCoTenancy
        .filter((a) => a.shared_hosting && a.actors.length >= 3)
        .sort((a, b) => b.actors.length - a.actors.length || a.asn - b.asn)
        .slice(0, 20)
        .map((a) => ({ asn: a.asn, name: a.name, cc: a.cc, addresses: a.addresses, actors: a.actors })),
    },
  } : {}),
  ...(args.since ? { new_since: { dir: args.since, count: added.length } } : {}),
};
writeJson(path.join(OUT, "stats.json"), stats);

console.log(`IOC ${iocs.length}（分析対象 ${stats.iocs.usable}）`);
for (const k of KINDS) {
  const n = stats.overlaps[k].pairs;
  if (n) console.log(`  ${k.padEnd(9)} 実体 ${String(owned.get(k).size).padStart(4)} / 重なり ${n} 組`);
}
console.log(`  /24 で別アクターが同居: ${stats.subnets.multi_actor} 網`);
if (HAS_ASN) {
  console.log(`  AS で別アクターが同居: ${stats.asns.multi_actor} 件`
    + `（うち相乗りでない小さい AS ${stats.asns.multi_actor_small} 件）`);
  for (const a of stats.asns.top.slice(0, 6)) {
    console.log(`    AS${String(a.asn).padEnd(7)} ${String(a.addresses).padStart(6)} ${(a.cc || "?").padEnd(3)} `
      + `${(a.name || "?").slice(0, 26).padEnd(26)} ${a.actors.join(" / ")}`);
  }
  if (stats.asns.hosting_like.length) {
    const h = stats.asns.hosting_like[0];
    console.log(`  多くのアクターが借りている事業者: ${stats.asns.hosting_like.length} 件`
      + `（最多 AS${h.asn} ${h.name} に ${h.actors.length} アクター）`);
  }
}
if (args.since) console.log(`  前回から増えた IOC: ${added.length} 件`);
console.log(`  → ${path.relative(REPO_ROOT, OUT)}`);
