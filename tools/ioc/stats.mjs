#!/usr/bin/env node
// 集めた IOC から「重なり」を計算する。外部呼び出しなし。
//
//   node tools/ioc/stats.mjs [--in data/ioc/latest] [--out <同じ場所>]
//                            [--since <前回のスナップショット>] [--include-noise]
//                            [--ubiquity-cap 8] [--min-shared 1]
//                            [--asn-max-addresses 4096] [--asn-max-actors 8]
//                            [--jarm-cap 0.01] [--filename-cap 8]
//                            [--hosting-ratio 0.7] [--hosting-min 3]
//
// 重なりの見方を 9 つ出す。どれも「共有している IOC の数」を根拠にする。
// 後半 5 つは enrich-intel.mjs があるときだけ出る。
//   certificate … 同じ証明書（thumbprint 一致）。**最も強いインフラ共有の証拠**
//   ioc         … 同じ IOC を指している
//   resolution  … 同じ IP に解決するドメインを持っている
//   family      … VT が同じ脅威ラベルを付けている
//   subnet      … 同じ /24 に IP がある（インフラの共有。API 不要で出せる）
//   asn         … 同じ AS に IP がある。**小さい AS に限る**（enrich-asn.mjs が要る）
//   filename    … 珍しいファイル名の共有
//   registrable … 同じ登録可能ドメインを使っている
//   jarm        … 同じ TLS 指紋。**単独では根拠にしない**
//
// **根拠に強さの順を入れる。** 共有数と割合だけだと、根拠の種類による差が数字に出ない。
// 上の順を点数にして合算した `strength` を持たせ、要約の並べ替えをこれにする。
// 弱い根拠（filename / registrable / jarm）だけで成立している組には weak_only の印を
// 付ける。**除くのではなく印を付ける**（bogon / noise と同じ扱い）。
//
// asn を大きさで絞るのは、絞らないと意味を持たないため。400 万アドレスを持つ事業者に
// 2 つの実体が居るのは偶然だが、1,024 アドレスしか持たない AS なら同じ相手から
// 借りているとみてよい。境目は --asn-max-addresses（既定 4,096 = /20 相当）。
// AbuseIPDB があれば **その AS の IP が事業者の網である割合**も見る（3 つ目の観点）。
//
// 既定では bogon と noise（公開 DNS など）を除く。これらは誰にでも現れるので、
// 入れると重なりの上位が意味の無いもので埋まる。--include-noise で戻せる。
//
// 出力
//   stats.json      **カバレッジ**・件数・種別内訳・重なりの要約・時間軸・判定の分布
//   overlaps.jsonl  実体の組ごとの重なり（根拠と強さつき）
//   graph.json      実体と重なりのグラフ（そのまま描ける形）
//   new.jsonl       --since を渡したときだけ。前回に無かった IOC
//
// stats.json の先頭には必ず coverage を置く。1 キーでは全件が埋まるまで日数がかかり、
// その途中の統計は一部しか見ていない。「検知されたのは 12%」と「調べた範囲の 12%」は
// 別物で、後者を前者として読むと必ず間違える。未エンリッチは陰性ではなく未知と数える。

import path from "node:path";
import { byKeys, parseArgs, readJson, readJsonl, writeJson, writeJsonl } from "./lib/io.mjs";
import { coverageOf } from "./lib/enrich.mjs";
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
/**
 * JARM は既定の nginx / Apache でも一致するので、**ありふれた値は外す**。
 * 全体の何割を超えたら外すか（既定 1%）。
 */
const JARM_CAP = Number(args["jarm-cap"] || 0.01);
/** ファイル名も同じ考え方。これより多くの IOC に付いている名前は根拠にしない。 */
const FILENAME_CAP = Number(args["filename-cap"] || args["ubiquity-cap"] || 8);
/**
 * AbuseIPDB が「事業者の網」と言う IP の割合がこれを超えたら相乗りとみなす（§3.2）。
 * ただし判定の付いた IP が --hosting-min 未満の AS では割合が当てにならないので使わない。
 */
const HOSTING_RATIO = Number(args["hosting-ratio"] || 0.7);
const HOSTING_MIN = Number(args["hosting-min"] || 3);

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

/* エンリッチの結果は enrich-intel.mjs があれば使う。無くても他は全部出る */
const vt = readJsonl(path.join(IN, "vt.jsonl"));
const abuse = readJsonl(path.join(IN, "abuseipdb.jsonl"));
const derivedLinks = readJsonl(path.join(IN, "derived-links.jsonl"));
const derivedCerts = readJsonl(path.join(IN, "derived-certs.jsonl"));
const enrichMeta = readJson(path.join(IN, "enrich-meta.json"));
const HAS_VT = vt.length > 0;
const HAS_ABUSE = abuse.length > 0;

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

/* ---------------- エンリッチから来る根拠 ---------------- */

const vtByIoc = new Map(vt.map((r) => [r.ioc, r]));

/** ドメイン → 解決先 IP。今の IOC ↔ IOC の辺を桁で増やすのがこれ（§2.2）。 */
const resolvesTo = new Map();
/** ハッシュ → VT が付けたファミリ名。マルウェア名の正規化の実体（§2.1）。 */
const familyOf = new Map();
for (const l of derivedLinks) {
  if (l.kind === "ioc" && l.rel === "resolves_to") {
    if (!resolvesTo.has(l.ioc)) resolvesTo.set(l.ioc, new Set());
    resolvesTo.get(l.ioc).add(l.name);
  } else if (l.kind === "malware" && l.rel === "suggested_threat_label") {
    if (!familyOf.has(l.ioc)) familyOf.set(l.ioc, new Set());
    familyOf.get(l.ioc).add(l.name);
  }
}

/**
 * 誰かの解決先になっている IP。ここに入っている IP だけを resolution の根拠に使う。
 *
 * ただし **大きい AS に居る解決先は外す**。実測すると Cloudflare（104.21.x /
 * 172.67.x / 2606:4700::）や Vercel の edge に 6〜16 の実体が集まっていた。
 * 「同じ AS に居る」が大きさ抜きでは何も言えないのと同じで、
 * **「同じ IP に解決する」も、その IP が edge なら何も言えない**。
 * AS が分からない解決先は判断できないので残す（enrich-asn.mjs が無い環境でも動く）。
 */
const resolvedIps = new Set();
const cdnIps = new Set();
for (const set of resolvesTo.values()) {
  for (const ip of set) {
    const asn = asnOf.get(ip);
    const size = asn ? (asnInfo.get(asn)?.addresses ?? 0) : 0;
    if (size > ASN_MAX_ADDRESSES) { cdnIps.add(ip); continue; }
    resolvedIps.add(ip);
  }
}

/** 共用ホスティングの証明書は根拠にしない（SAN が多すぎるもの・基盤に出されたもの）。 */
const weakCert = new Set(derivedCerts.filter((c) => c.weak).map((c) => c.thumbprint));
const certOf = new Map();
for (const r of vt) {
  if (!r.cert?.thumbprint) continue;
  if (weakCert.has(r.cert.thumbprint)) continue;
  // 自分の名前が SAN に無く、ワイルドカードで拾っただけの組み合わせは根拠にしない
  if (r.cert.wildcard) continue;
  certOf.set(r.ioc, r.cert.thumbprint);
}

/**
 * ありふれた JARM とファイル名を外す。
 * 既定の nginx で一致する JARM や `invoice.doc` を根拠にすると、
 * 無関係な実体が総当たりで繋がってしまう。
 */
const jarmCount = new Map();
for (const r of vt) if (r.jarm) jarmCount.set(r.jarm, (jarmCount.get(r.jarm) || 0) + 1);
const jarmTotal = [...jarmCount.values()].reduce((a, b) => a + b, 0);
const commonJarm = new Set([...jarmCount].filter(([, n]) => n > jarmTotal * JARM_CAP).map(([j]) => j));

const nameCount = new Map();
for (const r of vt) for (const n of r.names || []) nameCount.set(n, (nameCount.get(n) || 0) + 1);
const commonName = new Set([...nameCount].filter(([, n]) => n > FILENAME_CAP).map(([n]) => n));

/**
 * AS ごとの「事業者の網の割合」（§3.2 の 3 つ目の観点）。
 * 判定が付いた IP が少ない AS では割合が当てにならないので、件数も一緒に持つ。
 */
const hostingByAsn = new Map();
for (const r of abuse) {
  const asn = asnOf.get(r.ioc);
  if (!asn) continue;
  if (!hostingByAsn.has(asn)) hostingByAsn.set(asn, { n: 0, hosting: 0 });
  const h = hostingByAsn.get(asn);
  h.n++;
  if (r.hosting) h.hosting++;
}
const hostingRatio = (asn) => {
  const h = hostingByAsn.get(asn);
  if (!h || h.n < HOSTING_MIN) return null;
  return Math.round((h.hosting / h.n) * 1000) / 1000;
};

/** AS ごとに、そこで見えたアクターの数。相乗り（事業者）かどうかの実測。 */
const actorsPerAsn = new Map();
for (const l of links) {
  if (l.kind !== "actor" || !usable(l.ioc)) continue;
  const asn = asnOf.get(l.ioc);
  if (!asn) continue;
  if (!actorsPerAsn.has(asn)) actorsPerAsn.set(asn, new Set());
  actorsPerAsn.get(asn).add(l.name);
}
/**
 * 小さく、多くのアクターが居ず、事業者の網でもない AS だけを根拠に使う。
 * 3 つ目（事業者の網の割合）は AbuseIPDB の判定が足りている AS にだけ効く。
 */
const asnUsable = (asn) => {
  const a = asnInfo.get(asn);
  if (!a || !(a.addresses > 0) || a.addresses > ASN_MAX_ADDRESSES) return false;
  if ((actorsPerAsn.get(asn)?.size ?? 0) > ASN_MAX_ACTORS) return false;
  const hr = hostingRatio(asn);
  return !(hr !== null && hr > HOSTING_RATIO);
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
    const via = [...v.via].sort();
    return {
      kind,
      a,
      b,
      shared: v.n,
      via,
      // 根拠の種類による差を数字に出す。共有数だけでは弱い根拠が 10 個ある組が上位に来る
      strength: strengthOf(via),
      ...(via.every((x) => WEAK_VIA.has(x)) ? { weak_only: true } : {}),
      a_iocs: sa,
      b_iocs: sb,
      // 小さいほうに対する割合。件数だけだと大きい実体が常に上位に来る
      ratio: Math.round((v.n / Math.max(1, Math.min(sa, sb))) * 1000) / 1000,
    };
  });
}

/**
 * 根拠の強さ（docs/ioc-enrich-plan.md §3.1）。
 * 同じ証明書を使っている > 同じ IOC > 同じ解決先 > ファミリ・/24・AS > 名前・登録者・JARM。
 * 出てきた根拠の点数を合算する。共有数を掛けないのは、
 * 弱い根拠を数で押した組が、強い根拠 1 つの組を追い越さないようにするため。
 */
const VIA_WEIGHT = {
  certificate: 9, ioc: 8, resolution: 7,
  family: 5, subnet: 5, asn: 5,
  filename: 2, registrable: 2, jarm: 1,
};
/** これだけで成立している組には印を付ける。除きはしない（bogon / noise と同じ扱い）。 */
const WEAK_VIA = new Set(["filename", "registrable", "jarm"]);
const strengthOf = (via) => via.reduce((n, v) => n + (VIA_WEIGHT[v] || 0), 0);

/** 根拠ごとの「値 → その値を共有する実体名の集合」。 */
function groupsFor(kind) {
  const byIoc = new Map();
  const bySubnet = new Map();
  const byDomain = new Map();
  const byAsn = new Map();
  const byCert = new Map();
  const byResolution = new Map();
  const byFamily = new Map();
  const byFilename = new Map();
  const byJarm = new Map();
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

      if (!HAS_VT) continue;
      put(byCert, certOf.get(key));
      // **ドメインしか持たない実体と IP しか持たない実体が繋がる**のがこの根拠の狙い。
      // ただし自分の IP を無条件に入れると `ioc`（同じ IOC を指している）の写しに
      // なってしまうので、**誰かの解決先になっている IP のときだけ**数える
      if (resolvedIps.has(key)) put(byResolution, key);
      for (const ip of resolvesTo.get(key) || []) if (!cdnIps.has(ip)) put(byResolution, ip);
      for (const fam of familyOf.get(key) || []) put(byFamily, fam);
      const v = vtByIoc.get(key);
      for (const n of v?.names || []) if (!commonName.has(n)) put(byFilename, n);
      if (v?.jarm && !commonJarm.has(v.jarm)) put(byJarm, v.jarm);
    }
  }
  return [
    ["ioc", byIoc], ["subnet", bySubnet], ["registrable", byDomain],
    ...(HAS_ASN ? [["asn", byAsn]] : []),
    ...(HAS_VT ? [
      ["certificate", byCert], ["resolution", byResolution],
      ["family", byFamily], ["filename", byFilename], ["jarm", byJarm],
    ] : []),
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
    const hr = hostingRatio(asn);
    return {
      asn,
      name: info.name ?? null,
      cc: info.cc ?? null,
      addresses: info.addresses ?? 0,
      ips: v.ips.size,
      actors: [...v.actors].sort(),
      malware: [...v.malware].sort(),
      // AbuseIPDB が「事業者の網」と言う IP の割合。判定が足りない AS では出さない
      ...(hr === null ? {} : { hosting_ratio: hr, hosting_seen: hostingByAsn.get(asn).n }),
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

/* ---------------- 時間軸（§3.3） ---------------- */

/**
 * VT の first_submission_date は、索引が持っていない「世に出た日」。
 * 索引の観測日と突き合わせると、**自分たちの索引がどれだけ遅れて拾っているか**が出る。
 */
const firstSub = new Map();
for (const r of vt) if (r.first_submission) firstSub.set(r.ioc, r.first_submission);

const days = (a, b) => Math.round((Date.parse(b) - Date.parse(a)) / 86400000);
const quantile = (sorted, q) => (sorted.length ? sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * q))] : null);

/** 実体ごとの活動期間。その実体に繋がる IOC が世に出た日の最小と最大。 */
function activity(kind) {
  const out = [];
  for (const [name, keys] of owned.get(kind)) {
    const ds = [...keys].map((k) => firstSub.get(k)).filter(Boolean).sort();
    if (!ds.length) continue;
    out.push({ name, first: ds[0], last: ds[ds.length - 1], dated: ds.length, iocs: keys.size });
  }
  return out.sort(byKeys("name"));
}

const campaignSpans = HAS_VT ? activity("campaign") : [];
const actorSpans = HAS_VT ? activity("actor") : [];

/** 期間が重なっている組。IOC を共有していなくても「同じ時期に動いていた」は手掛かり。 */
const timeOverlaps = [];
for (let i = 0; i < campaignSpans.length; i++) {
  for (let j = i + 1; j < campaignSpans.length; j++) {
    const [x, y] = [campaignSpans[i], campaignSpans[j]];
    if (x.first > y.last || y.first > x.last) continue;
    timeOverlaps.push({
      a: x.name, b: y.name,
      from: x.first > y.first ? x.first : y.first,
      to: x.last < y.last ? x.last : y.last,
    });
  }
}

/** 索引の遅れ。観測日 − 世に出た日。負なら索引のほうが早い。 */
const lags = [];
for (const r of iocs) {
  const sub = firstSub.get(r.key);
  if (!sub || !r.observed_first) continue;
  lags.push(days(sub, r.observed_first));
}
lags.sort((a, b) => a - b);

/* ---------------- 判定そのものの統計（§3.4） ---------------- */

const median = (xs) => {
  if (!xs.length) return null;
  const s = [...xs].sort((a, b) => a - b);
  const m = s.length >> 1;
  return s.length % 2 ? s[m] : Math.round(((s[m - 1] + s[m]) / 2) * 10) / 10;
};

/** アクターごとの悪性度。極端に低い実体は、索引の誤りか、まだ知られていないか。 */
const actorVerdicts = [];
for (const [name, keys] of owned.get("actor")) {
  const seen = [...keys].map((k) => vtByIoc.get(k)).filter((r) => r?.known);
  if (!seen.length) continue;
  actorVerdicts.push({
    name,
    checked: seen.length,
    iocs: keys.size,
    median_malicious: median(seen.map((r) => r.malicious)),
    unknown: [...keys].filter((k) => vtByIoc.get(k)?.known === false).length,
  });
}
actorVerdicts.sort(byKeys("name"));

/**
 * 索引の主張と VT の判定の食い違い。索引が「C2」「マルウェア」と言っているのに
 * 検知 0 のもの。索引側の誤りか、まだ知られていないかのどちらかで、どちらでも見る価値がある。
 */
const CLAIMED = new Set(["c2", "malware", "phishing-site"]);
const disagreements = iocs
  .filter((r) => {
    if (!usable(r.key)) return false;
    if (!(r.classes || []).some((c) => CLAIMED.has(c))) return false;
    const v = vtByIoc.get(r.key);
    return v?.known === true && v.malicious === 0 && v.suspicious === 0;
  })
  .map((r) => ({ ioc: r.key, classes: r.classes, sources: r.sources }))
  .sort(byKeys("ioc"));

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
      // 描くときに太さで差を出せるように、強さも辺に持たせる
      strength: o.strength,
      ratio: o.ratio,
      via: o.via,
      ...(o.weak_only ? { weak_only: true } : {}),
    }))
    .sort(byKeys("kind", "source", "target")),
});

writeJsonl(path.join(OUT, "overlaps.jsonl"), overlaps);
// 要約には上位しか載らないので、同居は全件を別に残す
writeJsonl(path.join(OUT, "subnets.jsonl"), subnets);
if (HAS_ASN) writeJsonl(path.join(OUT, "asn-cotenancy.jsonl"), asnCoTenancy);

/* ---------------- 要約 ---------------- */

/** 既定の並べ替えは強さ。共有数だけだと、弱い根拠を数で押した組が上位に来る。 */
const top = (kind, n = 10) => overlaps
  .filter((o) => o.kind === kind)
  .sort((a, b) => b.strength - a.strength || b.shared - a.shared || b.ratio - a.ratio || (a.a < b.a ? -1 : 1))
  .slice(0, n)
  .map((o) => ({
    a: o.a, b: o.b, shared: o.shared, strength: o.strength, ratio: o.ratio, via: o.via,
    ...(o.weak_only ? { weak_only: true } : {}),
  }));

const byType = {};
for (const r of iocs) byType[r.type] = (byType[r.type] || 0) + 1;

const VIA = [
  "ioc", "subnet", "registrable",
  ...(HAS_ASN ? ["asn"] : []),
  ...(HAS_VT ? ["certificate", "resolution", "family", "filename", "jarm"] : []),
];

/**
 * **どこまで調べたか**を先頭に置く（§3.5）。
 * 数え方は enrich-intel.mjs と同じ関数を使う。別々に数えると分母が食い違う。
 */
const coverage = coverageOf({
  iocs, links,
  fresh: new Set(readJsonl(path.join(IN, "new.jsonl")).map((r) => r.key)),
  asnOf, asnInfo,
  vtRows: vt, abuseRows: abuse,
  includeNoise: INCLUDE_NOISE,
  fetchDays: [enrichMeta?.coverage?.oldest_fetch, enrichMeta?.coverage?.newest_fetch],
});

const stats = {
  tool: "tools/ioc/stats.mjs",
  schema: 1,
  // 途中の統計は一部しか見ていない。未エンリッチは「陰性」ではなく「未知」
  coverage,
  from: { collected_at: meta.collected_at || null, week: meta.week || null },
  options: {
    include_noise: INCLUDE_NOISE,
    ubiquity_cap: UBIQUITY_CAP,
    min_shared: MIN_SHARED,
    ...(HAS_ASN ? { asn_max_addresses: ASN_MAX_ADDRESSES } : {}),
    ...(HAS_VT ? { jarm_cap: JARM_CAP, filename_cap: FILENAME_CAP } : {}),
    ...(HAS_ABUSE ? { hosting_ratio: HOSTING_RATIO, hosting_min: HOSTING_MIN } : {}),
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
    // 弱い根拠だけで成立している組。除かずに数える
    weak_only: overlaps.filter((o) => o.kind === k && o.weak_only).length,
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
      // **3 つ目の観点だけで外れたもの。** 大きさとアクター数では根拠に使える AS
      // なのに、AbuseIPDB が「事業者の網」と言ったせいで外れた。攻撃側の基盤は
      // ほとんどが事業者の網なので、ここは効きすぎることがある。**外したものを
      // 見えるようにしておかないと、外れたこと自体に気づけない**
      ...(HAS_ABUSE ? {
        hosting_excluded: asnCoTenancy
          .filter((a) => {
            if (!a.shared_hosting || a.actors.length < 2) return false;
            const info = asnInfo.get(a.asn);
            if (!info || !(info.addresses > 0) || info.addresses > ASN_MAX_ADDRESSES) return false;
            return (actorsPerAsn.get(a.asn)?.size ?? 0) <= ASN_MAX_ACTORS;
          })
          .sort((a, b) => b.actors.length - a.actors.length || a.addresses - b.addresses)
          .map((a) => ({
            asn: a.asn, name: a.name, cc: a.cc, addresses: a.addresses,
            hosting_ratio: a.hosting_ratio ?? null, hosting_seen: a.hosting_seen ?? 0,
            actors: a.actors,
          })),
      } : {}),
      hosting_like: asnCoTenancy
        .filter((a) => a.shared_hosting && a.actors.length >= 3)
        .sort((a, b) => b.actors.length - a.actors.length || a.asn - b.asn)
        .slice(0, 20)
        .map((a) => ({ asn: a.asn, name: a.name, cc: a.cc, addresses: a.addresses, actors: a.actors })),
    },
  } : {}),
  ...(HAS_VT ? {
    // 索引が持っていない「世に出た日」から出る 3 つ（§3.3）
    timeline: {
      dated: firstSub.size,
      actors: {
        with_dates: actorSpans.length,
        // 長く続いている順。活動期間そのものが手掛かりになる
        longest: [...actorSpans]
          .sort((a, b) => days(b.first, b.last) - days(a.first, a.last) || (a.name < b.name ? -1 : 1))
          .slice(0, 10)
          .map((s) => ({ ...s, span_days: days(s.first, s.last) })),
      },
      campaigns: {
        with_dates: campaignSpans.length,
        spans: campaignSpans,
        // IOC を共有していなくても「同じ時期に動いていた」は手掛かりになる
        time_overlaps: timeOverlaps.sort(byKeys("a", "b")),
      },
      index_lag: {
        pairs: lags.length,
        median_days: lags.length ? quantile(lags, 0.5) : null,
        p25_days: lags.length ? quantile(lags, 0.25) : null,
        p75_days: lags.length ? quantile(lags, 0.75) : null,
        // 索引のほうが VT より早かったもの。索引の独自性
        ahead: lags.filter((d) => d < 0).length,
      },
    },
    verdicts: {
      // VT が知らない IOC。**失敗ではなく結果**。索引の独自性の指標になる
      unknown: coverage.virustotal.unknown,
      malicious: vt.filter((r) => r.known && r.malicious > 0).length,
      clean: vt.filter((r) => r.known && r.malicious === 0 && r.suspicious === 0).length,
      by_actor: {
        checked: actorVerdicts.length,
        // 検知が少ない実体から出す。索引の誤りか、まだ知られていないか
        lowest: [...actorVerdicts]
          .filter((a) => a.checked >= 3)
          .sort((a, b) => a.median_malicious - b.median_malicious || (a.name < b.name ? -1 : 1))
          .slice(0, 10),
      },
      // 索引の主張と VT の判定の食い違い
      disagreement: {
        total: disagreements.length,
        samples: disagreements.slice(0, 15),
      },
    },
  } : {}),
  ...(args.since ? { new_since: { dir: args.since, count: added.length } } : {}),
};
writeJson(path.join(OUT, "stats.json"), stats);

console.log(`IOC ${iocs.length}（分析対象 ${stats.iocs.usable}）`);
// 何割を見た上での数字かを最初に言う。これが無いと以下の数を読み違える
const pct = (x) => `${(x * 100).toFixed(1)}%`;
console.log(`  調べた範囲: VT ${coverage.virustotal.done} / ${coverage.virustotal.target}（${pct(coverage.virustotal.ratio)}）`
  + ` / AbuseIPDB ${coverage.abuseipdb.done} / ${coverage.abuseipdb.target}（${pct(coverage.abuseipdb.ratio)}）`);
if (HAS_VT) {
  const s1 = coverage.virustotal.by_stage["1"];
  if (s1) console.log(`    段階 1（複数の実体に繋がる IOC）${s1.done} / ${s1.target}  ${pct(s1.done / Math.max(1, s1.target))}`);
}
for (const k of KINDS) {
  const n = stats.overlaps[k].pairs;
  if (n) {
    console.log(`  ${k.padEnd(9)} 実体 ${String(owned.get(k).size).padStart(4)} / 重なり ${n} 組`
      + (stats.overlaps[k].weak_only ? `（うち弱い根拠だけ ${stats.overlaps[k].weak_only} 組）` : ""));
  }
}
console.log(`  /24 で別アクターが同居: ${stats.subnets.multi_actor} 網`);
if (HAS_ASN) {
  console.log(`  AS で別アクターが同居: ${stats.asns.multi_actor} 件`
    + `（うち相乗りでない小さい AS ${stats.asns.multi_actor_small} 件）`);
  for (const a of stats.asns.top.slice(0, 6)) {
    console.log(`    AS${String(a.asn).padEnd(7)} ${String(a.addresses).padStart(6)} ${(a.cc || "?").padEnd(3)} `
      + `${(a.name || "?").slice(0, 26).padEnd(26)} ${a.actors.join(" / ")}`);
  }
  for (const a of stats.asns.hosting_excluded || []) {
    console.log(`    ! AS${String(a.asn).padEnd(7)} ${String(a.addresses).padStart(6)} ${(a.cc || "?").padEnd(3)} `
      + `${(a.name || "?").slice(0, 26).padEnd(26)} ${a.actors.join(" / ")}`);
  }
  if (stats.asns.hosting_excluded?.length) {
    console.log(`      ↑ 大きさとアクター数では根拠になるが、AbuseIPDB が事業者の網と言うので外した`
      + `（--hosting-ratio ${HOSTING_RATIO} / 最低 ${HOSTING_MIN} 件）`);
  }
  if (stats.asns.hosting_like.length) {
    const h = stats.asns.hosting_like[0];
    console.log(`  多くのアクターが借りている事業者: ${stats.asns.hosting_like.length} 件`
      + `（最多 AS${h.asn} ${h.name} に ${h.actors.length} アクター）`);
  }
}
if (HAS_VT) {
  console.log(`  VT: 検知あり ${stats.verdicts.malicious} / 検知 0 ${stats.verdicts.clean}`
    + ` / VT が知らない ${stats.verdicts.unknown}`);
  if (stats.verdicts.disagreement.total) {
    console.log(`    索引が C2 などと言っているのに検知 0: ${stats.verdicts.disagreement.total} 件`);
  }
  if (stats.timeline.index_lag.pairs) {
    const l = stats.timeline.index_lag;
    console.log(`  索引の遅れ: 中央値 ${l.median_days} 日（${l.p25_days}〜${l.p75_days} 日 / 索引が先 ${l.ahead} 件）`);
  }
  const certPairs = overlaps.filter((o) => o.via.includes("certificate")).length;
  const resPairs = overlaps.filter((o) => o.via.includes("resolution")).length;
  const famPairs = overlaps.filter((o) => o.via.includes("family")).length;
  console.log(`  エンリッチ由来の根拠: 証明書 ${certPairs} 組 / 解決先 ${resPairs} 組 / ファミリ ${famPairs} 組`);
}
if (args.since) console.log(`  前回から増えた IOC: ${added.length} 件`);
console.log(`  → ${path.relative(REPO_ROOT, OUT)}`);
