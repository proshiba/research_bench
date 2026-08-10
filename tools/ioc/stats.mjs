#!/usr/bin/env node
// 集めた IOC から「重なり」を計算する。外部呼び出しなし。
//
//   node tools/ioc/stats.mjs [--in data/ioc/latest] [--out <同じ場所>]
//                            [--since <前回のスナップショット>] [--include-noise]
//                            [--ubiquity-cap 8] [--min-shared 1]
//                            [--asn-max-addresses 4096] [--asn-max-actors 8]
//                            [--jarm-cap 0.01] [--filename-cap 8] [--filename-min 2]
//                            [--family-cap 8] [--vhash-cap 8] [--imphash-cap 8]
//                            [--resolution-cap 3] [--resolution-asn-cap 2]
//                            [--hash-size-spread 10] [--regday-min 3] [--regday-cap 25]
//                            [--target-min-malicious 3]
//                            [--evidence-cap 5]
//                            [--hosting-ratio 0.7] [--hosting-min 3]  ← asn と subnet の両方に効く
//
// 重なりの見方を 9 つ出す。どれも「共有している IOC の数」を根拠にする。
// 後半 5 つは enrich-intel.mjs があるときだけ出る。
//   certificate … 同じ証明書（thumbprint 一致）。**最も強いインフラ共有の証拠**
//   ioc         … 同じ IOC を指している
//   resolution  … 同じ IP に解決するドメインを持っている
//   vhash       … VT の構造ハッシュが一致。**提供元の判断が入らない**
//   imphash     … PE のインポート表が一致。パッカーで衝突するので中くらい
//   subnet      … 同じ /24 に IP がある。**貸し出し用の /24 は外す**（asn と同じ観点）
//   asn         … 同じ AS に IP がある。**小さい AS に限る**（enrich-asn.mjs が要る）
//   family      … VT が同じ脅威ラベルを付けている。**弱い**（提供元の札は広く付く）
//   registrable … 同じ登録可能ドメインを使っている。弱い
//   filename    … 珍しいファイル名の共有。**弱い**（2 つ以上揃って初めて数える）
//   jarm        … 同じ TLS 指紋。弱い（単独では根拠にしない）
//
// **根拠に強さの順を入れる。** 共有数と割合だけだと、根拠の種類による差が数字に出ない。
// 上の順を点数にして合算した `strength` を持たせ、要約の並べ替えをこれにする。
// 弱い根拠（family / filename / registrable / jarm）だけで成立している組には weak_only の印を
// 付ける。**除くのではなく印を付ける**（bogon / noise と同じ扱い）。
//
// asn を大きさで絞るのは、絞らないと意味を持たないため。400 万アドレスを持つ事業者に
// 2 つの実体が居るのは偶然だが、1,024 アドレスしか持たない AS なら同じ相手から
// 借りているとみてよい。境目は --asn-max-addresses（既定 4,096 = /20 相当）。
// AbuseIPDB があれば **その AS の IP が事業者の網である割合**も見る（3 つ目の観点）。
//
// 既定では bogon と noise（公開 DNS など）を除く。これらは誰にでも現れるので、
// 入れると重なりの上位が意味の無いもので埋まる。--include-noise で戻せる。
// enrich-intel.mjs が付けた sample の印（通報の中身が空ばかりの見本アドレス）も同じ扱い。
// net.mjs の帯の一覧は手で足すしかないので、そこから漏れたものをこちらで拾う。
//
// 出力
//   stats.json      **カバレッジ**・件数・種別内訳・重なりの要約・時間軸・判定の分布
//   overlaps.jsonl  実体の組ごとの重なり（根拠・強さ・**根拠になった値**つき）
//   targets.jsonl   正規サービスを騙った／悪用したドメイン。**根拠からは外すが標的は残す**
//   identical-sets.jsonl  IOC 集合が完全に一致した組。**共有率 100% は構造上そう
//                   なるだけで根拠にならない**ので overlaps からは外す。捨てはしない
//   graph.json      実体と重なりのグラフ（そのまま描ける形）
//   new.jsonl       --since を渡したときだけ。前回に無かった IOC
//
// stats.json の先頭には必ず coverage を置く。1 キーでは全件が埋まるまで日数がかかり、
// その途中の統計は一部しか見ていない。「検知されたのは 12%」と「調べた範囲の 12%」は
// 別物で、後者を前者として読むと必ず間違える。未エンリッチは陰性ではなく未知と数える。

import path from "node:path";
import { byKeys, parseArgs, readJson, readJsonl, writeJson, writeJsonl } from "./lib/io.mjs";
import { coverageOf } from "./lib/enrich.mjs";
import { strengthOf, weakOnly } from "./lib/overlap.mjs";
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
/** ファミリ名も同じ。これより多くの実体にぶら下がるラベルは、ファミリではなく手口。 */
const FAMILY_CAP = Number(args["family-cap"] || args["ubiquity-cap"] || 8);
/** ファイル名を根拠に数えるのに要る、一致した名前の数。1 つだけの一致は偶然が多い。 */
const FILENAME_MIN = Number(args["filename-min"] || 2);
/** 根拠の値を 1 種類あたり何件まで残すか。全部だと overlaps.jsonl が膨らむ。 */
const EVIDENCE_CAP = Number(args["evidence-cap"] || 5);
/**
 * 解決先も同じ考え方。これより多くの実体のドメインが解決する IP は共用の入れ物。
 * **他の根拠より厳しくする**（既定 3）。resolution は 7 点と強い根拠なので、
 * 弱い根拠と同じ緩さで通すと、パーキング 1 つで上位が埋まる。
 */
const RESOLUTION_CAP = Number(args["resolution-cap"] || 3);
/**
 * 同じことを AS 単位でも見る。パーキングは IP 単位では小さくても AS 全体では広い。
 *
 * 既定 2。実測で境目を動かすと、3 では Seznam.cz（`77.75.77.222`）が
 * APT28 ↔ APT29 を、韓国テレコム（`168.126.27.83`）が APT37 ↔ DPRK IT Worker
 * Schemes を繋いだままだった。4 では Squarespace（`198.185.159.176`）が残った。
 * どれも**顧客のドメインが並ぶ入れ物**であって、共有された C2 ではない。
 *
 * **代償は承知の上。** 2 にすると「3 つの実体が同じ防弾ホストを共有している」
 * という本物も切れる。resolution は 7 点と強い根拠なので、
 * 取りこぼすより誤って繋ぐほうが害が大きいと判断した。緩めるならこの値を上げる。
 */
const RESOLUTION_ASN_CAP = Number(args["resolution-asn-cap"] || 2);
/** ファジーハッシュも同じ考え方。これより多くの実体に付く値は、作りが共通なだけ。 */
const VHASH_CAP = Number(args["vhash-cap"] || args["ubiquity-cap"] || 8);
const IMPHASH_CAP = Number(args["imphash-cap"] || args["ubiquity-cap"] || 8);
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
const derivedIocs = readJsonl(path.join(IN, "derived-iocs.jsonl"));
const enrichMeta = readJson(path.join(IN, "enrich-meta.json"));
const HAS_VT = vt.length > 0;
const HAS_ABUSE = abuse.length > 0;

const iocById = new Map(iocs.map((r) => [r.key, r]));
/**
 * 通報の中身から見本アドレスと判定された IP（enrich-intel.mjs が印を付ける）。
 * net.mjs の帯の一覧は手で足すしかないので、そこから漏れたものをここで拾う。
 */
const sampleIps = new Set(abuse.filter((r) => r.sample).map((r) => r.ioc));
/**
 * 正規サービスと判定されたドメイン（enrich-intel.mjs が popular の印を付ける）。
 * 攻撃者が**使った**だけのサービスは、支配しているインフラではない。
 * 実測で seznam.cz / mail.ru の正規証明書が APT28 ↔ APT29 の「証明書共有」として
 * 最上位に立っていた。ioc・certificate・jarm・registrable と多重に効くので、
 * 大元のここで bogon / noise と同じ扱いにする。
 */
const popularDomains = new Set(vt.filter((r) => r.popular).map((r) => r.ioc));

/**
 * **正規サービスの印は「捨てるもの」であると同時に「何を狙ったか」の手掛かり**（§3.6）。
 *
 * 根拠からは外すが、名前を騙られている以上、そこには標的が現れている。実測で
 * `danas.bid` と本物の `danas.rs`、`politika.bid` と `politika.rs` のように、
 * **なりすまし先が IOC として併記されている**ことがある。
 *
 * 2 つに分ける。意味がまるで違う。
 *   なりすまし … 別の登録可能ドメインで名前を騙る（`google-com.online`）
 *   悪用       … 本物のサービスの下にぶら下がる（`…….supabase.co`）
 *
 * 突き合わせは**ラベル単位の完全一致**にする。部分一致だと `drive` が
 * `driver-hub.net` に当たり、実測で 168 件中の相当数が的外れになった。
 */
const TARGET_MIN_MAL = Number(args["target-min-malicious"] || 3);
const targetsOf = () => {
  const pops = vt.filter((r) => r.popular)
    .map((r) => ({ reg: iocById.get(r.ioc)?.registrable, rank: r.popular }))
    .filter((p) => p.reg);
  const impersonation = [], abuse_ = [];
  for (const r of vt) {
    if (!r.ioc.startsWith("ioc.domain|") || r.popular) continue;
    if ((r.malicious ?? 0) < TARGET_MIN_MAL) continue;
    const d = r.ioc.slice("ioc.domain|".length);
    const reg = iocById.get(r.ioc)?.registrable;
    const labels = new Set(d.split(/[.\-_]/).filter(Boolean));
    for (const p of pops) {
      const row = { ioc: r.ioc, target: p.reg, rank: p.rank, malicious: r.malicious };
      // 本物の下にぶら下がっているかは名前の長さと関係ない。**先に見る**
      if (reg === p.reg) { abuse_.push(row); break; }
      // 名前を騙る側だけ、短すぎる語を除く（`rf` `esy` が偶然当たるため）
      const stem = p.reg.split(".")[0];
      if (stem.length >= 4 && labels.has(stem)) { impersonation.push(row); break; }
    }
  }
  const byKeys2 = (a, b) => a.target.localeCompare(b.target) || a.ioc.localeCompare(b.ioc);
  return { impersonation: impersonation.sort(byKeys2), abuse: abuse_.sort(byKeys2) };
};
const dropped = (r) => r.bogon || r.noise || sampleIps.has(r.key) || popularDomains.has(r.key);
const usable = (key) => {
  const r = iocById.get(key);
  if (!r) return false;
  if (r.malformed) return false;
  if (!INCLUDE_NOISE && dropped(r)) return false;
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
/** 生えた IP にも bogon / noise の印は付いている。索引の IOC と同じ扱いにする。 */
const markOf = new Map([...iocById, ...derivedIocs.map((r) => [r.key, r])]);

/**
 * 解決先ごとの「そこに解決するドメインを持つ実体」の数。
 *
 * **大きさだけでは足りない。** ドメインパーキングは AS が小さいのに解決先だけ膨大で、
 * 実測で SEDO GmbH（AS47846、**1,024 アドレス**）の `91.195.240.12` が上限を
 * 素通りし、APT33 / Cytrox / Konni / Lazarus Group など 8 実体を総当たりで
 * 繋いでいた。Trellian（AS133618）と ParkingCrew（AS206834）も同じ形。
 * 他の根拠に入れている ubiquity cap を、解決先にも同じ考えで入れる。
 */
const entityLabels = new Map();   // IOC 鍵 → その IOC を持つ実体の名札
for (const kind of ["actor", "malware"]) {
  for (const [name, keys] of owned.get(kind)) {
    for (const k of keys) {
      if (!entityLabels.has(k)) entityLabels.set(k, new Set());
      entityLabels.get(k).add(`${kind}:${name}`);
    }
  }
}
const entitiesPerResolvedIp = new Map();
/**
 * AS 単位でも同じことを見る。**パーキングは 1 つの IP では跨りが小さくても、
 * AS 全体で見ると必ず広い。** 実測で 4,096 アドレス以下の AS を跨りの多い順に
 * 並べると、上位 4 つが SEDO(12) / Trellian(7) / Team Internet(7) / IP Vendetta(7)
 * で、5 つ目から 4 に落ちる。事業の性質がそのまま数字に出る。
 */
const entitiesPerResolvedAsn = new Map();
for (const [domain, set] of resolvesTo) {
  const labels = entityLabels.get(domain);
  if (!labels?.size) continue;
  for (const ip of set) {
    if (!entitiesPerResolvedIp.has(ip)) entitiesPerResolvedIp.set(ip, new Set());
    for (const l of labels) entitiesPerResolvedIp.get(ip).add(l);
    const asn = asnOf.get(ip);
    if (asn === undefined) continue;
    if (!entitiesPerResolvedAsn.has(asn)) entitiesPerResolvedAsn.set(asn, new Set());
    for (const l of labels) entitiesPerResolvedAsn.get(asn).add(l);
  }
}

for (const set of resolvesTo.values()) {
  for (const ip of set) {
    // 127.0.0.1 に解決するドメイン同士は「同じ所に居る」ではなく、**どちらも
    // シンクホールされている**。実測で APT28 ↔ STAC4749 を繋いでいた
    const m = markOf.get(ip);
    if (m && (m.malformed || m.bogon || (!INCLUDE_NOISE && (m.noise || sampleIps.has(m.key))))) { cdnIps.add(ip); continue; }
    const asn = asnOf.get(ip);
    const size = asn ? (asnInfo.get(asn)?.addresses ?? 0) : 0;
    if (size > ASN_MAX_ADDRESSES) { cdnIps.add(ip); continue; }
    if ((entitiesPerResolvedIp.get(ip)?.size ?? 0) > RESOLUTION_CAP) { cdnIps.add(ip); continue; }
    if (asn !== undefined && (entitiesPerResolvedAsn.get(asn)?.size ?? 0) > RESOLUTION_ASN_CAP) { cdnIps.add(ip); continue; }
    resolvedIps.add(ip);
  }
}

/** 共用ホスティングの証明書は根拠にしない（SAN が多すぎるもの・基盤に出されたもの）。 */
const weakCert = new Set(derivedCerts.filter((c) => c.weak).map((c) => c.thumbprint));
/**
 * **IOC を 1 つしか持たない証明書は「橋」ではない。**
 *
 * 両実体が同じ IOC を指しているという事実は `ioc`（8 点）で既に数えている。
 * その IOC の証明書を `certificate`（9 点）でもう一度数えると、同じ事実が
 * 17 点になる。実測で、根拠に引かれた証明書のべ 159 枚のうち **133 枚が
 * IOC 1 つの鏡写し**で、91 組中 67 組の証明書根拠がこれだけで立っていた。
 * 証明書が根拠になるのは、**別々の IOC を同じ鍵が結んでいる**ときだけ。
 */
const certIocs = new Map(derivedCerts.map((c) => [c.thumbprint, c.iocs || []]));
const bridgeCert = new Set(derivedCerts.filter((c) => !c.weak && (c.iocs || []).length >= 2).map((c) => c.thumbprint));
const certOf = new Map();
for (const r of vt) {
  if (!r.cert?.thumbprint) continue;
  if (weakCert.has(r.cert.thumbprint)) continue;
  // 自分の名前が SAN に無く、ワイルドカードで拾っただけの組み合わせは根拠にしない
  if (r.cert.wildcard) continue;
  if (!bridgeCert.has(r.cert.thumbprint)) continue;
  certOf.set(r.ioc, r.cert.thumbprint);
}

/**
 * 同じ日にまとめて取られたドメイン（§3.1c）。**一斉登録は運用の跡**。
 *
 * 実測で APT29 の `eu-central-1-aws.mzv-sk.cloud`（スロバキア外務省）など 107 件が
 * 2024-08-15〜26 の 2 週間に集中し、命名も揃っていた。登録業者は 7 社に分けてある
 * ので業者では追えないが、**日付は分けられていない**。
 *
 * **数えるのは登録可能ドメインの種類。** そのまま数えると上位が動的 DNS で埋まる。
 * `actor-tv.ddns.net` のような子ドメインには**親（ddns.net）の登録日が返る**ので、
 * 実測で 2001-06-28 に 264 件、2000-02-17 に 108 件が並んだ。これは 1 種にまとまる。
 *
 * 大きすぎる日も外す。1 日に何十種類も取るのは、キャンペーンではなく
 * 登録業者側の一括処理か、日付そのものが当てにならない（実測の最大は 37 種）。
 */
const REGDAY_MIN = Number(args["regday-min"] || 3);
const REGDAY_CAP = Number(args["regday-cap"] || 25);
const regDayOf = new Map();   // IOC 鍵 → 登録日
{
  const perDay = new Map();   // 日 → その日に登録された登録可能ドメインの集合
  for (const r of vt) {
    if (!r.created || !r.ioc.startsWith("ioc.domain|")) continue;
    const reg = iocById.get(r.ioc)?.registrable;
    if (!reg) continue;
    if (!perDay.has(r.created)) perDay.set(r.created, new Set());
    perDay.get(r.created).add(reg);
  }
  const usableDay = new Set([...perDay]
    .filter(([, s]) => s.size >= REGDAY_MIN && s.size <= REGDAY_CAP).map(([d]) => d));
  for (const r of vt) {
    if (r.created && usableDay.has(r.created) && r.ioc.startsWith("ioc.domain|")) {
      regDayOf.set(r.ioc, r.created);
    }
  }
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
 * ファジーハッシュ。**提供元の判断が入らないぶん、検知名より素直な根拠**。
 *
 *   vhash   … VT の構造ハッシュ。一致すれば作りが同じ
 *   imphash … PE のインポート表。一致すれば同じ取り込み方だが、**パッカーでよく衝突する**
 *
 * どちらも「みんなが同じ値になる」ことがあるので、ありふれた値は外す。
 * 数え方は他と揃えて **何実体にぶら下がっているか**で測る。
 */
const DEGENERATE_HASH = new Set([
  "d41d8cd98f00b204e9800998ecf8427e",   // 空（インポートが無い PE の imphash）
  "0000000000000000000000000000000000000000000000000000000000000000",
]);
/**
 * **vhash は PE のときだけ使う。**
 *
 * 実測で、PE 以外の vhash は**中身ではなく入れ物の形式**しか見ていなかった。
 *   `fe43cc09…`  18 検体 / 4 アクター  Hangul 文書 + Outlook + MS Word（12KB〜800KB）
 *   `7596fdd0…`   5 検体 / 3 アクター  JavaScript + シェルスクリプト（**105B〜1.5MB**）
 *   `9f0d05f0…`   4 検体 / 3 アクター  PDF
 *   `2a85fbef…`   9 検体 / 4 アクター  ELF（1.4MB〜6.2MB）
 * 105 バイトのシェルスクリプトと 1.5MB の JavaScript が同じ値になる時点で、
 * これは「同じ物」の証拠にならない。APT29 ↔ APT41 のような組が立っていた。
 *
 * PE では 1,679 群が安定していて、同じ問題は出ていない。種別で切るほうが、
 * 上限を下げて PE ごと巻き添えにするより損が小さい（上限 2 だと 77 組 → 16 組、
 * 種別で切ると 77 組 → 58 組で、誤検知はどちらも 0 になる）。
 * `imphash` は PE のインポート表なので、そもそも PE にしか付かない。
 */
const PE_TYPE = /^Win(32|64) (EXE|DLL)/;
const isPe = (ioc) => PE_TYPE.test(vtByIoc.get(ioc)?.type_description || "");
const hashOwners = (field) => {
  const m = new Map();
  for (const l of links) {
    if (!KINDS.includes(l.kind)) continue;
    if (field === "vhash" && !isPe(l.ioc)) continue;
    const v = vtByIoc.get(l.ioc)?.[field];
    if (!v || DEGENERATE_HASH.has(v)) continue;
    if (!m.has(v)) m.set(v, new Set());
    m.get(v).add(`${l.kind}\t${l.name}`);
  }
  return m;
};

/**
 * **同じ値なのに大きさが桁で違う群は、同じ物を指していない。**
 *
 * 実測で `f34d5f2d…` が 420 検体・47 実体に付き、5KB から 38MB まで並んでいた。
 * `.NET` の起動部だけを取り込む実行ファイルはインポート表が同じになるので、
 * 中身と関係なく imphash が一致する。実体数の上限（8）は 47 や 24 を落とすが、
 * `d42595b695…`（91 検体・6 実体・**1.5MB 〜 630MB**）のように上限を通るものが残る。
 *
 * 同じ物の別ビルドなら、デバッグ情報や埋め込みの差でせいぜい数倍。
 * 実測でも 10 倍を境に分かれた（imphash 13 群 / vhash 7 群が超え、
 * 上位は生成器の署名そのもの）。大きさの分からない検体は判断材料にしない。
 */
const SIZE_SPREAD_CAP = Number(args["hash-size-spread"] || 10);
const spreadOut = (field) => {
  const sizes = new Map();
  for (const r of vt) {
    const v = r[field];
    if (!v || !Number.isFinite(r.size) || r.size <= 0) continue;
    if (field === "vhash" && !isPe(r.ioc)) continue;
    if (!sizes.has(v)) sizes.set(v, []);
    sizes.get(v).push(r.size);
  }
  const out = new Set();
  for (const [v, list] of sizes) {
    if (list.length < 2) continue;
    if (Math.max(...list) / Math.min(...list) > SIZE_SPREAD_CAP) out.add(v);
  }
  return out;
};
const spreadVhash = spreadOut("vhash");
const spreadImphash = spreadOut("imphash");
const commonVhash = new Set([...hashOwners("vhash")].filter(([, e]) => e.size > VHASH_CAP).map(([v]) => v));
const commonImphash = new Set([...hashOwners("imphash")].filter(([, e]) => e.size > IMPHASH_CAP).map(([v]) => v));

/**
 * 署名者。**窃取されたコード署名証明書の共有は、インフラの証明書共有と同種の証拠。**
 * 実測で EGIS Co., Ltd.（52 検体・3 実体。窃取署名として既知）や
 * Gray Matter Software S.R.L.（4 実体）が跨っていた。
 *
 * Microsoft 署名は除く。正規の Windows ファイルが IOC に混ざった印であって
 * （実測で 6 実体に跨っていた）、共有の根拠ではない。ありふれた署名者も外す。
 */
const LEGIT_SIGNER = /microsoft|windows/i;
const SIGNER_CAP = Number(args["signer-cap"] || args["ubiquity-cap"] || 8);
/**
 * 署名者を根拠に数えるのに要る、その検体自身の検知数。
 *
 * サイドローディングの宿主（NVIDIA や LENOVO が署名した**正規バイナリ**）も
 * IOC として索引に載る。検知が付かない検体の署名者を数えると、
 * 「同じ正規ツールを悪用した」という手口の一致が「署名証明書の共有」に化ける。
 * 実測で NVIDIA 署名の検体は検知 [0, 53] と割れた。0 は正規の宿主、
 * 53 は署名を**騙っている**マルウェア。検知で切ると前者だけが落ちる。
 */
const SIGNER_MIN_MAL = Number(args["signer-min-malicious"] || 5);
const commonSigner = new Set([...hashOwners("signer")].filter(([, e]) => e.size > SIGNER_CAP).map(([v]) => v));
const usableSigner = (v) => {
  const s = v?.signer;
  if (typeof s !== "string" || !s) return null;
  if ((v.malicious ?? 0) < SIGNER_MIN_MAL) return null;
  if (LEGIT_SIGNER.test(s)) return null;
  if (commonSigner.has(s)) return null;
  return s;
};
/** 署名者 → その署名を持つ検体。証明書と同じ橋の条件（下）を組ごとに見るために持つ。 */
const signerIocs = new Map();
for (const r of vt) {
  const sg = usableSigner(r);
  if (!sg) continue;
  if (!signerIocs.has(sg)) signerIocs.set(sg, new Set());
  signerIocs.get(sg).add(r.ioc);
}
const usableHash = (field, v) => {
  if (!v || DEGENERATE_HASH.has(v)) return null;
  if (field === "vhash" && (commonVhash.has(v) || spreadVhash.has(v))) return null;
  if (field === "imphash" && (commonImphash.has(v) || spreadImphash.has(v))) return null;
  return v;
};

/**
 * ありふれたファミリ名も外す。
 *
 * VT のラベルには `tedy` のように、手口や検出器の都合で付いた**ファミリではない名前**が
 * 混じる。実測すると `tedy` が 61 検体・12 実体、`dllhijack` が 10 実体に付いていて、
 * APT28 ↔ APT41 のような無関係な組を生んでいた。名前で弾くのは一般化しないので、
 * **何実体にぶら下がっているかで測る**（ありふれた IOC を外すのと同じ考え方）。
 * kind をまたいで数えるのが要点で、kind ごとに数えると 12 実体でも
 * 「アクターは 5 つだけ」として通ってしまう。
 */
const entitiesPerFamily = new Map();
for (const l of derivedLinks) {
  if (l.kind !== "malware" || l.rel !== "suggested_threat_label") continue;
  if (!entitiesPerFamily.has(l.name)) entitiesPerFamily.set(l.name, new Set());
  for (const e of links) {
    if (e.ioc !== l.ioc || !KINDS.includes(e.kind)) continue;
    entitiesPerFamily.get(l.name).add(`${e.kind}\t${e.name}`);
  }
}
const commonFamily = new Set([...entitiesPerFamily].filter(([, s]) => s.size > FAMILY_CAP).map(([f]) => f));

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
 * **`/24` にも AS と同じ守りを入れる（§3.2b）。**
 *
 * `asn` には 3 つの条件（アドレス数・アクター数・事業者の網の割合）を掛けているのに、
 * `/24` は同じ 5 点なのに実質無条件だった。この非対称のせいで、強い根拠のグラフに
 * **70 実体が地続きの塊**ができ、その 99 辺のうち 40 辺を `subnet` 単独が支えていた
 * （APT1 / APT28 / APT29 / APT37 / APT41 / BITTER … が 1 つに繋がる）。
 *
 * 実測すると、2 実体以上が居る /24 が 572 あり、そのうち **344（60%）が
 * 事業者の網と判定した AS の中**にあった。上位は RouterHosting・BL Networks・
 * Antbox Networks・CTG Server・Zappie Host・UAB Bacloud。どれも VPS 事業者で、
 * `45.61.136.0/24` に 5 実体が居るのは**同じ業者から借りているだけ**。
 *
 * 「同じ AS に居る」が大きさ抜きでは何も言えないのと同じで、
 * **「同じ /24 に居る」も、その /24 が貸し出し用なら何も言えない**。
 * 判定は AS 単位で持つ（/24 単位だと判定の付いた IP が 1〜3 件しかなく当てにならない。
 * 実測で判定 3 件以上ある /24 は 572 のうち 56 だけだった）。
 * AbuseIPDB が無い環境では判定できないので、そのときは今までどおり通す。
 */
const hostingSubnet = new Set();
for (const r of iocs) {
  if (!r.subnet) continue;
  const asn = asnOf.get(r.key);
  if (asn === undefined) continue;
  const hr = hostingRatio(asn);
  if (hr !== null && hr > HOSTING_RATIO) hostingSubnet.add(r.subnet);
}
const subnetUsable = (subnet) => !!subnet && !hostingSubnet.has(subnet);

/**
 * 組ごとの共有数を数える。
 *
 * 総当たりだと実体数の 2 乗になるので、IOC 側から「その IOC を共有する実体」を
 * 見て、実際に共有がある組だけを起こす。ありふれた IOC（多数の実体に付くもの）は
 * 根拠として弱いうえに組を大量に生むので、上限を超えたら数えない。
 */
function pairsFor(kind, groups) {
  // "a\tb" → { byVia: Map(via → 共有した値の集合) }
  //
  // **共有した値そのものを持つ。** 数だけだと「証明書で繋がっている」と言われても
  // どの証明書かを確かめられない。根拠は後から検算できないと意味がない。
  const pairCount = new Map();
  for (const [via, byValue] of groups) {
    for (const [value, names] of byValue) {
      const list = [...names].sort();
      if (list.length < 2 || list.length > UBIQUITY_CAP) continue;
      for (let i = 0; i < list.length; i++) {
        for (let j = i + 1; j < list.length; j++) {
          const k = `${list[i]}\t${list[j]}`;
          if (!pairCount.has(k)) pairCount.set(k, { byVia: new Map() });
          const m = pairCount.get(k).byVia;
          if (!m.has(via)) m.set(via, new Set());
          m.get(via).add(value);
        }
      }
    }
  }
  const sizes = owned.get(kind);
  return [...pairCount.entries()].map(([k, v]) => {
    const [a, b] = k.split("\t");
    // 証明書と署名者は**組ごとに**橋の条件を見る。同じ鍵が複数の IOC に付いていても、
    // 両実体が同じ 1 つの IOC からしか届いていなければ、それは ioc 根拠の鏡写しのまま
    for (const [viaName, iocsOf] of [["certificate", certIocs], ["signer", signerIocs]]) {
      const set = v.byVia.get(viaName);
      if (!set) continue;
      const oa = sizes.get(a) || new Set();
      const ob = sizes.get(b) || new Set();
      for (const t of [...set]) {
        const list = [...(iocsOf.get(t) || [])];
        const ia = list.filter((i) => oa.has(i));
        const ib = list.filter((i) => ob.has(i));
        if (!ia.some((x) => ib.some((y) => x !== y))) set.delete(t);
      }
      if (!set.size) v.byVia.delete(viaName);
    }
    const sa = sizes.get(a)?.size || 0;
    const sb = sizes.get(b)?.size || 0;
    // **ファイル名は 1 つだけの一致では数えない。** 置き名や自動命名を落としても
    // 「たまたま同じ名前」は残る。2 つ以上揃って初めて手掛かりになる
    const via = [...v.byVia.keys()].filter((x) => !(x === "filename" && v.byVia.get(x).size < FILENAME_MIN)).sort();
    const shared = via.reduce((t, x) => t + v.byVia.get(x).size, 0);
    if (!via.length) return null;
    // **IOC 集合が完全に一致する組は「重なり」ではない。**同じものが 2 つの名前で
    // 立っているだけで、自分自身と比べている。実測で `"マルウェア": "A, N"` が
    // 区切りで割れ、468 IOC を共有する 2 実体の間に shared 1190 の組が立っていた。
    // 元を断ったあとも、上流の別名が畳めていなければ同じことが起きる。
    if (sameSet(sizes.get(a), sizes.get(b))) return { kind, a, b, iocs: sa, same_set: true };
    // 根拠の値そのもの。多いものは切るが、切ったことが分かるように件数は shared に残る
    const evidence = Object.fromEntries(via.map((x) => [x, [...v.byVia.get(x)].sort().slice(0, EVIDENCE_CAP)]));
    return {
      kind,
      a,
      b,
      shared: shared,
      via,
      // 根拠の種類による差を数字に出す。共有数だけでは弱い根拠が 10 個ある組が上位に来る
      strength: strengthOf(via),
      evidence,
      ...(weakOnly(via) ? { weak_only: true } : {}),
      a_iocs: sa,
      b_iocs: sb,
      // 小さいほうに対する割合。件数だけだと大きい実体が常に上位に来る
      ratio: Math.round((shared / Math.max(1, Math.min(sa, sb))) * 1000) / 1000,
    };
  }).filter(Boolean);
}


/** 2 つの実体が同じ IOC 集合を持つか。空同士は「一致」と見なさない。 */
const sameSet = (a, b) => !!a && !!b && a.size > 0 && a.size === b.size && [...a].every((k) => b.has(k));

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
  const byVhash = new Map();
  const byImphash = new Map();
  const bySigner = new Map();
  const byRegDay = new Map();
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
      // 貸し出し用の /24 は根拠にしない（AS と同じ観点。§3.2b）
      if (subnetUsable(rec?.subnet)) put(bySubnet, rec.subnet);
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
      for (const fam of familyOf.get(key) || []) if (!commonFamily.has(fam)) put(byFamily, fam);
      const v = vtByIoc.get(key);
      for (const n of v?.names || []) if (!commonName.has(n)) put(byFilename, n);
      if (v?.jarm && !commonJarm.has(v.jarm)) put(byJarm, v.jarm);
      if (isPe(key)) put(byVhash, usableHash("vhash", v?.vhash));
      put(bySigner, usableSigner(v));
      // 一斉登録。**同じ登録可能ドメイン同士では数えない**（registrable の写しになる）
      put(byRegDay, regDayOf.get(key));
      put(byImphash, usableHash("imphash", v?.imphash));
    }
  }
  return [
    ["ioc", byIoc], ["subnet", bySubnet], ["registrable", byDomain],
    ...(HAS_ASN ? [["asn", byAsn]] : []),
    ...(HAS_VT ? [
      ["certificate", byCert], ["resolution", byResolution],
      ["vhash", byVhash], ["imphash", byImphash], ["signer", bySigner],
      ["registered", byRegDay],
      ["family", byFamily], ["filename", byFilename], ["jarm", byJarm],
    ] : []),
  ];
}

const overlaps = [];
/**
 * IOC 集合が完全に一致した組。重なりとしては出さず、別の出口に回す。
 *
 * 実体の種類で意味が変わる。malware / actor なら **同じものが 2 つの名前で
 * 立っている**疑い（実測で CloudSorcerer ↔ DeedRAT、Gshell ↔ TencShell など、
 * 既知の別名が並んだ）。case は 1 つの記事から起こすので集合が一致しやすく、
 * 別名ではなく単に同じ括り。どちらにしても「共有率 100%」は構造上そうなるだけで
 * 重なりの根拠にならないので、overlaps.jsonl からは外して数と中身を別に出す。
 */
const identicalSets = [];
for (const kind of KINDS) {
  if (!owned.get(kind).size) continue;
  for (const o of pairsFor(kind, groupsFor(kind))) {
    (o.same_set ? identicalSets : overlaps).push(o);
  }
}
overlaps.sort(byKeys("kind", "a", "b"));
identicalSets.sort(byKeys("kind", "a", "b"));

/* ---------------- /24 の同居 ---------------- */

/**
 * 「同じ入れ物に複数の実体が居る」を数える。/24 と AS で同じ形をとる。
 * 入れ物の鍵の作り方だけを差し替える。
 */
function coTenancy(binOf) {
  const bins = new Map();   // 鍵 → { ips:Set, actors:Set, malware:Set }
  for (const r of iocs) {
    if (r.type !== "ioc.ipv4" && r.type !== "ioc.ipv6") continue;
    if (!INCLUDE_NOISE && dropped(r)) continue;
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
writeJsonl(path.join(OUT, "identical-sets.jsonl"), identicalSets.map((o) => ({ kind: o.kind, a: o.a, b: o.b, iocs: o.iocs })));
// 要約には上位しか載らないので、同居は全件を別に残す
writeJsonl(path.join(OUT, "subnets.jsonl"), subnets);
if (HAS_VT) {
  const t = targetsOf();
  writeJsonl(path.join(OUT, "targets.jsonl"), [
    ...t.impersonation.map((r) => ({ ...r, kind: "impersonation" })),
    ...t.abuse.map((r) => ({ ...r, kind: "abuse" })),
  ].sort((a, b) => a.kind.localeCompare(b.kind) || a.target.localeCompare(b.target) || a.ioc.localeCompare(b.ioc)));
}
if (HAS_ASN) writeJsonl(path.join(OUT, "asn-cotenancy.jsonl"), asnCoTenancy);

/* ---------------- 要約 ---------------- */

/** 既定の並べ替えは強さ。共有数だけだと、弱い根拠を数で押した組が上位に来る。 */
const top = (kind, n = 10) => overlaps
  .filter((o) => o.kind === kind)
  .sort((a, b) => b.strength - a.strength || b.shared - a.shared || b.ratio - a.ratio || (a.a < b.a ? -1 : 1))
  .slice(0, n)
  .map((o) => ({
    a: o.a, b: o.b, shared: o.shared, strength: o.strength, ratio: o.ratio, via: o.via,
    evidence: o.evidence,
    ...(o.weak_only ? { weak_only: true } : {}),
  }));

const byType = {};
for (const r of iocs) byType[r.type] = (byType[r.type] || 0) + 1;

/**
 * 内訳に出す根拠の並び。**lib/overlap.mjs の VIA とは別物。**
 * あちらは「あり得る根拠の全種類」で、こちらは「この環境で実際に出せるもの」。
 * AS もエンリッチも無い環境では、出ない根拠を 0 件として並べても読み手を惑わせる。
 */
const VIA_SHOWN = [
  "ioc", "subnet", "registrable",
  ...(HAS_ASN ? ["asn"] : []),
  ...(HAS_VT ? ["certificate", "resolution", "vhash", "imphash", "signer", "registered", "family", "filename", "jarm"] : []),
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
    ...(HAS_VT ? { jarm_cap: JARM_CAP, filename_cap: FILENAME_CAP, filename_min: FILENAME_MIN,
      family_cap: FAMILY_CAP, vhash_cap: VHASH_CAP, imphash_cap: IMPHASH_CAP } : {}),
    ...(HAS_ABUSE ? { hosting_ratio: HOSTING_RATIO, hosting_min: HOSTING_MIN } : {}),
  },
  iocs: {
    total: iocs.length,
    usable: iocs.filter((r) => usable(r.key)).length,
    by_type: byType,
    excluded: {
      bogon: iocs.filter((r) => r.bogon).length,
      noise: iocs.filter((r) => r.noise).length,
      // 通報の中身が空ばかりで、見本アドレスと判断したもの
      sample_reported: iocs.filter((r) => sampleIps.has(r.key)).length,
      // 人気順位が高く検知が付かない、正規サービスの混入と判断したもの
      popular: iocs.filter((r) => popularDomains.has(r.key)).length,
      malformed: iocs.filter((r) => r.malformed).length,
    },
    dated: iocs.filter((r) => r.observed_first).length,
  },
  entities: Object.fromEntries(KINDS.map((k) => [k, owned.get(k).size])),
  overlaps: Object.fromEntries(KINDS.map((k) => [k, {
    pairs: overlaps.filter((o) => o.kind === k).length,
    // 弱い根拠だけで成立している組。除かずに数える
    weak_only: overlaps.filter((o) => o.kind === k && o.weak_only).length,
    // IOC 集合が一致したので重なりから外した組。中身は identical-sets.jsonl
    identical_sets: identicalSets.filter((o) => o.kind === k).length,
    by_via: VIA_SHOWN.reduce((acc, v) => {
      acc[v] = overlaps.filter((o) => o.kind === k && o.via.includes(v)).length;
      return acc;
    }, {}),
    top: top(k),
  }])),
  /** 何を狙ったか（§3.6）。根拠からは外した正規サービスを、標的として数え直す */
  targets: (() => {
    if (!HAS_VT) return { impersonation: 0, abuse: 0, by_target: [] };
    const t = targetsOf();
    const per = new Map();
    for (const kind of ["impersonation", "abuse"]) {
      for (const r of t[kind]) {
        if (!per.has(r.target)) per.set(r.target, { target: r.target, rank: r.rank, impersonation: 0, abuse: 0 });
        per.get(r.target)[kind]++;
      }
    }
    return {
      impersonation: t.impersonation.length,
      abuse: t.abuse.length,
      by_target: [...per.values()]
        .sort((a, b) => (b.impersonation + b.abuse) - (a.impersonation + a.abuse) || a.target.localeCompare(b.target))
        .slice(0, 20),
    };
  })(),
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
