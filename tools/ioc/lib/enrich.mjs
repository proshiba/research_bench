// エンリッチの共通部分。外に出る工程（fetch-vt / fetch-abuseipdb）と
// 分析する工程（enrich-intel）の両方が使う。ここ自体は外に出ない。
//
// 3 つを持つ。
//   1. 鍵の束と枠の配り方  … 複数の鍵を順に回し、1 分あたり・1 時間あたり・1 日あたりを守る
//   2. 写しの置き方        … 1 IOC 1 ファイル。応答の写しはここにだけ置く
//   3. 埋める順の決め方    … docs/ioc-enrich-plan.md §4 の段階分け
//
// 3 を fetch 側と enrich 側で共有するのが肝。別々に持つと「何件を対象と数えたか」が
// 食い違い、カバレッジ（§3.5）が信用できなくなる。

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { sha256, stableStringify } from "./io.mjs";

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/* ---------------- 鍵 ---------------- */

/**
 * 環境変数から鍵を読む。カンマか空白で区切って複数入れられる。
 * リポジトリには一切書かない（docs/ioc-enrich-plan.md §7）。
 */
export function readKeys(...envNames) {
  const seen = new Set();
  for (const name of envNames) {
    for (const k of String(process.env[name] || "").split(/[,\s]+/)) {
      if (k) seen.add(k);
    }
  }
  return [...seen];
}

/**
 * 鍵そのものの代わりに使う短い識別子。
 * 状態ファイルにも表示にも鍵は出さない。同じ鍵かどうかだけが分かればよい。
 */
export const keyId = (key) => crypto.createHash("sha256").update(key).digest("hex").slice(0, 12);

/**
 * 鍵の束。1 本ずつに「次に使ってよい時刻」と「使った数」を持たせ、
 * 一番早く空く鍵を配る。使い切った鍵は自然に外れる。
 *
 * 1 分あたりの間隔を鍵ごとに持つのが要点。まとめて数えると、
 * 鍵 3 本でも 1 本の上限に張り付いて 3 倍にならない。
 */
export class KeyPool {
  constructor(keys, { rpm = 4, hourly = Infinity, daily = Infinity } = {}) {
    this.minInterval = rpm > 0 ? 60000 / rpm : 0;
    this.slots = keys.map((key) => ({
      key,
      id: keyId(key),
      next: 0,
      hour: 0,
      hourStart: Date.now(),
      day: 0,
      hourCap: hourly,
      dayCap: daily,
      blocked: null,   // 使えなくなった理由。null なら生きている
      used: 0,
    }));
  }

  /**
   * 1 時間ぶんの窓を送る。1 時間の上限は「待てば戻るもの」で、
   * 日の上限とは性質が違う。区別しないと、1 時間ぶんを使った所で走行が終わってしまう。
   */
  roll(at = Date.now()) {
    for (const s of this.slots) {
      if (at - s.hourStart >= 3600_000) { s.hour = 0; s.hourStart = at; }
    }
  }

  /** 取得元に聞いた「もう使った数」を反映する。手元で数えるより確かなため。 */
  seed(id, { hour, day, hourCap, dayCap } = {}) {
    const s = this.slots.find((x) => x.id === id);
    if (!s) return;
    if (Number.isFinite(hour)) s.hour = hour;
    if (Number.isFinite(day)) s.day = day;
    if (Number.isFinite(hourCap)) s.hourCap = hourCap;
    if (Number.isFinite(dayCap)) s.dayCap = dayCap;
  }

  block(slot, why) {
    slot.blocked = why;
  }

  get live() {
    return this.slots.filter((s) => !s.blocked && s.hour < s.hourCap && s.day < s.dayCap);
  }

  /**
   * 今日あと何回引けるか。1 時間の上限は待てば戻るので、ここには数えない
   * （数えると「1 時間ぶんしか引けません」と嘘の見積もりになる）。
   */
  get remaining() {
    return this.slots
      .filter((s) => !s.blocked && s.day < s.dayCap)
      .reduce((n, s) => n + (s.dayCap - s.day), 0);
  }

  /**
   * 使ってよい鍵を 1 本渡す。全部が空になったら null。
   * 待つ間に他の鍵が塞がれることがあるので、細かく起きて数え直す。
   */
  async take() {
    for (;;) {
      this.roll();
      const live = this.live;
      if (!live.length) {
        // 1 時間の上限に当たっているだけなら、待てば戻る
        const waiting = this.slots.filter((s) => !s.blocked && s.day < s.dayCap);
        if (!waiting.length) return null;
        await sleep(1000);
        continue;
      }
      const best = live.reduce((a, b) => (a.next <= b.next ? a : b));
      const wait = best.next - Date.now();
      if (wait <= 0) {
        best.next = Date.now() + this.minInterval;
        best.hour++;
        best.day++;
        best.used++;
        return best;
      }
      await sleep(Math.min(wait, 500));
    }
  }

  /** 同じ鍵でもう 1 回引くときの記帳（取り直しなど）。数え落とすと枠を踏み越える。 */
  charge(slot) {
    slot.next = Date.now() + this.minInterval;
    slot.hour++;
    slot.day++;
    slot.used++;
  }

  /** 表示と meta 用。鍵は出さない。 */
  report() {
    return this.slots
      .map((s) => ({
        key: s.id,
        used: s.used,
        ...(Number.isFinite(s.dayCap) ? { day_used: s.day, day_cap: s.dayCap } : {}),
        ...(s.blocked ? { blocked: s.blocked } : {}),
      }))
      .sort((a, b) => (a.key < b.key ? -1 : 1));
  }
}

/* ---------------- 写しの置き方 ---------------- */

/**
 * 1 IOC 1 ファイル。名前は IOC 鍵のハッシュにする。
 * IOC の値をそのままファイル名にすると、長さ・大文字小文字・使えない文字で必ず破綻する。
 * 中身に `ioc` を持たせてあるので、写しだけからでもどれのものか分かる。
 */
export function cacheFile(root, iocKey) {
  const h = sha256(Buffer.from(iocKey, "utf8"));
  return path.join(root, h.slice(0, 2), `${h}.json`);
}

export function readRecord(root, iocKey) {
  const f = cacheFile(root, iocKey);
  if (!fs.existsSync(f)) return null;
  try {
    return JSON.parse(fs.readFileSync(f, "utf8"));
  } catch {
    return null;   // 書きかけで落ちた写しは無かったことにして取り直す
  }
}

/**
 * 写しを 1 件置く。**鍵は既定で `rec.ioc`** だが、同じ IOC に複数の写しを持つ工程
 * （関係の取得。IOC ごとに contacted_ips / contacted_domains … と分かれる）は
 * `key` を明示して分ける。
 */
export function writeRecord(root, rec, key) {
  const f = cacheFile(root, key ?? rec.ioc);
  fs.mkdirSync(path.dirname(f), { recursive: true });
  // 途中で落ちても壊れた写しが残らないように、書いてから差し替える
  const tmp = `${f}.tmp`;
  fs.writeFileSync(tmp, stableStringify(rec));
  fs.renameSync(tmp, f);
}

/** 写しを全部読む。分析する工程はここしか見ない。 */
export function readAllRecords(root) {
  const out = [];
  if (!fs.existsSync(root)) return out;
  for (const shard of fs.readdirSync(root).sort()) {
    const dir = path.join(root, shard);
    if (!/^[0-9a-f]{2}$/.test(shard) || !fs.statSync(dir).isDirectory()) continue;
    for (const name of fs.readdirSync(dir).sort()) {
      if (!name.endsWith(".json")) continue;
      try {
        out.push(JSON.parse(fs.readFileSync(path.join(dir, name), "utf8")));
      } catch {
        /* 壊れた写しは無視する。取り直せばよい */
      }
    }
  }
  return out;
}

/**
 * 写し全体をひとつのハッシュにまとめる。
 * `asn-meta.json` が経路表 1 ファイルのハッシュを持つのと同じ役目で、
 * 「どの写しから出た結果か」を後から固定できるようにする。
 */
export function digestRecords(records) {
  const h = crypto.createHash("sha256");
  for (const r of [...records].sort((a, b) => (a.ioc < b.ioc ? -1 : 1))) {
    h.update(r.ioc).update("\0").update(String(r.status)).update("\0");
    h.update(sha256(Buffer.from(stableStringify(r.body ?? null, 0), "utf8"))).update("\n");
  }
  return h.digest("hex");
}

/* ---------------- 応答の射影 ---------------- */

/**
 * 写しに残す欄。**応答そのものではなく、計画（§1）が使うと決めた欄だけ**を残す。
 *
 * なぜ全部残さないか。VT のファイル応答は 1 件 50〜200 KB あり、その大半は
 * `last_analysis_results`（ベンダーごとの判定文字列）と静的解析の中身が占める。
 * 18,537 件では 1 GB を超え、写しとして持ち歩ける大きさではなくなる。
 *
 * 代わりに **版（PROJECTION）を写しに書く**。使う欄を増やしたら版を上げ、
 * 版が古い写しは取り直す。何を落としたかが写し自身から分かるようにするため。
 * 全部残したいときは fetch-vt.mjs に --full を付ける（`projection: 0` になる）。
 */
/**
 * 版は**引き先ごとに持つ**。使う欄が増えたときに、増えた種類だけ取り直せばよい。
 * まとめて 1 つにすると、ファイルの欄を増やしただけでドメインも IP も
 * 取り直すことになる（実測で 2,058 件で済むところが 5,433 件になる）。
 */
export const PROJECTION = { files: 2, domains: 1, ip_addresses: 1, urls: 1 };
export const projectionOf = (kind) => PROJECTION[kind] ?? 1;

export const VT_FIELDS = {
  files: [
    "last_analysis_stats", "reputation", "popular_threat_classification",
    "first_submission_date", "last_analysis_date", "last_submission_date",
    "meaningful_name", "names", "type_description", "size", "signature_info",
    "md5", "sha1", "sha256",
    // 版 2 で足した**ファジーハッシュ**。提供元の判断が入らず、論理が明示的なので
    // 検知名より根拠として素直（vhash / imphash は完全一致、ssdeep / tlsh は距離）
    "vhash", "ssdeep", "tlsh", "authentihash", "telfhash", "permhash", "magic",
  ],
  domains: [
    "last_analysis_stats", "reputation", "last_dns_records", "last_https_certificate",
    "last_https_certificate_date", "jarm", "creation_date", "registrar", "categories",
    "last_analysis_date", "last_modification_date", "popularity_ranks",
  ],
  ip_addresses: [
    "last_analysis_stats", "reputation", "as_owner", "asn", "network", "country",
    "continent", "last_https_certificate", "last_https_certificate_date", "jarm",
    "last_analysis_date", "last_modification_date", "regional_internet_registry",
  ],
  urls: [
    "last_analysis_stats", "reputation", "last_final_url", "title", "categories",
    "redirection_chain", "first_submission_date", "last_analysis_date", "url",
  ],
};

/**
 * 入れ子から引き上げる欄。`pe_info` は丸ごとだと数十 KB あるので、
 * 使うハッシュだけを平らに持つ。
 */
const VT_LIFT = {
  files: { imphash: (a) => a.pe_info?.imphash, rich_header: (a) => a.pe_info?.rich_pe_header_hash },
};

/** 使う欄だけを抜く。無い欄は作らない（あとで「取れなかった」と区別できるように）。 */
export function project(kind, attributes) {
  const keep = VT_FIELDS[kind];
  if (!keep) return attributes;
  const out = {};
  for (const k of keep) if (attributes?.[k] !== undefined) out[k] = attributes[k];
  for (const [k, pick] of Object.entries(VT_LIFT[kind] || {})) {
    const v = pick(attributes || {});
    if (v !== undefined && v !== null && v !== "") out[k] = v;
  }
  return out;
}

/* ---------------- 対象と埋める順 ---------------- */

/** VT の対象になる IOC の型 → 引く先。 */
export function vtTarget(ioc) {
  switch (ioc.type) {
    case "ioc.md5":
    case "ioc.sha1":
    case "ioc.sha256":
      return { kind: "files", id: ioc.value };
    case "ioc.domain":
      return { kind: "domains", id: ioc.value };
    case "ioc.ipv4":
    case "ioc.ipv6":
      return { kind: "ip_addresses", id: ioc.value };
    case "ioc.url":
      // URL の識別子は base64url（詰め物は落とす）
      return { kind: "urls", id: Buffer.from(ioc.value, "utf8").toString("base64url").replace(/=+$/, "") };
    // ioc.sha512 は VT が索引していない（引いても必ず外れる）。
    // ioc.email / ioc.endpoint は対応する引き先が無い。どれも対象から外す。
    default:
      return null;
  }
}

export const ABUSE_TARGET_TYPES = new Set(["ioc.ipv4", "ioc.ipv6"]);

/** 分析にも問い合わせにも使わないもの。印は collect が既に付けている。 */
export const excluded = (r, { includeNoise = false } = {}) =>
  !!(r.malformed || r.bogon || (!includeNoise && r.noise));

const ENTITY_KINDS = new Set(["actor", "malware", "campaign", "case"]);

/**
 * IOC ごとに繋がっている実体の数を数える。段階分けの中心になる値。
 * 「複数の実体に繋がる IOC」＝ 重なりの根拠そのもの（§4 の段階 1）。
 */
export function entityCounts(links) {
  const per = new Map();
  for (const l of links) {
    if (!ENTITY_KINDS.has(l.kind)) continue;
    if (!per.has(l.ioc)) per.set(l.ioc, new Set());
    per.get(l.ioc).add(`${l.kind}\t${l.name}`);
  }
  return new Map([...per].map(([k, v]) => [k, v.size]));
}

/**
 * 注目 IP（段階 2）。**既に怪しいと分かっている IP** を先に裏取りする。
 *   ・小さい AS に居る（借り先が絞れている）
 *   ・別のアクターが同居している /24 に居る
 */
export function notableIps(iocs, links, { asnOf, asnInfo, maxAddresses = 4096 }) {
  const out = new Set();
  const actorsPerSubnet = new Map();
  const iocById = new Map(iocs.map((r) => [r.key, r]));
  for (const l of links) {
    if (l.kind !== "actor") continue;
    const r = iocById.get(l.ioc);
    if (!r?.subnet) continue;
    if (!actorsPerSubnet.has(r.subnet)) actorsPerSubnet.set(r.subnet, new Set());
    actorsPerSubnet.get(r.subnet).add(l.name);
  }
  for (const r of iocs) {
    if (r.type !== "ioc.ipv4" && r.type !== "ioc.ipv6") continue;
    const asn = asnOf.get(r.key);
    const size = asn ? (asnInfo.get(asn)?.addresses ?? 0) : 0;
    const small = size > 0 && size <= maxAddresses;
    const crowded = (actorsPerSubnet.get(r.subnet)?.size ?? 0) > 1;
    if (small || crowded) out.add(r.key);
  }
  return out;
}

/**
 * 段階（docs/ioc-enrich-plan.md §4）。小さいほど先に埋める。
 *
 *   new … 前回に無かった IOC。常に最優先（新しく入ってくる分を溜めないため）
 *   1   … 複数の実体に繋がる IOC。**ここが終われば主目的はほぼ達成**
 *   2   … 注目 IP（小さい AS / 別アクター同居の /24）
 *   3   … ハッシュ（実体 1 つ）
 *   4   … ドメイン・URL（実体 1 つ）
 *   5   … 残りの IP
 *   6   … どれにも入らないもの（実体に繋がっていない IOC など）
 */
export const STAGES = ["new", "1", "2", "3", "4", "5", "6"];

export function stageOf(ioc, { entities, isNew, notable }) {
  if (isNew) return "new";
  if ((entities ?? 0) >= 2) return "1";
  if (notable) return "2";
  if (ioc.type === "ioc.md5" || ioc.type === "ioc.sha1" || ioc.type === "ioc.sha256") {
    return entities >= 1 ? "3" : "6";
  }
  if (ioc.type === "ioc.domain") return entities >= 1 ? "4" : "6";
  /**
   * **URL は IP より後ろに置く。** 元の計画では段階 4 にドメインと同居させていたが、
   * 実測すると URL の応答は**いま根拠に使っている欄を 1 つも持っていなかった**
   * （取得済み 749 件で証明書 0 / JARM 0 / DNS 0 / 人気順位 0）。
   * 返ってくるのは転送先と分類だけで、どちらもまだ via になっていない。
   * 同じ枠を IP に使えば、1,271 件で証明書 604・JARM 708・AS 1,233 が付いた。
   * 段階 5 に同居させ、buildQueue の KIND_YIELD で IP を先に引く。
   */
  if (ioc.type === "ioc.url") return entities >= 1 ? "5" : "6";
  if (ioc.type === "ioc.ipv4" || ioc.type === "ioc.ipv6") return "5";
  return "6";
}

/**
 * 引き先ごとの「1 回引いて得られる根拠の量」。段階の中の並びに使う。
 *
 * **同じ段階でも引き先で収穫が違う。** 段階 4 はドメインと URL が同居するが、
 * ドメインは証明書・解決先・JARM・人気順位（正規サービスの印）を返すのに対し、
 * URL が返すのは転送先と分類だけで、**いま根拠として使っている欄をほぼ持たない**。
 * 実測で段階 4 の残り 2,291 件のうち 2,074 件が URL だった。順を付けないと、
 * 枠の大半が収穫の薄いほうに流れる。
 *
 * files が domains の次なのは、ハッシュが署名者とファジーハッシュを返すため。
 */
const KIND_YIELD = { domains: 0, files: 1, ip_addresses: 2, urls: 3 };

/**
 * 引く順を決める。並びは決定的にする（同じ入力なら同じ順で引く）。
 * 段階の中では「繋がっている実体が多い順 → 収穫の多い引き先順 → 鍵順」。
 */
export function buildQueue(targets) {
  const rank = new Map(STAGES.map((s, i) => [s, i]));
  const yieldOf = (t) => KIND_YIELD[t.kind] ?? 9;
  return [...targets].sort((a, b) =>
    rank.get(a.stage) - rank.get(b.stage) ||
    (b.entities ?? 0) - (a.entities ?? 0) ||
    yieldOf(a) - yieldOf(b) ||
    (a.ioc < b.ioc ? -1 : 1));
}

/** 段階ごとの件数。--plan の表と、enrich 側のカバレッジで同じ数を使う。 */
export function tallyStages(targets) {
  const out = {};
  for (const s of STAGES) out[s] = 0;
  for (const t of targets) out[t.stage]++;
  for (const s of STAGES) if (!out[s]) delete out[s];
  return out;
}

/* ---------------- カバレッジ ---------------- */

/**
 * **どこまで調べたか**（docs/ioc-enrich-plan.md §3.5）。
 *
 * 1 キーでは全件が埋まるまで日数がかかるので、途中の統計は一部しか見ていない。
 * 「検知されたのは 12%」と「調べた範囲の 12%」は別物で、後者を前者として読むと
 * 必ず間違える。だから **未エンリッチは陰性ではなく未知として数え**、分母を必ず出す。
 *
 * enrich-intel.mjs と stats.mjs の両方がこれを呼ぶ。別々に数えると分母が食い違い、
 * どちらが正しいのか誰にも分からなくなる。
 */
export function coverageOf({
  iocs, links, fresh = new Set(), asnOf = new Map(), asnInfo = new Map(),
  vtRows = [], abuseRows = [], includeNoise = false, fetchDays = [],
}) {
  const counts = entityCounts(links);
  const notable = notableIps(iocs, links, { asnOf, asnInfo });

  const vtTargets = [], abuseTargets = [];
  for (const r of iocs) {
    if (excluded(r, { includeNoise })) continue;
    const n = counts.get(r.key) || 0;
    const stage = stageOf(r, { entities: n, isNew: fresh.has(r.key), notable: notable.has(r.key) });
    if (vtTarget(r)) vtTargets.push({ ioc: r.key, stage });
    if (ABUSE_TARGET_TYPES.has(r.type)) abuseTargets.push({ ioc: r.key, stage });
  }

  const perStage = (targets, doneKeys) => {
    const all = tallyStages(targets);
    const done = tallyStages(targets.filter((t) => doneKeys.has(t.ioc)));
    return Object.fromEntries(Object.keys(all).sort().map((s) => [s, { done: done[s] || 0, target: all[s] }]));
  };
  const ratio = (a, b) => (b > 0 ? Math.round((a / b) * 1000) / 1000 : 0);
  const days = [...fetchDays].filter(Boolean).sort();

  return {
    virustotal: {
      target: vtTargets.length,
      done: vtRows.length,
      known: vtRows.filter((r) => r.known).length,
      unknown: vtRows.filter((r) => !r.known).length,
      ratio: ratio(vtRows.length, vtTargets.length),
      by_stage: perStage(vtTargets, new Set(vtRows.map((r) => r.ioc))),
    },
    abuseipdb: {
      target: abuseTargets.length,
      done: abuseRows.length,
      ratio: ratio(abuseRows.length, abuseTargets.length),
      by_stage: perStage(abuseTargets, new Set(abuseRows.map((r) => r.ioc))),
    },
    oldest_fetch: days[0] || null,
    newest_fetch: days[days.length - 1] || null,
  };
}
