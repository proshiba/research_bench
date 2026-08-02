// 経路表（prefix → AS 番号）の読み込みと最長一致。
//
// 経路表は 118 万件（v4）あるので、素直にオブジェクトで持つと数百 MB になる。
// prefix 長ごとに Map を分け、値は 1 つの数値に詰めて持つ。こうすると
// 「長い側から順に、その長さでマスクした網を引く」だけで最長一致が出る。

import fs from "node:fs";
import { ipv4ToInt } from "./net.mjs";

/** IPv4 を a.b.c.d に戻す。 */
export const intToIpv4 = (n) =>
  [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");

/** IPv6 を 32 桁の 16 進にする。`::` の省略を展開する。壊れていれば null。 */
export function ipv6ToHex(addr) {
  const v = String(addr).trim().toLowerCase();
  if (!/^[0-9a-f:]*$/.test(v) || !v.includes(":")) return null;
  const [head, tail, ...rest] = v.split("::");
  if (rest.length) return null;
  const parse = (s) => (s ? s.split(":").filter((x) => x !== "") : []);
  const a = parse(head);
  const b = tail === undefined ? [] : parse(tail);
  const fill = 8 - a.length - b.length;
  if (tail === undefined ? a.length !== 8 : fill < 0) return null;
  const groups = [...a, ...Array(tail === undefined ? 0 : fill).fill("0"), ...b];
  if (groups.length !== 8) return null;
  let out = "";
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
    out += g.padStart(4, "0");
  }
  return out;
}

/** 値の詰め方。asn と hits を 1 つの数値にする（Map の要素数が 100 万を超えるため）。 */
const HITS_MAX = 8191;
const pack = (asn, hits) => asn * 8192 + Math.min(hits, HITS_MAX);
const unpackAsn = (v) => Math.floor(v / 8192);
const unpackHits = (v) => v % 8192;

const maskV4 = (n, len) => (len === 0 ? 0 : (n & ((0xffffffff << (32 - len)) >>> 0)) >>> 0);
const maskV6 = (hex, len) => {
  const bits = BigInt(128 - len);
  return ((BigInt("0x" + hex) >> bits) << bits).toString(16).padStart(32, "0");
};

/**
 * bgp.tools の table.jsonl を読む。
 *
 * `want` に "v4" / "v6" を渡すと、要る側だけ組み立てる。v6 は BigInt を使うので、
 * v6 の IOC が無いときに作ると無駄に数秒かかる。
 *
 * 同じ prefix を複数の AS が出している（MOAS）ことがある。観測数の多いほうを採り、
 * 同数なら AS 番号の小さいほうにする（結果を実行ごとに変えないため）。
 */
export function loadTable(file, want = ["v4"]) {
  const v4 = new Map();   // 長さ → Map<網(数値), packed>
  const v6 = new Map();   // 長さ → Map<網(16進), packed>
  let v4Count = 0, v6Count = 0, skipped = 0;
  const asnPrefixes = new Map();   // AS → { prefixes, addresses }

  const put = (bucket, len, key, asn, hits) => {
    if (!bucket.has(len)) bucket.set(len, new Map());
    const m = bucket.get(len);
    const cur = m.get(key);
    if (cur !== undefined) {
      const curHits = unpackHits(cur);
      const curAsn = unpackAsn(cur);
      if (hits < curHits || (hits === curHits && asn >= curAsn)) return false;
    }
    m.set(key, pack(asn, hits));
    return cur === undefined;
  };

  for (const line of fs.readFileSync(file, "utf8").split("\n")) {
    if (!line) continue;
    let o;
    try { o = JSON.parse(line); } catch { skipped++; continue; }
    const cidr = String(o.CIDR || "");
    const asn = Number(o.ASN);
    const hits = Number(o.Hits) || 0;
    const slash = cidr.lastIndexOf("/");
    if (slash < 0 || !Number.isInteger(asn) || asn <= 0) { skipped++; continue; }
    const base = cidr.slice(0, slash);
    const len = Number(cidr.slice(slash + 1));

    if (base.includes(":")) {
      if (!want.includes("v6")) continue;
      const hex = ipv6ToHex(base);
      if (hex === null || !(len >= 0 && len <= 128)) { skipped++; continue; }
      if (put(v6, len, maskV6(hex, len), asn, hits)) v6Count++;
    } else {
      if (!want.includes("v4")) continue;
      const n = ipv4ToInt(base);
      if (n === null || !(len >= 0 && len <= 32)) { skipped++; continue; }
      if (put(v4, len, maskV4(n, len), asn, hits)) v4Count++;
      // AS の大きさ。同じ AS が出している v4 アドレスの総数で測る。
      // 「大きい AS に同居している」はほぼ何も意味しないので、後で重みに使う
      if (!asnPrefixes.has(asn)) asnPrefixes.set(asn, { prefixes: 0, addresses: 0 });
      const a = asnPrefixes.get(asn);
      a.prefixes++;
      a.addresses += 2 ** (32 - len);
    }
  }

  // 長い側から引きたいので、長さは降順に持つ
  const order = (bucket) => [...bucket.keys()].sort((a, b) => b - a);
  return { v4, v6, v4Order: order(v4), v6Order: order(v6), v4Count, v6Count, skipped, asnPrefixes };
}

/** 最長一致。見つからなければ null（経路に出ていないアドレス）。 */
export function lookupIpv4(table, ip) {
  const n = ipv4ToInt(ip);
  if (n === null) return null;
  for (const len of table.v4Order) {
    const v = table.v4.get(len).get(maskV4(n, len));
    if (v !== undefined) {
      return { asn: unpackAsn(v), hits: unpackHits(v), prefix: `${intToIpv4(maskV4(n, len))}/${len}` };
    }
  }
  return null;
}

export function lookupIpv6(table, ip) {
  const hex = ipv6ToHex(ip);
  if (hex === null) return null;
  for (const len of table.v6Order) {
    const key = maskV6(hex, len);
    const v = table.v6.get(len).get(key);
    if (v !== undefined) {
      // 表示は詰めた形に戻す（先頭の 0 を落とし、連続する 0 群を :: にする）
      const groups = key.match(/.{4}/g).map((g) => g.replace(/^0+(?=.)/, ""));
      const shown = groups.join(":").replace(/(^|:)0(:0)+(:|$)/, "::").replace(/:{3,}/, "::");
      return { asn: unpackAsn(v), hits: unpackHits(v), prefix: `${shown}/${len}` };
    }
  }
  return null;
}

/**
 * bgp.tools の asns.csv（asn,name,class,cc）。名前に読点が入るので素直に split できない。
 */
export function parseAsnCsv(text) {
  const out = new Map();
  const lines = text.split("\n");
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i];
    if (!line.trim()) continue;
    const m = /^AS(\d+),(?:"((?:[^"]|"")*)"|([^,]*)),([^,]*),([^,]*)\s*$/.exec(line);
    if (!m) continue;
    const name = (m[2] !== undefined ? m[2].replace(/""/g, '"') : m[3]).trim();
    out.set(Number(m[1]), {
      name: name || null,
      class: m[4] && m[4] !== "Unknown" ? m[4] : null,
      cc: m[5] || null,
    });
  }
  return out;
}
