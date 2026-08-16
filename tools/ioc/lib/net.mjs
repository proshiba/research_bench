// IP の扱い。/24 でのまとめと、分析から外すべきアドレスの判定。
//
// 外すべきものは **捨てずに印を付ける**。捨てると「なぜ消えたか」が後から分からず、
// 元データの誤りにも気づけない。統計側が既定で除くだけにする。

/** IPv4 を 32bit の数値にする。壊れていれば null。 */
export function ipv4ToInt(ip) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(String(ip).trim());
  if (!m) return null;
  const parts = m.slice(1).map(Number);
  if (parts.some((n) => n > 255)) return null;
  return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
}

export function subnet24(ip) {
  const parts = String(ip).split(".");
  if (parts.length !== 4 || ipv4ToInt(ip) === null) return null;
  return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
}

const cidr = (s) => {
  const [base, bits] = s.split("/");
  const n = ipv4ToInt(base);
  const b = Number(bits);
  const mask = b === 0 ? 0 : (0xffffffff << (32 - b)) >>> 0;
  return { net: (n & mask) >>> 0, mask };
};

/**
 * 経路に乗らない・観測対象になりえないレンジ（RFC の予約など）。
 * ここに入るものはインフラの重なりを見るうえで意味を持たない。
 */
const BOGON = [
  "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
  "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16",
  "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
  "224.0.0.0/4", "240.0.0.0/4",
].map(cidr);

/**
 * 実在はするが、指標としてはまず意味を持たないもの。
 * 公開 DNS や計測用のアドレスが「C2」として紛れ込むことがある。
 */
const NOISE = [
  { range: cidr("1.0.0.0/24"), why: "APNIC 研究用 / Cloudflare DNS" },
  { range: cidr("1.1.1.0/24"), why: "Cloudflare DNS" },
  // 1.2.3.4 は「適当な IP」として書かれ続けた見本アドレス。経路には乗るので
  // bogon では拾えないが、報告書に出てきても実際の C2 ではまず無い。
  // AbuseIPDB でも ISP が "APNIC Debogon Project" と出て、汚染の計測対象であることが分かる。
  { range: cidr("1.2.3.0/24"), why: "見本アドレス / APNIC Debogon Project" },
  { range: cidr("8.8.8.0/24"), why: "Google DNS" },
  { range: cidr("8.8.4.0/24"), why: "Google DNS" },
  { range: cidr("9.9.9.0/24"), why: "Quad9 DNS" },
  { range: cidr("208.67.222.0/24"), why: "OpenDNS" },
  { range: cidr("208.67.220.0/24"), why: "OpenDNS" },
];

const inRange = (n, { net, mask }) => ((n & mask) >>> 0) === net;

/**
 * IPv4 の性質を返す。
 *   bogon … 経路に乗らない
 *   noise … 実在するが指標になりにくい（理由つき）
 */
export function classifyIpv4(ip) {
  const n = ipv4ToInt(ip);
  if (n === null) return { valid: false };
  if (BOGON.some((r) => inRange(n, r))) return { valid: true, bogon: true };
  const hit = NOISE.find((x) => inRange(n, x.range));
  if (hit) return { valid: true, noise: hit.why };
  return { valid: true };
}

/** IPv6 は簡易判定だけ。ループバックと未指定と文書用を落とす。 */
export function classifyIpv6(ip) {
  const v = String(ip).trim().toLowerCase();
  if (!/^[0-9a-f:]+$/.test(v) || !v.includes(":")) return { valid: false };
  if (v === "::" || v === "::1") return { valid: true, bogon: true };
  if (v.startsWith("fe80:") || v.startsWith("fc") || v.startsWith("fd")) return { valid: true, bogon: true };
  if (v.startsWith("2001:db8:")) return { valid: true, bogon: true };
  return { valid: true };
}

import { registrableFromPsl, hasPsl } from "./psl.mjs";

/** ドメインの登録可能部分（eTLD+1）。同一登録者の推定に使う。
 *
 *  **公開接尾辞一覧（PSL）の写しがあればそれを使う**（tools/ioc/fetch-psl.mjs）。
 *  無いときだけ下の手書き一覧に落ちる。手書きでは追いつかないことが実測で分かっている
 *  ——`com.br` は入っていたが `gov.br` が抜けていて、ブラジル政府のドメイン 19 件が
 *  「同じ登録者の子」に見えていた。`or.kr` `pe.kr` `com.ru` も同じ。
 *
 *  PSL の PRIVATE 区画（`ddns.net` `workers.dev` …）も接尾辞として扱う。
 *  `a.ddns.net` と `b.ddns.net` は「同じ人が買った」ではないため。 */
const MULTI_TLD = new Set([
  "co.uk", "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "com.au", "com.br", "com.cn",
  "com.mx", "com.tr", "com.tw", "co.kr", "co.in", "co.za", "com.ar", "com.pe", "com.my",
  "org.uk", "net.au", "gov.uk", "ac.uk", "com.sg", "com.hk", "com.ua", "co.il",
]);

export function registrableDomain(host) {
  const viaPsl = registrableFromPsl(host);
  if (viaPsl !== null) return viaPsl;
  if (hasPsl()) return null;   // 写しがあって null なら、それは接尾辞そのもの
  const parts = String(host).trim().toLowerCase().replace(/\.$/, "").split(".");
  if (parts.length < 2) return null;
  const last2 = parts.slice(-2).join(".");
  if (parts.length >= 3 && MULTI_TLD.has(last2)) return parts.slice(-3).join(".");
  return last2;
}
