// 攻撃者ドメインのトラッカーが共有する判定。**外には出ない。**
//
// ここに置いてあるのは「何を追い、何を無視するか」の線引きだけ。
// 取得（fetch-dns.mjs）と突き合わせ（track-domains.mjs）の両方から使う。

/** 動的 DNS と、誰でも子ドメインを作れる基盤。
 *
 *  **なぜ明示の一覧なのか。** 「同じ登録可能ドメインに子が N 件以上ぶら下がっていたら
 *  共用基盤」という数え方を試したが、実測（索引の 6,594 ドメイン）で分かれなかった。
 *  子が 5〜9 件の帯には `gov-pl.cloud` `mindef-nl.cloud` `ukrainesec.cloud` のような
 *  **攻撃者が自分で取った**ドメインが並ぶ。さらに `registrable` の算出が公開接尾辞を
 *  拾っていて、`gov.br`（19）`or.kr`（15）`com.ru`（13）のような eTLD が上位に混ざる。
 *  件数では three-way（DDNS / 公開接尾辞 / 攻撃者所有）を分けられない。
 *
 *  そのため一覧は手で持つ。代わりに、一覧に無いのに子が多い登録可能ドメインは
 *  `shared_suspect` の印を付けて人に見せる（自動では分類しない）。 */
export const DYNAMIC_SUFFIXES = [
  // No-IP
  "ddns.net", "hopto.org", "zapto.org", "sytes.net", "bounceme.net", "redirectme.net",
  "myftp.org", "myftp.biz", "serveftp.com", "servebeer.com", "serveblog.net",
  "servegame.com", "servehttp.com", "serveminecraft.net", "servemp3.com",
  "servepics.com", "servequake.com", "serveirc.com", "servecounterstrike.com",
  "3utilities.com", "ddnsking.com", "webhop.me", "myvnc.com", "onthewifi.com",
  "gotdns.ch", "dvrdns.org", "no-ip.org", "no-ip.biz", "no-ip.info", "no-ip.com",
  // Duck DNS / Dynu / FreeDNS ほか
  "duckdns.org", "dynu.net", "dynu.com", "freedynamicdns.net", "freedynamicdns.org",
  "casacam.net", "mywire.org", "kozow.com", "loseyourip.com", "theworkpc.com",
  "publicvm.com", "linkpc.net", "nsupdate.info", "ip-ddns.com", "dynns.com",
  "dyndns.org", "dyndns.info", "dyndns.biz", "dyndns.tv", "hopto.me",
  "cloudns.nz", "cloudns.ph", "cloudns.cl", "ddns.me", "chickenkiller.com",
  "crabdance.com", "mooo.com", "strangled.net", "twilightparadox.com",
  // 誰でも置ける実行基盤。IP は基盤側のものなので、子ドメインだけが手掛かり
  "workers.dev", "pages.dev", "azurewebsites.net", "web.app", "firebaseapp.com",
  "herokuapp.com", "netlify.app", "vercel.app", "glitch.me", "repl.co",
  "trycloudflare.com", "ngrok.io", "ngrok-free.app", "loca.lt", "serveo.net",
  "onrender.com", "fly.dev", "koyeb.app", "railway.app", "r2.dev",
  "amazonaws.com", "cloudfront.net", "elasticbeanstalk.com", "s3.amazonaws.com",
  "blob.core.windows.net", "cloudapp.azure.com", "appspot.com", "run.app",
];
const DYN = new Set(DYNAMIC_SUFFIXES);

/** そのドメイン名が動的 DNS / 共用基盤の下にあるか。
 *  返すのは「どの接尾辞に当たったか」。当たらなければ null */
export function dynamicSuffixOf(host) {
  const h = String(host || "").toLowerCase().replace(/\.$/, "");
  const parts = h.split(".");
  for (let i = 0; i < parts.length - 1; i++) {
    const suffix = parts.slice(i).join(".");
    if (DYN.has(suffix) && suffix !== h) return suffix;
  }
  return null;
}

/** 解決先が変わっても意味を持たない事業者。**IP ではなく AS で見る**。
 *
 *  CDN と大手クラウドは 1 つの名前が数十の IP を返し、しかも問い合わせるたびに
 *  変わる。IP の差分を取ると毎日「切り替わった」と言い続けることになるので、
 *  ここに載っている AS の中での IP 変化は記録はするが**変化として扱わない**。
 *  AS そのものが変わったときだけ変化とみなす。 */
export const CDN_ASNS = new Set([
  13335,  // Cloudflare
  16509, 14618,  // Amazon
  16625, 20940, 12222, 21342, 33905, 35994,  // Akamai
  15169, 396982,  // Google
  8075, 8068, 8069,  // Microsoft
  54113,  // Fastly
  22822, 15133,  // Limelight / Edgecast
  32934,  // Facebook
  13414,  // Twitter
  55836, 24940,  // Reliance Jio CDN / Hetzner（大きすぎて意味を持たない）
  209242, 203898,  // Cloudflare London / Cloudflare 予備
  19551, 12989,  // Incapsula / Highwinds
  60068, 9009,  // Datacamp / M247（大規模再販）
]);

/** アドレス数がこれを超える AS は、載っていなくても「大きすぎて意味を持たない」扱い。
 *  実測: 索引に出る AS 1,252 個のうち 100 万を超えるのは十数個で、
 *  Cloudflare（143 万）Amazon（2 億 1,553 万）Akamai（1,561 万）Google（421 万）
 *  Microsoft（8,178 万）が並ぶ。攻撃者が借りる小さな事業者とは桁が違う */
export const CDN_MIN_ADDRESSES = 1_000_000;

export const isCdnAsn = (asn, addresses) =>
  asn != null && (CDN_ASNS.has(Number(asn)) || (addresses ?? 0) >= CDN_MIN_ADDRESSES);

/** 解決はするが「生きている」とは言えない行き先。
 *  シンクホール・パーキング・ループバックの類 */
export const DEAD_ANSWERS = new Set([
  "0.0.0.0", "127.0.0.1", "::1", "::",
  "1.1.1.1", "8.8.8.8",           // 投げやりな設定の跡
  "192.168.0.1", "10.0.0.1",
]);
/** よく知られたパーキング／差し押さえの受け皿。増えたらここに足す */
export const SINKHOLE_PREFIXES = [
  "199.59.243.", "13.248.169.", "76.223.", // 売却待ち・Afternic
  "34.102.136.180",                        // Google のパーキング
  "185.53.177.", "185.53.178.",            // Team Internet のパーキング
];

export const looksDead = (ip) =>
  DEAD_ANSWERS.has(ip) || SINKHOLE_PREFIXES.some((p) => String(ip).startsWith(p));

/** 追跡する価値があるか。§3.8 と同じ考え方で、
 *  役割を述べられていない IOC は追わない（研究報告の URL などが混ざるため） */
export const GENERIC_REL = new Set(["観測アクター", "関連"]);
export function trackable(key, { relsOf, vt, iocs, minMalicious = 2 }) {
  const i = iocs.get(key);
  if (!i || i.bogon || i.noise || i.sample) return false;
  const rels = relsOf.get(key);
  if (rels && [...rels].some((r) => !GENERIC_REL.has(r))) return true;
  return (vt.get(key)?.malicious ?? 0) >= minMalicious;
}

/** 状態の名前。events.jsonl と state.jsonl で共通に使う */
export const STATUS = {
  ALIVE: "alive",          // A / AAAA が返り、行き先も意味がある
  PARKED: "parked",        // 応答はあるが、パーキングやシンクホールに落ちている
  NO_ANSWER: "no_answer",  // NOERROR だが A も AAAA も無い
  NXDOMAIN: "nxdomain",    // 名前が無い（失効・未登録）
  ERROR: "error",          // SERVFAIL・タイムアウトなど。判定を保留する
};
