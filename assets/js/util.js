// 共有ユーティリティ。DOM 生成・値の正規化・種別判定。

export function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

export function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k === "class") node.className = v;
    else if (k === "text") node.textContent = v;
    else if (k === "html") node.innerHTML = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else if (k === "dataset") Object.assign(node.dataset, v);
    else if (v === true) node.setAttribute(k, "");
    else node.setAttribute(k, v);
  }
  for (const c of [].concat(children)) {
    if (c == null) continue;
    node.append(c.nodeType ? c : document.createTextNode(String(c)));
  }
  return node;
}

export function fmtBytes(n) {
  if (!n) return "—";
  if (n >= 1048576) return (n / 1048576).toFixed(1) + " MB";
  if (n >= 1024) return Math.round(n / 1024) + " KB";
  return n + " B";
}

export function fmtNum(n) {
  return typeof n === "number" ? n.toLocaleString("en-US") : String(n ?? "—");
}

/** 難読化された指標を元に戻す。`1.2.3[.]4` `hxxps://` `foo(dot)bar` など。 */
export function refang(s) {
  return String(s)
    .replace(/\[\.\]|\(\.\)|\{\.\}/g, ".")
    .replace(/\(dot\)|\[dot\]/gi, ".")
    .replace(/\[:\]/g, ":")
    .replace(/\[@\]|\(at\)|\[at\]/gi, "@")
    .replace(/^h(?:xx|XX)(ps?):/i, "http$1:")
    .replace(/^(?:hxxp|hXXp)/i, "http")
    .trim();
}

const IPV4 = /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;
const CVE = /^CVE-\d{4}-\d{4,7}$/i;
const HEX32 = /^[a-f0-9]{32}$/i;
const HEX40 = /^[a-f0-9]{40}$/i;
const HEX64 = /^[a-f0-9]{64}$/i;
const HEX128 = /^[a-f0-9]{128}$/i;
const DOMAIN = /^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63})*\.[a-z]{2,}$/i;
const TTP = /^T\d{4}(?:\.\d{3})?$/i;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/** 入力文字列がどの種別として解釈できるかを返す。判定できなければ null。 */
export function detectType(raw) {
  const v = refang(String(raw).trim());
  if (!v) return null;
  if (IPV4.test(v)) return "ioc.ipv4";
  if (v.includes(":") && /^[0-9a-f:]+$/i.test(v) && v.split(":").length > 2) return "ioc.ipv6";
  if (CVE.test(v)) return "cve";
  if (HEX128.test(v)) return "ioc.sha512";
  if (HEX64.test(v)) return "ioc.sha256";
  if (HEX40.test(v)) return "ioc.sha1";
  if (HEX32.test(v)) return "ioc.md5";
  if (TTP.test(v)) return "ttp";
  if (EMAIL.test(v)) return "ioc.email";
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(v)) return "ioc.url";
  if (/^[^\s/]+:\d{1,5}$/.test(v)) return "ioc.endpoint";
  if (DOMAIN.test(v)) return "ioc.domain";
  return null;
}

const TYPE_JA = {
  "ioc.ipv4": "IP アドレス",
  "ioc.ipv6": "IPv6 アドレス",
  "ioc.domain": "ドメイン",
  "ioc.url": "URL",
  "ioc.endpoint": "エンドポイント",
  "ioc.email": "メールアドレス",
  "ioc.md5": "MD5",
  "ioc.sha1": "SHA-1",
  "ioc.sha256": "SHA-256",
  "ioc.sha512": "SHA-512",
  cve: "脆弱性",
  actor: "脅威アクター",
  malware: "マルウェア",
  case: "解析ケース",
  campaign: "キャンペーン",
  product: "製品",
  vendor: "ベンダー",
  ttp: "TTP",
  tool: "ツール",
  report: "レポート",
  // ポータル内だけの種別。OSINT のタグのように分類が定まらない値に使う。
  // 各アプリの索引がこれを出すことはない（spec の語彙には含めない）。
  other: "分類不明",
};

export function typeLabel(t) {
  return TYPE_JA[t] || t || "その他";
}

/**
 * エンティティ種別のグループ。ワークベンチのノードは
 * このグループで色と形が決まる（ソース由来ではない）。
 *
 * 色は dataviz の検証器で全ペア判定を通したもの:
 * 両モードの L バンド通過・クロマ床通過・通常視 ΔE 15.7（床 15）。
 * CVD ΔE は 6.3 で 6–8 の帯に入るため、**形状という二次符号化が前提**。
 * 形とノード直下のラベルが常に出ているのでこの条件を満たす。
 * 赤系は状態色（--crit）に予約しているため候補から外してある。
 */
export const TYPE_GROUPS = {
  network: { label: "IP / エンドポイント", shape: "circle", color: "--type-network" },
  host:    { label: "ドメイン / URL",      shape: "hexagon", color: "--type-host" },
  file:    { label: "ファイル / ケース",   shape: "square", color: "--type-file" },
  malware: { label: "マルウェア / ツール", shape: "triangle", color: "--type-malware" },
  actor:   { label: "アクター",            shape: "diamond", color: "--type-actor" },
  vuln:    { label: "脆弱性 / 製品",       shape: "pentagon", color: "--type-vuln" },
  context: { label: "キャンペーン / TTP",  shape: "roundsquare", color: "--type-context" },
  other:   { label: "その他",              shape: "ring", color: "--type-other" },
};

const TYPE_TO_GROUP = {
  "ioc.ipv4": "network", "ioc.ipv6": "network", "ioc.endpoint": "network",
  "ioc.domain": "host", "ioc.url": "host",
  "ioc.md5": "file", "ioc.sha1": "file", "ioc.sha256": "file", "ioc.sha512": "file",
  case: "file",
  malware: "malware", tool: "malware",
  actor: "actor",
  cve: "vuln", product: "vuln", vendor: "vuln", report: "vuln",
  campaign: "context", ttp: "context",
  "ioc.email": "other",
};

/** 種別 → グループ名。未知の種別は other に落とす（落ちないこと自体が仕様）。 */
export function typeGroup(type) {
  return TYPE_TO_GROUP[type] || "other";
}

/**
 * ソース横断の結合キー。同じ実体が別々のソースで違う書き方をされていても
 * 同じキーに落ちるようにする。仕様 §3 と対応。
 */
export function joinKey(type, value) {
  const v = refang(String(value ?? "")).trim();
  if (!v) return "";
  if (type === "cve") return v.toUpperCase();
  if (type === "actor" || type === "malware") {
    const k = v.toLowerCase().replace(/[^a-z0-9]+/g, "");
    return k ? "name:" + k : "";
  }
  if (type === "ttp") return v.toUpperCase();
  return v.toLowerCase();
}

/** 検索語との一致部分を <mark> で囲む。返り値はエスケープ済み HTML。 */
export function highlight(label, q) {
  const s = String(label ?? "");
  if (!q) return esc(s);
  const i = s.toLowerCase().indexOf(String(q).toLowerCase());
  if (i < 0) return esc(s);
  return esc(s.slice(0, i)) + "<mark>" + esc(s.slice(i, i + q.length)) + "</mark>" + esc(s.slice(i + q.length));
}

export function shorten(s, n = 22) {
  const v = String(s ?? "");
  return v.length > n ? v.slice(0, n - 1) + "…" : v;
}

/** 進捗つき fetch。Content-Length が無ければ approx で按分する。 */
export async function fetchWithProgress(url, { approx = 0, onProgress } = {}) {
  const res = await fetch(url, { mode: "cors", credentials: "omit" });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const total = Number(res.headers.get("content-length")) || approx || 0;
  if (!res.body || !onProgress) return res.text();

  const reader = res.body.getReader();
  const chunks = [];
  let received = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    received += value.length;
    onProgress(total ? Math.min(0.99, received / total) : 0);
  }
  onProgress(1);
  const buf = new Uint8Array(received);
  let at = 0;
  for (const c of chunks) { buf.set(c, at); at += c.length; }
  return new TextDecoder("utf-8").decode(buf);
}

/** テンプレート `#/case/{detail}` に値を埋める。 */
export function fillTemplate(tpl, vars) {
  return String(tpl).replace(/\{(\w+)\}/g, (m, k) =>
    k in vars ? encodeURIComponent(String(vars[k])) : m);
}

export function resolveUrl(base, maybeRelative) {
  try {
    return new URL(maybeRelative, base).href;
  } catch {
    return maybeRelative;
  }
}
