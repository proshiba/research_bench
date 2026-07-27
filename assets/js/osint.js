// OSINT サービス連携。API キーはブラウザの外に出さない。
//
// キーの持ち方は 3 段階から選べる（既定は「メモリだけ」）。
//   memory  … このモジュールのクロージャに置くだけ。リロードで消える。最も安全。
//   session … sessionStorage。タブを閉じると消える。
//   local   … localStorage。次回も残る。
// session / local は同一オリジンの別文書からも読めるため、ポータルが iframe で
// 表示している各アプリの JS からも到達し得る。既定を memory にしているのはこのため。
//
// CORS の実測（2026-07）:
//   Shodan            … Access-Control-Allow-Origin: * → ブラウザから直接呼べる
//   VirusTotal        … CORS ヘッダなし → ブラウザから直接は呼べない
//   abuse.ch/ThreatFox… CORS ヘッダなし → 同上
// API で取りに行くのは、ブラウザだけで完結する Shodan だけにしている。
// 残る 2 つは、キーの要らないリンク（linkOnly）として該当ページを開くだけ。
// 中継サーバーを置けば呼べるが、キーがブラウザの外に出るので採っていない。

const STORE_KEY = "rb-osint-v1";

// shodan はブラウザから直接 Shodan へ。virustotal と github は Active Research API に
// Authorization: Bearer で渡すので、値が端末の外（あの API サーバー）に出る。
// この違いは設定画面でも明示する。
const settings = {
  keys: { shodan: "", virustotal: "", github: "" },
  storage: "memory",              // memory | session | local
};

/* ---------------- 設定の保存 ---------------- */

function backing(kind) {
  try {
    if (kind === "session") return sessionStorage;
    if (kind === "local") return localStorage;
  } catch {
    // プライベートモードなどで使えないことがある
  }
  return null;
}

export function loadSettings() {
  for (const kind of ["session", "local"]) {
    const store = backing(kind);
    if (!store) continue;
    try {
      const raw = store.getItem(STORE_KEY);
      if (!raw) continue;
      const saved = JSON.parse(raw);
      Object.assign(settings.keys, saved.keys || {});
      settings.storage = kind;
      return settings;
    } catch {
      // 壊れていたら無視して既定のまま進む
    }
  }
  return settings;
}

export function getSettings() {
  return { keys: { ...settings.keys }, storage: settings.storage };
}

export function saveSettings(next) {
  Object.assign(settings.keys, next.keys || {});
  const kind = next.storage || "memory";
  // 置き場所を変えたときは前の置き場所から必ず消す
  for (const k of ["session", "local"]) backing(k)?.removeItem(STORE_KEY);
  settings.storage = kind;
  if (kind !== "memory") {
    backing(kind)?.setItem(STORE_KEY, JSON.stringify({ keys: settings.keys }));
  }
  return getSettings();
}

export function clearSettings() {
  settings.keys = { shodan: "", virustotal: "", github: "" };
  settings.storage = "memory";
  for (const k of ["session", "local"]) backing(k)?.removeItem(STORE_KEY);
}

/* ---------------- 通信 ---------------- */

async function callDirect({ url, method = "GET", headers = {}, body = null }) {
  const res = await fetch(url, { method, headers, body, mode: "cors", credentials: "omit" });
  const text = await res.text();
  return { status: res.status, text };
}

/* ---------------- プロバイダ ---------------- */

const IP = new Set(["ioc.ipv4", "ioc.ipv6"]);
const HASH = new Set(["ioc.md5", "ioc.sha1", "ioc.sha256", "ioc.sha512", "case"]);

export const PROVIDERS = {
  shodan: {
    label: "Shodan",
    keyField: "shodan",
    web: (v) => `https://www.shodan.io/host/${encodeURIComponent(v)}`,
    supports: (type) => IP.has(type),
    async lookup(value) {
      const key = settings.keys.shodan;
      if (!key) throw new Error("Shodan の API キーが設定されていません");
      const { status, text } = await callDirect({
        url: `https://api.shodan.io/shodan/host/${encodeURIComponent(value)}?key=${encodeURIComponent(key)}`,
      });
      if (status === 401) throw new Error("Shodan: API キーが受け付けられませんでした");
      if (status === 403) throw new Error("Shodan: この API キーでは許可されていません");
      if (status === 404) return { summary: [["結果", "Shodan に情報がありません"]], related: [] };
      if (status !== 200) throw new Error(`Shodan: HTTP ${status}`);
      const d = JSON.parse(text);
      const summary = [
        ["組織", d.org], ["ISP", d.isp], ["国", d.country_name],
        ["OS", d.os], ["ASN", d.asn], ["最終更新", d.last_update],
        ["ポート", (d.ports || []).join(", ")],
      ].filter(([, v]) => v);
      const related = [
        ...(d.hostnames || []).map((h) => ({ type: "ioc.domain", value: h, rel: "Shodan: 逆引き" })),
        ...(d.vulns || []).map((c) => ({ type: "cve", value: String(c).toUpperCase(), rel: "Shodan: 報告された脆弱性" })),
      ];
      return { summary, related };
    },
  },

  // 以下 2 つは CORS ヘッダを返さないため、ブラウザからは直接 API を呼べない。
  // ワークベンチの右クリック調査では Active Research API 経由で引ける（トークンは
  // その API サーバーを通る）。ここに出るのはキー不要のリンクだけ。
  virustotal: {
    label: "VirusTotal",
    linkOnly: true,
    web: (v, type) => {
      const kind = IP.has(type) ? "ip-address" : type === "ioc.domain" ? "domain"
        : type === "ioc.url" ? "url" : "file";
      return `https://www.virustotal.com/gui/${kind}/${encodeURIComponent(v)}`;
    },
    supports: (type) => IP.has(type) || HASH.has(type) || type === "ioc.domain" || type === "ioc.url",
  },

  abusech: {
    label: "ThreatFox (abuse.ch)",
    linkOnly: true,
    web: (v) => `https://threatfox.abuse.ch/browse.php?search=ioc%3A${encodeURIComponent(v)}`,
    supports: (type) => IP.has(type) || HASH.has(type)
      || type === "ioc.domain" || type === "ioc.url" || type === "ioc.endpoint",
  },
};

/** その種別に使えるプロバイダを、実際に呼べるかどうかの判定つきで返す。 */
export function providersFor(type) {
  return Object.entries(PROVIDERS)
    .filter(([, p]) => p.supports(type))
    .map(([id, p]) => ({
      id,
      label: p.label,
      linkOnly: !!p.linkOnly,
      hasKey: !p.linkOnly && !!settings.keys[p.keyField],
      callable: !p.linkOnly && !!settings.keys[p.keyField],
      web: p.web,
    }));
}

export async function lookup(providerId, value, type) {
  const p = PROVIDERS[providerId];
  if (!p) throw new Error(`未知のプロバイダ: ${providerId}`);
  if (!p.lookup) throw new Error(`${p.label} は API 連携に対応していません`);
  return p.lookup(value, type);
}
