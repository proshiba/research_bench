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
// 後者 2 つは、利用者が自分の端末で動かす中継（tools/osint-relay.mjs）を
// 設定したときだけ使う。中継はキーを保持せず、素通しするだけ。

const STORE_KEY = "rb-osint-v1";

const settings = {
  keys: { virustotal: "", shodan: "", abusech: "" },
  relay: { url: "", token: "" },
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
      Object.assign(settings.relay, saved.relay || {});
      settings.storage = kind;
      return settings;
    } catch {
      // 壊れていたら無視して既定のまま進む
    }
  }
  return settings;
}

export function getSettings() {
  return { keys: { ...settings.keys }, relay: { ...settings.relay }, storage: settings.storage };
}

export function saveSettings(next) {
  Object.assign(settings.keys, next.keys || {});
  Object.assign(settings.relay, next.relay || {});
  const kind = next.storage || "memory";
  // 置き場所を変えたときは前の置き場所から必ず消す
  for (const k of ["session", "local"]) backing(k)?.removeItem(STORE_KEY);
  settings.storage = kind;
  if (kind !== "memory") {
    backing(kind)?.setItem(STORE_KEY, JSON.stringify({ keys: settings.keys, relay: settings.relay }));
  }
  return getSettings();
}

export function clearSettings() {
  settings.keys = { virustotal: "", shodan: "", abusech: "" };
  settings.relay = { url: "", token: "" };
  settings.storage = "memory";
  for (const k of ["session", "local"]) backing(k)?.removeItem(STORE_KEY);
}

/* ---------------- 通信 ---------------- */

/** 中継が設定されているか。VirusTotal と abuse.ch はこれが無いと呼べない。 */
export function relayReady() {
  return !!settings.relay.url;
}

async function callDirect({ url, method = "GET", headers = {}, body = null }) {
  const res = await fetch(url, { method, headers, body, mode: "cors", credentials: "omit" });
  const text = await res.text();
  return { status: res.status, text };
}

async function callViaRelay({ url, method = "GET", headers = {}, body = null }) {
  const res = await fetch(settings.relay.url.replace(/\/+$/, "") + "/relay", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(settings.relay.token ? { "x-relay-token": settings.relay.token } : {}),
    },
    body: JSON.stringify({ url, method, headers, body }),
  });
  const payload = await res.json().catch(() => null);
  if (!res.ok) {
    throw new Error(payload?.error || `中継がエラーを返しました (HTTP ${res.status})`);
  }
  return { status: payload.status, text: payload.body };
}

/* ---------------- プロバイダ ---------------- */

const IP = new Set(["ioc.ipv4", "ioc.ipv6"]);
const HASH = new Set(["ioc.md5", "ioc.sha1", "ioc.sha256", "case"]);

export const PROVIDERS = {
  shodan: {
    label: "Shodan",
    keyField: "shodan",
    direct: true,                   // CORS が開いているので中継なしで呼べる
    web: (v) => `https://www.shodan.io/host/${encodeURIComponent(v)}`,
    supports: (type) => IP.has(type),
    async lookup(value) {
      const key = settings.keys.shodan;
      if (!key) throw new Error("Shodan の API キーが設定されていません");
      const { status, text } = await callDirect({
        url: `https://api.shodan.io/shodan/host/${encodeURIComponent(value)}?key=${encodeURIComponent(key)}`,
      });
      if (status === 401) throw new Error("Shodan: API キーが受け付けられませんでした");
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

  virustotal: {
    label: "VirusTotal",
    keyField: "virustotal",
    direct: false,                  // CORS ヘッダを返さないため中継が必要
    web: (v, type) => {
      const kind = IP.has(type) ? "ip-address" : type === "ioc.domain" ? "domain"
        : type === "ioc.url" ? "url" : "file";
      return `https://www.virustotal.com/gui/${kind}/${encodeURIComponent(v)}`;
    },
    supports: (type) => IP.has(type) || HASH.has(type) || type === "ioc.domain" || type === "ioc.url",
    async lookup(value, type) {
      const key = settings.keys.virustotal;
      if (!key) throw new Error("VirusTotal の API キーが設定されていません");
      if (!relayReady()) throw new Error("VirusTotal は CORS を許可していないため、中継の設定が必要です");
      const path = IP.has(type) ? `ip_addresses/${encodeURIComponent(value)}`
        : type === "ioc.domain" ? `domains/${encodeURIComponent(value)}`
        : type === "ioc.url" ? `urls/${btoa(value).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_")}`
        : `files/${encodeURIComponent(value)}`;
      const { status, text } = await callViaRelay({
        url: `https://www.virustotal.com/api/v3/${path}`,
        headers: { "x-apikey": key },
      });
      if (status === 401) throw new Error("VirusTotal: API キーが受け付けられませんでした");
      if (status === 404) return { summary: [["結果", "VirusTotal に情報がありません"]], related: [] };
      if (status !== 200) throw new Error(`VirusTotal: HTTP ${status}`);
      const a = JSON.parse(text)?.data?.attributes || {};
      const st = a.last_analysis_stats || {};
      const summary = [
        ["検知", st.malicious != null ? `${st.malicious} / ${(st.malicious || 0) + (st.harmless || 0) + (st.suspicious || 0) + (st.undetected || 0)}` : null],
        ["疑わしい", st.suspicious], ["評判", a.reputation],
        ["国", a.country], ["AS所有者", a.as_owner],
        ["種別", a.type_description], ["表示名", a.meaningful_name],
        ["初回登録", a.first_submission_date ? new Date(a.first_submission_date * 1000).toISOString().slice(0, 10) : null],
      ].filter(([, v]) => v != null && v !== "");
      const related = [];
      for (const r of a.last_dns_records || []) {
        if (r.type === "A" && r.value) related.push({ type: "ioc.ipv4", value: r.value, rel: "VT: Aレコード" });
      }
      // タグは自由記述で、マルウェア名とは限らない（分類語やアクター名も混ざる）。
      // 索引に同名があればそちらの種別が優先されるので、ここでは other に留める。
      for (const name of a.tags || []) related.push({ type: "other", value: name, rel: "VT: タグ" });
      if (a.popular_threat_classification?.suggested_threat_label) {
        related.push({
          type: "malware",
          value: a.popular_threat_classification.suggested_threat_label,
          rel: "VT: 推定ファミリ",
        });
      }
      return { summary, related };
    },
  },

  abusech: {
    label: "ThreatFox (abuse.ch)",
    keyField: "abusech",
    direct: false,                  // CORS ヘッダを返さないため中継が必要
    web: (v) => `https://threatfox.abuse.ch/browse.php?search=ioc%3A${encodeURIComponent(v)}`,
    supports: (type) => IP.has(type) || HASH.has(type)
      || type === "ioc.domain" || type === "ioc.url" || type === "ioc.endpoint",
    async lookup(value) {
      const key = settings.keys.abusech;
      if (!key) throw new Error("abuse.ch の Auth-Key が設定されていません");
      if (!relayReady()) throw new Error("abuse.ch は CORS を許可していないため、中継の設定が必要です");
      const { status, text } = await callViaRelay({
        url: "https://threatfox-api.abuse.ch/api/v1/",
        method: "POST",
        headers: { "Auth-Key": key, "Content-Type": "application/json" },
        body: JSON.stringify({ query: "search_ioc", search_term: value }),
      });
      // キーが違うときは 403 + query_status で返ってくるので、本文を先に見る
      let d = null;
      try { d = JSON.parse(text); } catch { /* 本文が JSON でないこともある */ }
      if (d?.query_status === "unknown_auth_key" || d?.query_status === "illegal_auth_key") {
        throw new Error("ThreatFox: Auth-Key が受け付けられませんでした");
      }
      if (status !== 200 || !d) throw new Error(`ThreatFox: HTTP ${status}`);
      if (d.query_status === "no_result" || !Array.isArray(d.data)) {
        return { summary: [["結果", "ThreatFox に該当なし"]], related: [] };
      }
      const first = d.data[0] || {};
      const summary = [
        ["脅威種別", first.threat_type_desc || first.threat_type],
        ["確度", first.confidence_level != null ? `${first.confidence_level}%` : null],
        ["マルウェア", first.malware_printable],
        ["初回登録", first.first_seen],
        ["報告者", first.reporter],
        ["件数", d.data.length],
      ].filter(([, v]) => v != null && v !== "");
      const related = [];
      const seen = new Set();
      for (const row of d.data) {
        const name = row.malware_printable || row.malware;
        if (name && !seen.has(name)) { seen.add(name); related.push({ type: "malware", value: name, rel: "ThreatFox: 関連マルウェア" }); }
        for (const tag of row.tags || []) {
          // タグはマルウェア名とは限らない（VT と同じ理由で other に留める）
          if (tag && !seen.has(tag)) { seen.add(tag); related.push({ type: "other", value: tag, rel: "ThreatFox: タグ" }); }
        }
      }
      return { summary, related };
    },
  },
};

/** その種別に使えるプロバイダを、実際に呼べるかどうかの判定つきで返す。 */
export function providersFor(type) {
  return Object.entries(PROVIDERS)
    .filter(([, p]) => p.supports(type))
    .map(([id, p]) => ({
      id,
      label: p.label,
      hasKey: !!settings.keys[p.keyField],
      callable: !!settings.keys[p.keyField] && (p.direct || relayReady()),
      needsRelay: !p.direct && !relayReady(),
      web: p.web,
    }));
}

export async function lookup(providerId, value, type) {
  const p = PROVIDERS[providerId];
  if (!p) throw new Error(`未知のプロバイダ: ${providerId}`);
  return p.lookup(value, type);
}

/** 中継の疎通確認。 */
export async function pingRelay() {
  if (!settings.relay.url) throw new Error("中継の URL が設定されていません");
  const res = await fetch(settings.relay.url.replace(/\/+$/, "") + "/health", {
    headers: settings.relay.token ? { "x-relay-token": settings.relay.token } : {},
  });
  // 401 は「応答が無い」ではなく「トークンが合っていない」なので分けて伝える
  if (res.status === 401) throw new Error("中継のトークンが違います（起動時に表示されたものを入れてください）");
  if (!res.ok) throw new Error(`中継が応答しません (HTTP ${res.status})`);
  return res.json().catch(() => ({}));
}
