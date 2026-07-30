// 外部サービスのキーを調査 API 側へ預ける（/api/credentials）。
//
// これまでキーはこの端末の中だけに置き、呼び出しのたびに専用ヘッダ
// （X-VirusTotal-Key など）で送っていた。API 側が AES-256-GCM で
// ユーザーごとに暗号化保存できるようになったので、預ける道も用意する。
//
// **預けたキーを使うときは、ヘッダを送らない。** API の仕様で
// 「専用ヘッダを明示したらその値を 1 回だけ優先する」ため、送ると
// 預けた側が使われない。値が空ならヘッダごと落ちる作りになっているので、
// 端末側の値を消しておけばそのまま預けたキーが使われる。
//
// Shodan はここに出てこない。ブラウザから直接 Shodan へ投げていて
// 調査 API を通らないので、預ける先が無い（端末の中だけに留まる）。

import { DEFAULT_BASE } from "./api-active-research.js";
import { authHeaders, isLoggedIn, recoverFromUnauthorized } from "./auth-active-research.js";
import { getModuleSettings } from "./modules.js";

/**
 * API の provider 名 ↔ ポータルの設定項目。
 *
 * Cloudflare だけ 1 対 1 にならない。API 側の provider は
 * `cloudflare_browser` の 1 つで、預けられるのは**トークンだけ**。
 * アカウント ID は秘密ではなく識別子なので、端末側に置いたまま毎回送る。
 */
export const PROVIDERS = [
  { id: "virustotal", field: "virustotal", label: "VirusTotal", needs: "vt" },
  { id: "abuseipdb", field: "abuseipdb", label: "AbuseIPDB", needs: "abuseipdb" },
  { id: "urlscan", field: "urlscan", label: "urlscan.io", needs: "urlscan" },
  { id: "censys", field: "censys", label: "Censys", needs: "censys" },
  { id: "github", field: "github", label: "GitHub", needs: "github" },
  {
    id: "cloudflare_browser", field: "cloudflareToken", label: "Cloudflare API トークン",
    needs: "cloudflare",
    note: "アカウント ID は預けられません（この端末に残ります）",
  },
];

const BY_FIELD = new Map(PROVIDERS.map((p) => [p.field, p]));

/** provider → { configured, hint, updatedAt }。ログイン中だけ中身が入る。 */
let stored = new Map();
let loaded = false;
const listeners = new Set();

export function onCredentialsChange(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

function notify() {
  for (const fn of listeners) {
    try { fn(); } catch (err) { console.warn("[research_bench] 資格情報の通知でエラー", err); }
  }
}

function base() {
  return (getModuleSettings().activeResearchBase || DEFAULT_BASE).replace(/\/+$/, "");
}

async function req(method, path, body, { retried = false } = {}) {
  const init = { method, headers: { ...(await authHeaders()) }, credentials: "omit" };
  if (body !== undefined) {
    init.headers["content-type"] = "application/json";
    init.body = JSON.stringify(body);
  }

  let res;
  try {
    res = await fetch(new URL(path, base() + "/"), init);
  } catch {
    throw new Error("調査 API に繋がりませんでした");
  }

  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* 204 は本文が無い */ }

  if (res.status === 401 && !retried && res.headers.get("www-authenticate")) {
    if (await recoverFromUnauthorized(json)) return req(method, path, body, { retried: true });
  }
  if (!res.ok) {
    if (res.status === 401) throw new Error("ログインが必要です");
    throw new Error(json?.error_description || json?.error || `HTTP ${res.status}`);
  }
  return json;
}

/** 預けている状態。秘密値は返ってこない（末尾 4 文字の目印だけ）。 */
export async function loadCredentials({ force = false } = {}) {
  if (!isLoggedIn()) {
    if (stored.size) { stored = new Map(); notify(); }
    loaded = true;
    return stored;
  }
  if (loaded && !force) return stored;
  try {
    const json = await req("GET", "/api/credentials");
    stored = new Map((json?.providers || [])
      .filter((p) => p.configured)
      .map((p) => [p.provider, { hint: p.hint || "", updatedAt: p.updatedAt || null, header: p.header || null }]));
  } catch {
    // 取れなくても端末側のキーで動く。状態が分からないだけ
    stored = new Map();
  }
  loaded = true;
  notify();
  return stored;
}

/** ログインし直したら取り直す。 */
export function resetCredentials() {
  loaded = false;
  stored = new Map();
  notify();
}

export function credentialState(providerId) {
  return stored.get(providerId) || null;
}

/** 設定項目の名前から見る。UI と investigate.js はこちらを使う。 */
export function isStoredByField(field) {
  const p = BY_FIELD.get(field);
  return !!(p && stored.has(p.id));
}

export async function saveCredential(providerId, credential) {
  const json = await req("PUT", "/api/credentials", { provider: providerId, credential });
  const c = json?.credential || {};
  stored.set(providerId, { hint: c.hint || "", updatedAt: c.updatedAt || Date.now(), header: null });
  notify();
  return stored.get(providerId);
}

export async function deleteCredential(providerId) {
  await req("DELETE", `/api/credentials?provider=${encodeURIComponent(providerId)}`);
  stored.delete(providerId);
  notify();
}
