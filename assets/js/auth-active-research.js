// Active Research API のログイン（OAuth 2.0 認可コードフロー + PKCE）。
//
// ポータルは GitHub Pages の静的配信でサーバーを持たないため、クライアント
// シークレットを隠せない。そこで RFC 7636 の PKCE で「同じブラウザが始めた
// 手続きか」を証明する。詳しい背景は docs/auth-pkce.md にある。
//
// Cookie は使わない。ポータル（github.io）と API（chatgpt.site）は別サイトなので
// セッション Cookie はサードパーティ Cookie になり、Safari と Firefox では届かない。
//
// 流れは 1 箇所だけ画面遷移する。
//   ① begin()   … verifier / state を作って sessionStorage に置き、authorize へ「移動」する
//   ② （API 側で GitHub ログイン。戻り先はこのポータル）
//   ③ finish()  … 起動時に URL の code を拾って state を照合し、トークンに交換する
//
// トークンの置き場所は osint.js の 3 段階（メモリ / このタブ / このブラウザ）に
// 合わせるが、既定は「このタブ」にする。メモリだけだとリロードのたびに
// ログインし直しになり、ログインとしては使いものにならないため。

import { DEFAULT_BASE } from "./api-active-research.js";

const STORE_KEY = "rb-ar-auth-v1";
const PENDING_KEY = "rb-ar-auth-pending";   // 手続き中の verifier / state（必ず sessionStorage）
const CLIENT_ID = "research_bench";
const SCOPE = "tools tools:active";

/** 期限切れ扱いにする余裕。時計のずれと往復ぶんを見て早めに切る。 */
const EXPIRY_SKEW_MS = 60_000;

const listeners = new Set();

/** いまのセッション。token は平文でここに載るので、外へは渡さない。 */
let session = null;      // { access_token, refresh_token, expires_at, scope, user }
let storage = "session"; // memory | session | local
let lastError = null;

export function onAuthChange(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

function notify() {
  for (const fn of listeners) {
    try { fn(); } catch (err) { console.warn("[research_bench] 認証の通知でエラー", err); }
  }
}

/* ---------------- 保存 ---------------- */

function backing(kind) {
  try {
    if (kind === "session") return sessionStorage;
    if (kind === "local") return localStorage;
  } catch {
    // プライベートモードなどで使えないことがある
  }
  return null;
}

function persist() {
  for (const k of ["session", "local"]) backing(k)?.removeItem(STORE_KEY);
  if (storage === "memory" || !session) return;
  try {
    backing(storage)?.setItem(STORE_KEY, JSON.stringify({ session, storage }));
  } catch {
    // 容量やモードで書けないことがある。メモリ上では使えているので続行する
  }
}

/** 起動時に呼ぶ。保存済みのセッションを戻す。 */
export function loadAuth() {
  for (const kind of ["session", "local"]) {
    const raw = backing(kind)?.getItem(STORE_KEY);
    if (!raw) continue;
    try {
      const saved = JSON.parse(raw);
      if (saved?.session?.access_token) {
        session = saved.session;
        storage = kind;
        return;
      }
    } catch {
      backing(kind)?.removeItem(STORE_KEY);
    }
  }
}

export function setAuthStorage(kind) {
  storage = ["memory", "session", "local"].includes(kind) ? kind : "session";
  persist();
  notify();
}

export function authStorage() {
  return storage;
}

/* ---------------- 状態 ---------------- */

export function isLoggedIn() {
  return !!session?.access_token;
}

/** アクセストークンの期限が切れている（か、切れかけている）か。 */
function expired() {
  if (!session?.expires_at) return false;   // 期限を貰っていなければ切れないものとして扱う
  return Date.now() > session.expires_at - EXPIRY_SKEW_MS;
}

export function authState() {
  if (!session?.access_token) return { loggedIn: false, error: lastError };
  return {
    loggedIn: true,
    user: session.user || null,
    scope: session.scope || null,
    expiresAt: session.expires_at || null,
    expired: expired(),
    canRefresh: !!session.refresh_token,
    error: lastError,
  };
}

export function logout() {
  const base = session?._base;
  const token = session?.refresh_token;
  session = null;
  lastError = null;
  persist();
  notify();
  // 失効はついでに頼むだけ。失敗しても手元から消えていれば目的は足りている
  if (base && token) {
    const body = new URLSearchParams({ token, token_type_hint: "refresh_token" });
    fetch(new URL("api/oauth/revoke", base.replace(/\/+$/, "") + "/"), {
      method: "POST", credentials: "omit",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body,
    }).catch(() => { /* 失効は best effort */ });
  }
}

/* ---------------- PKCE の材料 ---------------- */

const b64url = (bytes) => btoa(String.fromCharCode(...bytes))
  .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

function randomString(bytes = 32) {
  return b64url(crypto.getRandomValues(new Uint8Array(bytes)));
}

async function challengeOf(verifier) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return b64url(new Uint8Array(digest));
}

/**
 * 戻り先。ハッシュとクエリは落とす。
 *
 * API 側は `redirect_uri` を**完全一致**で照合する（登録は `…/research_bench/` の形）。
 * `…/index.html` を明示して開いていると pathname にそれが入り、実測で 400 になる。
 * 末尾スラッシュのディレクトリ形に正規化してから渡す。
 */
export function redirectUri() {
  let path = location.pathname.replace(/\/index\.html?$/i, "/");
  if (!path.endsWith("/")) path += "/";
  return location.origin + path;
}

/* ---------------- ① 開始 ---------------- */

/**
 * ログインを始める。**この関数は画面を移動させるので、呼んだら戻ってこない。**
 * fetch では authorize のログイン画面を出せないため、本当にページを移す。
 */
export async function beginLogin(base = DEFAULT_BASE) {
  const verifier = randomString(32);           // 43 文字の BASE64URL
  const state = randomString(16);
  const uri = redirectUri();

  // 手続き中の値は必ず sessionStorage（このタブだけ・戻ってきたら消す）
  sessionStorage.setItem(PENDING_KEY, JSON.stringify({
    verifier, state, base, redirect_uri: uri, at: Date.now(),
  }));

  const url = new URL("api/oauth/authorize", base.replace(/\/+$/, "") + "/");
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", CLIENT_ID);
  url.searchParams.set("redirect_uri", uri);
  url.searchParams.set("state", state);
  url.searchParams.set("code_challenge", await challengeOf(verifier));
  url.searchParams.set("code_challenge_method", "S256");
  url.searchParams.set("scope", SCOPE);
  location.assign(url.href);
}

/* ---------------- ③ 帰還 ---------------- */

/**
 * 起動時に 1 回呼ぶ。URL に code か error が載っていれば処理する。
 * 何も載っていなければ false を返して何もしない。
 *
 * URL からは必ず code を消す（履歴とブックマークに残さないため）。
 */
export async function finishLogin() {
  const q = new URLSearchParams(location.search);
  const code = q.get("code");
  const err = q.get("error");
  const state = q.get("state");
  if (!code && !err) return false;

  let pending = null;
  try { pending = JSON.parse(sessionStorage.getItem(PENDING_KEY) || "null"); } catch { /* 壊れていた */ }
  sessionStorage.removeItem(PENDING_KEY);
  stripQuery();

  if (err) {
    lastError = err === "access_denied"
      ? "ログインが許可されませんでした（このアカウントは利用を許可されていない可能性があります）"
      : `${err}${q.get("error_description") ? `: ${q.get("error_description")}` : ""}`;
    notify();
    return true;
  }

  // state の照合。合わなければ自分が始めた手続きではないので捨てる
  if (!pending || !pending.state || pending.state !== state) {
    lastError = "ログインの照合に失敗しました（state が一致しません）。もう一度お試しください";
    notify();
    return true;
  }

  try {
    const token = await exchange(pending.base, {
      grant_type: "authorization_code",
      code,
      redirect_uri: pending.redirect_uri,
      client_id: CLIENT_ID,
      code_verifier: pending.verifier,
    });
    adopt(token, pending.base);
    fetchUser().finally(notify);
  } catch (e) {
    lastError = e.message;
  }
  notify();
  return true;
}

/** URL から code / state / error を消す。他のクエリは残す。 */
function stripQuery() {
  const q = new URLSearchParams(location.search);
  let touched = false;
  for (const k of ["code", "state", "error", "error_description", "error_uri"]) {
    if (q.has(k)) { q.delete(k); touched = true; }
  }
  if (!touched) return;
  const s = q.toString();
  history.replaceState(null, "", location.pathname + (s ? `?${s}` : "") + location.hash);
}

/* ---------------- トークンのやりとり ---------------- */

async function exchange(base, params) {
  const url = new URL("api/oauth/token", base.replace(/\/+$/, "") + "/");
  let res;
  try {
    res = await fetch(url, {
      method: "POST", credentials: "omit",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(params),
    });
  } catch {
    throw new Error(`${url.host} に繋がりませんでした（CORS の可能性もあります）`);
  }
  let json = null;
  try { json = JSON.parse(await res.text()); } catch { /* JSON でないこともある */ }

  if (!res.ok || !json?.access_token) {
    // RFC 6749 のエラー形。文言はそのまま出す（利用者が直せる情報が入っている）
    const code = json?.error || `HTTP ${res.status}`;
    const desc = json?.error_description;
    throw new Error(desc ? `${code}: ${desc}` : String(code));
  }
  return json;
}

function adopt(token, base) {
  session = {
    access_token: token.access_token,
    refresh_token: token.refresh_token || null,
    scope: token.scope || null,
    expires_at: token.expires_in ? Date.now() + Number(token.expires_in) * 1000 : null,
    user: session?.user || null,
    _base: base,
  };
  lastError = null;
  persist();
}

/** 誰としてログインしているか。取れなくてもログイン自体は成立している。 */
async function fetchUser() {
  if (!session) return;
  try {
    const url = new URL("api/oauth/userinfo", session._base.replace(/\/+$/, "") + "/");
    const res = await fetch(url, {
      credentials: "omit",
      headers: { authorization: `Bearer ${session.access_token}` },
    });
    if (!res.ok) return;
    const json = await res.json();
    session.user = json.user || json || null;
    if (json.scope) session.scope = json.scope;
    persist();
  } catch {
    // 表示上の飾りなので、取れなければ黙って諦める
  }
}

let refreshing = null;

/**
 * アクセストークンを取り直す。同時に何度も走らせない。
 * 失敗したらセッションを捨てる（回転式なのでリフレッシュトークンも死んでいる）。
 */
export function refresh() {
  if (!session?.refresh_token) return Promise.resolve(false);
  if (refreshing) return refreshing;

  refreshing = (async () => {
    try {
      const token = await exchange(session._base, {
        grant_type: "refresh_token",
        refresh_token: session.refresh_token,
        client_id: CLIENT_ID,
      });
      adopt(token, session._base);
      notify();
      return true;
    } catch (e) {
      lastError = `セッションが切れました（${e.message}）。もう一度ログインしてください`;
      session = null;
      persist();
      notify();
      return false;
    } finally {
      refreshing = null;
    }
  })();
  return refreshing;
}

/**
 * API を叩くときに足すヘッダ。ログインしていなければ空。
 * 期限が切れていれば先に取り直す（呼び出し側は await するだけでよい）。
 */
export async function authHeaders() {
  if (!session?.access_token) return {};
  if (expired() && session.refresh_token) {
    if (!await refresh()) return {};
  }
  return session?.access_token ? { authorization: `Bearer ${session.access_token}` } : {};
}

/** 401 invalid_token を受けたときに 1 回だけ試す立て直し。 */
export async function recoverFromUnauthorized(body) {
  const code = body?.error;
  if (code && code !== "invalid_token" && code !== "authentication_required") return false;
  if (!session?.refresh_token) {
    if (session) {
      lastError = "セッションが無効になりました。もう一度ログインしてください";
      session = null;
      persist();
      notify();
    }
    return false;
  }
  return refresh();
}
