// 調査 API の STIX ストレージ（/api/stix/objects）との連携。
//
// API が保存するのは **STIX JSON だけ**で、タイトル・説明・画面写真を入れる欄が無い。
// なので、それらは束（bundle）の中に STIX の `report` オブジェクトとして載せる。
// report は 2.1 の正規の SDO で name / description / published を持つため、
// **他の STIX ツールから読んでも題と説明がそのまま見える**。
// ポータル固有のもの（画面写真とグラフの配置）だけ `x_rb_*` の拡張属性に置く。
//
// 復元の忠実さのために、`x_rb_graph` にはワークベンチが localStorage へ
// 書いているのと同じ形の写しを入れる。復元は既存の復元経路をそのまま通せる。
//
// 認証: 読み取りのうち public だけが匿名で、me の読み取りと書き込みは常に必須。
// これは API の認証強制フラグとは無関係（実測で確認済み）。

import { DEFAULT_BASE } from "./api-active-research.js";
import { authHeaders, isLoggedIn, recoverFromUnauthorized } from "./auth-active-research.js";
import { getModuleSettings } from "./modules.js";

/** STIX 本体の上限は 10 MiB。手前で止めて、API に弾かれる前に理由を出す。 */
export const MAX_BYTES = 10 * 1024 * 1024;

/** 長い属性（取り込んだ HTML など）を保存時に切る長さ。上限に当たらないための保険。 */
const ATTR_CAP = 4000;

function base() {
  return (getModuleSettings().activeResearchBase || DEFAULT_BASE).replace(/\/+$/, "");
}

function endpoint(params = {}) {
  const url = new URL("/api/stix/objects", base() + "/");
  for (const [k, v] of Object.entries(params)) {
    if (v !== "" && v != null) url.searchParams.set(k, v);
  }
  return url;
}

/**
 * API を叩く。401 + WWW-Authenticate（＝この API が出した 401）のときだけ
 * 1 回トークンを取り直して同じ要求をやり直す。外部サービスの 401 とは混ざらない。
 */
async function req(method, url, body, { retried = false } = {}) {
  const init = { method, headers: { ...(await authHeaders()) }, credentials: "omit" };
  if (body !== undefined) {
    init.headers["content-type"] = "application/json";
    init.body = JSON.stringify(body);
  }

  let res;
  try {
    res = await fetch(url, init);
  } catch {
    throw new Error(`調査 API に繋がりませんでした（${new URL(url).host}）`);
  }

  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* 204 など本文が無いことがある */ }

  if (res.status === 401 && !retried && res.headers.get("www-authenticate")) {
    if (await recoverFromUnauthorized(json)) return req(method, url, body, { retried: true });
  }

  if (!res.ok) {
    if (res.status === 401) throw new Error("ログインが必要です（保存・更新・削除と me の一覧は認証必須）");
    if (res.status === 404) throw new Error("見つかりませんでした（削除済みか、他の人のものです）");
    if (res.status === 413) throw new Error("STIX が大きすぎます（上限 10 MiB）");
    if (res.status === 429) throw new Error("呼び出しが早すぎます。少し待って再試行してください");
    throw new Error(json?.error_description || json?.error || `HTTP ${res.status}`);
  }
  return json;
}

/* ---------------- 束の組み立てと読み出し ---------------- */

/** RFC 4122 v4。crypto.randomUUID があればそれを使う。 */
function uuid() {
  if (crypto.randomUUID) return crypto.randomUUID();
  const b = crypto.getRandomValues(new Uint8Array(16));
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

/** 保存に載せない・切り詰める。base64 の画像や取り込んだ HTML で 10 MiB を食わないため。 */
function trimSnapshot(snapshot) {
  if (!snapshot) return null;
  const extras = (snapshot.extras || []).map((e) => {
    const attrs = {};
    for (const [k, v] of Object.entries(e.attrs || {})) {
      if (k.startsWith("_")) continue;                      // 画面写真などの内部属性
      const s = String(v ?? "");
      attrs[k] = s.length > ATTR_CAP ? s.slice(0, ATTR_CAP) + "…（保存時に省略）" : s;
    }
    return { ...e, attrs };
  });
  return { ...snapshot, extras };
}

/**
 * ワークベンチの状態を、保存できる 1 つの STIX bundle にまとめる。
 *
 * @param bundle   exchange.js の toStix() が返す束
 * @param meta     { title, description, screenshot, snapshot }
 */
export function wrapBundle(bundle, { title, description, screenshot, snapshot } = {}) {
  const objects = (bundle?.objects || []).filter((o) => o && o.type !== "report");
  const now = new Date().toISOString().replace(/\.\d+Z$/, ".000Z");

  const report = {
    type: "report",
    spec_version: "2.1",
    id: `report--${uuid()}`,
    created: now,
    modified: now,
    published: now,
    name: (title || "").trim() || "無題のグラフ",
    ...(description?.trim() ? { description: description.trim() } : {}),
    report_types: ["threat-report"],
    // STIX 2.1 の report は object_refs が 1 件以上必須。空グラフは保存させない
    object_refs: objects.map((o) => o.id),
    x_rb_app: "research_bench",
    ...(screenshot ? { x_rb_screenshot: screenshot } : {}),
    ...(snapshot ? { x_rb_graph: trimSnapshot(snapshot) } : {}),
  };

  return { type: "bundle", id: `bundle--${uuid()}`, objects: [report, ...objects] };
}

/** 保存した束から、ポータルが使うメタ情報を取り出す。 */
export function readMeta(stix) {
  const objects = Array.isArray(stix?.objects) ? stix.objects : [];
  const report = objects.find((o) => o?.type === "report" && o.x_rb_app === "research_bench")
    || objects.find((o) => o?.type === "report");
  return {
    title: report?.name || "",
    description: report?.description || "",
    screenshot: report?.x_rb_screenshot || null,
    snapshot: report?.x_rb_graph || null,
    published: report?.published || report?.created || null,
    // report 自体は数えない（利用者から見た「ノードの数」に合わせる）
    objectCount: objects.filter((o) => o !== report).length,
  };
}

/** 束から report を除いた、素の調査結果だけの束。読み込み（取り込み）に使う。 */
export function stripReport(stix) {
  const objects = (stix?.objects || []).filter((o) => !(o?.type === "report"));
  return { ...stix, objects };
}

/* ---------------- API ---------------- */

/**
 * 一覧。API が返すのはメタデータだけで、題や説明は STIX 本体の中にある。
 * 将来 API 側が name / description を一覧に載せたらそのまま使えるよう、
 * 先に一覧の値を見てから本体の取得に落とす。
 */
export async function list({ visibility = "me", limit = 50 } = {}) {
  if (visibility === "me" && !isLoggedIn()) return [];
  const json = await req("GET", endpoint({ visibility, limit }));
  return (json?.objects || []).map(normalize);
}

function normalize(o) {
  return {
    id: o.id,
    stixId: o.stixId || null,
    stixType: o.stixType || null,
    visibility: o.visibility || "me",
    owner: o.owner?.login || null,
    sizeBytes: o.sizeBytes ?? null,
    objectCount: o.objectCount ?? null,
    createdAt: o.createdAt || null,
    updatedAt: o.updatedAt || o.createdAt || null,
    canWrite: !!o.canWrite,
    // 一覧に載っていれば使う。無ければ read() で埋める
    title: o.name || o.title || "",
    description: o.description || "",
    screenshot: o.x_rb_screenshot || null,
    loaded: !!(o.name || o.title),
  };
}

/** 1 件の STIX 本体まで取る。 */
export async function read(id) {
  const json = await req("GET", endpoint({ id }));
  const item = normalize(json?.object || { id });
  const stix = json?.stix || null;
  const meta = readMeta(stix);
  return {
    ...item,
    title: meta.title || item.title,
    description: meta.description || item.description,
    screenshot: meta.screenshot || item.screenshot,
    snapshot: meta.snapshot,
    objectCount: meta.objectCount || item.objectCount,
    loaded: true,
    stix,
  };
}

function checkSize(stix) {
  const bytes = new TextEncoder().encode(JSON.stringify(stix)).length;
  if (bytes > MAX_BYTES) {
    throw new Error(`STIX が ${(bytes / 1024 / 1024).toFixed(1)} MiB あり、上限 10 MiB を超えています`);
  }
  return bytes;
}

export async function create(stix, { visibility = "me" } = {}) {
  checkSize(stix);
  const json = await req("POST", endpoint(), { visibility, stix });
  return normalize(json?.object || {});
}

export async function update(id, stix, { visibility = "me" } = {}) {
  checkSize(stix);
  const json = await req("PUT", endpoint({ id }), { visibility, stix });
  return normalize(json?.object || { id });
}

export async function remove(id) {
  await req("DELETE", endpoint({ id }));
  return true;
}
