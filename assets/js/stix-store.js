// 調査 API の STIX ストレージ（/api/stix/objects）との連携。
//
// API は STIX 本体とは別に、グラフの題（graphTitle）・説明（graphDescription）・
// サムネイル（thumbnail）を一次情報として持つ。一覧にも載るので、一覧を出すのに
// 本体を取りに行く必要はない。
//
// サムネイルは一覧に画像そのものではなく取得 URL が載る。me のものは取得にも
// Authorization が要るため、<img src> では出せない。fetch で取って
// オブジェクト URL にしてから貼る。
//
// STIX bundle の中には、それとは別に `report` オブジェクトを 1 つ入れている。
// 用途は 2 つ。
//   ① グラフの配置・ピン・トレイ（x_rb_graph）。API にこれを置く欄は無く、
//      これが無いと「復元」が「取り込み直し」に落ちる
//   ② 題と説明を STIX 側にも残す。report は 2.1 の正規の SDO なので、
//      **束だけ他のツールに渡しても題と説明が読める**
//
// 認証: 読み取りのうち public だけが匿名で、me の読み取りと書き込みは常に必須。
// これは API の認証強制フラグとは無関係（実測で確認）。

import { DEFAULT_BASE } from "./api-active-research.js";
import { authHeaders, isLoggedIn, recoverFromUnauthorized } from "./auth-active-research.js";
import { getModuleSettings } from "./modules.js";

/**
 * 上限。API が /api/meta で機械可読に出してくれるので、起動後はそちらで上書きする。
 * ここの値は取得前・取得失敗時の控えで、実測に合わせた既定値。
 * 手前で確かめてから送る（弾かれてから理由を出すより早いため）。
 */
export const LIMITS = {
  stixMaxBytes: 10 * 1024 * 1024,
  thumbMaxBytes: 512 * 1024,
  thumbTypes: ["image/png", "image/jpeg", "image/webp"],
  titleMax: 200,
  descriptionMax: 5000,
  qMax: 200,
  listMaxLimit: 100,
  listPageSize: 50,
};

let metaLoaded = null;

/**
 * /api/meta の stix ツール定義から上限を取り込む。1 回だけ引いて使い回す。
 * 失敗しても既定値のまま動く（上限の確認が甘くなるだけで、API 側が弾く）。
 */
export async function loadLimits() {
  if (metaLoaded) return LIMITS;
  metaLoaded = (async () => {
    try {
      const res = await fetch(new URL("/api/meta", base() + "/"), { credentials: "omit" });
      const tool = (await res.json())?.tools?.find((t) => t.id === "stix");
      if (!tool) return LIMITS;
      const l = tool.limits || {};
      const t = tool.thumbnail || {};
      const p = tool.pagination || {};
      if (l.stix_max_bytes) LIMITS.stixMaxBytes = l.stix_max_bytes;
      if (l.title_max) LIMITS.titleMax = l.title_max;
      if (l.description_max) LIMITS.descriptionMax = l.description_max;
      if (l.q_max) LIMITS.qMax = l.q_max;
      if (t.max_bytes) LIMITS.thumbMaxBytes = t.max_bytes;
      if (Array.isArray(t.content_types) && t.content_types.length) LIMITS.thumbTypes = t.content_types;
      if (p.max_limit) LIMITS.listMaxLimit = p.max_limit;
      if (p.default_limit) LIMITS.listPageSize = p.default_limit;
    } catch {
      // 既定値のまま進む
    }
    return LIMITS;
  })();
  return metaLoaded;
}

/** 長い属性（取り込んだ HTML など）を保存時に切る長さ。STIX の上限に当たらないための保険。 */
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

function friendlyError(status, json) {
  if (status === 401) return new Error("ログインが必要です（保存・更新・削除と me の一覧は認証必須）");
  if (status === 404) return new Error("見つかりませんでした（削除済みか、他の人のものです）");
  if (status === 413) return new Error("大きすぎます（STIX は 10 MiB、サムネイルは 512 KiB まで）");
  if (status === 429) return new Error("呼び出しが早すぎます。少し待って再試行してください");
  return new Error(json?.error_description || json?.error || `HTTP ${status}`);
}

/**
 * API を叩く。401 + WWW-Authenticate（＝この API が出した 401）のときだけ
 * 1 回トークンを取り直して同じ要求をやり直す。外部サービスの 401 とは混ざらない。
 */
async function req(method, url, body, { retried = false, blob = false } = {}) {
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

  if (res.status === 401 && !retried && res.headers.get("www-authenticate")) {
    // 本文を読む前に判定する（画像のときは JSON ではないため）
    const json = await res.clone().json().catch(() => null);
    if (await recoverFromUnauthorized(json)) return req(method, url, body, { retried: true, blob });
  }

  if (blob) {
    if (!res.ok) throw friendlyError(res.status, await res.json().catch(() => null));
    return res.blob();
  }

  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* 204 など本文が無いことがある */ }
  if (!res.ok) throw friendlyError(res.status, json);
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

/** 保存に載せない・切り詰める。画像や取り込んだ HTML で 10 MiB を食わないため。 */
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
 * 画像はここには入れない（API 側が別に持つ）。題と説明は API にも入れるが、
 * 束だけを他のツールへ渡しても読めるよう report にも残す。
 */
export function wrapBundle(bundle, { title, description, snapshot } = {}) {
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
    ...(snapshot ? { x_rb_graph: trimSnapshot(snapshot) } : {}),
  };

  return { type: "bundle", id: `bundle--${uuid()}`, objects: [report, ...objects] };
}

/** 保存した束から、ポータルが使うものを取り出す。 */
export function readMeta(stix) {
  const objects = Array.isArray(stix?.objects) ? stix.objects : [];
  const report = objects.find((o) => o?.type === "report" && o.x_rb_app === "research_bench")
    || objects.find((o) => o?.type === "report");
  return {
    title: report?.name || "",
    description: report?.description || "",
    snapshot: report?.x_rb_graph || null,
    // 旧い保存には画像が束の中にある。互換のために見る
    legacyScreenshot: report?.x_rb_screenshot || null,
    objectCount: objects.filter((o) => o !== report).length,
  };
}

/** 束から report を除いた、素の調査結果だけの束。取り込みに使う。 */
export function stripReport(stix) {
  const objects = (stix?.objects || []).filter((o) => !(o?.type === "report"));
  return { ...stix, objects };
}

/* ---------------- API ---------------- */

function normalize(o) {
  const t = o.thumbnail || null;
  return {
    id: o.id,
    stixId: o.stixId || null,
    stixType: o.stixType || null,
    visibility: o.visibility || "me",
    owner: o.owner?.login || null,
    title: o.graphTitle || "",
    description: o.graphDescription || "",
    // 一覧に載るのは取得 URL とメタデータだけ。画像は別途取りに行く。
    // sha256 は画像の中身の指紋（ETag と同じ値）。控えの鍵に使うと、
    // 中身が変わっていない画像は取り直しも条件付き GET も要らなくなる
    thumbnail: t?.url
      ? {
        url: new URL(t.url, base() + "/").href,
        contentType: t.contentType || null,
        sizeBytes: t.sizeBytes ?? null,
        sha256: t.sha256 || null,
      }
      : null,
    sizeBytes: o.sizeBytes ?? null,
    objectCount: o.objectCount ?? null,
    createdAt: o.createdAt || null,
    updatedAt: o.updatedAt || o.createdAt || null,
    canWrite: !!o.canWrite,
  };
}

/**
 * 一覧。q を渡すと題・説明・STIX name を部分一致で絞る（サーバー側）。
 * 題も説明もサムネイルの在処も一覧に載るので、ここだけで画面が作れる。
 *
 * 件数は offset で辿る。total と hasMore が返るので、
 * 「全部ではない」ことを画面で断れる。
 */
export async function list({ visibility = "me", limit, offset = 0, q = "" } = {}) {
  await loadLimits();
  if (visibility === "me" && !isLoggedIn()) {
    return { items: [], total: 0, offset: 0, hasMore: false };
  }
  const json = await req("GET", endpoint({
    visibility,
    limit: Math.min(limit || LIMITS.listPageSize, LIMITS.listMaxLimit),
    offset,
    q: q.slice(0, LIMITS.qMax),
  }));
  const items = (json?.objects || []).map(normalize);
  return {
    items,
    total: json?.total ?? items.length,
    offset: json?.offset ?? offset,
    // hasMore が無い API でも動くよう、件数からも判定できるようにしておく
    hasMore: json?.hasMore ?? (offset + items.length < (json?.total ?? items.length)),
  };
}

/** 1 件を STIX 本体まで取る。復元と、旧い保存の画像取り出しに使う。 */
export async function read(id) {
  const json = await req("GET", endpoint({ id }));
  const item = normalize(json?.object || { id });
  const stix = json?.stix || null;
  const meta = readMeta(stix);
  return {
    ...item,
    // API 側の題を優先し、無ければ束の report から拾う（旧い保存との互換）
    title: item.title || meta.title,
    description: item.description || meta.description,
    snapshot: meta.snapshot,
    legacyScreenshot: meta.legacyScreenshot,
    objectCount: item.objectCount ?? meta.objectCount,
    stix,
  };
}

/**
 * サムネイルの画像。me のものは取得にも Authorization が要るので
 * <img src> では出せない。取ってからオブジェクト URL にする。
 * 使い終わったら revokeObjectURL すること。
 *
 * API が ETag と Cache-Control（public は max-age=300、me は private）を
 * 付けてくれるので、2 回目以降の fetch はブラウザが If-None-Match を付けて
 * 304 に落とす。ここで自前の条件付き GET は組まない。
 */
export async function thumbnailUrl(id) {
  const b = await req("GET", endpoint({ id, asset: "thumbnail" }), undefined, { blob: true });
  return URL.createObjectURL(b);
}

function checkSize(stix) {
  const bytes = new TextEncoder().encode(JSON.stringify(stix)).length;
  if (bytes > LIMITS.stixMaxBytes) {
    const cap = (LIMITS.stixMaxBytes / 1024 / 1024).toFixed(0);
    throw new Error(`STIX が ${(bytes / 1024 / 1024).toFixed(1)} MiB あり、上限 ${cap} MiB を超えています`);
  }
}

/** base64 の実バイト数。API と同じ「デコード後」で見る。 */
function decodedBytes(base64) {
  const s = String(base64 || "");
  const pad = (s.endsWith("==") ? 2 : s.endsWith("=") ? 1 : 0);
  return Math.floor(s.length / 4) * 3 - pad;
}

/** 保存本文の組み立て。題と説明は API の上限で切る。 */
function payload({ visibility, title, description, thumbnail, stix }) {
  checkSize(stix);
  let thumb = thumbnail;
  if (thumb) {
    const bytes = decodedBytes(thumb.base64);
    if (!LIMITS.thumbTypes.includes(thumb.contentType)) {
      // 受け付けない形式を送ると保存ごと失敗する。画像だけ諦めて本体は通す
      thumb = null;
    } else if (bytes > LIMITS.thumbMaxBytes) {
      throw new Error(
        `サムネイルが上限 ${Math.round(LIMITS.thumbMaxBytes / 1024)} KiB を超えています（${Math.round(bytes / 1024)} KiB）`,
      );
    }
  }
  return {
    visibility,
    graphTitle: (title || "").trim().slice(0, LIMITS.titleMax) || null,
    graphDescription: (description || "").trim().slice(0, LIMITS.descriptionMax) || null,
    // 省略すると更新時に現在値を保持する仕様。撮れなかったときは触らない
    ...(thumb ? { thumbnail: thumb } : {}),
    stix,
  };
}

export async function create(stix, opts = {}) {
  await loadLimits();
  const json = await req("POST", endpoint(), payload({ ...opts, stix }));
  return normalize(json?.object || {});
}

export async function update(id, stix, opts = {}) {
  await loadLimits();
  const json = await req("PUT", endpoint({ id }), payload({ ...opts, stix }));
  return normalize(json?.object || { id });
}

export async function remove(id) {
  await req("DELETE", endpoint({ id }));
  return true;
}
