// ソースの登録・遅延ロード・索引・クロスサーチ。
//
// ソースは互いを知らない。横串はここで `joinKey` の一致から作る（仕様 §3）。

import { getAdapter } from "./adapters.js";
import { detectType, fillTemplate, joinKey, resolveUrl } from "./util.js";

const listeners = new Set();

export const store = {
  spec: null,
  sources: [],
  tools: [],
  /** joinKey → [{ source, entity }]。ロード済みソースぶんだけ入る。 */
  joins: new Map(),
};

export function onChange(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

function emit() {
  for (const fn of listeners) fn(store);
}

export async function initStore() {
  const res = await fetch("apps.json", { cache: "no-cache" });
  if (!res.ok) throw new Error(`apps.json を読めません (HTTP ${res.status})`);
  const cfg = await res.json();
  store.spec = cfg.spec_version || "1.0";
  store.tools = cfg.tools || [];
  store.sources = (cfg.sources || []).map((s) => ({
    ...s,
    status: "idle",     // idle | loading | ready | error
    progress: 0,
    entities: [],
    byId: new Map(),
    stats: {},
    limits: [],
    error: null,
  }));
  // meta.json は小さいので起動時にまとめて取る。deep_links と embed_css が
  // ダッシュボード表示の時点で要るため、索引の遅延ロードとは切り離す（仕様 §1.1）。
  await Promise.allSettled(store.sources.map(loadMeta));
  emit();
  return store;
}

/** ソースの meta.json を読み、apps.json の記述より優先して反映する。 */
export async function loadMeta(source) {
  if (!source.meta_url) return null;
  try {
    const res = await fetch(source.meta_url, { mode: "cors", credentials: "omit" });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const meta = await res.json();
    source.meta = meta;
    if (meta.name) source.name = meta.name;
    if (meta.site_url) source.site_url = meta.site_url;
    if (meta.deep_links) source.deep_links = { ...(source.deep_links || {}), ...meta.deep_links };
    if (meta.embed_css && !source.embed_css) source.embed_css = meta.embed_css;
    if (meta.capabilities) source.capabilities = meta.capabilities;
    if (meta.stats && source.status !== "ready") source.stats = meta.stats;
    if (!source.index_url) {
      source.index_url = resolveUrl(meta.site_url || source.meta_url,
        meta.endpoints?.search || "api/v1/search.json");
    }
    return meta;
  } catch (err) {
    console.warn(`[research_bench] ${source.app_id} の meta.json を読めません`, err);
    return null;
  }
}

export function getSource(appId) {
  return store.sources.find((s) => s.app_id === appId) || null;
}

/** 索引に使う小文字の連結文字列。検索のたびに作り直さないよう一度だけ計算する。 */
function buildBlob(e) {
  const parts = [e.label, e.value];
  if (e.aliases) parts.push(...e.aliases);
  if (e.attrs) {
    for (const [k, v] of Object.entries(e.attrs)) {
      if (k.startsWith("_")) continue;
      if (typeof v === "string" || typeof v === "number") parts.push(v);
    }
  }
  return parts.filter(Boolean).join("  ").toLowerCase();
}

function indexSource(source) {
  source.byId = new Map();
  for (const e of source.entities) {
    e._src = source.app_id;
    e._blob = buildBlob(e);
    e._key = joinKey(e.type, e.value);
    source.byId.set(e.id, e);

    const keys = new Set();
    if (e._key) keys.add(e._key);
    for (const a of e.aliases || []) {
      const k = joinKey(e.type, a);
      if (k) keys.add(k);
    }
    e._keys = [...keys];
    for (const k of e._keys) {
      let bucket = store.joins.get(k);
      if (!bucket) store.joins.set(k, (bucket = []));
      bucket.push({ source, entity: e });
    }
  }
}

function dropFromIndex(source) {
  for (const [k, bucket] of store.joins) {
    const kept = bucket.filter((b) => b.source !== source);
    if (kept.length) store.joins.set(k, kept);
    else store.joins.delete(k);
  }
}

/** 1 ソースを読み込む。読み込み済みなら何もしない。 */
export async function loadSource(source, { force = false } = {}) {
  if (source.status === "loading") return source._promise;
  if (source.status === "ready" && !force) return source;

  source.status = "loading";
  source.progress = 0;
  source.error = null;
  emit();

  source._promise = (async () => {
    try {
      const adapter = getAdapter(source.adapter);
      const result = await adapter.load(source, (p) => {
        source.progress = p;
        emit();
      });
      if (source.entities.length) dropFromIndex(source);
      source.entities = result.entities || [];
      source.stats = result.stats || {};
      source.limits = result.limits || [];
      if (result.meta?.deep_links) source.deep_links = result.meta.deep_links;
      indexSource(source);
      source.status = "ready";
      source.progress = 1;
    } catch (err) {
      source.status = "error";
      source.error = err?.message || String(err);
      console.error(`[research_bench] ${source.app_id} の読み込みに失敗`, err);
    } finally {
      source._promise = null;
      emit();
    }
    return source;
  })();

  return source._promise;
}

/** 索引が要る画面に入る前に呼ぶ。まだのソースをまとめて読み込む。 */
export function loadAllSources() {
  return Promise.all(store.sources.map((s) => loadSource(s)));
}

export function readySources() {
  return store.sources.filter((s) => s.status === "ready");
}

/* ---------------- 検索 ---------------- */

const PER_SOURCE_LIMIT = 60;

/**
 * クロスサーチ。ソース別にまとめた結果を返す。
 * 完全一致（結合キー）を最優先し、続いて部分一致。
 */
export function search(rawQuery) {
  const q = String(rawQuery || "").trim();
  const result = {
    query: q,
    detectedType: detectType(q),
    groups: [],
    total: 0,
    matchedSources: 0,
    joinKeys: [],
  };
  if (!q) return result;

  const needle = q.toLowerCase();
  const exactKeys = new Set();
  // 入力が指標として解釈できるなら、その型の結合キーで完全一致を引く
  if (result.detectedType) {
    const k = joinKey(result.detectedType, q);
    if (k) exactKeys.add(k);
  }
  // 名前系（アクター/マルウェア）としての完全一致も試す
  const nameKey = joinKey("actor", q);
  if (nameKey) exactKeys.add(nameKey);

  for (const source of store.sources) {
    if (source.status !== "ready") continue;
    const exact = [];
    const partial = [];
    const seen = new Set();

    for (const k of exactKeys) {
      for (const b of store.joins.get(k) || []) {
        if (b.source !== source || seen.has(b.entity.id)) continue;
        seen.add(b.entity.id);
        exact.push(b.entity);
      }
    }

    if (partial.length < PER_SOURCE_LIMIT) {
      for (const e of source.entities) {
        if (seen.has(e.id)) continue;
        if (!e._blob.includes(needle)) continue;
        seen.add(e.id);
        partial.push(e);
        if (partial.length >= PER_SOURCE_LIMIT * 3) break;
      }
    }

    partial.sort((a, b) => rank(a, needle) - rank(b, needle));
    const items = exact.concat(partial).slice(0, PER_SOURCE_LIMIT);
    const count = exact.length + partial.length;
    if (!count) continue;

    result.groups.push({
      source,
      items,
      count,
      truncated: count > items.length,
      exactCount: exact.length,
    });
    result.total += count;
    result.matchedSources += 1;
  }

  // 2 ソース以上に現れた結合キー = 横串
  for (const k of exactKeys) {
    const bucket = store.joins.get(k);
    if (!bucket) continue;
    const srcs = new Set(bucket.map((b) => b.source.app_id));
    if (srcs.size > 1) result.joinKeys.push({ key: k, sources: [...srcs] });
  }

  result.groups.sort((a, b) => b.exactCount - a.exactCount || b.count - a.count);
  return result;
}

function rank(e, needle) {
  const label = e.label.toLowerCase();
  if (label === needle) return 0;
  if (label.startsWith(needle)) return 1;
  if (label.includes(needle)) return 2;
  return 3;
}

/** そのエンティティが他ソースにも存在するか。存在するなら相手側の一覧を返す。 */
export function crossSourceMatches(entity) {
  const out = [];
  for (const k of entity._keys || []) {
    for (const b of store.joins.get(k) || []) {
      if (b.entity === entity || b.source.app_id === entity._src) continue;
      if (!out.some((o) => o.entity.id === b.entity.id && o.source === b.source)) out.push(b);
    }
  }
  return out;
}

/** エンティティの詳細ページ URL。テンプレートが無ければ null。 */
export function deepLink(entity, kind) {
  const source = getSource(entity._src);
  if (!source) return null;
  const links = source.deep_links || {};
  const tpl = kind ? links[kind] : (links[entity.type] || links._default);
  if (!tpl) return null;
  const vars = {
    detail: entity.detail ?? entity.id,
    id: entity.id,
    value: entity.value,
    prefix: entity.attrs?.prefix ?? entity.attrs?._prefix ?? "",
  };
  return resolveUrl(source.site_url, fillTemplate(tpl, vars));
}

/** ソース側のグラフ画面へ渡すリンク（持っているソースだけ）。 */
export function graphLink(entity) {
  const source = getSource(entity._src);
  if (!source?.deep_links?._graph) return null;
  return deepLink(entity, "_graph");
}
