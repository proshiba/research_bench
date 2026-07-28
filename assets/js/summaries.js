// 見出しに対する「要約」の取り方。
//
// 本来の置き場所は search.json の attrs（`概要` など）で、そこにあればそれを使う。
// ただし索引に載せていないソースもある。デイリーニュースがそれで、要約は
// アプリ側の別ファイル（記事索引）に入っている。
//
// そこで apps.json に summaries を書けるようにした。書いてあるソースだけ、
// **実際に要約が要求されたとき**（＝見出しにマウスを載せたとき）に 1 回だけ取りに行く。
// トップ画面を開いただけでは取らない。
//
//   "summaries": {
//     "url":  "data/articles.json",  // site_url からの相対、または絶対
//     "list": "articles",            // 配列がある場所（省略時は応答そのものが配列）
//     "key":  "{d}/{i}",             // 1 件から作るキー。entity.detail と突き合わせる
//     "text": "s"                    // 要約のフィールド名
//   }
//
// これはポータル側の当て木で、仕様の一部ではない。アプリが search.json に
// 要約を載せてくれればこの設定は要らなくなる（attrs 側が優先される）。

import { resolveUrl } from "./util.js";

/**
 * キーの組み立て。util.js の fillTemplate は URL 用に値をエンコードするが、
 * ここで作るのは URL ではなく entity.detail と直接比べる文字列なので、
 * エンコードせずそのまま埋める。
 */
function fillKey(tpl, row) {
  return String(tpl).replace(/\{(\w+)\}/g, (m, k) => (k in row ? String(row[k]) : m));
}

/** app_id → Map(キー → 要約)。取得済みのソースだけ入る。 */
const loaded = new Map();
/** app_id → Promise。同時に何度も取りに行かないための待ち合わせ。 */
const inflight = new Map();
/** app_id → エラー内容。一度失敗したら繰り返さない。 */
const failed = new Map();

/** 索引そのものに要約があればそれを返す。こちらが本来の置き場所。 */
function fromAttrs(entity) {
  const attrs = entity?.attrs || {};
  for (const k of ["概要", "要約", "summary", "description"]) {
    const v = attrs[k];
    if (typeof v === "string" && v.trim()) return v.trim();
  }
  return null;
}

const keyOf = (entity) => String(entity?.detail ?? entity?.id ?? "");

export function hasSummarySource(source) {
  return !!source?.summaries?.url && !failed.has(source.app_id);
}

/** いま手元にある要約。取りに行かない（描画中に呼ぶ用）。 */
export function summaryNow(source, entity) {
  const own = fromAttrs(entity);
  if (own) return own;
  return loaded.get(source?.app_id)?.get(keyOf(entity)) ?? null;
}

/** 別ファイルを取りに行ったが、そのソースには載っていなかったか。 */
export function summaryState(source, entity) {
  if (fromAttrs(entity)) return "ready";
  const map = loaded.get(source?.app_id);
  if (map) return map.has(keyOf(entity)) ? "ready" : "missing";
  if (failed.has(source?.app_id)) return "error";
  return source?.summaries?.url ? "pending" : "missing";
}

export function summaryError(source) {
  return failed.get(source?.app_id) || null;
}

/**
 * 要約のファイルを 1 回だけ取る。すでに取ってあれば何もしない。
 * 失敗しても投げない（要約が出ないだけで、画面は使えるべきなので）。
 */
export function loadSummaries(source) {
  const id = source?.app_id;
  const spec = source?.summaries;
  if (!id || !spec?.url) return Promise.resolve(false);
  if (loaded.has(id)) return Promise.resolve(true);
  if (failed.has(id)) return Promise.resolve(false);
  if (inflight.has(id)) return inflight.get(id);

  const url = resolveUrl(source.site_url || source.meta_url || location.href, spec.url);
  const task = (async () => {
    try {
      const res = await fetch(url, { mode: "cors", credentials: "omit" });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const json = await res.json();
      const rows = spec.list ? json?.[spec.list] : json;
      if (!Array.isArray(rows)) throw new Error("要約の一覧が配列ではありません");

      const map = new Map();
      for (const row of rows) {
        const text = row?.[spec.text || "summary"];
        if (typeof text !== "string" || !text.trim()) continue;
        map.set(fillKey(spec.key || "{id}", row), text.trim());
      }
      loaded.set(id, map);
      return true;
    } catch (err) {
      failed.set(id, err.message || String(err));
      console.warn(`[research_bench] ${id} の要約を読めません`, err);
      return false;
    } finally {
      inflight.delete(id);
    }
  })();

  inflight.set(id, task);
  return task;
}
