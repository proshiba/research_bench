// 索引（meta.json / search.json）の取得。
//
// 既定はネットワークから取るが、`--from <dir>` で手元の写しからも読める。
// 取ったものは `--cache <dir>` に保存でき、次回以降そこから読み直せる。
// これで **同じ入力での再実行がネットワーク無しで再現できる**。

import fs from "node:fs";
import path from "node:path";
import { readJson, sha256 } from "./io.mjs";
import { markBrokenRefs } from "./refs.mjs";

const REPO_ROOT = path.resolve(new URL("../../..", import.meta.url).pathname);

/** apps.json の登録内容。ポータルと同じ定義を使う（二重管理を避ける）。 */
export function loadRegistry() {
  const cfg = readJson(path.join(REPO_ROOT, "apps.json"));
  if (!cfg?.sources?.length) throw new Error("apps.json にソースがありません");
  return cfg.sources.map((s) => ({
    app_id: s.app_id,
    name: s.name,
    meta_url: s.meta_url,
    site_url: s.site_url,
  }));
}

/** URL のパス部分をそのままファイル名にする。写しと URL が 1 対 1 で対応する。 */
const cachePath = (dir, url) => path.join(dir, new URL(url).hostname, new URL(url).pathname);

async function fetchText(url, { cache, from }) {
  if (from) {
    const f = cachePath(from, url);
    if (!fs.existsSync(f)) throw new Error(`写しがありません: ${f}`);
    return fs.readFileSync(f, "utf8");
  }
  const res = await fetch(url, { headers: { accept: "application/json" } });
  if (!res.ok) throw new Error(`${url} が HTTP ${res.status}`);
  const text = await res.text();
  if (cache) {
    const f = cachePath(cache, url);
    fs.mkdirSync(path.dirname(f), { recursive: true });
    fs.writeFileSync(f, text);
  }
  return text;
}

/**
 * 1 ソースぶんの meta と search を取る。
 * search の場所は meta の endpoints.search を site_url 基準で解く
 * （ポータルの store.js と同じ解き方）。
 */
export async function loadSource(source, opts) {
  const metaText = await fetchText(source.meta_url, opts);
  const meta = JSON.parse(metaText);
  const base = meta.site_url || source.site_url || source.meta_url;
  const searchUrl = new URL(
    meta.endpoints?.search || "api/v1/search.json",
    base.endsWith("/") ? base : base + "/",
  ).href;

  const searchText = await fetchText(searchUrl, opts);
  const search = JSON.parse(searchText);
  const entities = search.entities || search.items || [];
  // 参照先が選ばれていない関係に印を付ける。辿ると無関係なものが繋がる
  const broken = markBrokenRefs(entities);

  return {
    app_id: source.app_id,
    name: source.name,
    meta_url: source.meta_url,
    search_url: searchUrl,
    // 取得元が同じ中身かを後から確かめられるようにハッシュを残す
    meta_sha256: sha256(metaText),
    search_sha256: sha256(searchText),
    generated_at: meta.generated_at || null,
    entities,
    ...(broken.size ? { broken_rels: Object.fromEntries([...broken].sort()) } : {}),
  };
}

export async function loadAll(opts) {
  const out = [];
  for (const s of loadRegistry()) {
    // 1 つ落ちても他は集める。落ちたことは呼び出し側に返す
    try {
      out.push(await loadSource(s, opts));
    } catch (err) {
      out.push({ app_id: s.app_id, name: s.name, error: err.message, entities: [] });
    }
  }
  return out;
}

export { REPO_ROOT };
