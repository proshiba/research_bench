// 索引の壊れ方の検出。
//
// 索引は自動生成されているので、**参照切れにはならないが中身が誤っている**という
// 壊れ方をする。この形の壊れ方は既存の検査を全部すり抜けて、画面にだけ症状が出る。
//
// ポータル（store.js）と収集スクリプト（tools/ioc）の両方がここを使う。
// 別々に持つと、片方だけ直したときに画面と手元のデータが食い違う。
// 同じ判定は docs/validate-index.py にもある（各アプリが公開前に自分で流すため）。

/** `article:20260728#3` のように「家族」と「その中の番号」でできた id。 */
const SEQ_ID = /^(.+)#(\d+)$/;

/** これ未満の辺数では偶然そうなることがあるので判定しない。 */
const MIN_EDGES = 20;

/**
 * 参照先が「兄弟の先頭」に固定されている関係を見つける。
 *
 * 同じ家族に兄弟が複数いるのに参照が**常に同じ番号**を指しているなら、その関係は
 * 参照先を選んでいない。生成側で既定値のまま出ているということ。
 *
 * これを信じると、**まったく無関係なものが関係あるものとして出る**。実際に、ある
 * IOC の「収集元」が常にその日の 1 本目の記事を指していて、SparkKitty の IOC に
 * Apple の訴訟記事がぶら下がっていた。誤った辺は無い辺より悪いので、辿らない。
 *
 * @param {Array<{id?: string, refs?: Array<{rel?: string, target?: string}>}>} entities
 * @returns {Map<string, number>} rel → その rel の辺の数
 */
export function brokenRels(entities) {
  const siblings = new Map();   // 家族 → 兄弟の番号
  for (const e of entities) {
    const m = SEQ_ID.exec(e.id || "");
    if (!m) continue;
    if (!siblings.has(m[1])) siblings.set(m[1], new Set());
    siblings.get(m[1]).add(m[2]);
  }
  const out = new Map();
  if (!siblings.size) return out;

  const perRel = new Map();     // rel → { edges, seqs, withSiblings }
  for (const e of entities) {
    for (const r of e.refs || []) {
      const m = SEQ_ID.exec(r.target || "");
      if (!m) continue;
      let s = perRel.get(r.rel);
      if (!s) perRel.set(r.rel, (s = { edges: 0, seqs: new Set(), withSiblings: 0 }));
      s.edges++;
      s.seqs.add(m[2]);
      if ((siblings.get(m[1])?.size ?? 0) > 1) s.withSiblings++;
    }
  }
  for (const [rel, s] of perRel) {
    // 兄弟が居る家族しか指していないのに、番号が 1 種類しかない
    if (s.edges >= MIN_EDGES && s.seqs.size === 1 && s.withSiblings === s.edges) {
      out.set(rel, s.edges);
    }
  }
  return out;
}

/**
 * 該当する参照に `_broken` の印を付ける。
 * **捨てずに印を付ける**のは bogon / noise と同じ扱い。捨てると理由が追えない。
 */
export function markBrokenRefs(entities) {
  const broken = brokenRels(entities);
  if (!broken.size) return broken;
  for (const e of entities) {
    for (const r of e.refs || []) {
      if (broken.has(r.rel) && SEQ_ID.test(r.target || "")) r._broken = true;
    }
  }
  return broken;
}

/** 画面と実行ログに出す説明。文言を 1 か所にする。 */
export const brokenRelNote = (rel, n) =>
  `「${rel}」の参照先が常に同じ相手に固定されているため、この関係の ${n} 件は使いません（索引側の不具合）。`;
