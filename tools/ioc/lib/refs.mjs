// 参照先が選ばれていない関係の検出。
//
// 索引が `<家族>#<番号>` という id を使っているとき（`article:20260728#3` など）、
// 同じ家族に兄弟が複数いるのに参照が**常に同じ番号**を指しているなら、その関係は
// 参照先を選んでいない。生成側で既定値のまま出ているということ。
//
// 参照切れにはならないので、他の検査は全部通ってしまう。それでいて、辿ると
// **まったく無関係なものが関係あるものとして出る**。実際に、ある IOC の「収集元」が
// 常にその日の 1 本目の記事を指していて、SparkKitty の IOC に Apple の訴訟記事が
// ぶら下がっていた。誤った辺は無い辺より悪いので、集める側でも落とす。
//
// ポータル側（assets/js/store.js の detectBrokenRefs）と同じ判定を持つ。
// 片方だけ直すと画面と手元のデータが食い違うため。

const SEQ_ID = /^(.+)#(\d+)$/;
/** これ未満の辺数では偶然そうなることがあるので判定しない。 */
const MIN_EDGES = 20;

/**
 * 参照先が固定されている rel を返す。
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

  const perRel = new Map();
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

/** 該当する参照に印を付ける。捨てずに印を付けるのは他の除外と同じ扱い。 */
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
