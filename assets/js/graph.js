// ワークベンチのグラフ。外部ライブラリなしの力学レイアウト + Canvas 描画。
//
// 1 ノード = 1 実体。同じ結合キーを持つ別ソースのエンティティは同じノードに畳む。
// ノードの色と形は「エンティティ種別」で決まる（出典ソースではない）。
// ソース横断で畳まれた実体は外側の破線リングで示し、出典はサイドバーに出す。

import { getAdapter } from "./adapters.js";
import { worstLevel } from "./risk.js";
import { getSource, store } from "./store.js";
import { TYPE_GROUPS, joinKey, typeGroup, typeShape } from "./util.js";

const REPULSION = 4200;
const REST_LENGTH = 112;
const SPRING = 0.021;
const DAMPING = 0.85;
const CENTER_PULL = 0.0014;
const EXPAND_CAP = 40;

/** ソース内の被参照インデックス。展開時に逆方向の辺も辿れるようにする。 */
const reverseIndexes = new WeakMap();

function reverseIndex(source) {
  let idx = reverseIndexes.get(source);
  if (idx) return idx;
  idx = new Map();
  for (const e of source.entities) {
    for (const r of e.refs || []) {
      let bucket = idx.get(r.target);
      if (!bucket) idx.set(r.target, (bucket = []));
      bucket.push({ rel: r.rel, entity: e });
    }
  }
  reverseIndexes.set(source, idx);
  return idx;
}

function nodeKeyFor(source, entity) {
  const k = entity._key || joinKey(entity.type, entity.value);
  return k ? `k:${entity.type}:${k}` : `e:${source.app_id}:${entity.id}`;
}

export function createGraph(canvas, { onSelect, onStatus, onMutate, onContext } = {}) {
  const ctx = canvas.getContext("2d");
  const nodes = new Map();   // nodeId → node
  const edges = new Map();   // edgeId → edge
  const view = { k: 1, tx: 0, ty: 0 };

  let W = 0, H = 0, dpr = 1;
  let alpha = 1, raf = null;
  let selectedId = null, hoverId = null;
  let dragNode = null, panning = null, moved = false;
  let linking = null;        // ドラッグ中の手動リンク { from, wx, wy, target }
  let pendingLink = null;    // ボタン起動の手動リンク（次にクリックしたノードへ張る）
  let theme = {};
  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  /* ---------------- モデル ---------------- */

  function addEntity(source, entity, opts = {}) {
    return addEntityInfo(source, entity, opts).node;
  }

  /** 追加結果まで返す内部版。created=新規ノード、joined=既存ノードに別ソースが合流。 */
  function addEntityInfo(source, entity, { x, y, expandedFrom } = {}) {
    const id = nodeKeyFor(source, entity);
    let node = nodes.get(id);
    const created = !node;
    const sourcesBefore = node ? node.sources.size : 0;
    if (!node) {
      const origin = expandedFrom && nodes.get(expandedFrom);
      node = {
        id,
        type: entity.type,
        label: entity.label,
        members: [],
        sources: new Set(),
        x: x ?? (origin ? origin.x + (Math.random() - 0.5) * 90 : W / 2 + (Math.random() - 0.5) * 220),
        y: y ?? (origin ? origin.y + (Math.random() - 0.5) * 90 : H / 2 + (Math.random() - 0.5) * 180),
        vx: 0, vy: 0,
        pinned: false,
        expanded: false,
        degree: 0,
      };
      nodes.set(id, node);
      alpha = Math.max(alpha, 0.6);
    }
    if (!node.members.some((m) => m.entity === entity)) {
      node.members.push({ source, entity });
      node.sources.add(source.app_id);
      // 表示名は最初に入った実体のものを使うが、より短いラベルがあれば拾う
      if (entity.label.length < node.label.length) node.label = entity.label;
    }
    return { node, created, joined: !created && node.sources.size > sourcesBefore };
  }

  /** ユーザーが自分で張るリンク。ソース由来の辺と区別して保持する。 */
  function addManualEdge(fromId, toId, rel = "手動リンク") {
    if (fromId === toId) return null;
    const e = addEdge(fromId, toId, rel);
    if (!e) return null;
    e.manual = true;
    e.from = fromId;
    alpha = Math.max(alpha, 0.3);
    kick();
    notify();
    return e;
  }

  /** ボタンからのリンク開始。次にクリックしたノードへ張る（マウス以外でも張れるように）。 */
  function beginLink(nodeId) {
    pendingLink = nodes.has(nodeId) ? nodeId : null;
    canvas.style.cursor = pendingLink ? "crosshair" : "grab";
    draw();
    return !!pendingLink;
  }

  function cancelLink() {
    pendingLink = null;
    linking = null;
    canvas.style.cursor = "grab";
    draw();
  }

  /** ノードの画面座標。UI テストから位置を知るために使う。 */
  function screenOf(nodeId) {
    const n = nodes.get(nodeId);
    if (!n) return null;
    const [sx, sy] = toScreen(n.x, n.y);
    return { x: sx, y: sy, r: radius(n) * view.k };
  }

  function removeEdge(edgeId) {
    if (!edges.delete(edgeId)) return;
    recountDegrees();
    draw();
    onMutate?.();
  }

  function setEdgeRel(edgeId, rel) {
    const e = edges.get(edgeId);
    if (!e) return;
    e.rels = new Set([rel || "手動リンク"]);
    draw();
    onMutate?.();
  }

  function addEdge(aId, bId, rel, cross = false) {
    if (aId === bId) return null;
    const id = aId < bId ? `${aId}|${bId}` : `${bId}|${aId}`;
    let e = edges.get(id);
    if (!e) {
      e = { id, a: aId, b: bId, rels: new Set(), cross };
      edges.set(id, e);
      const na = nodes.get(aId), nb = nodes.get(bId);
      if (na) na.degree++;
      if (nb) nb.degree++;
    }
    if (rel) e.rels.add(rel);
    if (cross) e.cross = true;
    return e;
  }

  /** ノードを 1 件足す。横串の相手が既にグラフ上にいれば同じノードに畳まれる。 */
  function addRoot(source, entity) {
    const node = addEntity(source, entity);
    selectedId = node.id;
    kick();
    notify();
    return node;
  }

  /** ノードの隣接を展開する。remote=true のソースは遅延取得も行う。 */
  async function expand(node, { typeFilter = null } = {}) {
    if (!node) return { added: 0 };
    const candidates = [];

    for (const { source, entity } of node.members) {
      for (const r of entity.refs || []) {
        const target = source.byId.get(r.target);
        if (target) candidates.push({ source, entity: target, rel: r.rel });
      }
      for (const back of reverseIndex(source).get(entity.id) || []) {
        candidates.push({ source, entity: back.entity, rel: back.rel });
      }
    }

    // 別ソースに同じ実体があれば、その周辺も展開対象に含める
    for (const { source, entity } of node.members) {
      for (const k of entity._keys || []) {
        for (const b of store.joins.get(k) || []) {
          if (b.source === source) continue;
          candidates.push({ source: b.source, entity: b.entity, rel: "同一実体", cross: true });
        }
      }
    }

    const remote = await expandRemote(node);
    candidates.push(...remote);

    const filtered = typeFilter ? candidates.filter((c) => c.entity.type === typeFilter) : candidates;
    // 次数の低い（＝珍しい）関係から入れる。ありふれたノードで埋もれないように。
    filtered.sort((a, b) => (a.entity.refs?.length || 0) - (b.entity.refs?.length || 0));

    let added = 0, joined = 0;
    for (const c of filtered) {
      if (added >= EXPAND_CAP) break;
      const info = addEntityInfo(c.source, c.entity, { expandedFrom: node.id });
      addEdge(node.id, info.node.id, c.rel, !!c.cross);
      if (info.created) added++;
      else if (info.joined) joined++;
    }
    node.expanded = true;
    linkExisting();
    alpha = Math.max(alpha, 0.75);
    kick();
    notify();
    return { added, joined, skipped: Math.max(0, filtered.length - EXPAND_CAP) };
  }

  /** アダプタが遅延取得に対応していれば、そこから追加の周辺実体を得る。 */
  async function expandRemote(node) {
    const out = [];
    for (const { source, entity } of node.members) {
      const adapter = getAdapter(source.adapter);
      if (!adapter.expand || entity._remoteExpanded) continue;
      entity._remoteExpanded = true;
      onStatus?.({ loading: true, message: `${source.name} から ${entity.label} の詳細を取得中` });
      try {
        const extra = await adapter.expand(source, entity);
        for (const e of extra) {
          e._src = source.app_id;
          e._key = joinKey(e.type, e.value);
          e._keys = e._key ? [e._key] : [];
          if (!source.byId.has(e.id)) {
            source.byId.set(e.id, e);
            source.entities.push(e);
            reverseIndexes.delete(source);
            for (const k of e._keys) {
              const bucket = store.joins.get(k);
              if (bucket) bucket.push({ source, entity: e });
              else store.joins.set(k, [{ source, entity: e }]);
            }
          }
          out.push({ source, entity: e, rel: e.refs?.[0]?.rel || "関連" });
        }
        onStatus?.({ loading: false, message: `${entity.label}: ${extra.length} 件を追加` });
      } catch (err) {
        onStatus?.({ loading: false, error: `${entity.label} の詳細を取得できませんでした: ${err.message}` });
      }
    }
    return out;
  }

  /** 既にグラフ上にあるノード同士の、まだ張られていない関係を張る。 */
  function linkExisting() {
    const idOf = new Map();
    for (const node of nodes.values()) {
      for (const { source, entity } of node.members) idOf.set(source.app_id + "::" + entity.id, node.id);
    }
    for (const node of nodes.values()) {
      for (const { source, entity } of node.members) {
        for (const r of entity.refs || []) {
          const otherId = idOf.get(source.app_id + "::" + r.target);
          if (otherId) addEdge(node.id, otherId, r.rel);
        }
      }
    }
  }

  function remove(nodeId) {
    if (!nodes.delete(nodeId)) return;
    for (const [id, e] of edges) if (e.a === nodeId || e.b === nodeId) edges.delete(id);
    if (selectedId === nodeId) selectedId = null;
    recountDegrees();
    kick();
    notify();
  }

  function keepOnly(nodeId) {
    for (const id of [...nodes.keys()]) if (id !== nodeId) nodes.delete(id);
    edges.clear();
    recountDegrees();
    kick();
    notify();
  }

  function recountDegrees() {
    for (const n of nodes.values()) n.degree = 0;
    for (const e of edges.values()) {
      const a = nodes.get(e.a), b = nodes.get(e.b);
      if (a) a.degree++;
      if (b) b.degree++;
    }
  }

  function clear() {
    nodes.clear();
    edges.clear();
    selectedId = null;
    view.k = 1; view.tx = 0; view.ty = 0;
    draw();
    notify();
  }

  function notify() {
    onSelect?.(selectedId ? nodes.get(selectedId) : null, { nodes: nodes.size, edges: edges.size });
    onMutate?.();
  }

  function select(nodeId) {
    selectedId = nodeId;
    draw();
    notify();
  }

  /* ---------------- 物理 ---------------- */

  function radius(n) {
    return 7 + Math.min(n.degree, 8) * 1.4 + (n.sources.size > 1 ? 2 : 0);
  }

  function step() {
    const list = [...nodes.values()];
    for (let i = 0; i < list.length; i++) {
      const a = list[i];
      for (let j = i + 1; j < list.length; j++) {
        const b = list[j];
        let dx = b.x - a.x, dy = b.y - a.y;
        let d2 = dx * dx + dy * dy;
        if (d2 > 160000) continue;
        if (d2 < 0.01) { d2 = 0.01; dx = Math.random() - 0.5; dy = Math.random() - 0.5; }
        const d = Math.sqrt(d2);
        const f = REPULSION / d2;
        a.vx -= (dx / d) * f; a.vy -= (dy / d) * f;
        b.vx += (dx / d) * f; b.vy += (dy / d) * f;
      }
    }
    for (const e of edges.values()) {
      const a = nodes.get(e.a), b = nodes.get(e.b);
      if (!a || !b) continue;
      const dx = b.x - a.x, dy = b.y - a.y;
      const d = Math.hypot(dx, dy) || 0.01;
      const f = (d - REST_LENGTH) * SPRING;
      a.vx += (dx / d) * f; a.vy += (dy / d) * f;
      b.vx -= (dx / d) * f; b.vy -= (dy / d) * f;
    }
    const cx = W / 2, cy = H / 2;
    for (const n of list) {
      if (n === dragNode || n.pinned) { n.vx = 0; n.vy = 0; continue; }
      n.vx += (cx - n.x) * CENTER_PULL;
      n.vy += (cy - n.y) * CENTER_PULL;
      n.x += n.vx * alpha;
      n.y += n.vy * alpha;
      n.vx *= DAMPING;
      n.vy *= DAMPING;
    }
    alpha *= 0.992;
  }

  /* ---------------- 描画 ---------------- */

  /** 種別グループごとの輪郭。色だけに頼らないための二次符号化。 */
  function shapePath(shape, x, y, r) {
    const poly = (n, rot, rad) => {
      for (let i = 0; i < n; i++) {
        const a = rot + (i / n) * Math.PI * 2;
        const px = x + Math.cos(a) * rad, py = y + Math.sin(a) * rad;
        if (i) ctx.lineTo(px, py); else ctx.moveTo(px, py);
      }
      ctx.closePath();
    };
    ctx.beginPath();
    switch (shape) {
      case "square": ctx.rect(x - r * 0.86, y - r * 0.86, r * 1.72, r * 1.72); break;
      case "roundsquare":
        if (ctx.roundRect) ctx.roundRect(x - r * 0.86, y - r * 0.86, r * 1.72, r * 1.72, r * 0.42);
        else ctx.rect(x - r * 0.86, y - r * 0.86, r * 1.72, r * 1.72);
        break;
      case "diamond": poly(4, -Math.PI / 2, r * 1.18); break;
      case "triangle": poly(3, -Math.PI / 2, r * 1.22); break;
      case "pentagon": poly(5, -Math.PI / 2, r * 1.1); break;
      case "hexagon": poly(6, -Math.PI / 2, r * 1.08); break;

      // Web ページ。ブラウザの窓に見えるよう、上辺にタイトルバーを持つ角丸四角
      case "window": {
        const w = r * 1.9, h = r * 1.5;
        const left = x - w / 2, top = y - h / 2;
        if (ctx.roundRect) ctx.roundRect(left, top, w, h, r * 0.24);
        else ctx.rect(left, top, w, h);
        ctx.moveTo(left, top + h * 0.32);
        ctx.lineTo(left + w, top + h * 0.32);
        break;
      }

      // AS。回線の塊なので雲
      case "cloud": {
        const s = r * 0.92;
        ctx.moveTo(x - s, y + s * 0.5);
        ctx.arc(x - s * 0.55, y + s * 0.1, s * 0.55, Math.PI * 0.6, Math.PI * 1.6);
        ctx.arc(x + s * 0.02, y - s * 0.35, s * 0.68, Math.PI * 1.15, Math.PI * 1.9);
        ctx.arc(x + s * 0.68, y + s * 0.05, s * 0.52, Math.PI * 1.6, Math.PI * 0.5);
        ctx.closePath();
        break;
      }

      // 地理。地図のピン
      case "pin": {
        const s = r * 1.05;
        ctx.moveTo(x, y + s * 1.15);
        ctx.quadraticCurveTo(x - s * 0.95, y - s * 0.1, x - s * 0.52, y - s * 0.62);
        ctx.arc(x, y - s * 0.35, s * 0.63, Math.PI * 1.25, Math.PI * 1.75);
        ctx.quadraticCurveTo(x + s * 0.95, y - s * 0.1, x, y + s * 1.15);
        ctx.closePath();
        break;
      }

      default: ctx.arc(x, y, r, 0, Math.PI * 2);
    }
  }

  function readTheme() {
    const cs = getComputedStyle(document.documentElement);
    theme = {
      line: cs.getPropertyValue("--line").trim(),
      ink: cs.getPropertyValue("--ink").trim(),
      dim: cs.getPropertyValue("--ink-dim").trim(),
      faint: cs.getPropertyValue("--ink-faint").trim(),
      focus: cs.getPropertyValue("--focus").trim(),
      surface: cs.getPropertyValue("--surface").trim(),
      crit: cs.getPropertyValue("--crit").trim(),
      types: Object.fromEntries(Object.entries(TYPE_GROUPS)
        .map(([k, g]) => [k, cs.getPropertyValue(g.color).trim()])),
    };
  }

  // 色と形は種別だけで決まる。出所（索引由来か手動追加か）は輪郭の実線/破線で示す。
  function nodeColor(n) { return theme.types[typeGroup(n.type)] || theme.dim; }
  function nodeShape(n) { return typeShape(n.type); }
  function isManualOnly(n) {
    return n.members.length > 0 && n.members.every((m) => m.source.app_id === "__manual");
  }

  function toScreen(x, y) { return [x * view.k + view.tx, y * view.k + view.ty]; }
  function toWorld(sx, sy) { return [(sx - view.tx) / view.k, (sy - view.ty) / view.k]; }

  /** 線の先端に矢羽を描く。手動リンクの向きを示すため。 */
  function arrowHead(fromX, fromY, toX, toY, radius, color) {
    const ang = Math.atan2(toY - fromY, toX - fromX);
    const tipX = toX - Math.cos(ang) * radius;
    const tipY = toY - Math.sin(ang) * radius;
    const len = 9 / view.k, spread = 0.42;
    ctx.beginPath();
    ctx.moveTo(tipX, tipY);
    ctx.lineTo(tipX - Math.cos(ang - spread) * len, tipY - Math.sin(ang - spread) * len);
    ctx.lineTo(tipX - Math.cos(ang + spread) * len, tipY - Math.sin(ang + spread) * len);
    ctx.closePath();
    ctx.fillStyle = color;
    ctx.fill();
  }

  function edgeLabel(text, mx, my) {
    const label = text.length > 20 ? text.slice(0, 19) + "…" : text;
    if (!label) return;
    ctx.font = `${11 / view.k}px ui-monospace, SFMono-Regular, Menlo, monospace`;
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    const tw = ctx.measureText(label).width;
    ctx.fillStyle = theme.surface;
    ctx.fillRect(mx - tw / 2 - 3 / view.k, my - 7 / view.k, tw + 6 / view.k, 14 / view.k);
    ctx.fillStyle = theme.dim;
    ctx.fillText(label, mx, my);
  }

  function draw() {
    if (!W || !H) return;
    readTheme();
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, W, H);
    ctx.save();
    ctx.translate(view.tx, view.ty);
    ctx.scale(view.k, view.k);

    const labelledDegree = selectedId ? (nodes.get(selectedId)?.degree ?? 0) : 0;

    for (const e of edges.values()) {
      const a = nodes.get(e.a), b = nodes.get(e.b);
      if (!a || !b) continue;
      const lit = selectedId && (e.a === selectedId || e.b === selectedId);

      ctx.beginPath();
      ctx.moveTo(a.x, a.y);
      ctx.lineTo(b.x, b.y);
      ctx.lineWidth = (e.manual ? 1.8 : lit ? 1.7 : 1) / view.k;
      ctx.setLineDash(e.cross && !e.manual ? [5 / view.k, 4 / view.k] : []);
      ctx.strokeStyle = e.manual || e.cross ? theme.focus : theme.line;
      ctx.globalAlpha = e.manual ? 1 : lit ? 1 : e.cross ? 0.9 : 0.65;
      ctx.stroke();
      ctx.setLineDash([]);
      ctx.globalAlpha = 1;

      // 手動リンクは向きが意味を持つので矢羽を出し、ラベルも常に見せる
      if (e.manual) {
        const from = nodes.get(e.from) === a ? a : b;
        const to = from === a ? b : a;
        arrowHead(from.x, from.y, to.x, to.y, radius(to) + 2 / view.k, theme.focus);
        if (view.k > 0.5) edgeLabel([...e.rels][0] || "手動リンク", (a.x + b.x) / 2, (a.y + b.y) / 2);
      } else if (lit && view.k > 0.55 && labelledDegree <= 8) {
        // 選択ノードの次数が多いとラベルが重なって読めなくなるので、少ないときだけ出す
        edgeLabel([...e.rels][0] || "", (a.x + b.x) / 2, (a.y + b.y) / 2);
      }
    }

    // 引きかけの手動リンク
    if (linking) {
      const from = linking.from;
      const tx = linking.target ? linking.target.x : linking.wx;
      const ty = linking.target ? linking.target.y : linking.wy;
      ctx.beginPath();
      ctx.moveTo(from.x, from.y);
      ctx.lineTo(tx, ty);
      ctx.lineWidth = 1.8 / view.k;
      ctx.setLineDash(linking.target ? [] : [6 / view.k, 4 / view.k]);
      ctx.strokeStyle = theme.focus;
      ctx.stroke();
      ctx.setLineDash([]);
      arrowHead(from.x, from.y, tx, ty, linking.target ? radius(linking.target) + 2 / view.k : 0, theme.focus);
    }

    for (const n of nodes.values()) {
      const r = radius(n);
      const color = nodeColor(n);
      const shape = nodeShape(n);
      const manualOnly = isManualOnly(n);
      const isSel = n.id === selectedId;
      const isHov = n.id === hoverId || n === linking?.target;

      if (isSel || n === linking?.target || n.id === pendingLink) {
        ctx.beginPath();
        ctx.arc(n.x, n.y, r + 8, 0, Math.PI * 2);
        ctx.fillStyle = theme.focus;
        ctx.globalAlpha = 0.16;
        ctx.fill();
        ctx.globalAlpha = 1;
      }

      shapePath(shape, n.x, n.y, r);
      ctx.fillStyle = color;
      ctx.globalAlpha = manualOnly ? 0.09 : isSel || isHov ? 0.36 : 0.2;
      ctx.fill();
      ctx.globalAlpha = 1;
      ctx.lineWidth = (isSel ? 2.4 : 1.6) / view.k;
      ctx.strokeStyle = color;
      // 索引に裏付けが無い手動ノードは破線にして、事実と仮説を見分けられるようにする
      if (manualOnly) ctx.setLineDash([3.5 / view.k, 2.5 / view.k]);
      ctx.stroke();
      ctx.setLineDash([]);

      // 複数ソースに畳まれた実体は外側の破線リングで示す（色は種別に使うため）
      if (n.sources.size > 1) {
        ctx.beginPath();
        ctx.arc(n.x, n.y, r + 4.5, 0, Math.PI * 2);
        ctx.lineWidth = 1.2 / view.k;
        ctx.setLineDash([3 / view.k, 3 / view.k]);
        ctx.strokeStyle = theme.focus;
        ctx.stroke();
        ctx.setLineDash([]);
      }

      if (!n.expanded) {
        ctx.beginPath();
        ctx.arc(n.x + r * 0.78, n.y - r * 0.78, 2.6 / view.k, 0, Math.PI * 2);
        ctx.fillStyle = theme.focus;
        ctx.fill();
      }

      // 危険度の印。右上は「未展開」で埋まっているので右下に置く。
      // 色は 1 色（警戒色）だけにして、段階は塗り/中抜き/小点で見分ける
      // ——種別の符号化に使っている色数を増やさないため。
      riskBadge(n, r);

      if (view.k > 0.4) {
        const label = n.label.length > 26 ? n.label.slice(0, 25) + "…" : n.label;
        ctx.font = `${isSel ? "600 " : ""}${11 / view.k}px ui-monospace, SFMono-Regular, Menlo, monospace`;
        ctx.textAlign = "center";
        ctx.textBaseline = "top";
        ctx.fillStyle = isSel || isHov ? theme.ink : theme.dim;
        ctx.fillText(label, n.x, n.y + r + 6 / view.k);
      }
    }

    ctx.restore();
  }

  /** ノード右下の危険度バッジ。clean は何も描かない（印が増えるだけなので）。 */
  function riskBadge(n, r) {
    const level = worstLevel(n);
    if (level === "clean") return;
    const bx = n.x + r * 0.74;
    const by = n.y + r * 0.74;
    const rad = (level === "low" ? 2.6 : 4.2) / view.k;

    // 下地。ノードの塗りや辺の線と重なっても印だと分かるようにする
    ctx.beginPath();
    ctx.arc(bx, by, rad + 1.4 / view.k, 0, Math.PI * 2);
    ctx.fillStyle = theme.surface;
    ctx.fill();

    ctx.beginPath();
    ctx.arc(bx, by, rad, 0, Math.PI * 2);
    if (level === "high") {
      ctx.fillStyle = theme.crit;
      ctx.fill();
    } else if (level === "elevated") {
      ctx.lineWidth = 1.6 / view.k;
      ctx.strokeStyle = theme.crit;
      ctx.stroke();
    } else {
      ctx.fillStyle = theme.faint;
      ctx.fill();
    }
  }

  const settleWaiters = [];

  function loop() {
    step();
    draw();
    if (alpha > 0.012 || dragNode) {
      raf = requestAnimationFrame(loop);
    } else {
      raf = null;
      while (settleWaiters.length) settleWaiters.pop()();
    }
  }

  /** レイアウトが落ち着くまで待つ。fit() をかける前に使う。 */
  function whenSettled({ timeout = 2500 } = {}) {
    if (!raf) return Promise.resolve();
    return new Promise((resolve) => {
      const done = () => { clearTimeout(timer); resolve(); };
      const timer = setTimeout(() => {
        const i = settleWaiters.indexOf(done);
        if (i >= 0) settleWaiters.splice(i, 1);
        resolve();
      }, timeout);
      settleWaiters.push(done);
    });
  }

  function kick() {
    if (reduceMotion) {
      for (let i = 0; i < 320; i++) step();
      draw();
      return;
    }
    if (!raf) raf = requestAnimationFrame(loop);
  }

  function fit() {
    if (!nodes.size) { view.k = 1; view.tx = 0; view.ty = 0; draw(); return; }
    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    for (const n of nodes.values()) {
      minX = Math.min(minX, n.x); maxX = Math.max(maxX, n.x);
      minY = Math.min(minY, n.y); maxY = Math.max(maxY, n.y);
    }
    // 下辺は凡例が重なるので余白を多めに取る
    const padX = 70, padTop = 60, padBottom = 96;
    const k = Math.min(2, Math.max(0.25, Math.min(
      (W - padX * 2) / Math.max(1, maxX - minX),
      (H - padTop - padBottom) / Math.max(1, maxY - minY))));
    view.k = k;
    view.tx = W / 2 - ((minX + maxX) / 2) * k;
    view.ty = (padTop + (H - padBottom)) / 2 - ((minY + maxY) / 2) * k;
    draw();
  }

  function relayout() {
    for (const n of nodes.values()) {
      n.pinned = false;
      n.vx += (Math.random() - 0.5) * 26;
      n.vy += (Math.random() - 0.5) * 26;
    }
    alpha = 0.9;
    kick();
  }

  /* ---------------- 入力 ---------------- */

  function pointer(ev) {
    const r = canvas.getBoundingClientRect();
    return toWorld(ev.clientX - r.left, ev.clientY - r.top);
  }

  function pick(wx, wy) {
    let best = null, bd = Infinity;
    for (const n of nodes.values()) {
      const dx = wx - n.x, dy = wy - n.y;
      const d2 = dx * dx + dy * dy;
      const rr = radius(n) + 9;
      if (d2 < rr * rr && d2 < bd) { bd = d2; best = n; }
    }
    return best;
  }

  canvas.addEventListener("pointerdown", (ev) => {
    const [wx, wy] = pointer(ev);
    const n = pick(wx, wy);
    moved = false;
    canvas.setPointerCapture(ev.pointerId);

    // ボタンでリンク待ちのときは、次のクリックが相手の指定になる
    if (pendingLink && n && n.id !== pendingLink) {
      const from = nodes.get(pendingLink);
      pendingLink = null;
      canvas.style.cursor = "grab";
      addManualEdge(from.id, n.id);
      onStatus?.({ message: `${from.label} → ${n.label} にリンクを張りました` });
      return;
    }

    // Ctrl（Mac は Cmd）を押しながらノードから引くと手動リンクになる
    if (n && (ev.ctrlKey || ev.metaKey)) {
      ev.preventDefault();
      linking = { from: n, wx, wy, target: null };
      select(n.id);
      onStatus?.({ message: `${n.label} からリンクを引いています — 相手のノードで離してください（Esc で取り消し）` });
      draw();
      return;
    }

    if (n) {
      dragNode = n;
      select(n.id);
      alpha = Math.max(alpha, 0.3);
      kick();
    } else {
      panning = { x: ev.clientX, y: ev.clientY, tx: view.tx, ty: view.ty };
    }
  });

  canvas.addEventListener("pointermove", (ev) => {
    if (linking) {
      const [wx, wy] = pointer(ev);
      linking.wx = wx; linking.wy = wy;
      const hit = pick(wx, wy);
      linking.target = hit && hit !== linking.from ? hit : null;
      canvas.style.cursor = linking.target ? "alias" : "crosshair";
      draw();
      return;
    }
    if (dragNode) {
      const [wx, wy] = pointer(ev);
      dragNode.x = wx; dragNode.y = wy;
      dragNode.vx = 0; dragNode.vy = 0;
      moved = true;
      if (reduceMotion) draw(); else kick();
      return;
    }
    if (panning) {
      view.tx = panning.tx + (ev.clientX - panning.x);
      view.ty = panning.ty + (ev.clientY - panning.y);
      moved = true;
      draw();
      return;
    }
    const [wx, wy] = pointer(ev);
    const n = pick(wx, wy);
    const id = n ? n.id : null;
    if (id !== hoverId) {
      hoverId = id;
      canvas.style.cursor = n ? "pointer" : "grab";
      draw();
    }
  });

  function endPointer() {
    if (linking) {
      const { from, target } = linking;
      linking = null;
      canvas.style.cursor = "grab";
      if (target) {
        addManualEdge(from.id, target.id);
        onStatus?.({ message: `${from.label} → ${target.label} にリンクを張りました` });
      } else {
        onStatus?.({ message: "リンクを取り消しました（相手のノード上で離してください）" });
      }
      draw();
      return;
    }
    if (dragNode && moved) dragNode.pinned = true;
    const changed = moved && (dragNode || panning);
    dragNode = null;
    panning = null;
    kick();
    if (changed) onMutate?.();
  }

  canvas.addEventListener("pointerup", endPointer);
  canvas.addEventListener("pointercancel", endPointer);
  canvas.addEventListener("pointerleave", () => { hoverId = null; draw(); });

  window.addEventListener("keydown", (ev) => {
    if (ev.key === "Escape" && (linking || pendingLink)) {
      cancelLink();
      onStatus?.({ message: "リンクを取り消しました" });
    }
  });

  canvas.addEventListener("dblclick", (ev) => {
    const [wx, wy] = pointer(ev);
    const n = pick(wx, wy);
    if (n) expand(n);
  });

  // 右クリック。ノードの上なら調査メニューを開く（何も無い場所では既定の動作に任せる）
  canvas.addEventListener("contextmenu", (ev) => {
    const [wx, wy] = pointer(ev);
    const n = pick(wx, wy);
    if (!n) return;
    ev.preventDefault();
    selectedId = n.id;
    draw();
    notify();
    onContext?.(n, { x: ev.clientX, y: ev.clientY });
  });

  canvas.addEventListener("wheel", (ev) => {
    ev.preventDefault();
    const r = canvas.getBoundingClientRect();
    const sx = ev.clientX - r.left, sy = ev.clientY - r.top;
    const [wx, wy] = toWorld(sx, sy);
    const k = Math.min(3, Math.max(0.2, view.k * (ev.deltaY < 0 ? 1.12 : 1 / 1.12)));
    view.k = k;
    view.tx = sx - wx * k;
    view.ty = sy - wy * k;
    draw();
  }, { passive: false });

  function resize() {
    const r = canvas.parentElement.getBoundingClientRect();
    if (!r.width || !r.height) return;
    const hadSize = W > 0;
    dpr = window.devicePixelRatio || 1;
    W = r.width; H = r.height;
    canvas.width = Math.round(W * dpr);
    canvas.height = Math.round(H * dpr);
    // 幅が確定する前に置かれたノードは原点付近に固まってしまうので中央へ寄せ直す
    if (!hadSize && nodes.size) recenter();
    draw();
  }

  function recenter() {
    let sx = 0, sy = 0;
    for (const n of nodes.values()) { sx += n.x; sy += n.y; }
    const dx = W / 2 - sx / nodes.size;
    const dy = H / 2 - sy / nodes.size;
    for (const n of nodes.values()) { n.x += dx; n.y += dy; }
  }

  if (window.ResizeObserver) new ResizeObserver(resize).observe(canvas.parentElement);
  window.addEventListener("resize", resize);
  new MutationObserver(() => draw()).observe(document.documentElement, {
    attributes: true, attributeFilter: ["data-theme"],
  });
  window.matchMedia("(prefers-color-scheme: dark)").addEventListener?.("change", () => draw());

  /** 別画面に移ったりリロードしても復元できるよう、グラフの状態を書き出す。 */
  function serialize() {
    return {
      v: 2,
      nodes: [...nodes.values()].map((n) => ({
        id: n.id,
        x: Math.round(n.x), y: Math.round(n.y),
        pinned: !!n.pinned, expanded: !!n.expanded,
        m: n.members.map((m) => [m.source.app_id, m.entity.id]),
      })),
      edges: [...edges.values()].map((e) => ({
        a: e.a, b: e.b, rels: [...e.rels],
        cross: e.cross ? 1 : 0,
        manual: e.manual ? 1 : 0,
        from: e.manual ? e.from : undefined,
      })),
      view: { k: view.k, tx: view.tx, ty: view.ty },
      selected: selectedId,
    };
  }

  /** serialize() の出力から復元する。ソースが読み込み済みである必要がある。 */
  function restore(snap) {
    if (!snap || (snap.v !== 1 && snap.v !== 2)) return 0;
    nodes.clear();
    edges.clear();
    selectedId = null;
    let restored = 0;

    for (const sn of snap.nodes || []) {
      let node = null;
      for (const [appId, entId] of sn.m || []) {
        const src = getSource(appId);
        const entity = src?.byId?.get(entId);
        if (!entity) continue;
        node = addEntityInfo(src, entity, { x: sn.x, y: sn.y }).node;
      }
      if (!node) continue;              // ソース側から消えた実体は黙って落とす
      node.x = sn.x; node.y = sn.y;
      node.vx = 0; node.vy = 0;
      node.pinned = !!sn.pinned;
      node.expanded = !!sn.expanded;
      restored++;
    }

    for (const raw of snap.edges || []) {
      // v1 は配列、v2 はオブジェクト
      const e = Array.isArray(raw)
        ? { a: raw[0], b: raw[1], rels: raw[2], cross: raw[3] }
        : raw;
      if (!nodes.has(e.a) || !nodes.has(e.b)) continue;
      const edge = addEdge(e.a, e.b, null, !!e.cross);
      if (!edge) continue;
      for (const r of e.rels || []) edge.rels.add(r);
      if (e.manual) {
        edge.manual = true;
        edge.from = nodes.has(e.from) ? e.from : e.a;
      }
    }

    if (snap.view) { view.k = snap.view.k ?? 1; view.tx = snap.view.tx ?? 0; view.ty = snap.view.ty ?? 0; }
    if (snap.selected && nodes.has(snap.selected)) selectedId = snap.selected;
    recountDegrees();
    alpha = 0.05;                        // 位置は保存値を尊重し、揺らさない
    draw();
    notify();
    return restored;
  }

  return {
    addRoot, addEntity, addEdge, addManualEdge, removeEdge, setEdgeRel,
    beginLink, cancelLink, screenOf,
    expand, remove, keepOnly, clear, select, fit, relayout, resize,
    linkExisting, whenSettled, serialize, restore,
    exportPng: () => canvas.toDataURL("image/png"),
    get nodes() { return nodes; },
    get edges() { return edges; },
    get selected() { return selectedId ? nodes.get(selectedId) : null; },
    get counts() { return { nodes: nodes.size, edges: edges.size }; },
    kick,
  };
}
