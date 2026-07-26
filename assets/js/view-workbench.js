// ワークベンチ。グラフ調査と、選択した値をその場で変換するモジュール。
//
// 調査中の状態（調査対象トレイとグラフ）は localStorage に保存する。
// 別のモードに移ってもリロードしても続きから調査できるようにするため。

import { createGraph } from "./graph.js";
import { deepLink, graphLink, loadAllSources, resolveValue, store } from "./store.js";
import { parseAny, toMermaid, toStix } from "./exchange.js";
import { lookup, providersFor } from "./osint.js";
import { OPS, runChain } from "./transform.js";
import { TYPE_GROUPS, el, shorten, typeGroup, typeLabel } from "./util.js";

const STORE_KEY = "rb-workbench-v1";

let ui = null;
let tray = [];          // [{ value, type }]
let restoring = false;

/* ---------------- 保存と復元 ---------------- */

function saveState() {
  if (!ui || restoring) return;
  try {
    localStorage.setItem(STORE_KEY, JSON.stringify({
      v: 1,
      tray,
      collapsed: ui.trayEl.dataset.collapsed === "true",
      graph: ui.graph.serialize(),
    }));
  } catch {
    // 容量超過やプライベートモードでは黙って諦める。調査自体は続けられる。
  }
}

function readState() {
  try {
    const raw = localStorage.getItem(STORE_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

function clearState() {
  try { localStorage.removeItem(STORE_KEY); } catch { /* 消せなくても支障はない */ }
}

/* ---------------- 組み立て ---------------- */

export async function renderWorkbench(root, { onQuery } = {}) {
  if (ui && root.contains(ui.wrap)) {
    ui.graph.resize();
    return ui;
  }

  const canvas = el("canvas");
  const status = el("span", { class: "wb-count" });

  const exportBtn = el("button", {
    class: "btn", type: "button", text: "書き出し ▾",
    "aria-haspopup": "true", "aria-expanded": "false",
    onclick: (ev) => { ev.stopPropagation(); toggleExportMenu(ev.target); },
  });

  const importInput = el("input", {
    type: "file", accept: ".mmd,.mermaid,.md,.json,.txt,text/plain,application/json",
    hidden: true,
    onchange: async (ev) => {
      const file = ev.target.files?.[0];
      ev.target.value = "";
      if (file) await importFile(file);
    },
  });

  const tools = el("div", { class: "wb-tools" }, [
    el("button", { class: "btn", type: "button", text: "全体表示", onclick: () => ui.graph.fit() }),
    el("button", { class: "btn", type: "button", text: "再レイアウト", onclick: () => ui.graph.relayout() }),
    exportBtn,
    el("button", {
      class: "btn", type: "button", text: "読み込み",
      title: "Mermaid / STIX 2.1 のファイルからグラフを復元する",
      onclick: () => importInput.click(),
    }),
    el("button", {
      class: "btn", type: "button", text: "クリア",
      onclick: () => {
        ui.graph.clear();
        tray = [];
        renderTray();
        clearState();
        renderSide(null);
      },
    }),
    status,
  ]);

  // 凡例は「エンティティ種別」で並べる。色と形はここで決まる（出典はサイドバー）
  const legend = el("div", { class: "wb-legend" }, [
    ...Object.entries(TYPE_GROUPS).map(([key, g]) =>
      el("span", { class: "lg", style: `color:var(${g.color})`, html: shapeGlyph(g.shape) + escapeText(g.label) })),
    el("span", { class: "lg is-dashed", style: "color:var(--ink-dim)", html: '<i></i>手動追加（索引に無い）' }),
    el("span", { class: "lg is-ring", style: "color:var(--focus)", html: '<i></i>複数ソースに存在' }),
    el("span", { class: "lg is-arrow", style: "color:var(--focus)", html: '<i></i>手動リンク' }),
  ]);

  const canvasWrap = el("div", { class: "wb-canvas-wrap" }, [tools, canvas, legend, importInput]);

  /* --- 調査対象トレイ --- */

  const trayInput = el("input", {
    type: "search", spellcheck: "false", "aria-label": "調査対象を追加",
    placeholder: "IP / ドメイン / ハッシュ",
  });
  const trayForm = el("form", { class: "tray-add" }, [
    trayInput,
    el("button", { class: "btn", type: "submit", text: "追加" }),
  ]);
  trayForm.addEventListener("submit", (ev) => {
    ev.preventDefault();
    const raw = trayInput.value.trim();
    if (!raw) return;
    const added = addValue(raw);
    if (added) trayInput.value = "";
  });

  const trayList = el("ul", { class: "tray-list" });
  const trayCount = el("span", { class: "tray-count", title: "調査対象の件数" });
  const trayToggle = el("button", {
    class: "tray-toggle", type: "button", "aria-label": "調査対象トレイの開閉",
    onclick: () => {
      const collapsed = ui.trayEl.dataset.collapsed === "true";
      ui.trayEl.dataset.collapsed = String(!collapsed);
      trayToggle.innerHTML = caretIcon(!collapsed);
      ui.graph.resize();
      saveState();
    },
  });
  trayToggle.innerHTML = caretIcon(false);

  const trayEl = el("div", { class: "wb-tray", "data-collapsed": "false" }, [
    el("div", { class: "tray-body" }, [
      el("h3", { class: "side-h", style: "margin:0", text: "調査対象" }),
      trayForm,
      trayList,
    ]),
    el("div", { class: "tray-rail" }, [trayToggle, trayCount]),
  ]);

  /* --- 右パネル --- */

  const paneDetail = el("div", { class: "tabpane", id: "wbDetail", role: "tabpanel" });
  const paneTransform = el("div", { class: "tabpane", id: "wbTransform", role: "tabpanel", hidden: true });
  const paneOsint = el("div", { class: "tabpane", id: "wbOsint", role: "tabpanel", hidden: true });

  const tabDetail = el("button", {
    class: "tab", type: "button", role: "tab", text: "詳細",
    "aria-selected": "true", "aria-controls": "wbDetail",
  });
  const tabTransform = el("button", {
    class: "tab", type: "button", role: "tab", text: "変換",
    "aria-selected": "false", "aria-controls": "wbTransform",
  });
  const tabOsint = el("button", {
    class: "tab", type: "button", role: "tab", text: "OSINT",
    "aria-selected": "false", "aria-controls": "wbOsint",
  });

  const TABS = [
    ["detail", tabDetail, paneDetail],
    ["transform", tabTransform, paneTransform],
    ["osint", tabOsint, paneOsint],
  ];

  function selectTab(which) {
    for (const [name, tab, pane] of TABS) {
      const on = name === which;
      tab.setAttribute("aria-selected", String(on));
      pane.hidden = !on;
    }
    if (which === "osint") renderOsint(ui?.graph.selected);
  }

  for (const [name, tab] of TABS) tab.addEventListener("click", () => selectTab(name));

  const side = el("aside", { class: "wb-side" }, [
    el("div", { class: "tabs", role: "tablist" }, [tabDetail, tabTransform, tabOsint]),
    paneDetail,
    paneTransform,
    paneOsint,
  ]);

  const wrap = el("div", { class: "wb" }, [trayEl, canvasWrap, side]);
  root.replaceChildren(wrap);

  const graph = createGraph(canvas, {
    onSelect: (node, counts) => {
      status.textContent = `ノード ${counts.nodes} / 辺 ${counts.edges}`;
      renderSide(node);
      markTraySelection(node);
    },
    onStatus: (s) => {
      if (s.error) status.textContent = s.error;
      else if (s.message) status.textContent = s.message;
    },
    onMutate: saveState,
  });
  graph.resize();

  ui = { wrap, graph, side, paneDetail, paneTransform, paneOsint, selectTab, status, onQuery,
    trayEl, trayList, trayCount };
  // UI テストから座標を取るためのフック。?uitest=1 が無ければ生えない。
  if (new URLSearchParams(location.search).has("uitest")) window.__rbGraph = graph;
  renderTray();
  renderSide(null);

  // 索引が無いと展開も復元もできないので、読み込みを待ってから状態を戻す
  loadAllSources().then(() => {
    if (!ui) return;
    restoreState();
    renderSide(graph.selected);
  });

  return ui;
}

function escapeText(t) {
  return String(t).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
}

/** 凡例と詳細パネルで使う、Canvas の形と揃えた小さな図形。 */
export function shapeGlyph(shape, size = 11) {
  const c = size / 2, r = size * 0.42;
  const poly = (n, rot, rad = r) => Array.from({ length: n }, (_, i) => {
    const a = rot + (i / n) * Math.PI * 2;
    return `${(c + Math.cos(a) * rad).toFixed(2)},${(c + Math.sin(a) * rad).toFixed(2)}`;
  }).join(" ");
  const T = -Math.PI / 2;
  let body;
  if (shape === "square") body = `<rect x="${c - r}" y="${c - r}" width="${r * 2}" height="${r * 2}"/>`;
  else if (shape === "roundsquare") body = `<rect x="${c - r}" y="${c - r}" width="${r * 2}" height="${r * 2}" rx="${r * 0.45}"/>`;
  else if (shape === "diamond") body = `<polygon points="${poly(4, T, r * 1.18)}"/>`;
  else if (shape === "triangle") body = `<polygon points="${poly(3, T, r * 1.24)}"/>`;
  else if (shape === "pentagon") body = `<polygon points="${poly(5, T, r * 1.1)}"/>`;
  else if (shape === "hexagon") body = `<polygon points="${poly(6, T, r * 1.08)}"/>`;
  else if (shape === "ring") body = `<circle cx="${c}" cy="${c}" r="${r}" stroke-dasharray="2 1.6"/>`;
  else body = `<circle cx="${c}" cy="${c}" r="${r}"/>`;
  return `<svg class="glyph" viewBox="0 0 ${size} ${size}" width="${size}" height="${size}" aria-hidden="true"
    fill="currentColor" fill-opacity="0.24" stroke="currentColor" stroke-width="1.2">${body}</svg>`;
}

function caretIcon(pointRight) {
  const path = pointRight ? "m3 2 4 4-4 4" : "m7 2-4 4 4 4";
  return `<svg viewBox="0 0 10 12" fill="none" stroke="currentColor" stroke-width="1.4"
    stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="${path}"/></svg>`;
}

function restoreState() {
  const snap = readState();
  if (!snap || snap.v !== 1) return;
  restoring = true;
  try {
    ui.trayEl.dataset.collapsed = String(!!snap.collapsed);
    ui.trayEl.querySelector(".tray-toggle").innerHTML = caretIcon(!!snap.collapsed);

    // トレイの値を先に復元する。手動ノードの実体をここで作り直す必要がある。
    tray = [];
    for (const item of snap.tray || []) {
      const res = resolveValue(item.value, { typeHint: item.type });
      if (res) tray.push({ value: res.value, type: res.type });
    }
    renderTray();

    const n = ui.graph.restore(snap.graph);
    if (n) ui.status.textContent = `前回の状態を復元しました（ノード ${n}）`;
  } finally {
    restoring = false;
  }
  ui.graph.resize();
}

/* ---------------- 調査対象トレイ ---------------- */

/** 値を索引に突き合わせてグラフに載せる。トレイにも登録する。 */
function addValue(raw) {
  const res = resolveValue(raw);
  if (!res) return null;

  let node = null;
  for (const b of res.matches) node = ui.graph.addRoot(b.source, b.entity);
  ui.graph.linkExisting();

  if (!tray.some((t) => t.value.toLowerCase() === res.value.toLowerCase())) {
    tray.push({ value: res.value, type: res.type });
  }
  renderTray();
  markTraySelection(node);

  const srcCount = new Set(res.matches.map((b) => b.source.app_id)).size;
  ui.status.textContent = res.manual
    ? `${res.value} を手動ノードとして追加しました（索引には見つかりません）`
    : `${res.value} を追加しました（${srcCount} ソース）`;

  // 落ち着いてから枠に収める。追加を連続でしても最後の 1 回だけ効く。
  ui.graph.whenSettled({ timeout: 1200 }).then(() => ui?.graph.fit());
  saveState();
  return node;
}

function renderTray() {
  if (!ui) return;
  ui.trayCount.textContent = tray.length ? String(tray.length) : "";
  ui.trayCount.title = `調査対象 ${tray.length} 件`;
  ui.trayList.replaceChildren();

  if (!tray.length) {
    ui.trayList.append(el("li", { class: "tray-empty" }, [
      "調べたい IP・ドメイン・ハッシュを上の欄から足すと、グラフに載ります。索引に無い値も手動ノードとして置けます。",
    ]));
    return;
  }

  for (const item of tray) {
    const res = resolveValue(item.value);
    const srcs = res ? new Set(res.matches.map((b) => b.source.app_id)) : new Set();
    const manual = !res || res.manual;
    const accent = `var(${TYPE_GROUPS[typeGroup(item.type)].color})`;

    const del = el("button", {
      class: "tray-del", type: "button", text: "×", title: "トレイから外す",
      "aria-label": `${item.value} をトレイから外す`,
      onclick: (ev) => {
        ev.stopPropagation();
        tray = tray.filter((t) => t !== item);
        renderTray();
        saveState();
      },
    });

    const row = el("button", {
      class: "tray-item", type: "button", style: `color:${accent}`,
      title: `${item.value}（${typeLabel(item.type)}）`,
      dataset: { value: item.value },
      onclick: () => focusValue(item.value),
    }, [
      el("span", {}, [
        el("span", { class: "tray-item-val", text: shorten(item.value, 24) }),
        el("span", { class: "tray-item-meta", text: manual ? "手動" : `${srcs.size} ソース` }),
      ]),
      del,
    ]);

    ui.trayList.append(el("li", {}, [row]));
  }
}

/** トレイの項目に対応するノードを選択する。無ければ載せ直す。 */
function focusValue(value) {
  const res = resolveValue(value);
  if (!res) return;
  let node = null;
  for (const b of res.matches) node = ui.graph.addRoot(b.source, b.entity);
  ui.graph.linkExisting();
  if (node) ui.graph.select(node.id);
  ui.graph.whenSettled({ timeout: 1200 }).then(() => ui?.graph.fit());
}

function markTraySelection(node) {
  if (!ui) return;
  const label = node?.label?.toLowerCase() || null;
  for (const row of ui.trayList.querySelectorAll(".tray-item")) {
    row.setAttribute("aria-current", String(!!label && row.dataset.value.toLowerCase() === label));
  }
}

/** クロスサーチなどからノードを 1 件立てる。 */
export async function pivotTo(source, entity) {
  if (!ui) return;
  ui.graph.resize();
  ui.graph.addRoot(source, entity);
  ui.graph.linkExisting();
  const node = ui.graph.selected;
  if (node && !node.expanded) await ui.graph.expand(node);
  await ui.graph.whenSettled();
  ui.graph.fit();
  saveState();
}

/* ---------------- 書き出しと読み込み ---------------- */

let exportMenu = null;

function toggleExportMenu(anchor) {
  if (exportMenu) { exportMenu.remove(); exportMenu = null; anchor.setAttribute("aria-expanded", "false"); return; }

  const pick = (fn) => () => { fn(); exportMenu?.remove(); exportMenu = null; anchor.setAttribute("aria-expanded", "false"); };
  exportMenu = el("div", { class: "popover", role: "menu" }, [
    el("div", { class: "menu-label", text: "書き出し" }),
    el("button", { class: "popover-item", type: "button", role: "menuitem", text: "Mermaid (.mmd)", onclick: pick(exportMermaid) }),
    el("button", { class: "popover-item", type: "button", role: "menuitem", text: "STIX 2.1 (.json)", onclick: pick(exportStix) }),
    el("button", { class: "popover-item", type: "button", role: "menuitem", text: "PNG (.png)", onclick: pick(exportPng) }),
  ]);
  exportMenu.addEventListener("click", (ev) => ev.stopPropagation());
  document.body.append(exportMenu);
  const r = anchor.getBoundingClientRect();
  exportMenu.style.left = `${Math.min(r.left, innerWidth - exportMenu.offsetWidth - 8)}px`;
  exportMenu.style.top = `${r.bottom + 5}px`;
  anchor.setAttribute("aria-expanded", "true");
  setTimeout(() => document.addEventListener("click", closeExportMenu, { once: true }), 0);
}

function closeExportMenu() {
  exportMenu?.remove();
  exportMenu = null;
  ui?.wrap.querySelector('[aria-haspopup="true"]')?.setAttribute("aria-expanded", "false");
}

function stamp() {
  const d = new Date();
  const p = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}`;
}

function download(filename, text, mime) {
  const url = URL.createObjectURL(new Blob([text], { type: mime }));
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 4000);
}

function exportMermaid() {
  if (!ui.graph.nodes.size) { ui.status.textContent = "書き出すノードがありません"; return; }
  const cs = getComputedStyle(document.documentElement);
  const text = toMermaid(ui.graph, (v) => cs.getPropertyValue(v).trim());
  download(`workbench-${stamp()}.mmd`, text, "text/plain;charset=utf-8");
  ui.status.textContent = `Mermaid を書き出しました（ノード ${ui.graph.nodes.size} / 辺 ${ui.graph.edges.size}）`;
}

function exportStix() {
  if (!ui.graph.nodes.size) { ui.status.textContent = "書き出すノードがありません"; return; }
  const bundle = toStix(ui.graph);
  download(`workbench-${stamp()}.stix.json`, JSON.stringify(bundle, null, 2), "application/json;charset=utf-8");
  ui.status.textContent = `STIX 2.1 を書き出しました（オブジェクト ${bundle.objects.length}）`;
}

function exportPng() {
  const a = document.createElement("a");
  a.href = ui.graph.exportPng();
  a.download = `workbench-${stamp()}.png`;
  a.click();
}

async function importFile(file) {
  ui.status.textContent = `${file.name} を読み込んでいます…`;
  try {
    const parsed = parseAny(await file.text(), file.name);
    await loadAllSources();          // 索引に突き合わせて出典を復元するため
    const r = importGraph(parsed);
    ui.status.textContent = `${parsed.format === "stix" ? "STIX" : "Mermaid"} を読み込みました — `
      + `ノード ${r.nodes}（うち索引に無いもの ${r.manual}） / リンク ${r.links}`
      + (r.skipped ? ` / 解決できず ${r.skipped}` : "");
  } catch (err) {
    ui.status.textContent = `読み込めませんでした: ${err.message}`;
  }
}

/**
 * 読み込んだ内容をグラフに反映する。
 * 値は索引に突き合わせ直すので、ファイルを作ったときより索引が新しければ
 * 出典やソース横断がその場で付く。索引に無い値は手動ノードとして置く。
 */
function importGraph(parsed) {
  const keyToNode = new Map();
  let manual = 0, skipped = 0;

  for (const n of parsed.nodes) {
    const res = resolveValue(n.value, { typeHint: n.type });
    if (!res) { skipped++; continue; }
    let node = null;
    for (const b of res.matches) node = ui.graph.addRoot(b.source, b.entity);
    if (!node) { skipped++; continue; }
    keyToNode.set(n.key, node.id);
    if (res.manual) manual++;
  }

  ui.graph.linkExisting();

  let links = 0;
  for (const e of parsed.edges) {
    const a = keyToNode.get(e.from), b = keyToNode.get(e.to);
    if (!a || !b || a === b) continue;
    const already = [...ui.graph.edges.values()]
      .some((x) => (x.a === a && x.b === b) || (x.a === b && x.b === a));
    // ソース由来で既に繋がっているものは張り直さない。手動リンクだけ復元する。
    if (already && !e.manual) continue;
    if (ui.graph.addManualEdge(a, b, e.rel)) links++;
  }

  ui.graph.whenSettled({ timeout: 1500 }).then(() => ui?.graph.fit());
  saveState();
  return { nodes: keyToNode.size, manual, links, skipped };
}

/* ---------------- 詳細タブ ---------------- */

function renderSide(node) {
  if (!ui) return;
  const pane = ui.paneDetail;

  if (!node) {
    pane.replaceChildren(el("div", { class: "side-empty" }, [
      "左のトレイに調査対象を足すか、クロスサーチの結果から「グラフで開く」を押してください。"
      + "ノードのダブルクリックで関連を展開します。",
    ]));
    renderTransform(null);
    return;
  }

  const group = TYPE_GROUPS[typeGroup(node.type)];
  const accent = `var(${group.color})`;
  const frag = document.createDocumentFragment();

  frag.append(
    el("span", {
      class: "side-type", style: `color:${accent}`,
      html: shapeGlyph(group.shape) + escapeText(node.type),
    }),
    el("p", { class: "side-label", text: node.label }),
    el("p", { class: "side-empty", text: `${typeLabel(node.type)} — ${group.label}` }),
  );

  frag.append(el("div", { class: "tf-row", style: "margin-top:12px" }, [
    el("button", {
      class: "btn", type: "button",
      text: node.expanded ? "さらに展開" : "展開",
      onclick: async (ev) => {
        ev.target.disabled = true;
        const r = await ui.graph.expand(node);
        const parts = [`${r.added} 件を追加`];
        if (r.joined) parts.push(`${r.joined} 件が別ソースと結合`);
        if (r.skipped) parts.push(`${r.skipped} 件は上限で省略`);
        ui.status.textContent = parts.join(" / ");
      },
    }),
    el("button", {
      class: "btn" + (node.pinned ? " is-on" : ""), type: "button",
      text: node.pinned ? "ピン解除" : "ピン留め",
      onclick: () => { node.pinned = !node.pinned; ui.graph.kick(); renderSide(node); saveState(); },
    }),
    el("button", {
      class: "btn", type: "button", text: "トレイに入れる",
      onclick: () => { addValue(node.label); },
    }),
    el("button", {
      class: "btn", type: "button", text: "リンクを張る",
      onclick: (ev) => {
        ui.graph.beginLink(node.id);
        ev.target.classList.add("is-on");
        ui.status.textContent = `${node.label} からリンクを張ります — 相手のノードをクリックしてください（Esc で取り消し）`;
      },
    }),
    el("button", { class: "btn", type: "button", text: "削除", onclick: () => ui.graph.remove(node.id) }),
  ]));

  frag.append(el("p", {
    class: "side-empty", style: "margin-top:8px",
    text: "Ctrl（Mac は Cmd）を押しながらノードから他のノードへドラッグしてもリンクを張れます。",
  }));

  frag.append(el("h3", { class: "side-h", text: `出典ソース ${node.members.length}` }));
  const srcList = el("ul", { class: "side-list" });
  for (const m of node.members) {
    const href = deepLink(m.entity);
    const gHref = graphLink(m.entity);
    const row = el(href ? "a" : "div", {
      class: "side-src",
      style: `color:var(--src-${m.source.accent})`,
      href: href || null,
      target: href ? "_blank" : null,
      rel: href ? "noopener" : null,
      title: gHref ? "詳細ページを開く" : null,
    }, [
      el("span", { class: "ctx-dot" }),
      el("span", { style: "color:var(--ink)", text: m.source.name }),
      el("span", { class: "go", text: href ? "開く →" : "リンク未設定" }),
    ]);
    srcList.append(el("li", {}, [row]));
  }
  frag.append(srcList);

  const attrs = collectAttrs(node);
  if (attrs.length) {
    frag.append(el("h3", { class: "side-h", text: "属性" }));
    const dl = el("dl", { class: "side-attrs" });
    for (const [k, v] of attrs) dl.append(el("dt", { text: k }), el("dd", { text: v }));
    frag.append(dl);
  }

  const rels = relationsOf(node);
  const manualCount = rels.filter((r) => r.manual).length;
  frag.append(el("h3", {
    class: "side-h",
    text: manualCount ? `関連 ${rels.length}（うち手動 ${manualCount}）` : `関連 ${rels.length}`,
  }));
  if (rels.length) {
    const list = el("div", { class: "side-list" });
    for (const r of rels.slice(0, 60)) {
      if (!r.manual) {
        list.append(el("button", {
          class: "side-rel", type: "button", title: r.label,
          onclick: () => { ui.graph.select(r.nodeId); },
        }, [
          el("em", { text: r.rel }),
          el("span", { text: shorten(r.label, 30) }),
        ]));
        continue;
      }
      // 手動リンクは自分の記述なので、名前を変えられて消せる
      const relInput = el("input", {
        class: "rel-edit", type: "text", value: r.rel, "aria-label": "リンクの名前",
        onchange: (ev) => ui.graph.setEdgeRel(r.edgeId, ev.target.value.trim()),
      });
      list.append(el("div", { class: "side-rel is-manual" }, [
        relInput,
        el("button", {
          class: "rel-go", type: "button", title: r.label, text: shorten(r.label, 22),
          onclick: () => ui.graph.select(r.nodeId),
        }),
        el("button", {
          class: "tray-del", type: "button", text: "×", title: "このリンクを消す",
          "aria-label": `${r.rel} のリンクを消す`,
          onclick: () => { ui.graph.removeEdge(r.edgeId); renderSide(node); },
        }),
      ]));
    }
    frag.append(list);
  } else {
    frag.append(el("p", {
      class: "side-empty",
      text: node.expanded ? "これ以上の関連はありません。" : "「展開」を押すと関連を取り込みます。",
    }));
  }

  pane.replaceChildren(frag);
  renderTransform(node);
  renderOsint(node);
}

/* ---------------- OSINT タブ ---------------- */

function renderOsint(node) {
  if (!ui) return;
  const pane = ui.paneOsint;

  if (!node) {
    pane.replaceChildren(el("p", { class: "side-empty", text: "ノードを選ぶと、その値を OSINT サービスに照会できます。" }));
    return;
  }

  const value = node.label;
  const type = node.type;
  const providers = providersFor(type);
  const frag = document.createDocumentFragment();

  frag.append(
    el("h3", { class: "side-h", style: "margin-top:0", text: "照会する値" }),
    el("p", { class: "side-label", text: value }),
  );

  if (!providers.length) {
    frag.append(el("p", { class: "side-empty", text: `${typeLabel(type)} に対応する OSINT サービスはありません。` }));
    pane.replaceChildren(frag);
    return;
  }

  const results = el("div", { class: "osint-results" });

  frag.append(el("h3", { class: "side-h", text: "サービス" }));
  for (const p of providers) {
    const row = el("div", { class: "osint-provider" });
    const state = el("span", { class: "osint-state" });

    const run = el("button", {
      class: "btn", type: "button", text: "照会",
      disabled: !p.callable || null,
      title: p.callable ? null
        : p.needsRelay ? "このサービスは CORS を許可していないため、中継の設定が必要です"
        : "API キーが設定されていません",
      onclick: async () => {
        run.disabled = true;
        state.className = "osint-state";
        state.textContent = "照会中…";
        try {
          const out = await lookup(p.id, value, type);
          state.textContent = "";
          results.replaceChildren(renderOsintResult(p, out, node));
        } catch (err) {
          state.className = "osint-state is-error";
          state.textContent = err.message;
        } finally {
          run.disabled = false;
        }
      },
    });

    row.append(
      el("span", { class: "osint-name", text: p.label }),
      run,
      el("a", {
        class: "btn", href: p.web(value, type), target: "_blank", rel: "noopener",
        text: "サイトで開く", title: "キー不要。ブラウザで該当ページを開きます",
      }),
    );
    frag.append(row, state);

    if (!p.hasKey) {
      frag.append(el("p", { class: "side-empty", text: "API キー未設定（左下の鍵アイコンから設定）" }));
    } else if (p.needsRelay) {
      frag.append(el("p", { class: "side-empty", text: "CORS 未対応のため中継が必要（左下の鍵アイコンから設定）" }));
    }
  }

  frag.append(results);
  pane.replaceChildren(frag);
}

function renderOsintResult(provider, out, node) {
  const box = el("div", { class: "osint-box" });
  box.append(el("h3", { class: "side-h", style: "margin-top:0", text: `${provider.label} の結果` }));

  if (out.summary?.length) {
    const dl = el("dl", { class: "side-attrs" });
    for (const [k, v] of out.summary) dl.append(el("dt", { text: k }), el("dd", { text: String(v) }));
    box.append(dl);
  }

  if (!out.related?.length) {
    box.append(el("p", { class: "side-empty", text: "グラフに取り込める関連は見つかりませんでした。" }));
    return box;
  }

  box.append(el("h3", { class: "side-h", text: `関連 ${out.related.length}` }));
  const list = el("div", { class: "side-list" });
  for (const r of out.related) {
    list.append(el("div", { class: "osint-rel" }, [
      el("span", { class: "osint-rel-val", text: shorten(r.value, 26), title: `${r.value}（${r.rel}）` }),
      el("span", { class: "chip", text: typeLabel(r.type) }),
      el("button", {
        class: "btn", type: "button", text: "取り込む",
        onclick: (ev) => {
          const added = addRelated(node, r);
          ev.target.textContent = added ? "取り込み済" : "取り込めず";
          ev.target.disabled = true;
        },
      }),
    ]));
  }
  box.append(list);
  box.append(el("button", {
    class: "btn", type: "button", style: "margin-top:8px",
    text: `${out.related.length} 件すべて取り込む`,
    onclick: (ev) => {
      let n = 0;
      for (const r of out.related) if (addRelated(node, r)) n++;
      ev.target.textContent = `${n} 件を取り込みました`;
      ev.target.disabled = true;
      ui.graph.whenSettled({ timeout: 1500 }).then(() => ui?.graph.fit());
    },
  }));
  return box;
}

/** OSINT で分かった関連を、由来をラベルに残した手動リンクとしてグラフに足す。 */
function addRelated(node, related) {
  const res = resolveValue(related.value, { typeHint: related.type });
  if (!res) return false;
  let target = null;
  for (const b of res.matches) target = ui.graph.addRoot(b.source, b.entity);
  if (!target) return false;
  ui.graph.linkExisting();
  ui.graph.addManualEdge(node.id, target.id, related.rel);
  saveState();
  return true;
}

function collectAttrs(node) {
  const out = [];
  const seen = new Set();
  for (const m of node.members) {
    for (const [k, v] of Object.entries(m.entity.attrs || {})) {
      if (k.startsWith("_") || v == null || v === "") continue;
      if (seen.has(k)) continue;
      seen.add(k);
      out.push([k, String(v)]);
    }
  }
  return out;
}

function relationsOf(node) {
  const out = [];
  for (const e of ui.graph.edges.values()) {
    if (e.a !== node.id && e.b !== node.id) continue;
    const otherId = e.a === node.id ? e.b : e.a;
    const other = ui.graph.nodes.get(otherId);
    if (!other) continue;
    out.push({
      nodeId: otherId, label: other.label, rel: [...e.rels][0] || "関連",
      edgeId: e.id, manual: !!e.manual,
    });
  }
  return out;
}

/* ---------------- 変換タブ ---------------- */

const QUICK_OPS = [
  "fromB64", "toB64", "fromHex", "toHex", "urlDec", "urlEnc",
  "gunzip", "inflate", "xor", "rot13", "utf16le", "strings",
  "refang", "defang", "json", "iocs", "reverse", "lower", "upper",
];

let chain = [];
let manualInput = null;

function renderTransform(node) {
  if (!ui) return;
  const pane = ui.paneTransform;
  const seed = manualInput ?? (node ? node.label : "");

  const input = el("textarea", {
    class: "tf-io", spellcheck: "false", "aria-label": "変換の入力",
    placeholder: "ノードを選ぶとその値が入ります。ここに直接貼り付けても構いません。",
  });
  input.value = seed;

  const output = el("textarea", { class: "tf-io", readonly: true, "aria-label": "変換の結果" });
  const chainBox = el("div", { class: "tf-chain" });
  const err = el("div", { class: "tf-err", hidden: true });
  const keyInput = el("input", { class: "tf-key", type: "text", placeholder: "16 進 または 文字列" });
  const keyRow = el("div", { class: "tf-row", hidden: true }, [
    el("label", { text: "XOR 鍵" }), keyInput,
  ]);

  async function recompute() {
    manualInput = input.value;
    const xorStep = chain.find((s) => s.op === "xor");
    keyRow.hidden = !xorStep;
    if (xorStep) xorStep.key = keyInput.value;

    drawChain();
    if (!chain.length) {
      output.value = "";
      err.hidden = true;
      return;
    }
    try {
      output.value = await runChain(input.value, chain);
      err.hidden = true;
    } catch (e) {
      output.value = "";
      err.textContent = e.message;
      err.hidden = false;
    }
  }

  function drawChain() {
    chainBox.replaceChildren();
    if (!chain.length) {
      chainBox.append(el("span", { text: "変換なし — 下のボタンで手順を足してください" }));
      return;
    }
    chain.forEach((step, i) => {
      chainBox.append(el("span", { class: "tf-step" }, [
        `${i + 1}. ${OPS[step.op].label}`,
        el("button", {
          type: "button", text: "×", "aria-label": `${OPS[step.op].label} を外す`,
          onclick: () => { chain.splice(i, 1); recompute(); },
        }),
      ]));
    });
  }

  const ops = el("div", { class: "tf-ops" }, QUICK_OPS.map((key) =>
    el("button", {
      class: "tf-op", type: "button", text: OPS[key].label,
      onclick: () => { chain.push({ op: key }); recompute(); },
    })));

  const copyBtn = el("button", {
    class: "btn", type: "button", text: "結果をコピー",
    onclick: async () => {
      try {
        await navigator.clipboard.writeText(output.value);
        copyBtn.textContent = "コピーしました";
        setTimeout(() => { copyBtn.textContent = "結果をコピー"; }, 1400);
      } catch {
        copyBtn.textContent = "コピーできません";
      }
    },
  });

  const trayBtn = el("button", {
    class: "btn", type: "button", text: "結果をトレイに入れる",
    onclick: () => {
      const v = (output.value || input.value).trim().split(/\s+/)[0];
      if (v) addValue(v);
    },
  });

  const searchBtn = el("button", {
    class: "btn", type: "button", text: "結果をクロスサーチ",
    onclick: () => {
      const v = (output.value || input.value).trim().split(/\s+/)[0];
      if (v) ui.onQuery?.(v);
    },
  });

  input.addEventListener("input", recompute);
  keyInput.addEventListener("input", recompute);

  pane.replaceChildren(
    el("div", { class: "tf" }, [
      el("h3", { class: "side-h", style: "margin-top:0", text: "入力" }),
      input,
      el("h3", { class: "side-h", text: "手順" }),
      chainBox,
      keyRow,
      ops,
      el("h3", { class: "side-h", text: "結果" }),
      err,
      output,
      el("div", { class: "tf-row" }, [copyBtn, trayBtn, searchBtn]),
    ]),
  );

  recompute();
}
