// ワークベンチ。グラフ調査と、選択した値をその場で変換するモジュール。
//
// 調査中の状態（調査対象トレイとグラフ）は localStorage に保存する。
// 別のモードに移ってもリロードしても続きから調査できるようにするため。

import { createGraph } from "./graph.js";
import { deepLink, graphLink, loadAllSources, registerManual, resolveValue, store } from "./store.js";
import { parseAny, toMermaid, toStix } from "./exchange.js";
import { actionsFor, nodeValue } from "./investigate.js";
import { lookup, providersFor } from "./osint.js";
import { LEVEL_JA, riskOf } from "./risk.js";
import { OPS, runChain } from "./transform.js";
import { TYPE_GROUPS, detectType, el, shorten, typeGroup, typeLabel, typeShape } from "./util.js";

const STORE_KEY = "rb-workbench-v1";

let ui = null;
let tray = [];          // [{ value, type }]
let restoring = false;

/**
 * 調査で手元に作った実体（AS・地理・Web ページや、取得した HTML などの属性）。
 * これらは索引に無いのでリロードすると消える。ここに控えておいて復元時に作り直す。
 *   キー: `${type} ${値の小文字}` → { value, type, label, attrs }
 */
let extras = new Map();

const extraKey = (value, type) => `${type} ${String(value).toLowerCase()}`;

function rememberExtra(value, type, { label, attrs } = {}) {
  if (!value || !type) return;
  const k = extraKey(value, type);
  const cur = extras.get(k) || { value: String(value), type, label: null, attrs: {} };
  if (label) cur.label = label;
  for (const [ak, av] of Object.entries(attrs || {})) {
    if (av != null && av !== "") cur.attrs[ak] = String(av);
  }
  extras.set(k, cur);
}

/**
 * 下部のステータス行。失敗は色を変えないと見落とすので、成否をここで一元化する。
 * error を渡したときだけ警戒色にし、次の成功メッセージで自動的に戻る。
 */
function setStatus(text, { error = false } = {}) {
  if (!ui) return;
  ui.status.textContent = text;
  ui.status.classList.toggle("is-error", !!error);
}

/* ---------------- 保存と復元 ---------------- */

function saveState() {
  if (!ui || restoring) return;
  try {
    localStorage.setItem(STORE_KEY, JSON.stringify({
      v: 1,
      tray,
      extras: [...extras.values()],
      collapsed: ui.trayEl.dataset.collapsed === "true",
      graph: ui.graph.serialize(),
    }));
  } catch (err) {
    // 容量超過は黙って捨てるとデータを失ったことに気づけないので、状態だけは伝える
    if (ui && String(err?.name).includes("Quota")) {
      setStatus("保存できませんでした（localStorage の容量超過）。取り込んだ本文が大きい可能性があります。", { error: true });
    }
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
  extras = new Map();
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
    // 調査で作る種別は、同じ色のまま形だけ変えて見分ける
    ...[["webpage", "host"], ["net.asn", "network"], ["geo", "context"]].map(([type, group]) =>
      el("span", {
        class: "lg", style: `color:var(${TYPE_GROUPS[group].color})`,
        html: shapeGlyph(typeShape(type)) + escapeText(typeLabel(type)),
      })),
    el("span", { class: "lg is-dashed", style: "color:var(--ink-dim)", html: '<i></i>手動追加（索引に無い）' }),
    el("span", { class: "lg is-ring", style: "color:var(--focus)", html: '<i></i>複数ソースに存在' }),
    el("span", { class: "lg is-arrow", style: "color:var(--focus)", html: '<i></i>手動リンク' }),
    // 危険度は色を増やさず、塗り / 中抜き / 小点で段階を見分ける
    el("span", { class: "lg", style: "color:var(--crit)", html: '<i class="rk is-high"></i>危険度 高' }),
    el("span", { class: "lg", style: "color:var(--crit)", html: '<i class="rk is-elevated"></i>中' }),
    el("span", { class: "lg", style: "color:var(--ink-faint)", html: '<i class="rk is-low"></i>低' }),
  ]);

  const canvasWrap = el("div", { class: "wb-canvas-wrap" }, [tools, canvas, legend, importInput]);

  /* --- 調査対象トレイ --- */

  // 1 行の input ではなく textarea。複数行を貼れるようにするため。
  // 見た目は 1 行のままで、中身が増えたぶんだけ伸びる。
  const trayInput = el("textarea", {
    rows: 1, spellcheck: "false", "aria-label": "調査対象を追加",
    placeholder: "IP / ドメイン / ハッシュ（改行で複数可）",
  });
  const trayPreview = el("div", { class: "tray-preview", hidden: true });
  const trayAddBtn = el("button", { class: "btn", type: "submit", text: "追加" });
  const trayForm = el("form", { class: "tray-add" }, [
    el("div", { class: "tray-add-row" }, [trayInput, trayAddBtn]),
    trayPreview,
  ]);

  // 貼り付けた分をその場で分解して見せる。追加する前に何が入るか分かるように。
  let pending = [];

  function growInput() {
    trayInput.style.height = "auto";
    trayInput.style.height = `${Math.min(trayInput.scrollHeight, 132)}px`;
  }

  function refreshPreview() {
    pending = parseBulk(trayInput.value);
    trayAddBtn.textContent = pending.length > 1 ? `追加 ${pending.length} 件` : "追加";
    trayPreview.hidden = pending.length < 2;
    if (trayPreview.hidden) { trayPreview.replaceChildren(); return; }
    trayPreview.replaceChildren(...pending.map((v) => el("span", { class: "tray-chip", title: v }, [
      el("span", { class: "tray-chip-type", text: typeLabel(detectType(v)) }),
      el("span", { class: "tray-chip-val", text: shorten(v, 24) }),
      el("button", {
        class: "tray-chip-del", type: "button", text: "×", "aria-label": `${v} を外す`,
        onclick: () => {
          trayInput.value = pending.filter((x) => x !== v).join("\n");
          growInput();
          refreshPreview();
        },
      }),
    ])));
  }

  trayInput.addEventListener("input", () => { growInput(); refreshPreview(); });
  // 貼り付けは input より後に値が入るので、次のフレームで見る
  trayInput.addEventListener("paste", () => setTimeout(() => { growInput(); refreshPreview(); }, 0));
  trayInput.addEventListener("keydown", (ev) => {
    // Enter で追加、Shift+Enter で改行（複数行を手で打てるように）
    if (ev.key === "Enter" && !ev.shiftKey) {
      ev.preventDefault();
      trayForm.requestSubmit();
    }
  });

  trayForm.addEventListener("submit", (ev) => {
    ev.preventDefault();
    const values = parseBulk(trayInput.value);
    if (!values.length) return;
    const n = addValues(values);
    if (n.added || n.duplicate) {
      trayInput.value = "";
      growInput();
      refreshPreview();
    }
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
      status.classList.remove("is-error");
      renderSide(node);
      markTraySelection(node);
    },
    onStatus: (s) => {
      if (s.error) { status.textContent = s.error; status.classList.add("is-error"); }
      else if (s.message) { status.textContent = s.message; status.classList.remove("is-error"); }
    },
    onMutate: saveState,
    onContext: (node, at) => openNodeMenu(node, at),
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
  else if (shape === "window") {
    const w = r * 2.1, h = r * 1.7;
    body = `<rect x="${c - w / 2}" y="${c - h / 2}" width="${w}" height="${h}" rx="${r * 0.28}"/>`
      + `<path d="M${c - w / 2} ${c - h / 2 + h * 0.34}H${c + w / 2}"/>`;
  } else if (shape === "cloud") {
    body = `<path d="M${c - r} ${c + r * 0.5}a${r * 0.55} ${r * 0.55} 0 0 1 ${r * 0.1} -${r * 0.95}`
      + `a${r * 0.7} ${r * 0.7} 0 0 1 ${r * 1.3} -${r * 0.1}`
      + `a${r * 0.55} ${r * 0.55} 0 0 1 ${r * 0.5} ${r * 1.05} Z"/>`;
  } else if (shape === "pin") {
    body = `<path d="M${c} ${c + r * 1.2} C${c - r * 1.1} ${c + r * 0.1} ${c - r * 0.85} ${c - r * 0.5}`
      + ` ${c} ${c - r * 1.1} C${c + r * 0.85} ${c - r * 0.5} ${c + r * 1.1} ${c + r * 0.1} ${c} ${c + r * 1.2} Z"/>`;
  } else body = `<circle cx="${c}" cy="${c}" r="${r}"/>`;
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

    // 調査で作った実体を先に作り直す。これが無いとグラフ復元時に
    // 「ソース側から消えた実体」と見なされて落ちてしまう。
    extras = new Map();
    for (const x of snap.extras || []) {
      if (!x?.value || !x?.type) continue;
      extras.set(extraKey(x.value, x.type), { ...x, attrs: x.attrs || {} });
      registerManual(x.value, x.type, { label: x.label, attrs: x.attrs, origin: "調査結果" });
    }

    // トレイの値を先に復元する。手動ノードの実体をここで作り直す必要がある。
    // staged が立っているものは他の画面から積まれた分で、グラフ側にはまだ無い。
    tray = [];
    const staged = [];
    for (const item of snap.tray || []) {
      const res = resolveValue(item.value, { typeHint: item.type });
      if (!res) continue;
      tray.push({ value: res.value, type: res.type });
      if (item.staged) staged.push(res);
    }
    renderTray();

    const n = ui.graph.restore(snap.graph);
    for (const res of staged) {
      for (const b of res.matches) ui.graph.addRoot(b.source, b.entity);
    }
    if (staged.length) ui.graph.linkExisting();

    if (staged.length) {
      ui.status.textContent = n
        ? `前回の状態を復元し、${staged.length} 件を受け取りました（ノード ${ui.graph.counts.nodes}）`
        : `${staged.length} 件を受け取りました`;
    } else if (n) {
      ui.status.textContent = `前回の状態を復元しました（ノード ${n}）`;
    }
  } finally {
    restoring = false;
  }
  ui.graph.resize();
  // 受け取った分を含めて保存し直す（staged の印はここで消える）
  saveState();
  ui.graph.whenSettled({ timeout: 1500 }).then(() => ui?.graph.fit());
}

/* ---------------- 調査対象トレイ ---------------- */

/**
 * 貼り付けたテキストを調査対象の並びに分解する。
 *
 * 1 行 1 件を基本にしつつ、カンマ・セミコロン・タブ区切りの貼り付けも受ける。
 * 空白では切らない（"Lazarus Group" のように空白を含む名前があるため）。
 * 箇条書きの記号と番号、前後の引用符は落とす。同じ値は 1 件に畳む。
 */
export function parseBulk(text) {
  const out = [];
  const seen = new Set();
  for (const line of String(text || "").split(/[\n\r,;\t]+/)) {
    // 前後の空白を先に落とさないと、記号の除去が効かない
    const v = line
      .trim()
      .replace(/^(?:[-*・•]|\d+[.)])\s+/, "")       // 箇条書きの記号・番号
      .replace(/^["'`<(\[]+|["'`>)\]]+$/g, "")      // 前後の引用符や括弧
      .trim();
    if (!v) continue;
    const k = v.toLowerCase();
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(v);
  }
  return out;
}

/**
 * まとめて追加する。1 件ずつ addValue を呼ぶと整列と保存が毎回走るので、
 * ここで一度だけまとめてやる。戻り値は内訳（画面に出すため）。
 */
function addValues(values) {
  const n = { added: 0, duplicate: 0, failed: [] };
  const before = new Set(tray.map((t) => t.value.toLowerCase()));

  for (const raw of values) {
    const res = resolveValue(raw);
    if (!res) { n.failed.push(raw); continue; }
    for (const b of res.matches) ui.graph.addRoot(b.source, b.entity);
    if (before.has(res.value.toLowerCase())) { n.duplicate++; continue; }
    before.add(res.value.toLowerCase());
    tray.push({ value: res.value, type: res.type });
    n.added++;
  }

  ui.graph.linkExisting();
  renderTray();
  saveState();
  ui.graph.whenSettled({ timeout: 1600 }).then(() => ui?.graph.fit());

  const parts = [];
  if (n.added) parts.push(`${n.added} 件を追加`);
  if (n.duplicate) parts.push(`${n.duplicate} 件は既にあり`);
  if (n.failed.length) parts.push(`${n.failed.length} 件は解釈できず（${shorten(n.failed[0], 20)} など）`);
  setStatus(parts.join(" / ") || "追加できるものがありませんでした", { error: !n.added && !n.duplicate });
  return n;
}

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
/**
 * 他の画面（モジュール画面など）から調査対象を渡す。
 *
 * ワークベンチが表示されていればその場で足す。表示されていなければ
 * 保存状態のトレイに積んでおき、次に開いたときに載る。
 * 戻り値は実際に積んだ件数。
 */
export function stageValues(values) {
  const list = [...new Set([].concat(values).map((v) => String(v || "").trim()).filter(Boolean))];
  if (!list.length) return 0;

  if (ui) {
    let n = 0;
    for (const v of list) if (addValue(v)) n++;
    return n;
  }

  const snap = readState() || {};
  const staged = Array.isArray(snap.tray) ? [...snap.tray] : [];
  let n = 0;
  for (const raw of list) {
    const res = resolveValue(raw);
    if (!res) continue;
    if (staged.some((t) => t.value.toLowerCase() === res.value.toLowerCase())) continue;
    // staged: 次にワークベンチを開いたときにグラフへ載せる印
    staged.push({ value: res.value, type: res.type, staged: true });
    n++;
  }
  try {
    localStorage.setItem(STORE_KEY, JSON.stringify({ ...snap, v: 1, tray: staged }));
  } catch {
    return 0;
  }
  return n;
}

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
  if (!ui.graph.nodes.size) { setStatus("書き出すノードがありません", { error: true }); return; }
  const cs = getComputedStyle(document.documentElement);
  const text = toMermaid(ui.graph, (v) => cs.getPropertyValue(v).trim());
  download(`workbench-${stamp()}.mmd`, text, "text/plain;charset=utf-8");
  setStatus(`Mermaid を書き出しました（ノード ${ui.graph.nodes.size} / 辺 ${ui.graph.edges.size}）`);
}

function exportStix() {
  if (!ui.graph.nodes.size) { setStatus("書き出すノードがありません", { error: true }); return; }
  const bundle = toStix(ui.graph);
  download(`workbench-${stamp()}.stix.json`, JSON.stringify(bundle, null, 2), "application/json;charset=utf-8");
  setStatus(`STIX 2.1 を書き出しました（オブジェクト ${bundle.objects.length}）`);
}

function exportPng() {
  const a = document.createElement("a");
  a.href = ui.graph.exportPng();
  a.download = `workbench-${stamp()}.png`;
  a.click();
}

async function importFile(file) {
  setStatus(`${file.name} を読み込んでいます…`);
  try {
    const parsed = parseAny(await file.text(), file.name);
    await loadAllSources();          // 索引に突き合わせて出典を復元するため
    const r = importGraph(parsed);
    ui.status.textContent = `${parsed.format === "stix" ? "STIX" : "Mermaid"} を読み込みました — `
      + `ノード ${r.nodes}（うち索引に無いもの ${r.manual}） / リンク ${r.links}`
      + (r.skipped ? ` / 解決できず ${r.skipped}` : "");
  } catch (err) {
    setStatus(`読み込めませんでした: ${err.message}`, { error: true });
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
      html: shapeGlyph(typeShape(node.type)) + escapeText(node.type),
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

  const risks = riskOf(node);
  if (risks.length) {
    frag.append(el("h3", { class: "side-h", text: "危険度" }));
    frag.append(el("ul", { class: "side-list risk-list" }, risks.map((r) => el("li", {}, [
      el("div", { class: `risk-row is-${r.level}` }, [
        el("span", { class: `rk is-${r.level}` }),
        el("span", { class: "risk-src", text: r.label }),
        el("b", { class: "risk-score", text: r.text }),
        el("span", { class: "risk-level", text: LEVEL_JA[r.level] }),
      ]),
    ]))));
  }

  const attrs = collectAttrs(node);
  if (attrs.length) {
    frag.append(el("h3", { class: "side-h", text: "属性" }));
    const dl = el("dl", { class: "side-attrs" });
    for (const [k, v] of attrs) dl.append(el("dt", { text: k }), attrValue(v));
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
    const link = el("a", {
      class: "btn", href: p.web(value, type), target: "_blank", rel: "noopener",
      text: "サイトで開く", title: "キー不要。ブラウザで該当ページを開きます",
    });

    // CORS を許可していないサービスは API 連携せず、リンクだけ出す
    if (p.linkOnly) {
      row.append(el("span", { class: "osint-name", text: p.label }), link);
      frag.append(row);
      continue;
    }

    const run = el("button", {
      class: "btn", type: "button", text: "照会",
      disabled: !p.callable || null,
      title: p.callable ? null : "API キーが設定されていません",
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

    row.append(el("span", { class: "osint-name", text: p.label }), run, link);
    frag.append(row, state);

    if (!p.hasKey) {
      frag.append(el("p", { class: "side-empty", text: "API キー未設定（左下の鍵アイコンから設定）" }));
    }
  }

  // リンクだけのサービスが混じっている理由を 1 行だけ添えておく
  const linkOnly = providers.filter((p) => p.linkOnly).map((p) => p.label);
  if (linkOnly.length) {
    frag.append(el("p", { class: "side-empty" }, [
      `${linkOnly.join(" / ")} は CORS を許可していないため API 連携はせず、リンクのみ。`,
    ]));
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

/* ---------------- 右クリックの調査メニュー ---------------- */

let nodeMenu = null;

function closeNodeMenu() {
  nodeMenu?.remove();
  nodeMenu = null;
}

/** ノードを右クリックしたときのメニュー。種別に応じた調査だけを並べる。 */
function openNodeMenu(node, at) {
  closeNodeMenu();
  if (!ui || !node) return;

  const actions = actionsFor(node);
  const menu = el("div", { class: "popover node-menu", role: "menu" });
  nodeMenu = menu;

  menu.append(el("div", { class: "menu-label", text: `${typeLabel(node.type)} · ${shorten(nodeValue(node), 28)}` }));

  let lastGroup = null;
  for (const a of actions) {
    if (a.group !== lastGroup) {
      lastGroup = a.group;
      menu.append(el("div", { class: "menu-label is-sub", text: a.group }));
    }
    menu.append(el("button", {
      class: "popover-item", type: "button", role: "menuitem",
      disabled: !a.ready || null,
      title: a.ready ? null : `${a.why}（左端の鍵アイコンから設定）`,
      onclick: () => { closeNodeMenu(); runAction(node, a); },
    }, [
      a.label,
      ...(a.ready ? [] : [el("span", { class: "menu-hint", text: "未設定" })]),
    ]));
  }

  menu.append(el("div", { class: "menu-label is-sub", text: "操作" }));
  const basics = [
    ["索引から展開", () => ui.graph.expand(node)],
    ["トレイに入れる", () => { addValue(nodeValue(node)); }],
    ["リンクを張る", () => ui.graph.beginLink(node.id)],
    ["値をコピー", async () => {
      try { await navigator.clipboard.writeText(nodeValue(node)); ui.status.textContent = "コピーしました"; }
      catch { setStatus("コピーできませんでした", { error: true }); }
    }],
    ["削除", () => { ui.graph.remove(node.id); saveState(); }],
  ];
  for (const [label, fn] of basics) {
    menu.append(el("button", {
      class: "popover-item", type: "button", role: "menuitem", text: label,
      onclick: () => { closeNodeMenu(); fn(); },
    }));
  }

  document.body.append(menu);
  // 画面からはみ出さない位置に置く
  const r = menu.getBoundingClientRect();
  menu.style.left = `${Math.max(8, Math.min(at.x, innerWidth - r.width - 8))}px`;
  menu.style.top = `${Math.max(8, Math.min(at.y, innerHeight - r.height - 8))}px`;

  const off = () => { closeNodeMenu(); document.removeEventListener("click", off); };
  setTimeout(() => document.addEventListener("click", off), 0);
  menu.addEventListener("click", (ev) => ev.stopPropagation());
}

/** メニューから選んだ調査を実行し、結果をグラフに反映する。 */
async function runAction(node, action) {
  if (!ui) return;
  const label = `${shorten(nodeValue(node), 24)} を ${action.label}`;
  setStatus(`${label}…`);
  try {
    const out = await action.run({
      onProgress: (job) => {
        if (!ui) return;
        const p = job.progress || {};
        const nums = Object.entries(p).map(([k, v]) => `${k} ${v}`).join(" / ");
        setStatus(`${label}… ジョブ ${job.status}${nums ? ` — ${nums}` : ""}`);
      },
    });
    applyResult(node, out);
    setStatus(`${label}: ${out.note || "完了"}`, { error: !!out.error });
  } catch (err) {
    setStatus(`${label}: ${err.message}`, { error: true });
  }
}

/** 調査結果を、元ノードの属性と新しい関連ノードとしてグラフに入れる。 */
function applyResult(node, out) {
  // 元のノードに属性を足す。索引由来の実体は触らず、手元の実体側に持たせる
  const own = Object.fromEntries(Object.entries(out.attrs || {}).filter(([, v]) => v != null && v !== ""));
  if (Object.keys(own).length) {
    registerManual(nodeValue(node), node.type, { attrs: own, origin: "調査結果" });
    rememberExtra(nodeValue(node), node.type, { attrs: own });
    // 手元の実体を同じノードに合流させる（種別と値が同じなので畳まれる）
    const b = registerManual(nodeValue(node), node.type, {});
    if (b) ui.graph.addEntity(b.source, b.entity);
  }

  for (const r of out.related || []) {
    const b = registerManual(r.value, r.type, { label: r.label, attrs: r.attrs, origin: "調査結果" });
    if (!b) continue;
    rememberExtra(r.value, r.type, { label: r.label, attrs: r.attrs });

    // 索引に同じ値があればそちらも同じノードに載せる（横串が効く）
    const res = resolveValue(r.value, { typeHint: r.type });
    let target = ui.graph.addEntity(b.source, b.entity);
    for (const m of res?.matches || []) {
      if (m.source === b.source) continue;
      target = ui.graph.addEntity(m.source, m.entity) || target;
    }
    ui.graph.linkExisting();
    if (target) ui.graph.addManualEdge(node.id, target.id, r.rel);
  }

  renderSide(ui.graph.selected);
  saveState();
  ui.graph.whenSettled({ timeout: 1500 }).then(() => ui?.graph.fit());
}

/**
 * 属性 1 件の表示。
 *
 * 調査で取り込んだ HTML 本文や WHOIS 全文のように長いものは、そのまま並べると
 * パネルが埋まるので畳んでおく。開くと折り返さない等幅で全文を出す。
 */
function attrValue(v) {
  const text = String(v);
  const long = text.length > 160 || text.includes("\n");
  if (!long) return el("dd", { text });

  const pre = el("pre", { class: "attr-long", text, hidden: true });
  const head = el("button", {
    class: "attr-toggle", type: "button",
    text: `${text.length.toLocaleString()} 文字 — 開く`,
    onclick: () => {
      pre.hidden = !pre.hidden;
      head.textContent = pre.hidden
        ? `${text.length.toLocaleString()} 文字 — 開く`
        : `${text.length.toLocaleString()} 文字 — 閉じる`;
    },
  });
  const copy = el("button", {
    class: "attr-toggle", type: "button", text: "コピー",
    onclick: async () => {
      try {
        await navigator.clipboard.writeText(text);
        copy.textContent = "コピーしました";
        setTimeout(() => { copy.textContent = "コピー"; }, 1500);
      } catch {
        copy.textContent = "コピーできません";
      }
    },
  });
  return el("dd", {}, [el("span", { class: "attr-bar" }, [head, copy]), pre]);
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
