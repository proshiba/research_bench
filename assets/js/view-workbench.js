// ワークベンチ。グラフ調査と、選択した値をその場で変換するモジュール。
//
// 調査中の状態（調査対象トレイとグラフ）は localStorage に保存する。
// 別のモードに移ってもリロードしても続きから調査できるようにするため。

import { createGraph } from "./graph.js";
import { deepLink, graphLink, loadAllSources, resolveValue, store } from "./store.js";
import { OPS, runChain } from "./transform.js";
import { el, shorten, typeLabel } from "./util.js";

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

  const tools = el("div", { class: "wb-tools" }, [
    el("button", { class: "btn", type: "button", text: "全体表示", onclick: () => ui.graph.fit() }),
    el("button", { class: "btn", type: "button", text: "再レイアウト", onclick: () => ui.graph.relayout() }),
    el("button", { class: "btn", type: "button", text: "PNG 保存", onclick: exportPng }),
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

  const legend = el("div", { class: "wb-legend" }, [
    ...store.sources.map((s) =>
      el("span", { class: "lg", style: `color:var(--src-${s.accent})` }, [el("i"), s.name])),
    el("span", { class: "lg", style: "color:var(--src-manual)" }, [el("i"), "手動追加"]),
    el("span", { class: "lg is-line", style: "color:var(--focus)" }, [el("i"), "ソース横断のリンク"]),
  ]);

  const canvasWrap = el("div", { class: "wb-canvas-wrap" }, [tools, canvas, legend]);

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

  const tabDetail = el("button", {
    class: "tab", type: "button", role: "tab", text: "詳細",
    "aria-selected": "true", "aria-controls": "wbDetail",
  });
  const tabTransform = el("button", {
    class: "tab", type: "button", role: "tab", text: "変換",
    "aria-selected": "false", "aria-controls": "wbTransform",
  });

  function selectTab(which) {
    const isDetail = which === "detail";
    tabDetail.setAttribute("aria-selected", String(isDetail));
    tabTransform.setAttribute("aria-selected", String(!isDetail));
    paneDetail.hidden = !isDetail;
    paneTransform.hidden = isDetail;
  }

  tabDetail.addEventListener("click", () => selectTab("detail"));
  tabTransform.addEventListener("click", () => selectTab("transform"));

  const side = el("aside", { class: "wb-side" }, [
    el("div", { class: "tabs", role: "tablist" }, [tabDetail, tabTransform]),
    paneDetail,
    paneTransform,
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
  graph.setAccentResolver((appId) =>
    (appId === "__manual" ? "manual" : store.sources.find((s) => s.app_id === appId)?.accent) || "manual");
  graph.resize();

  ui = { wrap, graph, side, paneDetail, paneTransform, selectTab, status, onQuery, trayEl, trayList, trayCount };
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
      const res = resolveValue(item.value);
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
    const accent = manual
      ? "var(--src-manual)"
      : `var(--src-${store.sources.find((s) => s.app_id === [...srcs][0])?.accent || "manual"})`;

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

function exportPng() {
  const a = document.createElement("a");
  a.href = ui.graph.exportPng();
  a.download = "workbench.png";
  a.click();
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

  const primary = node.members[0];
  const accent = `var(--src-${primary.source.accent})`;
  const frag = document.createDocumentFragment();

  frag.append(
    el("span", { class: "side-type", style: `color:${accent}`, text: node.type }),
    el("p", { class: "side-label", text: node.label }),
    el("p", { class: "side-empty", text: typeLabel(node.type) }),
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
    el("button", { class: "btn", type: "button", text: "削除", onclick: () => ui.graph.remove(node.id) }),
  ]));

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
  frag.append(el("h3", { class: "side-h", text: `関連 ${rels.length}` }));
  if (rels.length) {
    const list = el("div", { class: "side-list" });
    for (const r of rels.slice(0, 60)) {
      list.append(el("button", {
        class: "side-rel", type: "button", title: r.label,
        onclick: () => { ui.graph.select(r.nodeId); },
      }, [
        el("em", { text: r.rel }),
        el("span", { text: shorten(r.label, 30) }),
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
    out.push({ nodeId: otherId, label: other.label, rel: [...e.rels][0] || "関連" });
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
