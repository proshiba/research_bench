// ワークベンチ。グラフ調査と、選択した値をその場で変換するモジュール。

import { createGraph } from "./graph.js";
import { deepLink, graphLink, loadAllSources, store } from "./store.js";
import {
  OPS, configureCyberchef, cyberchefAvailable, cyberchefBuildHint, cyberchefLink, runChain,
} from "./transform.js";
import { el, esc, shorten, typeLabel } from "./util.js";

let ui = null;

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
    el("button", { class: "btn", type: "button", text: "クリア", onclick: () => { ui.graph.clear(); renderSide(null); } }),
    status,
  ]);

  const legend = el("div", { class: "wb-legend" }, [
    ...store.sources.map((s) =>
      el("span", { class: "lg", style: `color:var(--src-${s.accent})` }, [el("i"), s.name])),
    el("span", { class: "lg is-line", style: "color:var(--focus)" }, [el("i"), "ソース横断のリンク"]),
  ]);

  const canvasWrap = el("div", { class: "wb-canvas-wrap" }, [tools, canvas, legend]);

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

  const wrap = el("div", { class: "wb" }, [canvasWrap, side]);
  root.replaceChildren(wrap);

  const graph = createGraph(canvas, {
    onSelect: (node, counts) => {
      status.textContent = `ノード ${counts.nodes} / 辺 ${counts.edges}`;
      renderSide(node);
    },
    onStatus: (s) => {
      if (s.error) status.textContent = s.error;
      else if (s.message) status.textContent = s.message;
    },
  });
  graph.setAccentResolver((appId) => store.sources.find((s) => s.app_id === appId)?.accent || "tool");
  graph.resize();

  ui = { wrap, graph, side, paneDetail, paneTransform, selectTab, status, onQuery };
  configureCyberchef(store.tools.find((t) => t.tool_id === "cyberchef"));
  renderSide(null);

  // 索引が無いと展開できないので、裏で読み込んでおく
  loadAllSources().then(() => { if (ui) renderSide(graph.selected); });

  return ui;
}

/** 検索結果などからノードを 1 件立てる。 */
export async function pivotTo(source, entity) {
  if (!ui) return;
  ui.graph.resize();
  ui.graph.addRoot(source, entity);
  ui.graph.linkExisting();
  const node = ui.graph.selected;
  if (node && !node.expanded) await ui.graph.expand(node);
  await ui.graph.whenSettled();
  ui.graph.fit();
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
      "クロスサーチの結果から「グラフで開く」を押すか、既にあるノードをダブルクリックして展開してください。",
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

  const actions = el("div", { class: "tf-row", style: "margin-top:12px" }, [
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
      onclick: () => { node.pinned = !node.pinned; ui.graph.kick(); renderSide(node); },
    }),
    el("button", { class: "btn", type: "button", text: "削除", onclick: () => ui.graph.remove(node.id) }),
  ]);
  frag.append(actions);

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
    for (const [k, v] of attrs) {
      dl.append(el("dt", { text: k }), el("dd", { text: v }));
    }
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
      const key = `${k}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push([key, String(v)]);
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
  const keyRow = el("div", { class: "tf-row", hidden: true }, []);
  const keyInput = el("input", { class: "tf-key", type: "text", placeholder: "XOR 鍵（16 進 または 文字列）" });
  keyRow.append(el("label", { text: "XOR 鍵" }), keyInput);

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
    updateCyberchefHref();
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

  const ccLink = el("a", {
    class: "btn", target: "_blank", rel: "noopener",
    text: "CyberChef で開く", href: "#",
  });
  const ccHint = el("p", { class: "tf-hint", hidden: true });

  function updateCyberchefHref() {
    const href = cyberchefLink({ input: input.value, output: output.value, chain });
    if (href) ccLink.href = href;
  }

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
      el("div", { class: "tf-row" }, [copyBtn, searchBtn, ccLink]),
      ccHint,
    ]),
  );

  cyberchefAvailable().then((ok) => {
    if (ok) return;
    ccLink.setAttribute("aria-disabled", "true");
    ccLink.style.opacity = ".45";
    ccLink.style.pointerEvents = "none";
    ccHint.hidden = false;
    ccHint.innerHTML = "同梱の CyberChef が未ビルドです。"
      + `<code>${esc(cyberchefBuildHint(store.tools.find((t) => t.tool_id === "cyberchef")))}</code> `
      + "を実行するとここから開けるようになります。値を外部サイトに送らないため、公開インスタンスには接続しません。";
  });

  recompute();
}
