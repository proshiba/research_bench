// モジュール管理画面と、各モジュールの個別画面。
//
// 管理画面はカードを並べるだけ。個別画面は「その機能を単体で試せる場所」で、
// API を叩くモジュールならリクエストと生の応答が見え、CyberChef ならその UI が開く。
// 取れた値は「ワークベンチに送る」でグラフ側に持ち込める。

import { TOOLS, getTool, ping, run } from "./api-active-research.js";
import { MODULES, filterModules, getModule, getModuleSettings, saveModuleSettings } from "./modules.js";
import { PROVIDERS, getSettings, lookup, providersFor } from "./osint.js";
import { store } from "./store.js";
import { configureCyberchef, cyberchefAvailable, cyberchefBuildHint, cyberchefLink } from "./transform.js";
import { detectType, el, shorten, typeLabel } from "./util.js";
import { stageValues } from "./view-workbench.js";

let ctx = { onOpen: null, onBack: null };
let listQuery = "";

/* ---------------- 入口 ---------------- */

export function renderModules(root, { moduleId = null, onOpen, onBack } = {}) {
  ctx = { onOpen, onBack };
  const mod = moduleId ? getModule(moduleId) : null;
  if (moduleId && !mod) {
    root.replaceChildren(el("div", { class: "empty" }, [
      el("h2", { text: "そのモジュールはありません" }),
      el("p", { text: moduleId }),
      el("button", { class: "btn", type: "button", text: "一覧に戻る", onclick: () => ctx.onBack?.() }),
    ]));
    return;
  }
  if (mod) renderModuleScreen(root, mod);
  else renderList(root);
}

/* ---------------- 一覧（カード） ---------------- */

function renderList(root) {
  const q = el("input", {
    type: "search", class: "mod-search", spellcheck: "false", autocomplete: "off",
    placeholder: "モジュールを検索", value: listQuery, "aria-label": "モジュールを検索",
  });
  const grid = el("div", { class: "mod-grid" });

  function paint() {
    listQuery = q.value;
    const hits = filterModules(listQuery);
    grid.replaceChildren(...(hits.length
      ? hits.map(moduleCard)
      : [el("p", { class: "side-empty", text: "該当するモジュールがありません。" })]));
  }
  q.addEventListener("input", paint);

  root.replaceChildren(el("div", { class: "mod-page" }, [
    el("div", { class: "mod-head" }, [
      el("h1", { class: "mod-title", text: "モジュール" }),
      el("p", { class: "mod-lead", text: `個別機能を 1 つずつ試せます（${MODULES.length} 件）。` }),
    ]),
    q,
    grid,
  ]));
  paint();
}

function moduleIcon(mod, size = 22) {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("width", size);
  svg.setAttribute("height", size);
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "1.6");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("aria-hidden", "true");
  svg.innerHTML = mod.icon;
  return svg;
}

function moduleCard(mod) {
  return el("button", {
    class: "mod-card", type: "button", onclick: () => ctx.onOpen?.(mod.id),
    style: `--mod-accent: var(${mod.accent})`,
  }, [
    el("div", { class: "mod-card-top" }, [
      el("span", { class: "mod-card-icon" }, [moduleIcon(mod)]),
      el("span", { class: "mod-card-name", text: mod.name }),
      el("span", { class: "mod-card-id", text: mod.id }),
    ]),
    el("p", { class: "mod-card-sum", text: mod.summary }),
    el("div", { class: "mod-card-tags" }, mod.tags.map((t) => el("span", { class: "chip", text: t }))),
  ]);
}

/* ---------------- 個別画面の枠 ---------------- */

function renderModuleScreen(root, mod) {
  const body = el("div", { class: "mod-body" });
  root.replaceChildren(el("div", { class: "mod-page" }, [
    el("div", { class: "mod-bar" }, [
      el("button", { class: "btn", type: "button", text: "← モジュール一覧", onclick: () => ctx.onBack?.() }),
      el("span", { class: "mod-bar-icon", style: `color:var(${mod.accent})` }, [moduleIcon(mod, 18)]),
      el("span", { class: "mod-bar-name", text: mod.name }),
      el("span", { class: "mod-card-id", text: mod.id }),
    ]),
    el("p", { class: "mod-lead", text: mod.detail }),
    body,
  ]));

  if (mod.id === "shodan") renderShodan(body);
  else if (mod.id === "active-research") renderActiveResearch(body);
  else if (mod.id === "cyberchef") renderCyberchef(body);
}

/* ---------------- 共通部品 ---------------- */

/** 結果の枠。要点・生の応答・取れた値をまとめて出す。 */
function resultBox({ title, meta, summary, detail, iocs, raw }) {
  const box = el("section", { class: "mod-result" });
  box.append(el("div", { class: "mod-result-head" }, [
    el("h3", { class: "side-h", style: "margin:0", text: title }),
    ...(meta ? [el("span", { class: "mod-meta", text: meta })] : []),
  ]));

  const rows = (summary || []).filter(([, v]) => v != null && v !== "");
  if (rows.length) {
    const dl = el("dl", { class: "side-attrs" });
    for (const [k, v] of rows) dl.append(el("dt", { text: k }), el("dd", { text: String(v) }));
    box.append(dl);
  }

  if (detail) {
    box.append(el("h4", { class: "side-h", text: "本文" }));
    box.append(el("pre", { class: "mod-pre", text: shorten(String(detail), 4000) }));
  }

  if (iocs?.length) {
    // 証明書のように数百件になることがある。一覧は打ち切るが、
    // 打ち切ったことは必ず書く（「すべて送る」は全件を送る）。
    const SHOWN = 60;
    const shown = iocs.slice(0, SHOWN);
    box.append(el("h4", { class: "side-h", text: `取れた値 ${iocs.length}` }));
    if (iocs.length > SHOWN) {
      box.append(el("p", { class: "side-empty", text:
        `一覧は先頭 ${SHOWN} 件だけ出しています（残り ${iocs.length - SHOWN} 件は下の「すべて送る」に含まれます）。` }));
    }
    const list = el("div", { class: "mod-iocs" });
    for (const r of shown) {
      list.append(el("div", { class: "mod-ioc" }, [
        el("span", { class: "mod-ioc-val", text: shorten(r.value, 34), title: `${r.value}（${r.rel}）` }),
        el("span", { class: "chip", text: typeLabel(r.type) }),
        el("button", {
          class: "btn", type: "button", text: "送る", title: "ワークベンチの調査対象に足す",
          onclick: (ev) => {
            const n = stageValues([r.value]);
            ev.target.textContent = n ? "送信済" : "既にあり";
            ev.target.disabled = true;
          },
        }),
      ]));
    }
    box.append(list);
    box.append(el("button", {
      class: "btn", type: "button", style: "margin-top:8px",
      text: `${iocs.length} 件すべてワークベンチに送る`,
      onclick: (ev) => {
        const n = stageValues(iocs.map((r) => r.value));
        ev.target.textContent = `${n} 件を送りました`;
        ev.target.disabled = true;
      },
    }));
  }

  if (raw != null) {
    const pre = el("pre", { class: "mod-pre is-raw", text: raw, hidden: true });
    const toggle = el("button", {
      class: "btn", type: "button", text: "生の応答を見る",
      onclick: () => {
        pre.hidden = !pre.hidden;
        toggle.textContent = pre.hidden ? "生の応答を見る" : "生の応答を隠す";
      },
    });
    const copy = el("button", {
      class: "btn", type: "button", text: "コピー",
      onclick: async () => {
        try {
          await navigator.clipboard.writeText(raw);
          copy.textContent = "コピーしました";
          setTimeout(() => { copy.textContent = "コピー"; }, 1500);
        } catch {
          copy.textContent = "コピーできません";
        }
      },
    });
    box.append(el("div", { class: "mod-raw-bar" }, [toggle, copy]), pre);
  }

  return box;
}

function errorBox(message) {
  return el("p", { class: "mod-error", text: message });
}

/** ツール定義の params からフォームを組む。 */
function buildForm(params, values) {
  const wrap = el("div", { class: "mod-form" });
  const inputs = {};
  for (const p of params) {
    let input;
    if (p.type === "select") {
      input = el("select", { class: "modal-input", id: `p-${p.name}` },
        p.options.map((o) => el("option", {
          value: o, text: o || "（指定なし）", selected: values[p.name] === o || null,
        })));
    } else if (p.type === "checkbox") {
      input = el("input", { type: "checkbox", id: `p-${p.name}`, checked: !!values[p.name] || null });
    } else {
      input = el("input", {
        type: p.type === "password" ? "password" : p.type === "number" ? "number" : "text",
        class: "modal-input", id: `p-${p.name}`, spellcheck: "false", autocomplete: "off",
        placeholder: p.placeholder || "", value: values[p.name] ?? "",
      });
    }
    inputs[p.name] = input;
    wrap.append(el("div", { class: `mod-field${p.type === "checkbox" ? " is-check" : ""}` }, [
      el("label", { for: `p-${p.name}` }, [
        p.label,
        ...(p.required ? [el("span", { class: "mod-req", text: "必須" })] : []),
      ]),
      input,
      ...(p.hint ? [el("span", { class: "modal-desc", text: p.hint })] : []),
    ]));
  }
  const read = () => Object.fromEntries(Object.entries(inputs).map(([k, i]) =>
    [k, i.type === "checkbox" ? i.checked : i.value.trim()]));
  return { wrap, inputs, read };
}

/* ---------------- Shodan ---------------- */

function renderShodan(body) {
  const hasKey = providersFor("ioc.ipv4").find((p) => p.id === "shodan")?.hasKey;
  const value = el("input", {
    type: "text", class: "modal-input", id: "sh-value", spellcheck: "false",
    placeholder: "1.1.1.1", "aria-label": "IP アドレス",
  });
  const out = el("div", { class: "mod-out" });
  const runBtn = el("button", {
    class: "btn is-on", type: "button", text: "照会",
    onclick: async () => {
      const v = value.value.trim();
      if (!v) return;
      const t = detectType(v);
      if (t !== "ioc.ipv4" && t !== "ioc.ipv6") {
        out.replaceChildren(errorBox("Shodan の host 照会は IP アドレスだけです。"));
        return;
      }
      runBtn.disabled = true;
      out.replaceChildren(el("p", { class: "side-empty", text: "照会中…" }));
      try {
        const res = await lookup("shodan", v, t);
        out.replaceChildren(resultBox({
          title: `Shodan — ${v}`,
          summary: res.summary,
          iocs: res.related,
          raw: JSON.stringify(res, null, 2),
        }));
      } catch (err) {
        out.replaceChildren(errorBox(err.message));
      } finally {
        runBtn.disabled = false;
      }
    },
  });

  body.append(
    el("div", { class: "mod-form" }, [
      el("div", { class: "mod-field" }, [
        el("label", { for: "sh-value" }, ["IP アドレス", el("span", { class: "mod-req", text: "必須" })]),
        value,
        el("span", { class: "modal-desc", text: "Shodan の /shodan/host/{ip} を呼びます。" }),
      ]),
    ]),
    el("div", { class: "mod-actions" }, [
      runBtn,
      el("a", {
        class: "btn", href: PROVIDERS.shodan.web("1.1.1.1"), target: "_blank", rel: "noopener",
        text: "Shodan を開く",
      }),
    ]),
    hasKey
      ? el("p", { class: "modal-desc", text: "API キーは設定済みです。キーはこの端末の中だけにあります。" })
      : errorBox("API キーが未設定です。左端の鍵アイコン（OSINT 設定）から入れてください。"),
    out,
  );
}

/* ---------------- Active Research ---------------- */

function renderActiveResearch(body) {
  const cur = getModuleSettings();
  const base = el("input", {
    type: "url", class: "modal-input", id: "ar-base", spellcheck: "false", value: cur.activeResearchBase,
  });
  const note = el("p", { class: "modal-note" });
  const out = el("div", { class: "mod-out" });
  let selected = TOOLS[0];
  let form = null;
  // 設定済みのトークンを初期値に入れておく（毎回貼り直さずに済むように）
  const saved = getSettings().keys;
  const values = { apikey: saved.virustotal || "", token: saved.github || "" };

  const pane = el("div", { class: "mod-tool-pane" });
  const tabs = el("div", { class: "mod-tools", role: "tablist" });

  /** ツールの params は配列のことも、入力値で変わる関数のこともある。 */
  const paramsOf = (tool, v) => (typeof tool.params === "function" ? tool.params(v) : tool.params);

  function paintTool() {
    for (const b of tabs.children) b.setAttribute("aria-selected", String(b.dataset.tool === selected.id));
    paintForm();
    out.replaceChildren();
  }

  function paintForm() {
    form = buildForm(paramsOf(selected, values), values);
    // action のように、選び直すと必要な引数が変わるものはフォームごと作り直す
    for (const name of selected.rebuildOn || []) {
      form.inputs[name]?.addEventListener("change", () => {
        Object.assign(values, form.read());
        paintForm();
      });
    }
    pane.replaceChildren(
      el("p", { class: "mod-tool-desc" }, [
        selected.desc,
        el("code", { class: "mod-endpoint", text: `${selected.method} /${selected.path}` }),
        ...(selected.async ? [el("span", { class: "chip", text: "非同期ジョブ" })] : []),
      ]),
      ...(selected.keyWarning
        ? [el("p", { class: "mod-warn", text:
            "このツールはトークンを API サーバーに送ります（Authorization: Bearer）。"
            + "端末の外に出る点だけご承知ください。" })]
        : []),
      form.wrap,
      el("div", { class: "mod-actions" }, [runBtn, cancelBtn]),
    );
  }

  let controller = null;
  const cancelBtn = el("button", {
    class: "btn", type: "button", text: "中止", hidden: true,
    onclick: () => controller?.abort(),
  });

  const runBtn = el("button", {
    class: "btn is-on", type: "button", text: "実行",
    onclick: async () => {
      const v = form.read();
      Object.assign(values, v);
      const missing = paramsOf(selected, values).filter((p) => p.required && !v[p.name]).map((p) => p.label);
      if (missing.length) {
        out.replaceChildren(errorBox(`${missing.join(" / ")} を入れてください。`));
        return;
      }
      runBtn.disabled = true;
      cancelBtn.hidden = !selected.async;
      controller = new AbortController();

      const progress = el("p", { class: "side-empty", text: selected.async ? "ジョブを開始しています…" : "実行中…" });
      out.replaceChildren(progress);
      const b = saveModuleSettings({ activeResearchBase: base.value.trim() }).activeResearchBase;

      try {
        const res = await run(b, selected, v, {
          signal: controller.signal,
          onProgress: (job) => {
            const p = selected.progress ? selected.progress(job.progress || {}) : "";
            progress.textContent = `ジョブ ${job.status}${p ? ` — ${p}` : ""}`;
          },
        });
        const d = res.data;
        if (!d) {
          out.replaceChildren(resultBox({
            title: `${selected.label} — 結果を読めませんでした`,
            meta: `HTTP ${res.status} / ${res.ms} ms`,
            raw: res.text,
          }));
          return;
        }
        // ok:false でも中身を返すツールがある（RDAP は上流の 403 をそのまま載せてくる）。
        // エラーだからと捨てずに、警告を添えて要点も見せる。
        const box = resultBox({
          title: `${selected.label} の結果`,
          meta: `HTTP ${res.status} / ${res.ms} ms${res.job ? ` / jobId ${res.job.id}` : ""}`,
          summary: selected.summary(d),
          detail: selected.detail ? selected.detail(d) : null,
          iocs: selected.iocs(d),
          raw: JSON.stringify(res.raw ?? d, null, 2),
        });
        out.replaceChildren(...(d.ok === false
          ? [errorBox(`API は ok:false を返しました${d.error ? `: ${d.error}` : "（理由の記載なし）"}`), box]
          : [box]));
      } catch (err) {
        if (err.name === "AbortError") out.replaceChildren(el("p", { class: "side-empty", text: "中止しました。" }));
        else out.replaceChildren(errorBox(err.message), corsHelp(base.value.trim()));
      } finally {
        runBtn.disabled = false;
        cancelBtn.hidden = true;
        controller = null;
      }
    },
  });

  for (const t of TOOLS) {
    tabs.append(el("button", {
      class: "mod-tool", type: "button", role: "tab", dataset: { tool: t.id }, text: t.label,
      onclick: () => { selected = getTool(t.id); paintTool(); },
    }));
  }

  body.append(
    el("div", { class: "mod-form" }, [
      el("div", { class: "mod-field" }, [
        el("label", { for: "ar-base", text: "API のベース URL" }),
        el("div", { class: "modal-row" }, [
          base,
          el("button", {
            class: "btn", type: "button", text: "疎通確認",
            onclick: async (ev) => {
              const b = saveModuleSettings({ activeResearchBase: base.value.trim() }).activeResearchBase;
              ev.target.disabled = true;
              note.className = "modal-note";
              note.textContent = "確認中…";
              out.replaceChildren();
              try {
                const res = await ping(b);
                note.textContent = `繋がりました（HTTP ${res.status} / ${res.ms} ms）`;
              } catch (err) {
                note.className = "modal-note is-error";
                note.textContent = err.message;
                out.replaceChildren(corsHelp(b));
              } finally {
                ev.target.disabled = false;
              }
            },
          }),
        ]),
      ]),
    ]),
    note,
    tabs,
    pane,
    out,
  );
  paintTool();
}

/** CORS で弾かれたときに、何をどこに足せばよいかを画面上で示す。 */
function corsHelp(base) {
  let host = base;
  try { host = new URL(base).host; } catch { /* 入力途中でも壊れないように */ }
  return el("div", { class: "mod-help" }, [
    el("h4", { class: "side-h", style: "margin-top:0", text: "ブラウザから呼べない場合" }),
    el("p", { class: "modal-desc", text:
      `${host} が CORS ヘッダを返していないと、応答があってもブラウザが JS に渡しません。`
      + "API 側で次の 2 つを返すようにすると呼べるようになります。" }),
    el("pre", { class: "mod-pre", text:
      `Access-Control-Allow-Origin: ${location.origin}\n`
      + "Access-Control-Allow-Headers: content-type, accept, authorization\n"
      + "Access-Control-Allow-Methods: GET, POST, OPTIONS\n\n"
      + "# OPTIONS には 204 を返すこと（POST と Authorization はプリフライトが要る）" }),
    el("p", { class: "modal-desc", text:
      "2026-07 の実測ではこの API は ACAO: * を返しているので、通常はこの画面は出ません。"
      + "出た場合は Origin を絞ったか、API が落ちているかのどちらかです。" }),
  ]);
}

/* ---------------- CyberChef ---------------- */

function renderCyberchef(body) {
  const tool = (store.tools || []).find((t) => t.tool_id === "cyberchef") || null;
  configureCyberchef(tool);

  const input = el("input", {
    type: "text", class: "modal-input", id: "cc-input", spellcheck: "false",
    placeholder: "（任意）ここに入れた値を CyberChef の入力に渡します",
  });
  const frameWrap = el("div", { class: "mod-frame" });

  function openFrame(withInput) {
    const url = withInput
      ? cyberchefLink({ input: input.value, output: input.value, chain: [] })
      : tool?.url;
    if (!url) {
      frameWrap.replaceChildren(errorBox("CyberChef の場所が apps.json に登録されていません。"));
      return;
    }
    frameWrap.replaceChildren(el("iframe", {
      class: "mod-iframe", src: url, title: "CyberChef",
      sandbox: "allow-scripts allow-same-origin allow-downloads allow-popups allow-forms",
    }));
  }

  body.append(
    el("div", { class: "mod-form" }, [
      el("div", { class: "mod-field" }, [
        el("label", { for: "cc-input", text: "持ち込む値" }),
        input,
        el("span", { class: "modal-desc", text: "Base64 にして URL のフラグメントで渡すので、サーバーには出ません。" }),
      ]),
    ]),
    el("div", { class: "mod-actions" }, [
      el("button", { class: "btn is-on", type: "button", text: "この値で開く", onclick: () => openFrame(true) }),
      el("button", { class: "btn", type: "button", text: "空の状態で開く", onclick: () => openFrame(false) }),
      el("a", {
        class: "btn", href: tool?.url || "#", target: "_blank", rel: "noopener", text: "別タブで開く",
        hidden: !tool?.url || null,
      }),
    ]),
    frameWrap,
  );

  cyberchefAvailable().then((ok) => {
    if (ok) openFrame(false);
    else {
      frameWrap.replaceChildren(el("div", { class: "mod-help" }, [
        el("h4", { class: "side-h", style: "margin-top:0", text: "CyberChef がまだビルドされていません" }),
        el("p", { class: "modal-desc", text: "同梱の CyberChef はソースだけなので、一度ビルドすると開けます。" }),
        el("pre", { class: "mod-pre", text: cyberchefBuildHint(tool) }),
        el("p", { class: "modal-desc", text: "配信側では CI がビルドするため、GitHub Pages 上では自動で使えます。" }),
      ]));
    }
  });
}
