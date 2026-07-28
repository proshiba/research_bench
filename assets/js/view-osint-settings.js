// OSINT 設定画面。API キーの置き場所をここで決める。
//
// キーはこのポータルの外に出さない。保存先の既定は「メモリだけ」で、
// リロードすると消える。session / local を選ぶと同一オリジンの別文書からも
// 読めるようになるため、その旨を画面にも書いてある。

import { PROVIDERS, clearSettings, getSettings, saveSettings } from "./osint.js";
import { el } from "./util.js";

const STORAGE_CHOICES = [
  ["memory", "メモリだけ", "リロードで消える。最も安全。"],
  ["session", "このタブだけ (sessionStorage)", "タブを閉じると消える。"],
  ["local", "このブラウザに保存 (localStorage)", "次回も残る。共有端末では避けること。"],
];

export function openOsintSettings(dialog) {
  const cur = getSettings();
  const note = el("p", { class: "modal-note" });

  const keyInputs = {};
  const keyRows = Object.entries(PROVIDERS)
    .filter(([, p]) => !p.linkOnly)
    .map(([id, p]) => {
      const input = el("input", {
        type: "password", class: "modal-input", autocomplete: "off", spellcheck: "false",
        id: `key-${id}`, value: cur.keys[p.keyField] || "", placeholder: "API キー",
      });
      keyInputs[p.keyField] = input;
      const reveal = el("button", {
        class: "btn", type: "button", text: "表示",
        onclick: () => {
          const hidden = input.type === "password";
          input.type = hidden ? "text" : "password";
          reveal.textContent = hidden ? "隠す" : "表示";
        },
      });
      return el("div", { class: "modal-field" }, [
        el("label", { for: `key-${id}` }, [
          p.label,
          el("span", {
            class: "chip", style: "margin-left:6px", text: "ブラウザから直接",
            title: "Access-Control-Allow-Origin: * を返すため、中継なしでそのまま呼べます",
          }),
        ]),
        el("div", { class: "modal-row" }, [input, reveal]),
      ]);
    });

  const linkOnly = Object.values(PROVIDERS).filter((p) => p.linkOnly).map((p) => p.label);

  // Active Research API 経由で使うトークン。値はあの API サーバーを通るので、
  // ブラウザだけで完結する Shodan とは節を分けて置く。
  const VIA_API = [
    ["virustotal", "VirusTotal のトークン", "ワークベンチの右クリック調査で使います"],
    ["github", "GitHub のトークン", "コード検索で使います"],
    ["abuseipdb", "AbuseIPDB のトークン", "IP の通報状況と信頼度スコアを引きます"],
  ];
  const viaRows = VIA_API.map(([field, label, hint]) => {
    const input = el("input", {
      type: "password", class: "modal-input", autocomplete: "off", spellcheck: "false",
      id: `key-${field}`, value: cur.keys[field] || "", placeholder: "トークン",
    });
    keyInputs[field] = input;
    const reveal = el("button", {
      class: "btn", type: "button", text: "表示",
      onclick: () => {
        const hidden = input.type === "password";
        input.type = hidden ? "text" : "password";
        reveal.textContent = hidden ? "隠す" : "表示";
      },
    });
    return el("div", { class: "modal-field" }, [
      el("label", { for: `key-${field}` }, [
        label,
        el("span", {
          class: "chip is-crit", style: "margin-left:6px", text: "端末の外に出る",
          title: "Active Research API に Authorization: Bearer で渡します",
        }),
      ]),
      el("div", { class: "modal-row" }, [input, reveal]),
      el("span", { class: "modal-desc", text: hint }),
    ]);
  });

  const storageSel = el("div", { class: "modal-choices" }, STORAGE_CHOICES.map(([value, label, desc]) =>
    el("label", { class: "modal-choice" }, [
      el("input", { type: "radio", name: "rb-storage", value, checked: cur.storage === value || null }),
      el("span", {}, [el("strong", { text: label }), el("span", { class: "modal-desc", text: desc })]),
    ])));

  function collect() {
    return {
      keys: Object.fromEntries(Object.entries(keyInputs).map(([f, i]) => [f, i.value.trim()])),
      storage: dialog.querySelector('input[name="rb-storage"]:checked')?.value || "memory",
    };
  }

  const body = el("div", { class: "modal-body" }, [
    el("p", { class: "modal-lead" }, [
      "キーはこのブラウザの中にだけ置きます。研究用リポジトリや GitHub Pages には保存されません。",
      el("br"),
      "ただし送信先は 2 通りあります。下の節ごとに書き分けてあります。",
    ]),

    el("h3", { class: "side-h", text: "ブラウザの中だけで使うキー" }),
    ...keyRows,

    el("h3", { class: "side-h", text: "Active Research API 経由で使うトークン" }),
    el("p", { class: "modal-desc", text:
      "これらは調査 API サーバーに Authorization: Bearer で渡します。"
      + "つまり値がこの端末の外に出ます。ブラウザだけで完結させたい場合は入れないでください。" }),
    ...viaRows,

    el("h3", { class: "side-h", text: "キーの置き場所" }),
    storageSel,

    el("h3", { class: "side-h", text: "キーを使わないサービス" }),
    el("p", { class: "modal-desc" }, [
      `${linkOnly.join(" / ")} はブラウザからの呼び出しに CORS を許可していないため、`,
      el("br"),
      "API 連携はしていません（中継サーバーを挟めば呼べますが、キーがブラウザの外に出ます）。",
      el("br"),
      "OSINT タブの「サイトで開く」から、キー無しで該当ページを開けます。",
    ]),
  ]);

  // note は footer 側に置く。本文をスクロールしていても結果が必ず見える。
  const footer = el("div", { class: "modal-footer" }, [
    note,
    el("div", { class: "modal-actions" }, [
      el("button", {
        class: "btn", type: "button", text: "すべて消す",
        onclick: () => {
          clearSettings();
          dialog.close();
        },
      }),
      el("span", { style: "flex:1" }),
      el("button", { class: "btn", type: "button", text: "閉じる", onclick: () => dialog.close() }),
      el("button", {
        class: "btn is-on", type: "button", text: "保存",
        onclick: () => {
          const saved = saveSettings(collect());
          const n = Object.values(saved.keys).filter(Boolean).length;
          note.className = "modal-note";
          note.textContent = `保存しました（キー ${n} 件 / 置き場所: ${
            STORAGE_CHOICES.find(([v]) => v === saved.storage)[1]}）`;
        },
      }),
    ]),
  ]);

  dialog.replaceChildren(
    el("form", { method: "dialog", class: "modal-head" }, [
      el("h2", { id: "osintTitle", class: "modal-title", text: "OSINT 設定" }),
      el("button", { class: "modal-close", type: "submit", "aria-label": "閉じる", text: "×" }),
    ]),
    body,
    footer,
  );
  dialog.showModal();
}

/** ステータスバー用の短い要約。 */
export function osintSummary() {
  const s = getSettings();
  const n = Object.values(s.keys).filter(Boolean).length;
  if (!n) return "OSINT 未設定";
  const where = { memory: "メモリ", session: "タブ", local: "ブラウザ" }[s.storage];
  return `OSINT ${n} 件（${where}）`;
}

export function osintTooltip() {
  const s = getSettings();
  const rows = [
    `Shodan: ${s.keys.shodan ? "設定済み" : "未設定"}（ブラウザから直接）`,
    `VirusTotal: ${s.keys.virustotal ? "設定済み" : "未設定"}（API 経由・端末の外に出る）`,
    `GitHub: ${s.keys.github ? "設定済み" : "未設定"}（API 経由・端末の外に出る）`,
    `AbuseIPDB: ${s.keys.abuseipdb ? "設定済み" : "未設定"}（API 経由・端末の外に出る）`,
  ];
  return rows.join("\n");
}
