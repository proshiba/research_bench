// 「グラフを保存」のダイアログ。
//
// API が保存するのは STIX JSON だけなので、題・説明・画面写真は束の中の
// report オブジェクトに載せる（stix-store.js を参照）。ここは入力を取るだけ。

import { isLoggedIn } from "./auth-active-research.js";
import { el } from "./util.js";

const VISIBILITY = [
  ["me", "自分だけ", "作成者本人だけが一覧・取得できる。"],
  ["public", "公開", "URL を知らなくても匿名で一覧・取得できる。"],
];

/**
 * 保存ダイアログを開く。
 *
 * @param dialog   <dialog class="modal">
 * @param current  { id, title, description, visibility } — 更新のときだけ入る
 * @param onSubmit ({ title, description, visibility, asNew }) => Promise<void>
 */
export function openSaveDialog(dialog, current, onSubmit) {
  const updating = !!current?.id;

  const title = el("input", {
    class: "modal-input", type: "text", id: "gsTitle", maxlength: "200",
    value: current?.title || "", placeholder: "例: APT41 の C2 インフラ",
  });
  const desc = el("textarea", {
    class: "modal-input", id: "gsDesc", rows: "3", maxlength: "2000",
    placeholder: "何を追っていたか、どこまで分かったか（任意）",
  });
  desc.value = current?.description || "";

  const vis = current?.visibility || "me";
  const choices = VISIBILITY.map(([value, label, hint]) => el("label", { class: "modal-choice" }, [
    el("input", { type: "radio", name: "gs-visibility", value, checked: value === vis }),
    el("span", {}, [el("strong", { text: label }), el("span", { class: "modal-desc", text: hint })]),
  ]));

  const err = el("p", { class: "modal-lead is-error", hidden: true });
  const busy = (on) => {
    for (const b of dialog.querySelectorAll("button")) b.disabled = on;
    saveBtn.textContent = on ? "送信中…" : updating ? "更新する" : "保存する";
  };

  const submit = async (asNew) => {
    if (!title.value.trim()) {
      err.hidden = false;
      err.textContent = "題を入れてください。一覧で見分けが付かなくなります。";
      title.focus();
      return;
    }
    err.hidden = true;
    busy(true);
    try {
      await onSubmit({
        title: title.value.trim(),
        description: desc.value.trim(),
        visibility: dialog.querySelector('input[name="gs-visibility"]:checked')?.value || "me",
        asNew,
      });
      dialog.close();
    } catch (e) {
      err.hidden = false;
      err.textContent = e.message || String(e);
    } finally {
      busy(false);
    }
  };

  const saveBtn = el("button", {
    class: "btn is-primary", type: "button", text: updating ? "更新する" : "保存する",
    onclick: () => submit(false),
  });

  const footer = el("div", { class: "modal-footer" }, [
    el("div", { class: "modal-actions" }, [
      // 更新のときだけ「別物として残す」道を用意する。上書きは取り消せないため
      updating
        ? el("button", { class: "btn", type: "button", text: "別のグラフとして保存", onclick: () => submit(true) })
        : null,
      el("span", { style: "margin-left:auto" }),
      el("button", { class: "btn", type: "button", text: "やめる", onclick: () => dialog.close() }),
      saveBtn,
    ]),
  ]);

  const body = el("div", { class: "modal-body" }, [
    el("p", { class: "modal-lead" }, [
      "調査 API の STIX ストレージに保存します。",
      el("span", {
        class: "modal-desc",
        text: "保存されるのは STIX 2.1 の束です。題・説明・画面写真は束の中の report に載るので、"
          + "他の STIX ツールから読んでも題と説明が見えます。",
      }),
    ]),
    el("div", { class: "modal-field" }, [el("label", { for: "gsTitle", text: "題" }), title]),
    el("div", { class: "modal-field" }, [el("label", { for: "gsDesc", text: "説明（任意）" }), desc]),
    el("div", { class: "modal-field" }, [
      el("label", { text: "公開範囲" }),
      el("div", { class: "modal-choices" }, choices),
    ]),
    err,
  ]);

  dialog.replaceChildren(
    el("form", { method: "dialog", class: "modal-head" }, [
      el("h2", { class: "modal-title", id: "graphSaveTitle", text: updating ? "グラフを更新" : "グラフを保存" }),
      el("button", { class: "modal-close", type: "submit", value: "close", "aria-label": "閉じる", text: "×" }),
    ]),
    body,
    footer,
  );
  dialog.showModal();
  title.focus();
  title.select();

  if (!isLoggedIn()) {
    err.hidden = false;
    err.textContent = "保存には調査 API へのログインが必要です（左端の鍵アイコンから）。";
  }
}
