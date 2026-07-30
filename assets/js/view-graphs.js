// 保存したグラフの一覧。
//
// API の一覧はメタデータ（id・公開範囲・更新時刻・サイズ）しか返さず、
// 題・説明・画面写真は STIX 本体の中にある。そのため一覧を出すには
// 1 件ずつ本体を取りに行く必要がある。毎回全部取ると重いので、
// 取れた分は localStorage に控えて次からは即座に出す。
//
// 将来 API 側が一覧に name / description を載せたら、stix-store.js の
// normalize() がそれを拾うのでこの追加取得は自然に減る。

import { authState, onAuthChange } from "./auth-active-research.js";
import { list, read, remove } from "./stix-store.js";
import { el, shorten } from "./util.js";
import { openSavedGraph } from "./view-workbench.js";

const CACHE_KEY = "rb-graphs-v1";
/** 本体の同時取得数。一覧を開いた瞬間に何十本も並列で投げない */
const FETCH_CONCURRENCY = 4;

let root = null;
let items = [];
let visibility = "me";
let loading = false;
let error = null;
let bound = false;

/* ---------------- 控え ---------------- */

function readCache() {
  try { return JSON.parse(localStorage.getItem(CACHE_KEY) || "{}"); } catch { return {}; }
}

function writeCache(map) {
  try { localStorage.setItem(CACHE_KEY, JSON.stringify(map)); } catch { /* 容量超過は無視してよい */ }
}

/** 控えは更新時刻で持つ。API 側が更新されていたら作り直す。 */
function mergeCache(list) {
  const cache = readCache();
  return list.map((o) => {
    const c = cache[o.id];
    if (o.loaded || !c || c.updatedAt !== o.updatedAt) return o;
    return { ...o, title: c.title, description: c.description, screenshot: c.screenshot, loaded: true };
  });
}

function rememberCache(item) {
  const cache = readCache();
  cache[item.id] = {
    updatedAt: item.updatedAt,
    title: item.title,
    description: item.description,
    // 画面写真は控えの大半を占めるので、大きすぎるものは控えない
    screenshot: (item.screenshot || "").length < 200_000 ? item.screenshot : null,
  };
  writeCache(cache);
}

/* ---------------- 取得 ---------------- */

async function load() {
  loading = true;
  error = null;
  render();
  try {
    items = mergeCache(await list({ visibility, limit: 100 }));
    render();
    await fillMissing();
  } catch (e) {
    error = e.message || String(e);
    items = [];
  } finally {
    loading = false;
    render();
  }
}

/** 題や画面写真が無い分だけ本体を取りに行く。届いた順に画面へ出す。 */
async function fillMissing() {
  const queue = items.filter((o) => !o.loaded).map((o) => o.id);
  if (!queue.length) return;

  let cursor = 0;
  const worker = async () => {
    while (cursor < queue.length) {
      const id = queue[cursor++];
      try {
        const full = await read(id);
        const i = items.findIndex((o) => o.id === id);
        // 取得中に一覧が入れ替わっていたら捨てる
        if (i < 0) continue;
        items[i] = { ...items[i], ...full };
        rememberCache(items[i]);
        render();
      } catch {
        const i = items.findIndex((o) => o.id === id);
        if (i >= 0) { items[i] = { ...items[i], loaded: true, failed: true }; render(); }
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(FETCH_CONCURRENCY, queue.length) }, worker));
}

/* ---------------- 画面 ---------------- */

function fmtDate(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(+d)) return "";
  const p = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

function fmtSize(n) {
  if (!n) return "";
  return n >= 1048576 ? `${(n / 1048576).toFixed(1)} MB` : `${Math.round(n / 1024)} KB`;
}

function closeMenus() {
  for (const m of document.querySelectorAll(".gcard-menu[open]")) m.removeAttribute("open");
}

async function openItem(item) {
  // 一覧では本体まで取っていないことがある。開く直前に確実に取る
  let full = item;
  if (!item.snapshot && !item.stix) {
    try {
      full = { ...item, ...(await read(item.id)) };
    } catch (e) {
      error = e.message || String(e);
      render();
      return;
    }
  }
  if (openSavedGraph(full)) location.hash = "#/workbench";
}

async function deleteItem(item) {
  closeMenus();
  try {
    await remove(item.id);
    items = items.filter((o) => o.id !== item.id);
    const cache = readCache();
    delete cache[item.id];
    writeCache(cache);
    render();
  } catch (e) {
    error = e.message || String(e);
    render();
  }
}

/** ⋯ メニュー。details/summary で開閉するので JS の状態を持たない。 */
function cardMenu(item) {
  const menu = el("details", { class: "gcard-menu" }, [
    el("summary", { class: "gcard-dots", title: "この保存の操作", "aria-label": "メニュー" }, ["⋯"]),
    el("div", { class: "gcard-pop" }, [
      el("button", {
        class: "popover-item", type: "button", text: "開く",
        onclick: (ev) => { ev.stopPropagation(); closeMenus(); openItem(item); },
      }),
      el("button", {
        class: "popover-item is-danger", type: "button",
        text: item.canWrite === false ? "削除（権限なし）" : "削除",
        disabled: item.canWrite === false,
        onclick: (ev) => { ev.stopPropagation(); confirmDelete(item, menu); },
      }),
    ]),
  ]);
  // カード全体のクリック（＝開く）に巻き込まれないようにする
  menu.addEventListener("click", (ev) => ev.stopPropagation());
  return menu;
}

/** 削除は取り消せないので、その場で一段挟む。 */
function confirmDelete(item, menu) {
  const pop = menu.querySelector(".gcard-pop");
  pop.replaceChildren(
    el("p", { class: "gcard-confirm", text: "削除すると STIX は復元できません。" }),
    el("button", {
      class: "popover-item", type: "button", text: "やめる",
      onclick: (ev) => { ev.stopPropagation(); closeMenus(); render(); },
    }),
    el("button", {
      class: "popover-item is-danger", type: "button", text: "削除する",
      onclick: (ev) => { ev.stopPropagation(); deleteItem(item); },
    }),
  );
}

function card(item) {
  const thumb = item.screenshot
    ? el("img", { class: "gcard-shot", src: item.screenshot, alt: "", loading: "lazy" })
    : el("div", { class: "gcard-shot is-empty", text: item.loaded ? "画面写真なし" : "読み込み中…" });

  const meta = [
    fmtDate(item.updatedAt),
    item.objectCount != null ? `${item.objectCount} オブジェクト` : null,
    fmtSize(item.sizeBytes),
  ].filter(Boolean).join(" · ");

  return el("article", {
    class: "gcard", tabindex: "0", role: "button",
    "aria-label": `${item.title || "無題"} を開く`,
    onclick: () => openItem(item),
    onkeydown: (ev) => {
      if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); openItem(item); }
    },
  }, [
    thumb,
    el("div", { class: "gcard-body" }, [
      el("div", { class: "gcard-head" }, [
        el("h3", { class: "gcard-title", text: item.title || (item.failed ? "（読み込めませんでした）" : "無題のグラフ") }),
        cardMenu(item),
      ]),
      item.description
        ? el("p", { class: "gcard-desc", text: shorten(item.description, 120) })
        : null,
      el("p", { class: "gcard-meta" }, [
        el("span", { class: `gcard-vis is-${item.visibility}`, text: item.visibility === "public" ? "公開" : "自分だけ" }),
        el("span", { text: meta }),
      ]),
    ]),
  ]);
}

function render() {
  if (!root) return;
  const a = authState();

  const tabs = el("div", { class: "gv-tabs" }, [
    ["me", "自分のグラフ"], ["public", "公開されているもの"],
  ].map(([v, label]) => el("button", {
    class: "btn" + (visibility === v ? " is-on" : ""), type: "button", text: label,
    onclick: () => { if (visibility !== v) { visibility = v; load(); } },
  })));

  const head = el("div", { class: "gv-head" }, [
    el("div", {}, [
      el("h2", { class: "gv-title", text: "保存したグラフ" }),
      el("p", { class: "gv-lead", text: "調査 API の STIX ストレージに置いたものです。押すとワークベンチに復元します。" }),
    ]),
    tabs,
    el("button", { class: "btn", type: "button", text: "再読み込み", onclick: () => load() }),
  ]);

  let main;
  if (visibility === "me" && !a.loggedIn) {
    main = el("div", { class: "gv-empty" }, [
      el("p", { text: "自分のグラフを見るには調査 API へのログインが必要です。" }),
      el("p", { class: "gv-hint", text: "左端の鍵アイコン（OSINT 設定）から GitHub でログインしてください。保存・更新・削除も同様です。" }),
    ]);
  } else if (error) {
    main = el("div", { class: "gv-empty is-error" }, [el("p", { text: error })]);
  } else if (loading && !items.length) {
    main = el("div", { class: "gv-empty" }, [el("p", { text: "読み込み中…" })]);
  } else if (!items.length) {
    main = el("div", { class: "gv-empty" }, [
      el("p", { text: visibility === "me" ? "まだ保存したグラフがありません。" : "公開されているグラフはありません。" }),
      el("p", { class: "gv-hint", text: "ワークベンチでグラフを作り、右上の「保存」から保存できます。" }),
    ]);
  } else {
    main = el("div", { class: "gv-grid" }, items.map(card));
  }

  root.replaceChildren(el("div", { class: "gv" }, [head, main]));
}

export function renderGraphs(container) {
  root = container;
  if (!bound) {
    bound = true;
    // ログインし直したら一覧を取り直す（未ログインでは me が空のため）
    onAuthChange(() => { if (root) load(); });
    document.addEventListener("click", closeMenus);
  }
  render();
  load();
}
