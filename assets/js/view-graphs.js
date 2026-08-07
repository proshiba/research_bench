// 保存したグラフの一覧。
//
// 題・説明・サムネイルの在処はすべて API の一覧に載るので、一覧は 1 リクエストで作れる。
// 絞り込みもサーバー側（?q=）に任せる。題・説明・STIX の name を横断してくれる。
//
// サムネイルだけは別。一覧に載るのは取得 URL とメタデータで、画像そのものは
// もう 1 回取りに行く。me のものは画像の取得にも Authorization が要るため、
// <img src="…"> では出せない（ヘッダを付けられない）。fetch してから
// オブジェクト URL にして貼る。

import { authState, onAuthChange } from "./auth-active-research.js";
import { list, read, remove, thumbnailUrl } from "./stix-store.js";
import { el, shorten } from "./util.js";
import { openSavedGraph, startNewGraph } from "./view-workbench.js";

let root = null;
let items = [];
let visibility = "me";
let query = "";
let loading = false;
let loadingMore = false;
let error = null;
let bound = false;
let reqSeq = 0;
let total = 0;
let hasMore = false;

/**
 * 画像の控え。鍵は `id:sha256`（sha256 は API が返す画像の指紋＝ETag と同じ値）。
 * 中身が変われば鍵も変わるので、更新した画像は自動で取り直される。
 * 変わっていなければ条件付き GET すら発生しない。
 */
const thumbs = new Map();

const thumbKey = (item) => `${item.id}:${item.thumbnail?.sha256 || ""}`;

function dropThumbs(keep) {
  for (const [key, url] of thumbs) {
    if (keep && keep.has(key)) continue;
    URL.revokeObjectURL(url);
    thumbs.delete(key);
  }
}

/* ---------------- 取得 ---------------- */

async function load() {
  const seq = ++reqSeq;
  loading = true;
  error = null;
  render();
  try {
    const got = await list({ visibility, q: query });
    // 打っている最中に前の結果が返ってくることがある。古いものは捨てる
    if (seq !== reqSeq) return;
    items = got.items;
    total = got.total;
    hasMore = got.hasMore;
    dropThumbs(new Set(items.map(thumbKey)));
  } catch (e) {
    if (seq !== reqSeq) return;
    error = e.message || String(e);
    items = [];
    total = 0;
    hasMore = false;
  } finally {
    if (seq === reqSeq) {
      loading = false;
      render();
    }
  }
}

/** 続きを足す。offset は今持っている件数から。 */
async function loadMore() {
  if (loadingMore || !hasMore) return;
  const seq = reqSeq;
  loadingMore = true;
  render();
  try {
    const got = await list({ visibility, q: query, offset: items.length });
    if (seq !== reqSeq) return;
    // 取得中に消えた分があると id が重なることがある。畳んでおく
    const seen = new Set(items.map((o) => o.id));
    items = [...items, ...got.items.filter((o) => !seen.has(o.id))];
    total = got.total;
    hasMore = got.hasMore;
  } catch (e) {
    if (seq === reqSeq) error = e.message || String(e);
  } finally {
    if (seq === reqSeq) {
      loadingMore = false;
      render();
    }
  }
}

/** 画像を取ってその img にだけ入れる。画面全体は描き直さない。 */
async function fillThumb(item, img) {
  const key = thumbKey(item);
  if (thumbs.has(key)) { img.src = thumbs.get(key); img.classList.remove("is-pending"); return; }
  try {
    const url = await thumbnailUrl(item.id);
    // 再描画などで同じ鍵の取得が並行すると、後勝ちで map を上書きし、
    // 先に作った objectURL が revoke されず孤児になる。既にあれば作った分は捨てる
    if (thumbs.has(key)) { URL.revokeObjectURL(url); img.src = thumbs.get(key); img.classList.remove("is-pending"); return; }
    thumbs.set(key, url);
    img.src = url;
    img.classList.remove("is-pending");
  } catch {
    img.replaceWith(el("div", { class: "gcard-shot is-empty", text: "画面写真を取得できませんでした" }));
  }
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
  // 一覧には STIX 本体が載らない。開く直前に取る
  let full = item;
  try {
    full = { ...item, ...(await read(item.id)) };
  } catch (e) {
    error = e.message || String(e);
    render();
    return;
  }
  if (openSavedGraph(full)) location.hash = "#/workbench";
}

async function deleteItem(item) {
  closeMenus();
  try {
    await remove(item.id);
    items = items.filter((o) => o.id !== item.id);
    total = Math.max(0, total - 1);
    dropThumbs(new Set(items.map(thumbKey)));
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
    el("p", { class: "gcard-confirm", text: "削除すると STIX と画面写真は復元できません。" }),
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
  let thumb;
  if (item.thumbnail) {
    thumb = el("img", { class: "gcard-shot is-pending", alt: "", loading: "lazy" });
    fillThumb(item, thumb);
  } else {
    thumb = el("div", { class: "gcard-shot is-empty", text: "画面写真なし" });
  }

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
        el("h3", { class: "gcard-title", text: item.title || "無題のグラフ" }),
        cardMenu(item),
      ]),
      item.description ? el("p", { class: "gcard-desc", text: shorten(item.description, 120) }) : null,
      el("p", { class: "gcard-meta" }, [
        el("span", { class: `gcard-vis is-${item.visibility}`, text: item.visibility === "public" ? "公開" : "自分だけ" }),
        item.visibility === "public" && item.owner ? el("span", { text: `@${item.owner}` }) : null,
        el("span", { text: meta }),
      ]),
    ]),
  ]);
}

let searchTimer = null;
let shell = null;      // { wrap, main, tabs }

/**
 * 外枠は 1 回だけ組んで使い回す。
 * 絞り込みのたびに作り直すと、打っている最中に入力欄が入れ替わって
 * focus とカーソル位置が飛ぶ。
 */
function buildShell() {
  const search = el("input", {
    class: "gv-search", type: "search", id: "gvSearch",
    placeholder: "題や説明で検索",
    "aria-label": "保存したグラフを題・説明で検索",
    title: "サーバー側で絞り込みます（題・説明のほか、STIX の名前も見ます）",
    oninput: (ev) => {
      query = ev.target.value;
      // 1 文字ごとに投げない。打ち終わりを待つ
      clearTimeout(searchTimer);
      searchTimer = setTimeout(load, 280);
    },
  });
  // 検索欄だと分かるように虫眼鏡を添える
  const searchBox = el("div", { class: "gv-search-box" }, [
    el("span", {
      class: "gv-search-icon", "aria-hidden": "true",
      html: '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" '
        + 'stroke-linecap="round"><circle cx="7" cy="7" r="4.5"/><path d="M10.4 10.4 14 14"/></svg>',
    }),
    search,
  ]);

  const tabs = [["me", "自分のグラフ"], ["public", "公開されているもの"]].map(([v, label]) =>
    el("button", {
      class: "btn", type: "button", text: label, dataset: { vis: v },
      onclick: () => { if (visibility !== v) { visibility = v; load(); } },
    }));

  const main = el("div", { class: "gv-main" });
  const wrap = el("div", { class: "gv" }, [
    el("div", { class: "gv-head" }, [
      el("div", { class: "gv-headings" }, [
        el("h2", { class: "gv-title", text: "保存したグラフ" }),
        el("p", { class: "gv-lead", text: "調査 API の STIX ストレージに置いたものです。押すとワークベンチに復元します。" }),
      ]),
      searchBox,
      el("div", { class: "gv-tabs" }, tabs),
      el("button", { class: "btn", type: "button", text: "再読み込み", onclick: () => load() }),
      // 一覧からそのまま新しい調査を始められるようにする。
      // 一覧と描画が別画面なので、ここに入口が無いと行き来が分かりにくい
      el("button", {
        class: "btn is-primary", type: "button", text: "新規調査",
        title: "空のグラフでワークベンチを開く",
        onclick: () => { startNewGraph(); location.hash = "#/workbench"; },
      }),
    ]),
    main,
  ]);
  return { wrap, main, tabs };
}

function render() {
  if (!root) return;
  const a = authState();

  if (!shell || !root.contains(shell.wrap)) {
    shell = buildShell();
    root.replaceChildren(shell.wrap);
  }
  for (const t of shell.tabs) t.classList.toggle("is-on", t.dataset.vis === visibility);

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
      el("p", {
        text: query
          ? `「${query}」に当たるグラフはありません。`
          : visibility === "me" ? "まだ保存したグラフがありません。" : "公開されているグラフはありません。",
      }),
      query
        ? null
        : el("p", { class: "gv-hint", text: "ワークベンチでグラフを作り、右上の「保存」から保存できます。" }),
      query
        ? null
        : el("button", {
          class: "btn is-primary", type: "button", text: "新規調査を始める",
          onclick: () => { startNewGraph(); location.hash = "#/workbench"; },
        }),
    ]);
  } else {
    // 何件のうち何件を出しているかは常に断る（黙って打ち切らない）
    main = el("div", {}, [
      el("p", { class: "gv-count", text: total > items.length ? `${total} 件中 ${items.length} 件` : `${total} 件` }),
      el("div", { class: "gv-grid" }, items.map(card)),
      hasMore
        ? el("div", { class: "gv-more" }, [el("button", {
          class: "btn", type: "button", disabled: loadingMore,
          text: loadingMore ? "読み込み中…" : `さらに読み込む（残り ${Math.max(0, total - items.length)} 件）`,
          onclick: () => loadMore(),
        })])
        : null,
    ]);
  }

  shell.main.replaceChildren(main);
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
