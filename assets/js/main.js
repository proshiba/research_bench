// ポータルの起動・ルーティング・クローム（上部バー / ステータスバー）。

import { authState, finishLogin, loadAuth, onAuthChange } from "./auth-active-research.js";
import { loadCredentials, resetCredentials } from "./credentials.js";
import { freshness, oldestSource } from "./freshness.js";
import { getModule, loadModuleSettings } from "./modules.js";
import { loadSettings } from "./osint.js";
import { deepLink, getSource, initStore, loadSource, onChange, store } from "./store.js";
import { el, esc, fmtBytes, fmtNum } from "./util.js";
import { openDashboardAt, renderDashboard } from "./view-dashboard.js";
import { renderGraphs } from "./view-graphs.js";
import { renderModules } from "./view-modules.js";
import { openOsintSettings, osintSummary, osintTooltip } from "./view-osint-settings.js";
import { renderSearch } from "./view-search.js";
import { refreshTop, renderTop } from "./view-top.js";
import { pivotTo, renderWorkbench } from "./view-workbench.js";

const dom = {
  rail: document.querySelectorAll(".rail-btn[data-route]"),
  views: document.querySelectorAll(".view"),
  ctxBtn: document.getElementById("ctxBtn"),
  ctxMenu: document.getElementById("ctxMenu"),
  ctxDot: document.getElementById("ctxDot"),
  ctxHome: document.getElementById("ctxHome"),
  ctxName: document.getElementById("ctxName"),
  ctxSlug: document.getElementById("ctxSlug"),
  ctxCaret: document.getElementById("ctxCaret"),
  searchForm: document.getElementById("searchForm"),
  q: document.getElementById("q"),
  statusbar: document.getElementById("statusbar"),
  repoBtn: document.getElementById("repoBtn"),
  repoMenu: document.getElementById("repoMenu"),
  themeBtn: document.getElementById("themeBtn"),
  osintBtn: document.getElementById("osintBtn"),
  osintDialog: document.getElementById("osintDialog"),
  openExternal: document.getElementById("openExternal"),
};

const state = { route: "dashboard", appId: null, query: "", moduleId: null };

/* ---------------- ルーティング ---------------- */

function parseHash() {
  const raw = location.hash.replace(/^#\/?/, "");
  const [route, ...rest] = raw.split("/");
  const arg = rest.join("/");
  if (route === "search") return { route: "search", query: decodeURIComponent(arg || "") };
  if (route === "workbench") return { route: "workbench" };
  if (route === "graphs") return { route: "graphs" };
  if (route === "modules") return { route: "modules", moduleId: decodeURIComponent(arg || "") || null };
  if (route === "dashboard") return { route: "dashboard", appId: arg || null };
  return { route: "dashboard", appId: null };
}

function setHash(route, arg) {
  const next = arg ? `#/${route}/${encodeURIComponent(arg)}` : `#/${route}`;
  if (location.hash === next) render();   // 同じ検索語の再実行
  else location.hash = next;
}

async function render() {
  const parsed = parseHash();
  state.route = parsed.route;
  // ダッシュボードは引数なし＝速報トップ、引数ありでそのアプリ
  if (parsed.route === "dashboard") state.appId = parsed.appId || null;
  if (parsed.route === "search") state.query = parsed.query;
  if (parsed.route === "modules") state.moduleId = parsed.moduleId;

  for (const btn of dom.rail) {
    btn.setAttribute("aria-current", String(btn.dataset.route === state.route));
  }
  for (const view of dom.views) {
    view.classList.toggle("is-active", view.dataset.route === state.route);
  }

  updateTopbar();

  const view = [...dom.views].find((v) => v.dataset.route === state.route);
  if (!view) return;

  if (state.route === "dashboard") {
    if (state.appId) renderDashboard(view, getSource(state.appId));
    else renderTop(view, { onOpen: openFromTop, onQuery: (q) => setHash("search", q) });
  } else if (state.route === "search") {
    dom.q.value = state.query;
    await renderSearch(view, state.query, { onPivot: handlePivot });
  } else if (state.route === "workbench") {
    await renderWorkbench(view, { onQuery: (q) => setHash("search", q) });
  } else if (state.route === "graphs") {
    renderGraphs(view);
  } else if (state.route === "modules") {
    renderModules(view, {
      moduleId: state.moduleId,
      onOpen: (id) => setHash("modules", id),
      onBack: () => setHash("modules"),
    });
  }
}

/** 速報トップから、そのアプリのダッシュボードへ移る（実体があればその場所へ）。 */
function openFromTop(appId, entity) {
  const source = getSource(appId);
  if (entity && source) openDashboardAt(deepLink(entity, entity.type) || null);
  setHash("dashboard", appId);
}

async function handlePivot(action) {
  if (action.kind === "query") {
    setHash("search", action.query);
    return;
  }
  if (action.kind === "graph") {
    setHash("workbench");
    await renderWorkbench(
      [...dom.views].find((v) => v.dataset.route === "workbench"),
      { onQuery: (q) => setHash("search", q) },
    );
    pivotTo(action.source, action.entity);
  }
}

/* ---------------- 上部バー ---------------- */

function updateTopbar() {
  const isDashboard = state.route === "dashboard";
  // ダッシュボード以外ではアプリ選択の意味が無いが、押せない箱が残っていると
  // 操作できないことが分かりにくい。ここをダッシュボードへ戻る入口にする。
  dom.ctxBtn.disabled = false;
  dom.ctxCaret.hidden = !isDashboard;
  dom.ctxHome.hidden = isDashboard;
  dom.ctxDot.hidden = !isDashboard;
  dom.ctxBtn.classList.toggle("is-home", !isDashboard);
  dom.ctxBtn.setAttribute("aria-haspopup", String(isDashboard));
  dom.ctxBtn.title = isDashboard ? "表示するアプリを選ぶ" : "ダッシュボードに戻る";

  if (isDashboard) {
    const s = state.appId ? getSource(state.appId) : null;
    dom.ctxDot.style.color = s ? `var(--src-${s.accent})` : "var(--ink-faint)";
    dom.ctxName.textContent = s ? s.name : "速報";
    dom.ctxSlug.textContent = s ? s.app_id : "トップ";
    dom.openExternal.hidden = !s;
    if (s) dom.openExternal.href = s.dashboard_url || s.site_url;
  } else if (state.route === "modules") {
    const mod = state.moduleId ? getModule(state.moduleId) : null;
    dom.ctxDot.style.color = mod ? `var(${mod.accent})` : "var(--ink-faint)";
    dom.ctxName.textContent = mod ? mod.name : "モジュール";
    dom.ctxSlug.textContent = mod ? mod.id : "個別機能";
    dom.openExternal.hidden = true;
  } else {
    dom.ctxDot.style.color = "var(--ink-faint)";
    const TITLES = {
      search: ["クロスサーチ", "統合インデックス"],
      graphs: ["保存したグラフ", "STIX ストレージ"],
      workbench: ["ワークベンチ", "統合グラフ"],
    };
    const [name, slug] = TITLES[state.route] || TITLES.workbench;
    dom.ctxName.textContent = name;
    dom.ctxSlug.textContent = slug;
    dom.openExternal.hidden = true;
  }
  // ワークベンチではグラフ内の操作と紛れやすいので、検索窓は虫眼鏡だけに縮めておく
  setSearchCompact(state.route === "workbench" && !dom.q.value.trim());

  buildAppMenu();
  closeMenus();
}

function setSearchCompact(compact) {
  dom.searchForm.classList.toggle("is-compact", compact);
  dom.searchForm.title = compact ? "クリックして全ソース横断検索" : "";
}

function buildAppMenu() {
  dom.ctxMenu.replaceChildren(el("div", { class: "menu-label", text: `接続ソース · spec v${store.spec}` }));
  dom.ctxMenu.append(el("button", {
    class: "ctx-item", type: "button", role: "menuitem",
    "aria-current": String(state.route === "dashboard" && !state.appId),
    onclick: () => { setHash("dashboard"); closeMenus(); },
  }, [
    el("span", { class: "ctx-dot", style: "color:var(--focus)" }),
    el("span", { class: "ctx-item-name", text: "速報トップ" }),
    el("span", { class: "ctx-item-slug", text: "各ソースの新着" }),
  ]));
  for (const s of store.sources) {
    dom.ctxMenu.append(el("button", {
      class: "ctx-item", type: "button", role: "menuitem",
      "aria-current": String(s.app_id === state.appId),
      onclick: () => { setHash("dashboard", s.app_id); closeMenus(); },
    }, [
      el("span", { class: "ctx-dot", style: `color:var(--src-${s.accent})` }),
      el("span", { class: "ctx-item-name", text: s.name }),
      el("span", { class: "ctx-item-slug", text: s.app_id }),
    ]));
  }
}

function closeMenus() {
  dom.ctxMenu.hidden = true;
  dom.ctxBtn.setAttribute("aria-expanded", "false");
  dom.repoMenu.hidden = true;
  dom.repoBtn.setAttribute("aria-expanded", "false");
}

/* ---------------- ステータスバー ---------------- */

function renderStatus() {
  const bar = dom.statusbar;
  bar.replaceChildren();
  bar.append(el("span", { html: `spec <b>v${esc(store.spec || "1.0")}</b>` }));
  // どのビルドを見ているかが分かるようにする。キャッシュ由来の混乱を切り分けるため
  const build = document.querySelector('meta[name="rb-build"]')?.content || "dev";
  bar.append(el("span", { html: `build <b>${esc(build)}</b>`, title: "配信中のポータルのビルド識別子" }));
  if (newBuild) {
    bar.append(el("button", {
      class: "st-link is-new", type: "button",
      text: `新しいビルド ${newBuild} があります — 再読み込み`,
      title: "ブラウザが古い index.html を掴んでいます。押すと取り直します",
      onclick: () => location.reload(),
    }));
  }

  let indexed = 0;
  for (const s of store.sources) {
    if (s.status === "ready") indexed += s.entities.length;
    const cls = s.status === "ready" ? "" : s.status === "loading" ? " is-loading"
      : s.status === "error" ? " is-error" : " is-idle";
    const label = s.status === "ready" ? fmtNum(s.entities.length)
      : s.status === "loading" ? `${Math.round(s.progress * 100)}%`
      : s.status === "error" ? "失敗" : "未取得";
    const f = freshness(s);
    bar.append(el("span", {
      class: `st-src${cls}`,
      style: s.status === "ready" || s.status === "loading" ? `color:var(--src-${s.accent})` : null,
      title: s.status === "error" ? s.error
        : s.status === "idle" ? `${fmtBytes(s.approx_bytes)} — 検索時に取得します\n${f.text}`
        : `${s.app_id}\n${f.text}`,
    }, [
      el("i"),
      el("span", { style: "color:var(--ink-faint)", text: `${s.short || s.name} ${label}` }),
    ]));
  }

  bar.append(el("span", { html: `索引 <b>${fmtNum(indexed)}</b> エンティティ` }));

  // 索引そのものの古さ。ポータルの build 表示と並べて、
  // 「画面が古い」の原因がどちら側かをここだけで見分けられるようにする。
  const worst = oldestSource(store.sources);
  if (worst) {
    const f = worst.freshness;
    bar.append(el("button", {
      class: `st-link is-age is-${f.level}`, type: "button",
      text: `索引 最古 ${worst.source.short || worst.source.name} ${f.label}`,
      title: `${f.title}\n\n押すと全ソースの索引を取り直します（ブラウザの写しは使いません）`,
      onclick: () => store.sources.forEach((s) => loadSource(s, { force: true })),
    }));
  }
  bar.append(el("button", {
    class: "st-link", type: "button", text: osintSummary(), title: osintTooltip(),
    onclick: () => openOsintSettings(dom.osintDialog),
  }));

  // Active Research にログインしているか。エラーは警戒色で出す
  const auth = authState();
  const name = auth.user?.login || auth.user?.name;
  bar.append(el("button", {
    class: `st-link${auth.error ? " is-error" : ""}${auth.loggedIn ? " is-on" : ""}`,
    type: "button",
    text: auth.error ? "調査 API ログイン失敗"
      : auth.loggedIn ? `調査 API ${name ? `@${name}` : "ログイン中"}` : "調査 API 未ログイン",
    title: auth.error || (auth.loggedIn
      ? `Active Research にログインしています${auth.scope ? `（scope: ${auth.scope}）` : ""}`
      : "Active Research は未ログインでも一部使えます。押すと設定を開きます"),
    onclick: () => openOsintSettings(dom.osintDialog),
  }));

  const failed = store.sources.filter((s) => s.status === "error");
  if (failed.length) {
    bar.append(el("button", {
      class: "btn push", type: "button", style: "font-size:10.5px;padding:2px 7px",
      text: `${failed.length} ソースの取得に失敗 — 再試行`,
      onclick: () => failed.forEach((s) => loadSource(s, { force: true })),
    }));
  } else {
    bar.append(el("span", { class: "push", text: "GitHub Pages 上の静的インデックスを直接読み込んでいます" }));
  }
}

/* ---------------- 配信版の追従 ---------------- */

// GitHub Pages は index.html に max-age=600 を付けるため、更新直後は
// 古い index.html を掴んだままになる。資産には ?v=<sha> を付けているので
// 一度掴んだ組は一貫しているが、「直したはずが変わらない」に見えてしまう。
// 起動時に配信側の版を見に行き、違っていたら気づけるようにする。
let newBuild = null;

async function checkBuild() {
  const current = document.querySelector('meta[name="rb-build"]')?.content;
  if (!current || current === "dev") return;      // ローカルでは意味がない
  try {
    const res = await fetch(`index.html?_=${Date.now()}`, { cache: "no-store" });
    if (!res.ok) return;
    const latest = (await res.text()).match(/name="rb-build"\s+content="([^"]+)"/)?.[1];
    if (latest && latest !== current) {
      newBuild = latest;
      renderStatus();
    }
  } catch {
    // 取れなくても支障はない。表示中の版のまま使える
  }
}

/* ---------------- リポジトリ ---------------- */

const GH_ICON = '<svg viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82a7.6 7.6 0 0 1 2-.27c.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8Z"/></svg>';

function buildRepoMenu() {
  const repos = [
    { name: "proshiba/research_bench", url: "https://github.com/proshiba/research_bench" },
    ...store.sources.filter((s) => s.repository).map((s) => ({
      name: s.repository.replace("https://github.com/", ""), url: s.repository,
    })),
  ];
  dom.repoMenu.replaceChildren(el("div", { class: "menu-label", text: "リポジトリ" }));
  for (const r of repos) {
    dom.repoMenu.append(el("a", {
      class: "popover-item", href: r.url, target: "_blank", rel: "noopener", role: "menuitem",
      html: GH_ICON + esc(r.name),
    }));
  }
}

/* ---------------- テーマ ---------------- */

const THEMES = ["auto", "light", "dark"];

function applyTheme(next) {
  if (next === "auto") document.documentElement.removeAttribute("data-theme");
  else document.documentElement.setAttribute("data-theme", next);
  try { localStorage.setItem("rb-theme", next); } catch { /* プライベートモードなど */ }
  dom.themeBtn.title = `表示テーマ: ${{ auto: "自動", light: "ライト", dark: "ダーク" }[next]}`;
}

function initTheme() {
  let saved = "auto";
  try { saved = localStorage.getItem("rb-theme") || "auto"; } catch { /* 読めなくても既定で動く */ }
  applyTheme(THEMES.includes(saved) ? saved : "auto");
  dom.themeBtn.addEventListener("click", () => {
    const cur = document.documentElement.getAttribute("data-theme") || "auto";
    applyTheme(THEMES[(THEMES.indexOf(cur) + 1) % THEMES.length]);
  });
}

/* ---------------- 起動 ---------------- */

async function boot() {
  initTheme();
  loadSettings();         // 前回 session/local に置いた OSINT 設定があれば戻す
  loadModuleSettings();   // モジュールの設定（API のベース URL など）
  loadAuth();             // 調査 API のセッション

  // 認証から戻ってきた直後なら URL に code が載っている。索引の読み込みより先に
  // 片付ける（URL から消すのを遅らせない。履歴とブックマークに残るため）
  await finishLogin().catch((err) => console.warn("[research_bench] ログインの後処理", err));

  try {
    await initStore();
  } catch (err) {
    document.getElementById("stage").innerHTML =
      `<div class="empty"><h2>起動できませんでした</h2><p>${esc(err.message)}</p></div>`;
    return;
  }

  buildAppMenu();
  buildRepoMenu();
  renderStatus();
  onChange(() => { renderStatus(); buildAppMenu(); refreshTop(); });
  onAuthChange(() => {
    renderStatus();
    // ログインし直したら預けているキーの状態を取り直す
    // （ログアウト時は空に戻す）
    resetCredentials();
    loadCredentials();
  });
  checkBuild();           // 配信側に新しい版が出ていないか（待たない）

  for (const btn of dom.rail) {
    btn.addEventListener("click", () => {
      if (btn.dataset.route === "search") setHash("search", dom.q.value.trim());
      else setHash(btn.dataset.route);
    });
  }

  dom.ctxBtn.addEventListener("click", (ev) => {
    ev.stopPropagation();
    // ダッシュボード以外ではアプリ選択ではなく「戻る」として働く
    if (state.route !== "dashboard") {
      closeMenus();
      setHash("dashboard");
      return;
    }
    const open = dom.ctxMenu.hidden;
    closeMenus();
    dom.ctxMenu.hidden = !open;
    dom.ctxBtn.setAttribute("aria-expanded", String(open));
  });

  dom.osintBtn.addEventListener("click", () => openOsintSettings(dom.osintDialog));
  dom.osintDialog.addEventListener("close", renderStatus);

  dom.repoBtn.addEventListener("click", (ev) => {
    ev.stopPropagation();
    const open = dom.repoMenu.hidden;
    closeMenus();
    if (!open) return;
    dom.repoMenu.hidden = false;
    dom.repoBtn.setAttribute("aria-expanded", "true");
    const r = dom.repoBtn.getBoundingClientRect();
    const h = dom.repoMenu.offsetHeight;
    dom.repoMenu.style.left = `${r.right + 6}px`;
    dom.repoMenu.style.top = `${Math.max(8, Math.min(r.bottom - h, innerHeight - h - 8))}px`;
  });

  dom.ctxMenu.addEventListener("click", (ev) => ev.stopPropagation());
  dom.repoMenu.addEventListener("click", (ev) => ev.stopPropagation());
  document.addEventListener("click", closeMenus);
  document.addEventListener("keydown", (ev) => {
    if (ev.key === "Escape") closeMenus();
    // 「/」で検索へ飛ぶ。ただし文字を打っている最中は横取りしない。
    // ここを active===dom.q だけで判定すると、トレイや保存グラフ検索など
    // 他の入力欄で「/」が食われ、URL やパス（http:// など）が打てなくなる。
    // Cmd/Ctrl+K は入力中でも効くショートカットとして併せて用意する。
    const el = document.activeElement;
    const typing = el && (el.isContentEditable
      || el.tagName === "INPUT" || el.tagName === "TEXTAREA" || el.tagName === "SELECT");
    if ((ev.metaKey || ev.ctrlKey) && (ev.key === "k" || ev.key === "K")) {
      ev.preventDefault();
      focusSearch();
    } else if (ev.key === "/" && !typing) {
      ev.preventDefault();
      focusSearch();
    }
  });

  function focusSearch() {
    setSearchCompact(false);
    dom.q.focus();
    dom.q.select();
  }

  dom.searchForm.addEventListener("submit", (ev) => {
    ev.preventDefault();
    setHash("search", dom.q.value.trim());
  });

  dom.searchForm.addEventListener("click", () => {
    if (!dom.searchForm.classList.contains("is-compact")) return;
    setSearchCompact(false);
    dom.q.focus();
  });

  dom.q.addEventListener("focus", () => setSearchCompact(false));
  dom.q.addEventListener("blur", () => {
    if (state.route === "workbench" && !dom.q.value.trim()) setSearchCompact(true);
  });

  addEventListener("hashchange", render);
  await render();
}

boot();
