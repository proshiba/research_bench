// ダッシュボード。選択中アプリの画面を iframe で表示する。
//
// GitHub Pages のプロジェクトページは全て同一オリジン（https://<user>.github.io）なので、
// 埋め込み先の DOM に触れる。meta.json / apps.json の embed_css を注入して
// アプリ側のヘッダーとポータルのクロームが二重になるのを防ぐ（仕様 §4）。

import { el } from "./util.js";

let mounted = null;

// 速報トップから「この記事を開く」と言われたときの行き先。
// 一度使ったら捨てる（次に同じアプリを開いたときは普通の入口に戻す）。
let pendingUrl = null;

export function openDashboardAt(url) {
  pendingUrl = url || null;
}

export function renderDashboard(root, source) {
  if (!source) {
    root.replaceChildren(el("div", { class: "empty" }, [
      el("h2", { text: "表示できるアプリがありません" }),
      el("p", { text: "apps.json にソースを登録してください。" }),
    ]));
    return;
  }

  // 同じアプリを表示中なら iframe を作り直さない（再読み込みを避ける）。
  // ただし行き先を指定されているときは、その場所へ移す。
  if (mounted?.appId === source.app_id && root.contains(mounted.wrap)) {
    if (pendingUrl) {
      mounted.frame.src = pendingUrl;
      pendingUrl = null;
    }
    return;
  }

  const loading = el("div", { class: "frame-loading" }, [
    el("div", { class: "spinner" }),
    el("span", { text: `${source.name} を読み込んでいます` }),
  ]);

  const src = pendingUrl || source.dashboard_url || source.site_url;
  pendingUrl = null;

  const frame = el("iframe", {
    src,
    title: source.name,
    loading: "lazy",
    referrerpolicy: "no-referrer",
    allow: "clipboard-write",
  });

  frame.addEventListener("load", () => {
    loading.hidden = true;
    injectEmbedCss(frame, source);
  });

  frame.addEventListener("error", () => {
    loading.replaceChildren(
      el("span", { text: `${source.name} を読み込めませんでした` }),
      el("a", { class: "btn", href: source.site_url, target: "_blank", rel: "noopener", text: "別タブで開く" }),
    );
  });

  const host = el("div", { class: "frame-host" }, [frame, loading]);
  const wrap = el("div", { class: "frame-wrap" }, [
    el("div", { class: "frame-bar" }, [
      el("span", { class: "frame-tag", text: "IFRAME" }),
      el("span", { class: "frame-url", text: src }),
      el("span", { class: "frame-note", text: source.repository ? source.app_id : "" }),
    ]),
    host,
  ]);

  root.replaceChildren(wrap);
  mounted = { appId: source.app_id, wrap, frame };
}

function injectEmbedCss(frame, source) {
  if (!source.embed_css) return;
  try {
    const doc = frame.contentDocument;
    if (!doc) return; // 別オリジン（ローカル開発時など）
    const style = doc.createElement("style");
    style.dataset.injectedBy = "research_bench";
    style.textContent = source.embed_css;
    doc.head.appendChild(style);
  } catch {
    // 別オリジンで触れない場合は何もしない。表示自体には影響しない。
  }
}

export function currentFrameUrl() {
  if (!mounted?.frame) return null;
  try {
    return mounted.frame.contentWindow.location.href;
  } catch {
    return mounted.frame.src;
  }
}
