// クロスサーチ。ソース別にまとめた結果と、ソース横断で一致した指標を示す。

import { crossSourceMatches, deepLink, loadAllSources, readySources, search, store } from "./store.js";
import { el, esc, fmtNum, highlight, typeLabel } from "./util.js";

let lastQuery = "";

export async function renderSearch(root, query, { onPivot, onRerender } = {}) {
  lastQuery = query;

  const pending = store.sources.filter((s) => s.status !== "ready");
  if (pending.length) {
    root.replaceChildren(loadingPanel(pending));
    await loadAllSources();
    if (lastQuery !== query) return; // 待っている間に別の検索へ移った
  }

  if (!query) {
    root.replaceChildren(idlePanel(onPivot));
    return;
  }

  const result = search(query);
  root.replaceChildren(resultPanel(result, { onPivot, onRerender }));
}

function loadingPanel(pending) {
  return el("div", { class: "empty" }, [
    el("div", { class: "spinner" }),
    el("h2", { text: "索引を読み込んでいます" }),
    el("p", { text: pending.map((s) => s.name).join(" / ") + " を取得中です。初回のみ時間がかかります。" }),
  ]);
}

function idlePanel(onPivot) {
  const ready = readySources();
  const total = ready.reduce((n, s) => n + s.entities.length, 0);
  const examples = ["45.66.228.114", "ValleyRAT", "CVE-2019-6446", "Lazarus"];

  return el("div", { class: "cs" }, [
    el("div", { class: "empty" }, [
      el("h2", { text: "全ソース横断で検索" }),
      el("p", {
        text: `${ready.length} ソース・${fmtNum(total)} 件のエンティティを索引しています。`
          + " IP・ドメイン・ハッシュ・CVE・アクター名などを上の検索バーに入力してください。",
      }),
      el("div", { class: "cs-suggest" }, examples.map((q) =>
        el("button", {
          class: "btn", type: "button", text: q,
          onclick: () => onPivot?.({ kind: "query", query: q }),
        }))),
    ]),
  ]);
}

function resultPanel(result, { onPivot, onRerender }) {
  const wrap = el("div", { class: "cs" });

  wrap.append(el("div", { class: "cs-head" }, [
    el("span", { class: "cs-q", text: result.query }),
    el("span", {
      class: "cs-kind",
      text: result.detectedType ? `${typeLabel(result.detectedType)} として解決` : "全文検索",
    }),
    el("span", {
      class: "cs-count",
      html: `${result.matchedSources} ソースでヒット · 全 <b>${fmtNum(result.total)}</b> 件`,
    }),
  ]));

  if (!result.groups.length) {
    wrap.append(el("div", { class: "empty" }, [
      el("h2", { text: "一致するものがありませんでした" }),
      el("p", { text: "難読化された指標（1.2.3[.]4 や hxxp://）はそのまま貼っても解釈します。" }),
    ]));
    appendLimits(wrap);
    return wrap;
  }

  const groups = el("div", { class: "cs-groups" });
  for (const g of result.groups) groups.append(groupCard(g, result, onPivot));
  wrap.append(groups);

  if (result.joinKeys.length) {
    const names = result.joinKeys[0].sources
      .map((id) => store.sources.find((s) => s.app_id === id)?.name || id);
    wrap.append(el("p", {
      class: "cs-note",
      html: `同じ指標が <strong>${names.join("</strong> と <strong>")}</strong> の両方にあります。`
        + " ワークベンチで開くと 1 つのノードに畳まれ、両ソースの関係が 1 枚のグラフになります。",
    }));
  }

  appendLimits(wrap);
  if (onRerender) wrap.dataset.query = result.query;
  return wrap;
}

function appendLimits(wrap) {
  const limited = store.sources.filter((s) => s.limits?.length);
  for (const s of limited) {
    wrap.append(el("p", { class: "cs-note", html: `<strong>${esc(s.name)}</strong> — ${esc(s.limits[0])}` }));
  }
  const failed = store.sources.filter((s) => s.status === "error");
  for (const s of failed) {
    wrap.append(el("p", {
      class: "cs-note",
      html: `<strong>${esc(s.name)}</strong> を読み込めませんでした: ${esc(s.error)}`,
    }));
  }
}

function groupCard(group, result, onPivot) {
  const s = group.source;
  const accent = `var(--src-${s.accent})`;
  const card = el("section", { class: "grp" });

  card.append(el("div", { class: "grp-head", style: `color:${accent}` }, [
    el("span", { class: "grp-dot" }),
    el("span", { class: "grp-name", text: s.name }),
    el("span", { class: "grp-slug", text: s.app_id }),
    el("span", {
      class: "grp-n",
      text: group.truncated ? `${fmtNum(group.items.length)} / ${fmtNum(group.count)} 件` : `${fmtNum(group.count)} 件`,
    }),
  ]));

  if (group.exactCount) {
    card.append(el("div", {
      class: "grp-note",
      text: `完全一致 ${group.exactCount} 件を先頭に表示しています。`,
    }));
  }

  for (const e of group.items) card.append(hitRow(e, s, result, onPivot, accent));
  return card;
}

function hitRow(entity, source, result, onPivot, accent) {
  const crossed = crossSourceMatches(entity);
  const meta = el("div", { class: "hit-meta" });

  if (crossed.length) {
    meta.append(el("span", {
      class: "chip is-join",
      text: "ソース横断 " + crossed.map((c) => c.source.short || c.source.name).join("/"),
    }));
  }
  for (const f of entity.attrs?._flags || []) {
    meta.append(el("span", { class: "chip" + (f === "kev" || f === "exploited" ? " is-crit" : ""), text: f.toUpperCase() }));
  }
  if (entity.attrs) {
    let shown = 0;
    for (const [k, v] of Object.entries(entity.attrs)) {
      if (k.startsWith("_") || v == null || v === "") continue;
      if (shown >= 4) break;
      const text = String(v);
      meta.append(el("span", { text: `${k}: ${text.length > 46 ? text.slice(0, 45) + "…" : text}` }));
      shown++;
    }
  }

  const acts = el("div", { class: "hit-acts" }, [
    el("button", {
      class: "btn", type: "button", text: "グラフで開く",
      onclick: () => onPivot?.({ kind: "graph", source, entity }),
    }),
  ]);

  const href = deepLink(entity);
  if (href) {
    acts.append(el("a", {
      class: "btn", href, target: "_blank", rel: "noopener", text: "詳細",
    }));
  }

  return el("div", { class: "hit" }, [
    el("span", { class: "hit-type", style: `color:${accent}`, text: entity.type, title: typeLabel(entity.type) }),
    el("div", { class: "hit-main" }, [
      el("div", { class: "hit-label", html: highlight(entity.label, result.query) }),
      meta,
    ]),
    acts,
  ]);
}
