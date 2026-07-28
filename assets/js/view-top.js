// ダッシュボードのトップ。今日見るべきものだけを並べる。
//
// 各ソースが「新しい」と言える手掛かりは違うので、パネルごとに取り方を変える。
//   ニュース   … 記事の日付。最新日の見出しとタグ
//   脆弱性     … CVE の公開日。新しい順、KEV と悪用確認を強調
//   アクター   … プロファイルの更新日
//   マルウェア … ケースの初観測
// 手掛かりが無いソースは、件数だけ出して深追いしない（嘘を作らない）。
//
// 押すとそのアプリのダッシュボードへ飛ぶ。タグはクロスサーチに繋ぐ。

import { loadAllSources, store } from "./store.js";
import { hasSummarySource, loadSummaries, summaryError, summaryNow, summaryState } from "./summaries.js";
import { el, fmtNum, shorten } from "./util.js";

/** ニュースの記事に付く、タグとして扱う属性。値は「、」や「,」で複数入ることがある。 */
const TAG_KEYS = ["イベント種別", "攻撃手法", "初期アクセス", "犯罪手口", "製品分類",
  "アクター帰属", "アクター", "マルウェア", "製品"];

const DAY = /^(\d{4}-\d{2}-\d{2})/;

/** タグとして意味を持たない値。雲に出しても押しようがないので落とす。 */
const EMPTY_TAG = /^(該当なし|なし|無し|不明|未分類|その他|n\/?a|none|unknown|-|―|—)$/i;

let ctx = { onOpen: null, onQuery: null };
let span = 1;              // ニュースパネルの対象日数（1 = 当日だけ）

/* ---------------- 小さな道具 ---------------- */

function dayOf(entity, keys) {
  for (const k of keys) {
    const m = DAY.exec(String(entity.attrs?.[k] ?? ""));
    if (m) return m[1];
  }
  return null;
}

/** 日付を持つ実体を新しい順に。日付が無いものは落とす。 */
function newest(entities, keys, limit) {
  const withDay = [];
  for (const e of entities) {
    const d = dayOf(e, keys);
    if (d) withDay.push([d, e]);
  }
  withDay.sort((a, b) => (a[0] < b[0] ? 1 : a[0] > b[0] ? -1 : 0));
  return { days: withDay, latest: withDay[0]?.[0] || null, top: withDay.slice(0, limit) };
}

function daysBack(latest, n) {
  const out = new Set();
  const t = Date.parse(`${latest}T00:00:00Z`);
  for (let i = 0; i < n; i++) out.add(new Date(t - i * 86400000).toISOString().slice(0, 10));
  return out;
}

/* ---------------- 部品 ---------------- */

function panel(source, { subtitle, body, empty }) {
  const head = el("div", { class: "top-panel-head" }, [
    el("span", { class: "top-dot", style: `color:var(--src-${source.accent})` }),
    el("h2", { class: "top-panel-name", text: source.name }),
    ...(subtitle ? [el("span", { class: "top-sub", text: subtitle })] : []),
    el("button", {
      class: "btn top-open", type: "button", text: "ダッシュボードを開く →",
      onclick: () => ctx.onOpen?.(source.app_id),
    }),
  ]);
  return el("section", { class: "top-panel", dataset: { app: source.app_id } }, [
    head,
    body || el("p", { class: "side-empty", text: empty || "出せるものがありません。" }),
  ]);
}

function stats(rows) {
  return el("div", { class: "top-stats" }, rows.filter(([, v]) => v != null).map(([k, v, crit]) =>
    el("div", { class: `top-stat${crit ? " is-crit" : ""}` }, [
      el("b", { text: typeof v === "number" ? fmtNum(v) : String(v) }),
      el("span", { text: k }),
    ])));
}

/**
 * 見出しの並び。押すとそのアプリの該当ページを開く。
 * id: true は CVE 番号やアクター名のような短い識別子（折り返さず省略する）。
 * hover: true はマウスを載せると要約を出す（要約を持つソースだけ）。
 */
function itemList(source, items, { id = false, hover = false } = {}) {
  return el("ul", { class: "top-list" }, items.map(({ entity, day, note, flags, label }) => {
    const btn = el("button", {
      class: "top-item", type: "button",
      // 要約が出る行では title を付けない。ブラウザ標準の吹き出しと二重になるため
      title: hover ? null : `${label || entity.label}\n${entity.label}`,
      onclick: () => ctx.onOpen?.(source.app_id, entity),
    }, [
      el("span", { class: "top-item-day", text: day || "" }),
      el("span", { class: `top-item-label${id ? " is-id" : ""}`, text: label || entity.label }),
      ...(flags || []).map((f) => el("span", { class: "top-flag", text: f })),
      ...(note ? [el("span", { class: "top-item-note", text: note })] : []),
    ]);
    if (hover) attachSummary(btn, source, entity);
    return el("li", {}, [btn]);
  }));
}

/* ---------------- 要約の吹き出し ---------------- */

let card = null;          // 出しっぱなしにしない。1 枚を使い回す
let cardTimer = null;
let cardFor = null;       // いまどの実体のために出しているか

function hideCard() {
  clearTimeout(cardTimer);
  cardTimer = null;
  cardFor = null;
  card?.remove();
}

/** 吹き出しを対象の行の右側に置く。はみ出すなら左、下が足りなければ上に寄せる。 */
function placeCard(anchor) {
  const r = anchor.getBoundingClientRect();
  const w = card.offsetWidth, h = card.offsetHeight;
  const gap = 10;
  let x = r.right + gap;
  if (x + w > innerWidth - 8) x = Math.max(8, r.left - gap - w);
  let y = r.top - 4;
  if (y + h > innerHeight - 8) y = Math.max(8, innerHeight - 8 - h);
  card.style.left = `${Math.round(x)}px`;
  card.style.top = `${Math.round(y)}px`;
}

function showCard(anchor, source, entity) {
  if (cardFor === entity) return;
  card?.remove();
  cardFor = entity;

  const state = summaryState(source, entity);
  const body = state === "ready"
    ? el("p", { class: "top-card-text", text: summaryNow(source, entity) })
    : el("p", {
      class: `top-card-text is-${state}`,
      text: state === "pending" ? "要約を読み込んでいます…"
        : state === "error" ? `要約を取得できませんでした（${summaryError(source) || "理由不明"}）`
          : "この記事の要約は索引にありません。",
    });

  card = el("div", { class: "top-card", role: "tooltip" }, [
    el("p", { class: "top-card-title", text: entity.label }),
    body,
    el("p", { class: "top-card-foot", text: [entity.attrs?.日付, entity.attrs?.イベント種別].filter(Boolean).join(" · ") }),
  ]);
  document.body.append(card);
  placeCard(anchor);
}

/**
 * 見出し 1 行に要約の吹き出しを付ける。
 *
 * 要約は索引に入っていないことがあり、その場合は別ファイルを取りに行く。
 * トップ画面を開いただけでは取らず、**最初にマウスが載ったとき**に 1 回だけ取る。
 * 取れたら出しっぱなしの吹き出しをその場で描き直す。
 */
function attachSummary(btn, source, entity) {
  const open = () => {
    clearTimeout(cardTimer);
    // すっと通り過ぎただけで出さない
    cardTimer = setTimeout(() => {
      showCard(btn, source, entity);
      if (summaryState(source, entity) === "pending" && hasSummarySource(source)) {
        loadSummaries(source).then(() => {
          if (cardFor === entity && btn.isConnected) { cardFor = null; showCard(btn, source, entity); }
        });
      }
    }, 220);
  };
  btn.addEventListener("pointerenter", open);
  btn.addEventListener("focus", open);
  btn.addEventListener("pointerleave", hideCard);
  btn.addEventListener("blur", hideCard);
  btn.addEventListener("click", hideCard);
}

/**
 * タグ雲。頻度で 4 段階の大きさに分ける。
 * 押すとクロスサーチに渡す（そのタグが他のソースにも居るか見たいので）。
 */
function tagCloud(counts, limit = 40) {
  const all = [...counts.entries()].sort((a, b) => b[1] - a[1]);
  const sorted = all.slice(0, limit);
  if (!sorted.length) return null;
  const max = sorted[0][1];
  const tags = sorted.map(([word, n]) => {
    const step = max <= 1 ? 1 : Math.min(4, 1 + Math.floor((n / max) * 3.999));
    return el("button", {
      class: `top-tag is-s${step}`, type: "button",
      title: `${word} — ${n} 件。押すとクロスサーチ`,
      onclick: () => ctx.onQuery?.(word),
    }, [word, el("span", { class: "top-tag-n", text: String(n) })]);
  });
  // 出していないぶんは黙って捨てず、件数で断っておく
  if (all.length > sorted.length) {
    tags.push(el("span", { class: "top-tag-more", text: `ほか ${all.length - sorted.length} 種` }));
  }
  return el("div", { class: "top-cloud" }, tags);
}

/* ---------------- ソース別のパネル ---------------- */

function newsPanel(source) {
  const reports = source.entities.filter((e) => e.type === "report");
  const { latest } = newest(reports, ["日付"], 1);
  if (!latest) return panel(source, { empty: "日付を持つ記事がありません。" });

  const window_ = daysBack(latest, span);
  const picked = reports.filter((e) => window_.has(dayOf(e, ["日付"])));

  const counts = new Map();
  let withTag = 0;
  for (const e of picked) {
    let any = false;
    for (const k of TAG_KEYS) {
      for (const raw of String(e.attrs?.[k] ?? "").split(/[、,]/)) {
        const w = raw.trim();
        if (!w || EMPTY_TAG.test(w)) continue;
        counts.set(w, (counts.get(w) || 0) + 1);
        any = true;
      }
    }
    if (any) withTag++;
  }
  const cves = new Set();
  for (const e of picked) {
    for (const c of String(e.attrs?.CVE ?? "").split(/[、,\s]+/)) if (/^CVE-/i.test(c)) cves.add(c.toUpperCase());
  }

  const toggle = el("div", { class: "top-toggle" }, [1, 7].map((n) => el("button", {
    class: "btn", type: "button", text: n === 1 ? "当日" : `${n} 日`,
    "aria-pressed": String(span === n),
    onclick: () => { span = n; repaint(); },
  })));

  return panel(source, {
    subtitle: span === 1 ? latest : `${[...window_].sort()[0]} 〜 ${latest}`,
    body: el("div", { class: "top-body" }, [
      toggle,
      stats([["記事", picked.length], ["タグ付き", withTag], ["登場した CVE", cves.size]]),
      tagCloud(counts),
      el("h3", { class: "side-h", text: "見出し" }),
      // 種別はタグ雲に出ているので、ここは見出しだけに絞って読みやすさを取る。
      // 中身はマウスを載せたときに要約として出す
      itemList(source, picked.map((e) => ({
        entity: e, day: span === 1 ? null : dayOf(e, ["日付"]),
      })), { hover: true }),
    ]),
  });
}

function vulnPanel(source) {
  const cves = source.entities.filter((e) => e.type === "cve");
  const pub = newest(cves, ["公開"], 12);
  if (!pub.latest) return panel(source, { empty: "公開日を持つ脆弱性がありません。" });

  const sameDay = pub.days.filter(([d]) => d === pub.latest).length;
  const flagged = (e) => (e.attrs?.flags || []).filter((f) => f === "kev" || f === "exploited");

  // KEV や悪用確認は「公開が新しい」とは限らない（古い CVE が後から載る）。
  // 公開日で切ると漏れるので、こちらは更新日の新しい順で別に出す。
  const watch = newest(cves.filter((e) => flagged(e).length), ["更新", "公開"], 8);
  const kev = cves.filter((e) => (e.attrs?.flags || []).includes("kev")).length;
  const exploited = cves.filter((e) => (e.attrs?.flags || []).includes("exploited")).length;

  const body = [
    stats([
      ["最新日の公開", sameDay],
      ["KEV", kev, kev > 0],
      ["悪用確認", exploited, exploited > 0],
    ]),
    el("h3", { class: "side-h", text: `新しい脆弱性（${pub.latest}〜）` }),
    itemList(source, pub.top.map(([day, e]) => ({
      entity: e, day,
      note: shorten(e.attrs?.題名 || e.attrs?.製品 || "", 54),
      flags: flagged(e),
    })), { id: true }),
  ];
  if (watch.top.length) {
    body.push(
      el("h3", { class: "side-h", text: "悪用が確認されているもの（更新の新しい順）" }),
      // 印（kev / exploited）が幅を取るので、ここでは題名を諦めて印を優先する
      itemList(source, watch.top.map(([day, e]) => ({
        entity: e, day, flags: flagged(e),
      })), { id: true }),
    );
  }
  return panel(source, { subtitle: `最新の公開 ${pub.latest}`, body: el("div", { class: "top-body" }, body) });
}

function actorPanel(source) {
  const actors = source.entities.filter((e) => e.type === "actor");
  const { top, latest } = newest(actors, ["更新"], 12);
  if (!latest) return panel(source, { empty: "更新日を持つアクターがありません。" });

  const iocs = source.entities.filter((e) => e.type.startsWith("ioc.")).length;
  return panel(source, {
    subtitle: `最新の更新 ${latest}`,
    body: el("div", { class: "top-body" }, [
      stats([["アクター", actors.length], ["IOC", iocs]]),
      el("h3", { class: "side-h", text: "最近更新されたアクター" }),
      itemList(source, top.map(([day, e]) => ({
        entity: e, day,
        note: [e.attrs?.帰属, e.attrs?.種別].filter(Boolean).join(" / ") || null,
      })), { id: true }),
    ]),
  });
}

function malwarePanel(source) {
  const cases = source.entities.filter((e) => e.type === "case");
  const { top, latest } = newest(cases, ["初観測"], 12);
  const families = source.entities.filter((e) => e.type === "malware").length;

  if (!latest) {
    return panel(source, {
      body: el("div", { class: "top-body" }, [
        stats([["解析ケース", cases.length], ["ファミリ", families]]),
        el("p", { class: "side-empty", text: "初観測の日付を持つケースがないため、新着は出せません。" }),
      ]),
    });
  }
  return panel(source, {
    subtitle: `最新の初観測 ${latest}`,
    body: el("div", { class: "top-body" }, [
      stats([["解析ケース", cases.length], ["ファミリ", families], ["日付つき", top.length]]),
      el("h3", { class: "side-h", text: "新しい解析ケース" }),
      itemList(source, top.map(([day, e]) => ({
        entity: e, day,
        // 表示名は検体ハッシュなので、読める側（ファミリ）を前に出す
        label: e.attrs?.ファミリ || e.label,
        note: shorten(e.label, 18),
      })), { id: true }),
    ]),
  });
}

/** 登録簿に無いソース。件数だけ出して、日付の当てずっぽうはしない。 */
function genericPanel(source) {
  const byType = new Map();
  for (const e of source.entities) byType.set(e.type, (byType.get(e.type) || 0) + 1);
  const rows = [...byType.entries()].sort((a, b) => b[1] - a[1]).slice(0, 4);
  return panel(source, {
    body: el("div", { class: "top-body" }, [
      stats([["エンティティ", source.entities.length], ...rows.map(([t, n]) => [t, n])]),
      el("p", { class: "side-empty", text: "新着の取り方が未設定のソースです。ダッシュボードで見てください。" }),
    ]),
  });
}

/** 速報として見たい順。ここに無いソースは apps.json の並びで後ろに付く。 */
const ORDER = ["tech-memo-daily-news", "vuln-intel-agent", "threatactor-intel-analysis", "ai-security-analysis"];

const PANELS = {
  "tech-memo-daily-news": newsPanel,
  "vuln-intel-agent": vulnPanel,
  "threatactor-intel-analysis": actorPanel,
  "ai-security-analysis": malwarePanel,
};

/* ---------------- 画面 ---------------- */

let mount = null;

function repaint() {
  if (!mount) return;
  hideCard();
  const grid = mount.querySelector(".top-grid");
  if (!grid) return;
  const ordered = [...store.sources].sort((a, b) => {
    const ia = ORDER.indexOf(a.app_id), ib = ORDER.indexOf(b.app_id);
    return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib);
  });
  grid.replaceChildren(...ordered.map((s) => {
    if (s.status === "ready") return (PANELS[s.app_id] || genericPanel)(s);
    if (s.status === "error") {
      return panel(s, { empty: `索引を取得できませんでした（${s.error || "理由不明"}）。` });
    }
    return panel(s, {
      subtitle: s.status === "loading" ? `読み込み中 ${Math.round(s.progress * 100)}%` : "未取得",
      empty: "索引を読み込んでいます…",
    });
  }));
}

export function renderTop(root, { onOpen, onQuery } = {}) {
  ctx = { onOpen, onQuery };

  const grid = el("div", { class: "top-grid" });
  mount = el("div", { class: "top-page" }, [
    el("div", { class: "top-head" }, [
      el("h1", { class: "top-title", text: "速報" }),
      el("p", { class: "top-lead", text: "各ソースの新しいところだけを並べています。押すとそのダッシュボードへ移ります。" }),
    ]),
    grid,
  ]);
  root.replaceChildren(mount);
  repaint();

  // 索引が来たパネルから順に出す
  loadAllSources().then(repaint);
  return { repaint };
}

/** ソースの読み込み状況が変わったときに呼ぶ（main.js の onChange から）。 */
export function refreshTop() {
  if (mount?.isConnected) repaint();
}
