// モジュールの登録簿。
//
// ポータルの「個別機能」は 1 つずつモジュールとして数える。
// Shodan 検索・Active Research・CyberChef はいずれもこの単位で、
// モジュール管理画面にカードとして並び、各モジュール画面で単体で試せる。
//
// モジュールの追加は MODULES に 1 件足して、view-modules.js に描画を書くだけ。

import { DEFAULT_BASE } from "./api-active-research.js";

const STORE_KEY = "rb-modules-v1";

/** 秘密でない設定だけを持つ。API キーは osint.js 側（またはその場入力）で扱う。 */
const settings = {
  activeResearchBase: DEFAULT_BASE,
};

export function loadModuleSettings() {
  try {
    const raw = localStorage.getItem(STORE_KEY);
    if (raw) Object.assign(settings, JSON.parse(raw) || {});
  } catch {
    // 読めなくても既定値で動く
  }
  return getModuleSettings();
}

export function getModuleSettings() {
  return { ...settings };
}

export function saveModuleSettings(next) {
  Object.assign(settings, next);
  try {
    localStorage.setItem(STORE_KEY, JSON.stringify(settings));
  } catch {
    // 保存できなくてもその場では使える
  }
  return getModuleSettings();
}

/* ---------------- 登録簿 ---------------- */

export const MODULES = [
  {
    id: "shodan",
    name: "Shodan 検索",
    short: "Shodan",
    summary: "IP アドレスの公開ポート・組織・報告済み脆弱性を引く。",
    detail: "ブラウザから Shodan API を直接呼びます。API キーは端末の中だけに置きます。",
    tags: ["OSINT", "IP", "API キー必要"],
    accent: "--type-network",
    icon: `<circle cx="12" cy="12" r="3.2" /><path d="M12 4.4v2.6M12 17v2.6M19.6 12H17M7 12H4.4"/>
           <circle cx="12" cy="12" r="8.4" stroke-dasharray="2 3" />`,
  },
  {
    id: "active-research",
    name: "Active Research",
    short: "Active",
    summary: "DNS・RDAP・証明書・Web 解析・バナー・ポート確認などを API 経由で実行する。",
    detail: "自作の調査 API（hellow-world）に対応。ベース URL は設定で変えられます。",
    tags: ["能動調査", "DNS", "証明書", "ポート"],
    accent: "--type-host",
    icon: `<path d="M12 3.2v17.6M3.2 12h17.6" stroke-dasharray="2 2.6" />
           <circle cx="12" cy="12" r="4.4" /><circle cx="12" cy="12" r="8.6" />`,
  },
  {
    id: "cyberchef",
    name: "CyberChef",
    short: "CyberChef",
    summary: "同梱の CyberChef をこの画面の中で開いて、値を持ち込んで加工する。",
    detail: "ワークベンチの変換タブで足りないときに使います。ビルドが必要です。",
    tags: ["変換", "デコード", "同梱"],
    accent: "--type-malware",
    icon: `<path d="M7 3.6v7.2a5 5 0 0 0 10 0V3.6" /><path d="M12 15.8v4.6M9 20.4h6" />`,
  },
];

export function getModule(id) {
  return MODULES.find((m) => m.id === id) || null;
}

/** カードの絞り込み。名前・要約・タグをまとめて見る。 */
export function filterModules(q) {
  const needle = String(q || "").trim().toLowerCase();
  if (!needle) return MODULES;
  return MODULES.filter((m) =>
    [m.id, m.name, m.short, m.summary, m.detail, ...m.tags]
      .join(" ").toLowerCase().includes(needle));
}
