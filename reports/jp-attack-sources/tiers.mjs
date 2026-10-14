// 「**日本からの攻撃報告**」をどこで切るか。**この一箇所だけで決める。**
//
// AbuseIPDB の 23 カテゴリは「攻撃」から「属性」まで雑に混ざっている。
// VPN を使っていることは攻撃ではないし、オープンプロキシも攻撃ではない。
// 一方で DDoS とフィッシングは攻撃である。**まとめて「通報あり」と数えると、
// VPN を使っているだけの IP が攻撃元の一覧に入る。**
//
// そこで段に分ける。**消さずに印を付ける**方針なので、どの段も数えて出し、
// 読む側が外して数え直せるようにする。「攻撃」の既定は A1〜A4。
//
// カテゴリ番号は https://www.abuseipdb.com/categories（2026-10-09 に確認）。
export const TIERS = {
  A1: {
    label: "侵入・脆弱性",
    note: "**最も重い。**システムに入ろうとした、または入られた痕跡",
    ids: [15, 16, 20, 21, 23],
    attack: true,
  },
  A2: {
    label: "認証突破",
    note: "資格情報を破ろうとした。侵入とは別の筋だが攻撃ではある",
    ids: [5, 18, 22],
    attack: true,
  },
  A3: {
    label: "サービス妨害",
    note: "可用性を狙った",
    ids: [4, 6],
    attack: true,
  },
  A4: {
    label: "詐欺・なりすまし",
    note: "人を騙す側の攻撃。技術的侵入とは別だが被害は出る",
    ids: [3, 7, 8, 17],
    attack: true,
  },
  A5: {
    label: "偵察のみ",
    note: "**走査しただけ。これだけなら攻撃と呼ばない。**既定では攻撃に数えない",
    ids: [14],
    attack: false,
  },
  B: {
    label: "スパム・ボット",
    note: "迷惑ではあるが侵入ではない。既定では攻撃に数えない",
    ids: [10, 11, 12, 19],
    attack: false,
  },
  C: {
    label: "属性・その他",
    note: "**攻撃ではない。**VPN を使っている、オープンプロキシである、など。"
      + "DNS の乗っ取り/汚染は被害の報告で、送信元の行為とは限らない",
    ids: [1, 2, 9, 13],
    attack: false,
  },
};

/** 攻撃として数える段（既定 A1〜A4） */
export const ATTACK_TIERS = Object.entries(TIERS).filter(([, t]) => t.attack).map(([k]) => k);
/** カテゴリ番号 → 段 */
export const TIER_OF = (() => {
  const m = new Map();
  for (const [k, t] of Object.entries(TIERS)) for (const id of t.ids) m.set(id, k);
  return m;
})();
/** 23 カテゴリすべてがどこかの段に入っているか。抜けると黙って数え落とす */
export const COVERED = (() => {
  const missing = [];
  for (let i = 1; i <= 23; i++) if (!TIER_OF.has(i)) missing.push(i);
  return { ok: !missing.length, missing };
})();

/**
 * `jp_all_categories`（`番号:件数;番号:件数`）を段ごとに畳む。
 * **1 つの報告に複数のカテゴリが付く**ので、段の合計は報告数を超えることがある。
 * 「その段のカテゴリが付いた報告が何件あるか」は番号単位の最大値では求まらないため、
 * ここで出すのは**カテゴリの付与回数**である。件数と混同しないよう名前を分ける。
 */
export function tierCounts(jpAllCategories) {
  const out = {};
  for (const k of Object.keys(TIERS)) out[k] = 0;
  const unknown = [];
  for (const part of String(jpAllCategories || "").split(";").filter(Boolean)) {
    const [idStr, nStr] = part.split(":");
    const id = Number(idStr), n = Number(nStr);
    if (!Number.isFinite(id) || !Number.isFinite(n)) continue;
    const t = TIER_OF.get(id);
    if (!t) { unknown.push(id); continue; }
    out[t] += n;
  }
  return { tiers: out, unknown };
}

/** 攻撃段のカテゴリ付与が 1 回でもあるか */
export const isAttack = (jpAllCategories) => {
  const { tiers } = tierCounts(jpAllCategories);
  return ATTACK_TIERS.some((k) => tiers[k] > 0);
};

/**
 * 重さの順。**件数の多さではなく、段の重さで決める。**
 * A1 があれば A1、無ければ A2、…という単純な規則にする。
 * 「DDoS 1000 件」より「侵入 1 件」を上に出したいため。
 */
export const worstTier = (jpAllCategories) => {
  const { tiers } = tierCounts(jpAllCategories);
  for (const k of ["A1", "A2", "A3", "A4", "A5", "B", "C"]) if (tiers[k] > 0) return k;
  return "";
};
