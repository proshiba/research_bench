// 調査で分かった「危険度」の持ち方と表し方。
//
// 提供元ごとに尺度が違う。AbuseIPDB は 0–100 の信頼度スコア、VirusTotal は
// 「何社が検知したか」で、単位も分母も別物。無理に 1 つの点数へ均すと嘘になるので
// 2 段構えにしている。
//
//   1. 生の数字は提供元の尺度のまま持つ（92 / 100、7 / 94 ベンダー）
//   2. グラフに出す印は、提供元ごとに決めた境目で「段階」に落としてから決める
//
// 境目は下の SCALES に集めてある。ここだけ直せば画面もグラフも追従する。
//
// ノードへの持たせ方は、実体の attrs に `_risk:<提供元>` の JSON 文字列。
// `_` 始まりはポータルの内部用として属性一覧から除かれる（仕様 §2）。
// 提供元ごとにキーを分けているのは、属性のマージで互いを消さないため。

const PREFIX = "_risk:";

/** 段階の強さ。大きいほど危ない。グラフの印はこの順で「最悪のもの」を採る。 */
export const RANK = { clean: 0, low: 1, elevated: 2, high: 3 };

export const LEVEL_JA = { clean: "検知なし", low: "低", elevated: "中", high: "高" };

const SCALES = {
  abuseipdb: {
    label: "AbuseIPDB",
    // 通報の信頼度そのもの。80 以上を「高」にするのは AbuseIPDB 自身の目安に合わせている
    text: (r) => `${r.score} / 100`,
    level: (r) => (r.score >= 80 ? "high" : r.score >= 25 ? "elevated" : r.score >= 1 ? "low" : "clean"),
  },
  virustotal: {
    label: "VirusTotal",
    // 検知ベンダー数。分母（総ベンダー数）に対する割合ではなく実数で見る。
    // 1 社だけの検知は誤検知が普通にあるので「低」、5 社以上で「高」。
    text: (r) => `${r.score} / ${r.max ?? "?"} ベンダー`,
    level: (r) => (r.score >= 5 ? "high" : r.score >= 2 ? "elevated"
      : r.score >= 1 || (r.suspicious || 0) >= 2 ? "low" : "clean"),
  },
};

export function scaleLabel(provider) {
  return SCALES[provider]?.label || provider;
}

/**
 * 調査結果に付ける属性を作る。investigate.js から呼ぶ。
 * score が数値でなければ何も付けない（分からないものを 0 と言わない）。
 */
export function riskAttrs(provider, { score, max, suspicious, note } = {}) {
  if (!SCALES[provider] || typeof score !== "number" || !Number.isFinite(score)) return {};
  const rec = { score, max, suspicious, note };
  return { [PREFIX + provider]: JSON.stringify(rec) };
}

/** ノード（または実体の集まり）に付いている危険度を、危ない順に返す。 */
export function riskOf(node) {
  const out = [];
  const seen = new Set();
  for (const m of node?.members || []) {
    for (const [k, v] of Object.entries(m.entity?.attrs || {})) {
      if (!k.startsWith(PREFIX) || seen.has(k)) continue;
      seen.add(k);
      const provider = k.slice(PREFIX.length);
      const scale = SCALES[provider];
      if (!scale) continue;
      let rec;
      try { rec = JSON.parse(v); } catch { continue; }
      if (typeof rec?.score !== "number") continue;
      out.push({
        provider,
        label: scale.label,
        score: rec.score,
        max: rec.max,
        text: scale.text(rec),
        level: scale.level(rec),
        note: rec.note || null,
      });
    }
  }
  out.sort((a, b) => RANK[b.level] - RANK[a.level]);
  return out;
}

/** グラフの印に使う段階。複数の提供元が付いていれば、いちばん悪いものを採る。 */
export function worstLevel(node) {
  let worst = "clean";
  for (const r of riskOf(node)) {
    if (RANK[r.level] > RANK[worst]) worst = r.level;
  }
  return worst;
}
