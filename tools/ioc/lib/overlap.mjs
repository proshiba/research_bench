// 重なりの根拠と、その強さ（docs/ioc-enrich-plan.md §3.1）。
//
// 出す側（stats.mjs）と検査する側（validate.mjs）が同じ表を見る。
// 別々に持つと、片方の重みを変えたときに「検査だけが落ちる」か
// 「検査が古い重みを通してしまう」のどちらかになる。

/** 根拠の種類。ここに無いものが `via` に出てきたら、出す側の作り方が崩れている。 */
export const VIA = [
  "ioc", "subnet", "registrable", "asn",
  "certificate", "resolution", "family", "filename", "jarm",
];

/**
 * 根拠の強さ。
 * 同じ証明書を使っている > 同じ IOC > 同じ解決先 > ファミリ・/24・AS > 名前・登録者・JARM。
 *
 * 出てきた根拠の点数を合算する。**共有数は掛けない。** 掛けると、弱い根拠を数で押した組が
 * 強い根拠 1 つの組を追い越してしまう。
 */
export const VIA_WEIGHT = {
  certificate: 9, ioc: 8, resolution: 7,
  family: 5, subnet: 5, asn: 5,
  filename: 2, registrable: 2, jarm: 1,
};

/**
 * これだけで成立している組には印を付ける（`weak_only`）。
 * 除きはしない。bogon / noise と同じで、**捨てずに印を付ける**。
 */
export const WEAK_VIA = new Set(["filename", "registrable", "jarm"]);

export const strengthOf = (via) => via.reduce((n, v) => n + (VIA_WEIGHT[v] || 0), 0);

export const weakOnly = (via) => via.length > 0 && via.every((v) => WEAK_VIA.has(v));
