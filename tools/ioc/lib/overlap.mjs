// 重なりの根拠と、その強さ（docs/ioc-enrich-plan.md §3.1）。
//
// 出す側（stats.mjs）と検査する側（validate.mjs）が同じ表を見る。
// 別々に持つと、片方の重みを変えたときに「検査だけが落ちる」か
// 「検査が古い重みを通してしまう」のどちらかになる。

/** 根拠の種類。ここに無いものが `via` に出てきたら、出す側の作り方が崩れている。 */
export const VIA = [
  "ioc", "subnet", "registrable", "asn",
  "certificate", "resolution", "vhash", "imphash", "signer", "registered", "family", "filename", "jarm",
];

/**
 * 根拠の強さ。
 * 同じ証明書 > 同じ IOC > 同じ解決先 > 構造ハッシュ > /24・AS > インポート表 >
 * ファミリ・登録者 > 名前・JARM。
 *
 * 出てきた根拠の点数を合算する。**共有数は掛けない。** 掛けると、弱い根拠を数で押した組が
 * 強い根拠 1 つの組を追い越してしまう。
 *
 * **署名者はインフラの証明書と同種。** 窃取されたコード署名証明書の共有は
 * 偶然では起きない。Microsoft などの正規署名は stats 側で除いたうえで使う。
 *
 * **一斉登録（registered）は弱い根拠。** 同じ日にまとめてドメインを取るのは運用の跡
 * だが、**日付が一致しただけでは繋がりにならない**。実測でこれを入れると 976 組に
 * 付き、そのうち 799 組が日付だけで成立してしまった。他の根拠と重なって初めて効く
 * （Cellebrite ↔ Cytrox は証明書・IOC・解決先に 2020-05-23 の一斉登録が乗って 30 点）。
 *
 * **ファジーハッシュを検知名より上に置く。** `vhash` と `imphash` は算出の論理が
 * 明示的で提供元の判断が入らず、完全一致で使える。`imphash` が `vhash` より下なのは
 * パッカーで衝突するため。
 */
export const VIA_WEIGHT = {
  certificate: 9, ioc: 8, resolution: 7, signer: 7, vhash: 6,
  subnet: 5, asn: 5, imphash: 4,
  registered: 3,
  family: 2, registrable: 2, filename: 1, jarm: 1,
};

/**
 * これだけで成立している組には印を付ける（`weak_only`）。
 * 除きはしない。bogon / noise と同じで、**捨てずに印を付ける**。
 *
 * **`family`（VT の検知名）はここに入れる。** 使っているのは VT が集約した
 * `popular_threat_classification` だけだが、それでも提供元の都合で広く付く札が混じる。
 * 実測で `mikey` が APT28（Sednit）と Silver Fox（Atlas RAT）を繋いでいたが、
 * 変種は `dynamer` / `etset` / `pswdump` と全部違い、検体も JS・DLL・OCX だった。
 */
export const WEAK_VIA = new Set(["family", "filename", "registrable", "jarm", "registered"]);

export const strengthOf = (via) => via.reduce((n, v) => n + (VIA_WEIGHT[v] || 0), 0);

export const weakOnly = (via) => via.length > 0 && via.every((v) => WEAK_VIA.has(v));
