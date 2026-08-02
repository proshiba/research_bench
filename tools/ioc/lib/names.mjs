// 実体名の扱い。索引の名前欄は人が書いた記事から起こされているので、そのまま使えない。
//
// ここに集めているのは、実データで繰り返し見つかった壊れ方への対処。
//   ・確度の但し書きが名前欄に入っている  … `medium-to-high confidence`
//   ・1 つの欄に複数の名前が入っている    … `Qilin, TAG-195 (Golden Chickens`
//   ・閉じ括弧が落ちている                … 上と同じ例。`(` から後ろが切れている
//   ・区切り文字で意味の無い断片になる    … `N/A` が `N` と `A` の 2 つになる
//
// 集める側（collect）と検査する側（validate）が別々に持つと、片方だけ直したときに
// 「検査は通るのに中身は壊れている」状態になる。判定は必ずここ 1 か所に置く。

/** 名前を突き合わせるための鍵。表記ゆれ（記号・大小・空白）を落とす。 */
export const nameKey = (s) => String(s ?? "").trim().toLowerCase().replace(/[^a-z0-9]+/g, "");

/**
 * 名前ではなく確度の但し書きだったもの。実体として数えると
 * 「medium-to-high confidence」というアクターが生まれてしまう。
 */
const QUALIFIER = new Set([
  "suspected", "possible", "likely", "probable", "unknown", "unattributed",
  "unclear", "na", "tbd", "none", "multipleactors", "multiple", "various",
]);

export function isQualifier(s) {
  const k = nameKey(s);
  if (!k) return true;
  if (QUALIFIER.has(k)) return true;
  // 「high confidence」「low-medium confidence」など
  return /confidence$/.test(k) || /^aka/.test(k);
}

/**
 * 名前として短すぎるもの。
 *
 * 区切りで切った断片がここに来る。実際に `N/A` が `A` と `N` に分かれ、
 * **索引側にも `malware:a` / `malware:n` という実体として載っていた**。
 * 放置すると、その 2 つが 468 IOC を持つ最大のマルウェアになり、
 * 「マルウェア間の重なり」の 1 位を占める。
 */
const MIN_KEY_LENGTH = 2;
export const tooShort = (s) => nameKey(s).length < MIN_KEY_LENGTH;

/**
 * 実体名として使えるか。
 *
 * `known`（既に代表名として確立している名前の集合）を渡すと、但し書き判定を飛ばす。
 * 実在するアクターが `Unknown` のような名前を持っていることがあるため。
 * **短すぎる判定は飛ばさない。** 飛ばすと上の `A` / `N` が通ってしまう
 * （索引に実体として載っていると `known` に入るため）。
 */
export function usableName(s, known) {
  if (tooShort(s)) return false;
  if (known?.has(nameKey(s))) return true;
  return !isQualifier(s);
}

const count = (s, re) => (s.match(re) || []).length;

/**
 * 分割で片方だけ残った括弧を整える。
 *
 * 対になっている括弧は名前の一部（`GRU GTsST (Main Center for Special Technology)`）
 * なので残す。片方だけ残ったものは区切りで切れた跡なので落とす。
 * ここを一律に「先頭と末尾の括弧を削る」でやると、対になっている名前を壊す。
 */
export function fixParens(v) {
  let s = String(v).trim();
  while (count(s, /\(/g) > count(s, /\)/g)) s = s.slice(0, s.lastIndexOf("(")).trim();
  while (count(s, /\)/g) > count(s, /\(/g)) s = s.replace(")", "").trim();
  if (/^\([^()]*\)$/.test(s)) s = s.slice(1, -1).trim();   // 全体がくくられているだけなら外す
  return s;
}

/**
 * 値を複数入れられる欄（`A, B` `A、B`）を分ける。
 *
 * 元データに**閉じ括弧が落ちている**ものがある
 * （`"Qilin, TAG-195 (Golden Chickens, Venom Spider"` のように）。
 * 括弧の中身はたいてい別名か但し書きなので、対応する `)` が無ければ `(` から後ろを捨てる。
 * 捨てた別名は別名表で同じ代表名に寄るので損はしない。
 */
export function splitNames(s) {
  let v = String(s ?? "");
  if (count(v, /\(/g) > count(v, /\)/g)) v = v.slice(0, v.indexOf("("));
  return v
    .split(/[,、;／/]+/)
    .map((x) => fixParens(x.replace(/^[\s"'「『]+|[\s"'」』]+$/g, "")))
    .filter(Boolean);
}

/** 欄を分けたうえで、実体名として使えるものだけ返す。 */
export function entityNames(raw, known) {
  return splitNames(raw).filter((n) => usableName(n, known));
}

/**
 * 表示用の別名一覧を作る。
 *
 * 索引は同じ名前を id（小文字）と表示名の両方で載せていることが多く、そのまま並べると
 * 「APT1 の別名は apt1」のような中身の無い行が並ぶ。突き合わせは名前鍵で行うので、
 * 同じ鍵に潰れるものは 1 つに絞ってよい。大文字を含む表記のほうが情報が多いので残す。
 */
export function pickAliases(set, rep) {
  const repKey = nameKey(rep);
  const best = new Map();   // 名前鍵 → 表記
  for (const a of [...set].sort()) {
    const k = nameKey(a);
    if (!k || k === repKey) continue;
    const cur = best.get(k);
    if (!cur || (/[A-Z]/.test(a) && !/[A-Z]/.test(cur))) best.set(k, a);
  }
  return [...best.values()].sort();
}
