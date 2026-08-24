// 公開接尾辞一覧を読んで「どこからが誰かの持ち物か」を決める。**写しだけを見る。**
//
// 写しが無いときは null を返す。呼び出し側（lib/net.mjs）が手書きの一覧に落ちる。
// **写しの有無で結果が変わる**ので、どちらで数えたかは meta に残すこと。
import fs from "node:fs";
import path from "node:path";
import { REPO_ROOT } from "./sources.mjs";

const DEFAULT_FILE = path.resolve(REPO_ROOT, "data/ioc/.cache/psl/public_suffix_list.dat");

/** 規則は 3 種類ある。
 *   通常   `com` `co.jp`          … そのまま接尾辞
 *   ワイルドカード `*.ck`          … `ck` の下 1 段はすべて接尾辞
 *   例外   `!www.ck`              … ワイルドカードの穴。ここは接尾辞ではない
 *  一致は**最も長い規則が勝つ**。例外があれば例外が最優先。 */
export function parsePsl(text) {
  const rules = new Map();      // 規則の文字列 -> { icann, wildcard }
  const exceptions = new Set();
  let section = "icann";
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (!line) continue;
    if (line.startsWith("//")) {
      if (line.includes("===BEGIN PRIVATE DOMAINS===")) section = "private";
      else if (line.includes("===BEGIN ICANN DOMAINS===")) section = "icann";
      continue;
    }
    if (line.startsWith("!")) { exceptions.add(line.slice(1).toLowerCase()); continue; }
    rules.set(line.toLowerCase(), { icann: section === "icann" });
  }
  return { rules, exceptions };
}

let cached = null;
/** 写しを読む。無ければ null。一度読んだら使い回す */
export function loadPsl(file = DEFAULT_FILE) {
  if (cached !== null) return cached || null;
  if (!fs.existsSync(file)) { cached = false; return null; }
  cached = parsePsl(fs.readFileSync(file, "utf8"));
  return cached;
}
export const hasPsl = (file) => !!loadPsl(file);

/** どの版で数えたか。写しが無ければ null。
 *  **これを一式に残さないと、写しの有無で結果が変わったことに気付けない。**
 *  実測: daily.sh が fetch-psl を呼んでいなかった間、本番は手書きの一覧で
 *  `registrable` を作り続けていたが、検査もその環境で走るので誰も気付かなかった。 */
export function pslVersion(file = DEFAULT_FILE) {
  if (!loadPsl(file)) return null;
  const meta = path.join(path.dirname(file), "meta.json");
  try { return JSON.parse(fs.readFileSync(meta, "utf8")).version || "不明"; }
  catch { return "不明"; }
}

/** その名前の公開接尾辞を返す。
 *  @param includePrivate  PRIVATE 区画（`ddns.net` など）も接尾辞として扱うか。
 *    既定は true。**同一登録者の推定に使うなら true が正しい** ——
 *    `a.ddns.net` と `b.ddns.net` は「同じ人が買った」ではないので。 */
export function publicSuffixOf(host, { psl = loadPsl(), includePrivate = true } = {}) {
  if (!psl) return null;
  const h = String(host || "").trim().toLowerCase().replace(/\.$/, "");
  if (!h || h.includes(" ")) return null;
  const labels = h.split(".");
  // 長いほうから順に規則を当てる
  for (let i = 0; i < labels.length; i++) {
    const candidate = labels.slice(i).join(".");
    if (psl.exceptions.has(candidate)) return labels.slice(i + 1).join(".");
    const exact = psl.rules.get(candidate);
    if (exact && (includePrivate || exact.icann)) return candidate;
    // ワイルドカード: `*.<残り>` が規則にあれば、この段が接尾辞
    if (i > 0) {
      const wild = "*." + labels.slice(i).join(".");
      const w = psl.rules.get(wild);
      if (w && (includePrivate || w.icann)) return labels.slice(i - 1).join(".");
    }
  }
  // どの規則にも当たらないときは、右端 1 段が接尾辞（一覧の既定の振る舞い）
  return labels[labels.length - 1];
}

/** 誰かが実際に登録した単位（接尾辞 + 1 段）。
 *  名前そのものが接尾辞なら null（`com` `ddns.net` などは誰の持ち物でもない） */
export function registrableFromPsl(host, opts = {}) {
  const suffix = publicSuffixOf(host, opts);
  if (suffix === null) return null;
  const h = String(host || "").trim().toLowerCase().replace(/\.$/, "");
  if (h === suffix) return null;
  const rest = h.slice(0, h.length - suffix.length - 1).split(".");
  return rest[rest.length - 1] + "." + suffix;
}

/** PRIVATE 区画に当たったか。当たったならその接尾辞を返す。
 *  **これがそのまま「動的 DNS / 誰でも子を作れる基盤」の判定になる。**
 *  ICANN だけの接尾辞（`com` `co.jp`）は null。 */
export function privateSuffixOf(host, { psl = loadPsl() } = {}) {
  if (!psl) return null;
  const withPrivate = publicSuffixOf(host, { psl, includePrivate: true });
  const icannOnly = publicSuffixOf(host, { psl, includePrivate: false });
  if (withPrivate && icannOnly && withPrivate !== icannOnly) return withPrivate;
  return null;
}
