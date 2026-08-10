// 索引の鮮度。
//
// 各ソースは meta.json に `generated_at` を出しているのに、ポータルはそれを
// 一度も画面に出していなかった。そのため「表示が古い」と感じたときに、
//   ポータル（配信された HTML/JS）が古いのか
//   索引（ソース側の生成物）が古いのか
// を利用者が切り分けられなかった。ここで後者を見えるようにする。
//
// 前者はステータスバーの build 表示と checkBuild()（main.js）が受け持つ。

const DAY_MS = 86400000;

/** 日次更新のソースが 1 日飛ばしたら気づきたいので 2 日。1 週間空いたら止まっている扱い。 */
const AGING_DAYS = 2;
const STALE_DAYS = 7;

/** meta.generated_at を Date に。読めなければ null（当てずっぽうはしない）。 */
export function generatedAt(source) {
  const raw = source?.meta?.generated_at;
  if (!raw) return null;
  const t = Date.parse(raw);
  return Number.isFinite(t) ? new Date(t) : null;
}

/** 生成時刻から今までの日数。切り捨てなので「23 時間前」は 0 日。 */
export function ageDays(at, now = Date.now()) {
  if (!at) return null;
  return Math.max(0, Math.floor((now - at.getTime()) / DAY_MS));
}

export function levelOf(days) {
  if (days == null) return "unknown";
  if (days >= STALE_DAYS) return "stale";
  if (days >= AGING_DAYS) return "aging";
  return "fresh";
}

/**
 * 経過の言い方。1 日未満は「今日」ではなく時間で出す。
 * 生成時刻の日付と「今日」がずれることがあり（22 時生成を翌朝に見るなど）、
 * 「今日」と書くと添えた日付と食い違って見えるため。
 */
export function ageLabel(ms) {
  if (ms == null) return "生成時刻なし";
  const hours = Math.floor(Math.max(0, ms) / 3600000);
  if (hours < 1) return "1 時間以内";
  if (hours < 24) return `${hours} 時間前`;
  return `${Math.floor(hours / 24)} 日前`;
}

/** ローカル時刻の `YYYY-MM-DD HH:MM`。UTC のまま出すと手元の実感と合わない。 */
export function localStamp(at) {
  if (!at) return null;
  const p = (n) => String(n).padStart(2, "0");
  return `${at.getFullYear()}-${p(at.getMonth() + 1)}-${p(at.getDate())}`
    + ` ${p(at.getHours())}:${p(at.getMinutes())}`;
}

/**
 * ソース 1 件の鮮度。
 * @returns {{at: Date|null, days: number|null, level: string, label: string,
 *            stamp: string|null, text: string, title: string}}
 */
export function freshness(source, now = Date.now()) {
  const at = generatedAt(source);
  const days = ageDays(at, now);
  const ms = at ? Math.max(0, now - at.getTime()) : null;
  const level = levelOf(days);
  const stamp = localStamp(at);
  return {
    at, days, level, stamp,
    label: ageLabel(ms),
    text: stamp ? `索引 ${stamp}（${ageLabel(ms)}）` : "索引の生成時刻が不明です",
    title: stamp
      ? `ソースが索引を作った時刻: ${stamp}（${ageLabel(ms)}）\n`
        + `${level === "fresh" ? "最近更新されています。" : "この時刻より新しい内容はポータルには出せません。"}`
      : "このソースの meta.json に generated_at がないため、索引がいつのものか分かりません。",
  };
}

/** 全ソースのうち一番古いもの。ready でなくても meta は取れているので対象にする。 */
export function oldestSource(sources, now = Date.now()) {
  let worst = null;
  for (const s of sources) {
    const f = freshness(s, now);
    if (!f.at) continue;
    // 日数は切り捨てで並びやすいので、比較は生成時刻そのもので行う
    if (!worst || f.at < worst.freshness.at) worst = { source: s, freshness: f };
  }
  return worst;
}
