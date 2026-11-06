// 名指しした IP の集まりを毎日追うための共有部品。
//
// ## なぜ本線のエンリッチに相乗りしないのか
//
// `fetch-abuseipdb.mjs` は **各 IP を一度だけ**引く設計で、`abuseipdb.jsonl` に
// 判定がある IP は `alreadyKnown` で二度と引かない。枠を無駄にしないための正しい
// 設計だが、**毎日追う用途とは真逆**である。接ぎ木すると本線の枠配分が壊れる。
//
// ## 何を残して何を残さないか
//
// **`reporterId` は保存しない。**
// 「同じ通報者か」は IP ごとの `numDistinctUsers` の増減で足りる。識別子に塩を
// 付けて畳んでも、`reporterId` は小さな整数なので総当たりで戻せてしまう。
// 塩を git の外に置くと、別の容器で観測が再現できなくなる。**そもそも持たない。**
//
// **コメント原文は保存しない。**日付と数字を畳んだ「形」だけを残す。
// 形は定型文の判別に要るが、個人に紐づく情報ではない。
//
// ## 「フィードの一括登録か」を決め打ちしない
//
// `/ICS Labs/` のような固有の文字列で判定すると、他のフィードを取り逃がす。
// 代わりに**観測から数え直す**: 同じ形が多数の IP に付いていれば一括登録の印。
// 人が確認したものは `watchlist.json` の `feed_shapes` に書ける。
// **印であって判定ではない。**該当しても行は捨てない。
import { sanitize, forDisplay } from "../../../reports/global-jp-vuln/rules.mjs";

/** 監視対象を IP の一覧に展開する。`ranges` + `host_range`、または `explicit` */
export function expandWatchlist(wl) {
  const out = [];
  const seen = new Set();
  for (const cl of wl.clusters || []) {
    const push = (ip) => {
      if (seen.has(ip)) return; // 同じ IP が 2 つのクラスタに居ても 1 回しか引かない
      seen.add(ip);
      out.push({ ip, cluster: cl.name });
    };
    for (const ip of cl.explicit || []) push(ip);
    for (const r of cl.ranges || []) {
      const base = String(r).split("/")[0].split(".").slice(0, 3).join(".");
      const [lo, hi] = cl.host_range || [1, 254];
      for (let i = lo; i <= hi; i++) push(`${base}.${i}`);
    }
  }
  out.sort((a, b) => ipNum(a.ip) - ipNum(b.ip));
  return out;
}

export const ipNum = (ip) => String(ip).split(".").reduce((a, b) => a * 256 + Number(b), 0);

/**
 * コメントの「形」。**日付と数字を畳む。**
 *
 * 畳まないと `Last observed 2026-10-17` と `2026-10-24` が別の本文に見え、
 * 一括登録を取り逃がす（artex-timeline で実際に取り逃がした）。
 *
 * ## 差し込む記号に山括弧を使わない
 *
 * `sanitize` は `<[^>]{0,200}>` を HTML タグとして**消す**。`<date>` や `<n>` を
 * 差し込むと、**もう一度無害化を通った時点で placeholder ごと消える**:
 *
 *   "... Last observed <date> UTC." → "... Last observed UTC."
 *
 * 畳んだ形は表示や再集計で何度も通るので、角括弧 `[date]` にして耐えるようにする。
 * `sanitize` 自身が入れる `<email>` と `<internal-host>` も同じ理由で畳み直す。
 * これで `shapeOf(shapeOf(s)) === shapeOf(s)` が成り立ち、検査できる。
 *
 * （`rules.mjs` の `sanitize` 側の placeholder は他の成果物が既に使っているので
 *   ここでは変えない。**この関数の出口で揃える。**）
 */
export const shapeOf = (s) => sanitize(s)
  .replace(/\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2})?)?/g, "[date]")
  .replace(/\d{1,3}(\.\d{1,3}){3}/g, "[ip]")
  .replace(/\b\d+\b/g, "[n]")
  .replace(/<email>/g, "[email]")
  .replace(/<internal-host>/g, "[host]")
  .replace(/\s+/g, " ")
  .trim();

/**
 * 1 IP の `/check` 応答を、その日の観測 1 行に畳む。
 *
 * **`reportedAt` は通報者が申告した観測時刻、`lastReportedAt` は AbuseIPDB が
 * 受け取った時刻（投稿）。** 混ぜると時系列が壊れる。2026-11-06 に実測:
 * フィード本文の `Last observed <日付>` が `reportedAt` と 58/58 件一致し、
 * `lastReportedAt` は 57/65 件でそれより後ろ（中央 1.04 日・最大 7.32 日）。
 */
export function distill({ ip, cluster, body, fetchedAt, maxAgeDays }) {
  const b = body || {};
  const reports = Array.isArray(b.reports) ? b.reports : [];
  const rows = reports.map((x) => ({
    // 観測時刻。**活動日として読むのはこちら**
    observed_at: String(x.reportedAt || ""),
    cc: String(x.reporterCountryCode || ""),
    cats: (x.categories || []).map(Number).filter(Number.isFinite).sort((a, b2) => a - b2),
    shape: forDisplay(shapeOf(x.comment), 160),
    empty: !x.comment,
  })).sort((a, b2) => String(a.observed_at).localeCompare(String(b2.observed_at))
    || a.cc.localeCompare(b2.cc) || a.shape.localeCompare(b2.shape));
  const obs = rows.map((r) => r.observed_at).filter(Boolean).sort();
  const total = b.totalReports ?? 0;
  const lastSub = String(b.lastReportedAt || "");
  return {
    ioc: "ioc.ipv4|" + ip,
    ip,
    cluster,
    fetched_at: fetchedAt,
    max_age_days: maxAgeDays,
    score: b.abuseConfidenceScore ?? 0,
    reports: total,
    reporters: b.numDistinctUsers ?? 0,
    first_observed_at: obs[0] || "",
    last_observed_at: obs[obs.length - 1] || "",
    /** 投稿時刻。**活動日ではない** */
    last_submitted_at: lastSub,
    /** さかのぼり日数。**通報 1 件のときだけ一対一に決まる。**他は null（0 ではない） */
    backdate_days: total === 1 && lastSub && obs[0]
      ? Number(((Date.parse(lastSub) - Date.parse(obs[0])) / 86400000).toFixed(3)) : null,
    jp_reports: rows.filter((r) => r.cc === "JP").length,
    countries: [...new Set(rows.map((r) => r.cc).filter(Boolean))].sort(),
    categories: [...new Set(rows.flatMap((r) => r.cats))].sort((a, b2) => a - b2),
    country_code: b.countryCode || "",
    isp: b.isp || "",
    usage_type: b.usageType || "",
    hostnames: (b.hostnames || []).slice().sort(),
    is_tor: b.isTor === true,
    is_whitelisted: b.isWhitelisted === true,
    /** **reporterId は入れない。**国・カテゴリ・観測時刻・本文の形だけ */
    by_report: rows,
  };
}

/** 通報 1 件を日をまたいで同定する鍵。`reporterId` を使わずに済ませる */
export const reportKey = (ip, r) =>
  [ip, r.observed_at, r.cc, (r.cats || []).join("+"), r.shape].join("|");

/**
 * 一括登録らしい「形」を観測から数え直す。
 *
 * **判定ではなく印。** 同じ形が多数の IP に付いていれば、1 件ずつ見て出した
 * ものではない。閾値は `min_ips`（既定 10）。人が確認した形は `declared` で渡す。
 */
export function bulkShapes(allReports, { minIps = 10, declared = [], soleBackdates = [] } = {}) {
  /**
   * さかのぼり日数を**形に帰属させられるのは、その形がその IP の唯一の通報のとき**だけ。
   *
   * `lastReportedAt` は IP ごとに 1 つしかないので、通報が 2 件ある IP では
   * どちらの通報の投稿時刻なのか決まらない。IP 単位で持った値を「その IP に
   * 付いている全部の形」に配ると、他人のさかのぼりが紛れ込む。
   * 実際に 38.11.173.107（フィード 10-24 観測・10-27 投稿 = 3.06 日）の値が、
   * 同じ IP に後から付いた被害者側の形に移り、ずれ 0 を 3.06 日に見せていた。
   */
  const dsByShape = new Map();
  for (const b of soleBackdates) {
    if (!b || !b.shape || typeof b.days !== "number") continue;
    if (!dsByShape.has(b.shape)) dsByShape.set(b.shape, []);
    dsByShape.get(b.shape).push(b.days);
  }
  const byShape = new Map();
  for (const r of allReports) {
    if (!r.shape) continue;
    if (!byShape.has(r.shape)) byShape.set(r.shape, new Set());
    byShape.get(r.shape).add(r.ip);
  }
  const marks = new Map();
  for (const [shape, ips] of byShape) {
    const isDeclared = declared.some((d) => shape.includes(d));
    /**
     * **IP の数だけで決めない。**
     *
     * 実測した判別子は「さかのぼって投稿しているか」。フィードは手元の台帳を
     * まとめて流すので観測日をさかのぼる（中央 1.04 日・最大 7.32 日）。
     * 被害者側の検知器は見たその場で出すのでずれが 0 になる。
     *
     * IP の数だけで切ると危うい。ARTEX では被害者側の通報が 8 IP で、閾値 10 を
     * **ぎりぎり下回っただけ**だった。その検知器がもう 2 IP 分報告していたら
     * 一括登録として割り引いてしまう。**ずれが 0 なら一括登録とは呼ばない。**
     */
    const ds = dsByShape.get(shape) || [];
    const immediate = ds.length > 0 && ds.every((v) => v < 1 / 24);
    marks.set(shape, {
      shape,
      distinct_ips: ips.size,
      declared: isDeclared,
      /** さかのぼりを測れた「観測の回数」（同じ IP が日をまたいで複数回入る）と最大値 */
      backdate_measurements: ds.length,
      backdate_days_max: ds.length ? Number(Math.max(...ds).toFixed(3)) : null,
      files_immediately: immediate,
      bulk: isDeclared || (ips.size >= minIps && !immediate),
    });
  }
  return marks;
}
