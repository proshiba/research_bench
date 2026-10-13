#!/usr/bin/env node
// 索引の IP のうち、**日本のレポーターから通報が上がっているもの**を出す。
// **写しだけを見る。API は呼ばない。** 同じ写しからは何度でも同じものが出る。
//
//   node tools/ioc/jp-reports.mjs [--in data/ioc/latest]
//                                 [--out data/ioc/reports/jp-reporters.md]
//
// ## 何を言える表で、何を言えない表なのか
//
// `reporterCountryCode === "JP"` が意味するのは「**通報した人が日本に居る**」こと
// だけである。これは次のどれも意味しない。
//
//   - 攻撃先が日本である（日本の観測者が海外の資産を見ていることがある）
//   - その IP の持ち主が日本を狙っている（日本に監視機器が多いだけでも同じ数字になる）
//   - 送信元の国籍や所属（クラウド・VPN・NAT・踏み台のどれでもありうる）
//
// なので「日本向け攻撃元」という列は作らない。作れるのは「**日本からも見えている**」
// という列だけである。
//
// ## 重なりをどう見るか
//
// いちばん意味があるのは「索引が名前の付いたアクターに紐付けていて、かつ日本からも
// 通報されている IP」である。これは脅威情報の記事と、日本の現場の観測が、同じ IP で
// 一致したという意味になる。表の順はそこを先に出す。
import fs from "node:fs";
import path from "node:path";
import { parseArgs, readJsonl, writeJson } from "./lib/io.mjs";
import { statedRoles } from "./lib/tracker.mjs";
import { REPO_ROOT } from "./lib/sources.mjs";

const args = parseArgs(process.argv.slice(2));
const IN = path.resolve(REPO_ROOT, args.in || "data/ioc/latest");
const OUT = path.resolve(REPO_ROOT, args.out || "data/ioc/reports/jp-reporters.md");

/**
 * 脆弱性・侵入を狙った攻撃のカテゴリ。AbuseIPDB の分類名（畳み込み済みの日本語）で持つ。
 * **レポーターの自己申告なので誤分類を含む。** 強さの順に 3 段。
 */
const STRICT = new Set(["SQL インジェクション", "Web アプリ攻撃", "IoT 狙い"]);
/** 範囲が広い。単独では強い根拠にしない */
const BROAD = new Set(["侵入"]);
/** 認証を破ろうとした。脆弱性とは別の筋だが攻撃ではある */
const AUTH = new Set(["総当たり", "SSH", "FTP 総当たり"]);
/** 走査しただけ。これだけなら攻撃と呼ばない */
const SCAN_ONLY = new Set(["ポートスキャン"]);
/** 送信元自身が侵害されている可能性。技法ではなく被害の印 */
const EXPLOITED = "踏み台";

const abuse = readJsonl(path.join(IN, "abuseipdb.jsonl"));
const iocs = readJsonl(path.join(IN, "iocs.jsonl"));
const links = readJsonl(path.join(IN, "links.jsonl"));
if (!abuse.length) {
  console.error(`${IN} に abuseipdb.jsonl がありません。先にエンリッチを実行してください。`);
  process.exit(1);
}

/* ---------------- 索引が何と言っているか ---------------- */

const actorsOf = new Map();
const rolesOf = new Map();
const malwareOf = new Map();
const articlesOf = new Map();
for (const l of links) {
  if (!l.ioc) continue;
  const add = (m, v) => {
    if (!v) return;
    if (!m.has(l.ioc)) m.set(l.ioc, new Set());
    m.get(l.ioc).add(v);
  };
  if (l.kind === "actor") add(actorsOf, l.name);
  if (l.kind === "malware") add(malwareOf, l.name);
  if (l.kind === "article") add(articlesOf, l.name);
  add(rolesOf, l.rel);
}

/* ---------------- 日本ぶんがある IP を集める ---------------- */

/** 分からないものを負に数えないための分母。通報があるのに数えていない IP */
const reportedIps = abuse.filter((r) => (r.reports || 0) > 0);
const unmeasured = reportedIps.filter((r) => !r.jp_measured);

const rows = [];
for (const r of abuse) {
  if (!r.jp) continue;
  const cats = Object.keys(r.jp.categories || {});
  const strict = cats.filter((c) => STRICT.has(c));
  const broad = cats.filter((c) => BROAD.has(c));
  const auth = cats.filter((c) => AUTH.has(c));
  const onlyScan = cats.length > 0 && cats.every((c) => SCAN_ONLY.has(c));
  const actors = [...(actorsOf.get(r.ioc) || [])].sort();
  const roles = statedRoles(rolesOf.get(r.ioc));
  rows.push({
    ip: r.ioc.slice(r.ioc.indexOf("|") + 1),
    ioc: r.ioc,
    jp_reports: r.jp.reports,
    jp_reporters: r.jp.reporters,
    jp_substantive: r.jp.substantive,
    jp_last: r.jp.last_reported_at || "",
    jp_categories: cats.sort(),
    strict, broad, auth,
    // **「日本から通報された」以上のことを言える材料があるか**
    kind: strict.length ? "脆弱性狙い"
      : broad.length ? "侵入（範囲広い）"
        : auth.length ? "認証狙い"
          : onlyScan ? "走査のみ"
            : "その他",
    exploited_host: cats.includes(EXPLOITED) || undefined,
    score: r.score ?? 0,
    reports: r.reports ?? 0,
    reporters: r.reporters ?? 0,
    country: r.country || "",
    isp: r.isp || "",
    usage_type: r.usage_type || "",
    // 印は捨てずに付ける。読む側が外して数え直せるように
    hosting: r.hosting || undefined,
    sample: r.sample || undefined,
    tor: r.tor || undefined,
    whitelisted: r.whitelisted || undefined,
    actors,
    roles,
    malware: [...(malwareOf.get(r.ioc) || [])].sort(),
    articles: [...(articlesOf.get(r.ioc) || [])].sort(),
  });
}

/**
 * 並び順。**索引がアクターを言っていて、日本の観測者が複数居て、本文のある通報がある**
 * ものを先に出す。数字の大小ではなく、人が見る価値の順。
 */
const rank = (r) => [
  r.actors.length ? 0 : 1,
  r.jp_reporters >= 2 ? 0 : 1,
  r.jp_substantive ? 0 : 1,
  r.kind === "脆弱性狙い" ? 0 : r.kind === "侵入（範囲広い）" ? 1 : r.kind === "認証狙い" ? 2 : 3,
  -r.jp_reporters, -r.jp_reports, r.ip,
];
rows.sort((a, b) => {
  const x = rank(a), y = rank(b);
  for (let i = 0; i < x.length; i++) {
    if (x[i] === y[i]) continue;
    return x[i] < y[i] ? -1 : 1;
  }
  return 0;
});

/* ---------------- 数える ---------------- */

const tally = (list, f) => {
  const m = new Map();
  for (const r of list) for (const v of [].concat(f(r))) if (v) m.set(v, (m.get(v) || 0) + 1);
  return [...m].sort((a, b) => (b[1] - a[1]) || (a[0] < b[0] ? -1 : 1));
};
const withActor = rows.filter((r) => r.actors.length);
const summary = {
  tool: "jp-reports",
  measured: { reported_ips: reportedIps.length, unmeasured: unmeasured.length },
  jp_reported: rows.length,
  jp_reported_with_actor: withActor.length,
  by_kind: Object.fromEntries(tally(rows, (r) => r.kind)),
  jp_reporter_distribution: Object.fromEntries(
    tally(rows, (r) => (r.jp_reporters >= 5 ? "5+" : String(r.jp_reporters)))),
  jp_categories: Object.fromEntries(tally(rows, (r) => r.jp_categories)),
  top_countries: tally(rows, (r) => r.country).slice(0, 12),
  top_isp: tally(rows, (r) => r.isp).slice(0, 12),
  exploited_host: rows.filter((r) => r.exploited_host).length,
  marks: {
    hosting: rows.filter((r) => r.hosting).length,
    sample: rows.filter((r) => r.sample).length,
    tor: rows.filter((r) => r.tor).length,
    whitelisted: rows.filter((r) => r.whitelisted).length,
  },
};

/* ---------------- 書く ---------------- */

const safe = (s) => String(s || "").replace(/\|/g, "／").replace(/\s+/g, " ").slice(0, 40);
const T = (head, body) => [
  `| ${head.join(" | ")} |`,
  `| ${head.map(() => "---").join(" | ")} |`,
  ...body.map((r) => `| ${r.join(" | ")} |`),
].join("\n");
const code = (s) => "`" + s + "`";

const L = [];
L.push("# 日本のレポーターから通報が上がっている索引の IP", "");
L.push("> この表が言えるのは「**通報した人が日本に居る**」ことだけです。");
L.push("> 攻撃先が日本であること、送信元が日本を狙っていることは**意味しません**。");
L.push("> 日本に観測者や監視機器が多いというだけでも同じ数字になります。", "");
L.push(T(["項目", "件数"], [
  ["通報が 1 件以上ある索引の IP", String(summary.measured.reported_ips)],
  ["うち日本ぶんを数えた", String(summary.measured.reported_ips - summary.measured.unmeasured)],
  ["**まだ数えていない（分からない）**", `**${summary.measured.unmeasured}**`],
  ["**日本からの通報があった**", `**${summary.jp_reported}**`],
  ["うち索引がアクター名を付けている", `**${summary.jp_reported_with_actor}**`],
]), "");
L.push("## 日本の通報の中身", "");
L.push(T(["見え方", "件数"], Object.entries(summary.by_kind).map(([k, v]) => [k, String(v)])), "");
L.push("カテゴリは**レポーターの自己申告**です。誤分類を含みます。", "");
L.push(T(["カテゴリ（日本の通報だけ）", "IP 数"],
  Object.entries(summary.jp_categories).map(([k, v]) => [k, String(v)])), "");
L.push("## 日本の観測者の数", "");
L.push("**1 人しか見ていない IP は、その 1 人の環境固有の事情かもしれません。**", "");
L.push(T(["日本のレポーター数", "IP 数"],
  Object.entries(summary.jp_reporter_distribution).map(([k, v]) => [`${k} 人`, String(v)])), "");

if (withActor.length) {
  L.push("## 索引のアクターと日本の観測が一致した IP", "");
  L.push("**脅威情報の記事が名前を付けている IP に、日本の現場からも通報が付いている**ものです。");
  L.push("ここがいちばん人の確認に値します。", "");
  L.push(T(["IP", "アクター", "役割", "日本の通報", "観測者", "本文あり", "最新", "カテゴリ", "国", "ISP"],
    withActor.map((r) => [
      code(r.ip), safe(r.actors.join(", ")), safe(r.roles.join(", ")) || "—",
      String(r.jp_reports), String(r.jp_reporters), String(r.jp_substantive), r.jp_last || "—",
      safe(r.jp_categories.join(", ")), r.country, safe(r.isp),
    ])), "");
}

const rest = rows.filter((r) => !r.actors.length).slice(0, 60);
if (rest.length) {
  L.push(`## アクター名の付いていないもの（上位 ${rest.length} 件）`, "");
  L.push(T(["IP", "日本の通報", "観測者", "本文あり", "最新", "見え方", "全体スコア", "国", "ISP"],
    rest.map((r) => [
      code(r.ip), String(r.jp_reports), String(r.jp_reporters), String(r.jp_substantive),
      r.jp_last || "—", r.kind, String(r.score), r.country, safe(r.isp),
    ])), "");
}

L.push("## 印", "");
L.push("**消していません。**読む側が外して数え直せるように付けてあります。", "");
L.push(T(["印", "意味", "件数"], [
  ["hosting", "事業者の網（相乗りの可能性）", String(summary.marks.hosting)],
  ["sample", "中身の無い通報が大半（見本アドレスの疑い）", String(summary.marks.sample)],
  ["tor", "Tor 出口", String(summary.marks.tor)],
  ["whitelisted", "AbuseIPDB の除外一覧", String(summary.marks.whitelisted)],
  ["踏み台の通報あり", "**送信元自体が侵害されている可能性**。持ち主も被害者かもしれません",
    String(summary.exploited_host)],
]), "");

L.push("## 制約", "");
L.push("- **母集団は索引が持っている IP だけ**です。AbuseIPDB 全体ではありません");
L.push("- 通報の窓は 365 日です");
L.push(`- 通報があるのに日本ぶんを数えていない IP が ${summary.measured.unmeasured} 件あります。`
  + "これは「日本からの通報なし」ではなく**分からない**という意味です");
L.push("- `reporterId` は数を数えるためだけに使い、値は保存していません");
L.push("- 通報コメントの本文は保存していません。中身があったかどうかだけを数えています");
L.push("- 対象 IP への接続・走査は行っていません。AbuseIPDB の公開情報だけです");
L.push("");

fs.mkdirSync(path.dirname(OUT), { recursive: true });
fs.writeFileSync(OUT, L.join("\n"));
writeJson(path.join(IN, "jp-reports.json"), { ...summary, rows });

console.log(`日本からの通報があった IP ${rows.length} 件`
  + `（アクター名つき ${withActor.length} / 未測定 ${summary.measured.unmeasured}）`);
for (const [k, v] of Object.entries(summary.by_kind)) console.log(`  ${k.padEnd(10)} ${String(v).padStart(5)}`);
console.log(`  → ${path.relative(REPO_ROOT, OUT)}`);
