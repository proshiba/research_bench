#!/usr/bin/env node
// 成果物を**読み直して**検査する。作った側の変数は見ない。
//
//   node validate.mjs
//
// このデータセットの答えは負なので、**負を負として裏づける検査**を重く置く。
// 分母が埋まっていること、写しから数え直して一致すること、
// 「無害」と言い換えていないことを見る。
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { expandWatchlist } from "../../tools/ioc/lib/watch.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "../..");
const CFG = JSON.parse(fs.readFileSync(path.join(HERE, "config.json"), "utf8"));

function parseCsv(text) {
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
  const rows = []; let row = [], field = "", q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) { if (c === '"') { if (text[i + 1] === '"') { field += '"'; i++; } else q = false; } else field += c; }
    else if (c === '"') q = true;
    else if (c === ",") { row.push(field); field = ""; }
    else if (c === "\n") { row.push(field); field = ""; rows.push(row); row = []; }
    else if (c === "\r") { /* CRLF */ }
    else field += c;
  }
  if (field.length || row.length) { row.push(field); rows.push(row); }
  const h = rows.shift();
  return { header: h.map((x) => x.replace(/^﻿/, "")), rows: rows.filter((r) => r.length > 1).map((r) => Object.fromEntries(h.map((k, i) => [k.replace(/^﻿/, ""), r[i] ?? ""]))) };
}
const num = (v) => (v === "" ? 0 : Number(v));
const bool = (v) => v === "true";
let failed = 0;
const check = (ok, label, detail = "") => {
  console.log(`  ${ok ? "ok" : "NG"}  ${label}${ok || !detail ? "" : "  — " + detail}`);
  if (!ok) failed++;
};

const S = JSON.parse(fs.readFileSync(path.join(HERE, "artex_38_11_summary.json"), "utf8"));
const A = parseCsv(fs.readFileSync(path.join(HERE, "artex_38_11_all.csv"), "utf8"));
const J = parseCsv(fs.readFileSync(path.join(HERE, "artex_38_11_jp_observed.csv"), "utf8"));
const FL = parseCsv(fs.readFileSync(path.join(HERE, "artex_38_11_flagged.csv"), "utf8"));
const all = A.rows;
const md = fs.readFileSync(path.join(HERE, "artex_38_11_report_ja.md"), "utf8");

console.log("== 分母が埋まっているか（負の答えはここで決まる）");
/**
 * **対象は宣言から数え直す。**ここに別の宣言を持つと、訂正から取り残される
 * （2026-11-06 の 1 クラスタ化で実際そうなった）。
 */
const WL = JSON.parse(fs.readFileSync(path.resolve(ROOT, CFG.WATCHLIST), "utf8"));
const declared = expandWatchlist(WL);
const expect = declared.length;
check(all.length === expect, `CSV の行数が対象の数と一致（${expect}）`, String(all.length));
check(S.coverage.targets === expect, "summary の対象数が一致");
check(S.coverage.abuseipdb_checked === expect,
  "**AbuseIPDB を全件引けている**（引けていない IP を「通報なし」に数えないため）",
  `${S.coverage.abuseipdb_checked}/${expect}`);
check(S.coverage.abuseipdb_missing === 0, "AbuseIPDB の取り漏らしが 0");
check(all.every((r) => bool(r.abuse_checked)), "全行に AbuseIPDB を引いた印が付いている");
const ips = new Set(all.map((r) => r.ip_address));
check(ips.size === expect, "IP に重複が無い");
const want = new Set(declared.map((t) => t.ip));
check([...want].every((ip) => ips.has(ip)), "指定された IP がすべて入っている");
check([...ips].every((ip) => want.has(ip)), "指定外の IP が混ざっていない");
/** **対照群は 255 件の統計に混ぜない。**写しにはあるが行には入らない */
const CONTROL = new Set((CFG.CONTROL_IPS || []).filter((ip) => !want.has(ip)));
check([...CONTROL].every((ip) => !ips.has(ip)),
  "**対照群が本体の行に混ざっていない**（母数が狂うため）",
  [...CONTROL].filter((ip) => ips.has(ip)).slice(0, 3).join(" "));
check(S.control?.available === true && S.control.ips === CONTROL.size,
  `対照群の件数が summary と一致（${CONTROL.size}）`, String(S.control?.ips));
/** 対照群が同じ土俵に乗っているか。**乗っていなければ §5 の比較が読めない** */
if (S.control?.available) {
  const c = S.control.comparable;
  check(c.with_vt_record === S.control.ips,
    "**対照群は全件 VT にレコードがある**（データが無いから白い、ではない）",
    `${c.with_vt_record}/${S.control.ips}`);
  check(Math.abs(c.engines_evaluated_median_control - c.engines_evaluated_median_cluster) <= 5,
    "**対照群とクラスタで評価エンジン数が同程度**",
    `${c.engines_evaluated_median_control} / ${c.engines_evaluated_median_cluster}`);
  check(c.as_owners_control.length > 0
    && c.as_owners_control.every((o) => c.as_owners_cluster.includes(o)),
  "**対照群とクラスタが同じ AS**（別の事業者と比べていない）",
  `${c.as_owners_control.join(",")} / ${c.as_owners_cluster.join(",")}`);
  /** エンジンごとの当たり方を写しから数え直す */
  check(Object.values(S.control.by_engine).every((v) => v.control <= S.control.ips
    && v.cluster <= expect), "エンジンごとの件数が母数を超えていない");
}

console.log("\n== 写しから数え直して一致するか");
const cache = (kind) => {
  const dir = path.join(HERE, ".cache", kind);
  const m = new Map();
  if (!fs.existsSync(dir)) return m;
  for (const d of fs.readdirSync(dir)) {
    const sub = path.join(dir, d);
    if (!fs.statSync(sub).isDirectory()) continue;
    for (const f of fs.readdirSync(sub)) {
      if (!f.endsWith(".json")) continue;
      try { const r = JSON.parse(fs.readFileSync(path.join(sub, f), "utf8")); if (r?.ip) m.set(r.ip, r); } catch { /* 壊れた写しは数えない */ }
    }
  }
  return m;
};
const ab = cache("abuseipdb"), vt = cache("virustotal");
/** 写しには対照群も入る。**本体の行数と混同しない** */
check(ab.size === expect + CONTROL.size,
  `AbuseIPDB の写しの数が一致（対象 ${expect} + 対照群 ${CONTROL.size}）`, String(ab.size));
check([...want].every((ip) => ab.has(ip)), "対象が全件 写しにある");
check([...CONTROL].every((ip) => ab.has(ip)), "対照群が全件 写しにある");
let bad = [];
let jpTotal = 0, repTotal = 0;
for (const r of all) {
  const c = ab.get(r.ip_address);
  if (!c) { bad.push(`${r.ip_address} 写しが無い`); continue; }
  const b = c.body || {};
  const reports = Array.isArray(b.reports) ? b.reports : [];
  const jp = reports.filter((x) => x.reporterCountryCode === "JP");
  jpTotal += jp.length;
  repTotal += b.totalReports || 0;
  if (num(r.abuse_confidence_score) !== (b.abuseConfidenceScore ?? 0)) bad.push(`${r.ip_address} スコアが違う`);
  else if (num(r.abuse_total_reports_365d) !== (b.totalReports ?? 0)) bad.push(`${r.ip_address} 通報数が違う`);
  else if (num(r.jp_report_count_365d) !== jp.length) bad.push(`${r.ip_address} 日本の通報数が違う`);
  if (bad.length >= 5) break;
}
check(!bad.length, "スコア・通報数・日本の通報数が写しから再現できる", bad.slice(0, 3).join(" / "));
check(S.japan.total_jp_reports_365d === jpTotal, "日本の通報の総数が写しと一致",
  `${S.japan.total_jp_reports_365d} / ${jpTotal}`);
check(S.abuseipdb.total_reports_365d === repTotal, "通報の総数が写しと一致");

console.log("\n== 部分集合として筋が通っているか");
check(J.rows.length === S.japan.ips_with_any_jp_report_365d,
  "日本からの通報がある CSV の行数が summary と一致");
check(J.rows.every((r) => num(r.jp_report_count_365d) > 0), "その CSV は全行が日本の通報 1 件以上");
check(all.every((r) => num(r.jp_report_count_90d) <= num(r.jp_report_count_365d)),
  "90 日の日本の通報 ≦ 365 日の日本の通報");
check(all.every((r) => num(r.jp_report_count_365d) <= num(r.abuse_total_reports_365d)),
  "日本の通報 ≦ 全通報");
check(all.every((r) => num(r.jp_vuln_report_count_90d) <= num(r.jp_report_count_90d)),
  "日本の脆弱性報告 ≦ 日本の通報");
check(FL.rows.length === new Set([...all.filter((r) => num(r.abuse_total_reports_365d) > 0),
  ...all.filter((r) => num(r.vt_malicious) + num(r.vt_suspicious) > 0)].map((r) => r.ip_address)).size,
  "印の付いた CSV の行数が、通報または検知のある IP の数と一致");

console.log("\n== 格子の主張が成り立っているか");
const F = S.vt_freshness;
const host = (ip) => Number(ip.split(".")[3]);
const freshRows = all.filter((r) => r.vt_first_seen && r.vt_first_seen.slice(0, 7) >= F.threshold_month);
check(freshRows.length === F.ips, "新しく初見になった IP の数が一致", `${freshRows.length} / ${F.ips}`);
check(freshRows.every((r) => F.host_numbers.includes(host(r.ip_address))),
  "**その IP のホスト番号がすべて格子に乗っている**");
check(F.host_numbers.length < 15, `格子が ${F.host_numbers.length} 個に収まっている（散らばっていれば主張は無効）`);
check(F.with_certificate === freshRows.filter((r) => r.cert_issuer).length,
  "格子上の IP の証明書の数が一致");
check(/first_seen は VT が項目を作った日/.test(JSON.stringify(F)),
  "summary に first_seen の限界が書かれている");

console.log("\n== 証明書");
check(S.certificates.count === all.filter((r) => r.cert_issuer || r.cert_subject_cn).length,
  "証明書を持つ IP の数が一致");
check(S.certificates.expired_before_collection === S.certificates.count,
  "**全件が取得時点で失効**という主張が成り立つ（1 件でも有効なら書き換えが要る）",
  `${S.certificates.expired_before_collection} / ${S.certificates.count}`);
check(S.virustotal.ips_with_artex_in_certificate
  === all.filter((r) => r.cert_mentions_artex === "true").length,
  "証明書に ARTEX を含む IP の数が一致");

console.log("\n== 禁止したものが混ざっていないか");
const body = fs.readFileSync(path.join(HERE, "artex_38_11_all.csv"), "utf8") + JSON.stringify(S) + md;
check(!/reporter_?id/i.test(A.header.join(",")), "reporterId の列が無い");
// **語の有無で見てはいけない。**レポートには「reporterId は保存していません」という
// 宣言文が載る。見るべきは**値が付いた形**（`reporterId: 12345` など）が無いこと
check(!/reporterId["'\s]*[:=]\s*\d/.test(body), "reporterId に値が付いた形が成果物に無い");
check(!/\b[0-9a-f]{64}\b/.test(JSON.stringify(S.config || {}) + A.header.join(",")),
  "設定と列名に鍵らしい文字列が無い");
check(!all.some((r) => /^[=+@]/.test(r.isp) || /^[=+@]/.test(r.cert_subject_cn || "")),
  "外部由来の列が表計算の式として始まっていない");

console.log("\n== 負の答えを言い換えていないか");
check(/無害の証明ではありません/.test(md), "**「通報 0」を無害と言い換えていない**");
check(/接続・走査・認証試行は一切行っていません/.test(md), "能動調査をしていないと明記している");
check(/対照実験/.test(md) && /193\.32\.204\.199/.test(md), "計測器の対照実験が書かれている");
check(/first_seen_date/.test(md) && /配備日ではありません|動き出した日とは限りません/.test(md),
  "first_seen を配備日と断定していない");
check(/AS45548/.test(md) && /無関係/.test(md), "Artex Securities との名前の衝突に触れている");
/**
 * **誰の観測かを明示しているか。**
 *
 * 2026-11-12 に利用者が「255 IP 全部で 8787/tcp に ARTEX が上がっている。
 * 個別に確認済み」と申告した。それまでは「稼働は確認できていない」と書くのが
 * 正しかったが、今は**事実が変わった**。
 *
 * 守るべき不変条件は「確認していないと書くこと」ではなく、
 * **「誰が確認したのかを取り違えないこと」**。こちらは能動調査をしていない。
 */
check(/こちらの観測ではなく、利用者の確認/.test(md)
  || /こちらで確認したものではありません/.test(md),
"**ARTEX の稼働を自分の観測として書いていない**（利用者の確認だと明示）");
check(/接続・走査・認証試行を一切行っていません/.test(md)
  || /接続・走査・認証試行は一切行っていません/.test(md),
"こちら側が能動調査をしていないと明記している");
/** 8787 と 443 を取り違えていないか。**証明書は ARTEX ではない** */
check(/8787/.test(md), "ARTEX のポート（8787）に触れている");
check(/443 の痕跡であって ARTEX のものではない/.test(md)
  || /ARTEX を指紋採取したものではありません/.test(md),
"**証明書を ARTEX の痕跡と取り違えていない**");
check(/「ARTEX が上がっていること」と「通報・検知が付いていること」は別の観測です/.test(md),
  "**待ち受けサービスとレピュテーションを別物として書いている**");
check(/reporterCountryCode/.test(md) && /攻撃先が日本であることは意味しません/.test(md),
  "日本のレポーター＝日本向け攻撃と断定していない");
check(!/日本向け攻撃元/.test(md), "「日本向け攻撃元」と断定していない");

/* ---- 今回の主張（対照群）が文章に出ているか ---- */
check(/宣言の外にある近隣/.test(md) || /対照群/.test(md), "対照群を使ったと書いている");
check(/空き住所なのか使われていて綺麗なのかは区別できません/.test(md),
  "**対照群が白い理由を『無害』と言い換えていない**");
check(/独立した 4 つの観測とは限りません/.test(md) || /独立した観測の数ではありません/.test(md),
  "**エンジンの数を独立した観測の数と読んでいない**");
check(/同じ AS・同じエンジン数で評価されています/.test(md),
  "対照群が同じ土俵だと示している");
check(new RegExp("境界は `\\.125` にあり").test(md) || /境界と一致/.test(md),
  "境界が宣言と一致することを書いている");
check(/前回の注意は今も有効/.test(md) || /無害の証明ではありません/.test(md),
  "前回の注意を引き継いでいる");

console.log(failed ? `\n${failed} 件 NG` : "\nすべて通りました");
process.exit(failed ? 1 : 0);
