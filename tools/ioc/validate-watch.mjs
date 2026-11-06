#!/usr/bin/env node
// 監視の成果物を**読み直して**検査する。作った側の変数は見ない。
//
//   node tools/ioc/validate-watch.mjs [--watch data/ioc/watch]
//
// この仕組みの主張は「観測だけから state と events が再生できる」なので、
// **観測から数え直して突き合わせる**のを重く見る。
//
// 事実が変わったら落ちるべき検査は書かない。artex-timeline で
// `check(artexRids.size === 1, ...)` と書いて、通報者が増えた日に落ちた。
// **ここでは件数を固定せず、数え直して一致を見る。**
import fs from "node:fs";
import path from "node:path";
import { parseArgs, readJson, readJsonl } from "./lib/io.mjs";
import { REPO_ROOT } from "./lib/sources.mjs";
import { expandWatchlist, bulkShapes, reportKey, shapeOf, ipNum } from "./lib/watch.mjs";

const args = parseArgs(process.argv.slice(2));
const WATCH = path.resolve(REPO_ROOT, args.watch || "data/ioc/watch");

let failed = 0;
const check = (ok, label, detail = "") => {
  console.log(`  ${ok ? "ok" : "NG"}  ${label}${ok || !detail ? "" : "  — " + detail}`);
  if (!ok) failed++;
};

const wl = readJson(path.join(WATCH, "watchlist.json"));
const M = readJson(path.join(WATCH, "watch-meta.json"));
const state = readJsonl(path.join(WATCH, "state.jsonl"));
const events = readJsonl(path.join(WATCH, "events.jsonl"));
const shapes = readJsonl(path.join(WATCH, "shapes.jsonl"));
const md = fs.existsSync(path.join(WATCH, "watch-report-ja.md"))
  ? fs.readFileSync(path.join(WATCH, "watch-report-ja.md"), "utf8") : "";

const obsDir = path.join(WATCH, "observations");
const dayFiles = fs.existsSync(obsDir)
  ? fs.readdirSync(obsDir).filter((f) => /^\d{4}-\d{2}-\d{2}\.jsonl$/.test(f)).sort() : [];
const days = dayFiles.map((f) => ({ day: f.slice(0, 10), rows: readJsonl(path.join(obsDir, f)) }));

console.log("== 宣言と観測が噛み合っているか");
check(!!wl && Array.isArray(wl.clusters) && wl.clusters.length > 0, "watchlist.json に clusters がある");
const targets = expandWatchlist(wl || { clusters: [] });
check(targets.length > 0, `監視対象が展開できる（${targets.length} IP）`);
const wantIps = new Set(targets.map((t) => t.ip));
check(days.length > 0, `観測が 1 日以上ある（${days.length} 日）`);
check(days.every((d) => d.rows.every((r) => wantIps.has(r.ip))),
  "観測に宣言外の IP が混ざっていない");
check(state.every((r) => wantIps.has(r.ip)), "state に宣言外の IP が混ざっていない");
/** 宣言から外した IP が state に残り続けないか。**残ると古い結論が居座る** */
const stale = state.filter((r) => !wantIps.has(r.ip));
check(stale.length === 0, "宣言から外れた IP が state に残っていない",
  stale.slice(0, 3).map((r) => r.ip).join(" "));

console.log("\n== 観測の形");
const allRows = days.flatMap((d) => d.rows);
check(allRows.length > 0, `観測の行が読める（${allRows.length} 行）`);
check(days.every((d) => {
  const ips = d.rows.map((r) => r.ip);
  return ips.every((ip, i) => i === 0 || ipNum(ips[i - 1]) <= ipNum(ip));
}), "各日の観測が IP 順に並んでいる（決定的）");
check(days.every((d) => new Set(d.rows.map((r) => r.ip)).size === d.rows.length),
  "同じ日に同じ IP が 2 行ない");
/** **さかのぼりは通報 1 件のときだけ算出。**0 で埋めていないか */
const badBd = allRows.filter((r) => r.reports !== 1 && typeof r.backdate_days === "number");
check(badBd.length === 0, "**通報が 1 件でない行の backdate_days が null**（0 で埋めていない）",
  badBd.slice(0, 3).map((r) => `${r.ip}:${r.reports}`).join(" "));
const bdOk = allRows.filter((r) => r.reports === 1 && typeof r.backdate_days === "number");
check(bdOk.length === 0 || bdOk.every((r) => r.backdate_days >= -0.01),
  "さかのぼりが負になっていない（投稿 ≥ 観測）",
  bdOk.filter((r) => r.backdate_days < -0.01).slice(0, 3).map((r) => r.ip).join(" "));
check(allRows.every((r) => r.reports === (r.by_report || []).length),
  "reports の数と by_report の行数が一致");
/** 観測時刻が取得時刻より先なら、通報者の申告が壊れている。**知らせる** */
const future = allRows.filter((r) => r.last_observed_at && r.fetched_at
  && Date.parse(r.last_observed_at) > Date.parse(r.fetched_at) + 60000);
check(future.length === 0, "取得時刻より先の観測時刻が無い",
  future.slice(0, 3).map((r) => r.ip).join(" "));

console.log("\n== 残してはいけないものが入っていないか");
const obsText = dayFiles.map((f) => fs.readFileSync(path.join(obsDir, f), "utf8")).join("\n");
/** データの成果物。**レポートは別**（「reporterId は保存していません」と書いてあるので、
 *  語の有無で見ると必ず落ちる。artex-timeline で同じ誤検知を踏んだ） */
const dataText = obsText + fs.readFileSync(path.join(WATCH, "state.jsonl"), "utf8")
  + fs.readFileSync(path.join(WATCH, "events.jsonl"), "utf8");
check(!/reporter_?id/i.test(dataText), "**データの成果物に reporterId という語が無い**");
/** レポートには語が出てよい。**値が付いた形**が無いことを見る */
check(!/reporter_?id["'\s]*[:=]\s*\d/i.test(dataText + md),
  "reporterId に値が付いた形がどこにも無い");
check(!/"reporterId"\s*:/.test(dataText), "reporterId の項目が無い");
check(allRows.every((r) => (r.by_report || []).every((x) =>
  !("reporterId" in x) && !("reporter_id" in x))), "通報の行に reporterId が無い");
/** 本文は「形」だけ。日付や IP がそのまま残っていないか */
const rawish = allRows.flatMap((r) => (r.by_report || []).map((x) => x.shape))
  .filter((s) => /\d{4}-\d{2}-\d{2}/.test(s) || /\b\d{1,3}(\.\d{1,3}){3}\b/.test(s));
check(rawish.length === 0, "**本文の形から日付と IP が畳まれている**", rawish.slice(0, 2).join(" / "));
/** 差し込む記号に山括弧を使っていないか。**使うと再度の無害化で消える** */
const angled = allRows.flatMap((r) => (r.by_report || []).map((x) => x.shape))
  .filter((s) => /<[^>]{0,200}>/.test(s));
check(angled.length === 0,
  "**形に山括弧の placeholder が無い**（あると再度の無害化で消える）",
  angled.slice(0, 2).join(" / "));
check(allRows.every((r) => (r.by_report || []).every((x) => x.shape === shapeOf(x.shape))),
  "形がもう一度畳んでも変わらない（畳み方が一貫している）");
check(!/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(obsText), "観測に制御文字が無い");
/** 鍵が紛れていないか。長い英数字の塊を探す */
check(!/\b[0-9a-f]{64,}\b/.test(obsText.replace(/"(ioc|shape)":"[^"]*"/g, "")),
  "観測に鍵らしい長い文字列が無い");

console.log("\n== 復元した観測に印が付いているか");
const recon = allRows.filter((r) => r.source === "reconstructed_from_snapshot");
const fetched = allRows.filter((r) => !r.source);
check(recon.length === 0 || recon.every((r) => r.source_note),
  `復元した観測に出所が書かれている（${recon.length} 行）`);
check(fetched.length > 0, `取得した観測がある（${fetched.length} 行）`);
if (recon.length) {
  const reconDays = [...new Set(days.filter((d) => d.rows.some((r) => r.source)).map((d) => d.day))];
  console.log(`      復元したのは ${reconDays.join(" ")}（取得ぶんと混ぜていない）`);
  check(days.every((d) => d.rows.every((r) => !!r.source) || d.rows.every((r) => !r.source)),
    "**同じ日の中で復元と取得が混ざっていない**");
}

console.log("\n== 形の印を数え直す");
const soleBackdates = [];
const allReports = [];
for (const d of days) {
  for (const r of d.rows) {
    for (const x of (r.by_report || [])) allReports.push({ ip: r.ip, ...x });
    if (r.reports === 1 && (r.by_report || []).length === 1 && typeof r.backdate_days === "number") {
      soleBackdates.push({ ip: r.ip, shape: r.by_report[0].shape, days: r.backdate_days });
    }
  }
}
const re = bulkShapes(allReports, {
  minIps: Number(wl.bulk_min_ips || 10), declared: wl.feed_shapes || [], soleBackdates,
});
check(re.size === shapes.length, "形の数が観測から再現できる", `${re.size} / ${shapes.length}`);
check(shapes.every((s) => {
  const r = re.get(s.shape);
  return r && r.bulk === s.bulk && r.distinct_ips === s.distinct_ips
    && r.files_immediately === s.files_immediately;
}), "**一括登録の印が観測から再現できる**");
/**
 * さかのぼりを形に帰属させる条件を数え直す。
 * **通報がちょうど 1 件の観測だけ**が材料でなければならない。
 * 以前は IP 単位で持った値を「その IP の全部の形」に配っていて、
 * 38.11.173.107 のフィードぶん（3.06 日）が被害者側の形に移っていた。
 */
check(shapes.every((s) => {
  const want = soleBackdates.filter((b) => b.shape === s.shape).length;
  return s.backdate_measurements === want;
}), "**さかのぼりの測定が「通報 1 件の観測」からだけ来ている**",
shapes.filter((s) => s.backdate_measurements
  !== soleBackdates.filter((b) => b.shape === s.shape).length)
  .map((s) => `${s.shape.slice(0, 24)}: ${s.backdate_measurements} ≠ `
    + soleBackdates.filter((b) => b.shape === s.shape).length).join(" / "));
const imm = shapes.filter((s) => s.files_immediately);
check(imm.every((s) => !s.bulk || s.declared),
  "**ずれ 0 の形を（宣言なしで）一括登録と呼んでいない**",
  imm.filter((s) => s.bulk && !s.declared).map((s) => s.shape.slice(0, 30)).join(" / "));

console.log("\n== state を観測から数え直す");
const lastOf = new Map();
for (const d of days) for (const r of d.rows) lastOf.set(r.ip, r);
check(state.length === lastOf.size, "state の行数が観測に現れた IP の数と一致",
  `${state.length} / ${lastOf.size}`);
const isBulk = (shape) => !!re.get(shape)?.bulk;
let bad = [];
for (const s of state) {
  const r = lastOf.get(s.ip);
  if (!r) { bad.push(`${s.ip} 観測が無い`); continue; }
  if (s.reports !== r.reports) bad.push(`${s.ip} 通報数`);
  else if (s.score !== r.score) bad.push(`${s.ip} スコア`);
  else if (s.reporters !== r.reporters) bad.push(`${s.ip} 通報者数`);
  else if (s.independent_reports !== (r.by_report || []).filter((x) => !isBulk(x.shape)).length) {
    bad.push(`${s.ip} フィード以外の通報数`);
  }
  if (bad.length >= 5) break;
}
check(!bad.length, "**通報数・スコア・通報者数・フィード以外の通報数が観測から再現できる**",
  bad.slice(0, 3).join(" / "));
check(state.every((s, i) => i === 0 || ipNum(state[i - 1].ip) <= ipNum(s.ip)),
  "state が IP 順に並んでいる（決定的）");
check(state.every((s) => s.observed_days >= 1 && s.observed_days <= days.length),
  "観測日数が 1 以上・総日数以下");

console.log("\n== events を観測から数え直す");
check(events.every((e, i) => i === 0 || events[i - 1].day <= e.day
  || events[i - 1].day === e.day), "events が日付の昇順に並んでいる");
check(events.every((e) => wantIps.has(e.ip)), "events に宣言外の IP が無い");
check(M.events.total === events.length, "events の件数が meta と一致",
  `${M.events.total} / ${events.length}`);
/** **1 つの事実に 3 行出していないか。**初通報の日に reporters_up / new_category を出さない */
const firstDays = new Map();
for (const e of events) if (e.kind === "first_report") firstDays.set(e.ip + "|" + e.day, true);
const dupes = events.filter((e) => ["reporters_up", "new_category"].includes(e.kind)
  && firstDays.has(e.ip + "|" + e.day));
check(dupes.length === 0, "**初めて通報が付いた日に重複する変化を出していない**",
  dupes.slice(0, 3).map((e) => `${e.ip}:${e.kind}`).join(" "));
/** スコアの減衰を変化として出していないか */
const down = events.filter((e) => e.kind === "score_up" && Number(e.to) <= Number(e.from));
check(down.length === 0, "スコアの下がりを score_up として出していない");
/** first_independent_report が本当にフィード以外か */
const fir = events.filter((e) => e.kind === "first_independent_report");
check(fir.every((e) => {
  const s = state.find((x) => x.ip === e.ip);
  return s && s.independent_reports > 0;
}), "**first_independent_report の IP は state でもフィード以外の通報がある**");
check(fir.every((e) => e.since), "first_independent_report に前回の観測日が入っている");
/** さかのぼり投稿の主張を数え直す */
const back = events.filter((e) => e.kind === "backdated_report");
check(back.every((e) => e.observed_at && e.since && e.observed_at.slice(0, 10) < e.since),
  "**backdated_report の観測日が前回の観測日より前**",
  back.filter((e) => !(e.observed_at?.slice(0, 10) < e.since)).slice(0, 3).map((e) => e.ip).join(" "));
/** 通報の増減を鍵で数え直し、events の数と噛み合うか見る */
if (days.length >= 2) {
  const prevKeys = new Set();
  for (const r of days[days.length - 2].rows) {
    for (const x of (r.by_report || [])) prevKeys.add(reportKey(r.ip, x));
  }
  let fresh = 0;
  for (const r of days[days.length - 1].rows) {
    for (const x of (r.by_report || [])) if (!prevKeys.has(reportKey(r.ip, x))) fresh++;
  }
  const lastDay = days[days.length - 1].day;
  const totPrev = days[days.length - 2].rows.reduce((s, r) => s + r.reports, 0);
  const totNow = days[days.length - 1].rows.reduce((s, r) => s + r.reports, 0);
  check(fresh === totNow - totPrev,
    `最新日に増えた通報の数が総数の差と一致（${fresh} = ${totNow} - ${totPrev}）`);
  console.log(`      ${lastDay} に増えた通報 ${fresh} 件`);
}

console.log("\n== レポートが前提を書いているか");
if (md) {
  check(/接続・走査・認証試行は一切行っていません/.test(md), "能動調査をしていないと明記している");
  check(/通報が無いことは無害の証明ではありません/.test(md), "通報 0 を無害と言い換えていない");
  check(/は通報者が申告した観測時刻/.test(md), "reportedAt が自己申告の観測時刻だと書いている");
  check(/は投稿時刻\*\*で、活動日ではありません/.test(md), "**lastReportedAt を活動日と読むなと書いている**");
  check(/今日の集計は明日増えます/.test(md), "さかのぼり投稿で集計が確定しないと書いている");
  check(/レポーターの自己申告/.test(md), "カテゴリが自己申告だと書いている");
  check(/運用者の国籍や所属を示しません/.test(md), "所在地の解釈に注意を書いている");
  check(/は保存していません/.test(md), "reporterId を保存していないと書いている");
  check(/ずれが 0 なら、IP の数が閾値を超えても一括登録とは呼びません/.test(md),
    "**件数だけで一括登録と決めないと書いている**");
  const today = events.filter((e) => e.day === M.day_range[1]);
  check(today.length > 0 ? /## 今日の変化/.test(md) : /変化はありません/.test(md),
    today.length ? "今日の変化を載せている" : "**変化が無い日に「無い」と書いている**");
} else {
  check(false, "watch-report-ja.md がある");
}

console.log(failed ? `\n${failed} 件 NG` : "\nすべて通りました");
process.exit(failed ? 1 : 0);
