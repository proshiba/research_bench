#!/usr/bin/env node
// 名指しした IP を AbuseIPDB で毎日引き、その日の観測を 1 ファイル残す。
// **ここだけが外に出る。**
//
//   ABUSEIPDB_API_KEY="k" node tools/ioc/fetch-watch.mjs
//     [--watch data/ioc/watch] [--cache data/ioc/.cache/watch-abuseipdb]
//     [--max-check 400] [--plan] [--day 2026-11-06]
//
// ## やらないこと
//
// **対象 IP への接続・走査・認証試行は一切行わない。** AbuseIPDB の公開情報だけ。
//
// ## 枠の取り合い
//
// `/check` は 1 日 10,000 回で **UTC 0 時にリセット**される。配分:
//
//   本線のエンリッチ（索引ぶん）      約 100
//   この監視                          対象の数ぶん（既定の上限 400）
//   日本向け攻撃元の収集              9,000
//   予備                              残り
//
// **この監視は本線の後、9,000 件の掃き出しより先に回す。** 件数が小さく、
// 「初めて通報が付いた日」を逃さないことの価値が高い。
//
// ## 観測はここで書く
//
// 写し（`.cache/`）は git 管理外で容器も使い捨てなので、**写しだけでは翌日に残らない**。
// その日の観測を畳んで `observations/<日付>.jsonl` に残す。state と events は
// この観測から**毎回作り直す**（track-watch.mjs）。前回の state を読んで更新する
// 作りにすると、一度おかしくなった状態が永久に残る。
//
// 鍵は環境変数からのみ読み、コンソール・ログ・観測・ソース・エラーに出さない。
import fs from "node:fs";
import path from "node:path";
import { parseArgs, readJson, writeJson, writeJsonl } from "./lib/io.mjs";
import { REPO_ROOT } from "./lib/sources.mjs";
import { KeyPool, readKeys, readRecord, writeRecord, sleep } from "./lib/enrich.mjs";
import { expandWatchlist, distill, ipNum } from "./lib/watch.mjs";

const args = parseArgs(process.argv.slice(2));
const WATCH = path.resolve(REPO_ROOT, args.watch || "data/ioc/watch");
const CACHE = path.resolve(REPO_ROOT, args.cache || "data/ioc/.cache/watch-abuseipdb");
const LIMIT = Number(args["max-check"] || 400);
const PLAN = !!args.plan;
/** 観測を書く日。既定は今日（UTC）。**枠のリセットと同じ UTC 基準にそろえる** */
const DAY = String(args.day || new Date().toISOString().slice(0, 10));
/** 写しをどれだけ新しいものとみなすか。既定 20 時間（1 日 1 回のルーチンを想定） */
const MAX_AGE_H = Number(args["max-age-hours"] || 20);

const wl = readJson(path.join(WATCH, "watchlist.json"));
if (!wl || !Array.isArray(wl.clusters) || !wl.clusters.length) {
  console.error(`${path.join(WATCH, "watchlist.json")} に clusters がありません。`);
  process.exit(1);
}
const AGE_DAYS = Number(wl.max_age_days || 365);
const targets = expandWatchlist(wl);
const byCluster = {};
for (const t of targets) byCluster[t.cluster] = (byCluster[t.cluster] || 0) + 1;
console.log(`監視対象 ${targets.length} IP ${JSON.stringify(byCluster)}（窓 ${AGE_DAYS} 日）`);

/** 写しが古いか。**鮮度を見ないと「変化なし」という嘘が出る** */
const stale = (ioc) => {
  const rec = readRecord(CACHE, ioc);
  if (!rec) return true;
  if (rec.max_age_days !== AGE_DAYS) return true; // 窓が変わったら引き直す
  const t = Date.parse(rec.fetched_at || 0);
  return !Number.isFinite(t) || Date.now() - t > MAX_AGE_H * 3600000;
};
const queue = targets.filter((t) => stale("ioc.ipv4|" + t.ip));
console.log(`  写しが ${MAX_AGE_H} 時間以内 ${targets.length - queue.length} / 引くのは ${queue.length}`);
if (queue.length > LIMIT) console.log(`  ! 上限 ${LIMIT} 件に切ります。残りは翌日に続きます`);

if (PLAN) { console.log("  → 引かずに終わります（--plan）"); process.exit(0); }

const stat = { ok: 0, failed: 0 };
let stop = null;

if (queue.length) {
  const keys = readKeys("ABUSEIPDB_API_KEY", "ABUSEIPDB_API_KEYS", "ABUSE_IP_DB");
  if (!keys.length) {
    console.error('AbuseIPDB の鍵がありません。ABUSEIPDB_API_KEY="k" を環境変数で渡してください。');
    process.exit(2);
  }
  const pool = new KeyPool(keys, { rpm: Number(args.rpm || 30), daily: Number(args.daily || 1000) });
  const budget = Math.min(LIMIT, pool.remaining, queue.length);
  console.log(`  鍵 ${keys.length} 本。今この場で引けるのは ${budget} 件`);

  let taken = 0;
  const failures = [];
  process.on("SIGINT", () => { console.log("\n  中断しました。ここまでの写しは残ります。"); stop = "中断"; });

  const fetchOne = async (slot, t) => {
    const u = new URL("https://api.abuseipdb.com/api/v2/check");
    u.searchParams.set("ipAddress", t.ip);
    u.searchParams.set("maxAgeInDays", String(AGE_DAYS));
    u.searchParams.set("verbose", "");
    const res = await fetch(u, { headers: { key: slot.key, accept: "application/json" } });
    const left = Number(res.headers.get("x-ratelimit-remaining"));
    if (Number.isFinite(left) && left <= 0) pool.block(slot, "枠を使い切りました");
    if (res.status === 429) return { retry: "quota" };
    if (res.status === 401 || res.status === 403) return { retry: "auth" };
    if (res.status >= 500) return { retry: "server" };
    const body = await res.json().catch(() => null);
    if (!res.ok || !body?.data) return { retry: "server" };
    return { body: body.data };
  };

  const worker = async () => {
    for (;;) {
      if (stop || taken >= budget) return;
      const slot = await pool.take();
      if (!slot) return;
      if (stop || taken >= budget) return;
      const t = queue[taken++];
      if (!t) return;
      let r = null;
      for (let a = 0; a < 3; a++) {
        try { r = await fetchOne(slot, t); } catch (e) {
          // **鍵を含む URL は出さない。**IP とエラーの種類だけ
          r = { retry: "network", why: String(e?.message || e).slice(0, 80) };
        }
        if (r.body) break;
        if (r.retry === "quota") { pool.block(slot, "枠を使い切りました"); r = null; break; }
        if (r.retry === "auth") { pool.block(slot, "鍵が受け付けられません"); r = null; break; }
        await sleep(2000 * (a + 1));
      }
      if (!r?.body) {
        failures.push({ ip: t.ip, reason: r?.retry || "unknown" });
        stat.failed++;
        continue;
      }
      // **第 3 引数は写しの鍵。`slot.key`（API キー）を渡してはいけない。**
      // 渡すとファイル名が API キーのハッシュになり、写しが IOC から引けなくなる
      writeRecord(CACHE, {
        ioc: "ioc.ipv4|" + t.ip, ip: t.ip, cluster: t.cluster,
        endpoint: "check", status: 200, max_age_days: AGE_DAYS,
        fetched_at: new Date().toISOString(), body: r.body,
      });
      stat.ok++;
      if (stat.ok % 50 === 0) process.stdout.write(`\r  ${stat.ok}/${budget}    `);
    }
  };
  await Promise.all(Array.from({ length: Number(args.concurrency || 6) }, worker));
  console.log(`\n  取得 ${stat.ok} 件 / 失敗 ${stat.failed} 件` + (stop ? `  — ${stop}` : ""));
  if (failures.length) {
    writeJson(path.join(WATCH, "fetch-failures.json"), failures);
    console.log(`  ! 失敗 ${failures.length} 件を fetch-failures.json に残しました`);
  }
}

/* ---------------- その日の観測を書く ---------------- */

const rows = [];
const missing = [];
for (const t of targets) {
  const rec = readRecord(CACHE, "ioc.ipv4|" + t.ip);
  if (!rec?.body) { missing.push(t.ip); continue; }
  rows.push(distill({
    ip: t.ip, cluster: t.cluster, body: rec.body,
    fetchedAt: rec.fetched_at, maxAgeDays: rec.max_age_days ?? AGE_DAYS,
  }));
}
rows.sort((a, b) => ipNum(a.ip) - ipNum(b.ip));
if (!rows.length) {
  console.error("観測が 0 件です。写しが無いので観測を書きません。");
  process.exit(1);
}
const obsDir = path.join(WATCH, "observations");
fs.mkdirSync(obsDir, { recursive: true });
writeJsonl(path.join(obsDir, `${DAY}.jsonl`), rows);

/**
 * **引けなかった IP を「通報なし」にしない。**観測に入れず、別に数える。
 * 0 件と未取得を混ぜると、引けなかった日に「静かになった」と読めてしまう。
 */
writeJson(path.join(WATCH, "fetch-meta.json"), {
  day: DAY,
  targets: targets.length,
  by_cluster: byCluster,
  max_age_days: AGE_DAYS,
  observed: rows.length,
  not_observed: missing.length,
  not_observed_ips: missing.slice(0, 50),
  fetched_now: stat.ok,
  reused_copies: rows.length - stat.ok,
  failures: stat.failed,
  max_check: LIMIT,
  interrupted: !!stop,
  finished_at: new Date().toISOString(),
});
console.log(`→ observations/${DAY}.jsonl（${rows.length} IP`
  + (missing.length ? ` / 引けていない ${missing.length} IP` : "") + "）");
if (missing.length) {
  console.log(`  ! 引けていない IP は観測に入れていません（「通報なし」とは別）`);
}
