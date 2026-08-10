#!/usr/bin/env node
// VirusTotal の判定を取ってきて写しに置く。**ここは外に出る工程**。
//
//   VT_API_KEYS="k1,k2,k3" node tools/ioc/fetch-vt.mjs
//                          [--in data/ioc/latest] [--cache data/ioc/.cache/vt]
//                          [--limit 1500] [--stage 1] [--plan]
//                          [--rpm 4] [--daily 500] [--hourly 240]
//                          [--max-age 2592000] [--refresh] [--full] [--include-noise]
//                          [--relation-ips]
//
// 1 IOC につき **object を 1 回**だけ引く。関係（/resolutions など）は引かない。
// 1 IOC あたり呼び出しが 1〜3 回増え、18,537 件では成立しないため
// （docs/ioc-enrich-plan.md §2.7）。object の応答だけでも DNS レコード・証明書・
// JARM・脅威ラベルは入っているので、まずこれで足りる。
//
// 引く順は §4 の段階分けに従う。順番が結果を決めるので、**途中で止めても
// 意味のある所まで進んでいる**ようにする。--plan で引かずに内訳だけ出せる。
//
// 枠は取得元に聞く（/users/{key}）。手元で数えるより確かで、
// 前に別の用途で使った分も反映される。使い切った鍵は自然に外れる。
//
// 写しには **応答そのものではなく、計画が使うと決めた欄だけ**を残す（lib/enrich.mjs の
// PROJECTION）。全欄だと 1 件 50〜200 KB あり 18,537 件で 1 GB を超えるため。
// 版を写しに書いてあるので、使う欄を増やしたら版を上げれば取り直せる。--full で全欄。

import path from "node:path";
import { parseArgs, readJsonl } from "./lib/io.mjs";
import {
  KeyPool, buildQueue, entityCounts, excluded, keyId, notableIps, project,
  projectionOf, readKeys, readRecord, sleep, stageOf, tallyStages, vtTarget, writeRecord,
} from "./lib/enrich.mjs";
import { REPO_ROOT } from "./lib/sources.mjs";

const args = parseArgs(process.argv.slice(2));
const IN = path.resolve(REPO_ROOT, args.in || "data/ioc/latest");
const CACHE = path.resolve(REPO_ROOT, args.cache || "data/ioc/.cache/vt");
const PLAN_ONLY = !!args.plan;
const FULL = !!args.full;
const INCLUDE_NOISE = !!args["include-noise"];
/** 関係の根拠に使える IP（stats.mjs の relation-ips.jsonl）も引く。§3.7 */
const RELATION_IPS = !!args["relation-ips"];
const LIMIT = args.limit === undefined ? Infinity : Number(args.limit);
/** これより古い写しは取り直す。既定 30 日（判定は動くが、毎回取り直すほどではない） */
const MAX_AGE = Number(args["max-age"] || 2592000) * 1000;
const ONLY_STAGE = args.stage === undefined ? null : String(args.stage);

/* ---------------- 対象を決める ---------------- */

const iocs = readJsonl(path.join(IN, "iocs.jsonl"));
if (!iocs.length) {
  console.error(`${IN} に iocs.jsonl がありません。先に collect.mjs を実行してください。`);
  process.exit(1);
}
const links = readJsonl(path.join(IN, "links.jsonl"));
const fresh = new Set(readJsonl(path.join(IN, "new.jsonl")).map((r) => r.key));

const asnOf = new Map();
for (const r of readJsonl(path.join(IN, "ip-asn.jsonl"))) if (r.asn) asnOf.set(r.ioc, r.asn);
const asnInfo = new Map(readJsonl(path.join(IN, "asns.jsonl")).map((a) => [a.asn, a]));

const counts = entityCounts(links);
const notable = notableIps(iocs, links, { asnOf, asnInfo });

const targets = [];
const seenTarget = new Set();
for (const r of iocs) {
  const t = vtTarget(r);
  if (!t) continue;
  if (excluded(r, { includeNoise: INCLUDE_NOISE })) continue;
  seenTarget.add(r.key);
  targets.push({
    ioc: r.key,
    kind: t.kind,
    id: t.id,
    entities: counts.get(r.key) || 0,
    stage: stageOf(r, { entities: counts.get(r.key) || 0, isNew: fresh.has(r.key), notable: notable.has(r.key) }),
  });
}

/**
 * **関係の根拠に使える IP（§3.7）のうち、索引が持っていないものも引く。**
 * 索引の IOC ではないのでカバレッジの分母には入らない（数十件しかない）。
 * 判定が無いままだと、正規サービス（CA の失効確認・CDN・広告配信）を
 * 根拠から外す手立てがない。§9.1e
 */
if (RELATION_IPS) {
  for (const r of readJsonl(path.join(IN, "relation-ips.jsonl"))) {
    if (!r.derived || seenTarget.has(r.ioc)) continue;
    const type = r.ioc.slice(0, r.ioc.indexOf("|"));
    const value = r.ioc.slice(r.ioc.indexOf("|") + 1);
    const t = vtTarget({ type, value });
    if (!t) continue;
    seenTarget.add(r.ioc);
    targets.push({ ioc: r.ioc, kind: t.kind, id: t.id, entities: 0, stage: "rel" });
  }
}

const now = Date.now();
/** 取り直すか。版が変わった写しは、使う欄が増えているので取り直す。 */
const stale = (rec) => {
  if (!rec) return true;
  // 版は引き先ごと。ファイルの欄を増やしても、ドメインや IP は取り直さない
  if ((rec.projection ?? 0) < (FULL ? 0 : projectionOf(rec.endpoint))) return true;
  return now - Date.parse(rec.fetched_at || 0) > MAX_AGE;
};

/**
 * 写しが消えていても、既に判定を持っている IOC には枠を使い直さない。
 *
 * 写しは追跡していない（`.gitignore`）ので、別の環境で動かすと最初は空になる。
 * そこで **`vt.jsonl` を「もう引いた」の控えとして使う**。判定そのものは写しからしか
 * 作らないので、分析の入り口は変わらない。取り直したいときは --refresh。
 */
const alreadyKnown = args.refresh ? new Set() : new Set(readJsonl(path.join(IN, "vt.jsonl")).map((r) => r.ioc));

/* 写しを見るのは 1 回だけ。2 度読むと 18,000 件では目に見えて遅くなる */
const todo = buildQueue(targets).filter((t) => {
  const rec = readRecord(CACHE, t.ioc);
  // 写しがあるなら、取り直すかどうかは版と古さで決める（vt.jsonl の有無は関係ない）
  if (rec) return stale(rec);
  // 写しが無いときだけ vt.jsonl を控えとして使う。**判定を持っているなら枠を使わない**
  return !alreadyKnown.has(t.ioc);
});
const queue = ONLY_STAGE ? todo.filter((t) => t.stage === ONLY_STAGE) : todo;

console.log(`VT の対象 ${targets.length} 件（写し済み ${targets.length - todo.length} / 残り ${todo.length}）`);
const byStage = tallyStages(targets);
const remainByStage = tallyStages(todo);
for (const [s, n] of Object.entries(byStage)) {
  console.log(`  段階 ${s.padEnd(3)} ${String(n).padStart(6)} 件  残り ${String(remainByStage[s] || 0).padStart(6)}`);
}

if (PLAN_ONLY) {
  console.log(`  → 引かずに終わります（--plan）。写し: ${path.relative(REPO_ROOT, CACHE)}`);
  process.exit(0);
}

/* ---------------- 鍵と枠 ---------------- */

const keys = readKeys("VT_API_KEYS", "VT_API_KEYs", "VT_API_KEY");
if (!keys.length) {
  console.error([
    "VirusTotal の鍵がありません。環境変数から読みます（リポジトリには書きません）。",
    "",
    '  VT_API_KEYS="k1,k2,k3" node tools/ioc/fetch-vt.mjs',
    "",
    "カンマ区切りで複数入れれば順に回します（1 つでも動きます）。",
  ].join("\n"));
  process.exit(2);
}

const pool = new KeyPool(keys, {
  rpm: Number(args.rpm || 4),
  hourly: Number(args.hourly || 240),
  daily: Number(args.daily || 500),
});

/** 枠は取得元に聞く。この呼び出し自体は枠を消費しない。 */
async function seedQuotas() {
  for (const key of keys) {
    try {
      const res = await fetch(`https://www.virustotal.com/api/v3/users/${key}`, {
        headers: { "x-apikey": key, accept: "application/json" },
      });
      if (res.status === 401 || res.status === 403) {
        pool.block(pool.slots.find((s) => s.id === keyId(key)), `HTTP ${res.status}`);
        continue;
      }
      const q = (await res.json())?.data?.attributes?.quotas || {};
      pool.seed(keyId(key), {
        hour: q.api_requests_hourly?.used,
        day: q.api_requests_daily?.used,
        hourCap: Math.min(Number(args.hourly || Infinity), q.api_requests_hourly?.allowed ?? Infinity),
        dayCap: Math.min(Number(args.daily || Infinity), q.api_requests_daily?.allowed ?? Infinity),
      });
    } catch (e) {
      console.error(`  ! 枠が聞けませんでした（${keyId(key)}）: ${e.message}。手元の既定で進めます`);
    }
  }
}

await seedQuotas();

const budget = Math.min(LIMIT, pool.remaining, queue.length);
console.log(`  鍵 ${keys.length} 本。今この場で引けるのは ${pool.remaining} 件`
  + `（1 分 ${Number(args.rpm || 4) * pool.live.length} 件・上限まで約 ${Math.ceil(budget / Math.max(1, Number(args.rpm || 4) * pool.live.length))} 分）`);
for (const s of pool.report()) {
  console.log(`    ${s.key}  今日 ${s.day_used ?? "?"} / ${s.day_cap ?? "?"}${s.blocked ? `  使えません（${s.blocked}）` : ""}`);
}
if (!budget) {
  console.log("  引けるものがありません。");
  process.exit(0);
}

/* ---------------- 引く ---------------- */

const stat = { ok: 0, unknown: 0, failed: 0, quota: 0 };
const started = new Date().toISOString();
let taken = 0;
let stop = false;

process.on("SIGINT", () => {
  // 途中で止めても写しは 1 件ずつ確定しているので、そのまま次回に続けられる
  console.log("\n  中断しました。ここまでの写しは残ります。");
  stop = true;
});

async function fetchOne(slot, item) {
  const url = `https://www.virustotal.com/api/v3/${item.kind}/${item.id}`;
  const res = await fetch(url, { headers: { "x-apikey": slot.key, accept: "application/json" } });

  if (res.status === 429) return { retry: "quota" };
  if (res.status === 401 || res.status === 403) return { retry: "auth" };
  if (res.status >= 500) return { retry: "server", why: `HTTP ${res.status}` };

  const body = await res.json().catch(() => null);
  if (res.status === 404) {
    // VT が知らない＝**失敗ではなく結果**。索引の独自性の指標になる（§3.4）
    return { record: { ioc: item.ioc, endpoint: item.kind, status: 404 } };
  }
  if (res.status === 400) {
    /**
     * **VT が引数として受け付けない名前も、失敗ではなく結果**（404 と同じ扱い）。
     *
     * 実測で 24 件あり、どれも取り直しても直らない性質のものだった。
     *   `meower.eth` `roanoke.sol` … ブロックチェーンの名前で DNS ではない
     *   `minio.internal`           … 内部専用 TLD
     *   `in.ua` `co.cr` `com.co`   … 公開接尾辞そのもの（登録可能ドメインではない）
     * 記録しないと毎日 24 回引き直して枠を捨てることになる。
     */
    return { record: { ioc: item.ioc, endpoint: item.kind, status: 400 } };
  }
  if (!res.ok || !body?.data) {
    return { retry: "server", why: `HTTP ${res.status} ${body?.error?.code || ""}`.trim() };
  }
  const attrs = body.data.attributes || {};
  return {
    record: {
      ioc: item.ioc,
      endpoint: item.kind,
      status: 200,
      body: FULL ? attrs : project(item.kind, attrs),
    },
  };
}

async function worker() {
  for (;;) {
    if (stop || taken >= budget) return;
    const slot = await pool.take();
    if (!slot) return;
    if (stop || taken >= budget) return;
    const item = queue[taken++];
    if (!item) return;

    let result = null;
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        result = await fetchOne(slot, item);
      } catch (e) {
        result = { retry: "network", why: e.message };
      }
      if (result.record) break;
      if (result.retry === "quota") {
        // その鍵は今日ぶんを使い切っている。取得元の言い分を優先して外す
        pool.block(slot, "枠を使い切りました");
        stat.quota++;
        result = null;
        break;
      }
      if (result.retry === "auth") {
        pool.block(slot, "鍵が受け付けられません");
        result = null;
        break;
      }
      if (result.retry === "bad") break;
      await sleep(2000 * (attempt + 1));
      pool.charge(slot);
    }

    if (!result?.record) {
      // 写しを残さない。次回の実行がそのまま拾い直す
      stat.failed++;
      // 何が起きたかは見えるようにする。黙って落ちると「対象が減った」ようにしか見えない
      if (stat.failed <= 10) console.error(`  ! ${item.ioc}  ${result?.why || result?.retry || "取れず"}`);
      continue;
    }
    writeRecord(CACHE, {
      ...result.record,
      fetched_at: new Date().toISOString(),
      projection: FULL ? 0 : projectionOf(item.kind),
      source: "virustotal",
    });
    if (result.record.status === 404 || result.record.status === 400) stat.unknown++;
    else stat.ok++;

    const n = stat.ok + stat.unknown + stat.failed;
    if (n % 50 === 0 || n === budget) {
      console.log(`  ${String(n).padStart(5)} / ${budget}  判定あり ${stat.ok} / 未知 ${stat.unknown} / 取れず ${stat.failed}`);
    }
  }
}

await Promise.all(pool.slots.map(() => worker()));

console.log(`取得 ${stat.ok + stat.unknown} 件（判定あり ${stat.ok} / VT が知らない ${stat.unknown}）`);
if (stat.failed) console.log(`  取れなかったもの ${stat.failed} 件（写しを残さないので次回に持ち越します）`);
if (stat.quota) console.log(`  枠を使い切った鍵 ${stat.quota} 本`);
console.log(`  期間 ${started} 〜 ${new Date().toISOString()}`);
for (const s of pool.report()) console.log(`    ${s.key}  この実行で ${s.used} 件${s.blocked ? `  ${s.blocked}` : ""}`);
console.log(`  → ${path.relative(REPO_ROOT, CACHE)}`);
