#!/usr/bin/env node
// VirusTotal の **関係（relationship）** を取ってきて写しに置く。**ここは外に出る工程**。
//
//   VT_API_KEYS="k1,k2,k3" node tools/ioc/fetch-vt-rel.mjs
//                          [--in data/ioc/latest] [--cache data/ioc/.cache/vt-rel]
//                          [--rel contacted_ips] [--limit 1000] [--plan]
//                          [--min-malicious 10] [--min-entities 2]
//                          [--rpm 4] [--daily 500] [--hourly 240] [--max-age 2592000]
//
// object（fetch-vt.mjs）と分けてあるのは、**枠の食い方がまるで違う**から。
// object は 1 IOC につき 1 回で済むが、関係は 1 IOC につき関係の種類だけ増える。
// 全 18,940 件に広げると成立しないので、**引く相手を絞ることが前提の工程**にしてある
// （docs/ioc-enrich-plan.md §9.1）。
//
// なぜ要るか
//   いまのピボットは「ドメイン → 解決先 IP」が主で、**ドメインを持っている実体しか
//   繋がらない**。ハッシュしか持っていない実体は `family` / `vhash` / `imphash` と
//   いう**検体の似姿**でしか繋がっていない。`contacted_ips` が入ると
//   「この検体はこの IP と話した」という**動作の証拠**になり、
//   ハッシュ側と IP / ドメイン側が初めて直接つながる。
//
// 絞り方（既定）
//   ・ハッシュであること（IP / ドメインの関係は object の欄でほぼ代替できる。§9.1c）
//   ・VT が知っていて、検知が --min-malicious 以上（無害な宿主を引かない）
//   ・実体が --min-entities 以上（重なりの根拠になりうるものから引く）
//   実測では 検知 10 以上 かつ 実体 2 以上 で 1,084 件。鍵 6 本なら 1 日で終わる。

import path from "node:path";
import { parseArgs, readJsonl } from "./lib/io.mjs";
import {
  KeyPool, entityCounts, keyId, readKeys, readRecord, sleep, writeRecord,
} from "./lib/enrich.mjs";
import { REPO_ROOT } from "./lib/sources.mjs";

const args = parseArgs(process.argv.slice(2));
const IN = path.resolve(REPO_ROOT, args.in || "data/ioc/latest");
const CACHE = path.resolve(REPO_ROOT, args.cache || "data/ioc/.cache/vt-rel");
const PLAN_ONLY = !!args.plan;
const LIMIT = args.limit === undefined ? Infinity : Number(args.limit);
const REL = String(args.rel || "contacted_ips");
const MIN_MAL = Number(args["min-malicious"] ?? 10);
const MIN_ENT = Number(args["min-entities"] ?? 2);
const MAX_AGE = Number(args["max-age"] || 2592000) * 1000;

/**
 * 引ける関係。引き先（files / domains）ごとに分けて持つ。
 * ここに無いものは打ち間違いとして止める。
 */
const REL_KIND = {
  contacted_ips: "files",
  contacted_domains: "files",
  contacted_urls: "files",
  // ドメインの**過去の**解決先。object の last_dns_records は現在しか返さないので、
  // ここでしか埋まらない（§9.1b）
  resolutions: "domains",
};
const KIND = REL_KIND[REL];
if (!KIND) {
  console.error(`--rel は ${Object.keys(REL_KIND).join(" / ")} のどれかです: ${REL}`);
  process.exit(2);
}

/* ---------------- 対象を決める ---------------- */

const iocs = readJsonl(path.join(IN, "iocs.jsonl"));
if (!iocs.length) {
  console.error(`${IN} に iocs.jsonl がありません。先に collect.mjs を実行してください。`);
  process.exit(1);
}
const links = readJsonl(path.join(IN, "links.jsonl"));
const vt = new Map(readJsonl(path.join(IN, "vt.jsonl")).map((r) => [r.ioc, r]));
if (!vt.size) {
  console.error("vt.jsonl がありません。先に fetch-vt.mjs → enrich-intel.mjs を実行してください。");
  process.exit(1);
}

const counts = entityCounts(links);
const HASH = new Set(["ioc.md5", "ioc.sha1", "ioc.sha256"]);

/**
 * ドメインの `resolutions` は**現在の解決先が無いものから引く**。
 *
 * 実測（40 件の試験取得）で、現在の解決先が無いドメインの 40% に履歴があり、
 * 1 件あたり平均 5.4 の IP が返った。しかも **72% は CDN ではない実サーバ**で、
 * `driver-store.com` の `89.36.224.5` のように**索引が既に持っている IP** に
 * 当たるものが 63 件中 9 件あった。
 *
 * いまドメインが Cloudflare の裏にあると `last_dns_records` は `104.21.x` しか
 * 返さず、解決先の守りで落ちる。**過去の解決先には Cloudflare を入れる前の
 * 原本 IP が残っている**ので、そこが取れるのがこの関係の値打ち。
 */
const resolved = new Set(
  readJsonl(path.join(IN, "derived-links.jsonl"))
    .filter((l) => l.rel === "resolves_to").map((l) => l.ioc));

const targets = [];
for (const r of iocs) {
  const n = counts.get(r.key) || 0;
  if (KIND === "domains") {
    if (r.type !== "ioc.domain") continue;
    if (n < 1) continue;               // 実体に繋がらないドメインは重なりを作れない
    if (resolved.has(r.key)) continue; // 現在の解決先があるなら object で足りている
    targets.push({ ioc: r.key, id: r.value, entities: n, malicious: vt.get(r.key)?.malicious ?? 0 });
    continue;
  }
  if (!HASH.has(r.type)) continue;
  const v = vt.get(r.key);
  // VT が知らない検体には関係も無い。引くだけ枠の無駄
  if (!v?.known) continue;
  if ((v.malicious ?? 0) < MIN_MAL) continue;
  if (n < MIN_ENT) continue;
  targets.push({ ioc: r.key, id: r.value, entities: n, malicious: v.malicious ?? 0 });
}
// 引く順は「跨る実体が多い順 → 検知が多い順 → 鍵順」。途中で止めても意味のある所まで進む
targets.sort((a, b) =>
  b.entities - a.entities || b.malicious - a.malicious || (a.ioc < b.ioc ? -1 : 1));

const now = Date.now();
const stale = (rec) => !rec || now - Date.parse(rec.fetched_at || 0) > MAX_AGE;
const todo = targets.filter((t) => stale(readRecord(CACHE, `${t.ioc}\t${REL}`)));

console.log(`関係 ${REL} の対象 ${targets.length} 件`
  + (KIND === "domains"
    ? "（実体つき・現在の解決先が無いドメイン）"
    : `（検知 ${MIN_MAL} 以上・実体 ${MIN_ENT} 以上のハッシュ）`));
console.log(`  写し済み ${targets.length - todo.length} / 残り ${todo.length}`);

if (PLAN_ONLY) {
  console.log(`  → 引かずに終わります（--plan）。写し: ${path.relative(REPO_ROOT, CACHE)}`);
  process.exit(0);
}

/* ---------------- 鍵と枠 ---------------- */

const keys = readKeys("VT_API_KEYS", "VT_API_KEYs", "VT_API_KEY");
if (!keys.length) {
  console.error('VirusTotal の鍵がありません。VT_API_KEYS="k1,k2,k3" で渡してください。');
  process.exit(2);
}

const pool = new KeyPool(keys, {
  rpm: Number(args.rpm || 4),
  hourly: Number(args.hourly || 240),
  daily: Number(args.daily || 500),
});

/** 枠は取得元に聞く。この呼び出し自体は枠を消費しない（fetch-vt.mjs と同じ）。 */
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

const budget = Math.min(LIMIT, pool.remaining, todo.length);
console.log(`  鍵 ${keys.length} 本。今この場で引けるのは ${pool.remaining} 件`);
if (!budget) {
  console.log("  引けるものがありません。");
  process.exit(0);
}

/* ---------------- 引く ---------------- */

/**
 * 写しに残すのは **相手の識別子だけ**（object と同じく射影する）。
 * 関係の応答は 1 件あたり相手の属性を丸ごと含むので、そのままだと写しが膨らむ。
 * 相手の判定が要るなら、その相手を object として引けばよい（そちらは既に全件ある）。
 */
const LIMIT_PER = 40;

const stat = { ok: 0, empty: 0, failed: 0 };
let taken = 0;
let stop = false;
process.on("SIGINT", () => {
  console.log("\n  中断しました。ここまでの写しは残ります。");
  stop = true;
});

async function fetchOne(slot, item) {
  const url = `https://www.virustotal.com/api/v3/${KIND}/${item.id}/${REL}?limit=${LIMIT_PER}`;
  const res = await fetch(url, { headers: { "x-apikey": slot.key, accept: "application/json" } });

  if (res.status === 429) return { retry: "quota" };
  if (res.status === 401 || res.status === 403) return { retry: "auth" };
  if (res.status >= 500) return { retry: "server", why: `HTTP ${res.status}` };

  const body = await res.json().catch(() => null);
  // 404 / 400 は結果として残す（object と同じ扱い。引き直しても直らない）
  if (res.status === 404 || res.status === 400) {
    return { record: { ioc: item.ioc, rel: REL, status: res.status, ...(REL === "resolutions" ? { hits: [] } : { ids: [] }) } };
  }
  if (!res.ok || !Array.isArray(body?.data)) {
    return { retry: "server", why: `HTTP ${res.status} ${body?.error?.code || ""}`.trim() };
  }
  if (REL === "resolutions") {
    /**
     * **いつの解決先かを一緒に残す。** 時期を捨てると、5 年前に同じ共用ホストに
     * 居ただけの組が上位に来る（§9.1b）。実体の活動期間と突き合わせられるように
     * `{ip, at}` の形で持つ。同じ IP が何度も出るので、**最も新しい日**だけ残す。
     */
    const seen = new Map();
    for (const d of body.data) {
      const ip = String(d?.attributes?.ip_address || "").trim();
      if (!ip) continue;
      const sec = Number(d?.attributes?.date);
      const at = Number.isFinite(sec) && sec > 0
        ? new Date(sec * 1000).toISOString().slice(0, 10) : null;
      const prev = seen.get(ip);
      if (!prev || (at && (!prev.at || at > prev.at))) seen.set(ip, { ip, ...(at ? { at } : {}) });
    }
    const hits = [...seen.values()].sort((a, b) => (a.ip < b.ip ? -1 : 1));
    return { record: { ioc: item.ioc, rel: REL, status: 200, hits } };
  }
  const ids = body.data.map((d) => String(d?.id || "")).filter(Boolean).sort();
  return { record: { ioc: item.ioc, rel: REL, status: 200, ids: [...new Set(ids)] } };
}

async function worker() {
  for (;;) {
    if (stop || taken >= budget) return;
    const item = todo[taken++];
    if (!item) return;

    let result = null;
    for (let attempt = 0; attempt < 3 && !stop; attempt++) {
      const slot = await pool.take();
      if (!slot) return;
      try {
        result = await fetchOne(slot, item);
      } catch (e) {
        result = { retry: "server", why: e.message };
      }
      if (result.record) break;
      if (result.retry === "auth") { pool.block(slot, result.why || "auth"); result = null; continue; }
      if (result.retry === "quota") { pool.exhaust(slot); result = null; continue; }
      await sleep(1000 * (attempt + 1));
      result = null;
    }
    if (!result?.record) { stat.failed++; continue; }

    writeRecord(CACHE, {
      ...result.record,
      // 鍵は写しに混ぜない。ヘッダも保存しない（fetch-vt.mjs と同じ約束）
      fetched_at: new Date().toISOString(),
      source: "virustotal",
    }, `${item.ioc}\t${REL}`);

    if ((result.record.ids ?? result.record.hits).length) stat.ok++; else stat.empty++;
    const n = stat.ok + stat.empty + stat.failed;
    if (n % 50 === 0 || n === budget) {
      console.log(`  ${String(n).padStart(5)} / ${budget}  相手あり ${stat.ok} / 相手なし ${stat.empty} / 取れず ${stat.failed}`);
    }
  }
}

await Promise.all(pool.slots.map(() => worker()));

console.log(`取得 ${stat.ok + stat.empty} 件（相手あり ${stat.ok} / 相手なし ${stat.empty} / 取れず ${stat.failed}）`);
for (const s of pool.report()) {
  console.log(`    ${s.key}  この実行で ${s.used} 件`);
}
console.log(`  → ${path.relative(REPO_ROOT, CACHE)}`);
