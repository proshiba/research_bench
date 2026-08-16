#!/usr/bin/env node
// 攻撃者ドメインを片端から名前解決して、その日の観測を残す。**ここは外に出る工程**。
//
//   node tools/ioc/fetch-dns.mjs [--in data/ioc/latest] [--out data/ioc/tracker]
//                                [--limit 0] [--concurrency 24] [--timeout 5000]
//                                [--resolver 8.8.8.8,1.1.1.1] [--date 2026-08-16]
//                                [--retries 2] [--retry-concurrency 6]
//
// 攻撃者のサーバには触らない。**公開リゾルバに名前を聞くだけ**で、
// 解決先に接続もしない。API の鍵も要らず、枠も消費しない。
//
// 出力は 1 日 1 ファイル。
//   data/ioc/tracker/observations/<YYYY-MM-DD>.jsonl
//
// **なぜ「最新の写し」ではなく日付ごとに残すのか。** 追いたいのは現在値ではなく
// 切り替わりだから。上書きしてしまうと、いつ変わったのかが永久に分からない。
// 1 日 1 ファイルなら決定的で、git の差分としても読める。
//
// **答えが返らなかったものは引き直す。** 初回 6,245 件の実測で `error` が 622 件
// 出たが、内訳は ETIMEOUT 497 / ESERVFAIL 120 / EREFUSED 3 で、大半は相手側の
// 問題ではなく**こちらが 1 台のリゾルバを叩きすぎたため**（同時 24 × 4 問い合わせ）。
// `error` は track-domains 側で「判定保留」になるので、放っておくと毎日 1 割の
// ドメインが**生死不明のまま**になる。同時数を落とし、リゾルバを変えて引き直す。
import fs from "node:fs";
import path from "node:path";
import dns from "node:dns";
import { parseArgs, readJsonl, writeJsonl, writeJson, byKeys } from "./lib/io.mjs";
import { REPO_ROOT } from "./lib/sources.mjs";
import { dynamicSuffixOf, trackable } from "./lib/tracker.mjs";

const args = parseArgs(process.argv.slice(2));
const IN = path.resolve(REPO_ROOT, args.in || "data/ioc/latest");
const OUT = path.resolve(REPO_ROOT, args.out || "data/ioc/tracker");
const LIMIT = args.limit === undefined ? Infinity : Number(args.limit) || Infinity;
const CONCURRENCY = Number(args.concurrency || 24);
const TIMEOUT = Number(args.timeout || 5000);
const DATE = String(args.date || new Date().toISOString().slice(0, 10));
const RETRIES = Number(args.retries ?? 2);
const RETRY_CONCURRENCY = Number(args["retry-concurrency"] || 6);

// リゾルバは**複数を順に使う**。1 台に寄せると、その 1 台の機嫌で
// 「生死不明」の件数が毎日変わってしまい、差分が読めなくなる。
const RESOLVERS = String(args.resolver || "8.8.8.8,1.1.1.1")
  .split(",").map((s) => s.trim()).filter(Boolean);
/** 引き直しの回ごとにリゾルバを変える。同じ 1 台に聞き直しても答えは変わらない。
 *
 *  **リゾルバ側の再送を外側の制限時間の中に収める。** 1 問い合わせぜんたいを
 *  TIMEOUT で打ち切っているので、リゾルバに `timeout: TIMEOUT` を渡すと再送が
 *  1 回も入らない。実測: `tries: 1` にしたら 1 回目の error が 622 → 2,861 件に
 *  増えた（引き直しで最終 155 件まで戻ったが、6,245 件のうち 2,861 件を
 *  二度引くのは無駄）。1 回あたりを短くして、中で 3 回試させる。 */
const resolverFor = (round) => {
  const r = new dns.promises.Resolver({ timeout: Math.max(1000, Math.floor(TIMEOUT / 3)), tries: 3 });
  r.setServers([RESOLVERS[round % RESOLVERS.length], ...RESOLVERS.filter((_, i) => i !== round % RESOLVERS.length)]);
  return r;
};

/* ---------------- 誰を追うか ---------------- */

const iocs = new Map([...readJsonl(path.join(IN, "iocs.jsonl")),
  ...readJsonl(path.join(IN, "derived-iocs.jsonl"))].map((r) => [r.key, r]));
const vt = new Map([...readJsonl(path.join(IN, "vt.jsonl")),
  ...readJsonl(path.join(IN, "derived-verdicts.jsonl"))].map((r) => [r.ioc, r]));
const links = [...readJsonl(path.join(IN, "links.jsonl")),
  ...readJsonl(path.join(IN, "derived-links.jsonl"))];
const relsOf = new Map();
for (const l of links) {
  if (!relsOf.has(l.ioc)) relsOf.set(l.ioc, new Set());
  if (l.rel) relsOf.get(l.ioc).add(l.rel);
}

const targets = [];
for (const [key, rec] of iocs) {
  if (!key.startsWith("ioc.domain|")) continue;
  if (!trackable(key, { relsOf, vt, iocs })) continue;
  targets.push({ key, host: key.slice("ioc.domain|".length), dynamic: dynamicSuffixOf(rec.key ? key.slice("ioc.domain|".length) : "") });
}
targets.sort(byKeys("host"));
const todo = targets.slice(0, LIMIT);
console.log(`追跡対象のドメイン ${targets.length} 件（役割つき または VT 検知 2 以上）`);
console.log(`  うち動的 DNS / 共用基盤の下: ${targets.filter((t) => t.dynamic).length}`);
console.log(`  今回引く: ${todo.length} 件 / 同時 ${CONCURRENCY} / リゾルバ ${RESOLVERS.join(",")}`);

/* ---------------- 引く ---------------- */

const withTimeout = (p) => Promise.race([p,
  new Promise((_, rej) => setTimeout(() => rej(Object.assign(new Error("timeout"), { code: "ETIMEOUT" })), TIMEOUT))]);

/** 1 ドメインぶん。A / AAAA / CNAME / NS を引く。
 *  NS も引くのは、A が消えたときに「失効した」のか「向き先を外しただけ」なのかを
 *  分けるため。NS が残っていれば登録自体は生きている */
async function lookup(t, resolver) {
  const out = { ioc: t.key, host: t.host, date: DATE };
  if (t.dynamic) out.dynamic_suffix = t.dynamic;
  const ask = async (kind, fn) => {
    try { return await withTimeout(fn()); }
    catch (e) {
      if (!out.errors) out.errors = {};
      out.errors[kind] = e.code || String(e.message || e).slice(0, 24);
      return null;
    }
  };
  const [a, aaaa, cname, ns] = await Promise.all([
    ask("a", () => resolver.resolve4(t.host)),
    ask("aaaa", () => resolver.resolve6(t.host)),
    ask("cname", () => resolver.resolveCname(t.host)),
    ask("ns", () => resolver.resolveNs(t.host)),
  ]);
  if (a?.length) out.a = [...new Set(a)].sort();
  if (aaaa?.length) out.aaaa = [...new Set(aaaa)].sort();
  if (cname?.length) out.cname = [...new Set(cname.map((x) => x.toLowerCase()))].sort();
  if (ns?.length) out.ns = [...new Set(ns.map((x) => x.toLowerCase()))].sort();
  // 一番強い手掛かりを status にする。NXDOMAIN は A の結果だけで決める
  out.status = out.a || out.aaaa ? "answer"
    : out.errors?.a === "ENOTFOUND" ? "nxdomain"
    : out.errors?.a === "ENODATA" ? "no_answer"
    : "error";
  return out;
}

/** 1 回ぶん引く。答えは host をキーにして返す */
async function pass(targets, { concurrency, round }) {
  const resolver = resolverFor(round);
  const out = new Map();
  let done = 0;
  const queue = [...targets].reverse();
  const worker = async () => {
    for (;;) {
      const t = queue.pop();
      if (!t) return;
      out.set(t.host, await lookup(t, resolver));
      if (++done % 200 === 0) process.stdout.write(`\r  ${done} / ${targets.length}      `);
    }
  };
  await Promise.all(Array.from({ length: concurrency }, worker));
  return out;
}

const answers = await pass(todo, { concurrency: CONCURRENCY, round: 0 });
console.log(`\r  ${todo.length} / ${todo.length}      `);

// 答えが返らなかったものだけ、同時数を落として引き直す。
// **nxdomain と no_answer は引き直さない** ——「無い」も立派な答えなので。
const byHost = new Map(todo.map((t) => [t.host, t]));
for (let round = 1; round <= RETRIES; round++) {
  const failed = [...answers.values()].filter((r) => r.status === "error").map((r) => byHost.get(r.host));
  if (!failed.length) break;
  console.log(`  引き直し ${round}: ${failed.length} 件 / 同時 ${RETRY_CONCURRENCY} / リゾルバ ${RESOLVERS[round % RESOLVERS.length]}`);
  const retried = await pass(failed, { concurrency: RETRY_CONCURRENCY, round });
  let fixed = 0;
  for (const [host, r] of retried) {
    // 引き直しで答えが出たときだけ差し替える。**悪くなる方向には上書きしない**
    if (r.status === "error") continue;
    answers.set(host, { ...r, retried: round });
    fixed++;
  }
  console.log(`  → ${fixed} 件が答えるようになりました`);
}

const results = [...answers.values()];
results.sort(byKeys("host"));
const dir = path.join(OUT, "observations");
fs.mkdirSync(dir, { recursive: true });
const file = path.join(dir, `${DATE}.jsonl`);
writeJsonl(file, results);

const tally = results.reduce((m, r) => (m[r.status] = (m[r.status] || 0) + 1, m), {});
console.log(`\n観測 ${results.length} 件: ` + Object.entries(tally).map(([k, v]) => `${k} ${v}`).join(" / "));
writeJson(path.join(OUT, "fetch-meta.json"), {
  tool: "tools/ioc/fetch-dns.mjs", schema: 1,
  date: DATE, fetched_at: new Date().toISOString(),
  resolvers: RESOLVERS, targets: targets.length, resolved: results.length, by_status: tally,
  retries: RETRIES, recovered_by_retry: results.filter((r) => r.retried).length,
});
console.log(`  → ${file}`);
