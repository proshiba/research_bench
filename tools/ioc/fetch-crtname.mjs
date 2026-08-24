#!/usr/bin/env node
// 証明書の記録から、攻撃者ドメインの**兄弟（サブドメイン）**を集める。
// **ここは外に出る工程**。鍵は要らない。
//
//   node tools/ioc/fetch-crtname.mjs [--in data/ioc/latest] [--tracker data/ioc/tracker]
//                                    [--cache data/ioc/.cache/crtname]
//                                    [--limit 0] [--max-age 604800] [--plan]
//
// 取得元は crt.name（`/v1/search?apex=<登録可能ドメイン>`）。応答は text/plain で
// 1 行 1 ホスト名。レート上限は応答ヘッダ `x-ratelimit-limit` が 1000 と言う。
//
// ## なぜ効くか
//
// 公開の証明書記録には、攻撃者が証明書を取った名前がすべて残る。**攻撃者は
// 消せない**。実測（68 apex）で `glara.info` から `admin` `git` `dev` `portal`
// `config` `api-test` `springboot` `storage` などが出て、**全部が同じ 1 つの IP**
// （34.76.205.124）に解決した。索引には apex しか無かった。
//
// ## 何を的にするか
//
// **役割を述べられている apex だけ。** 実測で、役割を問わないと 1,381 apex に膨らみ、
// しかも増えたぶんの大半が共用基盤だった。役割つきなら 108 apex（約 2 分）で収まる。
// 生死は問わない —— 死んだドメインの証明書記録にも兄弟は残っているため。
import fs from "node:fs";
import path from "node:path";
import { parseArgs, readJsonl, writeJson, sha256 } from "./lib/io.mjs";
import { REPO_ROOT } from "./lib/sources.mjs";
import { statedRoles } from "./lib/tracker.mjs";

const args = parseArgs(process.argv.slice(2));
const IN = path.resolve(REPO_ROOT, args.in || "data/ioc/latest");
const TRACKER = path.resolve(REPO_ROOT, args.tracker || "data/ioc/tracker");
const CACHE = path.resolve(REPO_ROOT, args.cache || "data/ioc/.cache/crtname");
const LIMIT = args.limit === undefined ? Infinity : Number(args.limit) || Infinity;
const MAX_AGE = Number(args["max-age"] || 604800) * 1000;
const PLAN_ONLY = !!args.plan;
const DELAY = Number(args.delay || 300);
const BASE = args.url || "https://crt.name/v1/search";

/* ---------------- 何を引くか ---------------- */

const iocs = new Map();
for (const f of ["iocs.jsonl", "derived-iocs.jsonl"]) {
  const p = path.join(IN, f);
  if (fs.existsSync(p)) for (const r of readJsonl(p)) iocs.set(r.key, r);
}
const rels = new Map();
for (const l of readJsonl(path.join(IN, "links.jsonl"))) {
  if (!String(l.ioc || "").startsWith("ioc.domain|") || !l.rel) continue;
  const h = l.ioc.slice("ioc.domain|".length);
  if (!rels.has(h)) rels.set(h, new Set());
  rels.get(h).add(l.rel);
}
const state = new Map();
const sf = path.join(TRACKER, "state.jsonl");
if (fs.existsSync(sf)) for (const r of readJsonl(sf)) state.set(r.host, r);

/** apex（登録可能ドメイン）ごとに、そこへ役割を与えている子をまとめる */
const apexes = new Map();
for (const r of iocs.values()) {
  if (!String(r.key).startsWith("ioc.domain|") || !r.registrable) continue;
  const roles = statedRoles(rels.get(r.value));
  if (!roles.length) continue;
  // 事業者のドメインと動的 DNS の下は引かない。兄弟は他人のもの
  const s = state.get(r.value) || {};
  if (s.service_like || s.dynamic_suffix) continue;
  if (!apexes.has(r.registrable)) apexes.set(r.registrable, { roles: new Set(), hosts: new Set() });
  const a = apexes.get(r.registrable);
  for (const x of roles) a.roles.add(x);
  a.hosts.add(r.value);
}

const now = Date.now();
const file = (apex) => path.join(CACHE, apex.replace(/[^a-z0-9.-]/gi, "_") + ".json");
const stale = (apex) => {
  const f = file(apex);
  if (!fs.existsSync(f)) return true;
  try { return now - new Date(JSON.parse(fs.readFileSync(f, "utf8")).fetched_at || 0).getTime() >= MAX_AGE; }
  catch { return true; }
};

const all = [...apexes.keys()].sort();
const todo = all.filter(stale).slice(0, LIMIT);
console.log(`役割を述べられた apex ${all.length} 個`);
console.log(`  ${MAX_AGE / 86400000} 日以上引いていないもの ${all.filter(stale).length} / 今回引く ${todo.length}`);
if (!todo.length) { console.log("  引くものがありません"); process.exit(0); }
if (PLAN_ONLY) { console.log("  → 引かずに終わります（--plan）"); process.exit(0); }

/* ---------------- 引く ---------------- */

fs.mkdirSync(CACHE, { recursive: true });
let done = 0, failed = 0, remaining = null, total = 0;
for (const apex of todo) {
  let res;
  try {
    res = await fetch(`${BASE}?apex=${encodeURIComponent(apex)}`, { headers: { accept: "text/plain" } });
  } catch (e) {
    failed++; console.error(`\n${apex}: ${String(e.message || e).slice(0, 60)}`);
    continue;
  }
  remaining = res.headers.get("x-ratelimit-remaining") ?? remaining;
  if (!res.ok) {
    failed++;
    // 上限に当たったら止める。写しは残っているので次回続きから引く
    if (res.status === 429) { console.log(`\n枠切れ（HTTP 429）。${done} 件で止めます`); break; }
    writeJson(file(apex), { tool: "tools/ioc/fetch-crtname.mjs", schema: 1, apex,
      fetched_at: new Date().toISOString(), status: res.status, hosts: [] });
    continue;
  }
  const text = await res.text();
  // 応答は 1 行 1 ホスト。**そのままの並びには意味が無い**ので名前順にして写す
  const hosts = [...new Set(text.split("\n").map((s) => s.trim().toLowerCase())
    .filter((s) => s && !s.includes(" ")))].sort();
  writeJson(file(apex), {
    tool: "tools/ioc/fetch-crtname.mjs", schema: 1, apex,
    fetched_at: new Date().toISOString(), status: 200,
    sha256: sha256(Buffer.from(text, "utf8")), bytes: text.length,
    hosts,
  });
  done++; total += hosts.length;
  process.stdout.write(`\r  ${done}/${todo.length}  枠残 ${remaining ?? "?"}  ${apex.slice(0, 34).padEnd(36)} ${hosts.length} 件      `);
  if (DELAY) await new Promise((r) => setTimeout(r, DELAY));
}
console.log(`\n完了 ${done} / 取れず ${failed} / のべ ${total} ホスト`);
console.log(`  → ${CACHE}`);
console.log("  次は node tools/ioc/crtname.mjs（写しから兄弟を出す）");
