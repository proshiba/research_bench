#!/usr/bin/env node
// 既にある IP を**新しい畳み方で引き直す**。30 日の件数を埋めるため。
//
//   ABUSEIPDB_API_KEY=k node refetch.mjs [--limit 400] [--reserve 50] [--plan]
//
// ## なぜ要るのか
//
// `jp_report_count_30d` などは畳み方を直したあとに足した項目なので、
// それより前に引いた写しには入っていない。**生の reports 配列を残していない**ので、
// 手元の写しからは計算できない。引き直すしかない。
//
// 1 回の `/check` で 90 日ぶんの報告が返り、報告 1 件ずつに `reportedAt` が
// 付いているので、**同じ 1 回から 7 日・30 日・90 日の数が全部出る**。
// API 呼び出しは増えない。
//
// ## どれから引き直すか
//
// `jp_attack_sources_all.csv` の並び（段の重さ → 証拠の具体性）の上から。
// **人の確認に値する順**に埋まるようにする。枠が尽きても上から埋まっている。
//
// 鍵は環境変数からのみ読み、**どこにも書き出さない**。
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { digest, iso } from "../global-jp-vuln/rules.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "../..");
const CFG = JSON.parse(fs.readFileSync(path.join(HERE, "config.json"), "utf8"));
const args = process.argv.slice(2);
const has = (f) => args.includes(f);
const argOf = (f) => { const i = args.indexOf(f); return i >= 0 ? args[i + 1] : null; };
const LIMIT = Number(argOf("--limit") || 400);
const RESERVE = Number(argOf("--reserve") || 50);
const PLAN = has("--plan");

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
  const h = rows.shift().map((x) => x.replace(/^﻿/, ""));
  return rows.filter((r) => r.length > 1).map((r) => Object.fromEntries(h.map((k, i) => [k, r[i] ?? ""])));
}

const csv = path.join(HERE, "jp_attack_sources_all.csv");
if (!fs.existsSync(csv)) {
  console.error("jp_attack_sources_all.csv がありません。先に build.mjs を実行してください。");
  process.exit(1);
}
/** 既に 30 日を数えてある行は引き直さない */
const todo = parseCsv(fs.readFileSync(csv, "utf8"))
  .filter((r) => r.jp_30d_method !== "counted")
  .map((r) => r.ip_address);
console.log(`30 日の件数が無い主対象: ${todo.length} 件`);

const KEY = process.env.ABUSEIPDB_API_KEY || String(process.env.ABUSEIPDB_API_KEYS || "").split(",")[0];
if (!KEY) { console.error("ABUSEIPDB_API_KEY がありません。"); process.exit(2); }
const HEADERS = { Key: KEY, Accept: "application/json" };

/** 残量はヘッダが教えてくれる。手元の数より取得元を信じる */
let remaining = null;
{
  const u = new URL("https://api.abuseipdb.com/api/v2/check");
  u.searchParams.set("ipAddress", "127.0.0.1");
  u.searchParams.set("maxAgeInDays", "1");
  const r = await fetch(u, { headers: HEADERS });
  remaining = Number(r.headers.get("x-ratelimit-remaining"));
  console.log(`/check 残量 ${remaining}（予備枠 ${RESERVE} は使いません）`);
}
const budget = Math.max(0, Math.min(LIMIT, todo.length, (remaining || 0) - RESERVE));
console.log(`引き直すのは ${budget} 件（上から順。人の確認に値する順）`);
if (PLAN) { console.log("  → 引かずに終わります（--plan）"); process.exit(0); }
if (!budget) { console.log("枠がありません。終了します。"); process.exit(0); }

const out = fs.createWriteStream(path.resolve(ROOT, CFG.CHECKS), { flags: "a" });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let done = 0, failed = 0, stop = null;
const queue = todo.slice(0, budget);
const CONC = 6;
const worker = async () => {
  for (;;) {
    if (stop) return;
    const ip = queue.shift();
    if (!ip) return;
    await sleep(120);
    const u = new URL("https://api.abuseipdb.com/api/v2/check");
    u.searchParams.set("ipAddress", ip);
    // **90 日で引く。**30 日は報告の日時から切り出せるが、逆はできない
    u.searchParams.set("maxAgeInDays", String(CFG.CONTEXT_WINDOW_DAYS));
    u.searchParams.set("verbose", "");
    let res = null;
    try { res = await fetch(u, { headers: HEADERS }); } catch (e) {
      // **鍵を含む URL は出さない。**IP とエラーの種類だけ
      failed++; continue;
    }
    const left = Number(res.headers.get("x-ratelimit-remaining"));
    if (Number.isFinite(left)) remaining = left;
    if (res.status === 429) { stop = "枠を使い切りました"; return; }
    if (res.status === 401 || res.status === 403) { stop = "鍵が受け付けられませんでした"; return; }
    const body = await res.json().catch(() => null);
    if (!res.ok || !body?.data) { failed++; continue; }
    const rec = digest(ip, body, "refetch_30d", { checkedAt: iso(new Date()) });
    await new Promise((r) => out.write(JSON.stringify(rec) + "\n", r));
    if (++done % 50 === 0) process.stdout.write(`\r  ${done}/${budget}  残量 ${remaining ?? "?"}    `);
  }
};
await Promise.all(Array.from({ length: CONC }, worker));
out.end();
console.log(`\n引き直し ${done} 件 / 失敗 ${failed} 件` + (stop ? `  — 中断: ${stop}` : "")
  + `  残量 ${remaining ?? "?"}`);
console.log("  → build.mjs を再実行すると 30 日の件数が入ります");
