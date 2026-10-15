#!/usr/bin/env node
// ARTEX_38_11 — 指定された 250 IP の**レピュテーションの写しを取る工程**。
// **ここだけが外に出る。** 取ったものは .cache/ に置き、分析は写しからしか読まない。
//
//   ABUSEIPDB_API_KEY=k VT_API_KEYS=k1,k2 node fetch.mjs [--abuse] [--vt] [--plan]
//
// 引数なしなら両方。--plan は引かずに件数だけ出す。
//
// ## やらないこと
//
// **対象 IP への接続・走査・認証試行は一切行わない。** ポートスキャンもしない。
// HTTP も叩かない。ping も打たない。AbuseIPDB と VirusTotal の公開情報だけを見る。
// 相手は「ペンテスト用ツールが動いている」と言われているサーバであって、
// こちらから触りに行く理由が無い。触れば観測ではなく関与になる。
//
// ## 鍵の扱い
//
// 環境変数からのみ読む。コンソール・ログ・CSV・JSON・ソース・エラーメッセージに
// **一切出さない**。失敗したときも鍵を含む URL は出さない。
//
// ## 窓
//
// AbuseIPDB は `maxAgeInDays=365` で引く。90 日の窓は写しから切り出せるが、
// その逆はできない。**広く取って狭める。**
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CACHE = path.join(HERE, ".cache");
const CFG = JSON.parse(fs.readFileSync(path.join(HERE, "config.json"), "utf8"));
const args = process.argv.slice(2);
const has = (f) => args.includes(f);
const PLAN = has("--plan");
const DO_ABUSE = has("--abuse") || (!has("--abuse") && !has("--vt"));
const DO_VT = has("--vt") || (!has("--abuse") && !has("--vt"));

/* ---------------- 対象 ---------------- */

const targets = [];
for (const r of CFG.RANGES) {
  const base = r.split("/")[0].split(".").slice(0, 3).join(".");
  for (let i = CFG.HOST_RANGE[0]; i <= CFG.HOST_RANGE[1]; i++) targets.push(`${base}.${i}`);
}
console.log(`対象 ${targets.length} IP（${CFG.RANGES.join(" / ")} の .${CFG.HOST_RANGE[0]}〜.${CFG.HOST_RANGE[1]}）`);

const sha = (s) => crypto.createHash("sha256").update(s).digest("hex");
const slot = (kind, ip) => {
  const h = sha(`${kind}|${ip}`);
  return path.join(CACHE, kind, h.slice(0, 2), `${h}.json`);
};
const saved = (kind, ip) => fs.existsSync(slot(kind, ip));
const save = (kind, ip, rec) => {
  const f = slot(kind, ip);
  fs.mkdirSync(path.dirname(f), { recursive: true });
  fs.writeFileSync(f, JSON.stringify(rec, null, 1) + "\n");
};

const needAbuse = targets.filter((ip) => !saved("abuseipdb", ip));
const needVt = targets.filter((ip) => !saved("virustotal", ip));
console.log(`  AbuseIPDB: 写し済み ${targets.length - needAbuse.length} / 引くのは ${needAbuse.length}`);
console.log(`  VirusTotal: 写し済み ${targets.length - needVt.length} / 引くのは ${needVt.length}`);
if (PLAN) { console.log("  → 引かずに終わります（--plan）"); process.exit(0); }

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const stat = { abuse: { ok: 0, fail: 0 }, vt: { ok: 0, fail: 0 } };
const failures = [];

/* ---------------- AbuseIPDB ---------------- */

if (DO_ABUSE && needAbuse.length) {
  const KEY = process.env.ABUSEIPDB_API_KEY || process.env.ABUSEIPDB_API_KEYS?.split(",")[0];
  if (!KEY) {
    console.error("ABUSEIPDB_API_KEY がありません。AbuseIPDB は引きません。");
  } else {
    let remaining = null, i = 0, done = 0, stop = null;
    const queue = [...needAbuse];
    const worker = async () => {
      for (;;) {
        if (stop) return;
        const ip = queue.shift();
        if (!ip) return;
        await sleep(CFG.ABUSE_MIN_INTERVAL_MS * (i++ % CFG.ABUSE_CONCURRENCY));
        const u = new URL("https://api.abuseipdb.com/api/v2/check");
        u.searchParams.set("ipAddress", ip);
        u.searchParams.set("maxAgeInDays", String(CFG.FETCH_WINDOW_DAYS));
        u.searchParams.set("verbose", "");
        let res = null;
        try {
          res = await fetch(u, { headers: { Key: KEY, Accept: "application/json" } });
        } catch (e) {
          // **鍵を含む URL は出さない。**IP とエラーの種類だけ
          failures.push({ source: "abuseipdb", ip, reason: String(e?.message || e).slice(0, 120) });
          stat.abuse.fail++; continue;
        }
        const left = Number(res.headers.get("x-ratelimit-remaining"));
        if (Number.isFinite(left)) remaining = left;
        if (res.status === 429) { stop = "枠を使い切りました"; queue.unshift(ip); return; }
        if (res.status === 401 || res.status === 403) { stop = "鍵が受け付けられませんでした"; return; }
        const body = await res.json().catch(() => null);
        if (!res.ok || !body?.data) {
          failures.push({ source: "abuseipdb", ip, reason: `HTTP ${res.status}` });
          stat.abuse.fail++; continue;
        }
        save("abuseipdb", ip, {
          ip, source: "abuseipdb", endpoint: "check", status: 200,
          max_age_days: CFG.FETCH_WINDOW_DAYS,
          fetched_at: new Date().toISOString(), body: body.data,
        });
        stat.abuse.ok++;
        if (++done % 50 === 0) process.stdout.write(`\r  AbuseIPDB ${done}/${needAbuse.length}  残量 ${remaining ?? "?"}    `);
      }
    };
    await Promise.all(Array.from({ length: CFG.ABUSE_CONCURRENCY }, worker));
    console.log(`\n  AbuseIPDB 取得 ${stat.abuse.ok} 件 / 失敗 ${stat.abuse.fail} 件`
      + (stop ? `  — 中断: ${stop}` : "") + `  残量 ${remaining ?? "?"}`);
  }
}

/* ---------------- VirusTotal ---------------- */

if (DO_VT && needVt.length) {
  // **名前を 1 つに決めつけない。**この環境の鍵は `VT_API_KEYs`（末尾が小文字）に
  // 入っている。索引側の readKeys も同じ理由で複数の名前を見ている
  const keys = [...new Set(["VT_API_KEYS", "VT_API_KEYs", "VT_API_KEY"]
    .flatMap((n) => String(process.env[n] || "").split(/[,\s]+/))
    .map((s) => s.trim()).filter(Boolean))];
  if (!keys.length) {
    console.error("VT の鍵がありません（VT_API_KEYS / VT_API_KEYs / VT_API_KEY）。VirusTotal は引きません。");
  } else {
    // 1 鍵あたり毎分 N 件。鍵をまわして間隔を守る
    const gap = Math.ceil(60000 / CFG.VT_RPM_PER_KEY);
    const nextAt = keys.map(() => 0);
    const queue = [...needVt];
    let done = 0, stop = null;
    const worker = async (k) => {
      for (;;) {
        if (stop) return;
        const ip = queue.shift();
        if (!ip) return;
        const wait = nextAt[k] - Date.now();
        if (wait > 0) await sleep(wait);
        nextAt[k] = Date.now() + gap;
        let res = null;
        try {
          res = await fetch(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`,
            { headers: { "x-apikey": keys[k], accept: "application/json" } });
        } catch (e) {
          failures.push({ source: "virustotal", ip, reason: String(e?.message || e).slice(0, 120) });
          stat.vt.fail++; continue;
        }
        if (res.status === 429) { queue.unshift(ip); nextAt[k] = Date.now() + 60000; continue; }
        if (res.status === 401) { stop = "VT の鍵が受け付けられませんでした"; return; }
        if (res.status === 404) {
          save("virustotal", ip, { ip, source: "virustotal", status: 404,
            fetched_at: new Date().toISOString(), body: null });
          stat.vt.ok++; done++; continue;
        }
        const body = await res.json().catch(() => null);
        if (!res.ok || !body?.data) {
          failures.push({ source: "virustotal", ip, reason: `HTTP ${res.status}` });
          stat.vt.fail++; continue;
        }
        save("virustotal", ip, { ip, source: "virustotal", status: 200,
          fetched_at: new Date().toISOString(), body: body.data });
        stat.vt.ok++;
        if (++done % 25 === 0) process.stdout.write(`\r  VirusTotal ${done}/${needVt.length}    `);
      }
    };
    await Promise.all(keys.map((_, k) => worker(k)));
    console.log(`\n  VirusTotal 取得 ${stat.vt.ok} 件 / 失敗 ${stat.vt.fail} 件` + (stop ? `  — 中断: ${stop}` : ""));
  }
}

/* ---------------- 失敗は残す ---------------- */

if (failures.length) {
  fs.writeFileSync(path.join(HERE, "fetch_failures.json"), JSON.stringify(failures, null, 2) + "\n");
  console.log(`  ! 失敗 ${failures.length} 件を fetch_failures.json に残しました`);
}
const count = (kind) => targets.filter((ip) => saved(kind, ip)).length;
fs.writeFileSync(path.join(HERE, "fetch_meta.json"), JSON.stringify({
  dataset: CFG.DATASET,
  ranges: CFG.RANGES,
  targets: targets.length,
  fetch_window_days: CFG.FETCH_WINDOW_DAYS,
  copies: { abuseipdb: count("abuseipdb"), virustotal: count("virustotal") },
  failures: failures.length,
  finished_at: new Date().toISOString(),
}, null, 2) + "\n");
console.log(`写し: AbuseIPDB ${count("abuseipdb")} / VirusTotal ${count("virustotal")}（対象 ${targets.length}）`);
