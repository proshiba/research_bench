#!/usr/bin/env node
// 同じ IP に居るドメインの「形」を測る。**追跡の写しと索引だけを見る。外には出ない。**
//
//   node reports/weekly/review/colocation-profile.mjs [--min 8] [--json]
//
// ## 何のための道具か
//
// 週次レポートは 2 か月にわたって「同居」をどう読むかに手こずっていた。
// 同じ IP に複数のアクターのドメインが居たとき、それが
//
//   (a) 1 つの運用者が使っているノード          → 所見になる
//   (b) 失効ドメインの受け皿（シンクホール・パーキング） → 所見にしてはいけない
//   (c) 共有サービスの接尾辞（動的 DNS・無料ホスティング） → 材料にしない
//
// のどれなのかは、毎回その場の判断で書かれていた。2026-11-14 に
// `104.219.250.37` が (b) だと分かったとき、**それ以前の週の「つながり」が
// 何件巻き添えになるのかを誰も数えられなかった。**ここを数で分ける。
//
// ## 分け方
//
// **apex の数をホスト数で割る。**
//
//   比が低い  = 少数の apex に多数のホスト名がぶら下がっている
//               → 1 人が持っているドメインの下のサブドメイン群
//   比が高い  = ホストごとに apex が違う
//               → 無関係なドメインが 1 つの住所に集められている
//
// これに**索引のアクター数**を足す。無関係なアクターが何人も並ぶのは (b) の印。
// ただし比が低くても、最大 apex が `ddns.net` や `infinityfreeapp.com` のような
// **共有接尾辞**なら (c) であって (a) ではない。そこは接尾辞の一覧で分ける。
//
// **どれも印であって判定ではない。** 該当しても行は捨てない。
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "../../..");
const args = process.argv.slice(2);
const MIN = Number(args[args.indexOf("--min") + 1]) || 8;
const AS_JSON = args.includes("--json");

/**
 * 共有サービスの接尾辞。ここに載る apex は「1 人の持ち物」ではないので、
 * 比が低くても運用ノードとは読まない。**足りなければ足す。網羅はしていない。**
 */
const SHARED_SUFFIX = new Set([
  "ddns.net", "duckdns.org", "no-ip.org", "no-ip.biz", "hopto.org", "zapto.org",
  "serveo.net", "ngrok.io", "trycloudflare.com", "infinityfreeapp.com", "epizy.com",
  "000webhostapp.com", "gr.com", "github.io", "pages.dev", "workers.dev",
  "vercel.app", "netlify.app", "herokuapp.com", "firebaseapp.com", "web.app",
  "blogspot.com", "wordpress.com", "weebly.com", "glitch.me", "repl.co",
  // 2026-11-15 の見直しで追加。追跡の中に実際に居た分だけ足している
  "onrender.com", "3utilities.com", "atwebpages.com", "1cooldns.com",
  "myftp.biz", "myftp.org", "serveftp.com", "servebeer.com", "sytes.net",
  "redirectme.net", "servegame.com", "servehttp.com", "bounceme.net",
]);

const readJsonl = (p) => {
  if (!fs.existsSync(p)) return [];
  return fs.readFileSync(p, "utf8").split("\n").filter(Boolean)
    .map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
};

const state = readJsonl(path.join(ROOT, "data/ioc/tracker/state.jsonl"));
if (!state.length) {
  console.error("data/ioc/tracker/state.jsonl がありません。先に track-domains.mjs を実行してください。");
  process.exit(1);
}
const events = readJsonl(path.join(ROOT, "data/ioc/tracker/events.jsonl"));
const links = readJsonl(path.join(ROOT, "data/ioc/latest/links.jsonl"));
const extIps = new Set(readJsonl(path.join(ROOT, "data/ioc/latest/iocs.jsonl"))
  .filter((r) => String(r.key || "").startsWith("ioc.ipv4|")).map((r) => r.key.slice(9)));

/** `state.jsonl` の `registrable` は空なので、ホスト名の末尾 2 ラベルで代用する。
 *  **公開接尾辞を見ていないので、`co.uk` のような二段の接尾辞では粗い。** */
const apexOf = (h) => {
  const p = String(h).split(".");
  return p.length >= 2 ? p.slice(-2).join(".") : h;
};
const actorOf = new Map();
for (const l of links) {
  if (l.kind !== "actor") continue;
  const k = String(l.ioc || "");
  if (!k.startsWith("ioc.domain|")) continue;
  const d = k.slice(11);
  if (!actorOf.has(d)) actorOf.set(d, new Set());
  actorOf.get(d).add(l.name);
};
const actorsFor = (host) => {
  const out = new Set();
  for (const d of [host, apexOf(host)]) for (const a of actorOf.get(d) || []) out.add(a);
  return out;
};

/** その IP へ「移ってきた」日。**`since` は状態が変わった日なので使えない**
 *  （追跡に入った日とも重なるため、波に見えてしまう） */
const arrivals = new Map();
for (const e of events) {
  if (e.kind !== "ip_change" && e.kind !== "as_change") continue;
  for (const ip of (e.to || [])) {
    if (typeof ip !== "string") continue;
    if (!arrivals.has(ip)) arrivals.set(ip, []);
    arrivals.get(ip).push({ date: e.date, host: e.host });
  }
}

const byIp = new Map();
for (const r of state) {
  for (const ip of (r.ips || [])) {
    if (!byIp.has(ip)) byIp.set(ip, []);
    byIp.get(ip).push(r);
  }
}

const rows = [];
for (const [ip, hosts] of byIp) {
  if (hosts.length < MIN) continue;
  const apex = new Map();
  const actors = new Set();
  for (const r of hosts) {
    const a = apexOf(r.host);
    apex.set(a, (apex.get(a) || 0) + 1);
    for (const x of actorsFor(r.host)) actors.add(x);
  }
  const top = [...apex].sort((a, b) => b[1] - a[1])[0] || ["—", 0];
  const ratio = apex.size / hosts.length;
  const sharedTop = SHARED_SUFFIX.has(top[0]);
  const arr = arrivals.get(ip) || [];
  const byDay = new Map();
  for (const a of arr) byDay.set(a.date, (byDay.get(a.date) || 0) + 1);
  const biggestWave = Math.max(0, ...byDay.values());
  /** **印であって判定ではない。** */
  const mark = sharedTop ? "共有サービスの接尾辞"
    : (ratio >= 0.5 && actors.size >= 5) ? "受け皿らしい"
      : (ratio <= 0.25) ? "少数 apex に集中"
        : "どちらとも言えない";
  rows.push({
    ip, hosts: hosts.length, apexes: apex.size, actors: actors.size,
    apex_per_host: Number(ratio.toFixed(2)),
    top_apex: top[0], top_apex_hosts: top[1], top_apex_is_shared_suffix: sharedTop,
    actor_names: [...actors].sort(),
    arrivals_tracked: arr.length, biggest_arrival_wave: biggestWave,
    biggest_arrival_day: [...byDay].sort((a, b) => b[1] - a[1])[0]?.[0] || "",
    in_external_index: extIps.has(ip),
    mark,
  });
}
rows.sort((a, b) => b.hosts - a.hosts);

if (AS_JSON) {
  console.log(JSON.stringify({
    generated_from: "data/ioc/tracker/state.jsonl + events.jsonl + data/ioc/latest/links.jsonl",
    note: "印であって判定ではない。該当しても行は捨てない",
    min_hosts: MIN, ips: rows.length, rows,
  }, null, 2));
} else {
  console.log(`同じ IP に ${MIN} ホスト以上が居るもの: ${rows.length} 件`
    + `（追跡 ${state.length.toLocaleString()} ホスト）\n`);
  console.log("IP                ホスト apex アクター 比   最大 apex                 外部索引 印");
  for (const r of rows.slice(0, 30)) {
    console.log(`  ${r.ip.padEnd(16)} ${String(r.hosts).padStart(4)} `
      + `${String(r.apexes).padStart(4)} ${String(r.actors).padStart(6)} `
      + `${r.apex_per_host.toFixed(2)} ${(r.top_apex + "(" + r.top_apex_hosts + ")").padEnd(24)} `
      + `${r.in_external_index ? "あり" : "**無**"}  ${r.mark}`);
  }
  const recv = rows.filter((r) => r.mark === "受け皿らしい");
  console.log(`\n受け皿らしい ${recv.length} 件:`);
  for (const r of recv) {
    console.log(`  ${r.ip.padEnd(16)} ${r.hosts} ホスト / ${r.actors} アクター`
      + `  ${r.actor_names.slice(0, 8).join(", ")}`);
  }
}
