#!/usr/bin/env node
// 日々の名前解決の観測を畳んで、攻撃者ドメインの現況と「切り替わり」を出す。
// **写しだけを見る。外には出ない。**
//
//   node tools/ioc/track-domains.mjs [--in data/ioc/latest] [--tracker data/ioc/tracker]
//                                    [--cache data/ioc/.cache/bgptools] [--days 0]
//
// 出すもの
//   data/ioc/tracker/state.jsonl   1 ドメイン 1 行の現況（生死・現在の行き先・いつから）
//   data/ioc/tracker/events.jsonl  変化だけを並べたもの（いつ・何が・どう変わったか）
//
// **状態は観測から毎回作り直す。** 前回の state を読んで更新する作りにすると、
// 一度おかしくなった状態が永久に残る。observations/*.jsonl だけが真実で、
// state と events はそこから何度でも同じものが再生される。
//
// ## 何を「変化」と呼ばないか
//
//   1. **CDN / 大手クラウドの中での IP 移動。** Cloudflare は同じ名前に毎回違う IP を
//      返す。IP の差分を取ると毎日「切り替わった」と言い続けることになるので、
//      この手の AS の中では **AS が変わったときだけ**変化とみなす（lib/tracker.mjs）。
//   2. **動的 DNS の下のドメインの生死。** `foo.ddns.net` の登録可能ドメインは
//      No-IP のものであって攻撃者の資産ではない。**解決先だけを追い、ドメイン自体の
//      失効は追わない**（消えても「攻撃者が畳んだ」以上の意味を持たない）。
//   3. **一時的な引けなさ。** SERVFAIL やタイムアウトは判定を保留する。
//      これを「死んだ」と数えると、リゾルバが不機嫌な日に大量の誤報が出る。
import fs from "node:fs";
import path from "node:path";
import { parseArgs, readJsonl, writeJsonl, writeJson, byKeys } from "./lib/io.mjs";
import { REPO_ROOT } from "./lib/sources.mjs";
import { loadTable, lookupIpv4 } from "./lib/asn.mjs";
import { dynamicSuffixOf, isCdnAsn, looksDead, STATUS } from "./lib/tracker.mjs";

const args = parseArgs(process.argv.slice(2));
const IN = path.resolve(REPO_ROOT, args.in || "data/ioc/latest");
const TRACKER = path.resolve(REPO_ROOT, args.tracker || "data/ioc/tracker");
const CACHE = path.resolve(REPO_ROOT, args.cache || "data/ioc/.cache/bgptools");
/** 直近何日ぶんの観測を読むか。0 なら全部 */
const DAYS = Number(args.days || 0);

/* ---------------- 観測を日付順に読む ---------------- */

const obsDir = path.join(TRACKER, "observations");
if (!fs.existsSync(obsDir)) {
  console.error(`${obsDir} がありません。先に fetch-dns.mjs を実行してください。`);
  process.exit(2);
}
let dates = fs.readdirSync(obsDir).filter((f) => /^\d{4}-\d{2}-\d{2}\.jsonl$/.test(f))
  .map((f) => f.slice(0, 10)).sort();
if (DAYS > 0) dates = dates.slice(-DAYS);
if (!dates.length) { console.error("観測がありません"); process.exit(2); }
console.log(`観測 ${dates.length} 日ぶん（${dates[0]} 〜 ${dates[dates.length - 1]}）`);

/* ---------------- AS を引く道具 ---------------- */

const tableFile = path.join(CACHE, "table.jsonl");
const asns = new Map(readJsonl(path.join(IN, "asns.jsonl")).map((a) => [a.asn, a]));
let table = null;
if (fs.existsSync(tableFile)) {
  table = loadTable(tableFile, ["v4"]);
  console.log(`  経路表 ${table.v4Count.toLocaleString()} 件を読んだ`);
} else {
  console.log("  ! 経路表が無いので AS を引けません（fetch-asn.mjs を先に）。IP だけで比べます");
}
const asnOf = (ip) => {
  if (!table) return null;
  const hit = lookupIpv4(table, ip);
  return hit ? hit.asn : null;
};
/** その IP が「動いても意味を持たない」側にいるか */
const cdnLike = (ip) => {
  const asn = asnOf(ip);
  if (asn == null) return { cdn: false, asn: null };
  return { cdn: isCdnAsn(asn, asns.get(asn)?.addresses), asn };
};

/* ---------------- 1 日ぶんの観測を「見え方」に畳む ---------------- */

/** その日の観測 1 行から、比べるための形を作る。
 *  ここで CDN の IP を AS に丸める。丸めた事実は残す（隠さない） */
function shapeOf(o) {
  const ips = [...(o.a || []), ...(o.aaaa || [])];
  const live = ips.filter((ip) => !looksDead(ip));
  const asnSet = new Set(), cdnSet = new Set();
  let anyCdn = false;
  for (const ip of live) {
    if (ip.includes(":")) continue; // v6 は経路表を読んでいない
    const { cdn, asn } = cdnLike(ip);
    if (asn != null) asnSet.add(asn);
    if (cdn) { anyCdn = true; cdnSet.add(asn); }
  }
  const status = o.status === "nxdomain" ? STATUS.NXDOMAIN
    : o.status === "error" ? STATUS.ERROR
    : !ips.length ? STATUS.NO_ANSWER
    : !live.length ? STATUS.PARKED
    : STATUS.ALIVE;
  return {
    status,
    ips: live.sort(),
    parked_ips: ips.filter((ip) => looksDead(ip)).sort(),
    asns: [...asnSet].sort((a, b) => a - b),
    cname: (o.cname || []).slice().sort(),
    ns: (o.ns || []).slice().sort(),
    /** CDN の上に乗っているので IP の差分は見ない、という印 */
    cdn: anyCdn,
    cdn_asns: [...cdnSet].sort((a, b) => a - b),
  };
}
/** 比較に使う鍵。CDN の上なら AS だけ、そうでなければ IP まで見る */
const addressKey = (s) => (s.cdn ? "as:" + s.asns.join(",") : "ip:" + s.ips.join(","));

/* ---------------- 畳む ---------------- */

const state = new Map();   // host -> 現況
const events = [];
let observations = 0;

for (const date of dates) {
  for (const o of readJsonl(path.join(obsDir, `${date}.jsonl`))) {
    observations++;
    const host = o.host;
    const s = shapeOf(o);
    const dyn = o.dynamic_suffix || dynamicSuffixOf(host) || null;
    const prev = state.get(host);
    const push = (kind, detail) => events.push({ date, host, kind, ...detail });

    if (!prev) {
      state.set(host, { host, dynamic_suffix: dyn, first_seen: date, last_seen: date,
        status: s.status, since: date, shape: s, addr_key: addressKey(s),
        last_alive: s.status === STATUS.ALIVE ? date : null,
        changes: 0, ip_changes: 0, as_changes: 0 });
      continue;
    }
    prev.last_seen = date;
    if (s.status === STATUS.ALIVE) prev.last_alive = date;

    // 1. 引けなかった日は何も判定しない
    if (s.status === STATUS.ERROR) continue;

    // 2. 生死の変化。動的 DNS のドメインは生死を追わない（解決先だけ見る）
    if (s.status !== prev.status) {
      const bothLive = s.status === STATUS.ALIVE && prev.status === STATUS.ALIVE;
      const skip = dyn && (s.status === STATUS.NXDOMAIN || prev.status === STATUS.NXDOMAIN);
      if (!bothLive && !skip) {
        push("status", { from: prev.status, to: s.status,
          ...(dyn ? { dynamic_suffix: dyn } : {}) });
        prev.changes++;
      }
      prev.status = s.status;
      prev.since = date;
    }

    // 3. 行き先の変化
    if (s.status === STATUS.ALIVE) {
      const before = prev.shape, key = addressKey(s);
      if (key !== prev.addr_key) {
        const asChanged = before.asns.join(",") !== s.asns.join(",");
        if (s.cdn || before.cdn) {
          // CDN の上では AS が変わったときだけ
          if (asChanged) {
            push("as_change", { from: before.asns, to: s.asns, cdn: true,
              from_names: before.asns.map((a) => asns.get(a)?.name).filter(Boolean),
              to_names: s.asns.map((a) => asns.get(a)?.name).filter(Boolean) });
            prev.as_changes++; prev.changes++;
          }
        } else {
          push(asChanged ? "as_change" : "ip_change", {
            from: before.ips, to: s.ips,
            ...(asChanged ? { from_asns: before.asns, to_asns: s.asns,
              from_names: before.asns.map((a) => asns.get(a)?.name).filter(Boolean),
              to_names: s.asns.map((a) => asns.get(a)?.name).filter(Boolean) } : {}),
          });
          if (asChanged) prev.as_changes++; else prev.ip_changes++;
          prev.changes++;
        }
        prev.addr_key = key;
      }
      if (before.cname.join(",") !== s.cname.join(",") && (before.cname.length || s.cname.length)) {
        push("cname_change", { from: before.cname, to: s.cname });
        prev.changes++;
      }
    }
    prev.shape = s;
  }
}

/* ---------------- 書き出す ---------------- */

const rows = [...state.values()].map((r) => ({
  host: r.host,
  status: r.status,
  since: r.since,
  first_seen: r.first_seen,
  last_seen: r.last_seen,
  last_alive: r.last_alive,
  dynamic_suffix: r.dynamic_suffix || undefined,
  /** 動的 DNS の下では、追うのは解決先だけでドメインの生死は追わない */
  track_domain: r.dynamic_suffix ? false : true,
  ips: r.shape.ips,
  asns: r.shape.asns,
  asn_names: r.shape.asns.map((a) => asns.get(a)?.name).filter(Boolean),
  cdn: r.shape.cdn || undefined,
  parked_ips: r.shape.parked_ips.length ? r.shape.parked_ips : undefined,
  cname: r.shape.cname.length ? r.shape.cname : undefined,
  changes: r.changes,
  ip_changes: r.ip_changes,
  as_changes: r.as_changes,
})).sort(byKeys("host"));
writeJsonl(path.join(TRACKER, "state.jsonl"), rows);
events.sort((a, b) => (a.date < b.date ? -1 : a.date > b.date ? 1 : a.host < b.host ? -1 : 1));
writeJsonl(path.join(TRACKER, "events.jsonl"), events);

/* ---------------- 見せる ---------------- */

const tally = rows.reduce((m, r) => (m[r.status] = (m[r.status] || 0) + 1, m), {});
const alive = rows.filter((r) => r.status === STATUS.ALIVE);
console.log(`\n現況 ${rows.length} ドメイン: ` + Object.entries(tally).sort().map(([k, v]) => `${k} ${v}`).join(" / "));
console.log(`  生きているもの ${alive.length}（うち CDN の上 ${alive.filter((r) => r.cdn).length} / 動的 DNS の下 ${alive.filter((r) => r.dynamic_suffix).length}）`);
const kinds = events.reduce((m, e) => (m[e.kind] = (m[e.kind] || 0) + 1, m), {});
console.log(`変化 ${events.length} 件: ` + (Object.entries(kinds).map(([k, v]) => `${k} ${v}`).join(" / ") || "なし"));
const last = dates[dates.length - 1];
const today = events.filter((e) => e.date === last);
if (today.length) {
  console.log(`\n${last} の変化 ${today.length} 件:`);
  for (const e of today.slice(0, 30)) {
    const f = Array.isArray(e.from) ? e.from.join(",") : e.from;
    const t = Array.isArray(e.to) ? e.to.join(",") : e.to;
    console.log(`  ${e.kind.padEnd(13)} ${e.host.padEnd(38)} ${String(f).slice(0, 34)} → ${String(t).slice(0, 34)}`);
  }
}
writeJson(path.join(TRACKER, "tracker-meta.json"), {
  tool: "tools/ioc/track-domains.mjs", schema: 1,
  built_at: new Date().toISOString(),
  observations, days: dates.length, from: dates[0], to: last,
  domains: rows.length, by_status: tally,
  alive: { total: alive.length, cdn: alive.filter((r) => r.cdn).length,
    dynamic: alive.filter((r) => r.dynamic_suffix).length },
  events: { total: events.length, by_kind: kinds, on_last_day: today.length },
  routing_table: table ? { prefixes: table.v4Count } : null,
});
console.log(`\n  → ${path.join(TRACKER, "state.jsonl")} / events.jsonl`);
