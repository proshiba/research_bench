#!/usr/bin/env node
// validate.mjs 自体の検査。外部呼び出しなし、既存のデータも要らない。
//
//   node tools/ioc/selftest.mjs [--keep]
//
// なぜ要るか
//   検査script は「通る」だけでは意味がない。通ってしまう壊れ方があるなら、
//   それは検査していないのと同じ。ここでは **正しい一式を作り、既知の壊し方を 1 つずつ
//   加えて、狙った規則が鳴ることを確かめる**。鳴らなければ失敗する。
//
// 加える壊し方は、これまで実際に見つかったものを元にしている。
//   ・SHA-512 を ioc.sha256 として載せる（索引側に実在した誤り）
//   ・別名が「A, B, C」と 1 つにまとまっている
//   ・取得に失敗した索引があるのに、揃った一式として扱う

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { readJsonl, writeJson, writeJsonl } from "./lib/io.mjs";
import { coverageOf } from "./lib/enrich.mjs";
import { REPO_ROOT } from "./lib/sources.mjs";

const KEEP = process.argv.includes("--keep");

/* ---------------- 正しい一式を作る ---------------- */

const IOCS = [
  { key: "ioc.domain|evil.example.com", type: "ioc.domain", value: "evil.example.com",
    registrable: "example.com", sources: ["src-a"], raw: "evil[.]example[.]com" },
  // 正規サービスの混入（人気順位つき）。統計側で popular として除かれる
  { key: "ioc.domain|legit.example.com", type: "ioc.domain", value: "legit.example.com",
    registrable: "example.com", sources: ["src-a"] },
  // その名前を騙るドメイン。根拠からは外れるが標的として数え直される
  { key: "ioc.domain|legit-login.example.net", type: "ioc.domain", value: "legit-login.example.net",
    registrable: "example.net", sources: ["src-a"] },
  { key: "ioc.domain|c2.example.com", type: "ioc.domain", value: "c2.example.com",
    registrable: "example.com", sources: ["src-a", "src-b"],
    observed_first: "2026-01-05", observed_last: "2026-02-10" },
  // 203.0.113.0/24 は文書用の予約。bogon の印が付くこと自体を検査に含める
  { key: "ioc.ipv4|203.0.113.5", type: "ioc.ipv4", value: "203.0.113.5",
    subnet: "203.0.113.0/24", bogon: true, sources: ["src-a"] },
  { key: "ioc.ipv4|45.32.10.7", type: "ioc.ipv4", value: "45.32.10.7",
    subnet: "45.32.10.0/24", sources: ["src-b"] },
  // 経路に出ていない IP。AS の付与では routed:false の印だけが付く
  { key: "ioc.ipv4|45.32.10.8", type: "ioc.ipv4", value: "45.32.10.8",
    subnet: "45.32.10.0/24", sources: ["src-b"] },
  { key: "ioc.ipv4|8.8.8.8", type: "ioc.ipv4", value: "8.8.8.8",
    subnet: "8.8.8.0/24", noise: "Google DNS", sources: ["src-b"] },
  { key: "ioc.md5|" + "0".repeat(32), type: "ioc.md5", value: "0".repeat(32), sources: ["src-a"] },
  { key: "ioc.sha256|" + "1".repeat(64), type: "ioc.sha256", value: "1".repeat(64), sources: ["src-b"] },
  // VT が索引に無いファミリ名を付ける検体。生えた実体の道筋を通す
  { key: "ioc.sha1|" + "2".repeat(40), type: "ioc.sha1", value: "2".repeat(40), sources: ["src-a"] },
  // 通信先の根拠を通すための検体。**別々のアクターが別々の検体から同じ IP に届く**
  { key: "ioc.sha256|" + "3".repeat(64), type: "ioc.sha256", value: "3".repeat(64), sources: ["src-b"] },
  { key: "ioc.sha256|" + "4".repeat(64), type: "ioc.sha256", value: "4".repeat(64), sources: ["src-a"] },
  { key: "ioc.url|https://evil.example.com/a", type: "ioc.url", value: "https://evil.example.com/a",
    sources: ["src-a"] },
  // 報告書そのもの。索引は「一緒に出てきた」としか言っておらず、VT も何も言わない。
  // 両アクターが持っていても根拠にはならない（§3.8）
  { key: "ioc.url|https://report.example/writeup/", type: "ioc.url", value: "https://report.example/writeup/",
    sources: ["src-a"] },
];

const LINKS = [
  { ioc: "ioc.domain|c2.example.com", kind: "actor", name: "APT-Test", source: "src-a", rel: "c2" },
  { ioc: "ioc.domain|evil.example.com", kind: "actor", name: "APT-Test", source: "src-a", rel: "c2" },
  { ioc: "ioc.ipv4|45.32.10.7", kind: "actor", name: "APT-Test", source: "src-b", rel: null },
  { ioc: "ioc.ipv4|45.32.10.7", kind: "actor", name: "Other Group", source: "src-b", rel: null },
  { ioc: "ioc.ipv4|45.32.10.8", kind: "actor", name: "Other Group", source: "src-b", rel: null },
  { ioc: "ioc.md5|" + "0".repeat(32), kind: "malware", name: "TestRAT", source: "src-a", rel: "sample" },
  { ioc: "ioc.sha256|" + "1".repeat(64), kind: "malware", name: "TestRAT", source: "src-b", rel: "sample" },
  { ioc: "ioc.sha1|" + "2".repeat(40), kind: "malware", name: "TestRAT", source: "src-a", rel: "sample" },
  { ioc: "ioc.sha256|" + "3".repeat(64), kind: "actor", name: "Other Group", source: "src-b", rel: "sample" },
  { ioc: "ioc.sha256|" + "4".repeat(64), kind: "actor", name: "APT-Test", source: "src-a", rel: "sample" },
  { ioc: "ioc.url|https://report.example/writeup/", kind: "actor", name: "APT-Test", source: "src-a", rel: "観測アクター" },
  { ioc: "ioc.url|https://report.example/writeup/", kind: "actor", name: "Other Group", source: "src-a", rel: "観測アクター" },
  { ioc: "ioc.domain|c2.example.com", kind: "cve", name: "CVE-2026-0001", source: "src-a", rel: "attrs.関連CVE" },
];
const ALIASES = { "APT-Test": ["Test Panda"] };

/** entities と meta は必ず実データから起こす。手で書くと検査の意味が無くなる。 */
function buildFixture(dir) {
  const iocs = [...IOCS].sort((a, b) => (a.type + a.value < b.type + b.value ? -1 : 1));
  const links = [...LINKS].sort((a, b) => {
    const k = (l) => `${l.ioc}\t${l.kind}\t${l.name}\t${l.source}\t${l.rel ?? ""}`;
    return k(a) < k(b) ? -1 : 1;
  });

  const per = new Map();
  for (const l of links) {
    const k = `${l.kind}\t${l.name}`;
    if (!per.has(k)) per.set(k, { iocs: new Set(), sources: new Set() });
    per.get(k).iocs.add(l.ioc);
    per.get(k).sources.add(l.source);
  }
  const entities = [...per].map(([k, v]) => {
    const [kind, name] = k.split("\t");
    return {
      kind, name,
      ioc_count: v.iocs.size,
      sources: [...v.sources].sort(),
      ...(ALIASES[name] ? { aliases: ALIASES[name] } : {}),
    };
  }).sort((a, b) => (a.kind + a.name < b.kind + b.name ? -1 : 1));

  const tally = (rows, pick) => {
    const out = {};
    for (const r of rows) for (const v of [].concat(pick(r))) out[v] = (out[v] || 0) + 1;
    return out;
  };

  writeJsonl(path.join(dir, "iocs.jsonl"), iocs);
  writeJsonl(path.join(dir, "links.jsonl"), links);
  writeJsonl(path.join(dir, "entities.jsonl"), entities);
  buildAsnFixture(dir);
  buildEnrichFixture(dir, iocs, links);
  writeJson(path.join(dir, "meta.json"), {
    tool: "tools/ioc/selftest.mjs",
    schema: 1,
    collected_at: "2026-02-15T00:00:00.000Z",
    week: "2026-W07",
    sources: [
      { app_id: "src-a", name: "検査用 A", search_url: "https://a.example/api/v1/search.json",
        generated_at: null, meta_sha256: "a".repeat(64), search_sha256: "b".repeat(64), entities: 8, error: null },
      { app_id: "src-b", name: "検査用 B", search_url: "https://b.example/api/v1/search.json",
        generated_at: null, meta_sha256: "c".repeat(64), search_sha256: "d".repeat(64), entities: 5, error: null },
    ],
    counts: {
      iocs: iocs.length,
      links: links.length,
      entities: entities.length,
      by_type: tally(iocs, (r) => r.type),
      by_source: tally(iocs, (r) => r.sources),
      by_entity_kind: tally(entities, (e) => e.kind),
      excluded: {
        bogon: iocs.filter((r) => r.bogon).length,
        noise: iocs.filter((r) => r.noise).length,
        malformed: iocs.filter((r) => r.malformed).length,
      },
    },
  });
}

/**
 * AS の付与と同居の一式。enrich-asn.mjs / stats.mjs が出す形に合わせる。
 * 経路表そのものは要らない（validate は写しを見ない）。
 */
function buildAsnFixture(dir) {
  writeJsonl(path.join(dir, "ip-asn.jsonl"), [
    { asn: 64501, hits: 200, ioc: "ioc.ipv4|8.8.8.8", prefix: "8.8.8.0/24" },
    { asn: 64500, hits: 100, ioc: "ioc.ipv4|45.32.10.7", prefix: "45.32.8.0/21" },
    // 生えた IP にも AS を付ける。付けないと「解決先が edge かどうか」が判断できない
    { asn: 64500, hits: 50, ioc: "ioc.ipv4|45.32.11.9", prefix: "45.32.8.0/21" },
    // 通信先として生えた IP。経路が引けないと大きさの守りが素通りする
    { asn: 64500, hits: 40, ioc: "ioc.ipv4|45.32.12.5", prefix: "45.32.8.0/21" },
    // 過去の解決先として生えた IP。経路に無いので根拠には使われない
    { ioc: "ioc.ipv4|45.32.13.7", routed: false },
    { ioc: "ioc.ipv4|45.32.10.8", routed: false },
  ].sort((a, b) => (a.ioc < b.ioc ? -1 : 1)));

  writeJsonl(path.join(dir, "asns.jsonl"), [
    { asn: 64500, cc: "US", iocs: 3, name: "検査用ホスティング", prefixes: 2, addresses: 2048 },
    { asn: 64501, cc: "US", class: "Content", iocs: 1, name: "検査用 DNS", prefixes: 1, addresses: 256 },
  ]);

  writeJson(path.join(dir, "asn-meta.json"), {
    tool: "tools/ioc/enrich-asn.mjs",
    schema: 1,
    source: "bgp.tools",
    table: { url: "https://bgp.tools/table.jsonl", fetched_at: "2026-02-15T00:00:00.000Z",
      bytes: 1234, lines: 3, sha256: "f".repeat(64) },
    asn_names: null,
    table_prefixes: { v4: 3, v6: 0, skipped: 0 },
    counts: { routed: 4, unrouted: 2, skipped: 1, asns: 2 },
  });

}

/**
 * エンリッチの一式。enrich-intel.mjs が出す形に合わせる。
 * 写しそのものは要らない（validate は写しを見ない）。
 *
 * **カバレッジだけは手で書かない。** 分母を手書きすると、分母がずれる壊れ方を
 * 検査できなくなる。本番と同じ coverageOf で起こす。
 */
const CERT = "a".repeat(64);
function buildEnrichFixture(dir, iocs, links) {
  const vt = [
    { ioc: "ioc.domain|c2.example.com", known: true,
      malicious: 5, suspicious: 1, harmless: 60, undetected: 20, reputation: -12,
      analyzed_at: "2026-02-10", created: "2025-12-01", registrar: "検査用レジストラ",
      jarm: "0".repeat(62),
      dns: [{ type: "A", value: "45.32.10.7" }, { type: "A", value: "45.32.11.9" }],
      cert: { thumbprint: CERT, issuer: "検査用 CA", san_count: 2 } },
    { ioc: "ioc.domain|evil.example.com", known: true,
      malicious: 3, suspicious: 0, harmless: 62, undetected: 21,
      cert: { thumbprint: CERT, issuer: "検査用 CA", san_count: 2 } },
    // 正規サービスの混入。検知 0 で人気順位が付くので popular の印が乗る
    { ioc: "ioc.domain|legit.example.com", known: true,
      malicious: 0, suspicious: 0, harmless: 70, undetected: 15, popular: 500 },
    { ioc: "ioc.domain|legit-login.example.net", known: true,
      malicious: 8, suspicious: 0, harmless: 55, undetected: 22 },
    { ioc: "ioc.ipv4|45.32.10.7", known: true,
      malicious: 2, suspicious: 0, harmless: 63, undetected: 21,
      asn: 64500, as_owner: "検査用ホスティング", country: "US", network: "45.32.8.0/21" },
    { ioc: "ioc.md5|" + "0".repeat(32), known: true,
      malicious: 55, suspicious: 2, harmless: 0, undetected: 12,
      label: "trojan.testrat/heur", families: ["testrat"],
      first_submission: "2026-01-02", names: ["invoice.doc"], size: 4096,
      type_description: "Microsoft Word" },
    // VT が知らない＝失敗ではなく結果。判定を入れてはいけない
    { ioc: "ioc.sha1|" + "2".repeat(40), known: true,
      malicious: 40, suspicious: 0, harmless: 0, undetected: 30,
      label: "trojan.newfam/x", families: ["newfam", "othername"],
      first_submission: "2026-01-20" },
    { ioc: "ioc.sha256|" + "1".repeat(64), known: false },
  ].sort((a, b) => (a.ioc < b.ioc ? -1 : 1));

  const abuse = [{
    ioc: "ioc.ipv4|45.32.10.7", score: 84, reports: 12, reporters: 5,
    last_reported_at: "2026-02-12", usage_type: "Data Center/Web Hosting/Transit",
    hosting: true, isp: "検査用ホスティング", country: "US",
    categories: { "ポートスキャン": 8, "総当たり": 4 },
    // 中身無しはあるが、境目（20 件 / 30%）には届かないので印は付かない
    comments: 12, hollow: 2,
  }];

  // c2.example.com の解決先のうち、索引に無かったほうだけが生える
  const derivedIocs = [{
    key: "ioc.ipv4|45.32.11.9", type: "ioc.ipv4", value: "45.32.11.9",
    origin: "vt.dns", from: ["ioc.domain|c2.example.com"], subnet: "45.32.11.0/24",
  }, {
    // 検体の通信先（§3.7）。別々のアクターの検体が同じ IP に届く
    key: "ioc.ipv4|45.32.12.5", type: "ioc.ipv4", value: "45.32.12.5",
    origin: "vt.contacted",
    from: ["ioc.sha256|" + "3".repeat(64), "ioc.sha256|" + "4".repeat(64)].sort(),
    subnet: "45.32.12.0/24",
  }, {
    // 過去の解決先。**日付が付く**のはこの種類だけ
    key: "ioc.ipv4|45.32.13.7", type: "ioc.ipv4", value: "45.32.13.7",
    origin: "vt.resolution", from: ["ioc.domain|evil.example.com"], subnet: "45.32.13.0/24",
  }];
  // testrat は索引の TestRAT に畳まれ、newfam だけが実体として生える
  const derivedEntities = [{ kind: "malware", name: "newfam", ioc_count: 1, sources: ["virustotal"] }];
  const derivedLinks = [
    { ioc: "ioc.domain|c2.example.com", kind: "ioc", name: "ioc.ipv4|45.32.10.7", rel: "resolves_to", source: "virustotal" },
    { ioc: "ioc.domain|c2.example.com", kind: "ioc", name: "ioc.ipv4|45.32.11.9", rel: "resolves_to", source: "virustotal" },
    { ioc: "ioc.md5|" + "0".repeat(32), kind: "malware", name: "TestRAT", rel: "suggested_threat_label", source: "virustotal" },
    { ioc: "ioc.sha1|" + "2".repeat(40), kind: "malware", name: "newfam", rel: "suggested_threat_label", source: "virustotal" },
    { ioc: "ioc.sha256|" + "3".repeat(64), kind: "ioc", name: "ioc.ipv4|45.32.12.5", rel: "contacted", source: "virustotal" },
    { ioc: "ioc.sha256|" + "4".repeat(64), kind: "ioc", name: "ioc.ipv4|45.32.12.5", rel: "contacted", source: "virustotal" },
    { ioc: "ioc.domain|evil.example.com", kind: "ioc", name: "ioc.ipv4|45.32.13.7", rel: "resolved_at", at: "2019-05-04", source: "virustotal" },
  ].sort((a, b) => {
    const k = (l) => `${l.ioc}\t${l.kind}\t${l.name}\t${l.rel}\t${l.source}`;
    return k(a) < k(b) ? -1 : 1;
  });
  /**
   * 生えた IOC に付いた判定（§9.1e）。**索引の判定とは別の入れ物**なので、
   * ここに索引の IOC が来たら検査で落ちる。
   */
  const derivedVerdicts = [{
    ioc: "ioc.ipv4|45.32.12.5", known: true,
    malicious: 3, suspicious: 0, harmless: 60, undetected: 5,
    as_owner: "検査用ホスティング", country: "US",
    abuse_score: 12, abuse_reports: 2, usage_type: "Commercial", isp: "検査用 ISP",
  }];
  const derivedAliases = [{ name: "newfam", aliases: ["othername"], samples: 1, source: "virustotal" }];
  const derivedCerts = [{
    thumbprint: CERT, issuer: "検査用 CA", subject: "evil.example.com",
    san_count: 2, sans: ["c2.example.com", "evil.example.com"],
    iocs: ["ioc.domain|c2.example.com", "ioc.domain|evil.example.com"], shared: true,
  }];

  writeJsonl(path.join(dir, "vt.jsonl"), vt);
  writeJsonl(path.join(dir, "abuseipdb.jsonl"), abuse);
  writeJsonl(path.join(dir, "derived-iocs.jsonl"), derivedIocs);
  writeJsonl(path.join(dir, "derived-entities.jsonl"), derivedEntities);
  writeJsonl(path.join(dir, "derived-links.jsonl"), derivedLinks);
  writeJsonl(path.join(dir, "derived-aliases.jsonl"), derivedAliases);
  writeJsonl(path.join(dir, "derived-verdicts.jsonl"), derivedVerdicts);
  writeJsonl(path.join(dir, "derived-certs.jsonl"), derivedCerts);

  const asnOf = new Map();
  for (const r of readJsonl(path.join(dir, "ip-asn.jsonl"))) if (r.asn) asnOf.set(r.ioc, r.asn);
  writeJson(path.join(dir, "enrich-meta.json"), {
    tool: "tools/ioc/enrich-intel.mjs",
    schema: 1,
    coverage: coverageOf({
      iocs, links, asnOf,
      asnInfo: new Map(readJsonl(path.join(dir, "asns.jsonl")).map((a) => [a.asn, a])),
      vtRows: vt, abuseRows: abuse,
      fetchDays: ["2026-02-14", "2026-02-15"],
    }),
    cache: {
      virustotal: { dir: "data/ioc/.cache/vt", records: vt.length, sha256: "1".repeat(64), projection: 1 },
      abuseipdb: { dir: "data/ioc/.cache/abuseipdb", records: abuse.length, sha256: "2".repeat(64) },
    },
    counts: {
      vt: vt.length, abuseipdb: abuse.length,
      derived_iocs: derivedIocs.length, derived_links: derivedLinks.length,
      derived_entities: derivedEntities.length, derived_aliases: derivedAliases.length,
      derived_certs: derivedCerts.length, shared_certs: 1,
    },
    asn_check: { agree: 1, differ: 0 },
    options: { san_cap: 100, name_cap: 8, include_noise: false },
  });
}

/**
 * 重なり・同居・グラフ・要約は **stats.mjs に作らせる**。
 * 手で書くと、stats.mjs の出し方が変わったときに検査が付いてこない。
 */
function buildStats(dir) {
  execFileSync("node", [path.join(REPO_ROOT, "tools/ioc/stats.mjs"), "--in", dir],
    { encoding: "utf8", stdio: ["ignore", "ignore", "pipe"], cwd: REPO_ROOT });
}

/* ---------------- 壊し方 ---------------- */

const lines = (d, f) => fs.readFileSync(path.join(d, f), "utf8").split("\n");
const putLines = (d, f, L) => fs.writeFileSync(path.join(d, f), L.join("\n"));
const editLine = (d, f, find, fn) => {
  const L = lines(d, f);
  const i = L.findIndex((l) => l.includes(find));
  if (i < 0) throw new Error(`${f} に ${find} を含む行がありません`);
  L[i] = fn(L[i]);
  putLines(d, f, L);
};
const editMeta = (d, fn) => {
  const f = path.join(d, "meta.json");
  const m = JSON.parse(fs.readFileSync(f, "utf8"));
  fn(m);
  fs.writeFileSync(f, JSON.stringify(m, null, 2) + "\n");
};
/** 行を書き戻す。validate は正準形も見るのでキー順を保って書く。 */
const putRow = (row) => JSON.stringify(Object.fromEntries(Object.keys(row).sort().map((k) => [k, row[k]])));

/**
 * 実体名を全ファイルで付け替える。名前の壊れ方を試すとき、辺と実体だけ直しても
 * 同居の一覧が古い名前を指したままになり、狙いと別の規則が鳴ってしまう。
 */
const renameEntity = (d, from, to) => {
  for (const f of ["links.jsonl", "entities.jsonl", "subnets.jsonl", "asn-cotenancy.jsonl",
    "overlaps.jsonl", "derived-links.jsonl", "derived-entities.jsonl", "graph.json", "stats.json"]) {
    const file = path.join(d, f);
    if (!fs.existsSync(file)) continue;
    fs.writeFileSync(file, fs.readFileSync(file, "utf8")
      .split(`"${from}"`).join(`"${to}"`)
      // graph.json の節点は `kind:name` の形で名前を持つ。ここを直さないと
      // 名前の壊れ方ではなく「id が kind:name と違う」で鳴ってしまう
      .split(`:${from}"`).join(`:${to}"`));
  }
};

const CASES = [
  ["hash.length", "SHA-512 を ioc.sha256 として載せる", (d) => {
    editLine(d, "iocs.jsonl", '"ioc.sha256"', (l) => {
      const r = JSON.parse(l);
      r.value = "e".repeat(128);
      r.key = "ioc.sha256|" + r.value;
      return putRow(r);
    });
  }],
  ["hash.charset", "ハッシュに 16 進以外が混じる", (d) => {
    editLine(d, "iocs.jsonl", '"ioc.md5"', (l) => {
      const r = JSON.parse(l);
      r.value = "z".repeat(32);
      r.key = "ioc.md5|" + r.value;
      return putRow(r);
    });
  }],
  ["norm.key", "key が type|value と食い違う", (d) => {
    editLine(d, "iocs.jsonl", "evil.example.com", (l) => l.replace(/"key":"[^"]*"/, '"key":"ioc.domain|wrong.example"'));
  }],
  ["norm.value", "value が正規形でない（大文字のまま）", (d) => {
    editLine(d, "iocs.jsonl", "c2.example.com", (l) => l.replace(/c2\.example\.com/g, "C2.Example.com"));
  }],
  ["norm.refang", "value が defang 表記のまま", (d) => {
    editLine(d, "iocs.jsonl", '"ioc.url"', (l) => {
      const r = JSON.parse(l);
      r.value = "hxxps://evil[.]example[.]com/a";
      r.key = "ioc.url|" + r.value;
      return putRow(r);
    });
  }],
  ["canonical", "キー順を崩す", (d) => {
    editLine(d, "entities.jsonl", "APT-Test", (l) => {
      const r = JSON.parse(l);
      return JSON.stringify({ name: r.name, ...r });
    });
  }],
  ["order", "行の並びを入れ替える", (d) => {
    const L = lines(d, "iocs.jsonl");
    [L[0], L[2]] = [L[2], L[0]];
    putLines(d, "iocs.jsonl", L);
  }],
  ["duplicate", "同じ IOC を 2 行入れる", (d) => {
    const L = lines(d, "iocs.jsonl");
    L.splice(1, 0, L[0]);
    putLines(d, "iocs.jsonl", L);
  }],
  ["field.unknown", "知らない欄が増える", (d) => {
    editLine(d, "iocs.jsonl", '"ioc.md5"', (l) => {
      const r = JSON.parse(l);
      r.enriched = true;
      return putRow(r);
    });
  }],
  ["ipv4.subnet", "/24 が値と合っていない", (d) => {
    editLine(d, "iocs.jsonl", "45.32.10.7", (l) => l.replace(/"subnet":"[^"]*"/, '"subnet":"10.0.0.0/24"'));
  }],
  ["ipv4.bogon", "bogon の印が落ちている", (d) => {
    editLine(d, "iocs.jsonl", "203.0.113.5", (l) => l.replace(/"bogon":true,/, ""));
  }],
  ["ipv4.noise", "noise の印が落ちている", (d) => {
    editLine(d, "iocs.jsonl", "8.8.8.8", (l) => l.replace(/,"noise":"[^"]*"/, ""));
  }],
  ["domain.registrable", "登録可能ドメインが違う", (d) => {
    editLine(d, "iocs.jsonl", "evil.example.com", (l) => l.replace(/"registrable":"[^"]*"/, '"registrable":"other.test"'));
  }],
  ["date.range", "観測日の前後が逆", (d) => {
    editLine(d, "iocs.jsonl", "observed_first", (l) => l.replace(/"observed_first":"[^"]*"/, '"observed_first":"2026-12-31"'));
  }],
  ["date.invalid", "存在しない日付", (d) => {
    editLine(d, "iocs.jsonl", "observed_first", (l) => l.replace(/"observed_first":"[^"]*"/, '"observed_first":"2026-02-30"'));
  }],
  ["link.ioc", "辺が存在しない IOC を指す", (d) => {
    editLine(d, "links.jsonl", '"actor"', (l) => l.replace(/"ioc":"[^"]*"/, '"ioc":"ioc.ipv4|198.51.100.9"'));
  }],
  ["link.entity", "辺の実体が entities に無い", (d) => {
    editLine(d, "links.jsonl", "TestRAT", (l) => l.replace(/"name":"TestRAT"/, '"name":"GhostRAT"'));
  }],
  ["link.cve", "CVE の形をしていない", (d) => {
    editLine(d, "links.jsonl", "CVE-2026-0001", (l) => l.replace(/"name":"[^"]*"/, '"name":"CVE2026"'));
  }],
  ["entity.count", "ioc_count が辺と合わない", (d) => {
    editLine(d, "entities.jsonl", "APT-Test", (l) => l.replace(/"ioc_count":\d+/, '"ioc_count":99'));
  }],
  ["entity.sources", "sources が辺と合わない", (d) => {
    editLine(d, "entities.jsonl", "TestRAT", (l) => l.replace(/"sources":\[[^\]]*\]/, '"sources":["src-a"]'));
  }],
  ["entity.orphan", "どの辺からも参照されない実体", (d) => {
    const L = lines(d, "entities.jsonl").filter((l) => l.trim());
    L.push(JSON.stringify({ ioc_count: 0, kind: "malware", name: "Zombie", sources: ["src-a"] }), "");
    putLines(d, "entities.jsonl", L);
  }],
  ["entity.alias_self", "別名が代表名と同じ", (d) => {
    editLine(d, "entities.jsonl", "APT-Test", (l) => l.replace(/"aliases":\[[^\]]*\]/, '"aliases":["apt test"]'));
  }],
  ["entity.alias_comma", "別名が分けられていない", (d) => {
    editLine(d, "entities.jsonl", "APT-Test", (l) => l.replace(/"aliases":\[[^\]]*\]/, '"aliases":["Test Panda, Test Bear"]'));
  }, "warn"],
  ["entity.tooshort", "区切りで切れた断片が実体になっている", (d) => {
    renameEntity(d, "Other Group", "A");
  }],
  ["entity.qualifier", "但し書きが実体として残っている", (d) => {
    renameEntity(d, "Other Group", "medium-to-high confidence");
  }, "warn"],
  ["entity.parens", "括弧が閉じていない名前", (d) => {
    renameEntity(d, "Other Group", "Other Group (OG");
  }, "warn"],
  ["meta.count", "meta の件数が実データとずれる", (d) => {
    editMeta(d, (m) => { m.counts.iocs = 1; });
  }],
  ["meta.count", "meta の型別内訳がずれる", (d) => {
    editMeta(d, (m) => { m.counts.by_type["ioc.md5"] = 42; });
  }],
  ["meta.source_error", "取得に失敗した索引がある", (d) => {
    editMeta(d, (m) => { m.sources[0].error = "HTTP 503"; });
  }],
  ["meta.source_missing", "IOC の出典が meta に無い", (d) => {
    editMeta(d, (m) => { m.sources = m.sources.filter((s) => s.app_id !== "src-b"); });
  }],
  ["ipasn.prefix", "prefix が値を含んでいない", (d) => {
    editLine(d, "ip-asn.jsonl", "45.32.10.7", (l) => l.replace(/"prefix":"[^"]*"/, '"prefix":"10.0.0.0/8"'));
  }],
  ["ipasn.prefix", "prefix に網以外のビットが残っている", (d) => {
    editLine(d, "ip-asn.jsonl", "45.32.10.7", (l) => l.replace(/"prefix":"[^"]*"/, '"prefix":"45.32.10.7/21"'));
  }],
  ["ipasn.ioc", "AS が存在しない IOC に付いている", (d) => {
    editLine(d, "ip-asn.jsonl", "8.8.8.8", (l) => l.replace(/"ioc":"[^"]*"/, '"ioc":"ioc.ipv4|1.2.3.4"'));
  }],
  ["ipasn.type", "IP でない IOC に AS が付いている", (d) => {
    editLine(d, "ip-asn.jsonl", "8.8.8.8", (l) => l.replace(/"ioc":"[^"]*"/, '"ioc":"ioc.domain|c2.example.com"'));
  }],
  ["ipasn.routed", "routed:false なのに AS が入っている", (d) => {
    editLine(d, "ip-asn.jsonl", "routed", (l) => {
      const r = JSON.parse(l);
      r.asn = 64500;
      return putRow(r);
    });
  }],
  ["ipasn.unknown", "asns.jsonl に無い AS を指している", (d) => {
    editLine(d, "ip-asn.jsonl", "8.8.8.8", (l) => l.replace(/"asn":\d+/, '"asn":64999'));
  }],
  ["asn.count", "AS ごとの IOC 数が合わない", (d) => {
    editLine(d, "asns.jsonl", "64500", (l) => l.replace(/"iocs":\d+/, '"iocs":7'));
  }],
  ["asn.size", "prefixes と addresses が食い違う", (d) => {
    editLine(d, "asns.jsonl", "64500", (l) => l.replace(/"addresses":\d+/, '"addresses":0'));
  }],
  ["asnmeta.sha", "経路表のハッシュが無い", (d) => {
    const f = path.join(d, "asn-meta.json");
    const m = JSON.parse(fs.readFileSync(f, "utf8"));
    delete m.table.sha256;
    fs.writeFileSync(f, JSON.stringify(m, null, 2) + "\n");
  }],
  ["asnmeta.count", "経路ありの件数がずれる", (d) => {
    const f = path.join(d, "asn-meta.json");
    const m = JSON.parse(fs.readFileSync(f, "utf8"));
    m.counts.routed = 99;
    fs.writeFileSync(f, JSON.stringify(m, null, 2) + "\n");
  }],
  ["cotenancy.entity", "同居に知らない実体が入っている", (d) => {
    editLine(d, "subnets.jsonl", "45.32.10.0/24", (l) => l.replace(/"APT-Test"/, '"Ghost Actor"'));
  }],
  ["cotenancy.subnet", "/24 の形をしていない", (d) => {
    editLine(d, "subnets.jsonl", "45.32.10.0/24", (l) => l.replace("45.32.10.0/24", "45.32.10.7/24"));
  }],
  ["cotenancy.asn", "同居が asns.jsonl に無い AS を指す", (d) => {
    editLine(d, "asn-cotenancy.jsonl", "64500", (l) => l.replace(/"asn":\d+/, '"asn":64999'));
  }],
  ["file.missing", "ファイルが欠けている", (d) => {
    fs.rmSync(path.join(d, "entities.jsonl"));
  }],
  ["file.missing", "AS はあるのに asn-meta.json が無い", (d) => {
    fs.rmSync(path.join(d, "asn-meta.json"));
  }],
  ["json.parse", "JSON として壊れている", (d) => {
    editLine(d, "iocs.jsonl", "evil.example.com", (l) => l.slice(0, -3));
  }],

  /* ---- エンリッチ（VirusTotal / AbuseIPDB） ---- */

  ["vt.unknown", "VT が知らない IOC に判定が入っている", (d) => {
    // known:false は「調べたが無かった」。判定が入っていたら組み立てが崩れている
    editLine(d, "vt.jsonl", '"known":false', (l) => {
      const r = JSON.parse(l);
      r.malicious = 12;
      return putRow(r);
    });
  }],
  ["vt.ioc", "判定が存在しない IOC を指す", (d) => {
    editLine(d, "vt.jsonl", "ioc.domain|c2.example.com", (l) => l.replace("c2.example.com", "ghost.example.com"));
  }],
  ["vt.stats", "検知数が負になっている", (d) => {
    editLine(d, "vt.jsonl", "ioc.md5", (l) => l.replace(/"malicious":\d+/, '"malicious":-1'));
  }],
  ["vt.cert", "判定が derived-certs.jsonl に無い証明書を指す", (d) => {
    editLine(d, "vt.jsonl", "ioc.domain|evil.example.com", (l) => l.replace(CERT, "b".repeat(64)));
  }],
  ["field.missing", "検知の内訳が欠けている", (d) => {
    editLine(d, "vt.jsonl", "ioc.ipv4|45.32.10.7", (l) => {
      const r = JSON.parse(l);
      delete r.undetected;
      return putRow(r);
    });
  }],
  ["abuse.score", "スコアが 0〜100 の外に出る", (d) => {
    editLine(d, "abuseipdb.jsonl", "45.32.10.7", (l) => l.replace(/"score":\d+/, '"score":101'));
  }],
  ["abuse.count", "通報者が通報数を上回る", (d) => {
    editLine(d, "abuseipdb.jsonl", "45.32.10.7", (l) => l.replace(/"reporters":\d+/, '"reporters":99'));
  }],
  ["abuse.type", "IP でない IOC に通報状況が付く", (d) => {
    editLine(d, "abuseipdb.jsonl", "45.32.10.7", (l) => l.replace("ioc.ipv4|45.32.10.7", "ioc.domain|c2.example.com"));
  }],
  ["target.popular", "騙られた先に正規サービスの印が無い", (d) => {
    editLine(d, "targets.jsonl", "legit-login", (l) => l.replace(/"target":"[^"]*"/, '"target":"ghost.example.org"'));
  }],
  ["target.kind", "標的の種別が不正", (d) => {
    editLine(d, "targets.jsonl", "legit-login", (l) => l.replace(/"kind":"[^"]*"/, '"kind":"typo"'));
  }],
  ["vt.popular", "正規サービスの順位が 1 以上の整数でない", (d) => {
    editLine(d, "vt.jsonl", "legit.example.com", (l) => l.replace('"popular":500', '"popular":0'));
  }],
  ["vt.popular", "検知が付いているのに正規サービスの印が残る", (d) => {
    editLine(d, "vt.jsonl", "legit.example.com", (l) => l.replace('"malicious":0', '"malicious":9'));
  }],
  ["abuse.hollow", "中身無しの数が分母を超える", (d) => {
    editLine(d, "abuseipdb.jsonl", "45.32.10.7", (l) => l.replace('"hollow":2', '"hollow":13'));
  }],
  ["abuse.hollow", "判定に使った分母が残っていない", (d) => {
    editLine(d, "abuseipdb.jsonl", "45.32.10.7", (l) => l.replace('"comments":12,', ""));
  }],
  ["abuse.sample", "境目を超えているのに見本アドレスの印が無い", (d) => {
    // 鍵は並べ替えて書いているので、この 2 つは隣り合っていない
    editLine(d, "abuseipdb.jsonl", "45.32.10.7",
      (l) => l.replace('"comments":12', '"comments":40').replace('"hollow":2', '"hollow":30'));
  }],
  ["abuse.sample", "境目に届いていないのに見本アドレスの印が付く", (d) => {
    editLine(d, "abuseipdb.jsonl", "45.32.10.7", (l) => l.replace('"hollow":2', '"hollow":2,"sample":true'));
  }],
  ["derived.duplicate", "生えた IOC が索引の IOC と重複する", (d) => {
    // 重複したら索引側を優先する。混ざると「これはどこの主張か」が追えなくなる
    editLine(d, "derived-iocs.jsonl", "45.32.11.9", (l) =>
      l.replace(/45\.32\.11\.9/g, "45.32.10.8").replace("45.32.11.0/24", "45.32.10.0/24"));
  }],
  ["derived.from", "生えた IOC の出どころが存在しない", (d) => {
    editLine(d, "derived-iocs.jsonl", "45.32.11.9", (l) => l.replace("c2.example.com", "ghost.example.com"));
  }],
  ["derived.origin", "生えた IOC の出どころが知らない値", (d) => {
    editLine(d, "derived-iocs.jsonl", "45.32.11.9", (l) => l.replace('"vt.dns"', '"guess"'));
  }],
  // 関係から起こした IP（§3.7）。**種類ごとに別の入れ物**なので配線違いを見る
  ["date.format", "過去の解決先の日付が壊れている", (d) => {
    editLine(d, "derived-links.jsonl", "resolved_at", (l) => l.replace('"2019-05-04"', '"2019-5-4"'));
  }],
  ["derived.link_at", "通信先の辺に解決日が付いている", (d) => {
    // 日付が付くのは過去の解決先だけ。通信先に日付は無い
    editLine(d, "derived-links.jsonl", '"contacted"', (l) => {
      const r = JSON.parse(l);
      r.at = "2020-01-01";
      return putRow(r);
    });
  }],
  ["derived.from", "生えた IOC の from が辺と合わない", (d) => {
    editLine(d, "derived-iocs.jsonl", "45.32.12.5", (l) => {
      const r = JSON.parse(l);
      r.from = r.from.slice(0, 1);
      return putRow(r);
    });
  }],
  ["derived.origin", "生えた IOC の出どころが辺と食い違う", (d) => {
    // 通信先からしか来ていないのに「現在の解決先」を名乗る
    editLine(d, "derived-iocs.jsonl", "45.32.12.5", (l) => l.replace('"vt.contacted"', '"vt.dns"'));
  }],
  ["overlap.evidence", "通信先の根拠が辺に出てこない", (d) => {
    // 解決先と通信先は形が同じ。配線を取り違えると検算のできない根拠になる
    editLine(d, "overlaps.jsonl", '"kind":"actor"', (l) => {
      const r = JSON.parse(l);
      r.evidence = { ...r.evidence, contacted: ["ioc.ipv4|45.32.10.7"] };
      return putRow(r);
    });
  }],
  // 守りを通った IP の一覧（§3.7）と、生えた IOC の判定（§9.1e）
  ["relation.derived", "索引の IOC なのに派生の印が付く", (d) => {
    editLine(d, "relation-ips.jsonl", "45.32.12.5", (l) => l.replace('"derived":true', '"derived":false'));
  }],
  ["relation.from", "届く元に自分自身が入っている", (d) => {
    editLine(d, "relation-ips.jsonl", "45.32.12.5", (l) => {
      const r = JSON.parse(l);
      r.from = [...r.from, r.ioc].sort();
      return putRow(r);
    });
  }],
  ["overlap.evidence", "根拠が守りを通った一覧に無い", (d) => {
    // 守りを通していない値が根拠に出たら、絞り込みを迂回している
    editLine(d, "relation-ips.jsonl", "45.32.12.5", (l) =>
      l.replace(/45\.32\.12\.5/g, "45.32.12.9"));
  }],
  ["verdict.index", "索引の IOC の判定が混じる", (d) => {
    // 混ぜるとカバレッジの分子だけが増えて 100% を超える
    editLine(d, "derived-verdicts.jsonl", "45.32.12.5", (l) =>
      l.replace("45.32.12.5", "45.32.10.7"));
  }],
  ["verdict.hosting", "事業者の網の印が usage_type と食い違う", (d) => {
    editLine(d, "derived-verdicts.jsonl", "45.32.12.5", (l) => {
      const r = JSON.parse(l);
      r.hosting = true;
      return putRow(r);
    });
  }],
  ["verdict.unknown", "VT が知らないのに検知数が入っている", (d) => {
    editLine(d, "derived-verdicts.jsonl", "45.32.12.5", (l) =>
      l.replace('"known":true', '"known":false'));
  }],
  ["overlap.asserted", "役割も検知も無い IOC が根拠になっている", (d) => {
    // 研究報告の URL や被害組織のサイトが実体を繋いでしまう形（§3.8）
    editLine(d, "overlaps.jsonl", '"kind":"actor"', (l) => {
      const r = JSON.parse(l);
      r.evidence = { ...r.evidence, ioc: [...r.evidence.ioc, "ioc.url|https://report.example/writeup/"].sort() };
      return putRow(r);
    });
  }],
  ["derived.link_entity", "生えた辺が知らない実体を指す", (d) => {
    editLine(d, "derived-links.jsonl", "suggested_threat_label", (l) => l.replace('"TestRAT"', '"GhostFam"'));
  }],
  ["derived.link_target", "生えた辺の相手が存在しない", (d) => {
    editLine(d, "derived-links.jsonl", "resolves_to", (l) => l.replace("ioc.ipv4|45.32.10.7", "ioc.ipv4|45.32.99.99"));
  }],
  ["derived.entity_count", "生えた実体の ioc_count がずれる", (d) => {
    editLine(d, "derived-entities.jsonl", "newfam", (l) => l.replace(/"ioc_count":\d+/, '"ioc_count":7'));
  }],
  ["derived.entity_dup", "畳めるはずの実体が生えている", (d) => {
    // 索引に同じ名前があるのに生やしたら、正規化した意味が無くなる
    editLine(d, "derived-entities.jsonl", "newfam", (l) => l.replace('"newfam"', '"TestRAT"'));
    editLine(d, "derived-links.jsonl", '"newfam"', (l) => l.replace('"newfam"', '"TestRAT"'));
  }],
  ["derived.alias_self", "別名に自分自身が入っている", (d) => {
    editLine(d, "derived-aliases.jsonl", "newfam", (l) => l.replace('["othername"]', '["newfam"]'));
  }],
  ["cert.shared", "shared が IOC の数と食い違う", (d) => {
    editLine(d, "derived-certs.jsonl", CERT, (l) => l.replace('"shared":true', '"shared":false'));
  }],
  ["cert.ioc", "証明書が存在しない IOC を指す", (d) => {
    editLine(d, "derived-certs.jsonl", CERT, (l) => l.replace("ioc.domain|c2.example.com", "ioc.domain|ghost.example.com"));
  }],
  ["overlap.strength", "根拠の強さがずれる", (d) => {
    editLine(d, "overlaps.jsonl", '"kind":"actor"', (l) => l.replace(/"strength":\d+/, '"strength":99'));
  }],
  ["overlap.evidence", "根拠の値が残っていない", (d) => {
    // 「証明書で繋がっている」と言われても、どの証明書かが無ければ検算できない
    editLine(d, "overlaps.jsonl", '"kind":"actor"', (l) => {
      const r = JSON.parse(l);
      delete r.evidence;
      return putRow(r);
    });
  }],
  ["overlap.evidence", "via に無い根拠が混じる", (d) => {
    editLine(d, "overlaps.jsonl", '"kind":"actor"', (l) => {
      const r = JSON.parse(l);
      r.evidence = { ...r.evidence, certificate: ["a".repeat(64)] };
      return putRow(r);
    });
  }],
  ["overlap.weak", "強い根拠があるのに weak_only が付く", (d) => {
    editLine(d, "overlaps.jsonl", '"kind":"actor"', (l) => {
      const r = JSON.parse(l);
      r.weak_only = true;
      return putRow(r);
    });
  }],
  // IOC 集合が一致した組。**片方に出したつもりで両方に残ると、外したはずの組が上位に戻る**
  ["identical.both", "重なりと集合一致の両方に出ている", (d) => {
    const o = JSON.parse(fs.readFileSync(path.join(d, "overlaps.jsonl"), "utf8").trim().split("\n")[0]);
    fs.writeFileSync(path.join(d, "identical-sets.jsonl"),
      `${putRow({ kind: o.kind, a: o.a, b: o.b, iocs: 1 })}\n`);
  }],
  ["identical.entity", "集合一致の相手が実体一覧に無い", (d) => {
    fs.writeFileSync(path.join(d, "identical-sets.jsonl"),
      `${putRow({ kind: "actor", a: "APT-Test", b: "Ghost Group", iocs: 1 })}\n`);
  }],
  ["identical.iocs", "集合一致の数が実体の IOC 数を上回る", (d) => {
    fs.writeFileSync(path.join(d, "identical-sets.jsonl"),
      `${putRow({ kind: "actor", a: "APT-Test", b: "Other Group", iocs: 999 })}\n`);
  }],
  ["enrichmeta.sha", "写しのハッシュが無い", (d) => {
    const f = path.join(d, "enrich-meta.json");
    const m = JSON.parse(fs.readFileSync(f, "utf8"));
    delete m.cache.virustotal.sha256;
    fs.writeFileSync(f, JSON.stringify(m, null, 2) + "\n");
  }],
  ["coverage.count", "カバレッジの分母がずれる", (d) => {
    // 「調べた範囲の 12%」を「検知されたのは 12%」として読ませないための検査
    const f = path.join(d, "enrich-meta.json");
    const m = JSON.parse(fs.readFileSync(f, "utf8"));
    m.coverage.virustotal.target = 3;
    fs.writeFileSync(f, JSON.stringify(m, null, 2) + "\n");
  }],
  ["coverage.count", "カバレッジの分子がずれる", (d) => {
    const f = path.join(d, "stats.json");
    const m = JSON.parse(fs.readFileSync(f, "utf8"));
    m.coverage.abuseipdb.done = 99;
    fs.writeFileSync(f, JSON.stringify(m, null, 2) + "\n");
  }],
  ["coverage.missing", "統計に分母が入っていない", (d) => {
    const f = path.join(d, "stats.json");
    const m = JSON.parse(fs.readFileSync(f, "utf8"));
    delete m.coverage;
    fs.writeFileSync(f, JSON.stringify(m, null, 2) + "\n");
  }],
  ["file.missing", "判定はあるのに enrich-meta.json が無い", (d) => {
    fs.rmSync(path.join(d, "enrich-meta.json"));
  }],
];

/* ---------------- 実行 ---------------- */

function run(dir, extra = []) {
  try {
    const out = execFileSync("node", [path.join(REPO_ROOT, "tools/ioc/validate.mjs"), "--in", dir, "--samples", "1", ...extra],
      { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], cwd: REPO_ROOT });
    return { code: 0, out };
  } catch (e) {
    return { code: e.status ?? 1, out: (e.stderr || "") + (e.stdout || "") };
  }
}

const root = fs.mkdtempSync(path.join(os.tmpdir(), "ioc-selftest-"));
let failed = 0;
const check = (ok, label, detail = "") => {
  console.log(`${ok ? "  ok  " : "  NG  "}${label}${detail ? `  ${detail}` : ""}`);
  if (!ok) failed++;
};

try {
  /* 1. 正しい一式は素通りすること。これが落ちると以降の判定が意味を持たない */
  const base = path.join(root, "base");
  buildFixture(base);
  buildStats(base);
  const clean = run(base, ["--strict"]);
  check(clean.code === 0, "正しい一式が素通りする", clean.code === 0 ? "" : clean.out.split("\n").slice(0, 4).join(" / "));

  /* 2. 壊し方ごとに、狙った規則が鳴ること */
  console.log(`\n壊し方 ${CASES.length} 通り`);
  for (const [rule, label, breakIt, severity = "error"] of CASES) {
    const dir = path.join(root, rule.replace(/\W/g, "_") + "-" + label.length);
    fs.cpSync(base, dir, { recursive: true });
    breakIt(dir);
    // warn は既定では終了コード 0 なので --strict で失敗させる
    const r = run(dir, severity === "warn" ? ["--strict"] : []);
    const mark = severity === "error" ? "×" : "!";
    const hit = r.out.includes(`${mark} ${rule} `);
    check(r.code === 1 && hit, `${rule.padEnd(22)} ${label}`,
      r.code !== 1 ? "見逃した" : hit ? "" : "別の規則で鳴った");
  }

  /* 3. warn だけなら既定では通り、--strict でだけ落ちること */
  const warnDir = path.join(root, "warn-only");
  fs.cpSync(base, warnDir, { recursive: true });
  CASES.find(([r]) => r === "entity.parens")[2](warnDir);
  console.log("");
  check(run(warnDir).code === 0, "warn だけなら既定は通る");
  check(run(warnDir, ["--strict"]).code === 1, "--strict なら warn でも落ちる");
} finally {
  if (KEEP) console.log(`\n作業場所を残しました: ${root}`);
  else fs.rmSync(root, { recursive: true, force: true });
}

console.log(failed ? `\n${failed} 件失敗` : "\nすべて通りました");
process.exit(failed ? 1 : 0);
