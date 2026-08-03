#!/usr/bin/env node
// VirusTotal / AbuseIPDB の写しから判定を起こし、そこから **新しい実体と辺を生やす**。
// 外部呼び出しなし（写しだけを見る）。
//
//   node tools/ioc/enrich-intel.mjs [--in data/ioc/latest] [--out <同じ場所>]
//                                   [--vt-cache data/ioc/.cache/vt]
//                                   [--abuse-cache data/ioc/.cache/abuseipdb]
//                                   [--san-cap 100] [--name-cap 8] [--serial-min 3]
//                                   [--include-noise]
//
// 先に fetch-vt.mjs / fetch-abuseipdb.mjs で写しを作っておくこと。
// **同じ写しからは何度でも同じ結果が出る**（fetch-asn / enrich-asn と同じ分け方）。
//
// エンリッチの価値は判定そのものより、知らなかった実体と辺が生えることにある
// （docs/ioc-enrich-plan.md §2）。効く順に 3 つ。
//   1. マルウェア名の正規化   suggested_threat_label でファミリを畳む
//   2. ドメイン → IP の辺     last_dns_records の A / AAAA
//   3. 証明書の共有           thumbprint の一致。最も強いインフラ共有の証拠
//
// **元のファイルは汚さない。** 生えたものは derived-*.jsonl に分ける。索引が主張した
// IOC と、そこから導いた IOC を混ぜると「これはどこの主張か」が追えなくなる。
//
// 出力
//   vt.jsonl            IOC ごとの VT 判定。VT が知らないものは known:false（結果として残す）
//   abuseipdb.jsonl     IP ごとの通報状況。**通報数ではなく信頼度スコアで判断する**
//                       ただしスコアも万能ではない。中身の無い通報が積み上がって
//                       高スコアになる見本アドレスがあるので sample の印を付ける
//   derived-iocs.jsonl  写しから生えた IOC（今は DNS の解決先）
//   derived-links.jsonl 生えた辺（ファミリ・解決先）
//   derived-entities.jsonl 生えた実体（VT のファミリ名のうち索引に無かったもの）
//   derived-aliases.jsonl  ファミリの別名候補
//   derived-certs.jsonl 証明書ごとの IOC のまとまり
//   enrich-meta.json    カバレッジ・写しのハッシュ・取得の期間（時刻はここにだけ置く）

import path from "node:path";
import { byKeys, parseArgs, readJsonl, writeJson, writeJsonl } from "./lib/io.mjs";
import { classifyIpv4, classifyIpv6, subnet24 } from "./lib/net.mjs";
import { PROJECTION, coverageOf, digestRecords, readAllRecords } from "./lib/enrich.mjs";
import { REPO_ROOT } from "./lib/sources.mjs";

const args = parseArgs(process.argv.slice(2));
const IN = path.resolve(REPO_ROOT, args.in || "data/ioc/latest");
const OUT = path.resolve(REPO_ROOT, args.out || args.in || "data/ioc/latest");
const VT_CACHE = path.resolve(REPO_ROOT, args["vt-cache"] || "data/ioc/.cache/vt");
const ABUSE_CACHE = path.resolve(REPO_ROOT, args["abuse-cache"] || "data/ioc/.cache/abuseipdb");
const INCLUDE_NOISE = !!args["include-noise"];
/** SAN がこれを超える証明書は共用ホスティング。根拠にしない（/24 や AS と同じ考え方） */
const SAN_CAP = Number(args["san-cap"] || 100);
/** ファイル名を残す上限。1 件が何百も名前を持つことがある */
const NAME_CAP = Number(args["name-cap"] || 8);
/**
 * 「見本アドレス」を通報の中身から見つけるための境目（§2.8）。
 * 大勢が通報しているのに中身の無いコメントばかり、という組み合わせだけを見る。
 * 通報が 1〜2 件しか無い IP は中身無し率が 100% でも珍しくないので、
 * 件数の下限を置かないと大量に誤って印が付く。
 */
const SAMPLE_MIN = Number(args["sample-min"] || 20);
const SAMPLE_RATIO = Number(args["sample-ratio"] || 0.3);

const iocs = readJsonl(path.join(IN, "iocs.jsonl"));
if (!iocs.length) {
  console.error(`${IN} に iocs.jsonl がありません。先に collect.mjs を実行してください。`);
  process.exit(1);
}
const links = readJsonl(path.join(IN, "links.jsonl"));
const entities = readJsonl(path.join(IN, "entities.jsonl"));
const iocByKey = new Map(iocs.map((r) => [r.key, r]));

const vtRecords = readAllRecords(VT_CACHE);
const abuseRecords = readAllRecords(ABUSE_CACHE);
if (!vtRecords.length && !abuseRecords.length) {
  console.error([
    "写しがありません。先に取得してください。",
    '  VT_API_KEYS="…" node tools/ioc/fetch-vt.mjs',
    '  ABUSEIPDB_API_KEY="…" node tools/ioc/fetch-abuseipdb.mjs',
  ].join("\n"));
  process.exit(1);
}

/* ---------------- 日付と数の整え ---------------- */

/** UNIX 秒 → YYYY-MM-DD。時刻まで残しても使い道が無く、差分を無駄に動かす。 */
const day = (sec) => (Number.isFinite(sec) && sec > 0 ? new Date(sec * 1000).toISOString().slice(0, 10) : undefined);
const dayOf = (iso) => (typeof iso === "string" && iso.length >= 10 ? iso.slice(0, 10) : undefined);
const int = (v) => (Number.isFinite(v) ? Math.trunc(v) : undefined);

/* ---------------- 1. VT の判定 ---------------- */

/**
 * ファミリ名として意味を持たない語。**畳んだ先がこれになったら畳まない**。
 * `trojan.generic` を実体にすると、無関係な検体が 1 つの塊になってしまう。
 */
const GENERIC = new Set([
  "generic", "genericml", "gen", "malware", "malicious", "suspicious", "unknown",
  "heuristic", "heur", "trojan", "agent", "application", "riskware", "adware",
  "downloader", "dropper", "injector", "packed", "obfuscated", "cryptor", "crypt",
  "ransom", "ransomware", "virus", "worm", "backdoor", "spyware", "keylogger",
  "exploit", "script", "hacktool", "pua", "pup", "unwanted", "test", "eicar",
  "none", "undefined", "misc", "other", "variant", "trojandownloader", "trojandropper",
  "msil", "win32", "win64", "html", "vbs", "js", "ps1", "office", "macro", "encoded",
  // 手口や種別であって、ファミリ名ではないもの。実測で根拠に紛れ込んでいた
  "stealer", "shellcode", "dllhijack", "loader", "miner", "coinminer", "cryptominer",
  "banker", "clipbanker", "rootkit", "rat", "proxy", "tool", "patched", "fake",
  "fakeapp", "install", "installer", "bundler", "runner", "inject", "autorun",
  "phishing", "spam", "toolbar", "startpage", "webtoolbar", "abapplication",
  // 提供元ごとの「よく分からないが悪い」ラベル。ファミリのふりをするので厄介。
  // astraea は Kaspersky の機械学習エンジンの名前で、**検出器の名前**であって
  // ファミリではない。実測で Bohrium ↔ DragonForce を繋いでいた
  "astraea", "graftor", "gencirc", "convagent", "kryptik", "genkryptik", "zusy",
  "razy", "barys", "symmi", "midie", "wacatac", "occamy", "presenoker", "fugrafa",
  "bsymem", "ulise", "noon", "tedy", "strictor", "sivis", "malgent", "multi",
  // mikey は 4 検体に付いていたが、変種が dynamer / etset / pswdump と全部違い、
  // JS・DLL・OCX と種別も違った。APT28 ↔ Silver Fox を繋いでいたが根拠にならない
  "mikey",
]);

/**
 * 提供元の「連番の変種」。`agent` + 1〜2 文字は Kaspersky の Agent.a / Agent.b で、
 * 中身は何でもよい。実測で `agentb` が 6 実体に付き、Lazarus Group と Silver Fox を
 * 繋いでいた。**AgentTesla のような実在のファミリは残す**（後ろが 2 文字より長い）。
 */
const looksVariant = (name) =>
  /^agent[a-z0-9]{0,2}$/.test(name) ||
  /^gen[a-z0-9]{0,2}$/.test(name) ||
  // `ag1536201` `cve20151641` のような、短い頭文字＋長い数字。人が付けた名前ではない
  /^[a-z]{1,3}\d{3,}$/.test(name) ||
  // `generickdq` のような「generic + 検出器の連番」
  /^generic/.test(name) ||
  // `grhh` `kqil` `vsnw09g25` のような、母音の無い機械生成の札。人が付けた名前ではない
  !/[aeiou]/.test(name);

/** `trojan.emotet/heur` → `emotet`。畳めなければ null。 */
function familyOf(label) {
  const head = String(label || "").split("/")[0].trim().toLowerCase();
  if (!head) return null;
  const dot = head.indexOf(".");
  const name = (dot >= 0 ? head.slice(dot + 1) : head).replace(/[^a-z0-9._-]/g, "");
  const k = name.replace(/[^a-z0-9]/g, "");
  if (!k || GENERIC.has(k) || looksVariant(k)) return null;
  return name;
}

/**
 * 中身と関係のないファイル名。**置き名と自動命名**は結び付きの根拠にならない。
 *
 * 実測で `payload.bin` が APT28（Sednit）と Silver Fox（Atlas RAT）を繋いでいた。
 * 解析者やサンドボックスが付ける名前で、同じ名前でも同じ物とは限らない。
 * ハッシュそのものを名前にしているものも同じ（`6922b319….exe` は VT の自動命名）。
 */
const PLACEHOLDER = new Set([
  "payload.bin", "payload.exe", "payload.dll", "payload", "stage1.bin", "stage2.bin",
  "sample.exe", "sample.bin", "sample", "malware.exe", "malware.bin", "virus.exe",
  "file.exe", "file.bin", "file", "test.exe", "tmp.exe", "temp.exe", "output.exe",
  "a.exe", "b.exe", "1.exe", "2.exe", "x.exe", "new.exe", "dropped.exe", "binary.bin",
  "setup.exe", "install.exe", "installer.exe", "update.exe", "updater.exe", "main.exe",
  "app.exe", "program.exe", "document.doc", "invoice.doc", "unknown", "noname",
  "svchost.exe", "explorer.exe", "rundll32.exe", "cmd.exe", "powershell.exe",
  "regsvr32.exe", "msiexec.exe", "wscript.exe", "cscript.exe", "mshta.exe",
]);
const placeholderName = (v) => {
  const k = v.toLowerCase();
  if (PLACEHOLDER.has(k)) return true;
  // ハッシュそのもの（拡張子の有無は問わない）
  if (/^[0-9a-f]{16,}(\.[a-z0-9]{1,5})?$/.test(k)) return true;
  return false;
};

/** 実体名の突き合わせ鍵。collect.mjs の canonMalware と同じ潰し方にする。 */
const nameKey = (s) => String(s ?? "").toLowerCase().replace(/[^a-z0-9]+/g, "");

/**
 * 索引が既に持っているマルウェア名（別名を含む）→ 代表名。
 * VT のファミリがここに当たれば **索引側の表記に寄せる**。寄せないと
 * 「emotet」と「Emotet」が別の実体として並び、正規化した意味が無くなる。
 */
const knownMalware = new Map();
for (const e of entities) {
  if (e.kind !== "malware") continue;
  knownMalware.set(nameKey(e.name), e.name);
  for (const a of e.aliases || []) if (!knownMalware.has(nameKey(a))) knownMalware.set(nameKey(a), e.name);
}

const vtRows = [];
const derivedLinks = [];
const resolveTargets = new Map();   // 解決先 IP → それを出したドメインの集合
const certs = new Map();            // thumbprint → まとまり
const familySamples = new Map();    // ファミリ → 支えている IOC の集合
const aliasSupport = new Map();     // ファミリ → 別名候補 → 出てきた件数
let asnAgree = 0, asnDisagree = 0;

const asnOf = new Map();
for (const r of readJsonl(path.join(IN, "ip-asn.jsonl"))) if (r.asn) asnOf.set(r.ioc, r.asn);

for (const rec of vtRecords) {
  const ioc = iocByKey.get(rec.ioc);
  // 索引から消えた IOC の写しは残っていてよい（取り直す手間を省くため）が、判定には使わない
  if (!ioc) continue;

  if (rec.status === 404) {
    // VT が知らない＝結果。索引の独自性の指標になる（§3.4）
    vtRows.push({ ioc: rec.ioc, known: false });
    continue;
  }
  const b = rec.body || {};
  const s = b.last_analysis_stats || {};
  const row = {
    ioc: rec.ioc,
    known: true,
    malicious: int(s.malicious) ?? 0,
    suspicious: int(s.suspicious) ?? 0,
    harmless: int(s.harmless) ?? 0,
    undetected: int(s.undetected) ?? 0,
    ...(int(s.timeout) ? { timeout: int(s.timeout) } : {}),
    ...(Number.isFinite(b.reputation) ? { reputation: int(b.reputation) } : {}),
    // 応答に入っている解析時刻。取得時刻ではない（取得時刻は enrich-meta.json だけ）
    ...(day(b.last_analysis_date) ? { analyzed_at: day(b.last_analysis_date) } : {}),
  };

  /* ---- ファイル ---- */
  if (rec.endpoint === "files") {
    const cls = b.popular_threat_classification || {};
    const label = cls.suggested_threat_label;
    if (label) row.label = String(label);
    const popular = (cls.popular_threat_name || [])
      .map((x) => String(x?.value || "").toLowerCase())
      .filter(Boolean);
    if (popular.length) row.families = [...new Set(popular)].sort();
    if (day(b.first_submission_date)) row.first_submission = day(b.first_submission_date);
    if (b.type_description) row.type_description = String(b.type_description);
    if (Number.isFinite(b.size)) row.size = int(b.size);
    const signer = b.signature_info?.signers || b.signature_info?.["signers details"]?.[0]?.name;
    if (typeof signer === "string" && signer.trim()) row.signer = signer.trim();

    /**
     * ファジーハッシュ。**提供元の判断が入らず、論理が明示的**なので、
     * 検知名より根拠として素直（`vhash` と `imphash` は完全一致で使える）。
     * `ssdeep` と `tlsh` は距離を測る必要があるので、いまは残すだけ。
     */
    for (const f of ["vhash", "imphash", "rich_header", "ssdeep", "tlsh"]) {
      if (typeof b[f] === "string" && b[f].trim()) row[f] = b[f].trim();
    }
    const names = [b.meaningful_name, ...(b.names || [])]
      .filter((x) => typeof x === "string" && x.trim())
      .map((x) => x.trim())
      .filter((x) => !placeholderName(x));
    if (names.length) row.names = [...new Set(names)].sort().slice(0, NAME_CAP);

    /* §2.1 マルウェア名の正規化。索引に同じものがあれば索引の表記に寄せる */
    const fam = familyOf(label);
    if (fam) {
      const canon = knownMalware.get(nameKey(fam)) || fam;
      derivedLinks.push({
        ioc: rec.ioc, kind: "malware", name: canon,
        rel: "suggested_threat_label", source: "virustotal",
      });
      if (!familySamples.has(canon)) familySamples.set(canon, new Set());
      familySamples.get(canon).add(rec.ioc);
      // 同じ検体に付いた別名。ファミリ自身と一般名は候補にしない
      if (!aliasSupport.has(canon)) aliasSupport.set(canon, new Map());
      const m = aliasSupport.get(canon);
      for (const p of new Set(popular)) {
        if (nameKey(p) === nameKey(fam) || nameKey(p) === nameKey(canon)) continue;
        if (GENERIC.has(nameKey(p)) || !nameKey(p)) continue;
        m.set(p, (m.get(p) || 0) + 1);
      }
    }
  }

  /* ---- ドメイン ---- */
  if (rec.endpoint === "domains") {
    if (day(b.creation_date)) row.created = day(b.creation_date);
    if (b.registrar) row.registrar = String(b.registrar);
    if (b.jarm) row.jarm = String(b.jarm);

    /* §2.2 domain → IP。今の IOC ↔ IOC の辺は 315 本しかない */
    const dns = [];
    for (const d of b.last_dns_records || []) {
      const t = String(d?.type || "").toUpperCase();
      if (t !== "A" && t !== "AAAA" && t !== "CNAME") continue;
      const v = String(d?.value || "").trim().toLowerCase();
      if (!v) continue;
      dns.push({ type: t, value: v });
      if (t === "CNAME") continue;
      const key = `${t === "A" ? "ioc.ipv4" : "ioc.ipv6"}|${v}`;
      if (!resolveTargets.has(key)) resolveTargets.set(key, new Set());
      resolveTargets.get(key).add(rec.ioc);
      derivedLinks.push({ ioc: rec.ioc, kind: "ioc", name: key, rel: "resolves_to", source: "virustotal" });
    }
    if (dns.length) row.dns = dns.sort(byKeys("type", "value"));
  }

  /* ---- IP ---- */
  if (rec.endpoint === "ip_addresses") {
    if (Number.isFinite(b.asn)) row.asn = int(b.asn);
    if (b.as_owner) row.as_owner = String(b.as_owner);
    if (b.country) row.country = String(b.country);
    if (b.network) row.network = String(b.network);
    if (b.jarm) row.jarm = String(b.jarm);
    // §1.1 経路表と突き合わせる。食い違いは時点差なので、両方残して数だけ数える
    const mine = asnOf.get(rec.ioc);
    if (mine && Number.isFinite(b.asn)) {
      if (mine === int(b.asn)) asnAgree++;
      else { asnDisagree++; row.asn_differs = true; }
    }
  }

  /* ---- URL ---- */
  if (rec.endpoint === "urls") {
    if (b.last_final_url) row.final_url = String(b.last_final_url);
    if (typeof b.title === "string" && b.title.trim()) row.title = b.title.trim().slice(0, 200);
    if (day(b.first_submission_date)) row.first_submission = day(b.first_submission_date);
  }

  /* ---- 証明書（ドメインと IP に付く） ---- */
  const c = b.last_https_certificate;
  const thumb = c?.thumbprint_sha256 && String(c.thumbprint_sha256).toLowerCase();
  if (thumb) {
    const sans = [...new Set((c.extensions?.subject_alternative_name || [])
      .map((x) => String(x).trim().toLowerCase()).filter(Boolean))].sort();
    row.cert = { thumbprint: thumb, san_count: sans.length };
    const issuer = c.issuer?.O || c.issuer?.CN;
    if (issuer) row.cert.issuer = String(issuer);
    /**
     * **その名前で出された証明書か、ワイルドカードで拾っただけか。**
     *
     * 実測すると `*.squarespace.com` の証明書（SAN 14・ワイルドカードと実名が混在）が
     * 無関係な 2 つのテナントを結んでいた。証明書ごとの印（weak_why:"wildcard"）は
     * 全部がワイルドカードのときしか立たないので、これは素通りする。
     * **自分の名前が SAN に literal で入っているか**で見るのが正しい。
     * IP は名前を持たず、その IP 自身が出している証明書なので対象外。
     */
    const cn = String(c.subject?.CN || "").trim().toLowerCase();
    /** 実在しうる host 名の形か。`localhost` `0.0.0.0` `Fireware web CA` は当たらない。 */
    const isHostname = (v) => /^[a-z0-9*][a-z0-9.*-]*\.[a-z]{2,}$/.test(v);
    // SAN が無い証明書は、名前を CN でしか主張していない
    const namesHost = ioc.type === "ioc.domain"
      ? (sans.length ? sans.includes(ioc.value) : cn === ioc.value)
      // IP は名前を持たない。**何かの host 名を主張している証明書か**だけを見る。
      // `localhost` `0.0.0.0` `Fireware web CA` `letsencrypt-nginx-proxy-companion` は
      // どれも既定の自己署名で、同じ image や機器を使っている全員が同じものを出す
      : (sans.some(isHostname) || isHostname(cn));
    if (!namesHost) row.cert.wildcard = true;
    if (!certs.has(thumb)) {
      certs.set(thumb, {
        thumbprint: thumb,
        ...(issuer ? { issuer: String(issuer) } : {}),
        ...(c.subject?.CN ? { subject: String(c.subject.CN) } : {}),
        ...(c.serial_number ? { serial: String(c.serial_number).toLowerCase() } : {}),
        ...(dayOf(c.validity?.not_after) ? { not_after: dayOf(c.validity.not_after) } : {}),
        san_count: sans.length,
        // SAN が多いものは全部持っても読めない。数は san_count に残る
        sans: sans.slice(0, SAN_CAP),
        iocs: new Set(),
        // SAN に名前が載っている IOC の数。0 なら基盤に出された証明書
        literal: 0,
        // そのうちドメイン。**IP だけの群はどちらとも言えない**（下の anchor を見よ）
        anchors: 0,
      });
    }
    certs.get(thumb).iocs.add(rec.ioc);
    if (!row.cert.wildcard) {
      certs.get(thumb).literal++;
      if (ioc.type === "ioc.domain") certs.get(thumb).anchors++;
    }
  }

  vtRows.push(row);
}
vtRows.sort(byKeys("ioc"));

/* ---------------- 2. 生えた IOC ---------------- */

const derivedIocs = [];
for (const [key, from] of resolveTargets) {
  // 索引が既に主張しているものは索引側を優先する。派生に混ぜない
  if (iocByKey.has(key)) continue;
  const [type, value] = [key.slice(0, key.indexOf("|")), key.slice(key.indexOf("|") + 1)];
  const c = type === "ioc.ipv4" ? classifyIpv4(value) : classifyIpv6(value);
  if (!c.valid) continue;
  derivedIocs.push({
    key, type, value,
    origin: "vt.dns",
    from: [...from].sort(),
    ...(type === "ioc.ipv4" && subnet24(value) ? { subnet: subnet24(value) } : {}),
    ...(c.bogon ? { bogon: true } : {}),
    ...(c.noise ? { noise: c.noise } : {}),
  });
}
derivedIocs.sort(byKeys("type", "value"));

/** 索引が既に知っている名前。連番の判定でも、生えた実体の判定でも使う。 */
const knownNames = new Set(entities.filter((e) => e.kind === "malware").map((e) => e.name));

/* ---------------- 1b. 提供元の連番ファミリを落とす ---------------- */

/**
 * `boiq` `boir` `boiv` `boja` `bokf` … のように、**頭 2 文字と長さが同じ札が
 * 何本も並ぶ**のは提供元の連番であって、ファミリ名ではない。
 * 実測で 13 本の `bo` + 4 文字、3 本の `ag` + 7 桁が実体として生えていた。
 * 名前を列挙して弾くのは一般化しないので、**並びの数で測る**。
 *
 * 実在のファミリは頭 2 文字と長さが揃って何本も出てくることがない
 * （`turla` `tiny` は長さが違い、`data` `dump` は頭 2 文字が違う）。
 */
// 3 で実測すると提供元の連番だけが落ちる。2 まで下げると datper / rokrat /
// muddywater のような実在のファミリまで巻き込む
const SERIAL_MIN = Number(args["serial-min"] || 3);
const shapeCount = new Map();
for (const fam of familySamples.keys()) {
  const k = `${fam.slice(0, 2)}\t${fam.length}`;
  shapeCount.set(k, (shapeCount.get(k) || 0) + 1);
}
const serialFamilies = new Set([...familySamples.keys()]
  .filter((f) => (shapeCount.get(`${f.slice(0, 2)}\t${f.length}`) || 0) >= SERIAL_MIN)
  // 索引が既に知っている名前は、並びが揃っていても落とさない
  .filter((f) => !knownNames.has(f)));
for (const f of serialFamilies) {
  familySamples.delete(f);
  aliasSupport.delete(f);
}

const derivedKeys = new Set(derivedIocs.map((r) => r.key));
/* 解決先が索引側にも派生側にも無い（壊れた値）辺は残さない。
   同じ辺が 2 度出ることもあるので、ここで 1 本にまとめる */
const seenLink = new Set();
const usableDerivedLinks = derivedLinks.filter((l) => {
  if (l.kind === "ioc" && !iocByKey.has(l.name) && !derivedKeys.has(l.name)) return false;
  if (l.rel === "suggested_threat_label" && serialFamilies.has(l.name)) return false;
  const k = `${l.ioc}\t${l.kind}\t${l.name}\t${l.rel}\t${l.source}`;
  if (seenLink.has(k)) return false;
  seenLink.add(k);
  return true;
});

/* ---------------- 3. 生えた実体と別名 ---------------- */

const derivedEntities = [...familySamples.entries()]
  .filter(([name]) => !knownNames.has(name))
  .map(([name, set]) => ({ kind: "malware", name, ioc_count: set.size, sources: ["virustotal"] }))
  .sort(byKeys("kind", "name"));

/** 別名候補。2 件以上の検体で一緒に出たものだけ（1 件だけの同居は当てにならない）。 */
const derivedAliases = [...aliasSupport.entries()]
  .map(([name, m]) => {
    const aliases = [...m.entries()].filter(([, n]) => n >= 2).map(([a]) => a).sort();
    return aliases.length ? { name, aliases, samples: familySamples.get(name)?.size || 0, source: "virustotal" } : null;
  })
  .filter(Boolean)
  .sort(byKeys("name"));

/* ---------------- 4. 証明書 ---------------- */

/**
 * 根拠に使えない証明書を見分ける。**捨てずに印を付ける**。
 *
 *   san      … SAN が多すぎる。共用ホスティング（/24 や AS と同じ考え方）
 *   wildcard … **どの IOC も SAN に名前が載っていない**。その host に出された
 *              証明書ではなく、基盤に出された証明書。
 *
 * wildcard は実測で 2 度見つかった。`*.azurewebsites.net`（SAN 11 と 30）と
 * `*.squarespace.com`（SAN 14・ワイルドカードと実名が混在）が、どちらも
 * 無関係なテナント同士を結んでいた。**SAN の数でも「全部ワイルドカードか」でも
 * 見分けられない**ので、自分の名前が載っているかで見る。
 */
const certWeakness = (c) => {
  if (c.san_count > SAN_CAP) return "san";
  if (c.literal === 0) return "wildcard";
  // **IP だけの群は、運用者の証明書か基盤の既定かを見分けられない。**
  // 実測で `invalid2.invalid`（Cloudflare の既定）・`*.hstgr.io`（Hostinger の共用）・
  // `cloudflare-dns.com`・`n.sni-347-default.ssl.fastly.net` が、
  // 無関係なアクター同士を strength 9〜10 で繋いでいた。
  // 名前が当たったドメインが 1 つでも居れば「その運用者のもの」と言えるので、
  // それを錨（anchor）にする。錨が無い群は**捨てずに印を付け**、
  // daily-report が cert_excluded として人に渡す。
  if (c.anchors === 0) return "unanchored";
  return null;
};

const certRows = [...certs.values()]
  .map((c) => {
    const why = certWeakness(c);
    const { literal, anchors, ...rest } = c;
    return {
      ...rest,
      iocs: [...c.iocs].sort(),
      shared: c.iocs.size > 1,
      ...(why ? { weak: true, weak_why: why } : {}),
    };
  })
  .sort(byKeys("thumbprint"));

/* ---------------- 5. AbuseIPDB ---------------- */

/** 通報カテゴリ。番号のままでは読めないので名前にする。 */
const CATEGORY = {
  1: "DNS の乗っ取り", 2: "DNS 汚染", 3: "詐欺注文", 4: "DDoS", 5: "FTP 総当たり",
  6: "Ping of Death", 7: "フィッシング", 8: "VoIP 詐欺", 9: "オープンプロキシ",
  10: "Web スパム", 11: "メールスパム", 12: "ブログスパム", 13: "VPN", 14: "ポートスキャン",
  15: "侵入", 16: "SQL インジェクション", 17: "詐称", 18: "総当たり", 19: "不正ボット",
  20: "踏み台", 21: "Web アプリ攻撃", 22: "SSH", 23: "IoT 狙い",
};
/** 相乗り判定の 3 つ目の観点（§2.5）。事業者の網かどうか。 */
const HOSTING = /data center|web hosting|transit|content delivery|reserved/i;

/**
 * 中身の無い通報コメント。**通報したという事実だけが残っていて、何をされたかが書いていない。**
 * 見本アドレス（1.2.3.4 など）は「適当な IP」として書かれ続けるので、
 * 動作確認や無言の通報がここに溜まり、信頼度スコアだけが上がる。
 */
const HOLLOW = /^(|\.{2,}|-+|_+|\?+|x+|test(ing|ed)?|n\/?a|none|null|nil|abuse|spam|bad|blocked|report(ed)?|sample|example|dummy|placeholder|foo|bar|asdf?)$/i;

const abuseRows = [];
for (const rec of abuseRecords) {
  if (!iocByKey.has(rec.ioc)) continue;
  const b = rec.body || {};
  const cats = new Map();
  const reports = b.reports || [];
  for (const r of reports) {
    for (const c of r?.categories || []) {
      const name = CATEGORY[c] || `分類 ${c}`;
      cats.set(name, (cats.get(name) || 0) + 1);
    }
  }
  // 中身無しの数は常に残す。印が付かなかったものも、あとから境目を動かして見直せるように。
  // 分母は totalReports ではなく **実際にコメントを読めた件数**。API が返す通報は
  // 上限で切られるので、この 2 つは一致しない。判定に使った方を残さないと検算できない。
  const hollow = reports.filter((r) => HOLLOW.test(String(r?.comment ?? "").trim())).length;
  const sample = reports.length >= SAMPLE_MIN && hollow / reports.length >= SAMPLE_RATIO;
  abuseRows.push({
    ...(hollow ? { comments: reports.length, hollow } : {}),
    // **消さずに印を付ける。**stats 側でこの印の付いた IP を根拠から外す。
    ...(sample ? { sample: true } : {}),
    ioc: rec.ioc,
    // **通報数ではなくこれで判断する**（通報 97 件でスコア 0 の IP が実在する）
    score: int(b.abuseConfidenceScore) ?? 0,
    reports: int(b.totalReports) ?? 0,
    reporters: int(b.numDistinctUsers) ?? 0,
    ...(dayOf(b.lastReportedAt) ? { last_reported_at: dayOf(b.lastReportedAt) } : {}),
    ...(b.usageType ? { usage_type: String(b.usageType) } : {}),
    ...(b.usageType && HOSTING.test(String(b.usageType)) ? { hosting: true } : {}),
    ...(b.isp ? { isp: String(b.isp) } : {}),
    ...(b.domain ? { domain: String(b.domain) } : {}),
    ...(b.countryCode ? { country: String(b.countryCode) } : {}),
    ...(b.isTor ? { tor: true } : {}),
    ...(b.isWhitelisted ? { whitelisted: true } : {}),
    ...(cats.size ? { categories: Object.fromEntries([...cats].sort()) } : {}),
  });
}
abuseRows.sort(byKeys("ioc"));

/* ---------------- 6. カバレッジ ---------------- */

// 対象の数え方は fetch 側・stats 側と同じ関数を使う。別々に数えると分母が食い違う
const coverage = coverageOf({
  iocs, links,
  fresh: new Set(readJsonl(path.join(IN, "new.jsonl")).map((r) => r.key)),
  asnOf,
  asnInfo: new Map(readJsonl(path.join(IN, "asns.jsonl")).map((a) => [a.asn, a])),
  vtRows, abuseRows,
  includeNoise: INCLUDE_NOISE,
  fetchDays: [...vtRecords, ...abuseRecords].map((r) => dayOf(r.fetched_at)),
});
const ratio = (a, b) => (b > 0 ? Math.round((a / b) * 1000) / 1000 : 0);

/* ---------------- 書き出し ---------------- */

writeJsonl(path.join(OUT, "vt.jsonl"), vtRows);
writeJsonl(path.join(OUT, "abuseipdb.jsonl"), abuseRows);
writeJsonl(path.join(OUT, "derived-iocs.jsonl"), derivedIocs);
writeJsonl(path.join(OUT, "derived-links.jsonl"), usableDerivedLinks.sort(byKeys("ioc", "kind", "name", "rel", "source")));
writeJsonl(path.join(OUT, "derived-entities.jsonl"), derivedEntities);
writeJsonl(path.join(OUT, "derived-aliases.jsonl"), derivedAliases);
writeJsonl(path.join(OUT, "derived-certs.jsonl"), certRows);

writeJson(path.join(OUT, "enrich-meta.json"), {
  tool: "tools/ioc/enrich-intel.mjs",
  schema: 1,
  coverage,
  cache: {
    virustotal: {
      dir: path.relative(REPO_ROOT, VT_CACHE),
      records: vtRecords.length,
      // どの写しから出た結果かを固定する（asn-meta.json の table.sha256 と同じ役目）
      sha256: digestRecords(vtRecords),
      projection: PROJECTION,
    },
    abuseipdb: {
      dir: path.relative(REPO_ROOT, ABUSE_CACHE),
      records: abuseRecords.length,
      sha256: digestRecords(abuseRecords),
    },
  },
  counts: {
    vt: vtRows.length,
    abuseipdb: abuseRows.length,
    derived_iocs: derivedIocs.length,
    derived_links: usableDerivedLinks.length,
    derived_entities: derivedEntities.length,
    derived_aliases: derivedAliases.length,
    derived_certs: certRows.length,
    shared_certs: certRows.filter((c) => c.shared && !c.weak).length,
  },
  // AS は経路表とも突き合わせる。食い違いは時点差なので、消さずに数だけ残す
  asn_check: { agree: asnAgree, differ: asnDisagree },
  options: { san_cap: SAN_CAP, name_cap: NAME_CAP, include_noise: INCLUDE_NOISE },
});

/* ---------------- 表示 ---------------- */

const pct = (x) => `${(x * 100).toFixed(1)}%`;
console.log(`VT ${coverage.virustotal.done} / ${coverage.virustotal.target} 件（${pct(coverage.virustotal.ratio)}）`
  + `  判定あり ${coverage.virustotal.known} / VT が知らない ${coverage.virustotal.unknown}`);
for (const [s, v] of Object.entries(coverage.virustotal.by_stage)) {
  console.log(`    段階 ${s.padEnd(3)} ${String(v.done).padStart(6)} / ${String(v.target).padEnd(6)} ${pct(ratio(v.done, v.target))}`);
}
console.log(`AbuseIPDB ${coverage.abuseipdb.done} / ${coverage.abuseipdb.target} IP（${pct(coverage.abuseipdb.ratio)}）`);
const scored = abuseRows.filter((r) => r.score >= 25).length;
if (abuseRows.length) console.log(`    スコア 25 以上 ${scored} 件 / 事業者の網 ${abuseRows.filter((r) => r.hosting).length} 件`);
console.log(`生えたもの: IOC ${derivedIocs.length} / 辺 ${usableDerivedLinks.length}`
  + `（うち解決先 ${usableDerivedLinks.filter((l) => l.rel === "resolves_to").length}`
  + ` / ファミリ ${usableDerivedLinks.filter((l) => l.rel === "suggested_threat_label").length}）`);
console.log(`    実体 ${derivedEntities.length} / 別名 ${derivedAliases.length}`
  + ` / 証明書 ${certRows.length}（共有 ${certRows.filter((c) => c.shared && !c.weak).length}）`);
if (asnAgree + asnDisagree) {
  console.log(`    AS の突き合わせ: 一致 ${asnAgree} / 食い違い ${asnDisagree}（経路表との時点差）`);
}
console.log(`  → ${path.relative(REPO_ROOT, OUT)}`);
