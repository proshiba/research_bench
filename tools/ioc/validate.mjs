#!/usr/bin/env node
// 集めたデータを検査する。外部呼び出しなし。
//
//   node tools/ioc/validate.mjs [--in data/ioc/latest] [--json <報告の書き出し先>]
//                               [--strict] [--allow-partial] [--samples 5] [--quiet]
//
// 何のためにあるか
//   収集の元になる索引は人が書いた記事から起こされている。書式のゆれや型の取り違えは
//   必ず混ざる（実際に SHA-512 を `ioc.sha256` として載せている索引があった）。
//   出力を機械が使う前提にするなら、**壊れているかどうかを毎回同じ手順で確かめられる**
//   必要がある。ここはその手順を固定するためのもの。
//
// 判定は 2 段階。
//   error … データとして矛盾している。直さずに使ってはいけない（終了コード 1）
//   warn  … 使えるが疑わしい。元データ側の誤りの疑い（既定では終了コード 0）
// --strict を付けると warn も失敗にする。
//
// 検査するもの
//   1. 正準形    各行が stableStringify と 1 バイト違わないか（並び・キー順の保証）
//   2. 並び      ファイルが規定の鍵で整列しているか、重複が無いか
//   3. 型と欄    既知の欄だけか、型が合っているか、未知の欄が増えていないか
//   4. 正規化    key = type|joinKey(type,value) / value が正規形 / refang 済みか
//   5. 値の形    md5=32 sha1=40 sha256=64 sha512=128 桁、IPv4 の形、URL が解けるか
//   6. 参照      辺の指す IOC と実体が実在するか
//   7. 集計      entities の ioc_count・meta の counts が実データと一致するか
//   8. 派生物    overlaps / graph / stats / new があれば、元データと突き合わせる

import fs from "node:fs";
import path from "node:path";
import { joinKey, refang } from "../../assets/js/util.js";
import { byKeys, parseArgs, readJson, readJsonl, stableStringify, writeJson } from "./lib/io.mjs";
import { classifyIpv4, registrableDomain, subnet24 } from "./lib/net.mjs";
import { REPO_ROOT } from "./lib/sources.mjs";

const args = parseArgs(process.argv.slice(2));
const IN = path.resolve(REPO_ROOT, args.in || "data/ioc/latest");
const SAMPLES = Number(args.samples || 5);
const QUIET = !!args.quiet;

/* ---------------- 記録 ---------------- */

const issues = [];
const add = (severity, rule, message, where = {}) => issues.push({ severity, rule, message, ...where });
const err = (rule, message, where) => add("error", rule, message, where);
const warn = (rule, message, where) => add("warn", rule, message, where);

/** どの行かを示す共通の場所表記。 */
const at = (file, i) => ({ file, line: i + 1 });

/* ---------------- 欄の定義 ---------------- */

const IOC_FIELDS = {
  required: ["key", "type", "value", "sources"],
  optional: [
    "raw", "subnet", "registrable", "bogon", "noise", "malformed",
    "classes", "roles", "confidence",
    "observed_first", "observed_last", "collected_first", "collected_last",
  ],
};
const LINK_FIELDS = { required: ["ioc", "kind", "name", "source"], optional: ["rel", "id"] };
const ENTITY_FIELDS = { required: ["kind", "name", "ioc_count", "sources"], optional: ["aliases"] };

/** 索引が出しうる IOC の型。増えたら気づけるように列挙で持つ。 */
const IOC_TYPES = new Set([
  "ioc.ipv4", "ioc.ipv6", "ioc.domain", "ioc.url", "ioc.email", "ioc.endpoint",
  "ioc.md5", "ioc.sha1", "ioc.sha256", "ioc.sha512",
]);
const HASH_LEN = { "ioc.md5": 32, "ioc.sha1": 40, "ioc.sha256": 64, "ioc.sha512": 128 };
const LINK_KINDS = new Set(["actor", "malware", "campaign", "case", "article", "cve", "ioc"]);
/** IOC として妥当な URL の scheme。これ以外は元表記の取り違えを疑う。 */
const URL_SCHEMES = new Set(["http:", "https:", "ftp:", "ftps:", "ws:", "wss:", "smb:", "tcp:"]);
const VIA = new Set(["ioc", "subnet", "registrable"]);

/**
 * 名前ではなく確度の但し書きだったもの。collect 側と同じ判定を持つ。
 * ここでは弾くためではなく、**弾き漏らしに気づくため**に使う。
 */
const nameKey = (s) => String(s ?? "").trim().toLowerCase().replace(/[^a-z0-9]+/g, "");
const QUALIFIER = new Set([
  "suspected", "possible", "likely", "probable", "unknown", "unattributed",
  "unclear", "na", "tbd", "none", "multipleactors", "multiple", "various",
]);
const looksQualifier = (s) => {
  const k = nameKey(s);
  return !k || QUALIFIER.has(k) || /confidence$/.test(k) || /^aka/.test(k);
};

/* ---------------- 1. 読み込みと正準形 ---------------- */

/**
 * JSONL を読みつつ、各行が stableStringify の出力と一致するかを見る。
 *
 * これが通れば「キーが名前順」「余計な空白が無い」「JSON として妥当」が同時に保証される。
 * 出力の決定性はこのファイル群の前提なので、真っ先に確かめる。
 */
function loadJsonl(name, { required = true } = {}) {
  const file = path.join(IN, name);
  if (!fs.existsSync(file)) {
    if (required) err("file.missing", `${name} がありません`, { file: name });
    return null;
  }
  const text = fs.readFileSync(file, "utf8");
  if (text && !text.endsWith("\n")) err("file.newline", `${name} が改行で終わっていません`, { file: name });
  const rows = [];
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!line.trim()) {
      if (i !== lines.length - 1) err("file.blank", `${name} に空行があります`, at(name, i));
      continue;
    }
    let row;
    try {
      row = JSON.parse(line);
    } catch (e) {
      err("json.parse", `JSON として読めません: ${e.message}`, at(name, i));
      continue;
    }
    if (!row || typeof row !== "object" || Array.isArray(row)) {
      err("json.shape", "オブジェクトではありません", at(name, i));
      continue;
    }
    if (stableStringify(row, 0) !== line + "\n") {
      err("canonical", "正準形ではありません（キー順か空白の違い）", at(name, i));
    }
    rows.push(row);
  }
  return rows;
}

/** 派生物。読む前に報告へ出る経路があるので、ここで宣言だけしておく。 */
let overlaps = null;

const iocs = loadJsonl("iocs.jsonl");
const links = loadJsonl("links.jsonl");
const entities = loadJsonl("entities.jsonl");
const meta = readJson(path.join(IN, "meta.json"));
if (!meta) err("file.missing", "meta.json がありません", { file: "meta.json" });

if (!iocs || !links || !entities) {
  report();
  process.exit(1);
}

/* ---------------- 2. 並びと重複 ---------------- */

/** 整列済みか、識別鍵に重複が無いかを見る。並びも出力の一部なので error 扱い。 */
function checkOrder(name, rows, cmp, identity) {
  const seen = new Map();
  for (let i = 0; i < rows.length; i++) {
    if (i > 0 && cmp(rows[i - 1], rows[i]) > 0) {
      err("order", `${name} が整列していません`, at(name, i));
    }
    const id = identity(rows[i]);
    if (seen.has(id)) {
      err("duplicate", `重複しています（${seen.get(id) + 1} 行目と同じ）: ${id}`, at(name, i));
    } else {
      seen.set(id, i);
    }
  }
}

checkOrder("iocs.jsonl", iocs, byKeys("type", "value"), (r) => r.key);
checkOrder("links.jsonl", links, byKeys("ioc", "kind", "name", "source", "rel"),
  (r) => `${r.ioc}\t${r.kind}\t${r.name}\t${r.source}\t${r.rel ?? ""}`);
checkOrder("entities.jsonl", entities, byKeys("kind", "name"), (r) => `${r.kind}\t${r.name}`);

/* ---------------- 3. 欄の検査（共通） ---------------- */

function checkFields(name, row, i, spec) {
  for (const k of spec.required) {
    if (row[k] === undefined || row[k] === null || row[k] === "") {
      err("field.missing", `${k} がありません`, at(name, i));
    }
  }
  const allowed = new Set([...spec.required, ...spec.optional]);
  for (const k of Object.keys(row)) {
    // 知らない欄が増えたら、検査していない情報が出力に載っているということ
    if (!allowed.has(k)) err("field.unknown", `未知の欄: ${k}`, at(name, i));
  }
}

/** 文字列の配列で、整列済み・重複無し・空要素なしであること。 */
function checkStringArray(name, i, field, v, { sorted = true } = {}) {
  if (!Array.isArray(v)) { err("field.type", `${field} が配列ではありません`, at(name, i)); return; }
  if (!v.length) { err("field.empty", `${field} が空の配列です`, at(name, i)); return; }
  for (const x of v) {
    if (typeof x !== "string" || !x.trim()) {
      err("field.type", `${field} に空か文字列でない要素があります`, at(name, i));
      return;
    }
  }
  if (sorted) {
    const s = [...v].sort();
    if (s.join(" ") !== v.join(" ")) err("field.order", `${field} が整列していません`, at(name, i));
    if (new Set(v).size !== v.length) err("field.dup", `${field} に重複があります`, at(name, i));
  }
}

const DATE = /^\d{4}-\d{2}-\d{2}$/;
const today = new Date().toISOString().slice(0, 10);
function checkDate(name, i, field, v) {
  if (typeof v !== "string" || !DATE.test(v)) {
    err("date.format", `${field} が YYYY-MM-DD ではありません: ${v}`, at(name, i));
    return false;
  }
  // 「2025-02-30」のような存在しない日付を弾く
  if (new Date(v + "T00:00:00Z").toISOString().slice(0, 10) !== v) {
    err("date.invalid", `${field} は存在しない日付です: ${v}`, at(name, i));
    return false;
  }
  if (v > today) warn("date.future", `${field} が未来です: ${v}`, at(name, i));
  if (v < "2000-01-01") warn("date.old", `${field} が古すぎます: ${v}`, at(name, i));
  return true;
}

/* ---------------- 4. iocs.jsonl ---------------- */

const HEX = /^[0-9a-f]+$/;
const IPV4 = /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;
const HOSTNAME = /^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(?:\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/;
const iocKeys = new Set();
const sourceIds = new Set();

for (let i = 0; i < iocs.length; i++) {
  const r = iocs[i];
  checkFields("iocs.jsonl", r, i, IOC_FIELDS);
  iocKeys.add(r.key);

  if (typeof r.type !== "string" || !IOC_TYPES.has(r.type)) {
    err("ioc.type", `未知の型: ${r.type}`, at("iocs.jsonl", i));
    continue;
  }
  if (typeof r.value !== "string" || !r.value) continue;

  /* 正規化の不変条件。ここが崩れると照合が静かに外れる */
  const jk = joinKey(r.type, r.value);
  if (jk !== r.value) {
    err("norm.value", `value が正規形ではありません（期待 ${jk}）`, at("iocs.jsonl", i));
  }
  if (r.key !== `${r.type}|${jk}`) {
    err("norm.key", `key が type|joinKey(value) と一致しません: ${r.key}`, at("iocs.jsonl", i));
  }
  if (refang(r.value) !== r.value) {
    err("norm.refang", `value が defang 表記のままです: ${r.value}`, at("iocs.jsonl", i));
  }
  if (r.raw !== undefined) {
    if (typeof r.raw !== "string" || !r.raw) err("field.type", "raw が空です", at("iocs.jsonl", i));
    else if (joinKey(r.type, r.raw) !== r.value) {
      err("norm.raw", `raw を正規化しても value になりません: ${r.raw}`, at("iocs.jsonl", i));
    }
  }

  checkStringArray("iocs.jsonl", i, "sources", r.sources);
  for (const s of r.sources || []) sourceIds.add(s);
  for (const f of ["classes", "roles", "confidence"]) {
    if (r[f] !== undefined) checkStringArray("iocs.jsonl", i, f, r[f]);
  }
  for (const f of ["bogon", "malformed"]) {
    if (r[f] !== undefined && r[f] !== true) err("field.type", `${f} は true のときだけ置いてください`, at("iocs.jsonl", i));
  }
  if (r.noise !== undefined && (typeof r.noise !== "string" || !r.noise)) {
    err("field.type", "noise は理由の文字列です", at("iocs.jsonl", i));
  }

  /* 型ごとの値の形 */
  const len = HASH_LEN[r.type];
  if (len) {
    // 索引が型を取り違えていると、ここで長さが合わなくなる。
    // 実際に SHA-512 を ioc.sha256 として載せていた索引があった
    if (!HEX.test(r.value)) {
      err("hash.charset", `16 進数ではありません: ${r.value}`, at("iocs.jsonl", i));
    } else if (r.value.length !== len) {
      const actual = Object.entries(HASH_LEN).find(([, n]) => n === r.value.length);
      err("hash.length",
        `${r.type} は ${len} 桁のはずが ${r.value.length} 桁です`
        + (actual ? `（${actual[0]} の可能性）` : ""),
        at("iocs.jsonl", i));
    }
  } else if (r.type === "ioc.ipv4") {
    if (!IPV4.test(r.value)) {
      if (!r.malformed) err("ipv4.format", `IPv4 の形ではないのに印がありません: ${r.value}`, at("iocs.jsonl", i));
    } else {
      const c = classifyIpv4(r.value);
      if (!!r.bogon !== !!c.bogon) err("ipv4.bogon", `bogon の印が判定と違います: ${r.value}`, at("iocs.jsonl", i));
      if (!!r.noise !== !!c.noise) err("ipv4.noise", `noise の印が判定と違います: ${r.value}`, at("iocs.jsonl", i));
      const net = subnet24(r.value);
      if (r.subnet !== net) err("ipv4.subnet", `subnet が ${net} と一致しません: ${r.subnet}`, at("iocs.jsonl", i));
    }
  } else if (r.type === "ioc.ipv6") {
    if (!r.value.includes(":") && !r.malformed) {
      err("ipv6.format", `IPv6 の形ではありません: ${r.value}`, at("iocs.jsonl", i));
    }
    if (r.subnet !== undefined) err("field.unknown", "IPv6 に subnet は付きません", at("iocs.jsonl", i));
  } else if (r.type === "ioc.domain") {
    const rd = registrableDomain(r.value);
    if (r.registrable !== (rd ?? undefined)) {
      err("domain.registrable", `registrable が ${rd} と一致しません: ${r.registrable}`, at("iocs.jsonl", i));
    }
    if (!HOSTNAME.test(r.value)) warn("domain.format", `ホスト名として不自然です: ${r.value}`, at("iocs.jsonl", i));
    if (IPV4.test(r.value)) warn("domain.isip", `IP が domain として入っています: ${r.value}`, at("iocs.jsonl", i));
  } else if (r.type === "ioc.url") {
    try {
      const u = new URL(r.value);
      // 見慣れない scheme は refang の失敗（hxxp の変形など）の兆候になる
      if (!URL_SCHEMES.has(u.protocol)) warn("url.scheme", `見慣れない scheme です: ${r.value}`, at("iocs.jsonl", i));
    } catch {
      warn("url.format", `URL として解けません: ${r.value}`, at("iocs.jsonl", i));
    }
  } else if (r.type === "ioc.email") {
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(r.value)) {
      warn("email.format", `メールアドレスの形ではありません: ${r.value}`, at("iocs.jsonl", i));
    }
  }

  /* 日付。first <= last は必ず成り立つはず */
  for (const into of ["observed", "collected"]) {
    const a = r[`${into}_first`];
    const b = r[`${into}_last`];
    if ((a === undefined) !== (b === undefined)) {
      err("date.pair", `${into}_first と ${into}_last は両方必要です`, at("iocs.jsonl", i));
      continue;
    }
    if (a === undefined) continue;
    const ok = checkDate("iocs.jsonl", i, `${into}_first`, a) & checkDate("iocs.jsonl", i, `${into}_last`, b);
    if (ok && a > b) err("date.range", `${into}_first > ${into}_last (${a} > ${b})`, at("iocs.jsonl", i));
  }
}

/* ---------------- 5. links.jsonl ---------------- */

const entityKeys = new Set(entities.map((e) => `${e.kind}\t${e.name}`));
/** 参照の再計算。entities の集計と突き合わせるために作る。 */
const linkIocs = new Map();     // "kind\tname" → IOC 鍵の集合
const linkSources = new Map();  // "kind\tname" → 出典の集合

for (let i = 0; i < links.length; i++) {
  const l = links[i];
  checkFields("links.jsonl", l, i, LINK_FIELDS);

  if (!LINK_KINDS.has(l.kind)) {
    err("link.kind", `未知の種別: ${l.kind}`, at("links.jsonl", i));
    continue;
  }
  if (typeof l.ioc !== "string" || !iocKeys.has(l.ioc)) {
    err("link.ioc", `存在しない IOC を指しています: ${l.ioc}`, at("links.jsonl", i));
  }
  if (typeof l.name !== "string" || l.name !== l.name.trim() || !l.name) {
    err("link.name", `name が空か前後に空白があります: ${JSON.stringify(l.name)}`, at("links.jsonl", i));
  }
  if (l.rel !== undefined && l.rel !== null && typeof l.rel !== "string") {
    err("field.type", "rel は文字列か null です", at("links.jsonl", i));
  }
  if (typeof l.source !== "string" || !l.source) {
    err("field.type", "source が空です", at("links.jsonl", i));
  }

  if (l.kind === "ioc") {
    // IOC 同士の辺。相手は索引側の id 表記なので、鍵の形をしているときだけ実在を確かめる
    if (l.name.includes("|") && !iocKeys.has(l.name)) {
      warn("link.ioc_target", `IOC 同士の辺の相手が見つかりません: ${l.name}`, at("links.jsonl", i));
    }
    continue;
  }
  if (l.kind === "cve" && !/^CVE-\d{4}-\d{4,7}$/.test(l.name)) {
    err("link.cve", `CVE の形ではありません: ${l.name}`, at("links.jsonl", i));
  }
  if (!entityKeys.has(`${l.kind}\t${l.name}`)) {
    err("link.entity", `entities.jsonl に無い実体を指しています: ${l.kind}/${l.name}`, at("links.jsonl", i));
  }
  const k = `${l.kind}\t${l.name}`;
  if (!linkIocs.has(k)) { linkIocs.set(k, new Set()); linkSources.set(k, new Set()); }
  linkIocs.get(k).add(l.ioc);
  linkSources.get(k).add(l.source);
}

/* ---------------- 6. entities.jsonl ---------------- */

for (let i = 0; i < entities.length; i++) {
  const e = entities[i];
  checkFields("entities.jsonl", e, i, ENTITY_FIELDS);

  if (e.kind === "ioc" || !LINK_KINDS.has(e.kind)) {
    err("entity.kind", `未知の種別: ${e.kind}`, at("entities.jsonl", i));
    continue;
  }
  if (typeof e.name !== "string" || e.name !== e.name.trim() || !e.name) {
    err("entity.name", `name が空か前後に空白があります: ${JSON.stringify(e.name)}`, at("entities.jsonl", i));
    continue;
  }
  checkStringArray("entities.jsonl", i, "sources", e.sources);
  if (e.aliases !== undefined) checkStringArray("entities.jsonl", i, "aliases", e.aliases);
  if (!Number.isInteger(e.ioc_count) || e.ioc_count < 0) {
    err("field.type", `ioc_count が整数ではありません: ${e.ioc_count}`, at("entities.jsonl", i));
  }

  /* 集計の突き合わせ。辺から数え直して一致するか */
  const k = `${e.kind}\t${e.name}`;
  const iocSet = linkIocs.get(k);
  if (!iocSet) {
    err("entity.orphan", `どの辺からも参照されていません: ${e.kind}/${e.name}`, at("entities.jsonl", i));
  } else {
    if (iocSet.size !== e.ioc_count) {
      err("entity.count", `ioc_count が辺の数え直し（${iocSet.size}）と違います: ${e.ioc_count}`, at("entities.jsonl", i));
    }
    const recomputed = [...linkSources.get(k)].sort().join(",");
    if (recomputed !== (e.sources || []).join(",")) {
      err("entity.sources", `sources が辺の数え直し（${recomputed}）と違います`, at("entities.jsonl", i));
    }
  }

  /* 元データ由来の壊れ方。名前として成立していないもの */
  if ((e.kind === "actor" || e.kind === "malware") && looksQualifier(e.name)) {
    warn("entity.qualifier", `名前ではなく但し書きに見えます: ${e.kind}/${e.name}`, at("entities.jsonl", i));
  }
  if (e.kind === "actor" || e.kind === "malware") {
    // キャンペーンやケースの名前は文章なので、この 2 つだけを見る
    const open = (e.name.match(/\(/g) || []).length;
    const close = (e.name.match(/\)/g) || []).length;
    if (open !== close) warn("entity.parens", `括弧が閉じていません: ${e.name}`, at("entities.jsonl", i));
    if (/[,、;]/.test(e.name)) warn("entity.comma", `複数の名前が 1 つに入っている疑い: ${e.name}`, at("entities.jsonl", i));
  }
  if (e.aliases) {
    // 別名は名前鍵で 1 つに絞られているはず（collect の pickAliases）。
    // 崩れていれば「APT1 の別名は apt1」のような中身の無い行が並ぶ
    const seen = new Map();
    for (const a of e.aliases) {
      const k = nameKey(a);
      if (k === nameKey(e.name)) {
        err("entity.alias_self", `別名が代表名と同じです: ${e.name} / ${a}`, at("entities.jsonl", i));
      } else if (seen.has(k)) {
        err("entity.alias_dup", `別名が名前鍵で重複しています: ${seen.get(k)} / ${a}`, at("entities.jsonl", i));
      } else {
        seen.set(k, a);
      }
      if (/[,、;]/.test(a)) warn("entity.alias_comma", `別名が分けられていません: ${a}`, at("entities.jsonl", i));
    }
  }
}

/* ---------------- 7. meta.json ---------------- */

if (meta) {
  const c = meta.counts || {};
  const eq = (label, actual, expected) => {
    if (actual !== expected) err("meta.count", `counts.${label} が ${expected} と違います: ${actual}`, { file: "meta.json" });
  };
  eq("iocs", c.iocs, iocs.length);
  eq("links", c.links, links.length);
  eq("entities", c.entities, entities.length);

  const tally = (rows, pick) => {
    const out = {};
    for (const r of rows) for (const v of [].concat(pick(r))) out[v] = (out[v] || 0) + 1;
    return out;
  };
  const cmpMap = (label, actual, expected) => {
    const a = JSON.stringify(Object.fromEntries(Object.entries(actual || {}).sort()));
    const b = JSON.stringify(Object.fromEntries(Object.entries(expected).sort()));
    if (a !== b) err("meta.count", `counts.${label} が実データと違います\n    meta: ${a}\n    実際: ${b}`, { file: "meta.json" });
  };
  cmpMap("by_type", c.by_type, tally(iocs, (r) => r.type));
  cmpMap("by_source", c.by_source, tally(iocs, (r) => r.sources || []));
  cmpMap("by_entity_kind", c.by_entity_kind, tally(entities, (e) => e.kind));
  cmpMap("excluded", c.excluded, {
    bogon: iocs.filter((r) => r.bogon).length,
    noise: iocs.filter((r) => r.noise).length,
    malformed: iocs.filter((r) => r.malformed).length,
  });

  if (!/^\d{4}-W\d{2}$/.test(String(meta.week))) {
    err("meta.week", `week が YYYY-Www ではありません: ${meta.week}`, { file: "meta.json" });
  }
  if (Number.isNaN(Date.parse(meta.collected_at))) {
    err("meta.collected_at", `collected_at が日時として読めません: ${meta.collected_at}`, { file: "meta.json" });
  }

  const listed = new Set();
  for (const s of meta.sources || []) {
    listed.add(s.app_id);
    if (s.error) {
      // 取れなかった索引がある＝この一式は欠けている。完全なものとして扱ってはいけない
      const how = args["allow-partial"] ? warn : err;
      how("meta.source_error", `${s.app_id} の取得に失敗しています: ${s.error}`, { file: "meta.json" });
    } else if (!s.entities) {
      warn("meta.source_empty", `${s.app_id} の実体が 0 件です`, { file: "meta.json" });
    }
    if (!s.error && !/^[0-9a-f]{64}$/.test(String(s.search_sha256))) {
      err("meta.sha", `${s.app_id} の search_sha256 がありません`, { file: "meta.json" });
    }
  }
  for (const s of sourceIds) {
    if (!listed.has(s)) err("meta.source_missing", `IOC が参照する出典が meta にありません: ${s}`, { file: "meta.json" });
  }
}

/* ---------------- 8. 派生物 ---------------- */

overlaps = loadJsonl("overlaps.jsonl", { required: false });
if (overlaps) {
  checkOrder("overlaps.jsonl", overlaps, byKeys("kind", "a", "b"), (o) => `${o.kind}\t${o.a}\t${o.b}`);
  for (let i = 0; i < overlaps.length; i++) {
    const o = overlaps[i];
    for (const side of ["a", "b"]) {
      if (!entityKeys.has(`${o.kind}\t${o[side]}`)) {
        err("overlap.entity", `${side} が entities.jsonl にありません: ${o.kind}/${o[side]}`, at("overlaps.jsonl", i));
      }
    }
    if (o.a === o.b) err("overlap.self", "自分自身との組です", at("overlaps.jsonl", i));
    if (!(o.a < o.b)) err("overlap.order", `組が a < b になっていません: ${o.a} / ${o.b}`, at("overlaps.jsonl", i));
    if (!Number.isInteger(o.shared) || o.shared < 1) {
      err("overlap.shared", `shared が 1 以上の整数ではありません: ${o.shared}`, at("overlaps.jsonl", i));
    }
    if (!Array.isArray(o.via) || !o.via.length || o.via.some((v) => !VIA.has(v))) {
      err("overlap.via", `via が不正です: ${JSON.stringify(o.via)}`, at("overlaps.jsonl", i));
    }
    // 割合は「小さいほうの IOC 数」に対する共有数。件数だけで並べないための値
    const expect = Math.round((o.shared / Math.max(1, Math.min(o.a_iocs, o.b_iocs))) * 1000) / 1000;
    if (Math.abs(expect - o.ratio) > 1e-9) {
      err("overlap.ratio", `ratio が ${expect} と違います: ${o.ratio}`, at("overlaps.jsonl", i));
    }
  }
}

const graph = readJson(path.join(IN, "graph.json"));
if (graph) {
  const ids = new Set();
  for (const n of graph.nodes || []) {
    if (n.id !== `${n.kind}:${n.name}`) err("graph.node_id", `id が kind:name と違います: ${n.id}`, { file: "graph.json" });
    if (ids.has(n.id)) err("graph.node_dup", `節点が重複しています: ${n.id}`, { file: "graph.json" });
    ids.add(n.id);
    if (!entityKeys.has(`${n.kind}\t${n.name}`)) {
      err("graph.node_entity", `entities.jsonl にありません: ${n.id}`, { file: "graph.json" });
    }
  }
  const seen = new Set();
  for (const e of graph.edges || []) {
    for (const side of ["source", "target"]) {
      if (!ids.has(e[side])) err("graph.edge_end", `${side} の節点がありません: ${e[side]}`, { file: "graph.json" });
    }
    const k = `${e.source}\t${e.target}`;
    if (seen.has(k)) err("graph.edge_dup", `辺が重複しています: ${k}`, { file: "graph.json" });
    seen.add(k);
  }
  // 節点は「辺に出てくるものだけ」を載せる決まりなので、孤立節点があれば作り方が崩れている
  const used = new Set((graph.edges || []).flatMap((e) => [e.source, e.target]));
  for (const id of ids) if (!used.has(id)) err("graph.node_orphan", `辺に現れない節点があります: ${id}`, { file: "graph.json" });
}

const stats = readJson(path.join(IN, "stats.json"));
if (stats) {
  if (stats.iocs?.total !== iocs.length) {
    err("stats.total", `iocs.total が ${iocs.length} と違います: ${stats.iocs?.total}`, { file: "stats.json" });
  }
  if (overlaps) {
    for (const [kind, v] of Object.entries(stats.overlaps || {})) {
      const n = overlaps.filter((o) => o.kind === kind).length;
      if (v.pairs !== n) err("stats.pairs", `overlaps.${kind}.pairs が ${n} と違います: ${v.pairs}`, { file: "stats.json" });
    }
  }
}

const added = loadJsonl("new.jsonl", { required: false });
if (added) {
  const byKey = new Map(iocs.map((r) => [r.key, stableStringify(r, 0)]));
  for (let i = 0; i < added.length; i++) {
    const line = byKey.get(added[i].key);
    if (!line) err("new.missing", `iocs.jsonl にありません: ${added[i].key}`, at("new.jsonl", i));
    else if (line !== stableStringify(added[i], 0)) {
      err("new.mismatch", `iocs.jsonl の内容と違います: ${added[i].key}`, at("new.jsonl", i));
    }
  }
}

/* ---------------- 報告 ---------------- */

function report() {
  const errors = issues.filter((x) => x.severity === "error");
  const warns = issues.filter((x) => x.severity === "warn");

  if (!QUIET) {
    // 規則ごとにまとめる。同じ壊れ方が何百行も並ぶと読めなくなるため
    for (const severity of ["error", "warn"]) {
      const group = new Map();
      for (const x of issues.filter((y) => y.severity === severity)) {
        if (!group.has(x.rule)) group.set(x.rule, []);
        group.get(x.rule).push(x);
      }
      for (const [rule, list] of [...group].sort()) {
        const mark = severity === "error" ? "×" : "!";
        console.error(`${mark} ${rule} … ${list.length} 件`);
        for (const x of list.slice(0, SAMPLES)) {
          console.error(`    ${x.file}${x.line ? `:${x.line}` : ""}  ${x.message}`);
        }
        if (list.length > SAMPLES) console.error(`    … 他 ${list.length - SAMPLES} 件`);
      }
    }
  }

  const counts = {
    iocs: iocs?.length ?? 0,
    links: links?.length ?? 0,
    entities: entities?.length ?? 0,
    ...(overlaps ? { overlaps: overlaps.length } : {}),
  };
  console.log(
    `検査 ${path.relative(REPO_ROOT, IN)}`
    + `  IOC ${counts.iocs} / 辺 ${counts.links} / 実体 ${counts.entities}`
    + (overlaps ? ` / 重なり ${counts.overlaps}` : ""),
  );
  console.log(errors.length || warns.length
    ? `  error ${errors.length} / warn ${warns.length}`
    : "  問題なし");

  if (args.json) {
    const out = path.resolve(REPO_ROOT, args.json);
    writeJson(out, {
      tool: "tools/ioc/validate.mjs",
      schema: 1,
      target: path.relative(REPO_ROOT, IN),
      counts,
      summary: { error: errors.length, warn: warns.length },
      // 規則ごとの件数だけは常に全部残す。個票は多すぎるので上限を掛ける
      by_rule: Object.fromEntries(
        [...issues.reduce((m, x) => m.set(x.rule, (m.get(x.rule) || 0) + 1), new Map())].sort(),
      ),
      issues: issues.slice(0, Number(args["json-limit"] || 1000)),
    });
    console.log(`  → ${path.relative(REPO_ROOT, out)}`);
  }
  return { errors: errors.length, warns: warns.length };
}

const { errors, warns } = report();
if (errors) process.exit(1);
if (warns && args.strict) process.exit(1);
