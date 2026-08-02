#!/usr/bin/env node
// 4 ソースの索引から IOC を集め、正規化して書き出す。
//
//   node tools/ioc/collect.mjs [--out data/ioc/latest] [--from <写しの場所>]
//                              [--cache <保存先>] [--week 2026-W31]
//
// 外部サービスは一切呼ばない。索引を読むだけなので数秒で終わる。
//
// 出力（すべて決定的：同じ索引からは同じバイト列になる）
//   iocs.jsonl      1 行 1 IOC。値・種別・出典・日付・/24・除外の印
//   links.jsonl     IOC ↔ 実体（アクター / マルウェア / キャンペーン / ケース / 記事 / IOC）
//   entities.jsonl  実体の正規形。アクターは別名を畳んだ代表名
//   meta.json       実行時刻・取得元・ハッシュ・件数（**唯一、実行ごとに変わるファイル**）
//
// 別名の解決がこの工程の肝。アクター情報が公開している aliases で名前を代表名に寄せる。
// 寄せないと「アクター間の重なり」の上位が同一アクターの別名で埋まる。

import path from "node:path";
import { joinKey, refang } from "../../assets/js/util.js";
import { byKeys, isoWeek, parseArgs, writeJson, writeJsonl } from "./lib/io.mjs";
import { classifyIpv4, classifyIpv6, registrableDomain, subnet24 } from "./lib/net.mjs";
import { REPO_ROOT, loadAll } from "./lib/sources.mjs";

const args = parseArgs(process.argv.slice(2));
const OUT = path.resolve(REPO_ROOT, args.out || "data/ioc/latest");

/** 名前を突き合わせるための鍵。表記ゆれ（記号・大小・空白）を落とす。 */
const nameKey = (s) => String(s ?? "").trim().toLowerCase().replace(/[^a-z0-9]+/g, "");

/**
 * 名前ではなく確度の但し書きだったもの。実体として数えると
 * 「medium-to-high confidence」というアクターが生まれてしまう。
 */
const QUALIFIER = new Set([
  "suspected", "possible", "likely", "probable", "unknown", "unattributed",
  "unclear", "na", "tbd", "none", "multipleactors", "multiple", "various",
]);
const isQualifier = (s) => {
  const k = nameKey(s);
  if (!k) return true;
  if (QUALIFIER.has(k)) return true;
  // 「high confidence」「low-medium confidence」など
  return /confidence$/.test(k) || /^aka/.test(k);
};

/**
 * 値を複数入れられる欄（「A, B」「A、B」）を分ける。
 *
 * 元データに **閉じ括弧が落ちている**ものがある
 * （`"Qilin, TAG-195 (Golden Chickens, Venom Spider"` のように）。
 * 括弧の中身はたいてい別名か但し書きなので、対応する `)` が無ければ
 * `(` から後ろを捨てる。捨てた別名は別名表で同じ代表名に寄るので損はしない。
 */
const count = (s, re) => (s.match(re) || []).length;

/**
 * 分割で片方だけ残った括弧を整える。
 *
 * 対になっている括弧は名前の一部（`GRU GTsST (Main Center for Special Technology)`）
 * なので残す。片方だけ残ったものは区切りで切れた跡なので落とす。
 * ここを一律に「先頭と末尾の括弧を削る」でやると、対になっている名前を壊す。
 */
function fixParens(v) {
  let s = v.trim();
  while (count(s, /\(/g) > count(s, /\)/g)) s = s.slice(0, s.lastIndexOf("(")).trim();
  while (count(s, /\)/g) > count(s, /\(/g)) s = s.replace(")", "").trim();
  if (/^\([^()]*\)$/.test(s)) s = s.slice(1, -1).trim();   // 全体がくくられているだけなら外す
  return s;
}

function splitNames(s) {
  let v = String(s ?? "");
  if (count(v, /\(/g) > count(v, /\)/g)) v = v.slice(0, v.indexOf("("));
  return v
    .split(/[,、;／/]+/)
    .map((x) => fixParens(x.replace(/^[\s"'「『]+|[\s"'」』]+$/g, "")))
    .filter(Boolean);
}

/** 実体名として使えるものだけ返す。既知のアクター名なら但し書き判定より優先する。 */
function entityNames(raw, known) {
  const out = [];
  for (const n of splitNames(raw)) {
    if (known?.has(nameKey(n))) { out.push(n); continue; }
    if (isQualifier(n)) continue;
    if (nameKey(n).length < 2) continue;
    out.push(n);
  }
  return out;
}

/**
 * 表示用の別名一覧を作る。
 *
 * 索引は同じ名前を id（小文字）と表示名の両方で載せていることが多く、そのまま並べると
 * 「APT1 の別名は apt1」のような中身の無い行が並ぶ。突き合わせは名前鍵で行うので、
 * 同じ鍵に潰れるものは 1 つに絞ってよい。大文字を含む表記のほうが情報が多いので残す。
 */
function pickAliases(set, rep) {
  const repKey = nameKey(rep);
  const best = new Map();   // 名前鍵 → 表記
  for (const a of [...set].sort()) {
    const k = nameKey(a);
    if (!k || k === repKey) continue;
    const cur = best.get(k);
    if (!cur || (/[A-Z]/.test(a) && !/[A-Z]/.test(cur))) best.set(k, a);
  }
  return [...best.values()].sort();
}

const isIoc = (t) => String(t || "").startsWith("ioc.");

async function main() {
  const sources = await loadAll({ from: args.from, cache: args.cache });
  const failed = sources.filter((s) => s.error);
  for (const f of failed) console.error(`! ${f.app_id}: ${f.error}`);

  /* ---- 1. 別名表。アクター実体の label / detail / aliases を代表名へ寄せる ---- */

  const canonActor = new Map();   // 名前鍵 → 代表名
  const actorAliases = new Map(); // 代表名 → 別名の集合
  for (const s of sources) {
    for (const e of s.entities) {
      if (e.type !== "actor") continue;
      // 表示名にも「A, B (C」のように複数入っていることがある。先頭を代表名にし、
      // 残りは別名として登録する。括弧が閉じていない表記もここで落ちる
      const parts = splitNames(e.label);
      const rep = parts[0] || "";
      // 索引側にも但し書きが実体として載っていることがある
      // （ニュースの「アクター」欄から起こされたもの）。代表名にしない
      if (!rep || isQualifier(rep)) continue;
      // 別名欄にも「A, B, C」と 1 つにまとめて入っているものがある。分けておかないと
      // その並び全体が 1 個の別名になり、どの名前とも突き合わない
      const names = [...parts, ...splitNames(e.detail), ...(e.aliases || []).flatMap((a) => splitNames(a))];
      // 既に別ソースで代表名が決まっていればそちらを優先（アクター情報が先に来る）
      const known = names.map(nameKey).find((k) => canonActor.has(k));
      const use = known ? canonActor.get(known) : rep;
      if (!actorAliases.has(use)) actorAliases.set(use, new Set());
      for (const n of names) {
        const k = nameKey(n);
        if (!k) continue;
        canonActor.set(k, use);
        if (String(n).trim() !== use) actorAliases.get(use).add(String(n).trim());
      }
    }
  }

  /** マルウェアも同じ扱い。ただし別名の公開が無いので表記ゆれの吸収だけ。 */
  const canonMalware = new Map();
  for (const s of sources) {
    for (const e of s.entities) {
      if (e.type !== "malware" && e.type !== "tool") continue;
      const rep = String(e.label || "").trim();
      if (!rep || isQualifier(rep)) continue;
      const k = nameKey(rep);
      if (!canonMalware.has(k)) canonMalware.set(k, rep);
    }
  }

  /* ---- 2. 実体の表示名。refs の target（actor:xxx）から名前を引くため ---- */

  const labelById = new Map();    // "app_id\tid" → label
  for (const s of sources) {
    for (const e of s.entities) {
      if (e.id) labelById.set(`${s.app_id}\t${e.id}`, e.label || e.id);
    }
  }

  /* ---- 3. IOC を集める ---- */

  const iocs = new Map();         // key → レコード
  const links = new Map();        // 重複を畳むための鍵 → レコード
  let brokenSkipped = 0;          // 参照先が選ばれていないため辿らなかった辺

  const addLink = (iocKey, kind, name, { source, rel, id }) => {
    const n = String(name ?? "").trim();
    if (!n) return;
    const k = `${iocKey}\t${kind}\t${n}\t${source}\t${rel || ""}`;
    if (!links.has(k)) {
      links.set(k, { ioc: iocKey, kind, name: n, source, rel: rel || null, ...(id ? { id } : {}) });
    }
  };

  for (const s of sources) {
    for (const e of s.entities) {
      if (!isIoc(e.type)) continue;
      const rawValue = e.value || e.label || "";
      const jk = joinKey(e.type, rawValue);
      if (!jk) continue;
      const key = `${e.type}|${jk}`;
      const value = refang(String(rawValue)).trim();

      if (!iocs.has(key)) {
        const rec = { key, type: e.type, value: jk, sources: new Set() };
        // 表示用の元表記が正規化と違うときだけ残す（defang 表記など）
        if (value !== jk) rec.raw = value;
        if (e.type === "ioc.ipv4") {
          const c = classifyIpv4(jk);
          if (!c.valid) rec.malformed = true;
          if (c.bogon) rec.bogon = true;
          if (c.noise) rec.noise = c.noise;
          const net = subnet24(jk);
          if (net) rec.subnet = net;
        } else if (e.type === "ioc.ipv6") {
          const c = classifyIpv6(jk);
          if (!c.valid) rec.malformed = true;
          if (c.bogon) rec.bogon = true;
        } else if (e.type === "ioc.domain") {
          const rd = registrableDomain(jk);
          if (rd) rec.registrable = rd;
        }
        iocs.set(key, rec);
      }
      const rec = iocs.get(key);
      rec.sources.add(s.app_id);

      /* 日付。今のところニュースだけが持っている */
      for (const [field, into] of [["観測日", "observed"], ["収集日", "collected"]]) {
        for (const d of splitNames(e.attrs?.[field])) {
          if (!/^\d{4}-\d{2}-\d{2}$/.test(d)) continue;
          rec[`${into}_first`] = rec[`${into}_first`] ? (d < rec[`${into}_first`] ? d : rec[`${into}_first`]) : d;
          rec[`${into}_last`] = rec[`${into}_last`] ? (d > rec[`${into}_last`] ? d : rec[`${into}_last`]) : d;
        }
      }
      /* 属性から取れる分類・確度・役割 */
      for (const [field, into] of [["分類", "classes"], ["役割", "roles"], ["確度", "confidence"]]) {
        for (const v of splitNames(e.attrs?.[field])) {
          rec[into] = rec[into] || new Set();
          rec[into].add(v);
        }
      }

      /* refs から実体への辺 */
      for (const r of e.refs || []) {
        // 参照先が固定されている関係は辿らない（lib/refs.mjs）。
        // 「収集元」がその日の 1 本目の記事に固定されている索引が実在する
        if (r._broken) { brokenSkipped++; continue; }
        const target = String(r.target || "");
        const kind = target.split(":")[0];
        if (isIoc(kind) || target.includes("|")) {
          // 索引によっては IOC 同士を結ぶ（ドメイン → ホスト IP など）
          addLink(key, "ioc", target, { source: s.app_id, rel: r.rel });
          continue;
        }
        const label = labelById.get(`${s.app_id}\t${target}`) || target.slice(kind.length + 1);
        if (kind === "actor") {
          addLink(key, "actor", canonActor.get(nameKey(label)) || label, { source: s.app_id, rel: r.rel, id: target });
        } else if (kind === "malware" || kind === "tool") {
          addLink(key, "malware", canonMalware.get(nameKey(label)) || label, { source: s.app_id, rel: r.rel, id: target });
        } else if (kind === "campaign") {
          addLink(key, "campaign", label, { source: s.app_id, rel: r.rel, id: target });
        } else if (kind === "case") {
          addLink(key, "case", target, { source: s.app_id, rel: r.rel, id: target });
        } else if (kind === "article" || kind === "report") {
          addLink(key, "article", target, { source: s.app_id, rel: r.rel, id: target });
        }
      }

      /* 属性に名前で入っている分（ニュースはこちら） */
      for (const n of entityNames(e.attrs?.アクター, canonActor)) {
        addLink(key, "actor", canonActor.get(nameKey(n)) || n, { source: s.app_id, rel: "attrs.アクター" });
      }
      for (const n of entityNames(e.attrs?.マルウェア, canonMalware)) {
        addLink(key, "malware", canonMalware.get(nameKey(n)) || n, { source: s.app_id, rel: "attrs.マルウェア" });
      }
      for (const n of splitNames(e.attrs?.関連CVE)) {
        if (/^CVE-\d{4}-\d+$/i.test(n)) addLink(key, "cve", n.toUpperCase(), { source: s.app_id, rel: "attrs.関連CVE" });
      }
    }
  }

  /* ---- 4. 実体一覧 ---- */

  const entities = new Map();
  const touchEntity = (kind, name) => {
    const k = `${kind}\t${name}`;
    if (!entities.has(k)) entities.set(k, { kind, name, ioc_count: 0, sources: new Set() });
    return entities.get(k);
  };
  for (const l of links.values()) {
    if (l.kind === "ioc") continue;
    const ent = touchEntity(l.kind, l.name);
    ent.sources.add(l.source);
  }
  // IOC 数は「その実体に繋がる相異なる IOC」で数える
  const perEntity = new Map();
  for (const l of links.values()) {
    if (l.kind === "ioc") continue;
    const k = `${l.kind}\t${l.name}`;
    if (!perEntity.has(k)) perEntity.set(k, new Set());
    perEntity.get(k).add(l.ioc);
  }
  for (const [k, set] of perEntity) entities.get(k).ioc_count = set.size;
  for (const [rep, aliases] of actorAliases) {
    const ent = entities.get(`actor\t${rep}`);
    if (!ent) continue;
    const list = pickAliases(aliases, rep);
    if (list.length) ent.aliases = list;
  }

  /* ---- 5. 書き出し ---- */

  const iocRows = [...iocs.values()]
    .map((r) => ({
      ...r,
      sources: [...r.sources].sort(),
      ...(r.classes ? { classes: [...r.classes].sort() } : {}),
      ...(r.roles ? { roles: [...r.roles].sort() } : {}),
      ...(r.confidence ? { confidence: [...r.confidence].sort() } : {}),
    }))
    .sort(byKeys("type", "value"));

  const linkRows = [...links.values()].sort(byKeys("ioc", "kind", "name", "source", "rel"));

  const entityRows = [...entities.values()]
    .map((e) => ({ ...e, sources: [...e.sources].sort() }))
    .sort(byKeys("kind", "name"));

  writeJsonl(path.join(OUT, "iocs.jsonl"), iocRows);
  writeJsonl(path.join(OUT, "links.jsonl"), linkRows);
  writeJsonl(path.join(OUT, "entities.jsonl"), entityRows);

  const byType = {};
  for (const r of iocRows) byType[r.type] = (byType[r.type] || 0) + 1;
  const bySource = {};
  for (const r of iocRows) for (const s of r.sources) bySource[s] = (bySource[s] || 0) + 1;
  const byKind = {};
  for (const e of entityRows) byKind[e.kind] = (byKind[e.kind] || 0) + 1;

  const now = args.now ? new Date(args.now) : new Date();
  writeJson(path.join(OUT, "meta.json"), {
    tool: "tools/ioc/collect.mjs",
    schema: 1,
    collected_at: now.toISOString(),
    week: args.week || isoWeek(now),
    sources: sources.map((s) => ({
      app_id: s.app_id,
      name: s.name,
      search_url: s.search_url || null,
      generated_at: s.generated_at || null,
      meta_sha256: s.meta_sha256 || null,
      search_sha256: s.search_sha256 || null,
      entities: s.entities.length,
      error: s.error || null,
      // 参照先が選ばれていない関係。索引側の不具合なので、直ったら消える
      broken_rels: s.broken_rels || null,
    })).sort(byKeys("app_id")),
    counts: {
      iocs: iocRows.length,
      links: linkRows.length,
      entities: entityRows.length,
      by_type: byType,
      by_source: bySource,
      by_entity_kind: byKind,
      excluded: {
        bogon: iocRows.filter((r) => r.bogon).length,
        noise: iocRows.filter((r) => r.noise).length,
        malformed: iocRows.filter((r) => r.malformed).length,
      },
    },
  });

  console.log(`IOC ${iocRows.length} / 辺 ${linkRows.length} / 実体 ${entityRows.length}`);
  const brokenRels = sources.flatMap((s) => Object.entries(s.broken_rels || {}));
  if (brokenRels.length) {
    console.log(`  ! 参照先が選ばれていない関係を辿りませんでした（索引側の不具合）:`);
    for (const [rel, n] of brokenRels) console.log(`      「${rel}」 ${n} 件`);
  }
  console.log(`  除外の印: bogon ${iocRows.filter((r) => r.bogon).length}`
    + ` / noise ${iocRows.filter((r) => r.noise).length}`
    + ` / 壊れ ${iocRows.filter((r) => r.malformed).length}`);
  console.log(`  → ${path.relative(REPO_ROOT, OUT)}`);
  if (failed.length) process.exitCode = 1;
}

main().catch((err) => {
  console.error(err.stack || err.message);
  process.exit(1);
});
