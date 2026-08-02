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
import { entityNames, nameKey, pickAliases, splitNames, usableName } from "./lib/names.mjs";

const args = parseArgs(process.argv.slice(2));
const OUT = path.resolve(REPO_ROOT, args.out || "data/ioc/latest");

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
      // 索引側にも但し書きや、区切りで切れた断片が実体として載っていることがある。
      // 代表名にしない（`N/A` が `A` と `N` という実体になっていた索引が実在する）
      if (!usableName(rep)) continue;
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
      // アクターと同じ扱い。表示名に但し書きや別名が同じ欄で入っていることがある
      // （`BlazeTrack（暫定クラスタ）` `Atomic macOS Stealer（AMOS、…）`）
      const rep = splitNames(e.label)[0] || "";
      if (!usableName(rep)) continue;
      const k = nameKey(rep);
      if (!canonMalware.has(k)) canonMalware.set(k, rep);
    }
  }

  /* ---- 2. 実体の表示名。refs の target（actor:xxx）から名前を引くため ---- */

  const labelById = new Map();    // "app_id\tid" → label
  const entityById = new Map();   // "app_id\tid" → 実体（1 段先を辿るため）
  for (const s of sources) {
    for (const e of s.entities) {
      if (!e.id) continue;
      labelById.set(`${s.app_id}\t${e.id}`, e.label || e.id);
      entityById.set(`${s.app_id}\t${e.id}`, e);
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

  /**
   * ケースの先にあるアクター・マルウェアを IOC に繋ぐ。
   *
   * マルウェア解析の索引は**ファミリ名を IOC ではなくケースに付けている**。
   *   `ioc.domain|… ─[Winos control channel]→ case:ee0ef… ─[ファミリ]→ malware ValleyRAT`
   * IOC の refs だけを見ていると、この 1 段先に届かずファミリ名を取りこぼす
   * （実測で 647 組）。**1 段だけ**辿る。再帰させると、ケースを介して無関係な
   * IOC 同士が繋がる。
   */
  function hopThrough(iocKey, targetId, source) {
    const via = entityById.get(`${source.app_id}\t${targetId}`);
    if (!via) return;
    for (const r of via.refs || []) {
      if (r._broken) { brokenSkipped++; continue; }
      const t = String(r.target || "");
      const k = t.split(":")[0];
      if (k !== "actor" && k !== "malware" && k !== "tool" && k !== "family") continue;
      const next = entityById.get(`${source.app_id}\t${t}`);
      const raw = next?.label || labelById.get(`${source.app_id}\t${t}`) || t.slice(k.length + 1);
      // ファミリ名にも但し書きや別名が同じ欄に入っている
      // （`Atomic macOS Stealer（AMOS、アトミックmacOSスティーラー）`）。他と同じ処理を通す
      const label = splitNames(raw)[0] || "";
      // 参照先の型を見る。`family:` の id でも中身は malware というつくりがある
      const isActor = (next?.type || k) === "actor";
      const canon = isActor ? canonActor : canonMalware;
      if (!usableName(label, canon)) continue;
      // どこを経由したかを rel に残す。直接の辺と見分けが付くように
      addLink(iocKey, isActor ? "actor" : "malware", canon.get(nameKey(label)) || label,
        { source: source.app_id, rel: `${via.type}.${r.rel}`, id: t });
    }
  }

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
        if (kind === "actor" || kind === "malware" || kind === "tool") {
          // 索引に実体として載っていても、名前として成立していないものは辺にしない。
          // ここを通さないと `malware:a` `malware:n` のようなものが最大の実体になる
          const canon = kind === "actor" ? canonActor : canonMalware;
          if (!usableName(label, canon)) continue;
          addLink(key, kind === "actor" ? "actor" : "malware", canon.get(nameKey(label)) || label,
            { source: s.app_id, rel: r.rel, id: target });
        } else if (kind === "campaign") {
          addLink(key, "campaign", label, { source: s.app_id, rel: r.rel, id: target });
        } else if (kind === "case") {
          addLink(key, "case", target, { source: s.app_id, rel: r.rel, id: target });
          hopThrough(key, target, s);
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
