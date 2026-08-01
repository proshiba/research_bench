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
import { writeJson, writeJsonl } from "./lib/io.mjs";
import { REPO_ROOT } from "./lib/sources.mjs";

const KEEP = process.argv.includes("--keep");

/* ---------------- 正しい一式を作る ---------------- */

const IOCS = [
  { key: "ioc.domain|evil.example.com", type: "ioc.domain", value: "evil.example.com",
    registrable: "example.com", sources: ["src-a"], raw: "evil[.]example[.]com" },
  { key: "ioc.domain|c2.example.com", type: "ioc.domain", value: "c2.example.com",
    registrable: "example.com", sources: ["src-a", "src-b"],
    observed_first: "2026-01-05", observed_last: "2026-02-10" },
  // 203.0.113.0/24 は文書用の予約。bogon の印が付くこと自体を検査に含める
  { key: "ioc.ipv4|203.0.113.5", type: "ioc.ipv4", value: "203.0.113.5",
    subnet: "203.0.113.0/24", bogon: true, sources: ["src-a"] },
  { key: "ioc.ipv4|45.32.10.7", type: "ioc.ipv4", value: "45.32.10.7",
    subnet: "45.32.10.0/24", sources: ["src-b"] },
  { key: "ioc.ipv4|8.8.8.8", type: "ioc.ipv4", value: "8.8.8.8",
    subnet: "8.8.8.0/24", noise: "Google DNS", sources: ["src-b"] },
  { key: "ioc.md5|" + "0".repeat(32), type: "ioc.md5", value: "0".repeat(32), sources: ["src-a"] },
  { key: "ioc.sha256|" + "1".repeat(64), type: "ioc.sha256", value: "1".repeat(64), sources: ["src-b"] },
  { key: "ioc.url|https://evil.example.com/a", type: "ioc.url", value: "https://evil.example.com/a",
    sources: ["src-a"] },
];

const LINKS = [
  { ioc: "ioc.domain|c2.example.com", kind: "actor", name: "APT-Test", source: "src-a", rel: "c2" },
  { ioc: "ioc.domain|evil.example.com", kind: "actor", name: "APT-Test", source: "src-a", rel: "c2" },
  { ioc: "ioc.ipv4|45.32.10.7", kind: "actor", name: "APT-Test", source: "src-b", rel: null },
  { ioc: "ioc.ipv4|45.32.10.7", kind: "actor", name: "Other Group", source: "src-b", rel: null },
  { ioc: "ioc.md5|" + "0".repeat(32), kind: "malware", name: "TestRAT", source: "src-a", rel: "sample" },
  { ioc: "ioc.sha256|" + "1".repeat(64), kind: "malware", name: "TestRAT", source: "src-b", rel: "sample" },
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
  ["entity.qualifier", "但し書きが実体として残っている", (d) => {
    editLine(d, "links.jsonl", "Other Group", (l) => l.replace(/"name":"Other Group"/, '"name":"medium-to-high confidence"'));
    editLine(d, "entities.jsonl", "Other Group", (l) => l.replace(/"name":"Other Group"/, '"name":"medium-to-high confidence"'));
  }, "warn"],
  ["entity.parens", "括弧が閉じていない名前", (d) => {
    editLine(d, "links.jsonl", "Other Group", (l) => l.replace(/"name":"Other Group"/, '"name":"Other Group (OG"'));
    editLine(d, "entities.jsonl", "Other Group", (l) => l.replace(/"name":"Other Group"/, '"name":"Other Group (OG"'));
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
  ["file.missing", "ファイルが欠けている", (d) => {
    fs.rmSync(path.join(d, "entities.jsonl"));
  }],
  ["json.parse", "JSON として壊れている", (d) => {
    editLine(d, "iocs.jsonl", "evil.example.com", (l) => l.slice(0, -3));
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
