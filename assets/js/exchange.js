// ワークベンチのグラフを Mermaid / STIX 2.1 として書き出し、読み込む。
//
// Mermaid は「持ち出したあとも関係が見える」ことを目的にした形式で、
// 色と形をポータルの符号化に合わせた classDef 付きで出す。
// STIX 2.1 は他ツールに渡すための形式。
//
// どちらも `%% rb:` コメント / `x_rb_*` プロパティに種別と値を残すので、
// 読み込み直したときに元の構造まで戻せる。これらが無いファイル（他所で
// 手書きした Mermaid など）でも、ラベルから種別を推定して読み込む。

import { TYPE_GROUPS, detectType, typeGroup } from "./util.js";

const SPEC_VERSION = 1;

/* ---------------- Mermaid ---------------- */

// 種別グループ → Mermaid のノード形。Canvas 側の形と近いものを選ぶ。
const MERMAID_SHAPE = {
  network: ["((", "))"],      // 円
  host: ["{{", "}}"],         // 六角形
  file: ["[", "]"],           // 四角
  malware: ["[/", "/]"],      // 平行四辺形（三角に近い尖り）
  actor: ["{", "}"],          // 菱形
  vuln: ["[[", "]]"],         // 二重四角（五角形の代替）
  context: ["([", "])"],      // 角丸
  other: ["(", ")"],          // 丸括弧
};

const CLASS_NAME = { network: "rbNetwork", host: "rbHost", file: "rbFile", malware: "rbMalware",
  actor: "rbActor", vuln: "rbVuln", context: "rbContext", other: "rbOther" };

/** Mermaid のラベルに入れられる形にする。 */
function mmLabel(text) {
  return String(text)
    .replace(/"/g, "#quot;")
    .replace(/[[\]{}()]/g, (c) => `#${c.charCodeAt(0)};`)
    .replace(/\r?\n/g, " ");
}

function attr(key, value) {
  return `${key}=${encodeURIComponent(String(value ?? ""))}`;
}

function parseAttrs(rest) {
  const out = {};
  for (const token of String(rest).trim().split(/\s+/)) {
    const i = token.indexOf("=");
    if (i > 0) out[token.slice(0, i)] = decodeURIComponent(token.slice(i + 1));
  }
  return out;
}

/**
 * グラフを Mermaid の flowchart にする。
 * @param {{nodes: Map, edges: Map}} graph
 * @param {(varName: string) => string} colorOf CSS 変数名 → 実際の色
 */
export function toMermaid({ nodes, edges }, colorOf) {
  const ids = new Map();
  [...nodes.keys()].forEach((k, i) => ids.set(k, `n${i}`));

  const lines = [
    "%% research_bench workbench export",
    `%% rb:version ${SPEC_VERSION}`,
    "%% このファイルはワークベンチの「読み込み」からそのまま戻せます。",
    "flowchart LR",
  ];

  const byClass = new Map();
  for (const node of nodes.values()) {
    const id = ids.get(node.id);
    const group = typeGroup(node.type);
    const [open, close] = MERMAID_SHAPE[group] || MERMAID_SHAPE.other;
    const manualOnly = node.members.length > 0
      && node.members.every((m) => m.source.app_id === "__manual");

    // 値（実体を指すもの）と表示名は別に出す。同じなら label は省く
    const value = node.value ?? node.label;
    lines.push("%% rb:node " + [
      attr("id", id), attr("type", node.type), attr("value", value),
      ...(node.label !== value ? [attr("label", node.label)] : []),
      attr("sources", [...node.sources].join(",")), attr("manual", manualOnly ? 1 : 0),
    ].join(" "));
    lines.push(`    ${id}${open}"${mmLabel(node.label)}"${close}`);

    if (!byClass.has(group)) byClass.set(group, []);
    byClass.get(group).push(id);
  }

  for (const e of edges.values()) {
    const a = ids.get(e.a), b = ids.get(e.b);
    if (!a || !b) continue;
    const rel = [...e.rels][0] || "関連";
    // 手動リンクは太線、ソース横断は点線、ソース由来は実線
    const arrow = e.manual ? "==>" : e.cross ? "-.->" : "-->";
    const from = e.manual && ids.get(e.from) ? ids.get(e.from) : a;
    const to = from === a ? b : a;
    lines.push("%% rb:edge " + [
      attr("from", from), attr("to", to), attr("rel", rel),
      attr("manual", e.manual ? 1 : 0), attr("cross", e.cross ? 1 : 0),
    ].join(" "));
    lines.push(`    ${from} ${arrow}|"${mmLabel(rel)}"| ${to}`);
  }

  // 色はポータルと同じものを埋め込む。持ち出した先でも符号化が保たれるように。
  lines.push("");
  for (const [group, members] of byClass) {
    const color = colorOf(TYPE_GROUPS[group].color) || "#888888";
    lines.push(`    classDef ${CLASS_NAME[group]} fill:${color}33,stroke:${color},stroke-width:1.5px;`);
    lines.push(`    class ${members.join(",")} ${CLASS_NAME[group]};`);
  }
  return lines.join("\n") + "\n";
}

/** Mermaid を読む。`rb:` コメントがあればそれを使い、無ければラベルから推定する。 */
export function fromMermaid(text) {
  const nodeMeta = new Map();   // mermaid id → { type, value, sources, manual }
  const edgeMeta = [];
  const declared = new Map();   // mermaid id → ラベル
  const edges = [];

  const unlabel = (s) => String(s)
    .replace(/^"|"$/g, "")
    .replace(/#quot;/g, '"')
    .replace(/#(\d+);/g, (_, c) => String.fromCharCode(Number(c)));

  for (const raw of String(text).split(/\r?\n/)) {
    const line = raw.trim();
    if (!line) continue;

    if (line.startsWith("%%")) {
      const m = line.match(/^%%\s*rb:(node|edge)\s+(.*)$/);
      if (!m) continue;
      const a = parseAttrs(m[2]);
      if (m[1] === "node" && a.id) nodeMeta.set(a.id, a);
      else if (m[1] === "edge" && a.from && a.to) edgeMeta.push(a);
      continue;
    }
    if (/^(flowchart|graph)\b/.test(line)) continue;
    if (/^(classDef|class|style|linkStyle|subgraph|end)\b/.test(line)) continue;

    // 辺: A -->|ラベル| B / A ==> B / A -.->|…| B
    const edge = line.match(/^([A-Za-z0-9_-]+)\s*(-{2,3}>|={2,3}>|-\.->|-\.-|---)\s*(?:\|([^|]*)\|)?\s*([A-Za-z0-9_-]+)/);
    if (edge) {
      edges.push({ from: edge[1], to: edge[4], rel: unlabel(edge[3] || ""), arrow: edge[2] });
      continue;
    }

    // ノード宣言: id["ラベル"] / id(("…")) / id{{"…"}} など
    const decl = line.match(/^([A-Za-z0-9_-]+)\s*(\(\(|\{\{|\[\[|\(\[|\[\/|\[|\{|\()\s*(.*?)\s*(\)\)|\}\}|\]\]|\]\)|\/\]|\]|\}|\))\s*;?$/);
    if (decl) {
      declared.set(decl[1], unlabel(decl[3]));
      continue;
    }
    const bare = line.match(/^([A-Za-z0-9_-]+)\s*;?$/);
    if (bare && !declared.has(bare[1])) declared.set(bare[1], bare[1]);
  }

  const nodes = [];
  const seen = new Set([...declared.keys(), ...nodeMeta.keys()]);
  for (const id of seen) {
    const meta = nodeMeta.get(id) || {};
    const value = meta.value || declared.get(id) || id;
    // 表示名は `rb:node` の label があればそれ、無ければ描画側のラベル
    const label = meta.label || (declared.get(id) !== value ? declared.get(id) : null);
    nodes.push({
      key: id,
      value,
      type: meta.type || detectType(value) || "report",
      manual: meta.manual === "1",
      ...(label ? { label } : {}),
    });
  }

  const outEdges = edgeMeta.length
    ? edgeMeta.map((a) => ({
      from: a.from, to: a.to, rel: a.rel || "関連",
      manual: a.manual === "1", cross: a.cross === "1",
    }))
    : edges.map((e) => ({
      from: e.from, to: e.to, rel: e.rel || "関連",
      manual: e.arrow.startsWith("="), cross: e.arrow.includes("."),
    }));

  return { format: "mermaid", nodes, edges: outEdges };
}

/* ---------------- STIX 2.1 ---------------- */

// 種別 → STIX のオブジェクト型。`x-rb-` は STIX の独自型の書き方。
const STIX_TYPE = {
  "ioc.ipv4": "ipv4-addr", "ioc.ipv6": "ipv6-addr",
  "ioc.domain": "domain-name", "ioc.url": "url", "ioc.email": "email-addr",
  "ioc.md5": "file", "ioc.sha1": "file", "ioc.sha256": "file", "ioc.sha512": "file",
  case: "file",
  "ioc.endpoint": "x-rb-endpoint",
  cve: "vulnerability", report: "vulnerability",
  product: "software", vendor: "identity",
  actor: "intrusion-set", malware: "malware", tool: "tool",
  campaign: "campaign", ttp: "attack-pattern",
};

const HASH_KEY = { "ioc.md5": "MD5", "ioc.sha1": "SHA-1", "ioc.sha256": "SHA-256", "ioc.sha512": "SHA-512", case: "SHA-256" };

/** 文字列から決め打ちの UUID を作る。再書き出しでも同じ id になるように。 */
function uuidFrom(seed) {
  let h1 = 0x9e3779b9, h2 = 0x85ebca6b, h3 = 0xc2b2ae35, h4 = 0x27d4eb2f;
  const s = String(seed);
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    h1 = Math.imul(h1 ^ c, 0x85ebca6b) >>> 0;
    h2 = Math.imul(h2 + c, 0xc2b2ae35) >>> 0;
    h3 = (h3 ^ Math.imul(h1 + i, 0x27d4eb2f)) >>> 0;
    h4 = (h4 + Math.imul(h2 ^ i, 0x165667b1)) >>> 0;
  }
  const hex = [h1, h2, h3, h4].map((x) => x.toString(16).padStart(8, "0")).join("");
  // バージョン 4 / バリアント bits を立てて UUID の体裁にする
  const v = "4" + hex.slice(13, 16);
  const w = ((parseInt(hex[16], 16) & 0x3) | 0x8).toString(16) + hex.slice(17, 20);
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${v}-${w}-${hex.slice(20, 32)}`;
}

export function toStix({ nodes, edges }) {
  const objects = [];
  const stixId = new Map();
  const now = new Date().toISOString().replace(/\.\d+Z$/, ".000Z");

  for (const node of nodes.values()) {
    const type = STIX_TYPE[node.type] || "x-rb-observable";
    const id = `${type}--${uuidFrom(node.id)}`;
    stixId.set(node.id, id);

    // 値（実体を指すもの）と表示名は別。`report` は label が見出しで value が URL
    const value = node.value ?? node.label;
    const obj = { type, spec_version: "2.1", id };
    // SDO には作成/更新時刻が要る。SCO には付けない。
    const isSdo = ["vulnerability", "intrusion-set", "malware", "tool", "campaign",
      "attack-pattern", "identity", "x-rb-observable"].includes(type);
    if (isSdo) { obj.created = now; obj.modified = now; }

    if (type === "file") {
      obj.hashes = { [HASH_KEY[node.type] || "SHA-256"]: value };
    } else if (["ipv4-addr", "ipv6-addr", "domain-name", "url", "email-addr", "software",
      "x-rb-endpoint", "x-rb-observable"].includes(type)) {
      obj.value = value;
      if (type === "software") { obj.name = node.label; delete obj.value; }
    } else {
      obj.name = node.label;
    }
    if (type === "malware") obj.is_family = true;
    if (type === "vulnerability" && /^CVE-/i.test(value)) {
      obj.external_references = [{ source_name: "cve", external_id: value.toUpperCase() }];
    }
    if (type === "attack-pattern" && /^T\d{4}/i.test(value)) {
      obj.external_references = [{ source_name: "mitre-attack", external_id: value.toUpperCase() }];
    }
    if (type === "identity") obj.identity_class = "organization";

    // 読み込み直したときに元の種別へ戻せるようにする
    obj.x_rb_type = node.type;
    obj.x_rb_value = value;
    if (node.label !== value) obj.x_rb_label = node.label;
    const sources = [...node.sources].filter((s) => s !== "__manual");
    if (sources.length) obj.x_rb_sources = sources;
    if (!sources.length) obj.x_rb_manual = true;

    objects.push(obj);
  }

  for (const e of edges.values()) {
    const from = e.manual && stixId.get(e.from) ? e.from : e.a;
    const to = from === e.a ? e.b : e.a;
    const src = stixId.get(from), tgt = stixId.get(to);
    if (!src || !tgt) continue;
    const rel = [...e.rels][0] || "関連";
    objects.push({
      type: "relationship",
      spec_version: "2.1",
      id: `relationship--${uuidFrom(`${from}|${to}|${rel}`)}`,
      created: now,
      modified: now,
      // STIX の語彙に無い日本語のラベルは description に残し、型は related-to にする
      relationship_type: "related-to",
      description: rel,
      source_ref: src,
      target_ref: tgt,
      x_rb_rel: rel,
      ...(e.manual ? { x_rb_manual: true } : {}),
      ...(e.cross ? { x_rb_cross: true } : {}),
    });
  }

  return {
    type: "bundle",
    id: `bundle--${uuidFrom("rb-workbench-" + [...nodes.keys()].join("|"))}`,
    objects,
  };
}

export function fromStix(doc) {
  const objects = Array.isArray(doc?.objects) ? doc.objects : [];
  const byId = new Map();
  const nodes = [];

  for (const o of objects) {
    if (!o || o.type === "relationship" || o.type === "bundle") continue;
    const value = o.x_rb_value
      || o.value
      || o.name
      || (o.hashes && (o.hashes["SHA-256"] || o.hashes["SHA-1"] || o.hashes.MD5 || o.hashes["SHA-512"]))
      || o.external_references?.find((r) => r.external_id)?.external_id;
    if (!value) continue;
    const type = o.x_rb_type || detectType(value) || stixTypeToPortal(o.type) || "report";
    const label = o.x_rb_label || (o.name && o.name !== value ? o.name : null);
    byId.set(o.id, value);
    nodes.push({ key: o.id, value, type, manual: !!o.x_rb_manual, ...(label ? { label } : {}) });
  }

  const edges = [];
  for (const o of objects) {
    if (o?.type !== "relationship") continue;
    if (!byId.has(o.source_ref) || !byId.has(o.target_ref)) continue;
    edges.push({
      from: o.source_ref,
      to: o.target_ref,
      rel: o.x_rb_rel || o.description || o.relationship_type || "関連",
      manual: !!o.x_rb_manual,
      cross: !!o.x_rb_cross,
    });
  }

  return { format: "stix", nodes, edges };
}

function stixTypeToPortal(stixType) {
  const back = {
    "ipv4-addr": "ioc.ipv4", "ipv6-addr": "ioc.ipv6", "domain-name": "ioc.domain",
    url: "ioc.url", "email-addr": "ioc.email", file: "ioc.sha256",
    vulnerability: "cve", "intrusion-set": "actor", "threat-actor": "actor",
    malware: "malware", tool: "tool", campaign: "campaign", "attack-pattern": "ttp",
    software: "product", identity: "vendor", "x-rb-endpoint": "ioc.endpoint",
  };
  return back[stixType] || null;
}

/* ---------------- 判別 ---------------- */

/** 拡張子や中身から形式を見分けて読み込む。 */
export function parseAny(text, filename = "") {
  const trimmed = String(text).trim();
  if (!trimmed) throw new Error("中身が空です");
  if (trimmed.startsWith("{") || /\.json$/i.test(filename)) {
    let doc;
    try {
      doc = JSON.parse(trimmed);
    } catch (err) {
      // JSON.parse の文言はそのままだと利用者に意味が通らない
      throw new Error(`JSON として読めません（${err.message}）`);
    }
    if (doc?.type === "bundle" || Array.isArray(doc?.objects)) return fromStix(doc);
    throw new Error("STIX の bundle ではありません（objects 配列が見つかりません）");
  }
  if (/^(%%|flowchart|graph)\b/m.test(trimmed) || /-->|==>|-\.->/.test(trimmed)) {
    return fromMermaid(trimmed);
  }
  throw new Error("Mermaid でも STIX JSON でもないようです");
}
