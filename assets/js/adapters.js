// 各アプリの既存フォーマットを spec v1 のエンティティに正規化する。
//
// アプリ側が api/v1/search.json を出すようになったら apps.json の adapter を
// "spec-v1" に変えるだけでよく、ここ以外のコードは触らない。
// 詳細は docs/portal-spec.md §5。

import { detectType, fetchWithProgress, refang, resolveUrl } from "./util.js";

/** エンティティ 1 件を作る。空の value は捨てる。 */
function ent(type, id, label, extra = {}) {
  return {
    type,
    id,
    label: String(label),
    value: extra.value != null ? String(extra.value) : String(label),
    detail: extra.detail != null ? String(extra.detail) : undefined,
    aliases: extra.aliases,
    attrs: extra.attrs,
    refs: extra.refs || [],
  };
}

/* ------------------------------------------------------------------ *
 * ai-security-analysis — ui/data.js (window.MALDB)
 * ------------------------------------------------------------------ */

// data.js の IOC 種別は表記ゆれがある（`sha256` / `SHA-256` / `接続先` …）。
const MALDB_IOC_TYPES = {
  sha256: "ioc.sha256", "sha-256": "ioc.sha256",
  sha512: "ioc.sha512", "sha-512": "ioc.sha512",
  sha1: "ioc.sha1", "sha-1": "ioc.sha1",
  md5: "ioc.md5",
  url: "ioc.url",
  ipv4: "ioc.ipv4", ip: "ioc.ipv4", "ipアドレス": "ioc.ipv4",
  ipv6: "ioc.ipv6",
  domain: "ioc.domain", "ドメイン": "ioc.domain", host: "ioc.domain",
  email: "ioc.email", "メールアドレス": "ioc.email",
  "接続先": "ioc.endpoint", endpoint: "ioc.endpoint", "c2": "ioc.endpoint",
};

// 結合キーとして役に立たないもの。索引には入れない。
const MALDB_IOC_SKIP = new Set(["file_name", "filename", "ファイル名", "mutex", "ethereumアドレス", "bitcoinアドレス"]);

/** `1.2.3.4:8080/TCP` → `{ endpoint, host }` のように分解する。 */
function splitNetworkValue(raw) {
  let v = refang(String(raw || "").trim()).replace(/\/(TCP|UDP)$/i, "").trim();
  if (!v) return null;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(v)) {
    let host = null;
    try { host = new URL(v).hostname; } catch { /* 解釈できない URL はそのまま扱う */ }
    return { value: v, type: "ioc.url", host };
  }
  const m = v.match(/^(\[[0-9a-f:]+\]|[^\s:]+):(\d{1,5})$/i);
  if (m) return { value: v, type: "ioc.endpoint", host: m[1].replace(/^\[|\]$/g, "") };
  const t = detectType(v);
  return t ? { value: v, type: t, host: null } : null;
}

async function loadMaldb(source, onProgress) {
  const text = await fetchWithProgress(source.index_url, {
    approx: source.approx_bytes, onProgress,
  });
  const eq = text.indexOf("=");
  if (eq < 0) throw new Error("data.js の形式が想定と違います");
  const db = JSON.parse(text.slice(eq + 1).trim().replace(/;\s*$/, ""));

  const out = [];
  const seen = new Map(); // 正規化済み値 → エンティティ（同じ IOC を 1 ノードに畳む）

  const putIoc = (type, value, role, fromId, rel) => {
    const norm = refang(String(value || "").trim());
    if (!norm) return null;
    const key = type + "|" + norm.toLowerCase();
    let e = seen.get(key);
    if (!e) {
      e = ent(type, key, norm, { detail: norm, attrs: role ? { 役割: role } : undefined });
      seen.set(key, e);
      out.push(e);
    }
    if (fromId) e.refs.push({ rel: rel || "観測", target: fromId });
    return e;
  };

  for (const [key, fam] of Object.entries(db.families || {})) {
    out.push(ent("malware", "family:" + key, fam.label || fam.title || key, {
      detail: key,
      aliases: fam.aliases,
      attrs: { ケース数: fam.case_count, ルール: (fam.rules || []).length || undefined },
    }));
  }

  for (const c of db.cases || []) {
    const sha = String(c.sha256 || "");
    if (!sha) continue;
    const caseId = "case:" + sha;
    const refs = [];
    if (c.family) refs.push({ rel: "ファミリ", target: "family:" + c.family });

    out.push(ent("case", caseId, sha, {
      detail: sha,
      attrs: {
        ファミリ: c.family,
        版: c.version_key,
        形式: c.file_type,
        初観測: c.first_seen,
        提供元: c.provider,
        分類: c.campaign_type,
        判定: c.assessment?.status,
        タグ: (c.tags || []).join(", ") || undefined,
      },
      refs,
    }));

    for (const raw of c.c2 || []) {
      const s = splitNetworkValue(raw);
      if (!s) continue;
      const node = putIoc(s.type, s.value, "C2", caseId, "C2/通信");
      if (s.host && s.host !== s.value) {
        const ht = detectType(s.host);
        if (ht) {
          const hostNode = putIoc(ht, s.host, "C2ホスト", null, null);
          if (hostNode && node) node.refs.push({ rel: "ホスト", target: hostNode.id });
        }
      }
    }

    for (const ioc of c.iocs || []) {
      const rawType = String(ioc.type || "").trim();
      const lower = rawType.toLowerCase();
      if (MALDB_IOC_SKIP.has(lower)) continue;
      let type = MALDB_IOC_TYPES[lower];
      const s = splitNetworkValue(ioc.value);
      if (!s) continue;
      if (!type) type = s.type;
      if (!type) continue;
      // 検体自身の SHA-256 はケースノードに畳む
      if (type === "ioc.sha256" && s.value.toLowerCase() === sha.toLowerCase()) continue;
      const node = putIoc(type === "ioc.endpoint" || type === "ioc.url" ? s.type : type,
        s.value, ioc.role, caseId, ioc.role || "IOC");
      if (s.host && s.host !== s.value) {
        const ht = detectType(s.host);
        if (ht) {
          const hostNode = putIoc(ht, s.host, null, null, null);
          if (hostNode && node) node.refs.push({ rel: "ホスト", target: hostNode.id });
        }
      }
    }
  }

  for (const camp of db.intel?.campaigns || []) {
    const refs = (camp.members || []).map((m) => ({ rel: "相関ケース", target: "case:" + m }));
    for (const f of camp.families || []) refs.push({ rel: "ファミリ", target: "family:" + f });
    out.push(ent("campaign", "intel:" + camp.id, camp.id, {
      detail: camp.id,
      attrs: {
        分類: camp.classification,
        確度: camp.confidence,
        構成数: camp.member_count,
      },
      refs,
    }));
  }

  return { entities: out, stats: db.stats || {} };
}

/* ------------------------------------------------------------------ *
 * vuln-intel-agent — api/v1/search.json（列指向）
 * ------------------------------------------------------------------ */

async function loadVulnwatch(source, onProgress) {
  const text = await fetchWithProgress(source.index_url, {
    approx: source.approx_bytes, onProgress,
  });
  const db = JSON.parse(text);
  const F = {};
  (db.fields || []).forEach((name, i) => { F[name] = i; });
  const dict = db.prefix_dictionary || [];
  const FLAGS = db.flags || { fixed: 1, poc: 2, exploited: 4, kev: 8, ransomware: 16 };

  const out = [];
  for (const r of db.rows || []) {
    const cve = r[F.cve];
    const id = r[F.id];
    const label = cve || id;
    if (!label) continue;
    const bits = Number(r[F.flags]) || 0;
    const flags = [];
    for (const [name, bit] of Object.entries(FLAGS)) if (bits & bit) flags.push(name);
    const pi = Number(r[F.prefix]);
    out.push(ent(cve ? "cve" : "report", "vuln:" + id, label, {
      value: cve || id,
      detail: id,
      attrs: {
        題名: r[F.title] || undefined,
        ベンダー: r[F.vendors] || undefined,
        製品: r[F.products] || undefined,
        CVSS: r[F.cvss] ?? undefined,
        深刻度: r[F.sev] || undefined,
        優先度: r[F.prio] || undefined,
        公開: r[F.pub] || undefined,
        更新: r[F.upd] || undefined,
        攻撃面: r[F.asc] || undefined,
        _flags: flags,
        _prefix: pi >= 0 && dict[pi] ? dict[pi] : undefined,
        _internal_id: id,
      },
    }));
  }
  return { entities: out, stats: db.stats || {}, extra: { attack_surfaces: db.attack_surfaces } };
}

/* ------------------------------------------------------------------ *
 * threatactor-intel-analysis — ui/data/actors.json
 * ------------------------------------------------------------------ */

async function loadThreatactor(source, onProgress) {
  const text = await fetchWithProgress(source.index_url, {
    approx: source.approx_bytes, onProgress,
  });
  const db = JSON.parse(text);
  const out = [];
  for (const a of db.actors || []) {
    const refs = (a.relationships || []).map((r) => ({
      rel: r.type || "関連", target: "actor:" + r.target_slug,
    }));
    out.push(ent("actor", "actor:" + a.slug, a.name, {
      detail: a.slug,
      aliases: a.aliases,
      attrs: {
        別名: (a.aliases || []).join(", ") || undefined,
        種別: (a.actor_types || []).join(", ") || undefined,
        帰属: (a.attribution?.countries || []).join(", ") || undefined,
        確度: a.attribution?.confidence || undefined,
        動機: (a.motivations || []).join(", ") || undefined,
        標的分野: (a.target_sectors || []).slice(0, 6).join(", ") || undefined,
        概要: a.description || undefined,
        更新: a.updated_at || undefined,
        _counts: a.counts,
      },
      refs,
    }));
  }
  return {
    entities: out,
    stats: db.stats || {},
    // 索引にマルウェア名・IOC が無いぶんはワークベンチ側で遅延取得する（仕様 §5.1）
    limits: ["この索引はアクター名と別名のみ。IOC・マルウェア名はワークベンチでノードを展開したときに取得する。"],
  };
}

/** アクター 1 件の詳細を取り、周辺エンティティを返す（ワークベンチの展開用）。 */
async function expandActor(source, entity) {
  const slug = entity.detail || entity.id.replace(/^actor:/, "");
  const base = source.profiles_base || resolveUrl(source.site_url, "../profiles");
  const out = [];
  const push = (type, value, rel, attrs) => {
    const v = refang(String(value || "").trim());
    if (!v) return;
    out.push(ent(type, type + "|" + v.toLowerCase(), v, {
      detail: v, attrs, refs: [{ rel, target: entity.id }],
    }));
  };

  const [profile, iocs] = await Promise.all([
    fetch(`${base}/${slug}/actor-profile.json`, { mode: "cors" })
      .then((r) => (r.ok ? r.json() : null)).catch(() => null),
    fetch(`${base}/${slug}/iocs.json`, { mode: "cors" })
      .then((r) => (r.ok ? r.json() : null)).catch(() => null),
  ]);

  if (profile) {
    const cap = profile.capabilities || {};
    for (const m of cap.malware || []) push("malware", m.name || m, "使用マルウェア", { 種別: "malware" });
    for (const t of cap.tools || []) push("tool", t.name || t, "使用ツール");
    for (const v of cap.vulnerabilities || []) {
      const cve = v.cve_id || v.name || v;
      if (/^CVE-/i.test(String(cve))) push("cve", String(cve).toUpperCase(), "悪用");
    }
    for (const t of (profile.ttps || []).slice(0, 40)) {
      if (t.technique_id) {
        push("ttp", t.technique_id, "TTP", { 名称: t.technique_name, 戦術: t.tactic });
      }
    }
    for (const act of profile.activities || []) {
      if (act.name) push("campaign", act.name, act.activity_type || "活動");
    }
  }

  const IOC_MAP = {
    md5: "ioc.md5", sha1: "ioc.sha1", sha256: "ioc.sha256", sha512: "ioc.sha512",
    ipv4: "ioc.ipv4", ipv6: "ioc.ipv6", domain: "ioc.domain", url: "ioc.url", email: "ioc.email",
  };
  const list = Array.isArray(iocs) ? iocs : iocs?.indicators || iocs?.iocs || [];
  for (const i of list.slice(0, 400)) {
    const type = IOC_MAP[String(i.type || "").toLowerCase()];
    if (!type) continue;
    push(type, i.normalized_value || i.value, "指標", {
      確度: i.disposition, 観測数: i.observation_count,
    });
  }

  if (!profile && !list.length) {
    throw new Error("プロファイルを取得できませんでした");
  }
  return out;
}

/* ------------------------------------------------------------------ *
 * spec v1 ネイティブ
 * ------------------------------------------------------------------ */

async function loadSpecV1(source, onProgress) {
  // endpoints.* は site_url からの相対（仕様 §1.1）。meta.json の URL 基準ではない。
  const meta = source.meta || null;
  const indexUrl = source.index_url
    || resolveUrl(meta?.site_url || source.site_url, meta?.endpoints?.search || "api/v1/search.json");
  const text = await fetchWithProgress(indexUrl, {
    approx: source.approx_bytes, onProgress,
    cache: source._reload ? "reload" : undefined,
  });
  const db = JSON.parse(text);
  const entities = (db.entities || []).map((e) => ent(e.type, e.id, e.label, {
    value: e.value, detail: e.detail, aliases: e.aliases, attrs: e.attrs, refs: e.refs,
  }));
  return { entities, stats: db.stats || meta?.stats || {}, meta };
}

/* ------------------------------------------------------------------ */

export const ADAPTERS = {
  "spec-v1": { load: loadSpecV1 },
  maldb: { load: loadMaldb },
  vulnwatch: { load: loadVulnwatch },
  threatactor: { load: loadThreatactor, expand: expandActor },
};

export function getAdapter(name) {
  const a = ADAPTERS[name];
  if (!a) throw new Error(`未知のアダプタ: ${name}`);
  return a;
}
