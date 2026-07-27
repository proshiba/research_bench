// グラフ上のオブジェクトから直接引く調査。
//
// ワークベンチでノードを右クリックすると、その種別で意味のある調査だけが並ぶ。
// 実行結果は「そのノードに足す属性」と「新しく生やす関連ノード」に分けて返し、
// 呼び出し側（view-workbench）がグラフへ反映する。
//
// 調査の実体は Active Research API と Shodan。VirusTotal と GitHub は
// Active Research 経由なので、トークンが API サーバーを通る（画面で明示する）。

import { getTool, rdapRecord, run } from "./api-active-research.js";
import { getModuleSettings } from "./modules.js";
import { getSettings, lookup as osintLookup } from "./osint.js";
import { detectType } from "./util.js";

const IP = new Set(["ioc.ipv4", "ioc.ipv6"]);
const HASH = new Set(["ioc.md5", "ioc.sha1", "ioc.sha256", "ioc.sha512", "case"]);
const NAMEISH = new Set(["ioc.domain", "ioc.url", "ioc.endpoint", "webpage"]);

/** 値からホスト名を取り出す。URL でも裸のドメインでも同じ形に落とす。 */
function hostOf(value) {
  const v = String(value || "").trim();
  try {
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(v)) return new URL(v).hostname;
  } catch { /* 壊れた URL は下の分岐に落とす */ }
  return v.split("/")[0].split(":")[0];
}

/** 値を http(s) の URL にする。スキームが無ければ https を補う。 */
function urlOf(value) {
  const v = String(value || "").trim();
  return /^[a-z][a-z0-9+.-]*:\/\//i.test(v) ? v : `https://${v}`;
}

const ipType = (v) => (detectType(v) === "ioc.ipv6" ? "ioc.ipv6" : "ioc.ipv4");

/** グラフのノードが表している値。実体の value を優先し、無ければ表示名。 */
export function nodeValue(node) {
  for (const m of node?.members || []) {
    if (m.entity?.value) return m.entity.value;
  }
  return node?.label || "";
}

/* ---------------- 結果の組み立て ---------------- */

const res = () => ({ attrs: {}, related: [], note: null, error: false });

function addRel(out, type, value, rel, extra = {}) {
  const v = String(value ?? "").trim().replace(/\.$/, "");
  if (!v) return;
  if (out.related.some((r) => r.type === type && r.value.toLowerCase() === v.toLowerCase())) return;
  out.related.push({ type, value: v, rel, ...extra });
}

/**
 * Shodan と VirusTotal が返す所在情報を、AS と地理のノードにする。
 * 同じ AS / 同じ国は 1 ノードに畳みたいので、値は正規化した文字列にする。
 */
function addPlace(out, { asn, org, isp, country, city, region }) {
  if (asn) {
    addRel(out, "net.asn", String(asn).toUpperCase(), "所属 AS", {
      label: org ? `${String(asn).toUpperCase()} ${org}` : undefined,
      attrs: { 組織: org, ISP: isp },
    });
  }
  if (country) {
    const label = [country, region, city].filter(Boolean).join(" / ");
    addRel(out, "geo", country, "所在地", { label, attrs: { 国: country, 地域: region, 都市: city } });
  }
}

/* ---------------- 調査項目 ---------------- */

/**
 * 1 項目 = 右クリックメニューの 1 行。
 *   when   … この種別で出すか
 *   needs  … "shodan" | "vt" | "github"（未設定なら灰色にして理由を出す）
 *   value  … 調査に渡す値の作り方（既定はノードの値そのまま）
 */
export const ACTIONS = [
  {
    id: "dns", group: "名前", label: "DNS を引く",
    when: (t) => t === "ioc.domain" || t === "ioc.url" || t === "ioc.endpoint" || t === "webpage",
    async run(node) {
      const out = res();
      const d = await callTool("dns", { target: hostOf(nodeValue(node)), types: "A,AAAA,MX,NS,TXT,CNAME" });
      for (const r of d.results || []) {
        for (const a of r.answers || []) {
          const data = String(a.data ?? "").trim();
          if (!data) continue;
          if (r.type === "A") addRel(out, "ioc.ipv4", data, "DNS: A");
          else if (r.type === "AAAA") addRel(out, "ioc.ipv6", data, "DNS: AAAA");
          else if (r.type === "MX") addRel(out, "ioc.domain", data.replace(/^\d+\s+/, ""), "DNS: MX");
          else if (r.type === "NS") addRel(out, "ioc.domain", data, "DNS: NS");
          else if (r.type === "CNAME") addRel(out, "ioc.domain", data, "DNS: CNAME");
          else if (r.type === "TXT") out.attrs.TXT = [out.attrs.TXT, data].filter(Boolean).join(" / ");
        }
      }
      out.attrs["DNS 照会"] = d.queriedAt;
      out.note = `${out.related.length} 件の関連が取れました`;
      return out;
    },
  },

  {
    id: "rdap", group: "名前", label: "WHOIS / RDAP を引く",
    when: (t) => t === "ioc.domain" || t === "ioc.url" || t === "webpage",
    async run(node) {
      const out = res();
      const d = await callTool("rdap", { target: hostOf(nodeValue(node)) }, { allowNotOk: true });
      const r = rdapRecord(d);

      out.attrs["レジストラ"] = r.registrar;
      out.attrs["登録日"] = r.created;
      out.attrs["最終更新"] = r.updated;
      out.attrs["有効期限"] = r.expires;
      out.attrs["ステータス"] = r.status.join("\n") || null;
      out.attrs["連絡先"] = r.contact;
      if (r.note) out.attrs["注記"] = r.note;
      if (r.raw) out.attrs["WHOIS 本文"] = r.raw;

      for (const ns of r.nameservers) addRel(out, "ioc.domain", ns, "WHOIS: NS");

      if (d.ok === false) {
        out.error = true;
        out.note = `WHOIS を引けませんでした: ${d.error || "(理由の記載なし)"}`;
      } else if (!r.registrar && !r.raw) {
        out.error = true;
        out.note = "応答に WHOIS の中身がありませんでした";
      } else {
        out.note = `${r.registrar || "登録情報"} を取り込みました`;
      }
      return out;
    },
  },

  {
    id: "certificate", group: "名前", label: "証明書 (CT) からサブドメインを探す",
    when: (t) => t === "ioc.domain" || t === "ioc.url" || t === "webpage",
    async run(node) {
      const out = res();
      const d = await callTool("certificate", { target: hostOf(nodeValue(node)) });
      out.attrs["CT 記録数"] = d.count;
      const seen = new Set();
      for (const c of d.certificates || []) {
        const name = String(c.common_name || "").replace(/^\*\./, "").trim();
        if (detectType(name) !== "ioc.domain" || seen.has(name)) continue;
        seen.add(name);
        addRel(out, "ioc.domain", name, "CT: common_name");
      }
      out.note = `${out.related.length} 件の名前が見つかりました`;
      return out;
    },
  },

  {
    id: "web-analyze", group: "ページ", label: "Web ページを取得して解析",
    when: (t) => NAMEISH.has(t) || IP.has(t),
    async run(node) {
      const out = res();
      const url = urlOf(nodeValue(node));
      const d = await callTool("web-analyze", { url });
      const a = d.analysis || {};
      // ページそのものをノードにする。HTML 由来の中身は属性として持たせる
      addRel(out, "webpage", d.request?.url || url, "取得したページ", {
        attrs: {
          HTTP: d.response?.status != null ? `${d.response.status} ${d.response.statusText || ""}`.trim() : null,
          種類: d.response?.contentType,
          技術: (a.technologies || []).join(", "),
          Cookie: (a.cookieNames || []).join(", "),
          注目ヘッダ: Object.entries(a.notableHeaders || {}).map(([k, v]) => `${k}: ${v}`).join("\n"),
          リンク数: a.counts?.links,
          内部パス数: a.counts?.internalPaths,
          内部パス: (a.internalPaths || []).slice(0, 60).join("\n"),
          外部リンク: (a.links || []).slice(0, 60).join("\n"),
          取得元: url,
        },
      });
      for (const ip of d.request?.resolvedIps || []) addRel(out, ipType(ip), ip, "解決 IP");
      out.attrs["技術"] = (a.technologies || []).join(", ") || null;
      out.note = `HTTP ${d.response?.status ?? "?"} — ページを 1 件足しました`;
      return out;
    },
  },

  {
    id: "request", group: "ページ", label: "本文を取得する（リダイレクト追跡）",
    when: (t) => NAMEISH.has(t),
    async run(node) {
      const out = res();
      const url = urlOf(nodeValue(node));
      const d = await callTool("request", { url, method: "GET", followRedirects: true });
      const body = d.response?.body || d.response?.data || "";
      addRel(out, "webpage", d.request?.finalUrl || url, "取得したページ", {
        attrs: {
          HTTP: d.response?.status != null ? `${d.response.status} ${d.response.statusText || ""}`.trim() : null,
          種類: d.response?.contentType,
          本文: body.slice(0, 20000),
          本文の長さ: body.length,
          応答ヘッダ: Object.entries(d.response?.headers || {}).map(([k, v]) => `${k}: ${v}`).join("\n"),
          取得元: url,
        },
      });
      for (const ip of [...(d.request?.resolvedIps || []), ...(d.request?.finalResolvedIps || [])]) {
        addRel(out, ipType(ip), ip, "解決 IP");
      }
      for (const r of d.request?.redirectChain || []) {
        if (r.location) addRel(out, "ioc.url", r.location, `${r.status} の転送先`);
      }
      out.note = `HTTP ${d.response?.status ?? "?"}・${body.length.toLocaleString()} 文字を取り込みました`;
      return out;
    },
  },

  {
    id: "open-directory", group: "ページ", label: "ディレクトリを辿る",
    when: (t) => t === "ioc.url" || t === "webpage",
    async run(node, { onProgress } = {}) {
      const out = res();
      const d = await callTool("open-directory", { url: urlOf(nodeValue(node)), depth: 2, maxEntries: 500 }, { onProgress });
      out.attrs["走査ディレクトリ"] = d.scannedDirectories;
      out.attrs["見つかった項目"] = (d.entries || []).length;
      out.attrs["ディレクトリ木"] = d.treeText;
      for (const e of (d.entries || []).slice(0, 40)) {
        if (e.url) addRel(out, "ioc.url", e.url, `Open Directory: ${e.type || "項目"}`);
      }
      out.note = `${(d.entries || []).length} 件（グラフには先頭 40 件）`;
      return out;
    },
  },

  {
    id: "port-scan", group: "ホスト", label: "ポートを確認する",
    when: (t) => IP.has(t) || t === "ioc.domain" || t === "ioc.endpoint",
    async run(node, { onProgress } = {}) {
      const out = res();
      const target = hostOf(nodeValue(node));
      const d = await callTool("port-scan", { target }, { onProgress });
      const open = d.openports || d.openPorts || [];
      out.attrs["開いていたポート"] = open.join(", ") || "なし";
      out.attrs["調べたポート数"] = d.scannedPortCount;
      for (const p of open) addRel(out, "ioc.endpoint", `${target}:${p}`, "開いているポート");
      for (const ip of d.resolvedIps || []) addRel(out, ipType(ip), ip, "解決 IP");
      out.note = `${open.length} ポートが開いていました`;
      return out;
    },
  },

  {
    id: "banner", group: "ホスト", label: "バナーを取る",
    when: (t) => IP.has(t) || t === "ioc.domain" || t === "ioc.endpoint",
    async run(node) {
      const out = res();
      const value = String(nodeValue(node) || "");
      const port = value.includes(":") && detectType(value) === "ioc.endpoint"
        ? Number(value.split(":").pop()) : 443;
      const d = await callTool("banner", { target: hostOf(value), port, tls: port === 443 ? "true" : "" });
      out.attrs[`バナー:${port}`] = d.banner?.utf8 || null;
      out.attrs["経路"] = d.transport;
      if (d.status != null) out.attrs["HTTP"] = `${d.status} ${d.statusText || ""}`.trim();
      for (const ip of d.resolvedIps || []) addRel(out, ipType(ip), ip, "解決 IP");
      out.note = `ポート ${port} の応答を取り込みました`;
      return out;
    },
  },

  {
    id: "shodan", group: "脅威情報", label: "Shodan で引く", needs: "shodan",
    when: (t) => IP.has(t),
    async run(node) {
      const out = res();
      const type = detectType(nodeValue(node)) || "ioc.ipv4";
      const r = await osintLookup("shodan", nodeValue(node), type);
      for (const [k, v] of r.summary || []) out.attrs[k] = v;
      addPlace(out, {
        asn: pick(r.summary, "ASN"), org: pick(r.summary, "組織"),
        isp: pick(r.summary, "ISP"), country: pick(r.summary, "国"),
      });
      for (const rel of r.related || []) addRel(out, rel.type, rel.value, rel.rel);
      out.note = `${out.related.length} 件の関連が取れました`;
      return out;
    },
  },

  {
    id: "virustotal", group: "脅威情報", label: "VirusTotal で引く", needs: "vt",
    when: (t) => IP.has(t) || HASH.has(t) || t === "ioc.domain" || t === "ioc.url",
    async run(node) {
      const out = res();
      const t = node.type;
      const kind = IP.has(t) ? "ip" : HASH.has(t) ? "file" : t === "ioc.url" ? "url" : "domain";
      const d = await callTool("virustotal",
        { type: kind, value: nodeValue(node), apikey: getSettings().keys.virustotal }, { allowNotOk: true });
      const a = d.data?.attributes || {};
      const st = d.summary?.analysisStats || {};
      out.attrs["VT 判定"] = d.summary?.verdict;
      out.attrs["VT 検知"] = st.malicious != null ? `悪性 ${st.malicious} / 疑わしい ${st.suspicious ?? 0}` : null;
      out.attrs["VT 評判"] = d.summary?.reputation;
      out.attrs["カテゴリ"] = [...new Set(Object.values(d.summary?.categories || {}))].join(", ") || null;
      addPlace(out, { asn: a.asn ? `AS${a.asn}` : null, org: a.as_owner, country: a.country });
      for (const r of a.last_dns_records || []) {
        if (r.type === "A") addRel(out, "ioc.ipv4", r.value, "VT: Aレコード");
        if (r.type === "AAAA") addRel(out, "ioc.ipv6", r.value, "VT: AAAAレコード");
      }
      const family = a.popular_threat_classification?.suggested_threat_label;
      if (family) addRel(out, "malware", family, "VT: 推定ファミリ");
      if (d.ok === false) out.note = `VirusTotal がエラーを返しました: ${d.error || "(理由なし)"}`;
      return out;
    },
  },

  {
    id: "github", group: "脅威情報", label: "GitHub でコード検索", needs: "github",
    when: () => true,
    async run(node) {
      const out = res();
      const d = await callTool("github",
        { action: "code-search", query: nodeValue(node), token: getSettings().keys.github }, { allowNotOk: true });
      out.attrs["GitHub 一致ファイル"] = d.matchedFileCount;
      out.attrs["GitHub リポジトリ数"] = d.repositoryCount ?? (d.repositories || []).length;
      for (const r of (d.repositories || []).slice(0, 20)) {
        if (r.htmlUrl) addRel(out, "ioc.url", r.htmlUrl, "GitHub: リポジトリ", { label: r.fullName });
      }
      if (d.ok === false) out.note = `GitHub がエラーを返しました: ${d.error || "(理由なし)"}`;
      else out.note = `${(d.repositories || []).length} リポジトリ（グラフには先頭 20 件）`;
      return out;
    },
  },
];

function pick(summary, key) {
  return (summary || []).find(([k]) => k === key)?.[1] || null;
}

/** Active Research のツールを 1 つ実行して、結果の中身だけ返す。 */
async function callTool(id, values, { allowNotOk = false, onProgress } = {}) {
  const tool = getTool(id);
  if (!tool) throw new Error(`未知のツール: ${id}`);
  const r = await run(getModuleSettings().activeResearchBase, tool, values, { onProgress });
  const d = r.data;
  if (!d) {
    // 5xx は API サーバー側が落ちている（応答が HTML のこともある）。
    // 利用者が直せる話ではないので、そう分かる書き方にする。
    if (r.status >= 500) throw new Error(`API サーバーがエラーを返しました (HTTP ${r.status})。時間をおいて試してください`);
    throw new Error(`応答を読めませんでした (HTTP ${r.status})`);
  }
  if (d.ok === false && !allowNotOk) throw new Error(d.error || "API が ok:false を返しました");
  return d;
}

/** トークン/キーが要る調査は、設定済みかどうかを見て理由を添える。 */
function tokenState(needs) {
  if (!needs) return { ready: true };
  const keys = getSettings().keys;
  const map = {
    shodan: [keys.shodan, "Shodan の API キーが未設定です"],
    vt: [keys.virustotal, "VirusTotal のトークンが未設定です"],
    github: [keys.github, "GitHub のトークンが未設定です"],
  };
  const [value, why] = map[needs] || [];
  return { ready: !!value, why };
}

/** そのノードで実行できる調査を、実行可否つきで返す。 */
export function actionsFor(node) {
  if (!node) return [];
  return ACTIONS.filter((a) => a.when(node.type)).map((a) => ({
    id: a.id, group: a.group, label: a.label, needs: a.needs,
    ...tokenState(a.needs),
    run: (opts) => a.run(node, opts),
  }));
}
