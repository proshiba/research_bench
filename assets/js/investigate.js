// グラフ上のオブジェクトから直接引く調査。
//
// ワークベンチでノードを右クリックすると、その種別で意味のある調査だけが並ぶ。
// 実行結果は「そのノードに足す属性」と「新しく生やす関連ノード」に分けて返し、
// 呼び出し側（view-workbench）がグラフへ反映する。
//
// 調査の実体は Active Research API と Shodan。VirusTotal / GitHub / AbuseIPDB は
// Active Research 経由なので、トークンが API サーバーを通る（画面で明示する）。
//
// 危険度が付く調査（AbuseIPDB のスコア、VirusTotal の検知ベンダー数）は
// risk.js の形で属性に持たせる。グラフの印とサイドバーはそこから読む。

import {
  abuseCategoryText, abuseRecord, censysHits, censysIp, censysNames, censysPorts,
  getTool, rdapRecord, run,
} from "./api-active-research.js";
import { isStoredByField } from "./credentials.js";
import { getModuleSettings } from "./modules.js";
import { getSettings, lookup as osintLookup } from "./osint.js";
import { riskAttrs } from "./risk.js";
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
    // 旧 web-analyze は API 側で deprecated。request の includeAnalyze が後継。
    // 応答の analysis に counts は無いので、配列の長さから出す。
    id: "web-analyze", group: "ページ", label: "Web ページを取得して解析",
    when: (t) => NAMEISH.has(t) || IP.has(t),
    async run(node) {
      const out = res();
      const url = urlOf(nodeValue(node));
      const d = await callTool("request", { url, method: "GET", followRedirects: true, includeAnalyze: true });
      const a = d.analysis || {};
      // ページそのものをノードにする。HTML 由来の中身は属性として持たせる
      addRel(out, "webpage", d.request?.url || url, "取得したページ", {
        attrs: {
          HTTP: d.response?.status != null ? `${d.response.status} ${d.response.statusText || ""}`.trim() : null,
          種類: d.response?.contentType,
          技術: (a.technologies || []).join(", "),
          Cookie: (a.cookieNames || []).join(", "),
          注目ヘッダ: Object.entries(a.notableHeaders || {}).map(([k, v]) => `${k}: ${v}`).join("\n"),
          リンク数: (a.links || []).length || null,
          内部パス数: (a.internalPaths || []).length || null,
          内部パス: (a.internalPaths || []).slice(0, 60).join("\n"),
          外部リンク: (a.links || []).slice(0, 60).join("\n"),
          取得元: url,
        },
      });
      for (const ip of [...(d.request?.resolvedIps || []), ...(d.request?.finalResolvedIps || [])]) {
        addRel(out, ipType(ip), ip, "解決 IP");
      }
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
      const st = d.summary?.analysisStats || a.last_analysis_stats || {};
      // 分母は「判定を返したベンダーの総数」。malicious だけ見ても多いのか少ないのか
      // 分からないので、必ず総数と一緒に出す
      const vendors = ["malicious", "suspicious", "harmless", "undetected"]
        .reduce((n, k) => n + (typeof st[k] === "number" ? st[k] : 0), 0);
      out.attrs["VT 判定"] = d.summary?.verdict;
      out.attrs["VT 検知"] = st.malicious != null
        ? `${st.malicious} / ${vendors} ベンダー（疑わしい ${st.suspicious ?? 0}）` : null;
      out.attrs["VT 評判"] = d.summary?.reputation;
      Object.assign(out.attrs, riskAttrs("virustotal", {
        score: st.malicious, max: vendors || undefined, suspicious: st.suspicious,
      }));
      out.attrs["カテゴリ"] = [...new Set(Object.values(d.summary?.categories || {}))].join(", ") || null;
      addPlace(out, { asn: a.asn ? `AS${a.asn}` : null, org: a.as_owner, country: a.country });
      for (const r of a.last_dns_records || []) {
        if (r.type === "A") addRel(out, "ioc.ipv4", r.value, "VT: Aレコード");
        if (r.type === "AAAA") addRel(out, "ioc.ipv6", r.value, "VT: AAAAレコード");
      }
      const family = a.popular_threat_classification?.suggested_threat_label;
      if (family) addRel(out, "malware", family, "VT: 推定ファミリ");
      if (d.ok === false) {
        out.error = true;
        out.note = `VirusTotal がエラーを返しました: ${d.error || "(理由なし)"}`;
      } else if (st.malicious != null) {
        out.note = `${st.malicious} / ${vendors} ベンダーが検知${
          d.summary?.verdict ? `（判定 ${d.summary.verdict}）` : ""}`;
      } else {
        out.note = "応答に検知の内訳がありませんでした";
      }
      return out;
    },
  },

  {
    id: "abuseipdb", group: "脅威情報", label: "AbuseIPDB で通報状況を見る", needs: "abuseipdb",
    when: (t) => IP.has(t),
    async run(node) {
      const out = res();
      // verbose を付けると通報の明細が返る。スコアの根拠（何をして通報されたか）が
      // 分かるので、グラフから引くときは常に取る
      const d = await callTool("abuseipdb",
        { ip: nodeValue(node), verbose: true, apikey: getSettings().keys.abuseipdb }, { allowNotOk: true });
      const a = abuseRecord(d);

      out.attrs["AbuseIPDB 信頼度"] = a.score != null ? `${a.score} / 100` : null;
      out.attrs["AbuseIPDB 通報数"] = a.reports;
      out.attrs["AbuseIPDB 通報者数"] = a.users;
      out.attrs["AbuseIPDB 最終通報"] = a.lastReportedAt;
      out.attrs["AbuseIPDB 通報の種類"] = abuseCategoryText(a.categories);
      out.attrs["用途"] = a.usageType;
      out.attrs["ISP"] = a.isp;
      out.attrs["組織"] = a.org;
      if (a.whitelisted) out.attrs["AbuseIPDB ホワイトリスト"] = "はい";
      if (a.tor) out.attrs["Tor 出口"] = "はい";
      Object.assign(out.attrs, riskAttrs("abuseipdb", { score: a.score }));

      // AbuseIPDB は AS 番号を返さない（組織名だけ）ので AS ノードは作らない
      addPlace(out, { isp: a.isp, country: a.country });
      if (a.domain) addRel(out, "ioc.domain", a.domain, "AbuseIPDB: ドメイン");
      for (const h of a.hostnames) addRel(out, "ioc.domain", h, "AbuseIPDB: ホスト名");

      if (d.ok === false) {
        out.error = true;
        out.note = `AbuseIPDB がエラーを返しました: ${d.error || "(理由なし)"}`;
      } else if (a.score == null) {
        out.error = true;
        out.note = "応答にスコアが入っていませんでした";
      } else {
        const kinds = abuseCategoryText(a.categories, 3);
        out.note = `信頼度スコア ${a.score} / 100（通報 ${a.reports ?? "?"} 件${kinds ? ` — ${kinds}` : ""}）`;
      }
      return out;
    },
  },

  {
    id: "urlscan", group: "脅威情報", label: "urlscan で過去のスキャンを探す", needs: "urlscan",
    when: (t) => IP.has(t) || t === "ioc.domain" || t === "ioc.url" || t === "webpage",
    async run(node) {
      const out = res();
      const v = nodeValue(node);
      const t = node.type;
      // 種別ごとに検索軸を変える。日付を切って上流の負担を抑える
      const q = IP.has(t) ? `page.ip:"${v}"`
        : t === "ioc.domain" ? `page.domain:"${v}"`
          : `page.url:"${urlOf(v)}"`;
      const d = await callTool("urlscan",
        { action: "search", q: `${q} AND date:>now-1y`, size: 25, apikey: getSettings().keys.urlscan },
        { allowNotOk: true });
      const r = d.data || {};
      const rows = r.results || [];

      out.attrs["urlscan 件数"] = r.total != null ? `${rows.length} / ${r.total}` : rows.length || null;
      out.attrs["urlscan クエリ"] = d.query?.q || q;
      out.attrs["urlscan 最終スキャン"] = rows[0]?.task?.time || null;

      for (const row of rows.slice(0, 40)) {
        const p = row.page || {};
        if (p.ip) addRel(out, ipType(p.ip), p.ip, "urlscan: 解決 IP");
        if (p.domain) addRel(out, "ioc.domain", p.domain, "urlscan: ドメイン");
        const u = p.url || row.task?.url;
        if (u) {
          addRel(out, "webpage", u, "urlscan: スキャンされたページ", {
            attrs: {
              題名: p.title, サーバー: p.server, 国: p.country,
              AS: p.asnname || p.asn, 解決IP: p.ip,
              スキャン日時: row.task?.time,
              取得元: `https://urlscan.io/result/${row._id || ""}/`,
            },
          });
        }
        if (p.asn) {
          addPlace(out, { asn: p.asn, org: p.asnname, country: p.country });
        }
      }

      if (d.ok === false) {
        out.error = true;
        out.note = `urlscan がエラーを返しました: ${d.error || "(理由なし)"}`;
      } else {
        out.note = rows.length
          ? `${rows.length} 件のスキャン（全 ${r.total ?? "?"} 件。グラフには先頭 40 件）`
          : "該当するスキャンがありませんでした";
      }
      return out;
    },
  },

  {
    id: "censys", group: "脅威情報", label: "Censys で引く", needs: "censys",
    when: (t) => IP.has(t) || t === "ioc.domain",
    async run(node) {
      const out = res();
      const v = nodeValue(node);
      const q = IP.has(node.type) ? `host.ip: ${v}` : `web.hostname: "${v}"`;
      const d = await callTool("censys",
        { query: q, pageSize: 25, apikey: getSettings().keys.censys }, { allowNotOk: true });
      const hits = censysHits(d);

      out.attrs["Censys ヒット"] = hits.length || null;
      out.attrs["Censys クエリ"] = d.query?.cenql || q;

      for (const h of hits.slice(0, 25)) {
        const ip = censysIp(h);
        const ports = censysPorts(h);
        if (ip) {
          addRel(out, ipType(ip), ip, "Censys: ホスト");
          for (const port of ports) addRel(out, "ioc.endpoint", `${ip}:${port}`, "Censys: 開いているポート");
        }
        for (const name of censysNames(h)) addRel(out, "ioc.domain", name, "Censys: 名前");
      }
      // 自分自身のポートは属性にも入れておく（関連を辿らなくても見える）
      const self = hits.find((h) => censysIp(h) === v);
      if (self) out.attrs["開いていたポート (Censys)"] = censysPorts(self).join(", ") || null;

      if (d.ok === false) {
        out.error = true;
        out.note = `Censys がエラーを返しました: ${d.error || "(理由なし)"}`;
      } else {
        out.note = hits.length ? `${hits.length} 件ヒットしました` : "ヒットしませんでした";
      }
      return out;
    },
  },

  {
    id: "browser-gateway", group: "ページ", label: "隔離ブラウザで開く（画面と HTML）",
    needs: "cloudflare",
    when: (t) => t === "ioc.url" || t === "webpage" || t === "ioc.domain",
    async run(node) {
      const out = res();
      const url = urlOf(nodeValue(node));
      const keys = getSettings().keys;
      const d = await callTool("browser-gateway",
        { url, device: "desktop", accountId: keys.cloudflareAccount, apikey: keys.cloudflareToken },
        { allowNotOk: true });
      const g = d.gateway || {};

      // スクリーンショットは localStorage に入れない（すぐ容量を食う）。
      // `_` 始まりのキーは属性一覧にも出ないので、画面側だけが読む
      const shot = g.screenshot?.base64
        ? `data:${g.screenshot.contentType || "image/png"};base64,${g.screenshot.base64}`
        : null;

      addRel(out, "webpage", d.response?.finalUrl || url, "隔離ブラウザで見たページ", {
        attrs: {
          HTTP: d.response?.status != null ? `${d.response.status}` : null,
          題名: d.response?.title,
          描画: d.response?.browserMs != null ? `${d.response.browserMs} ms` : null,
          画面: g.screenshot ? `${g.screenshot.width}×${g.screenshot.height}` : null,
          リンク数: (g.links || []).length || null,
          "ページ内リンク": (g.links || []).slice(0, 60).map((l) => l.url).filter(Boolean).join("\n"),
          "描画後 HTML": g.renderedHtml ? g.renderedHtml.slice(0, 20000) : null,
          取得元: url,
          ...(shot ? { _shot: shot } : {}),
        },
      });

      for (const ip of d.request?.resolvedIps || []) addRel(out, ipType(ip), ip, "解決 IP");
      out.attrs["題名"] = d.response?.title || null;

      if (d.ok === false) {
        out.error = true;
        out.note = `Browser Gateway がエラーを返しました: ${d.error || "(理由なし)"}`;
      } else {
        out.note = `HTTP ${d.response?.status ?? "?"}・リンク ${(g.links || []).length} 件`
          + `${g.targetLoadedInUserBrowser === false ? "（自分のブラウザには読み込んでいません）" : ""}`;
      }
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
/**
 * レート制限で待っていることの通知。
 *
 * 待機はどの調査でも起きうる横断的な話なので、調査ごとに引き回さず
 * ここで受けて画面へ流す。待てば通るものなので失敗にはしない。
 */
const waitListeners = new Set();

export function onRateLimitWait(fn) {
  waitListeners.add(fn);
  return () => waitListeners.delete(fn);
}

function reportWait(tool, info) {
  for (const fn of waitListeners) {
    try { fn({ ...info, tool: tool.label }); } catch { /* 通知で落とさない */ }
  }
}

async function callTool(id, values, { allowNotOk = false, onProgress } = {}) {
  const tool = getTool(id);
  if (!tool) throw new Error(`未知のツール: ${id}`);
  const r = await run(getModuleSettings().activeResearchBase, tool, values, {
    onProgress,
    onWait: (info) => reportWait(tool, info),
  });
  // レート制限は待っても通らなかったということ。allowNotOk の調査でも
  // 上流サービスのエラーと混ぜず、待てば直ると分かる文言にする
  if (r.status === 429) {
    throw new Error(`${tool.label} が混み合っています（API のレート制限）。少し時間をおいて試してください`);
  }

  const d = r.data;
  if (!d) {
    // 5xx は API サーバー側が落ちている（応答が HTML のこともある）。
    // 利用者が直せる話ではないので、そう分かる書き方にする。
    if (r.status >= 500) throw new Error(`API サーバーがエラーを返しました (HTTP ${r.status})。時間をおいて試してください`);
    // 404 は「この API サーバーにそのツールが無い」。利用者が値を直しても直らないので分けて言う
    if (r.status === 404) throw new Error(`この API サーバーに ${tool.label} がありません (HTTP 404)`);
    throw new Error(`応答を読めませんでした (HTTP ${r.status})`);
  }
  if (d.ok === false && !allowNotOk) throw new Error(d.error || "API が ok:false を返しました");
  return d;
}

/**
 * トークン/キーが要る調査は、設定済みかどうかを見て理由を添える。
 *
 * 「設定済み」は端末の中にあるか、調査 API に預けてあるかのどちらか。
 * 預けてある場合はポータルが値を持っていないので、端末側は空のまま実行できる
 * （空ならヘッダが落ち、API が預かっている鍵を使う）。
 * Shodan だけは調査 API を通らないので、端末の中にしか無い。
 */
function tokenState(needs) {
  if (!needs) return { ready: true };
  const keys = getSettings().keys;
  const has = (field) => !!keys[field] || isStoredByField(field);
  const map = {
    shodan: [!!keys.shodan, "Shodan の API キーが未設定です"],
    vt: [has("virustotal"), "VirusTotal のトークンが未設定です"],
    github: [has("github"), "GitHub のトークンが未設定です"],
    abuseipdb: [has("abuseipdb"), "AbuseIPDB のトークンが未設定です"],
    urlscan: [has("urlscan"), "urlscan の API キーが未設定です"],
    censys: [has("censys"), "Censys の Personal Access Token が未設定です"],
    // アカウント ID は預けられないので、こちらは端末の中に要る
    cloudflare: [!!keys.cloudflareAccount && has("cloudflareToken"),
      keys.cloudflareAccount
        ? "Cloudflare の API トークンが未設定です"
        : "Cloudflare のアカウント ID が未設定です"],
  };
  const [ready, why] = map[needs] || [];
  return { ready: !!ready, why };
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
