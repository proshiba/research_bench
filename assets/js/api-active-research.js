// Active Research API（https://hellow-world.hiroshiba.chatgpt.site）のクライアント。
//
// API 自体の認証は不要。ただし VirusTotal と GitHub のツールだけは
// 利用者のトークンを Authorization: Bearer で渡す（API サーバーには保存されない）。
// ベース URL は設定で変えられる（自前の別環境に向けられるように）。
//
// CORS の実測（2026-07）:
//   Access-Control-Allow-Origin: *
//   Access-Control-Allow-Headers: content-type, accept, authorization
//   Access-Control-Allow-Methods: GET, POST, OPTIONS / プリフライトは 204 / max-age 86400
//   → ブラウザから直接呼べる。中継は要らない。
//   将来 Origin を絞ったときに気づけるよう、失敗時は CORS の可能性も併記して出す。
//
// port-scan と open-directory は非同期ジョブ。start が 202 で job.id を返し、
// action=status&jobId=… を completed になるまで叩く。結果は job.result に入っていて、
// 中身は同期だった頃と同じ形なので、要約と値の抽出はそのまま使える。

import { detectType } from "./util.js";

export const DEFAULT_BASE = "https://hellow-world.hiroshiba.chatgpt.site";

/** ジョブ待ちの上限。open-directory は仕様上 5 分まで走る。 */
const POLL_INTERVAL_MS = 1200;
const POLL_TIMEOUT_MS = 5 * 60 * 1000;

/* ---------------- 通信 ---------------- */

/**
 * API を 1 回叩く。
 *
 * fetch が TypeError で落ちるのは「CORS で読ませてもらえなかった」ときと
 * 「そもそも繋がらなかった」ときの両方なので、その場で切り分けられない。
 * ブラウザは理由を JS に渡さない仕様なので、両方の可能性を書いて返す。
 */
export async function call(base, tool, values, { signal } = {}) {
  const url = new URL(tool.path, base.replace(/\/+$/, "") + "/");
  const init = { method: tool.method || "GET", headers: {}, signal, credentials: "omit" };

  if (tool.method === "POST") {
    init.headers["content-type"] = "application/json";
    init.body = JSON.stringify(tool.body(values));
  } else {
    for (const [k, v] of Object.entries(tool.query(values))) {
      if (v !== "" && v != null) url.searchParams.set(k, v);
    }
  }
  for (const [k, v] of Object.entries(tool.headers ? tool.headers(values) : {})) {
    if (v) init.headers[k] = v;
  }

  const started = performance.now();
  let res;
  try {
    res = await fetch(url, init);
  } catch (err) {
    if (err.name === "AbortError") throw err;
    throw new Error(
      `ブラウザが応答を読めませんでした。${url.host} に繋がらないか、`
      + "CORS で読ませてもらえていません（ブラウザは理由を JS に渡さないため区別できません）。",
    );
  }
  const ms = Math.round(performance.now() - started);
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* JSON でないこともある */ }

  return { status: res.status, ms, url: url.href, text, json };
}

/** ジョブの状態を 1 回見る。 */
async function fetchJob(base, tool, jobId, signal) {
  const url = new URL(tool.path, base.replace(/\/+$/, "") + "/");
  url.searchParams.set("action", "status");
  url.searchParams.set("jobId", jobId);
  const res = await fetch(url, { signal, credentials: "omit" });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* JSON でないこともある */ }
  return { status: res.status, text, json };
}

const sleep = (ms, signal) => new Promise((resolve, reject) => {
  const t = setTimeout(resolve, ms);
  signal?.addEventListener("abort", () => { clearTimeout(t); reject(new DOMException("aborted", "AbortError")); },
    { once: true });
});

/**
 * ツールを 1 回実行する。非同期ジョブなら完了まで面倒を見る。
 *
 * 返り値の data が「要約と値の抽出に渡すもの」。同期ツールなら応答そのもの、
 * 非同期ツールなら job.result。raw は画面に出す生の応答で、ジョブの封筒ごと残す。
 */
export async function run(base, tool, values, { signal, onProgress } = {}) {
  const first = await call(base, tool, values, { signal });
  if (!tool.async || !first.json?.job?.id) {
    return { ...first, data: first.json, job: null, raw: first.json };
  }

  const jobId = first.json.job.id;
  onProgress?.(first.json.job);
  const started = performance.now();

  for (;;) {
    if (performance.now() - started > POLL_TIMEOUT_MS) {
      throw new Error(`ジョブが ${Math.round(POLL_TIMEOUT_MS / 60000)} 分で終わりませんでした（jobId: ${jobId}）`);
    }
    await sleep(POLL_INTERVAL_MS, signal);
    const st = await fetchJob(base, tool, jobId, signal);
    const job = st.json?.job;
    if (!job) throw new Error(st.json?.error || `ジョブの状態を取得できません (HTTP ${st.status})`);
    onProgress?.(job);

    if (job.status === "completed") {
      return {
        status: st.status,
        ms: Math.round(performance.now() - started),
        url: first.url,
        text: st.text,
        json: st.json,
        data: job.result || null,
        job,
        raw: st.json,
      };
    }
    if (job.status === "failed" || job.status === "error") {
      throw new Error(job.error || st.json?.error || "ジョブが失敗しました");
    }
  }
}

/** 疎通確認。CORS が通っているかを 1 回の GET で確かめる。 */
export async function ping(base) {
  const out = await call(base, getTool("dns"), { target: "example.com", types: "A" });
  if (out.status !== 200) throw new Error(`API が HTTP ${out.status} を返しました`);
  if (!out.json?.ok) throw new Error(out.json?.error || "API が ok:false を返しました");
  return out;
}

/* ---------------- 値の抽出 ---------------- */

/**
 * WHOIS / RDAP の応答を 1 つの形に均す。
 *
 * この API の rdap は 2026-07 に応答の形が変わり、平たい record を返すようになった。
 * 古い形（rdap.data + whois.iana）で動いている環境もあり得るので両方読む。
 * record 側のキー名には綴りの揺れ（namerservers / registranct_contact_email）が
 * あるため、正しい綴りも一緒に見る。
 */
export function rdapRecord(d) {
  const r = d?.record || {};
  const legacy = d?.rdap?.data || {};
  const ev = (action) => (legacy.events || []).find((e) => e.eventAction === action)?.eventDate || null;

  return {
    registrar: r.registrar
      || (legacy.entities || []).find((e) => (e.roles || []).includes("registrar"))
        ?.vcardArray?.[1]?.find((f) => f[0] === "fn")?.[3]
      || null,
    created: r.create_date || ev("registration"),
    updated: r.update_date || ev("last changed"),
    expires: r.expired_date || ev("expiration"),
    status: r.domain_status || legacy.status || [],
    nameservers: (r.namerservers || r.nameservers
      || (legacy.nameservers || []).map((n) => n.ldhName)).filter(Boolean),
    contact: r.registranct_contact_email || r.registrant_contact_email || null,
    note: r.note || null,
    raw: r.raw_whois || d?.whois?.iana?.text || null,
  };
}

function push(out, seen, type, value, rel) {
  const v = String(value ?? "").trim().replace(/\.$/, "");
  if (!v) return;
  const k = `${type}:${v.toLowerCase()}`;
  if (seen.has(k)) return;
  seen.add(k);
  out.push({ type, value: v, rel });
}

/* ---------------- ツール定義 ---------------- */

const DNS_DEFAULT = "A,AAAA,MX,NS,TXT";
const DNS_TYPES = "A, AAAA, CNAME, MX, NS, TXT, SOA, CAA, PTR";

/**
 * 1 ツール = 1 エンドポイント。
 *   params  … 画面のフォームを組み立てる定義
 *   query   … クエリ文字列に載せる値（GET）
 *   body    … JSON 本文（POST）
 *   headers … 追加ヘッダ（プリフライトが必要になる点に注意）
 *   summary … 結果の要点を [[見出し, 値]] で
 *   iocs    … ワークベンチに送れる値
 */
export const TOOLS = [
  {
    id: "dns",
    label: "DNS 照会",
    desc: "A / AAAA / MX / NS / TXT などのレコードを引く",
    method: "GET",
    path: "api/tools/dns",
    params: [
      { name: "target", label: "対象", placeholder: "example.com", required: true },
      { name: "types", label: "レコード種別", placeholder: DNS_DEFAULT, hint: `カンマ区切り・最大 9 種（${DNS_TYPES}）` },
    ],
    query: (v) => ({ target: v.target, types: v.types || "" }),
    summary: (d) => [
      ["対象", d.target],
      ["照会時刻", d.queriedAt],
      ["応答のあった種別", (d.results || []).filter((r) => r.answers?.length).map((r) => r.type).join(", ") || "なし"],
    ],
    iocs: (d) => {
      const out = [], seen = new Set();
      for (const r of d.results || []) {
        for (const a of r.answers || []) {
          const data = String(a.data ?? "").trim();
          if (!data) continue;
          if (r.type === "A") push(out, seen, "ioc.ipv4", data, "DNS: A");
          else if (r.type === "AAAA") push(out, seen, "ioc.ipv6", data, "DNS: AAAA");
          else if (r.type === "MX") push(out, seen, "ioc.domain", data.replace(/^\d+\s+/, ""), "DNS: MX");
          else if (r.type === "NS" || r.type === "CNAME") push(out, seen, "ioc.domain", data, `DNS: ${r.type}`);
        }
      }
      return out;
    },
  },

  {
    id: "rdap",
    label: "RDAP / WHOIS",
    desc: "登録情報を引く（ドメインのみ）",
    method: "GET",
    path: "api/tools/rdap",
    params: [{ name: "target", label: "ドメイン", placeholder: "example.com", required: true }],
    query: (v) => ({ target: v.target }),
    summary: (d) => {
      const r = rdapRecord(d);
      return [
        ["対象", d.target],
        ["レジストラ", r.registrar],
        ["登録日", r.created],
        ["最終更新", r.updated],
        ["有効期限", r.expires],
        ["ステータス", r.status.join(" / ")],
        ["ネームサーバー", r.nameservers.join(", ")],
        ["連絡先", r.contact],
        ["注記", r.note],
      ];
    },
    detail: (d) => rdapRecord(d).raw || "",
    iocs: (d) => {
      const out = [], seen = new Set();
      for (const n of rdapRecord(d).nameservers) push(out, seen, "ioc.domain", n, "WHOIS: NS");
      return out;
    },
  },

  {
    id: "certificate",
    label: "証明書 (CT ログ)",
    desc: "crt.sh から発行済み証明書を引く。サブドメインの洗い出しに使える",
    method: "GET",
    path: "api/tools/certificate",
    params: [{ name: "target", label: "ドメイン", placeholder: "example.com", required: true }],
    query: (v) => ({ target: v.target }),
    summary: (d) => [["対象", d.target], ["取得元", d.source], ["件数", d.count]],
    iocs: (d) => {
      const out = [], seen = new Set();
      for (const c of d.certificates || []) {
        // ワイルドカードはそのままでは名前として使えないので裸のドメインに直す。
        // CN には組織名（"The OFCA Project" など）も入るので、ドメインの形だけ拾う。
        const name = String(c.common_name || "").replace(/^\*\./, "").trim();
        if (detectType(name) !== "ioc.domain") continue;
        push(out, seen, "ioc.domain", name, "CT: common_name");
      }
      return out;
    },
  },

  {
    id: "web-analyze",
    label: "Web 解析",
    desc: "使われている技術・Cookie 名・注目ヘッダ・リンクを取る",
    method: "GET",
    path: "api/tools/web-analyze",
    params: [{ name: "url", label: "URL", placeholder: "https://example.com/", required: true }],
    query: (v) => ({ url: v.url }),
    summary: (d) => [
      ["HTTP", d.response?.status != null ? `${d.response.status} ${d.response.statusText || ""}`.trim() : null],
      ["種類", d.response?.contentType],
      ["所要", d.response?.durationMs != null ? `${d.response.durationMs} ms` : null],
      ["解決 IP", (d.request?.resolvedIps || []).join(", ")],
      ["技術", (d.analysis?.technologies || []).join(", ")],
      ["Cookie", (d.analysis?.cookieNames || []).join(", ")],
      ["注目ヘッダ", Object.entries(d.analysis?.notableHeaders || {}).map(([k, v]) => `${k}: ${v}`).join(" / ")],
      ["リンク", d.analysis?.counts?.links],
      ["内部パス", d.analysis?.counts?.internalPaths],
    ],
    iocs: (d) => {
      const out = [], seen = new Set();
      for (const ip of d.request?.resolvedIps || []) {
        push(out, seen, detectType(ip) === "ioc.ipv6" ? "ioc.ipv6" : "ioc.ipv4", ip, "Web 解析: 解決 IP");
      }
      return out;
    },
  },

  {
    id: "banner",
    label: "バナー取得",
    desc: "指定ポートに繋いで応答の先頭を取る",
    method: "GET",
    path: "api/tools/banner",
    params: [
      { name: "target", label: "対象", placeholder: "example.com", required: true },
      { name: "port", label: "ポート", placeholder: "80", type: "number" },
      { name: "tls", label: "TLS を使う", type: "checkbox", hint: "443 / 8443 / 9443 は自動で有効" },
      { name: "payload", label: "送信ペイロード", placeholder: "（任意）", hint: "最大 4 KiB" },
    ],
    query: (v) => ({ target: v.target, port: v.port || "", tls: v.tls ? "true" : "", payload: v.payload || "" }),
    // TLS のときは HTTPS の HEAD になり、生の TCP とは応答の形が変わる
    // （transport / status / headers が付き、resolvedIps と bytes は無い）
    summary: (d) => [
      ["対象", `${d.target}:${d.port}`],
      ["TLS", d.tls ? "あり" : "なし"],
      ["経路", d.transport],
      ["HTTP", d.status != null ? `${d.status} ${d.statusText || ""}`.trim() : null],
      ["所要", d.durationMs != null ? `${d.durationMs} ms` : null],
      ["解決 IP", (d.resolvedIps || []).join(", ")],
      ["受信", d.banner?.bytes ? `${d.banner.bytes} バイト${d.banner.truncated ? "（打ち切り）" : ""}` : null],
      ["タイムアウト", d.banner?.timedOut ? "した" : null],
    ],
    detail: (d) => d.banner?.utf8 || "",
    iocs: (d) => {
      const out = [], seen = new Set();
      for (const ip of d.resolvedIps || []) {
        push(out, seen, detectType(ip) === "ioc.ipv6" ? "ioc.ipv6" : "ioc.ipv4", ip, "バナー: 解決 IP");
      }
      if (d.target && d.port) push(out, seen, "ioc.endpoint", `${d.target}:${d.port}`, "バナー: 応答あり");
      return out;
    },
  },

  {
    id: "open-directory",
    label: "Open Directory",
    desc: "ディレクトリ一覧が開いている配信元を辿って木構造にする",
    method: "GET",
    path: "api/tools/open-directory",
    async: true,
    params: [
      { name: "url", label: "URL", placeholder: "https://example.com/files/", required: true },
      { name: "depth", label: "深さ", placeholder: "3", type: "number" },
      { name: "maxEntries", label: "最大件数", placeholder: "5000", type: "number" },
      { name: "path", label: "起点からの相対パス", placeholder: "（任意）" },
    ],
    query: (v) => ({ url: v.url, depth: v.depth || "", maxEntries: v.maxEntries || "", path: v.path || "" }),
    progress: (p) => `走査 ${p.scannedDirectories ?? 0} ディレクトリ / 発見 ${p.discoveredEntries ?? 0} 件`
      + (p.queuedDirectories ? `（残り ${p.queuedDirectories}）` : ""),
    summary: (d) => [
      ["起点", d.rootUrl],
      ["解決 IP", (d.resolvedIps || []).join(", ")],
      ["走査ディレクトリ", d.scannedDirectories],
      ["見つかった項目", (d.entries || []).length],
      ["深さ", d.depth],
      ["打ち切り", d.truncated ? "した" : "していない"],
      ["所要", d.durationMs != null ? `${d.durationMs} ms` : null],
      ["エラー", (d.errors || []).length || null],
    ],
    detail: (d) => d.treeText || "",
    iocs: (d) => {
      const out = [], seen = new Set();
      for (const ip of d.resolvedIps || []) {
        push(out, seen, detectType(ip) === "ioc.ipv6" ? "ioc.ipv6" : "ioc.ipv4", ip, "Open Directory: 解決 IP");
      }
      try {
        push(out, seen, "ioc.domain", new URL(d.rootUrl).hostname, "Open Directory: 配信元");
      } catch { /* URL が壊れていても他は出す */ }
      return out;
    },
  },

  {
    id: "port-scan",
    label: "ポート確認",
    desc: "TCP が開いているかを見る。既定は主要 28 ポート",
    method: "GET",
    path: "api/tools/port-scan",
    async: true,
    params: [
      { name: "target", label: "対象", placeholder: "example.com", required: true },
      { name: "ports", label: "ポート", placeholder: "22,80,443 または 8000-8100" },
    ],
    query: (v) => ({ target: v.target, ports: v.ports || "" }),
    progress: (p) => `走査 ${p.scannedPorts ?? 0} / ${p.totalPorts ?? "?"} ポート・開 ${p.openPorts ?? 0}`,
    summary: (d) => [
      ["対象", d.target],
      ["解決 IP", (d.resolvedIps || []).join(", ")],
      ["調べた数", d.scannedPortCount],
      ["開いていたポート", (d.openports || d.openPorts || []).join(", ") || "なし"],
      ["所要", d.durationMs != null ? `${d.durationMs} ms` : null],
    ],
    iocs: (d) => {
      const out = [], seen = new Set();
      for (const p of d.openports || d.openPorts || []) {
        push(out, seen, "ioc.endpoint", `${d.target}:${p}`, "ポート確認: 開いている");
      }
      return out;
    },
  },

  {
    id: "virustotal",
    label: "VirusTotal",
    desc: "VirusTotal v3 を API 経由で引く",
    // キーがこの API サーバーを経由する点は画面側で明示する
    keyWarning: true,
    method: "GET",
    path: "api/tools/virustotal",
    params: [
      { name: "type", label: "種別", type: "select", options: ["ip", "domain", "url", "file"], required: true },
      { name: "value", label: "値", placeholder: "8.8.8.8 / example.com / ハッシュ", required: true },
      { name: "relationships", label: "関連", placeholder: "（任意）", hint: "カンマ区切り・最大 8" },
      { name: "apikey", label: "VirusTotal API キー", type: "password", required: true,
        hint: "Authorization: Bearer で API サーバーに渡します（ブラウザの外に出ます）" },
    ],
    query: (v) => ({ type: v.type, value: v.value, relationships: v.relationships || "" }),
    headers: (v) => ({ authorization: `Bearer ${v.apikey}` }),
    summary: (d) => [
      ["判定", d.summary?.verdict],
      ["検知", d.summary?.analysisStats
        ? `悪性 ${d.summary.analysisStats.malicious ?? 0} / 疑わしい ${d.summary.analysisStats.suspicious ?? 0}` : null],
      ["評判", d.summary?.reputation],
      ["種別", d.data?.type],
      ["id", d.data?.id],
      // カテゴリはベンダーごとのサイト分類で、マルウェア名ではない。要約にだけ出す
      ["カテゴリ", [...new Set(Object.values(d.summary?.categories || {}))].join(", ")],
      ["AS所有者", d.data?.attributes?.as_owner],
      ["国", d.data?.attributes?.country],
      ["関連の種類", (d.summary?.relationshipNames || []).join(", ")],
    ],
    iocs: (d) => {
      const out = [], seen = new Set();
      const a = d.data?.attributes || {};
      for (const r of a.last_dns_records || []) {
        if (r.type === "A") push(out, seen, "ioc.ipv4", r.value, "VT: Aレコード");
      }
      const family = a.popular_threat_classification?.suggested_threat_label;
      if (family) push(out, seen, "malware", family, "VT: 推定ファミリ");
      return out;
    },
  },

  {
    id: "github",
    label: "GitHub 調査",
    desc: "コード検索・利用者のリポジトリ・所有者・関係をたどる",
    keyWarning: true,
    method: "GET",
    path: "api/tools/github",
    // action によって使う引数が変わるので、選び直したらフォームを組み直す
    rebuildOn: ["action"],
    params: (v) => {
      const action = v.action || "code-search";
      const common = [
        { name: "action", label: "動作", type: "select", required: true,
          options: ["code-search", "user-repositories", "repository-owners", "relationships"] },
      ];
      const byAction = {
        "code-search": [
          { name: "query", label: "検索語", placeholder: "パターンや文字列", required: true },
          { name: "mode", label: "モード", type: "select", options: ["", "literal", "regex"],
            hint: "regex は候補 30 件まで" },
          { name: "qualifiers", label: "絞り込み", placeholder: "language:python など" },
        ],
        "user-repositories": [
          { name: "username", label: "利用者名", placeholder: "octocat", required: true },
        ],
        "repository-owners": [
          { name: "repository", label: "リポジトリ", placeholder: "owner/repo", required: true },
        ],
        relationships: [
          { name: "seed", label: "起点", placeholder: "利用者名やリポジトリ", required: true },
          { name: "targetType", label: "対象種別", placeholder: "（任意）" },
          { name: "owner", label: "所有者", placeholder: "（任意）" },
        ],
      };
      return [
        ...common,
        ...byAction[action],
        { name: "token", label: "GitHub トークン", type: "password", required: true,
          hint: "Authorization: Bearer で API サーバーに渡します（ブラウザの外に出ます）" },
      ];
    },
    query: (v) => ({
      action: v.action || "code-search",
      query: v.query || "", mode: v.mode || "", qualifiers: v.qualifiers || "",
      seed: v.seed || "", username: v.username || "", repository: v.repository || "",
      targetType: v.targetType || "", owner: v.owner || "",
    }),
    headers: (v) => ({ authorization: `Bearer ${v.token}` }),
    summary: (d) => [
      ["動作", d.action],
      ["GitHub のクエリ", d.query?.githubQuery || d.query?.pattern],
      ["モード", d.query?.mode],
      ["一致ファイル", d.matchedFileCount],
      ["リポジトリ", d.repositoryCount ?? (d.repositories || []).length],
      ["残り回数", d.rateLimit?.remaining],
    ],
    detail: (d) => (d.repositories || [])
      .map((r) => `${r.fullName || "?"}  ${r.htmlUrl || ""}`).join("\n"),
    iocs: (d) => {
      const out = [], seen = new Set();
      for (const r of d.repositories || []) {
        if (r.htmlUrl) push(out, seen, "ioc.url", r.htmlUrl, "GitHub: リポジトリ");
      }
      return out;
    },
  },

  {
    id: "request",
    label: "任意リクエスト",
    desc: "API サーバー経由で任意の URL を叩く（本文は JSON で渡す）",
    method: "POST",
    path: "api/request",
    params: [
      { name: "url", label: "URL", placeholder: "https://example.com/", required: true },
      { name: "method", label: "メソッド", type: "select", options: ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"] },
      { name: "followRedirects", label: "リダイレクトを追う", type: "checkbox", hint: "最大 10 回" },
      { name: "headers", label: "ヘッダ (JSON)", placeholder: '{"accept":"application/json"}' },
      { name: "body", label: "本文", placeholder: "（任意）" },
    ],
    body: (v) => {
      let headers;
      try { headers = v.headers ? JSON.parse(v.headers) : undefined; } catch { throw new Error("ヘッダが JSON として読めません"); }
      return {
        url: v.url, method: v.method || "GET", headers, body: v.body || undefined,
        followRedirects: !!v.followRedirects,
      };
    },
    summary: (d) => {
      const chain = d.request?.redirectChain || [];
      return [
        ["宛先", d.request?.url],
        ["メソッド", d.request?.method],
        ["解決 IP", (d.request?.resolvedIps || []).join(", ")],
        ["最終 URL", d.request?.finalUrl && d.request.finalUrl !== d.request.url ? d.request.finalUrl : null],
        ["最終の解決 IP", chain.length ? (d.request?.finalResolvedIps || []).join(", ") : null],
        ["転送", chain.length ? chain.map((r) => `${r.status} → ${r.location}`).join(" / ") : null],
        ["HTTP", d.response?.status != null ? `${d.response.status} ${d.response.statusText || ""}`.trim() : null],
        ["所要", d.response?.durationMs != null ? `${d.response.durationMs} ms` : null],
        ["種類", d.response?.contentType],
      ];
    },
    detail: (d) => d.response?.body || d.response?.data || "",
    iocs: (d) => {
      const out = [], seen = new Set();
      const ips = [...(d.request?.resolvedIps || []), ...(d.request?.finalResolvedIps || [])];
      for (const ip of ips) {
        push(out, seen, detectType(ip) === "ioc.ipv6" ? "ioc.ipv6" : "ioc.ipv4", ip, "任意リクエスト: 解決 IP");
      }
      for (const r of d.request?.redirectChain || []) {
        if (r.location) push(out, seen, "ioc.url", r.location, `任意リクエスト: ${r.status} の転送先`);
      }
      return out;
    },
  },
];

export function getTool(id) {
  return TOOLS.find((t) => t.id === id) || null;
}
