// Active Research API（https://hellow-world.hiroshiba.chatgpt.site）のクライアント。
//
// ヘッダの使い分け（2026-07 に API 側が分離した）:
//   Authorization: Bearer … **この API のセッショントークン**（GitHub ログインで得る）
//   X-VirusTotal-Key など … 各外部サービスの API キー（ツール定義の keyHeader）
// 以前は Authorization を外部キーの受け渡しにも使っていたので衝突していた。
//
// セッションは auth-active-research.js が持つ。ログインしていなければ何も付けない
// （API 側は enforcement_enabled が false のあいだ匿名でも動く）。
// ベース URL は設定で変えられる（自前の別環境に向けられるように）。
//
// CORS の実測（2026-07）:
//   Access-Control-Allow-Origin: *（Cookie を使わないのでこれで足りる）
//   Access-Control-Allow-Headers: content-type, accept, authorization,
//     x-virustotal-key, x-github-token, x-abuseipdb-key, x-urlscan-api-key,
//     x-censys-token, x-cloudflare-api-token …
//   Access-Control-Expose-Headers: retry-after, x-ratelimit-interval, www-authenticate
//   Access-Control-Allow-Methods: GET, POST, OPTIONS / プリフライトは 204 / max-age 86400
//   → ブラウザから直接呼べる。中継は要らない。
//   www-authenticate が読めるので、この API が出した 401 と外部サービスの 401 を区別できる。
//   将来 Origin を絞ったときに気づけるよう、失敗時は CORS の可能性も併記して出す。
//
// port-scan と open-directory は非同期ジョブ。start が 202 で job.id を返し、
// action=status&jobId=… を completed になるまで叩く。結果は job.result に入っていて、
// 中身は同期だった頃と同じ形なので、要約と値の抽出はそのまま使える。

import { authHeaders, recoverFromUnauthorized } from "./auth-active-research.js";
import { detectType } from "./util.js";

export const DEFAULT_BASE = "https://hellow-world.hiroshiba.chatgpt.site";

/** ジョブ待ちの上限。open-directory は仕様上 5 分まで走る。 */
const POLL_INTERVAL_MS = 1200;
const POLL_TIMEOUT_MS = 5 * 60 * 1000;

/**
 * レート制限（HTTP 429）への対応。
 *
 * API は悪用防止のため機能ごとに間隔を設けている（実測: 匿名は 5 秒に 1 回、
 * 認証済みは 1 秒に 1 回。Browser Gateway は分あたりの回数）。超えると
 *   HTTP 429 / Retry-After: 4 / X-RateLimit-Interval: 5
 *   {"ok":false,"retryAfterSeconds":4,"rateLimitTier":"anonymous","intervalSeconds":5}
 * が返る。Retry-After と X-RateLimit-Interval は
 * Access-Control-Expose-Headers に入っているのでブラウザから読める。
 *
 * 待てば必ず通るものなので、待って自動でやり直す。利用者に「失敗」と
 * 見せる必要はないが、黙って止まって見えるのも困るので待機中は画面に出す。
 */
const RATE_LIMIT_RETRIES = 3;
/** サーバーの時計とのずれで待ち足りないことがあるので少し足す。 */
const RETRY_PAD_MS = 350;

/**
 * 機能ごとの最短間隔（秒）。429 や応答ヘッダから学ぶ。
 * ジョブのポーリング間隔をこれ以上に広げて、こちらから 429 を誘発しないようにする。
 */
const intervalByTool = new Map();

function noteInterval(toolId, res, json) {
  const sec = Number(res.headers.get("x-ratelimit-interval")) || Number(json?.intervalSeconds) || 0;
  if (sec > 0) intervalByTool.set(toolId, sec);
}

/** 429 のときに待つミリ秒。指定が無ければ間隔から、それも無ければ控えめな既定値。 */
function retryDelayMs(res, json, toolId) {
  const sec = Number(json?.retryAfterSeconds)
    || Number(res.headers.get("retry-after"))
    || intervalByTool.get(toolId)
    || 5;
  return Math.min(30_000, Math.max(500, sec * 1000)) + RETRY_PAD_MS;
}

/* ---------------- 通信 ---------------- */

const sleep = (ms, signal) => new Promise((resolve, reject) => {
  const t = setTimeout(resolve, ms);
  signal?.addEventListener("abort", () => { clearTimeout(t); reject(new DOMException("aborted", "AbortError")); },
    { once: true });
});


/**
 * API を 1 回叩く。
 *
 * fetch が TypeError で落ちるのは「CORS で読ませてもらえなかった」ときと
 * 「そもそも繋がらなかった」ときの両方なので、その場で切り分けられない。
 * ブラウザは理由を JS に渡さない仕様なので、両方の可能性を書いて返す。
 */
export async function call(base, tool, values, { signal, retried = false, onWait, rateTry = 0 } = {}) {
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
  // この API のセッション。ログインしていなければ何も付かない
  Object.assign(init.headers, await authHeaders());
  // 外部サービスのキーは、ツールごとの専用ヘッダで渡す
  if (tool.keyHeader && values[tool.keyField || "apikey"]) {
    init.headers[tool.keyHeader] = values[tool.keyField || "apikey"];
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
  noteInterval(tool.id, res, json);

  // レート制限。待てば通るので、待ってからやり直す
  if (res.status === 429 && rateTry < RATE_LIMIT_RETRIES) {
    const wait = retryDelayMs(res, json, tool.id);
    onWait?.({
      seconds: Math.ceil(wait / 1000),
      attempt: rateTry + 1,
      of: RATE_LIMIT_RETRIES,
      tier: json?.rateLimitTier || null,
    });
    await sleep(wait, signal);
    return call(base, tool, values, { signal, retried, onWait, rateTry: rateTry + 1 });
  }

  // セッションが切れていたら 1 回だけ取り直して同じ要求をやり直す。
  // 外部サービス側の 401（キーが違う）と混ざらないよう、
  // WWW-Authenticate が付いている＝この API が出した 401 のときだけ扱う。
  if (res.status === 401 && !retried && res.headers.get("www-authenticate")) {
    if (await recoverFromUnauthorized(json)) {
      return call(base, tool, values, { signal, retried: true, onWait, rateTry });
    }
  }

  return { status: res.status, ms, url: url.href, text, json };
}

/**
 * ジョブの状態を 1 回見る。
 *
 * status もレート制限の対象。**セッションを付けないと匿名扱い（5 秒に 1 回）**に
 * なるので、ここでも Authorization を送る。429 のときは待ってやり直す。
 */
async function fetchJob(base, tool, jobId, signal, { onWait, rateTry = 0 } = {}) {
  const url = new URL(tool.path, base.replace(/\/+$/, "") + "/");
  url.searchParams.set("action", "status");
  url.searchParams.set("jobId", jobId);
  const res = await fetch(url, {
    signal, credentials: "omit", headers: { ...(await authHeaders()) },
  });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* JSON でないこともある */ }
  noteInterval(tool.id, res, json);

  if (res.status === 429 && rateTry < RATE_LIMIT_RETRIES) {
    const wait = retryDelayMs(res, json, tool.id);
    onWait?.({ seconds: Math.ceil(wait / 1000), attempt: rateTry + 1, of: RATE_LIMIT_RETRIES,
      tier: json?.rateLimitTier || null, polling: true });
    await sleep(wait, signal);
    return fetchJob(base, tool, jobId, signal, { onWait, rateTry: rateTry + 1 });
  }
  return { status: res.status, text, json };
}

/**
 * ツールを 1 回実行する。非同期ジョブなら完了まで面倒を見る。
 *
 * 返り値の data が「要約と値の抽出に渡すもの」。同期ツールなら応答そのもの、
 * 非同期ツールなら job.result。raw は画面に出す生の応答で、ジョブの封筒ごと残す。
 */
export async function run(base, tool, values, { signal, onProgress, onWait } = {}) {
  const first = await call(base, tool, values, { signal, onWait });
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
    // 学んだ最短間隔より短く叩かない。こちらから 429 を誘発しないため
    const gap = Math.max(POLL_INTERVAL_MS, (intervalByTool.get(tool.id) || 0) * 1000);
    await sleep(gap, signal);
    const st = await fetchJob(base, tool, jobId, signal, { onWait });
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

/**
 * AbuseIPDB の通報カテゴリ。数字だけ返るので名前にする。
 * https://www.abuseipdb.com/categories
 */
const ABUSE_CATEGORIES = {
  1: "DNS 侵害", 2: "DNS 汚染", 3: "詐欺注文", 4: "DDoS", 5: "FTP 総当たり",
  6: "Ping of Death", 7: "フィッシング", 8: "VoIP 詐欺", 9: "オープンプロキシ",
  10: "Web スパム", 11: "メールスパム", 12: "ブログスパム", 13: "VPN", 14: "ポートスキャン",
  15: "ハッキング", 16: "SQL インジェクション", 17: "なりすまし", 18: "総当たり",
  19: "不正ボット", 20: "踏み台", 21: "Web アプリ攻撃", 22: "SSH", 23: "IoT 標的",
};

/** カテゴリの集計を「多い順」の 1 行にする。 */
export function abuseCategoryText(counts, limit = 6) {
  if (!counts?.size) return null;
  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, limit)
    .map(([id, n]) => `${ABUSE_CATEGORIES[id] || `分類 ${id}`} ${n}`)
    .join(" / ");
}

/**
 * AbuseIPDB の応答を 1 つの形に均す。
 *
 * この API は `{ ok, source, query, summary, data, note }` を返す。summary と data は
 * 中身が少しずつ違う（summary だけに組織名と国名、data だけにホスト名と通報明細）ので
 * 重ねて読む。包み方が変わっても拾えるよう、素通しと 1 枚包みも見る。
 *
 * score が見つからなければ null。「0 点」とは言わない（分からないことを安全側に丸めない）。
 */
export function abuseRecord(d) {
  const has = (c) => c && typeof c === "object" && "abuseConfidenceScore" in c;
  const layers = [d?.data?.data, d?.data, d?.summary, d?.result, d].filter(has);
  // 後ろの層ほど優先度が低い。先に見つかった値を残す
  const a = Object.assign({}, ...layers.slice().reverse());
  const num = (v) => (typeof v === "number" && Number.isFinite(v) ? v : null);

  // verbose のときだけ入る通報明細。何をして通報されたかがスコアの根拠になる
  const categories = new Map();
  for (const r of Array.isArray(a.reports) ? a.reports : []) {
    for (const c of r.categories || []) categories.set(c, (categories.get(c) || 0) + 1);
  }

  return {
    ip: a.ipAddress ?? null,
    score: num(a.abuseConfidenceScore),
    reports: num(a.totalReports),
    users: num(a.numDistinctUsers),
    lastReportedAt: a.lastReportedAt ?? null,
    isp: a.isp ?? null,
    org: a.asOrganization ?? null,
    asn: a.asn ?? null,
    usageType: a.usageType ?? null,
    country: a.countryCode ?? a.countryName ?? null,
    countryName: a.countryName ?? null,
    domain: a.domain ?? null,
    hostnames: Array.isArray(a.hostnames) ? a.hostnames : [],
    whitelisted: typeof a.isWhitelisted === "boolean" ? a.isWhitelisted : null,
    tor: typeof a.isTor === "boolean" ? a.isTor : null,
    categories,
    detailCount: Array.isArray(a.reports) ? a.reports.length : null,
    note: d?.note ?? null,
  };
}

/**
 * Censys の応答から値を取り出す小道具。
 *
 * Platform API v3 のヒットは `data.result.hits[]` で、フィールド名は
 * 契約プランと fields 指定で変わる。取れなければ空を返して落ちないようにする。
 */
export function censysHits(d) {
  const hits = d?.data?.result?.hits ?? d?.data?.hits ?? d?.result?.hits;
  return Array.isArray(hits) ? hits : [];
}

export function censysIp(hit) {
  return hit?.host?.ip ?? hit?.ip ?? hit?.["host.ip"] ?? null;
}

export function censysPorts(hit) {
  const svc = hit?.host?.services ?? hit?.services ?? [];
  const ports = (Array.isArray(svc) ? svc : []).map((x) => x?.port).filter((p) => Number.isFinite(p));
  const flat = hit?.["host.services.port"];
  if (!ports.length && Array.isArray(flat)) return flat.filter((p) => Number.isFinite(p));
  return [...new Set(ports)];
}

export function censysNames(hit) {
  const out = new Set();
  for (const n of hit?.host?.dns?.names ?? hit?.dns?.names ?? []) {
    if (detectType(n) === "ioc.domain") out.add(n);
  }
  const web = hit?.web?.hostname ?? hit?.["web.hostname"];
  if (web && detectType(web) === "ioc.domain") out.add(web);
  return [...out];
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
    label: "Web 解析（旧）",
    deprecated: "API 側で deprecated。/api/request の includeAnalyze に移行済み",
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
        hint: "X-VirusTotal-Key で API サーバーに渡します（ブラウザの外に出ます）" },
    ],
    query: (v) => ({ type: v.type, value: v.value, relationships: v.relationships || "" }),
    keyHeader: "X-VirusTotal-Key",
    credProvider: "virustotal",
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
    id: "abuseipdb",
    label: "AbuseIPDB",
    desc: "IP の通報状況を API 経由で引く",
    keyWarning: true,
    method: "GET",
    path: "api/tools/abuseipdb",
    params: [
      { name: "ip", label: "IP アドレス", placeholder: "8.8.8.8", required: true },
      { name: "maxAgeInDays", label: "遡る日数", placeholder: "90", type: "number", hint: "既定 90・最大 365" },
      { name: "verbose", label: "通報の明細も取る", type: "checkbox", hint: "何をして通報されたかの内訳が付く" },
      { name: "apikey", label: "AbuseIPDB API キー", type: "password", required: true,
        hint: "X-AbuseIPDB-Key で API サーバーに渡します（ブラウザの外に出ます）" },
    ],
    query: (v) => ({ ip: v.ip, maxAgeInDays: v.maxAgeInDays || "", verbose: v.verbose ? "true" : "" }),
    keyHeader: "X-AbuseIPDB-Key",
    credProvider: "abuseipdb",
    summary: (d) => {
      const a = abuseRecord(d);
      return [
        ["信頼度スコア", a.score != null ? `${a.score} / 100` : null],
        ["通報数", a.reports],
        ["通報した利用者数", a.users],
        ["最終通報", a.lastReportedAt],
        ["通報の種類", abuseCategoryText(a.categories)],
        ["ISP", a.isp],
        ["組織", a.org],
        ["用途", a.usageType],
        ["国", a.country],
        ["ドメイン", a.domain],
        ["ホスト名", (a.hostnames || []).join(", ")],
        ["ホワイトリスト", a.whitelisted == null ? null : a.whitelisted ? "はい" : "いいえ"],
        ["Tor", a.tor == null ? null : a.tor ? "はい" : "いいえ"],
        ["注記", a.note],
      ];
    },
    iocs: (d) => {
      const out = [], seen = new Set();
      const a = abuseRecord(d);
      if (a.domain) push(out, seen, "ioc.domain", a.domain, "AbuseIPDB: ドメイン");
      for (const h of a.hostnames || []) push(out, seen, "ioc.domain", h, "AbuseIPDB: ホスト名");
      return out;
    },
  },

  {
    id: "urlscan",
    label: "urlscan",
    desc: "urlscan.io の既存スキャンを検索する（新規スキャンは投げない）",
    keyWarning: true,
    method: "GET",
    path: "api/tools/urlscan",
    params: [
      { name: "action", label: "動作", type: "select", options: ["search", "result"] },
      { name: "q", label: "検索クエリ", placeholder: "domain:example.com AND date:>now-30d",
        hint: "action=search で必須。ElasticSearch の query string 構文" },
      { name: "scanId", label: "Scan ID", placeholder: "（action=result で必須）" },
      { name: "size", label: "件数", placeholder: "25", type: "number", hint: "1〜100" },
      { name: "apikey", label: "urlscan API キー", type: "password", required: true,
        hint: "X-Urlscan-API-Key で API サーバーに渡します（ブラウザの外に出ます）" },
    ],
    query: (v) => ({ action: v.action || "search", q: v.q || "", scanId: v.scanId || "", size: v.size || "" }),
    keyHeader: "X-Urlscan-API-Key",
    credProvider: "urlscan",
    summary: (d) => {
      const r = d.data || {};
      const top = (r.results || [])[0];
      return [
        ["件数", r.total != null ? `${(r.results || []).length} / ${r.total}` : null],
        ["続きあり", r.has_more == null ? null : r.has_more ? "はい" : "いいえ"],
        ["先頭の URL", top?.page?.url || top?.task?.url],
        ["先頭の IP", top?.page?.ip],
        ["先頭の AS", top?.page?.asnname || top?.page?.asn],
        ["先頭の国", top?.page?.country],
        ["スキャン日時", top?.task?.time],
      ];
    },
    iocs: (d) => {
      const out = [], seen = new Set();
      for (const r of d.data?.results || []) {
        const p = r.page || {};
        if (p.ip) push(out, seen, detectType(p.ip) === "ioc.ipv6" ? "ioc.ipv6" : "ioc.ipv4", p.ip, "urlscan: 解決 IP");
        if (p.domain) push(out, seen, "ioc.domain", p.domain, "urlscan: ドメイン");
        const u = p.url || r.task?.url;
        if (u) push(out, seen, "ioc.url", u, "urlscan: スキャンした URL");
      }
      return out;
    },
  },

  {
    id: "censys",
    label: "Censys",
    desc: "Censys Platform API v3 に CenQL 検索を送る",
    keyWarning: true,
    method: "GET",
    path: "api/tools/censys",
    params: [
      { name: "query", label: "CenQL", placeholder: 'host.ip: 1.1.1.1', required: true,
        hint: 'host.ip: … / web.hostname: "…" / host.services.software.product="GitLab"' },
      { name: "pageSize", label: "件数", placeholder: "25", type: "number", hint: "1〜100" },
      { name: "fields", label: "取得フィールド", placeholder: "（任意）", hint: "カンマ区切り・最大 50" },
      { name: "apikey", label: "Censys Personal Access Token", type: "password", required: true,
        hint: "X-Censys-Token で API サーバーに渡します（ブラウザの外に出ます）" },
    ],
    query: (v) => ({ query: v.query, pageSize: v.pageSize || "", fields: v.fields || "" }),
    keyHeader: "X-Censys-Token",
    credProvider: "censys",
    summary: (d) => {
      const hits = censysHits(d);
      return [
        ["ヒット", hits.length || null],
        ["CenQL", d.query?.cenql],
        ["HTTP", d.response?.status],
        ["残りレート", d.response?.rateLimitRemaining],
        ["先頭の IP", hits[0] && censysIp(hits[0])],
        ["先頭のポート", hits[0] && censysPorts(hits[0]).join(", ")],
      ];
    },
    iocs: (d) => {
      const out = [], seen = new Set();
      for (const h of censysHits(d)) {
        const ip = censysIp(h);
        if (ip) push(out, seen, detectType(ip) === "ioc.ipv6" ? "ioc.ipv6" : "ioc.ipv4", ip, "Censys: ホスト");
        for (const name of censysNames(h)) push(out, seen, "ioc.domain", name, "Censys: 名前");
        for (const port of censysPorts(h)) {
          if (ip) push(out, seen, "ioc.endpoint", `${ip}:${port}`, "Censys: 開いているポート");
        }
      }
      return out;
    },
  },

  {
    id: "browser-gateway",
    label: "Browser Gateway",
    desc: "Cloudflare 上の Chromium で開いて画面と HTML を取る（自分のブラウザには読み込ませない）",
    keyWarning: true,
    method: "POST",
    path: "api/tools/browser-gateway",
    params: [
      { name: "url", label: "URL", placeholder: "https://example.com/", required: true },
      { name: "device", label: "端末", type: "select", options: ["desktop", "mobile"] },
      { name: "javascript", label: "JavaScript を実行する", type: "checkbox", hint: "既定は実行する" },
      { name: "scrollY", label: "スクロール位置", placeholder: "0", type: "number",
        hint: "JavaScript 無効時は 0 のみ" },
      { name: "accountId", label: "Cloudflare アカウント ID", type: "password", required: true,
        hint: "X-Cloudflare-Account-Id で渡します（ブラウザの外に出ます）" },
      { name: "apikey", label: "Cloudflare API トークン", type: "password", required: true,
        hint: "Browser Rendering - Edit 権限。X-Cloudflare-API-Token で渡します" },
    ],
    body: (v) => ({
      url: v.url,
      device: v.device || "desktop",
      // 未指定は「実行する」が既定。チェックを外したときだけ false を送る
      javascript: v.javascript === false ? false : undefined,
      scrollY: v.scrollY ? Number(v.scrollY) : undefined,
    }),
    keyHeader: "X-Cloudflare-API-Token",
    credProvider: "cloudflare_browser",
    headers: (v) => ({ "X-Cloudflare-Account-Id": v.accountId }),
    summary: (d) => {
      const g = d.gateway || {};
      return [
        ["HTTP", d.response?.status],
        ["題名", d.response?.title],
        ["最終 URL", d.response?.finalUrl],
        ["解決 IP", (d.request?.resolvedIps || []).join(", ")],
        ["描画", d.response?.browserMs != null ? `${d.response.browserMs} ms` : null],
        ["画面", g.screenshot ? `${g.screenshot.width}×${g.screenshot.height}` : null],
        ["リンク", (g.links || []).length || null],
        ["HTML", g.renderedHtml ? `${g.renderedHtml.length.toLocaleString()} 文字${g.renderedHtmlTruncated ? "（打ち切り）" : ""}` : null],
        ["自分のブラウザに読み込んでいない", g.targetLoadedInUserBrowser === false ? "はい" : null],
      ];
    },
    iocs: (d) => {
      const out = [], seen = new Set();
      for (const ip of d.request?.resolvedIps || []) {
        push(out, seen, detectType(ip) === "ioc.ipv6" ? "ioc.ipv6" : "ioc.ipv4", ip, "Browser Gateway: 解決 IP");
      }
      if (d.response?.finalUrl) push(out, seen, "ioc.url", d.response.finalUrl, "Browser Gateway: 最終 URL");
      for (const l of (d.gateway?.links || []).slice(0, 60)) {
        if (l.url) push(out, seen, "ioc.url", l.url, "Browser Gateway: ページ内リンク");
      }
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
    keyHeader: "X-GitHub-Token", keyField: "token",
    credProvider: "github",
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
      { name: "includeAnalyze", label: "ページ解析も付ける", type: "checkbox",
        hint: "技術・Cookie・リンク・内部パスを analysis に入れる（旧 Web 解析の後継）" },
      { name: "headers", label: "ヘッダ (JSON)", placeholder: '{"accept":"application/json"}' },
      { name: "body", label: "本文", placeholder: "（任意）" },
    ],
    body: (v) => {
      let headers;
      try { headers = v.headers ? JSON.parse(v.headers) : undefined; } catch { throw new Error("ヘッダが JSON として読めません"); }
      return {
        url: v.url, method: v.method || "GET", headers, body: v.body || undefined,
        followRedirects: !!v.followRedirects,
        // クエリでは効かない（実測）。必ず本文に載せる
        ...(v.includeAnalyze ? { includeAnalyze: true } : {}),
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
