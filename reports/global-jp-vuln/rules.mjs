// GLOBAL_JP_VULN の**判定規則**。build.mjs と関連調査の両方から使う。
//
// **判定を 2 箇所に持たない。** 片方だけ直すと「検査は通るのに中身が食い違う」
// 状態になる。カテゴリの分け方・コメントの無害化・証拠の段階・研究スキャナの
// 見分け方は、すべてここにある。
import crypto from "node:crypto";

/* ---------------- 公式カテゴリ（2026-10-09 に https://www.abuseipdb.com/categories で確認） ---------------- */
export const CATEGORIES = {
  1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders", 4: "DDoS Attack",
  5: "FTP Brute-Force", 6: "Ping of Death", 7: "Phishing", 8: "Fraud VoIP",
  9: "Open Proxy", 10: "Web Spam", 11: "Email Spam", 12: "Blog Spam",
  13: "VPN IP", 14: "Port Scan", 15: "Hacking", 16: "SQL Injection",
  17: "Spoofing", 18: "Brute-Force", 19: "Bad Web Bot", 20: "Exploited Host",
  21: "Web App Attack", 22: "SSH", 23: "IoT Targeted",
};
export const STRICT_VULN = new Set([16, 21, 23]);   // 脆弱性攻撃として強い
export const BROAD_VULN = new Set([15]);            // Hacking。広すぎるので単独では上げない
export const VULN_ANY = new Set([...STRICT_VULN, ...BROAD_VULN]);
export const AUTH_ATTACK = new Set([5, 18, 22]);    // 認証総当たり。別種として分ける
export const SCAN_ONLY = new Set([14]);
export const EXPLOITED_HOST = 20;                   // 技法ではなく「送信元が侵害されている」補助情報

/* ---------------- 小物 ---------------- */
export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
export const iso = (v) => { if (!v) return ""; const d = new Date(v); return isNaN(d) ? "" : d.toISOString().replace(/\.\d{3}Z$/, "Z"); };
export const sha256 = (s) => crypto.createHash("sha256").update(s, "utf8").digest("hex");
export const uniq = (a) => [...new Set(a)];

/** 再現できる擬似乱数（層化サンプル用）。シードは config に置く */
export function mulberry32(seed) {
  let a = seed >>> 0;
  return () => { a = (a + 0x6d2b79f5) >>> 0; let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
}

/* ---------------- コメントの扱い ----------------
 * 外部入力。命令として読まない・開かない・実行しない。表示用に無害化する。 */
export const ANSI = /\u001b\[[0-9;?]*[A-Za-z]/g;
export function sanitize(raw) {
  let s = String(raw || "");
  s = s.replace(ANSI, " ");
  s = s.replace(/<[^>]{0,200}>/g, " ");              // HTML タグ
  s = s.replace(/[\u0000-\u001f\u007f]/g, " ");      // 制御文字
  s = s.replace(/[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}/g, "<email>");
  s = s.replace(/\b(?:[A-Za-z0-9-]+\.)+(?:local|internal|lan|corp|home|intra)\b/gi, "<internal-host>");
  s = s.replace(/\s+/g, " ").trim();
  return s;
}
export const forDisplay = (s, n = 160) => (s.length > n ? s.slice(0, n) + "…" : s);

/* ---------------- 証拠の段階 ----------------
 * 上から順に当てる。**当たった語を必ず残す**（なぜその段階にしたかが後から読めるように）。 */
export const E3 = [
  [/\bCVE-\d{4}-\d{4,7}\b/i, "cve"],
  [/\bunion\s+(all\s+)?select\b/i, "sqli:union-select"],
  [/\b(information_schema|benchmark\s*\(|sleep\s*\(\s*\d|waitfor\s+delay|concat\s*\(\s*0x)/i, "sqli:payload"],
  [/('|%27)\s*(or|and)\s*('|%27)?\s*\d+\s*(=|%3d)\s*\d+/i, "sqli:tautology"],
  [/\$\{jndi:/i, "log4shell"],
  [/\b(wget|curl)\s+(http|ftp|\d{1,3}\.\d{1,3})/i, "rce:fetch"],
  [/(\/bin\/(sh|bash)|bash\s+-i|sh\s*\|\s*sh|;\s*sh\b|\|\s*sh\b)/i, "rce:shell"],
  [/\b(powershell|cmd\.exe|certutil|bitsadmin)\b/i, "rce:windows"],
  [/\b(system|exec|passthru|shell_exec|popen|proc_open)\s*\(/i, "rce:php-exec"],
  [/base64_decode\s*\(/i, "rce:base64"],
  [/\b(c99|r57|wso|alfa|b374k|adminer)\.php\b/i, "webshell:known"],
  [/\b(webshell|backdoor\.php|cmd\.php|shell\.php|up\.php|hack\.php)\b/i, "webshell:generic"],
  [/https?:\/\/\S+\.(sh|bin|elf|exe|mips|arm\d?|mpsl|x86)\b/i, "malware:fetch"],
];
export const E2 = [
  [/vendor\/phpunit|eval-stdin\.php/i, "phpunit-rce-path"],
  [/\bboaform\b|\/device\.rsp|goform\//i, "router:boa"],
  [/\bHNAP1\b/i, "dlink:hnap"],
  [/GponForm|\/diag_form/i, "gpon"],
  [/\b(struts|ognl|\.action\b)/i, "struts"],
  [/\b(thinkphp|think\\app|invokefunction)\b/i, "thinkphp"],
  [/\/(solr|jenkins|zabbix|confluence|gitlab|elasticsearch|druid|actuator|_ignition|hudson)\b/i, "product-path"],
  [/\/cgi-bin\/|luci\/|\/setup\.cgi|\/shell\?|\/stalker_portal/i, "cgi-or-embedded"],
  [/wp-content\/plugins\/[\w-]+/i, "wp-plugin-specific"],
  [/\b(nas|dvr|ipcam|hikvision|dahua|tp-link|netgear|zyxel|draytek|fortinet|fortios|pulse\s*secure|citrix|vmware|exchange|owa)\b/i, "product-name"],
  [/\/(manager\/html|axis2|jmx-console|invoker|wls-wsat|console\/login)\b/i, "appserver-path"],
];
export const E1 = [
  [/(^|\/|\s)\.env\b/i, "dotenv"],
  [/\.git\/config|\/\.git\b/i, "git-config"],
  [/wp-login\.php|xmlrpc\.php|\/wp-admin\b/i, "wordpress-generic"],
  [/phpmyadmin|\/pma\b|\/myadmin\b/i, "phpmyadmin"],
  [/\/(admin|administrator|login|manager)\b/i, "admin-path"],
  [/\.(bak|old|sql|zip|tar\.gz|conf|ini|yml|yaml)\b/i, "config-or-backup"],
  [/\b(scan|probe|exploit|attack|intrusion|malicious)\b/i, "offensive-wording"],
];
export function grade(text) {
  const hits = [];
  for (const [re, tag] of E3) if (re.test(text)) hits.push(tag);
  if (hits.length) return { level: 3, terms: hits };
  for (const [re, tag] of E2) if (re.test(text)) hits.push(tag);
  if (hits.length) return { level: 2, terms: hits };
  for (const [re, tag] of E1) if (re.test(text)) hits.push(tag);
  if (hits.length) return { level: 1, terms: hits };
  return { level: 0, terms: [] };
}

/* ---------------- 研究スキャナ ----------------
 * **クラウドの AS に居るというだけでは判定しない。** 名乗っているかどうかで見る。 */
export const SCANNER_HOST = [
  [/\.censys-scanner\.com$|\bcensys\b/i, "Censys", "high"],
  [/\.shadowserver\.org$/i, "Shadowserver Foundation", "high"],
  [/\.shodan\.io$|^census\d*\./i, "Shodan", "high"],
  [/\.binaryedge\.ninja$/i, "BinaryEdge", "high"],
  [/\.rapid7\.com$|\bsonar\.labs\b/i, "Rapid7 Project Sonar", "high"],
  [/\.stretchoid\.com$/i, "Stretchoid", "high"],
  [/\.onyphe\.(net|io)$/i, "ONYPHE", "high"],
  [/\.leakix\.(net|org)$/i, "LeakIX", "high"],
  [/\.internet-measurement\.com$/i, "Driftnet / internet-measurement.com", "high"],
  [/\.netsystemsresearch\.com$/i, "Net Systems Research", "high"],
  [/\.alphastrike\.io$/i, "Alpha Strike Labs", "high"],
  [/\.recyber\.net$/i, "Recyber", "high"],
  [/\.expanseinc\.com$|\bexpanse\b/i, "Palo Alto Cortex Xpanse", "high"],
  [/\.criminalip\.com$/i, "CriminalIP", "high"],
  [/researchscan|research-scan|\.comsys\.rwth-aachen\.de$/i, "大学等の研究スキャン", "high"],
  [/\.security\.ipip\.net$/i, "ipip.net", "high"],
  [/scanner|scanning/i, "名称に scanner を含む", "low"],
];
export const SCANNER_ORG = [
  [/\bcensys\b/i, "Censys", "high"],
  [/academy for internet research|\bafir\b/i, "Academy for Internet Research", "high"],
  [/alpha ?strike/i, "Alpha Strike Labs", "high"],
  [/shadowserver/i, "Shadowserver Foundation", "high"],
  [/\bshodan\b/i, "Shodan", "high"],
  [/binaryedge/i, "BinaryEdge", "high"],
  [/\brapid7\b/i, "Rapid7", "high"],
  [/\bonyphe\b/i, "ONYPHE", "high"],
  [/\bleakix\b/i, "LeakIX", "high"],
  [/driftnet/i, "Driftnet", "high"],
  [/net systems research/i, "Net Systems Research", "high"],
  [/bitsight/i, "BitSight", "medium"],
  [/securitytrails/i, "SecurityTrails", "medium"],
  [/\bnetcraft\b/i, "Netcraft", "medium"],
  [/internet census|census project/i, "Internet Census", "medium"],
];
export function detectScanner(d) {
  const hosts = (d.hostnames || []).join(" ");
  const org = [d.isp, d.domain].filter(Boolean).join(" ");
  for (const [re, name, conf] of SCANNER_HOST)
    if (re.test(hosts) || re.test(d.domain || "")) return { flag: true, name, confidence: conf, evidence: "hostname/domain: " + forDisplay(sanitize(hosts || d.domain || ""), 60) };
  for (const [re, name, conf] of SCANNER_ORG)
    if (re.test(org)) return { flag: true, name, confidence: conf, evidence: "isp/domain: " + forDisplay(sanitize(org), 60) };
  return { flag: false, name: "", confidence: "", evidence: "" };
}
/* ================= 応答を 1 行に畳む ================= =============================
 * **build.mjs から移した。判定を 2 箇所に持たないため。**
 *
 * `opts.checkedAt` は「いつ数えたか」。写しから組むときは写しの取得時刻を渡す。
 *   `new Date()` を内側で呼ぶと、同じ写しから違うものが出てしまう。
 * `opts.since` を渡すと、**その時刻より新しい報告だけ**で数え直す。
 *   365 日ぶんの写しから 90 日の窓を切り出すのに使う。このとき
 *   `total_reports_90d` は `d.totalReports`（窓の外も含む）ではなく
 *   **絞ったあとの件数**になる。reports 配列は 10,000 件で切られるので、
 *   切られた IP では下限値になる（`reports_truncated` が立つ）。
 */
export function digest(ip, body, cohort, opts = {}) {
  const { checkedAt = "", since = null } = opts;
  const d = body?.data || {};
  const allReports = Array.isArray(d.reports) ? d.reports : [];
  // 窓を切るときは、その窓の中の報告だけを母数にする
  const reports = since == null ? allReports
    : allReports.filter((r) => r.reportedAt && new Date(r.reportedAt).getTime() >= since);
  const jp = reports.filter((r) => r.reporterCountryCode === "JP");
  const catOf = (r) => (r.categories || []).map(Number);
  const hasAny = (r, set) => catOf(r).some((c) => set.has(c));

  // **日本の報告 1 件ずつで判定する**（IP 全体の和集合ではない）
  const jpVuln = jp.filter((r) => hasAny(r, VULN_ANY));
  const jpStrict = jp.filter((r) => hasAny(r, STRICT_VULN));
  const jpBroad = jp.filter((r) => hasAny(r, BROAD_VULN));
  const jpAuth = jp.filter((r) => hasAny(r, AUTH_ATTACK));
  const jpExploited = jp.filter((r) => catOf(r).includes(EXPLOITED_HOST));
  const jpScanOnly = jp.filter((r) => !hasAny(r, VULN_ANY) && (hasAny(r, SCAN_ONLY) || catOf(r).length === 0));

  // 証拠は **日本の脆弱性報告のコメントからだけ**取る
  const graded = jpVuln.map((r) => {
    const clean = sanitize(r.comment);
    const g = grade(clean);
    return { level: g.level, terms: g.terms, clean, at: iso(r.reportedAt),
      reporter: r.reporterId ?? null, sha: r.comment ? sha256(String(r.comment)) : "" };
  }).sort((a, b) => b.level - a.level || String(b.at).localeCompare(String(a.at)));
  const top = graded.filter((g) => g.level === (graded[0]?.level ?? 0)).slice(0, 3);

  const vulnCats = uniq(jpVuln.flatMap(catOf).filter((c) => VULN_ANY.has(c))).sort((a, b) => a - b);
  const latest = (xs) => xs.map((r) => r.reportedAt).filter(Boolean).sort().pop() || "";
  const distinct = (xs) => uniq(xs.map((r) => r.reporterId).filter((x) => x != null)).length;
  const sc = detectScanner(d);

  return {
    ip_address: ip, selection_cohort: cohort, api_status: "ok", http_status: 200, error_message: "",
    checked_at_utc: checkedAt,
    abuse_confidence_score: d.abuseConfidenceScore ?? "", ip_country_code: d.countryCode || "",
    usage_type: d.usageType || "", isp: d.isp || "", domain: d.domain || "",
    hostnames: (d.hostnames || []).join(";"), is_tor: d.isTor === true, is_whitelisted: d.isWhitelisted === true,
    total_reports_90d: since == null ? (d.totalReports ?? 0) : reports.length,
    distinct_reporters_90d: since == null ? (d.numDistinctUsers ?? "") : distinct(reports),
    latest_reported_at_90d: iso(latest(reports)), reports_truncated: allReports.length >= 10000,
    returned_reports: reports.length,
    jp_report_count_90d: jp.length, jp_distinct_reporters_90d: distinct(jp),
    latest_jp_reported_at_90d: iso(latest(jp)),
    jp_vuln_report_count_90d: jpVuln.length, jp_vuln_distinct_reporters_90d: distinct(jpVuln),
    latest_jp_vuln_reported_at_90d: iso(latest(jpVuln)),
    jp_strict_vuln_report_count_90d: jpStrict.length, jp_strict_vuln_distinct_reporters_90d: distinct(jpStrict),
    jp_broad_vuln_report_count_90d: jpBroad.length,
    jp_auth_attack_report_count_90d: jpAuth.length,
    jp_scan_only_report_count_90d: jpScanOnly.length,
    jp_exploited_host_report_count_90d: jpExploited.length,
    /**
     * **日本の報告のカテゴリを全部数える。**`jp_vuln_category_ids` は脆弱性カテゴリ
     * しか残さないので、DDoS(4)・フィッシング(7)・詐称(17)・詐欺(3,8)・スパム(10-12)・
     * 不正ボット(19) が畳んだ時点で消えていた。「日本からの攻撃報告」を脆弱性より
     * 広く数えたいときに、写しを引き直さないと答えられなくなる。
     *
     * `カテゴリ番号:件数` を `;` でつなぐ。番号順なので並べて比較できる。
     * この項目が無い行は**まだ数えていない**という意味で、「該当なし」ではない。
     */
    jp_all_categories: (() => {
      const m = new Map();
      for (const r of jp) for (const c of catOf(r)) m.set(c, (m.get(c) || 0) + 1);
      return [...m].sort((a, b) => a[0] - b[0]).map(([c, n]) => `${c}:${n}`).join(";");
    })(),
    /** カテゴリがひとつも付いていない日本の報告。本文だけの通報がここに入る */
    jp_uncategorized_report_count_90d: jp.filter((r) => !catOf(r).length).length,
    jp_all_categories_measured: true,
    jp_vuln_category_ids: vulnCats.join(";"),
    jp_vuln_category_names: vulnCats.map((c) => CATEGORIES[c] || `unknown(${c})`).join(";"),
    jp_vuln_report_ratio: jp.length ? Number((jpVuln.length / jp.length).toFixed(4)) : 0,
    jp_vuln_days: uniq(jpVuln.map((r) => iso(r.reportedAt).slice(0, 10)).filter(Boolean)).length,
    evidence_level_max: graded.length ? graded[0].level : "",
    evidence_terms: uniq(graded.flatMap((g) => g.terms)).join(";"),
    evidence_example_1: top[0] ? forDisplay(top[0].clean) : "",
    evidence_example_2: top[1] ? forDisplay(top[1].clean) : "",
    evidence_example_3: top[2] ? forDisplay(top[2].clean) : "",
    evidence_comment_sha256: top.map((g) => g.sha).filter(Boolean).join(";"),
    evidence_latest_at: graded.find((g) => g.at)?.at || "",
    evidence_reporter_count: uniq(graded.map((g) => g.reporter).filter((x) => x != null)).length,
    evidence_reporter_concentration: (() => {
      const c = {}; for (const g of graded) if (g.reporter != null) c[g.reporter] = (c[g.reporter] || 0) + 1;
      const vals = Object.values(c); return vals.length ? Math.max(...vals) / graded.length : 0;
    })(),
    research_scanner_flag: sc.flag, research_scanner_name: sc.name,
    research_scanner_confidence: sc.confidence, research_scanner_evidence: sc.evidence,
  };
}
/* ================= 優先度と点数 ================= ===================================
 * **build.mjs から移した。** `now` は窓の終わりの時刻（ミリ秒）。
 * 「7 日以内 / 30 日以内」はここから数える。写しから組むときは写しの取得時刻を渡す。
 */
export const tsOf = (s) => (s ? new Date(s).getTime() : 0);

export function score(r, now) {
  const d7 = now - 7 * 86400000;
  const d30 = now - 30 * 86400000;
  const why = [], add = (p, t) => { why.push(`${p > 0 ? "+" : ""}${p} ${t}`); return p; };
  let s = 0;
  const lv = Number(r.evidence_level_max || 0);
  if (tsOf(r.latest_jp_vuln_reported_at_90d) >= d7) s += add(20, "日本の脆弱性報告が7日以内");
  else if (tsOf(r.latest_jp_vuln_reported_at_90d) >= d30) s += add(12, "30日以内");
  if (r.jp_strict_vuln_distinct_reporters_90d >= 2) s += add(20, "strictの日本レポーター2人以上");
  if (r.jp_strict_vuln_distinct_reporters_90d >= 5) s += add(10, "同5人以上");
  if (lv === 3) s += add(25, "E3 具体的な攻撃証拠");
  else if (lv === 2) s += add(15, "E2 製品・脆弱性固有の探索");
  const cats = String(r.jp_vuln_category_ids || "").split(";").filter(Boolean).map(Number);
  if (cats.includes(16) || cats.includes(23)) s += add(8, "SQLi または IoT Targeted");
  if (cats.includes(21)) s += add(5, "Web App Attack");
  if (r.jp_vuln_days >= 2) s += add(5, "複数日に分散");
  if (r.jp_exploited_host_report_count_90d > 0) s += add(3, "Exploited Host");
  if (r.research_scanner_flag && r.research_scanner_confidence === "high") s += add(-50, "研究スキャナ（高確度）");
  if (lv === 0) s += add(-15, "E0 のみ");
  if (cats.length === 1 && cats[0] === 15) s += add(-10, "Hacking(15) のみ");
  if (Number(r.evidence_reporter_concentration || 0) >= 0.9 && r.jp_vuln_report_count_90d >= 3) s += add(-10, "単一レポーターへ極端に集中");
  return { score: Math.max(0, Math.min(100, s)), reasons: why.join(" / ") };
}

export function classify(r, now) {
  const d30 = now - 30 * 86400000;
  if (r.api_status !== "ok") return { priority: "EXCLUDED_PRIMARY", reason: "APIエラー" };
  if (r.jp_vuln_report_count_90d === 0) {
    if (r.jp_report_count_90d === 0) return { priority: "EXCLUDED_PRIMARY", reason: "日本からの報告なし" };
    if (r.jp_auth_attack_report_count_90d > 0 || r.jp_scan_only_report_count_90d > 0)
      return { priority: "EXCLUDED_PRIMARY", reason: "日本報告が走査・総当たりのみで脆弱性カテゴリなし" };
    return { priority: "EXCLUDED_PRIMARY", reason: "日本報告に脆弱性カテゴリなし" };
  }
  if (r.research_scanner_flag && r.research_scanner_confidence === "high")
    return { priority: "EXCLUDED_PRIMARY", reason: `既知研究スキャナ（${r.research_scanner_name}）` };

  const lv = Number(r.evidence_level_max || 0);
  const recent30 = tsOf(r.latest_jp_vuln_reported_at_90d) >= d30;
  const strict2 = r.jp_strict_vuln_distinct_reporters_90d >= 2;
  const e3multi = lv === 3 && r.jp_vuln_report_count_90d >= 2;
  const e3multiReporter = lv === 3 && r.evidence_reporter_count >= 2;
  if ((recent30 && strict2 && lv >= 2) || e3multi || e3multiReporter) return { priority: "P1", reason: "" };
  if (strict2 || (r.jp_strict_vuln_report_count_90d > 0 && lv >= 2)
    || (r.jp_broad_vuln_report_count_90d > 0 && lv >= 2)) return { priority: "P2", reason: "" };
  return { priority: "P3", reason: "" };
}
