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

