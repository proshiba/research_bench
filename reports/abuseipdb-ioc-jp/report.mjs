#!/usr/bin/env node
// 出来上がった CSV と summary.json から日本語レポートを組む。
// **写しだけを見る。API は呼ばない。** 何度走らせても同じものが出る。
//
//   node report.mjs
//
// マークダウン中にバッククォートが多いので、テンプレートリテラルは使わず行の配列で組む。
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
function parseCsv(text) {
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
  const rows = []; let row = [], field = "", q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) { if (c === '"') { if (text[i + 1] === '"') { field += '"'; i++; } else q = false; } else field += c; }
    else if (c === '"') q = true;
    else if (c === ",") { row.push(field); field = ""; }
    else if (c === "\n") { row.push(field); field = ""; rows.push(row); row = []; }
    else if (c === "\r") { /* CRLF */ }
    else field += c;
  }
  if (field.length || row.length) { row.push(field); rows.push(row); }
  const h = rows.shift();
  return rows.filter((r) => r.length > 1).map((r) => Object.fromEntries(h.map((k, i) => [k, r[i] ?? ""])));
}
const read = (f) => parseCsv(fs.readFileSync(path.join(HERE, f), "utf8"));
const S = JSON.parse(fs.readFileSync(path.join(HERE, "abuseipdb_ioc_jp_summary.json"), "utf8"));
const all = read("abuseipdb_ioc_jp_all_90d.csv");

const bt = String.fromCharCode(96);
const code = (s) => bt + s + bt;
/** 表に入れる外部由来の文字列。縦棒と改行だけ落とす */
const safe = (s, n = 40) => String(s || "").replace(/\|/g, "／").replace(/\s+/g, " ").slice(0, n);
const T = (head, body) => [
  "| " + head.join(" | ") + " |",
  "| " + head.map(() => "---").join(" | ") + " |",
  ...body.map((r) => "| " + r.join(" | ") + " |"),
].join("\n");
const evOrder = ["E3", "E2", "E1", "E0"];

const L = [];
L.push("# ABUSEIPDB_IOC_JP — 索引が持つ送信元 IP のうち日本のレポーターが報告したもの（過去90日）", "");
L.push("> **この文書は Claude（AI）が自動生成したものです。人の確認を前提としてください。**", "");
L.push("母集団は **脅威情報の索引が既に持っている IP** です。AbuseIPDB の Blacklist 全体ではありません。");
L.push("抽出の条件は「**日本の人が、脆弱性攻撃として報告した**」ことだけです。");
L.push("対象 IP への接続・走査は一切行っていません。**この調査では API も呼んでいません**（既にある写しから組んでいます）。", "");

/* ---- 先に汚れを出す ---- */
const torPct = S.population.included ? Math.round((S.marks.tor / S.population.included) * 100) : 0;
L.push("## 0. 先に読んでほしいこと — 採用 " + S.population.included + " 件のうち "
  + S.marks.tor + " 件（" + torPct + "%）が Tor 出口です", "");
L.push("**Tor 出口は誰でも通れます。** そこに付いたアクター名は**その出口を借りた誰かの話**であって、");
L.push("出口の持ち主の話ではありません。帰属の根拠には使えません。", "");
const tor = all.filter((r) => r.is_tor === "true");
if (tor.length) {
  L.push(T(["IP", "日本の脆弱性報告", "レポーター", "証拠", "索引のアクター", "ISP"],
    tor.map((r) => [code(r.ip_address), r.jp_vuln_report_count_90d, r.jp_vuln_distinct_reporters_90d,
      "E" + (r.evidence_level_max || 0), safe(r.ioc_actors) || "—", safe(r.isp)])), "");
}
L.push("この割合の高さは母集団の性質です。索引は脅威情報の記事から IOC を集めており、");
L.push("**記事が Tor 出口を攻撃元として挙げることが多い**ため、ここに溜まります。", "");

/* ---- 窓の話 ---- */
L.push("## 1. 取得条件", "");
L.push(T([" 項目", "値"], [
  ["データセット", S.dataset],
  ["母集団", "索引が持つ IP の AbuseIPDB 写し " + S.population.copies_read + " 件"],
  ["窓", S.window.start_utc + " 〜 " + S.window.end_utc + "（" + S.window.days + " 日）"],
  ["窓の基準時刻", S.collected_at_utc + "（**写しの取得時刻のうち最新**。`new Date()` は使わない）"],
  ["API 呼び出し", "**0 回**"],
]), "");
L.push("### 窓を 90 日に切り直しています", "");
L.push("索引側の写しは **365 日**ぶんで取っています。GLOBAL_JP_VULN と並べるために、");
L.push("**写しの報告 1 件ずつの日時で 90 日に絞り直し**ました。その結果:", "");
L.push("- 365 日窓で日本からの報告があるのは **139 件**（`data/ioc/reports/jp-reporters.md`）");
L.push("- 90 日窓では **" + S.population.jp_reported + " 件**");
L.push("");
L.push("**差の " + (139 - S.population.jp_reported) + " 件は消えたのではなく、報告が 90 日より古いだけ**です。");
L.push("どちらが正しいということはなく、窓が違います。", "");
L.push("なお " + code("abuse_confidence_score") + " だけは AbuseIPDB 自身が出す値で窓を切れないため、");
L.push("**365 日ぶんのまま**です。この列だけ他の " + code("_90d") + " 列と意味が違います。", "");

/* ---- 件数 ---- */
L.push("## 2. 件数", "");
L.push(T(["項目", "件数"], [
  ["写しを読んだ", String(S.population.copies_read)],
  ["日本からの報告あり（90日窓）", String(S.population.jp_reported)],
  ["**うち脆弱性カテゴリあり＝採用**", "**" + S.population.included + "**"],
  ["除外", String(S.population.excluded)],
]), "");
L.push("### 優先度", "");
L.push(T(["優先度", "意味", "件数"], [
  ["**P1** 最優先", "複数の日本レポーター＋E2/E3、または具体的証拠が複数", "**" + S.population.P1 + "**"],
  ["**P2** 優先", "日本の strict 報告が複数、または単独＋E2 以上", "**" + S.population.P2 + "**"],
  ["P3 参考", "日本レポーター1人・根拠が弱い", String(S.population.P3)],
]), "");
L.push("### 除外の内訳", "");
L.push(T(["理由", "件数"], Object.entries(S.exclusion_reasons)
  .sort((a, b) => b[1] - a[1]).map(([k, v]) => [safe(k, 60), String(v)])), "");
L.push("**削除していません。** " + code("abuseipdb_ioc_jp_excluded.csv") + " に全件残しています。", "");

/* ---- 証拠 ---- */
L.push("## 3. 証拠の段階", "");
L.push("コメントから決定論的に判定したものです。**語の一致だけで決めており、意味は読んでいません。**", "");
L.push(T(["段階", "内容", "IP 数"], evOrder.filter((k) => S.evidence_levels[k]).map((k) => [k, ({
  E3: "CVE番号・SQLiペイロード・RCE要求・Webシェル等の具体的な攻撃証跡",
  E2: "製品・脆弱性に固有の探索（phpunit、HNAP1、boaform、製品名つきパス等）",
  E1: "一般的な攻撃的探索（.env、.git/config、wp-login.php、管理画面等）",
  E0: "根拠不足（カテゴリのみ、コメントなし、通常のクローラと区別できない）",
}[k]), String(S.evidence_levels[k])])), "");
L.push("## 4. 日本報告のカテゴリ", "");
L.push("**IP 全体ではなく、日本の報告だけから数えています。** カテゴリはレポーターの自己申告です。", "");
L.push(T(["カテゴリ", "IP 数"], Object.entries(S.jp_vuln_categories)
  .sort((a, b) => b[1] - a[1]).map(([k, v]) => [k, String(v)])), "");
L.push("## 5. 日本の脆弱性レポーター数", "");
L.push("**1 人しか見ていない IP は、その 1 人の環境固有の事情かもしれません。**", "");
L.push(T(["レポーター数", "IP 数"], Object.entries(S.jp_vuln_reporter_distribution)
  .sort((a, b) => (a[0] === "5+" ? 1 : b[0] === "5+" ? -1 : Number(a[0]) - Number(b[0])))
  .map(([k, v]) => [k + " 人", String(v)])), "");

/* ---- このデータセットの存在理由 ---- */
L.push("## 6. 索引の文脈が付いた IP", "");
L.push("**これが GLOBAL_JP_VULN に無いものです。** 脅威情報の記事が名前を付けている IP に、");
L.push("日本の現場からも脆弱性攻撃として報告が付いている、という重なりです。", "");
L.push(T(["付いているもの", "件数"], [
  ["アクター名", String(S.ioc_context.actor_named)],
  ["述べられた役割", String(S.ioc_context.with_role)],
  ["マルウェア名", String(S.ioc_context.with_malware)],
  ["共有証明書", String(S.ioc_context.with_shared_certificate)],
]), "");
const withActor = all.filter((r) => r.ioc_actors);
if (withActor.length) {
  L.push(T(["IP", "アクター", "マルウェア", "日本の脆弱性報告", "レポーター", "証拠", "印", "国", "ISP"],
    withActor.map((r) => [
      code(r.ip_address), safe(r.ioc_actors, 24), safe(r.ioc_malware, 20) || "—",
      r.jp_vuln_report_count_90d, r.jp_vuln_distinct_reporters_90d, "E" + (r.evidence_level_max || 0),
      r.is_tor === "true" ? "**Tor出口**" : "—", r.ip_country_code, safe(r.isp, 28),
    ])), "");
  L.push("**アクター名が付いていることは、その IP がそのアクターの持ち物であることを示しません。**");
  L.push("記事が挙げた IP であり、Tor 出口・VPN・踏み台・事業者の相乗りがいずれも含まれます。", "");
}

/* ---- 上位 ---- */
const top = all.filter((r) => r.priority === "P1" || r.priority === "P2");
if (top.length) {
  L.push("## 7. 後続調査を推奨する " + top.length + " 件（P1・P2）", "");
  L.push("**スコアは AbuseIPDB の信頼度そのままではなく**、日本の観測者数・証拠の具体性・");
  L.push("新しさから別に計算したものです。", "");
  L.push(T(["#", "IP", "優先", "点", "国", "証拠", "日本レポーター", "最新", "印", "カテゴリ", "ISP"],
    top.map((r, i) => [String(i + 1), code(r.ip_address), r.priority, r.priority_score, r.ip_country_code,
      "E" + (r.evidence_level_max || 0), r.jp_vuln_distinct_reporters_90d,
      (r.latest_jp_vuln_reported_at_90d || "").slice(0, 10),
      r.is_tor === "true" ? "**Tor**" : "—", safe(r.jp_vuln_category_names, 36), safe(r.isp, 26)])), "");
}

/* ---- 分布 ---- */
L.push("## 8. 送信元の分布（採用分）", "");
L.push(T(["国", "IP 数"], S.top_countries.map(([k, v]) => [k, String(v)])), "");
L.push("**所在地は攻撃者の国籍や所属を意味しません。** クラウド、VPN、Tor、NAT、");
L.push("侵害されたホスト、IP の再割り当てをいずれも含みます。", "");
L.push(T(["ISP", "IP 数"], S.top_isp.map(([k, v]) => [safe(k), String(v)])), "");

/* ---- 制約 ---- */
L.push("## 9. 抽出上の偏りと制約", "");
L.push("### 母集団の偏り", "");
L.push("- **索引が持っている IP だけ**です。索引は脅威情報の記事から集めているので、");
L.push("  記事に出てこない攻撃元は入っていません。「世界の攻撃元の上位」ではありません");
L.push("- その結果 **Tor 出口が " + torPct + "% を占めます**（記事が Tor 出口を挙げやすいため）");
L.push("- 索引の IP 4,801 件のうち、**通報が 1 件以上あるのは 816 件**です。残りは AbuseIPDB に");
L.push("  通報が無いので、日本のレポーターも居ません");
L.push("");
L.push("### 判定の限界", "");
L.push("- **AbuseIPDB のカテゴリはレポーターの自己申告**です。誤分類を含みます");
L.push("- **証拠段階は語の一致だけ**で決めています。文意は読んでいないので、無害な文脈で");
L.push("  CVE 番号に触れただけのコメントが E3 になることがあります。逆に、言い回しが");
L.push("  一覧に無ければ具体的な攻撃でも E0 になります");
L.push("- **カテゴリ15（Hacking）は範囲が広い**ため、単独では優先度を上げていません");
L.push("- reports 配列は最大 10,000 件です。超えた IP では確認数が下限値になります"
  + "（" + code("reports_truncated=true") + " が " + S.marks.reports_truncated + " 件）");
L.push("");
L.push("### 解釈の注意", "");
L.push("- **レポーターが日本に所在することは、日本企業や日本所在システムへの攻撃を意味しません。**");
L.push("  日本に観測者や監視機器が多いというだけでも同じ結果になります");
L.push("- **IP の所在地・ISP・ASN は、攻撃者の国籍や所属を示しません**");
L.push("- **コメント中の CVE 名や攻撃名だけで帰属を断定しないでください**");
L.push("- 本調査は AbuseIPDB と索引の公開情報のみを使用しています。能動調査は行っていません");
L.push("");
L.push("### 残していないもの", "");
L.push("- " + code("reporterId") + " は distinct を数えるためだけに使い、**値は保存していません**");
L.push("- コメント原文は保存せず、無害化して短く切ったものと SHA-256 だけ残しています");
L.push("");
L.push("## 10. GLOBAL_JP_VULN との対応", "");
L.push("CSV の **前 59 列は GLOBAL_JP_VULN と同一・同順**です。並べて比較できます。");
L.push("索引の文脈（" + code("ioc_actors") + " など 10 列）は**後ろに足して**あります。", "");
L.push(T(["", "GLOBAL_JP_VULN", "ABUSEIPDB_IOC_JP"], [
  ["母集団", "Blacklist 10 万件", "索引の IP " + S.population.copies_read + " 件"],
  ["採用", "2,763", String(S.population.included)],
  ["P1 / P2 / P3", "177 / 435 / 2,151", S.population.P1 + " / " + S.population.P2 + " / " + S.population.P3],
  ["索引の文脈", "無い", "**アクター名 " + S.ioc_context.actor_named + " 件**"],
  ["API 呼び出し", "この場で呼ぶ", "**0 回**"],
]), "");
L.push("判定規則は " + code("../global-jp-vuln/rules.mjs") + " を共有しています。**判定を 2 箇所に持ちません。**");
L.push("");
fs.writeFileSync(path.join(HERE, "abuseipdb_ioc_jp_report_ja.md"), L.join("\n"));
console.log("→ abuseipdb_ioc_jp_report_ja.md（採用 " + S.population.included
  + " 件 / P1・P2 " + top.length + " 件を掲載）");
