#!/usr/bin/env node
// 出来上がった CSV と summary.json から日本語レポートを組む。
// **写しだけを見る。API は呼ばない。** 何度走らせても同じものが出る。
//
//   node report.mjs
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
const S = JSON.parse(fs.readFileSync(path.join(HERE, "global_jp_vuln_summary.json"), "utf8"));
const all = read("global_jp_vuln_all_90d.csv");
const ex = read("global_jp_vuln_excluded.csv");
const n = (v) => (v === "" ? 0 : Number(v));
const tbl = (pairs, head) => [`| ${head.join(" | ")} |`, `| ${head.map(() => "---").join(" | ")} |`,
  ...pairs.map((r) => `| ${r.join(" | ")} |`)].join("\n");
/** 表に入れる外部由来の文字列。縦棒と改行だけ落とす */
const safe = (s) => String(s || "").replace(/\|/g, "／").replace(/\s+/g, " ").slice(0, 70);

const top50 = all.filter((r) => r.priority === "P1" || r.priority === "P2").slice(0, 50);
const evOrder = ["E3", "E2", "E1", "E0"];
const repDist = Object.entries(S.jp_vuln_reporter_distribution || {})
  .sort((a, b) => (a[0] === "5+" ? 1 : b[0] === "5+" ? -1 : Number(a[0]) - Number(b[0])));

const md = `# GLOBAL_JP_VULN — 日本のレポーターが脆弱性攻撃として報告した送信元IP（過去90日）

> **この文書は Claude（AI）が自動生成したものです。人の確認を前提としてください。**

送信元の所在地は限定していません。「**日本の人が、脆弱性攻撃として報告した**」ことだけを
抽出の条件にしています。対象 IP への接続・走査は一切行っていません。

## 1. 取得条件

${tbl([
  ["データセット", S.dataset],
  ["作成日時", S.generated_at_utc],
  ["調査期間", `${S.window.start_utc} 〜 ${S.window.end_utc}（ローリング ${S.window.days} 日）`],
  ["Blacklist 条件", `\`confidenceMinimum=${S.blacklist.confidenceMinimum}\` \`limit=${S.blacklist.limit}\` \`ipVersion=${S.blacklist.ipVersion}\`（国フィルタなし）`],
  ["Blacklist 生成日時", S.blacklist.generated_at],
  ["Check 条件", `\`maxAgeInDays=${S.config.REPORT_WINDOW_DAYS}\` \`verbose\``],
  ["乱数シード", String(S.config.RANDOM_SEED)],
], ["項目", "値"])}

## 2. 件数

${tbl([
  ["Blacklist 取得", String(S.blacklist.entries)],
  ["うち候補（30日以内・信頼度75以上）", String(S.blacklist.eligible_30d)],
  ["Check 対象に選定", String(S.checks.selected)],
  ["Check 成功", String(S.checks.succeeded)],
  ["Check 失敗", String(S.checks.failed)],
  ["キャッシュ再利用", String(Math.max(0, S.checks.cache_reused))],
  ["**日本の脆弱性報告あり（採用候補）**", `**${S.population.eligible_jp_vuln}**`],
  ["**GLOBAL_JP_VULN 採用**", `**${S.population.included}**`],
], ["項目", "件数"])}

### 優先度

${tbl([
  ["**P1** 最優先", "複数の日本レポーター＋E2/E3、または具体的証拠が複数", `**${S.population.P1}**`],
  ["**P2** 優先", "日本の strict 報告が複数、または単独＋E2 以上", `**${S.population.P2}**`],
  ["P3 参考", "日本レポーター1人・根拠が弱い", String(S.population.P3)],
  ["除外", "研究スキャナ・走査のみ・脆弱性カテゴリなし", String(S.population.excluded)],
], ["優先度", "意味", "件数"])}

## 3. 日本報告のカテゴリ別件数

**IP 全体ではなく、日本の報告だけから数えています。**

${tbl(Object.entries(S.jp_vuln_categories).sort((a, b) => b[1] - a[1]).map(([k, v]) => [k, String(v)]),
  ["カテゴリ", "IP 数"])}

## 4. 証拠の段階

コメントから決定論的に判定したものです。語の一致だけで決めており、意味は読んでいません。

${tbl(evOrder.filter((k) => S.evidence_levels[k]).map((k) => [k, ({
  E3: "CVE番号・SQLiペイロード・RCE要求・Webシェル等の具体的な攻撃証跡",
  E2: "製品・脆弱性に固有の探索（phpunit、HNAP1、boaform、製品名つきパス等）",
  E1: "一般的な攻撃的探索（.env、.git/config、wp-login.php、管理画面等）",
  E0: "根拠不足（カテゴリのみ、コメントなし、通常のクローラと区別できない）",
}[k]), String(S.evidence_levels[k])]), ["段階", "内容", "IP 数"])}

## 5. 日本の脆弱性レポーター数の分布

${tbl(repDist.map(([k, v]) => [`${k} 人`, String(v)]), ["レポーター数", "IP 数"])}

## 6. 送信元の分布（採用分）

### 国

${tbl(S.top_countries.slice(0, 12).map(([k, v]) => [k, String(v)]), ["国", "IP 数"])}

**所在地は攻撃者の国籍や所属を意味しません。** クラウド、VPN、NAT、侵害されたホスト、
IP の再割り当てをいずれも含みます。

### ISP

${tbl(S.top_isp.slice(0, 12).map(([k, v]) => [safe(k), String(v)]), ["ISP", "IP 数"])}

### usageType

${tbl(S.top_usage_type.map(([k, v]) => [safe(k), String(v)]), ["種別", "IP 数"])}

## 7. 研究スキャナ

**削除していません。** 印を付けて、高確度のものだけ主対象から外しています。

${tbl([
  ["判定した総数", String(S.research_scanners.flagged)],
  ["高確度として主対象から除外", String(S.research_scanners.high_confidence_excluded)],
], ["項目", "件数"])}

${Object.keys(S.research_scanners.by_name || {}).length ? tbl(
  Object.entries(S.research_scanners.by_name).sort((a, b) => b[1] - a[1]).map(([k, v]) => [safe(k), String(v)]),
  ["名称", "件数"]) : "（判定なし）"}

判定は hostname・domain・ISP の**名乗り**で行っています。クラウドの AS に属するというだけでは
判定していません。

## 8. Exploited Host

**${S.exploited_host_ips} 件**の採用 IP に、日本からのカテゴリ20（Exploited Host）報告が付いています。
これは攻撃の技法ではなく、**送信元自体が侵害されている可能性**を示す補助情報です。
踏み台にされた正規ホストである場合、送信元の所有者も被害者です。

## 9. 除外の内訳

${tbl(Object.entries(S.exclusion_reasons || {}).sort((a, b) => b[1] - a[1]).map(([k, v]) => [safe(k) || "（理由なし）", String(v)]),
  ["理由", "件数"])}

## 10. 後続調査を推奨する上位 ${top50.length} 件

優先度と優先スコアの順です。**スコアは AbuseIPDB の信頼度そのままではなく**、
日本の観測者数・証拠の具体性・新しさから別に計算したものです。

${tbl(top50.map((r, i) => [
  String(i + 1), r.ip_address, r.priority, r.priority_score, r.ip_country_code,
  `E${r.evidence_level_max || 0}`, r.jp_vuln_distinct_reporters_90d,
  (r.latest_jp_vuln_reported_at_90d || "").slice(0, 10),
  safe(r.jp_vuln_category_names), safe(r.isp).slice(0, 28),
]), ["#", "IP", "優先", "点", "国", "証拠", "日本レポーター", "最新", "カテゴリ", "ISP"])}

## 11. 抽出上の偏りと制約

### 母集団の偏り

- **Blacklist が上限で打ち切られています。** \`limit=${S.blacklist.limit}\` に対して
  ${S.blacklist.entries} 件が返っており、これは Basic の上限そのものです。信頼度の高い順に
  切られているため、**信頼度 75〜84 の帯は 1 件も含まれていません**。層化サンプルも
  85〜94 と 95〜100 の 2 帯からしか引けていません。
- **候補 ${S.blacklist.eligible_30d} 件に対し、確認できたのは ${S.checks.selected} 件**（1 日の API 上限）です。
  \`lastReportedAt\` の新しい順を主軸にしているので、**古い報告しかない IP は見ていません**。
- したがって「P1 が ${S.population.P1} 件」は**この母集団での件数**であり、世界全体の件数ではありません。

### 判定の限界

- **AbuseIPDB のカテゴリはレポーターの自己申告**です。誤分類を含みます。
- **証拠段階は語の一致だけ**で決めています。文意は読んでいないので、無害な文脈で
  CVE 番号に触れただけのコメントが E3 になることがあります。逆に、言い回しが
  一覧に無ければ具体的な攻撃でも E0 になります。
- **カテゴリ15（Hacking）は範囲が広い**ため、単独では優先度を上げていません。
- reports 配列は最大 10,000 件です。超えた IP では確認数が下限値になります
  （\`reports_truncated=true\`）。

### 解釈の注意

- **レポーターが日本に所在することは、日本企業や日本所在システムへの攻撃を意味しません。**
  日本に観測者や監視機器が多いというだけでも同じ結果になります。
- **IP の所在地・ISP・ASN は、攻撃者の国籍や所属を示しません。**
- **コメント中の CVE 名や攻撃名だけで帰属を断定しないでください。**
- 本調査は AbuseIPDB の公開情報のみを使用しています。能動調査は行っていません。
`;
fs.writeFileSync(path.join(HERE, "global_jp_vuln_report_ja.md"), md);
console.log(`→ global_jp_vuln_report_ja.md（上位 ${top50.length} 件を掲載）`);
