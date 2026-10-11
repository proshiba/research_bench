#!/usr/bin/env node
// 関連 IP の結果からレポートを組む。**写しだけを見る。API は呼ばない。**
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
const all = parseCsv(fs.readFileSync(path.join(HERE, "related_ips_all.csv"), "utf8"));
const S = JSON.parse(fs.readFileSync(path.join(HERE, "related_summary.json"), "utf8"));
const bt = String.fromCharCode(96);
const code = (s) => bt + s + bt;
const fence = bt + bt + bt;
const safe = (s) => String(s || "").replace(/\|/g, "／").replace(/\s+/g, " ").slice(0, 40);
const T = (head, rows) => [
  "| " + head.join(" | ") + " |",
  "| " + head.map(() => "---").join(" | ") + " |",
  ...rows.map((r) => "| " + r.join(" | ") + " |"),
].join("\n");

const by = {};
for (const r of all) {
  const v = (by[r.net] = by[r.net] || { s: 0, m: 0, w: 0, n: 0, seeds: r.net_seeds, den: Number(r.net_density) });
  if (r.relation_verdict === "関連・強") v.s++;
  else if (r.relation_verdict === "関連・中") v.m++;
  else if (r.relation_verdict === "関連・弱") v.w++;
  else v.n++;
}
const nets = Object.entries(by).sort((a, b) => b[1].s - a[1].s);
const strong = all.filter((r) => r.relation_verdict === "関連・強");

const L = [];
L.push("# GLOBAL_JP_VULN 関連IP — 昨日の一覧からの差分", "");
L.push("> **この文書は Claude（AI）が自動生成したものです。人の確認を前提としてください。**", "");
L.push("昨日の GLOBAL_JP_VULN の **P1+P2（" + S.seed.count + " 件）を種**として、そこから関連する IP を出したものです。");
L.push("**掲載の " + all.length + " 件はすべて昨日の一覧に無い IP** です。対象への接続・走査は行っていません。", "");
L.push("## 結果", "");
L.push(T(["関連の強さ", "意味", "件数"], [
  ["**関連・強**", "種と同じ濃い帯に居り、**自身も日本から脆弱性攻撃として報告**されている", "**" + S.verdicts["関連・強"] + "**"],
  ["関連・中", "自身も日本から脆弱性攻撃として報告されているが根拠は弱い", String(S.verdicts["関連・中"])],
  ["関連・弱", "日本からの報告はあるが脆弱性カテゴリではない", String(S.verdicts["関連・弱"])],
  ["同居のみ", "種と同じ帯に居るが、日本からの報告は確認できない", String(S.verdicts["同居のみ"])],
  ["除外", "研究スキャナ", String(S.verdicts["除外（研究スキャナ）"])],
]), "");
L.push("API は " + code("/check") + " " + S.checked.api_calls + " 回（うち " + S.checked.today + " 件が新規取得、"
  + S.checked.from_yesterday_cache + " 件は昨日の写しを再利用）。残量 " + S.checked.quota_remaining + "。", "");

L.push("## 何を「関連」と呼び、何を捨てたか", "");
L.push("### 採った: 種が濃く集まっている /24", "");
L.push("密度（種 ÷ その /24 にある Blacklist の総数）で見ます。**同じ /24 に居るというだけでは関連と言えません。**");
L.push(code("69.5.169.0/24") + " は Blacklist 253 件中 7 件が種（2.8%）で、これは単に大きな汚れた帯です。");
L.push("種 " + S.method.dense_24.min_seeds + " 件以上かつ密度 " + (S.method.dense_24.min_density * 100) + "% 以上の **"
  + S.method.dense_24.networks + " 網**に絞りました。", "");
L.push("### 捨てた: コメント本文の一致", "");
L.push("2 IP 以上に同じ本文が付く組が 151 通りあり、そこから **829 件**の「関連 IP」が出ました。");
L.push("**しかし中身は通報者の検知器が吐く定型文でした。**", "");
L.push(fence);
L.push("165 IP  Shield: Layer4 Port 9 Trap");
L.push("174 IP  port=80, indicator_type=info-leak");
L.push("171 IP  Knock-Knock honeypot brute-force: HTTP (1 total hits)");
L.push(" 62 IP  by Attack Lagwatch(gw)");
L.push(fence, "");
L.push("これが結ぶのは**攻撃者ではなく観測者**です。829 件すべて偽の関連だったので不採用にしました。", "");
L.push("### 補助: 証拠の語の組み合わせ一致", "");
L.push("語 2 つ以上が一致する組だけを見て **" + S.method.evidence_signature.added + " 件**を追加。"
  + code("dotenv") + " や " + code("offensive-wording") + " のような一般的な語は誰にでも付くので、単独では根拠にしていません。", "");

L.push("## /24 ごとの内訳", "");
L.push(T(["/24", "種", "密度", "強", "中", "弱", "同居のみ"], nets.map(([k, v]) =>
  [code(k), String(v.seeds), (v.den * 100).toFixed(0) + "%", String(v.s), String(v.m), String(v.w), String(v.n)])), "");
L.push("**密度が高いことと、関連が強いことは別です。** " + code("172.236.228.0/24") + " は密度 82% ですが、");
L.push("その帯の Blacklist 17 件のうち 14 件が既に種だったため、新しく出たのは 3 件だけでした。");
L.push("逆に " + code("45.156.128.0/24") + " は密度 19% ながら、新規 42 件が「強」でした。", "");

L.push("## 関連・強 の上位 " + Math.min(25, strong.length) + " 件", "");
L.push(T(["#", "IP", "国", "/24", "日本の脆弱性報告", "レポーター", "証拠", "ISP"],
  strong.slice(0, 25).map((r, i) => [String(i + 1), code(r.ip), r.ip_country_code, code(r.net),
    r.jp_vuln_report_count_90d, r.jp_vuln_distinct_reporters_90d, "E" + r.evidence_level_max, safe(r.isp)])), "");

const ispCount = {};
for (const r of all) if (r.relation_verdict.startsWith("関連")) ispCount[r.isp || "?"] = (ispCount[r.isp || "?"] || 0) + 1;
L.push("## ISP 上位（関連・強／中／弱）", "");
L.push(T(["ISP", "件数"], Object.entries(ispCount).sort((a, b) => b[1] - a[1]).slice(0, 12)
  .map(([k, v]) => [safe(k), String(v)])), "");

L.push("## 注意", "");
L.push("- **種と同じ帯に居ることは、同じ攻撃者であることを示しません。** 同じ事業者から借りた別人である可能性が常に残ります。帯の密度は「ひとつの持ち主の可能性が高い」という程度の根拠です");
L.push("- **「関連・強」でも証拠段階は E0 が多数あります。** 日本から脆弱性攻撃として報告されている事実はありますが、コメントに具体的な攻撃証跡が無いものが含まれます");
L.push("- レポーターが日本に所在することは、日本向け攻撃を意味しません");
L.push("- IP の所在地・ISP は攻撃者の国籍や所属を示しません");
L.push("- 母集団は昨日の Blacklist スナップショット（" + S.generated_at_utc.slice(0, 10) + " 時点）です。その後に現れた IP は含みません");
L.push("");
fs.writeFileSync(path.join(HERE, "related_report_ja.md"), L.join("\n"));
console.log("→ related_report_ja.md（関連・強 " + strong.length + " 件 / 全 " + all.length + " 件）");
