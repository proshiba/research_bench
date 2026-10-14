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
const S = JSON.parse(fs.readFileSync(path.join(HERE, "jp_attack_sources_summary.json"), "utf8"));
const attacks = read("jp_attack_sources_all.csv");
const missed = read("jp_attack_sources_missed_by_vuln_cut.csv");

const bt = String.fromCharCode(96);
const code = (s) => bt + s + bt;
const safe = (s, n = 36) => String(s || "").replace(/\|/g, "／").replace(/\s+/g, " ").slice(0, n);
const T = (head, body) => [
  "| " + head.join(" | ") + " |",
  "| " + head.map(() => "---").join(" | ") + " |",
  ...body.map((r) => "| " + r.join(" | ") + " |"),
].join("\n");
const pct = (a, b) => (b ? Math.round((a / b) * 100) + "%" : "—");

const L = [];
L.push("# JP_ATTACK_SOURCES — 日本のレポーターが攻撃として報告した送信元 IP", "");
L.push("> **この文書は Claude（AI）が自動生成したものです。人の確認を前提としてください。**", "");
L.push("AbuseIPDB をもとに、**日本の人が攻撃として報告した送信元 IP** を集めたものです。");
L.push("送信元の所在地は限定していません。対象 IP への接続・走査は一切行っていません。", "");
L.push("**この集計自体は API を呼びません。** 既にある写しから組んでいます。", "");

/* ---- 標準の窓を先に ---- */
const P = S.primary_window;
const TH = S.thresholds_30d;
L.push("## 0. 標準の窓は **" + P.days + " 日**です", "");
L.push("以前の版は **90 日窓**で数えていました。これは緩すぎました。");
L.push("索引側の生の写しでの実測では、日本からの報告がある IP は");
L.push("**365 日 139 件 → 90 日 55 件 → 30 日 31 件 → 7 日 8 件** と落ちます。");
L.push(code("176.65.139.31") + " は 90 日で 46 件ありますが **30 日では 0 件**で、");
L.push("90 日で数えると「もう止まっている送信元」が現役として並びます。", "");
L.push("窓の開始: " + P.since_utc, "");
L.push("### 過去 " + P.days + " 日以内の日本からの攻撃報告", "");
L.push("**分母は " + TH.denominator + " 件**（報告 1 件ずつの日時から正確に数えられた行だけ）。", "");
L.push(T(["条件", "IP 数", "観測者で見た場合"],
  [1, 2, 3, 5, 10].map((n) => [
    "**" + n + " 件以上**", "**" + TH["attack_reports_ge_" + n] + "**",
    n + " 人以上: " + TH["reporters_ge_" + n]])), "");
L.push("全件は " + code("jp_attack_sources_30d_confirmed.csv") + " です。", "");
L.push("### 言い切れる行と、言い切れない行を分けています", "");
L.push("畳み方を直したのが取得より後だったため、写しに世代が混ざっています。");
L.push("**引き直していない IP を「該当なし」に数えてはいけない**ので、列 "
  + code("jp_30d_method") + " で区別しました。", "");
L.push(T(["区分", "件数", "何が言えるか"], [
  ["**" + P.days + "日で確定**（" + code("counted") + "）", "**" + P.confirmed + "**",
    "**「" + P.days + "日以内に攻撃報告が N 件」を正確に言える**"],
  ["引き直し待ち（" + code("latest_only") + "）", String(P.pending_refetch),
    "「" + P.days + "日以内に日本から報告が 1 件以上」までは言える。"
    + "**その報告が攻撃カテゴリだったかは分からない**"],
  ["窓の外", String(P.no_jp_report_in_window),
    "90 日には攻撃報告があるが、" + P.days + "日以内に日本からの報告が無い"],
]), "");
L.push("なぜ引き直しが要るのか: " + code("jp_report_count_30d") + " は畳み方を直したあとに");
L.push("足した項目で、**生の報告配列を残していない**ため手元の写しからは計算できません。");
L.push("1 回の " + code("/check") + " で 90 日ぶんが返り、報告 1 件ずつに " + code("reportedAt"));
L.push("が付いているので、**同じ 1 回から 7 日・30 日・90 日の数が全部出ます**（API 呼び出しは増えません）。", "");
L.push("埋め方: " + code("node refetch.mjs --limit N") + "（人の確認に値する順に上から埋まります）", "");

/* ---- いちばん大事な前置き ---- */
L.push("## 0b. 「日本からの報告がある」だけでは絞り込みになりません", "");
L.push("写しのある **" + S.coverage.api_ok + " IP のうち " + S.population.with_jp_report_all_copies
  + " 件（" + pct(S.population.with_jp_report_all_copies, S.coverage.api_ok) + "）に日本からの報告があります**"
  + "（90 日窓）。", "");
L.push("**これは窓のせいだけではありません。** 母集団そのものが絞られています。", "");
L.push("```");
L.push("eligible = Blacklist の上位 10 万件のうち  信頼度 >= 75  かつ");
L.push("           lastReportedAt が 30 日以内（= 誰かが現に通報している）");
L.push("```");
L.push("つまり**構造上ほぼ全部が現役の騒がしい送信元**で、そういう先は日本のセンサーにも引っかかります。");
L.push("30 日に絞っても " + pct(7021, S.coverage.api_ok) + " 程度しか減りません。", "");
L.push("母集団が AbuseIPDB の Blacklist（世界で最も多く通報されている上位）なので、");
L.push("**通報者が何百人も付いている IP には、まず日本の人も混ざります。**");
L.push("つまり「日本から報告されている」は、この母集団ではほぼ全部に当てはまり、");
L.push("**絞り込みの条件として機能しません。** 意味が出るのは次の 2 つを足したときです。", "");
L.push("1. **何として報告されたか**（攻撃か、走査だけか、VPN を使っているだけか）");
L.push("2. **日本の観測者が何人居るか**（1 人ならその環境固有の事情かもしれない）");
L.push("");

/* ---- 段の定義 ---- */
L.push("## 1. 「攻撃」をどこで切ったか", "");
L.push("AbuseIPDB の 23 カテゴリは「攻撃」から「属性」まで混ざっています。");
L.push("**VPN を使っていることは攻撃ではありません。** オープンプロキシも、走査しただけも、攻撃ではありません。");
L.push("まとめて「通報あり」と数えると、VPN を使っているだけの IP が攻撃元の一覧に入ります。", "");
L.push("そこで段に分け、**既定では A1〜A4 だけを攻撃として数えました**。");
L.push("どの段も数えて出しているので、読む側で外して数え直せます（切り方は " + code("tiers.mjs") + " の一箇所）。", "");
L.push(T(["段", "意味", "カテゴリ", "攻撃に数えるか"],
  Object.entries(S.tier_definition).map(([k, t]) => [
    "**" + k + "**", t.label, t.categories.map((c) => safe(c, 24)).join("、"),
    t.counted_as_attack ? "**はい**" : "いいえ"])), "");

/* ---- 結果 ---- */
L.push("## 2. 結果", "");
L.push(T(["項目", "件数"], [
  ["写しのある IP（API 成功）", String(S.coverage.api_ok)],
  ["うち**段まで判定できた**", "**" + S.population.tier_judgeable + "**"],
  ["うち日本からの報告あり", String(S.population.with_jp_report)],
  ["うち攻撃段（A1〜A4）に当たった", String(S.population.attack_tier_matched)],
  ["（除外）高確度の研究スキャナ", "−" + S.population.excluded_research_scanners],
  ["**主対象**", "**" + S.population.jp_attack_sources + "**"],
  ["攻撃ではない（偵察のみ・スパム・属性）", String(S.population.jp_reported_not_attack)],
]), "");
L.push("### 研究スキャナを主対象から外しました（削除はしていません）", "");
L.push("攻撃段に当たった " + S.population.attack_tier_matched + " 件のうち **"
  + S.population.excluded_research_scanners + " 件（"
  + pct(S.population.excluded_research_scanners, S.population.attack_tier_matched)
  + "）がインターネット全域を計測している正規のプロジェクト**でした。");
L.push("日本のセンサーがこれを「攻撃」として通報するのは自然ですが、攻撃元の一覧に混ぜると母集団が汚れます。", "");
L.push(T(["名乗り", "件数"], Object.entries(S.excluded_scanner_names)
  .sort((a, b) => b[1] - a[1]).map(([k, v]) => [safe(k, 36), String(v)])), "");
L.push("全件は " + code("jp_attack_sources_excluded_scanners.csv") + " に残しています。");
L.push("判定は hostname・domain・ISP の**名乗り**で行っており、クラウドの AS に属するというだけでは判定していません。", "");
L.push("### 最も重い段ごと", "");
L.push("**件数の多さではなく段の重さで決めています。** A1 があれば A1、無ければ A2、という規則です。");
L.push("「DDoS 1000 件」より「侵入 1 件」を上に出したいためです。", "");
L.push(T(["最も重い段", "IP 数"], Object.entries(S.by_worst_tier)
  .sort((a, b) => (a[0] < b[0] ? -1 : 1)).map(([k, v]) => [k, String(v)])), "");

/* ---- 存在理由 ---- */
L.push("## 3. 脆弱性だけに絞ると落ちていたもの", "");
L.push("既存の GLOBAL_JP_VULN は**脆弱性カテゴリ（SQLi・Web アプリ攻撃・IoT 狙い・Hacking）だけ**を");
L.push("採っていました。そのため **DDoS・フィッシング・詐称・詐欺・認証突破**で日本から報告されている");
L.push("IP が落ちていました。", "");
L.push("**今回の切り方で新たに入ったのは " + S.population.missed_by_global_jp_vuln + " 件**です。", "");
if (missed.length) {
  const top = missed.slice(0, 20);
  L.push(T(["IP", "段", "日本の報告", "観測者", "最新", "カテゴリ", "国", "ISP"],
    top.map((r) => [code(r.ip_address), r.worst_tier, r.jp_report_count_90d,
      r.jp_distinct_reporters_90d, (r.latest_jp_reported_at_90d || "").slice(0, 10),
      safe(r.jp_category_names, 30), r.ip_country_code, safe(r.isp, 24)])), "");
  L.push("（上位 " + top.length + " 件。全件は " + code("jp_attack_sources_missed_by_vuln_cut.csv") + "）", "");
}

/* ---- 観測者数 ---- */
L.push("## 4. 日本の観測者の数 — **多いほど重要、ではありません**", "");
const C = S.jp_reporter_ceiling;
L.push("観測者数は **" + C.max_jp_reporters + " 人で天井**になり、分布はそこへ滑らかに向かいます。", "");
L.push("```");
L.push("上位の値と件数: " + C.top_values.join("  "));
L.push("```");
L.push("つまりこの数が測っているのは「どれだけ狙われたか」ではなく、");
L.push("**「日本にある AbuseIPDB のセンサーのうち何台が見たか」**です。", "");
L.push("**" + C.max_jp_reporters + " 人ということは「日本のほぼ全センサーが見た」**で、それは");
L.push("**インターネット全域を騒がしく走査している先**を意味します。標的型の逆です。");
L.push("実際、観測者数の上位は証拠段階が全件 E0（具体的な攻撃証跡なし）でした。", "");
L.push("そこで並び順は**証拠の具体性を観測者数より先に見ています**。");
L.push("E3/E2 が付いているものはコメントに攻撃の中身が書かれており、そちらが人の確認に値します。", "");
L.push("1 人しか見ていない IP は逆に、その 1 人の環境固有の事情かもしれません。");
L.push("**つまり観測者数は、多すぎても少なすぎても絞り込みに使えません。**", "");
L.push(T(["日本の観測者", "IP 数"], Object.entries(S.jp_reporter_distribution)
  .sort((a, b) => (a[0] === "5+" ? 1 : b[0] === "5+" ? -1 : Number(a[0]) - Number(b[0])))
  .map(([k, v]) => [k + " 人", String(v)])), "");
L.push("### 代わりに使える絞り込み — 証拠段階", "");
L.push(T(["段階", "意味", "IP 数"], ["E3", "E2", "E1", "E0"].filter((k) => S.evidence_levels[k])
  .map((k) => [k, {
    E3: "**CVE番号・SQLiペイロード・RCE要求・Webシェル等の具体的な攻撃証跡**",
    E2: "製品・脆弱性に固有の探索",
    E1: "一般的な攻撃的探索",
    E0: "根拠不足（カテゴリのみ、コメントなし）",
  }[k], String(S.evidence_levels[k])])), "");
L.push("**証拠段階は日本の脆弱性報告のコメントからだけ取っています。**");
L.push("DDoS や認証突破しかない IP では空欄になるので、E0 が多いことは");
L.push("「証拠が無い」よりも「この切り口では評価していない」に近い場合があります。", "");

/* ---- カテゴリ ---- */
L.push("## 5. 日本の報告のカテゴリ（攻撃と数えた分）", "");
L.push("**IP 全体ではなく、日本の報告だけから数えています。** カテゴリはレポーターの自己申告です。", "");
L.push(T(["カテゴリ", "IP 数"], Object.entries(S.jp_categories)
  .sort((a, b) => b[1] - a[1]).map(([k, v]) => [safe(k, 30), String(v)])), "");

/* ---- 上位 ---- */
const strong = attacks.filter((r) => r.evidence_level_max !== "" && Number(r.evidence_level_max) >= 2
  && Number(r.jp_distinct_reporters_90d) >= 2).slice(0, 40);
if (strong.length) {
  L.push("## 6. 人の確認に値する上位 " + strong.length + " 件", "");
  L.push("**証拠段階 E2 以上かつ日本の観測者 2 人以上**に絞ったものです。");
  L.push("観測者数の多い順ではありません（§4 の理由）。", "");
  L.push(T(["#", "IP", "段", "日本の報告", "観測者", "証拠", "最新", "印", "国", "ISP"],
    strong.map((r, i) => [String(i + 1), code(r.ip_address), r.worst_tier,
      r.jp_report_count_90d, r.jp_distinct_reporters_90d,
      r.evidence_level_max === "" ? "—" : "E" + r.evidence_level_max,
      (r.latest_jp_reported_at_90d || "").slice(0, 10),
      [r.is_tor === "true" ? "**Tor**" : "", r.research_scanner_flag === "true" ? "走査器" : "",
        r.is_whitelisted === "true" ? "除外一覧" : ""].filter(Boolean).join(" ") || "—",
      r.ip_country_code, safe(r.isp, 24)])), "");
}

/* ---- 印 ---- */
L.push("## 7. 印（消さずに付けてあります）", "");
L.push(T(["印", "意味", "件数"], [
  ["Tor 出口", "**誰でも通れる。**付いたアクター名はその出口を借りた誰かの話", String(S.marks.tor)],
  ["AbuseIPDB の除外一覧", "AbuseIPDB 側が除外している", String(S.marks.whitelisted)],
  ["研究スキャナと名乗る", "名乗りで判定。クラウドに居るだけでは判定しない", String(S.marks.research_scanner)],
  ["同（高確度）", "主対象から外すべきもの", String(S.marks.research_scanner_high)],
  ["報告配列が上限で切れた", "確認数が下限値になっている", String(S.marks.reports_truncated)],
  ["踏み台の報告あり", "**送信元自体が侵害されている可能性。**持ち主も被害者かもしれない", String(S.marks.exploited_host)],
]), "");

/* ---- 分布 ---- */
L.push("## 8. 送信元の分布（攻撃と数えた分）", "");
L.push(T(["国", "IP 数"], S.top_countries.map(([k, v]) => [k, String(v)])), "");
L.push("**所在地は攻撃者の国籍や所属を意味しません。** クラウド、VPN、Tor、NAT、");
L.push("侵害されたホスト、IP の再割り当てをいずれも含みます。", "");
L.push(T(["ISP", "IP 数"], S.top_isp.map(([k, v]) => [safe(k), String(v)])), "");
L.push(T(["種別", "IP 数"], S.top_usage_type.map(([k, v]) => [safe(k), String(v)])), "");

/* ---- 索引 ---- */
L.push("## 9. 脅威情報の索引との重なり", "");
L.push(T(["項目", "件数"], [
  ["索引に既出", String(S.threat_index.already_present)],
  ["索引がアクター名を付けている", String(S.threat_index.with_actor)],
]), "");
if (S.threat_index.top_actors.length) {
  L.push(T(["アクター", "IP 数"], S.threat_index.top_actors.map(([k, v]) => [safe(k, 28), String(v)])), "");
}

/* ---- 制約 ---- */
L.push("## 10. 偏りと制約", "");
L.push("### 母集団の偏り", "");
L.push("- **Blacklist が上限で打ち切られています。**"
  + (S.blacklist_snapshot ? " スナップショットは " + S.blacklist_snapshot.generated_at
    + " 生成の " + S.blacklist_snapshot.entries + " 件" : ""));
L.push("- **候補のうち確認できたのは " + S.coverage.checks_in_cache + " 件**です。"
  + (S.coverage.unchecked_candidates !== null
    ? "未確認が約 " + S.coverage.unchecked_candidates + " 件残っています。" : ""));
L.push("- **既定の選び方は " + code("lastReportedAt") + " の新しい順**なので、");
L.push("  **古い報告しか持たない IP は一度も見ていません。** 母集団を広げる日は");
L.push("  " + code("../global-jp-vuln/build.mjs --new-only") + " を使います");
L.push("- したがって件数はすべて**この母集団での数**であり、世界全体の数ではありません");
L.push("");
L.push("### 分からないものを負に数えていません", "");
L.push("- カテゴリの内訳をまだ数えていない IP が **" + S.coverage.jp_categories_unmeasured + " 件**あります");
L.push("  （うち日本からの報告があるもの " + S.coverage.unmeasured_with_jp_report + " 件）。");
L.push("  これは「攻撃ではない」ではなく**分からない**という意味で、第 2 節の分母から外しています");
L.push("- 古い写しは脆弱性カテゴリしか残しておらず、DDoS・フィッシング等が見えません。");
L.push("  引き直した写しだけが段の判定に使えます");
L.push("");
L.push("### 判定の限界", "");
L.push("- **AbuseIPDB のカテゴリはレポーターの自己申告**です。誤分類を含みます");
L.push("- **段の切り方は決め打ち**です（" + code("tiers.mjs") + "）。異論がある境目は");
L.push("  カテゴリ 15（Hacking、範囲が広い）、20（踏み台、被害の印）、14（走査のみ）です");
L.push("- **1 つの報告に複数のカテゴリが付きます。**"
  + "段ごとの数は「カテゴリの付与回数」で、報告件数ではありません");
L.push("- 証拠段階（E0〜E3）は**日本の脆弱性報告のコメントからだけ**取っています。");
L.push("  DDoS や認証突破しかない IP では空欄になります");
L.push("");
L.push("### 解釈の注意", "");
L.push("- **レポーターが日本に所在することは、日本企業や日本所在システムへの攻撃を意味しません。**");
L.push("  日本に観測者や監視機器が多いというだけでも同じ結果になります");
L.push("- **IP の所在地・ISP・ASN は、攻撃者の国籍や所属を示しません**");
L.push("- 本調査は AbuseIPDB の公開情報のみを使用しています。能動調査は行っていません");
L.push("");
L.push("### 残していないもの", "");
L.push("- " + code("reporterId") + " は distinct を数えるためだけに使い、値は保存していません");
L.push("- コメント原文は保存せず、無害化して短く切ったものと SHA-256 だけ残しています");
L.push("");
fs.writeFileSync(path.join(HERE, "jp_attack_sources_report_ja.md"), L.join("\n"));
console.log("→ jp_attack_sources_report_ja.md（攻撃 " + attacks.length
  + " 件 / 新たに入った " + missed.length + " 件）");
