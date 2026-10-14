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
const S = JSON.parse(fs.readFileSync(path.join(HERE, "artex_38_11_summary.json"), "utf8"));
const bt = String.fromCharCode(96);
const code = (s) => bt + s + bt;
const safe = (s, n = 40) => String(s || "").replace(/\|/g, "／").replace(/\s+/g, " ").slice(0, n);
const T = (head, body) => [
  "| " + head.join(" | ") + " |",
  "| " + head.map(() => "---").join(" | ") + " |",
  ...body.map((r) => "| " + r.join(" | ") + " |"),
].join("\n");

const L = [];
L.push("# ARTEX_38_11 — 指定 250 IP のレピュテーション調査", "");
L.push("> **この文書は Claude（AI）が自動生成したものです。人の確認を前提としてください。**", "");
L.push("対象は " + S.ranges.map(code).join(" と ") + " の "
  + code("." + S.host_range[0] + "〜." + S.host_range[1]) + "（" + S.coverage.targets + " IP）。");
L.push("**ペンテスト用ツール ARTEX が動いている**との情報を前提に、レピュテーションを調べたものです。", "");
L.push("**対象 IP への接続・走査・認証試行は一切行っていません。** ポートスキャンもせず、HTTP も叩かず、");
L.push("ping も打っていません。AbuseIPDB と VirusTotal、公開レジストリの情報だけを見ています。", "");

/* ---- 結論を先に ---- */
L.push("## 0. 結論", "");
L.push(T(["問い", "答え"], [
  ["**日本向けの攻撃観測はあるか**", "**AbuseIPDB 上には 1 件も無い**（" + S.coverage.targets + " IP 全件）"],
  ["AbuseIPDB の通報は", "**0 件**。スコアも全件 0"],
  ["VirusTotal の検知は", S.virustotal.ips_with_detection + " IP にあるが、**最大 "
    + S.virustotal.max_malicious + " エンジン**。feed の癖の域"],
  ["ARTEX の痕跡は", "**証明書には無い**（" + S.certificates.count + " 件調べて 0 件）"],
  ["素性は", "Cogent の " + code("38.0.0.0/8") + " を **AS54600 PEG TECH INC** が借りた帯。下位割当の登録なし"],
  ["唯一の構造的な手がかり", "**15 IP が規則的な格子に乗って 2026-10-01 前後に VT へ現れた**（§4）"],
]), "");
L.push("### 「通報 0」は無害の証明ではありません", "");
L.push("これが意味するのは「**誰も通報していない**」ことだけです。次のどれもありえます。", "");
L.push("- ペンテスト用ツールの正当な利用で、通報される行為をしていない");
L.push("- 通報される前の段階にある（**立てたばかりの攻撃基盤は、まさにこの見た目になります**）");
L.push("- 攻撃先が AbuseIPDB に通報する習慣を持たない");
L.push("- 観測されているが通報されていない");
L.push("");

/* ---- 計測器 ---- */
L.push("## 1. 計測器が働いていたことの確認", "");
L.push("負の結果でいちばん危ないのは、**計測器の故障を「汚れが無い」と読むこと**です。");
L.push("同じコード経路・同じ窓（" + S.fetch_window_days + " 日）で既知の汚い IP を引く対照実験をしました。", "");
L.push("```");
L.push("193.32.204.199   HTTP 200 | スコア 100 | 通報 5297 | レポーター 971 | reports 配列 5297");
L.push("38.11.173.54     HTTP 200 | スコア   0 | 通報    0 | レポーター   0 | reports 配列    0");
L.push("```");
L.push("**0 件は本物です。**", "");
L.push(T(["項目", "件数"], [
  ["対象", String(S.coverage.targets)],
  ["AbuseIPDB を引けた", String(S.coverage.abuseipdb_checked)],
  ["引けなかった", String(S.coverage.abuseipdb_missing)],
  ["VirusTotal を引けた", String(S.coverage.virustotal_checked)],
  ["VirusTotal が知らなかった", String(S.coverage.virustotal_unknown_404)],
]), "");
L.push("取得は " + S.collected_at_utc + "。日本の観測は "
  + code("reporterCountryCode === \"JP\"") + " で数えています。", "");

/* ---- 日本 ---- */
L.push("## 2. 日本向けの観測（主眼）", "");
L.push(T(["項目", "件数"], [
  ["日本のレポーターからの通報がある IP（" + S.fetch_window_days + " 日）", "**" + S.japan.ips_with_any_jp_report_365d + "**"],
  ["同（" + S.report_window.days + " 日）", String(S.japan.ips_with_jp_report_90d)],
  ["うち脆弱性カテゴリ", String(S.japan.ips_with_jp_vuln_report_90d)],
  ["日本からの通報の総数", String(S.japan.total_jp_reports_365d)],
]), "");
L.push("**日本からの通報は 1 件もありません。** ただしこれは「日本を狙っていない」ではなく、");
L.push("「**日本の観測者がまだ通報していない**」という意味です。そもそも世界中の誰からも");
L.push("通報が無いので、日本に限った話ではありません。", "");
L.push("なお " + code("reporterCountryCode") + " が言えるのは「通報した人が日本に居る」ことだけで、");
L.push("攻撃先が日本であることは意味しません。日本に観測者が多いだけでも同じ数字になります。", "");

/* ---- AbuseIPDB の素性 ---- */
L.push("## 3. 素性", "");
L.push(T(["観点", "値"], [
  ["AbuseIPDB の whois", Object.keys(S.infrastructure.isp).map(safe).join(" / ")],
  ["usageType", Object.keys(S.infrastructure.usage_type).map(safe).join(" / ")],
  ["国", Object.keys(S.infrastructure.country).join(" / ")],
  ["VT の AS", Object.keys(S.infrastructure.vt_as).map(safe).join(" / ")],
  ["VT の network", Object.keys(S.infrastructure.vt_network).join(" / ")],
  ["rDNS を持つ IP", String(S.infrastructure.with_rdns) + " / " + S.coverage.targets],
  ["Tor 出口", String(S.abuseipdb.tor)],
  ["AbuseIPDB の除外一覧", String(S.abuseipdb.whitelisted)],
  ["研究スキャナと名乗るもの", String(S.abuseipdb.research_scanner)],
  ["脅威情報の索引に既出", String(S.threat_index.already_present)],
]), "");
L.push("**AbuseIPDB は Cogent と答え、BGP と VT は AS54600 PEG TECH INC と答えます。**");
L.push("これは食い違いではなく、Cogent の " + code("38.0.0.0/8") + " から PEG TECH へ貸し出された帯で、");
L.push("ARIN RDAP に**下位割当（SWIP）の登録が無い**ためです（登録は 1991 年の Cogent のまま）。");
L.push("VPS 再販業者によくある形で、短命な基盤にもよくある形です。", "");
L.push("**rDNS は " + S.coverage.targets + " 件すべて空**です。素性を出していない帯です。", "");
L.push("### 名前の衝突に注意", "");
L.push("経路表には **AS45548 \"Artex Securities Joint Stock Company\"**（ベトナムの証券会社）が");
L.push("ありますが、**ARTEX ツールとは無関係**です。名前が同じだけなので結びつけないでください。", "");

/* ---- 格子 ---- */
const F = S.vt_freshness;
L.push("## 4. 唯一の構造的な手がかり — 規則的な格子", "");
L.push("VirusTotal が **" + F.threshold_month + " 以降に初めて項目を作った IP が " + F.ips + " 件**あり、");
L.push("そのホスト番号が完全に規則的でした。", "");
L.push("```");
L.push("ホスト番号: " + F.host_numbers.join(", "));
L.push("          = {30,31,32} ∪ {62,63,64} ∪ {94,95,96}  — 起点 30 / 間隔 32 / 長さ 3");
L.push("```");
L.push(T(["初見の日", "件数"], Object.entries(F.by_date).sort().map(([k, v]) => [k, String(v)])), "");
L.push("**125 個のホスト番号から 15 個を選んで、特定の 9 個組に全部入る確率は無視できる大きさ**です。");
L.push("偶然ではなく、機械が割り当てた形です。しかも **2 つの /24 で同じ番号の並び**が出ています。", "");
L.push("この " + F.ips + " 件は **証明書を 1 つも持たず**（" + F.with_certificate + " 件）、");
L.push("検知があるのは " + F.with_detection + " 件だけです。つまり**過去の用途の痕跡が無い、新しく動き出した一群**です。", "");
L.push("### ただし原因は決められません", "");
L.push("**" + code("first_seen_date") + " は「VT がその IP の項目を初めて作った日」であって、");
L.push("その IP が動き出した日とは限りません。** 次のどちらでも同じ日付になります。", "");
L.push("- その日あたりに基盤が配備され、誰かが観測して VT に現れた");
L.push("- **別の調査者が同じ日にこの一群をまとめて照会した**（ARTEX を追っている人が居れば自然です）");
L.push("");
L.push("どちらであっても言えるのは、「**この 15 個の住所が、規則的な形で他と区別されている**」");
L.push("ことです。" + code("38.11.221.94〜96") + " だけは 2023-12-10 に既出なので、");
L.push("格子の 3 組目はこの /24 では新しくありません。", "");
if (F.same_host_numbers_but_old.length) {
  L.push("格子上のホスト番号なのに初見が古いもの: " + F.same_host_numbers_but_old.map(code).join(" "), "");
}

/* ---- VT 検知 ---- */
L.push("## 5. VirusTotal の検知は証拠として弱い", "");
L.push(S.virustotal.ips_with_detection + " IP に検知が付いていますが、**最大でも "
  + S.virustotal.max_malicious + " エンジン**です（評価は約 90 エンジン）。内訳:", "");
L.push(T(["エンジン [判定]", "件数"], Object.entries(S.vt_detection_engines)
  .map(([k, v]) => [safe(k, 54), String(v)])), "");
L.push("**Gridinsoft・CRDF・SOCRadar・alphaMountain.ai に集中**しています。");
L.push("この 4 つは帯単位で広く印を付ける feed で、1〜2 エンジンだけの判定は");
L.push("**その IP についての証拠ではなく、feed の癖**と読むべきものです。", "");
L.push("証明書を持つかどうかと検知の有無に関係はありませんでした");
L.push("（検知あり 58 件のうち証明書あり 26% / 検知なし 192 件のうち 17%）。");
L.push("検知があるホスト番号も散らばっており、固まりを作りません。", "");

/* ---- 証明書 ---- */
L.push("## 6. 証明書 — ARTEX の痕跡は無く、過去は中国語圏の商用ホスティング", "");
L.push(T(["項目", "件数"], [
  ["証明書を持つ IP", String(S.certificates.count)],
  ["**取得時点で失効していたもの**", "**" + S.certificates.expired_before_collection + "**"],
  ["異なる CN の数", String(S.certificates.distinct_cn)],
  ["**証明書に ARTEX を含むもの**", "**" + S.virustotal.ips_with_artex_in_certificate + "**"],
]), "");
L.push("**" + S.certificates.count + " 件すべてが取得時点で失効済み**です。VT の "
  + code("last_https_certificate") + " は");
L.push("「最後に見た証明書」なので、これは**今動いているものではなく過去の用途の痕跡**です。", "");
L.push(T(["CN", "IP 数"], Object.entries(S.certificates.by_cn).map(([k, v]) => [code(safe(k, 30)), String(v)])), "");
L.push("発行者の内訳:", "");
L.push(T(["発行者", "件数"], Object.entries(S.infrastructure.cert_issuers)
  .filter(([k]) => k).map(([k, v]) => [safe(k, 46), String(v)])), "");
L.push("**すべて中国語圏の一般商用サイト**で、Let's Encrypt と TrustAsia です。");
L.push("PEG TECH は中国語圏向けの VPS 再販業者なので、過去の用途として自然な姿です。", "");
L.push("### 前回の ARTEX 調査との違い", "");
if (S.threat_index.prior_artex_certificates.length) {
  const p = S.threat_index.prior_artex_certificates[0];
  L.push("索引には前回の調査で見つけた ARTEX の痕跡が 1 件残っています。", "");
  L.push("```");
  L.push("発行者   " + p.issuer);
  L.push("subject  " + p.subject);
  L.push("拇印     " + p.thumbprint);
  L.push("```");
  L.push("これも Cogent 空間（" + code("38.0.0.0/8") + "）でしたが、**今回の 250 件には");
  L.push("同じ形の証明書がひとつもありません。** 前回 ARTEX を特定できた手がかりは、");
  L.push("この帯では使えませんでした。", "");
}

/* ---- 残り ---- */
L.push("## 7. /24 ごと", "");
L.push(T(["/24", "IP", "通報あり", "日本からの通報", "検知あり", "証明書あり"],
  Object.entries(S.by_range).map(([k, v]) => [code(k), String(v.ips), String(v.with_report),
    String(v.with_jp_report), String(v.with_detection), String(v.with_certificate)])), "");
L.push("**2 つの /24 はほぼ同じ姿**です。通報 0、日本からの通報 0、検知が 31 対 27、証明書が 21 対 25。", "");

L.push("## 8. この調査で言えないこと", "");
L.push("- **ARTEX が動いているかどうかは確認できていません。** 能動調査をしていないので、");
L.push("  待ち受けているサービスも証明書の現況も見ていません。渡された前提のままです");
L.push("- **通報・検知が無いことは無害の証明ではありません**（§0）");
L.push("- VT の " + code("first_seen_date") + " は配備日ではありません（§4）");
L.push("- AbuseIPDB のカテゴリはレポーターの自己申告です（今回は該当なし）");
L.push("- IP の所在地・ISP・AS は、運用者の国籍や所属を示しません");
L.push("- 母集団は**渡された 250 IP だけ**です。同じ AS の他の帯は見ていません");
L.push("");
L.push("## 9. 次に打てる手（提案）", "");
L.push("- **索引へ登録して継続観測する。** 今は索引に 0 件なので、通報や検知が付いても気付けません。");
L.push("  日次のエンリッチに載せれば、最初の通報が付いた日が分かります");
L.push("- **格子上の 15 IP だけを重点監視する。** 他と区別されている唯一の手がかりです");
L.push("- 証明書の記録（CT ログ）から、この帯に最近発行された証明書を探す。VT の");
L.push("  " + code("last_https_certificate") + " は古いものしか返しておらず、CT なら新しいものが見えます");
L.push("- 同じ AS54600 の他の帯を同じ手順で調べ、この 2 帯が特別かどうかを確かめる");
L.push("");
L.push("## 10. 残していないもの", "");
L.push("- API キーはコンソール・ログ・CSV・JSON・ソース・エラーにも出していません");
L.push("- " + code("reporterId") + " は distinct を数えるためだけに使い、値は保存していません");
L.push("- 写し（" + code(".cache/") + "）は git 管理外です");
L.push("- 対象 IP への接続・走査は行っていません");
L.push("");
fs.writeFileSync(path.join(HERE, "artex_38_11_report_ja.md"), L.join("\n"));
console.log("→ artex_38_11_report_ja.md");
