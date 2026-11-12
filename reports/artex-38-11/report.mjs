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
L.push("# " + S.cluster + " — " + S.coverage.targets + " IP のレピュテーション調査", "");
L.push("> **この文書は Claude（AI）が自動生成したものです。人の確認を前提としてください。**", "");
L.push("**1 つのクラスタです。** 対象は " + code(S.declared_in) + " の宣言（"
  + S.coverage.targets + " IP）。", "");
L.push(T(["役割", "対象"], S.groups.map((g) => [g.roles.map(code).join(" "),
  g.ranges ? g.ranges.map(code).join(" と ") + " の " + code(".1〜.125") : g.explicit.map(code).join(" ")])), "");
L.push("**ペンテスト用ツール ARTEX が動いている**（250 IP）、**sub2api があり同じリチャージ URL が");
L.push("セットされている**（全 255 IP）との利用者の観測を前提に、レピュテーションを調べたものです。", "");
L.push("**対象 IP への接続・走査・認証試行は一切行っていません。** ポートスキャンもせず、HTTP も叩かず、");
L.push("ping も打っていません。AbuseIPDB と VirusTotal、公開レジストリの情報だけを見ています。", "");

/* ---- 結論を先に ---- */
L.push("## 0. 結論", "");
const B = S.vs_baseline, CT = S.control;
L.push("**前回（" + B.baseline_date + "）から大きく変わりました。**", "");
L.push(T(["問い", "答え"], [
  ["**日本向けの攻撃観測はあるか**", "**AbuseIPDB 上には 1 件も無い**（" + S.coverage.targets + " IP 全件、前回と同じ）"],
  ["AbuseIPDB の通報は", "**" + S.abuseipdb.ips_with_any_report_365d + " IP に付いた**（前回 0 件）。"
    + "最大スコア " + S.abuseipdb.max_score + "。新しく通報が付いたのは " + B.newly_reported + " IP"],
  ["VirusTotal の検知は", "**" + S.virustotal.ips_with_detection + " IP**（前回 58 IP）。"
    + "悪性エンジンの最大 " + S.virustotal.max_malicious + "（前回 2）。新しく検知が付いたのは " + B.newly_detected + " IP"],
  ["それは帯ごと載せられただけか", "**違う。**宣言の外の近隣 " + CT.ips + " IP では検知 "
    + CT.control_with_detection + " 件・通報 " + CT.control_with_abuse_report + " 件（§5）"],
  ["ARTEX の痕跡は", "**証明書には無い**（" + S.certificates.count + " 件調べて 0 件）"],
  ["素性は", "Cogent の " + code("38.0.0.0/8") + " を **AS54600 PEG TECH INC** が借りた帯。下位割当の登録なし"],
]), "");
L.push("### 4 週間で「白」から「広く印が付いた」へ", "");
L.push("前回は通報 0・検知も最大 2 エンジンで、**立てたばかりの基盤の見た目**でした。");
L.push("今回は通報が " + S.abuseipdb.ips_with_any_report_365d + " IP、悪性エンジンの中央値が "
  + CT.cluster_malicious_median + " です。", "");
L.push("**ただし通報の中身は薄いままです。** 通報がある IP の大半が 1 件だけで、最大スコアも "
  + S.abuseipdb.max_score + " です。");
L.push("数が増えたのは「多くの観測者が見た」ではなく「**多くの IP に 1 件ずつ付いた**」形です。", "");
L.push("### 「通報 0」は無害の証明ではありません（前回の注意は今も有効）", "");
L.push("日本からの通報は今回も 0 件ですが、これが意味するのは「**日本の観測者がまだ通報していない**」");
L.push("ことだけです。次のどれもありえます。", "");
L.push("- ペンテスト用ツールの正当な利用で、通報される行為をしていない");
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
L.push("**（これは " + B.baseline_date + " の確認。当時の 0 件は本物でした。）**");
L.push("今回は通報が " + S.abuseipdb.ips_with_any_report_365d + " IP に付いているので、");
L.push("計測器が黙っているのではないことは結果そのものから分かります。", "");
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
L.push("「**日本の観測者がまだ通報していない**」という意味です。", "");
L.push("前回は世界中の誰からも通報が無かったので「日本に限った話ではない」と書きましたが、");
L.push("**今はそうではありません。** 世界では " + S.abuseipdb.ips_with_any_report_365d
  + " IP に通報が付いており、");
L.push("その中に日本の観測者が 1 人も居ない、という状態です。", "");
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
L.push("## 5. 検知は帯ごとの掲載ではなく、宣言した 255 IP に沿っている", "");
L.push("**ここが今回いちばん重要な確認です。**", "");
L.push(S.virustotal.ips_with_detection + " IP に検知が付いていますが、エンジンごとに見ると "
  + code("SOCRadar") + " は");
L.push("**255/255 すべてに付けています**。それだけ見れば「帯ごと載せただけ」に見えます。", "");
L.push("そこで**宣言の外にある近隣 " + CT.ips + " IP を同じ手順で引きました**（対照群）。", "");
L.push("### まず、同じ土俵に乗っているか", "");
L.push(T(["観点", "クラスタ", "対照群"], [
  ["VT にレコードがある", String(S.coverage.virustotal_checked) + " / " + S.coverage.targets,
    String(CT.comparable.with_vt_record) + " / " + CT.ips],
  ["評価したエンジン数（中央値）", String(CT.comparable.engines_evaluated_median_cluster),
    String(CT.comparable.engines_evaluated_median_control)],
  ["所有 AS", CT.comparable.as_owners_cluster.map(safe).join(" / "),
    CT.comparable.as_owners_control.map(safe).join(" / ")],
]), "");
L.push("**同じ AS・同じエンジン数で評価されています。**比較が成り立つ土俵です。", "");
L.push("### エンジンごとの当たり方", "");
L.push(T(["エンジン", "クラスタ（255）", "対照群（" + CT.ips + "）"],
  Object.entries(CT.by_engine).sort((a, b) => b[1].cluster - a[1].cluster).slice(0, 10)
    .map(([k, v]) => [safe(k, 30), v.cluster + " / 255（" + v.cluster_pct + "%）",
      v.control + " / " + CT.ips + (v.control_too_small_for_pct ? "" : "（" + v.control_pct + "%）")])), "");
L.push("**宣言の外では、ほぼ全部のエンジンが 0 件です。**");
L.push("悪性エンジン数の中央値はクラスタ " + CT.cluster_malicious_median + " に対して対照群 "
  + CT.control_malicious_median + "、");
L.push("AbuseIPDB の通報も対照群は " + CT.control_with_abuse_report + " / " + CT.ips + " 件です。", "");
L.push("対照群には**同じ /24 の " + code(".130") + " 〜 " + code(".250") + " が含まれます**。");
L.push("つまり境界は " + code(".125") + " にあり、**利用者が申告したクラスタの境界と一致しています**。", "");
L.push("### ここから言えること / 言えないこと", "");
L.push("- **言える**: 検知は「この界隈が丸ごと載っている」のではなく、"
  + "**宣言した 255 IP に沿って付いている**");
L.push("- **言える**: " + code("SOCRadar") + " の 255/255 も帯単位の掲載ではない"
  + "（帯単位なら対照群にも付くはずで、0 件だった）");
const IU = CT.in_use_signals;
L.push("- **言える**: 対照群は空き住所ではなさそうです。443 の証明書を持つ割合は"
  + "**対照群 " + IU.control_with_certificate_pct + "%（最後に見た日の中央値 "
  + IU.control_certificate_last_seen_median + "）**に対し、");
L.push("  クラスタは " + IU.cluster_with_certificate_pct + "%（中央値 "
  + IU.cluster_certificate_last_seen_median + "）。**対照群のほうが 443 では生きています**");
L.push("- **言えない**: それでも「使われていて綺麗」の証明にはなりません。"
  + "証明書は過去に見たものなので、**今動いているかは分かりません**。");
L.push("  能動調査をしていない以上、ここが限界です");
L.push("- **言えない**: エンジンが " + CT.cluster_malicious_median + " 個付いていても、"
  + "それが**独立した 4 つの観測とは限りません**。");
L.push("  1 つの掲載が複数ベンダへ伝わった可能性は残ります（名前は "
  + code("vt_flagged_by") + " 列に残してあります）");
L.push("");

/* ---- 証明書 ---- */
L.push("## 6. 証明書 — 443 の痕跡であって ARTEX のものではない", "");
L.push("**ARTEX は " + code("8787/tcp") + " です。** ここに出てくる証明書は VT の "
  + code("last_https_certificate") + " で、");
L.push("443 で最後に見たものです。**ARTEX を指紋採取したものではありません。**");
L.push("前回「証明書に ARTEX の痕跡が無い」と書きましたが、"
  + "**そもそも別のポートを見ているので、無くて当然でした**。", "");
L.push(T(["項目", "件数"], [
  ["証明書を持つ IP", String(S.certificates.count)],
  ["**取得時点で失効していたもの**", "**" + S.certificates.expired_before_collection + "**"],
  ["異なる CN の数", String(S.certificates.distinct_cn)],
  ["**証明書に ARTEX を含むもの**", "**" + S.virustotal.ips_with_artex_in_certificate + "**"],
]), "");
L.push("**" + S.certificates.count + " 件すべてが取得時点で失効済み**です。");
L.push("つまりこの帯の **443 は畳まれており、動いているのは 8787 の ARTEX** という、");
L.push("利用者の申告と整合する姿になっています。", "");
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
L.push("役割ごとに見ると:", "");
L.push(T(["役割", "IP", "通報あり", "割合", "検知あり", "最大スコア", "最大悪性"],
  Object.entries(S.per_role).map(([k, v]) => [code(k), String(v.ips), String(v.with_report),
    v.too_small_for_pct ? "**母数不足**" : v.reported_pct + "%", String(v.with_detection),
    String(v.max_score), String(v.max_malicious)])), "");
L.push("**母数が小さい役割の割合は読めません。** " + code("recharge_host") + " は 1 IP です。", "");

L.push("## 8. この調査で言えないこと", "");
L.push("- **ARTEX の稼働はこちらで確認したものではありません。** 利用者が 255 IP を個別に");
L.push("  確認した結果（" + code("8787/tcp") + "）を前提に置いています。こちらは能動調査をしていません");
L.push("- **レピュテーションは 8787 の中身を見ていません。** AbuseIPDB も VirusTotal も");
L.push("  振る舞いと掲載を見るもので、待ち受けサービスの指紋ではありません。");
L.push("  **「ARTEX が上がっていること」と「通報・検知が付いていること」は別の観測です**");
L.push("- **通報・検知が無いことは無害の証明ではありません**（§0）。");
L.push("  対照群が白いのも同じで、**空き住所なのか使われていて綺麗なのかは区別できません**");
L.push("- **エンジンの数は独立した観測の数ではありません**（§5）");
L.push("- VT の " + code("first_seen_date") + " は配備日ではありません（§4）");
L.push("- AbuseIPDB のカテゴリはレポーターの自己申告です（今回は該当なし）");
L.push("- IP の所在地・ISP・AS は、運用者の国籍や所属を示しません");
L.push("- 母集団は**渡された " + S.coverage.targets + " IP と対照群 " + CT.ips
  + " IP だけ**です。同じ AS の他の帯はほとんど見ていません");
L.push("");
L.push("## 9. 次に打てる手（提案）", "");
L.push("- **対照群を広げる。** 今回の " + CT.ips + " IP で境界は見えましたが、"
  + "「空き住所だから白い」可能性を潰すには、");
L.push("  **同じ AS で使われていることが分かっている帯**を対照に取る必要があります");
L.push("- **" + code("vt_flagged_by") + " を日ごとに記録する。** エンジンが増えた日が分かれば、"
  + "1 つの掲載が伝播したのか別々に付いたのかを分けられます");
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
