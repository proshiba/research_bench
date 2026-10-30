#!/usr/bin/env node
// 出来上がった CSV と summary.json から日本語レポートを組む。
// **写しだけを見る。API は呼ばない。** 何度走らせても同じものが出る。
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
  const h = rows.shift().map((x) => x.replace(/^﻿/, ""));
  return rows.filter((r) => r.length > 1).map((r) => Object.fromEntries(h.map((k, i) => [k, r[i] ?? ""])));
}
const read = (f) => parseCsv(fs.readFileSync(path.join(HERE, f), "utf8"));
const S = JSON.parse(fs.readFileSync(path.join(HERE, "artex_timeline_summary.json"), "utf8"));
const byIp = read("artex_timeline_by_ip.csv");
const events = read("artex_timeline_events.csv");

const bt = String.fromCharCode(96);
const code = (s) => bt + s + bt;
const safe = (s, n = 40) => String(s || "").replace(/\|/g, "／").replace(/\s+/g, " ").slice(0, n);
const T = (head, body) => [
  "| " + head.join(" | ") + " |",
  "| " + head.map(() => "---").join(" | ") + " |",
  ...body.map((r) => "| " + r.join(" | ") + " |"),
].join("\n");

const A = S.per_cluster.ARTEX, U = S.per_cluster.sub2api;
const L = [];
L.push("# ARTEX / sub2api クラスタ — AbuseIPDB 上の通報の時系列", "");
L.push("> **この文書は Claude（AI）が自動生成したものです。人の確認を前提としてください。**", "");
L.push("対象は 2 つのクラスタです。どちらも**利用者の観測**を前提にしています。", "");
L.push(T(["クラスタ", "対象", "利用者の観測"], S.clusters.map((c) => [
  "**" + c.name + "**",
  c.ranges ? c.ranges.map(code).join(" と ") + " の " + code(".1〜.125")
    : c.explicit.map(code).join(" "),
  safe(c.note, 70)])), "");
L.push("**対象 IP への接続・走査・認証試行は一切行っていません。** AbuseIPDB の公開情報と");
L.push("手元の経路表・索引だけを見ています。この集計自体は API も呼んでいません。", "");

/* ---- 結論 ---- */
L.push("## 0. 結論", "");
L.push(T(["問い", "答え"], [
  ["ARTEX クラスタは通報されるようになったか",
    "**はい。2026-10-14 は 0 / 250 件、今回は " + A.with_reports_now + " / " + A.ips + " 件**"],
  ["それは「複数の観測者が攻撃を見た」ことか",
    "**いいえ。" + A.with_reports_now + " 件すべてが単一の通報者**（" + A.distinct_reporters + " 人）"],
  ["何として通報されたか", "**Exploited Host（カテゴリ 20）だけ**。攻撃手法ではなく「この送信元自体が侵害されている可能性」"],
  ["sub2api クラスタは", "**5 IP のうち " + U.with_reports_now + " 件だけ**（" + code("198.200.59.85") + "）。通報 3 件 / 通報者 " + U.distinct_reporters + " 人"],
  ["日本からの通報は", "**両クラスタとも 0 件**"],
  ["2 つのクラスタは繋がるか", "**はい。経路表ではどちらも AS54600 PEG TECH INC**"],
]), "");

/* ---- いちばん大事な注意 ---- */
L.push("## 1. 「複数 IP が報告されている」の中身", "");
L.push("通報 " + S.reports.total + " 件のうち **" + S.bulk_feeds.reduce((s, f) => s + f.reports, 0)
  + " 件が単一の通報者**で、日付以外は同じ定型文でした。", "");
for (const f of S.bulk_feeds) {
  L.push(T(["項目", "値"], [
    ["通報者", "`" + f.reporter + "`（所在 " + f.country + "）"],
    ["通報", f.reports + " 件 / " + f.distinct_ips + " IP"],
    ["通報した日", f.days.split(";").join(" / ")],
    ["カテゴリ", f.category_names],
    ["本文", code(safe(f.comment_excerpt, 90))],
  ]), "");
}
L.push("**これは脅威情報フィードの一括登録で、被害者が「攻撃された」と通報したものではありません。**", "");
L.push("定型文の " + code("Last observed") + " の日付は**通報日と常に同一**だったので、");
L.push("フィード側の観測時刻を別に教えてくれるものでもありませんでした。", "");
L.push("### カテゴリ 20（Exploited Host）は攻撃手法ではありません", "");
L.push("「この送信元自体が侵害されている可能性」を示す補助情報です。踏み台にされた");
L.push("正規ホストであれば、**送信元の持ち主も被害者**です。「この IP が攻撃してきた」とは違います。", "");
const indep = events.filter((e) => !S.bulk_feeds.some((f) => f.reporter === e.reporter));
L.push("### 一括登録を除くと " + indep.length + " 件しか残りません", "");
if (indep.length) {
  L.push(T(["通報日", "IP", "クラスタ", "通報者", "カテゴリ", "本文"],
    indep.map((e) => [e.reported_at.slice(0, 16), code(e.ip_address), e.cluster,
      "`" + e.reporter + "`", safe(e.category_names, 28),
      e.comment_empty === "true" ? "（空）" : code(safe(e.comment_excerpt, 46))])), "");
  L.push("**両方とも " + code("198.200.59.85") + " への通報です。**");
  L.push("つまり **ARTEX クラスタ 250 IP には、一括登録以外の通報が 1 件もありません**。", "");
}

/* ---- 時系列 ---- */
L.push("## 2. 時系列", "");
L.push(T(["日", "通報", "IP", "通報者", "ARTEX", "sub2api", "カテゴリ"],
  S.by_day.map((d) => [d.day, String(d.reports), String(d.distinct_ips),
    String(d.distinct_reporters), String(d.artex_ips), String(d.sub2api_ips),
    safe(d.category_names, 34)])), "");
L.push("読み方:", "");
L.push("- **2026-09-30** — " + code("198.200.59.85") + " に最初の通報（NL、Port Scan + Hacking）。");
L.push("  **ARTEX クラスタより 2 週間以上早い**");
L.push("- **2026-10-14** — この日に ARTEX 250 件を調べた時点では**通報 0 件**");
L.push("- **2026-10-17 / 10-20 / 10-24** — フィードが 11 件 → 1 件 → 32 件と段階的に登録");
L.push("- **2026-10-23** — " + code("198.200.59.85") + " に MY から通報（Hacking + Web App Attack）");
L.push("");
L.push("**フィードの登録は 3 回に分かれています。** 攻撃の波ではなく、フィード側の");
L.push("更新の都合である可能性が高いです（同じ通報者・同じ定型文・同じカテゴリ）。", "");

/* ---- クラスタの素性 ---- */
L.push("## 3. 2 つのクラスタは同じ事業者です", "");
L.push("利用者の観測（リチャージ URL の共有）とは**独立に**、経路表で繋がりました。", "");
L.push("```");
L.push("38.11.173.1    → 38.11.160.0/19   AS54600 PEG TECH INC (US)");
L.push("38.11.221.1    → 38.11.192.0/19   AS54600 PEG TECH INC (US)");
L.push("198.200.59.85  → 198.200.32.0/19  AS54600 PEG TECH INC (US)");
L.push("```");
L.push(T(["観点", "ARTEX（" + A.ips + " IP）", "sub2api（" + U.ips + " IP）"], [
  ["AbuseIPDB の ISP", Object.keys(A.isp).map((s) => safe(s, 30)).join(" / "),
    Object.keys(U.isp).map((s) => safe(s, 30)).join(" / ")],
  ["rDNS を持つ", String(A.with_rdns) + " / " + A.ips, "**" + U.with_rdns + " / " + U.ips + "**"],
  ["rDNS の登録ドメイン", Object.keys(A.rdns_domains).filter(Boolean).join(" ") || "—",
    Object.keys(U.rdns_domains).filter(Boolean).map(code).join(" ")],
  ["脅威情報の索引に既出", String(A.in_threat_index), String(U.in_threat_index)],
]), "");
L.push("**AbuseIPDB は ARTEX 側の ISP を Cogent と答えますが、経路表と VirusTotal は PEG TECH です。**");
L.push("食い違いではなく、ARIN RDAP に下位割当（SWIP）の登録が無いためです（10-14 に確認）。", "");
const sub = byIp.filter((r) => r.cluster === "sub2api");
L.push("### sub2api の rDNS は機械が付けた形です", "");
L.push(T(["IP", "rDNS", "通報", "スコア"], sub.map((r) => [
  code(r.ip_address), code(r.hostnames || "—"), r.reports_now, r.score_now])), "");
L.push("5 件すべてが " + code("visiblooths.net") + " の下で、5 文字の無意味な名前です。");
L.push("**リチャージ URL の共有とは別の筋で、同じ持ち主であることを裏づけます。**", "");
L.push("一方 **ARTEX 側は 250 件すべて rDNS が空**で、素性を出していません。", "");

/* ---- 通報された ARTEX の IP ---- */
const rep = byIp.filter((r) => r.cluster === "ARTEX" && Number(r.reports_now) > 0);
if (rep.length) {
  L.push("## 4. 通報が付いた ARTEX の " + rep.length + " IP", "");
  L.push("**全件が同じ通報者・同じカテゴリ・1 件ずつ**なので、IP ごとの差はありません。");
  L.push("ホスト番号の並びだけを載せます。", "");
  for (const pfx of ["38.11.173", "38.11.221"]) {
    const h = rep.filter((r) => r.ip_address.startsWith(pfx + "."))
      .map((r) => Number(r.ip_address.split(".")[3])).sort((a, b) => a - b);
    L.push("- " + code(pfx + ".x") + " — " + h.length + " 件: " + h.join(", "));
  }
  L.push("");
  L.push("`38.11.173.x` は 68〜123 に偏り、`38.11.221.x` は散らばっています。");
  L.push("ただし**フィードがどの順で登録したかの反映**かもしれないので、");
  L.push("攻撃者側の使い方を示すとは言えません。", "");
}

/* ---- 言えないこと ---- */
L.push("## 5. この調査で言えないこと", "");
L.push("- **ARTEX や sub2api が動いているかは確認していません。** 能動調査をしていないので、");
L.push("  待ち受けているサービスも見ていません。利用者から渡された前提のままです");
L.push("- **「攻撃に使われた時期」は特定できていません。** 通報の " + S.bulk_feeds.reduce((s, f) => s + f.reports, 0)
  + " / " + S.reports.total + " 件が");
L.push("  フィードの一括登録で、登録日は攻撃日ではありません");
L.push("- **通報が無いことは無害の証明ではありません。** 誰も通報していないだけで、");
L.push("  立てたばかりの基盤や、通報しない被害者しか居ない基盤は同じ見た目になります");
L.push("- AbuseIPDB のカテゴリは**レポーターの自己申告**です");
L.push("- IP の所在地・ISP・AS は、運用者の国籍や所属を示しません");
L.push("- 母集団は**渡された 255 IP だけ**です。同じ AS の他の帯は見ていません");
L.push("");
L.push("## 6. 次に打てる手（提案）", "");
L.push("- **索引に登録して毎日追う。** 両クラスタとも索引に 0 件なので、今は新しい通報が");
L.push("  付いても気付けません。日次エンリッチに載せれば、**フィード以外の通報が初めて付いた日**が分かります");
L.push("- **" + code("198.200.59.85") + " だけを重点監視する。** 一括登録以外の通報が付いている");
L.push("  唯一の IP で、しかも利用者が特定したリチャージ URL のホストです");
L.push("- **" + code("visiblooths.net") + " を証明書の記録（CT ログ）で追う。** 同じ命名規則の");
L.push("  兄弟ホストが他の帯にも居るなら、クラスタの広がりが分かります");
L.push("- 同じ AS54600 の他の帯を同じ手順で調べ、この 3 帯が特別かどうかを確かめる");
L.push("");
L.push("## 7. 残していないもの", "");
L.push("- " + code("reporterId") + " の値は保存していません（`BR-R01` のような識別子に置き換え、");
L.push("  同じ人かどうかだけが分かるようにしています）");
L.push("- 通報コメントの原文は保存せず、無害化して短く切ったものと SHA-256 だけ残しています");
L.push("- API キーはコンソール・ログ・CSV・JSON・ソース・エラーにも出していません");
L.push("- 写し（" + code(".cache/") + "）は git 管理外です");
L.push("");
fs.writeFileSync(path.join(HERE, "artex_timeline_report_ja.md"), L.join("\n"));
console.log("→ artex_timeline_report_ja.md（通報 " + S.reports.total + " 件 / 一括登録以外 " + indep.length + " 件）");
