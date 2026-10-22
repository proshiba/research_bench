#!/bin/sh
# その日の収集ぶんの PR を作る（既に開いているものがあれば何もしない）。
#
#   sh reports/jp-attack-sources/open-pr.sh <branch>
#
# **これが落ちても収集は台無しにしない。**呼ぶ側は失敗を無視して終わる設計で、
# push は済んでいるので成果は残る。GitHub に届かない日は手で作ればよい。
#
# 同じ head+base で 2 つ目の PR は開けないので、**既に開いていれば作らない**。
# その日のぶんは既存の PR が自動で取り込む（PR はブランチを追跡するため）。
set -e

B=${1:-$(git rev-parse --abbrev-ref HEAD)}
HERE=$(dirname "$0")
REPO=$(git remote get-url origin | sed -e 's|.*github.com[:/]||' -e 's|\.git$||')
BASE=$(gh api "repos/$REPO" --jq '.default_branch' 2>/dev/null || echo main)

OPEN=$(gh api "repos/$REPO/pulls?state=open&head=${REPO%%/*}:$B" --jq 'length' 2>/dev/null || echo "?")
if [ "$OPEN" = "?" ]; then
  echo "  GitHub に問い合わせできませんでした。PR は作りません" >&2
  exit 1
fi
if [ "$OPEN" != "0" ]; then
  N=$(gh api "repos/$REPO/pulls?state=open&head=${REPO%%/*}:$B" --jq '.[0].number')
  echo "  既に PR #$N が開いています。この日のぶんも自動で入ります"
  exit 0
fi

DAY=$(date -u +%F)
BODY=$(node -e '
const fs=require("fs");
const S=JSON.parse(fs.readFileSync(process.argv[1]+"/jp_attack_sources_summary.json","utf8"));
const R=S.report_class_30d, P=S.primary_window, C=S.coverage;
const L=[];
L.push("AbuseIPDB をもとにした「日本のレポーターが攻撃として報告した送信元 IP」の日次収集です。**この PR はルーチンが自動で作っています。**","");
L.push("## 取得条件","");
L.push("| 項目 | 値 |","| --- | --- |");
L.push("| 窓 | 過去 "+P.days+" 日（"+P.since_utc+" 以降） |");
L.push("| 写しを読んだ IP | "+C.api_ok+" |");
L.push("| 未確認の候補 | "+(C.unchecked_candidates??"—")+" |");
L.push("");
L.push("## 結果","");
L.push("| 区分 | 条件 | 件数 |","| --- | --- | --- |");
L.push("| **マルチレポート** | "+P.days+" 日以内に 2 件以上 | **"+R.multi+"** |");
L.push("| **シングルレポート** | "+P.days+" 日以内に 1 件 | **"+R.single+"** |");
L.push("| 窓内に攻撃報告なし | 0 件 | "+R.none_in_window+" |");
L.push("| **判定不能** | 件数が不明 | **"+R.undecidable+"** |");
L.push("");
L.push("マルチのうち観測者も 2 人以上は **"+R.multi_with_2plus_reporters+" 件**。");
L.push("残り "+R.multi_single_reporter_only+" 件は同じ 1 人の複数回通報です。","");
L.push("**判定不能は「0 件」ではなく「引き直していないので分からない」という意味**で、");
L.push("シングルや「なし」に落としていないことを検査が確かめています。","");
L.push("## 読むときの注意","");
L.push("`reporterCountryCode` が意味するのは「**通報した人が日本に居る**」ことだけです。");
L.push("攻撃先が日本であること、送信元が日本を狙っていることは意味しません");
L.push("（日本に監視機器が多いだけでも同じ数字になります）。**「日本向け攻撃元」の列は作っていません。**","");
L.push("- 対象 IP への接続・走査・認証試行は行っていません");
L.push("- 研究スキャナ "+(S.marks?S.marks.research_scanner:"—")+" 件は消さずに別 CSV へ出し、主対象から外しています");
L.push("- `reporterId` の値とコメント原文は保存していません","");
L.push("検査 "+"（validate.mjs）"+"を通してからコミットしています。","");
L.push("🤖 Generated with [Claude Code](https://claude.com/claude-code)");
console.log(L.join("\n"));
' "$HERE")

TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT
PR_TITLE="data(reports): 日本からの攻撃報告の日次収集（$DAY）" \
PR_HEAD="$B" PR_BASE="$BASE" PR_BODY="$BODY" \
node -e '
require("node:fs").writeFileSync(process.argv[1], JSON.stringify({
  title: process.env.PR_TITLE, head: process.env.PR_HEAD,
  base: process.env.PR_BASE, body: process.env.PR_BODY,
}));' "$TMP"
N=$(gh api "repos/$REPO/pulls" --method POST --input "$TMP" --jq '.number')
echo "  PR #$N を作りました（$BASE ← $B）"
