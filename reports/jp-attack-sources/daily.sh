#!/bin/sh
# 日本からの攻撃報告がある IP の収集を 1 日ぶん通しでやる。
# **判断が要らないところは全部ここでやる。**
#
#   ABUSEIPDB_API_KEY="k" sh reports/jp-attack-sources/daily.sh [--commit] [--push] [--pr]
#                        [--max-check 9000] [--skip-days 7] [--candidate-days 1]
#                        [--no-refresh-blacklist]
#
# 何をするか
#   1. Blacklist を取り直す（候補の「30 日以内」条件を今日基準にするため）
#   2. 直近 N 日以内に確認した IP を外して /check を引く（既定 7 日・上限 9000 件）
#   3. 写しから畳み直して CSV と summary.json を作る（**API は呼ばない**）
#   4. 日本語レポートを組む
#   5. 検査する。**通らなければここで止まる**
#   6. コミットして push する（--commit / --push のときだけ）
#
# ## 枠の取り合いについて
#
# AbuseIPDB の `/check` は 1 日 10,000 回で **UTC 0 時にリセット**される。
# `IOC 日次エンリッチ`（00:00 UTC）が索引ぶんで 100 回前後を使うので、
# **この収集はその後に回し、上限 9,000 件に抑える**。予備枠 500 と合わせて
# 400 件ほど残るので、手元の引き直し（refetch.mjs）にも足りる。
#
# ## なぜ Blacklist を毎日取り直すのか
#
# 候補の条件が「`lastReportedAt` が 30 日以内」なので、**写しが古いとその 30 日も
# 古くなる**。5 日前の写しを使うと実質 35 日前までの IP が候補に入った。
# `/blacklist` の枠は 1 日 100 回なので、1 回使うだけなら問題ない。
#
# ## なぜ「7 日以内は除外」なのか
#
# 既定の選び方は `lastReportedAt` の新しい順で、キャッシュ判定は 24 時間以内だけ。
# 1 日経つと全部「未取得」に戻るので、放っておくと**毎回ほぼ同じ IP を引き直して
# バックログが前に進まない**。実測で写しが 16,571 行あるのに固有 IP が 9,499 件
# しかなく、未確認の候補 89,840 件は一度も選ばれていなかった。
#
# ## 台帳が無いと 7 日ルールは効かない（2026-10-22 に判明）
#
# `.cache/` は git 管理外なので、ルーチンが新しいクローンで走ると写しが空から
# 始まる。すると「7 日以内に確認した IP」が 0 件と判定され、**除外が何も働かない**。
#
# 実測（10-17〜10-22 のルーチン出力）では前日と 39〜46% が同じ IP で、
# 5 日ぶんの和集合は 12,846 件だった（毎日新規なら約 24,765 件のはず）。
# **枠の半分が引き直しに消えていた。**
#
# そこで `state/checked-ledger.jsonl`（`{at, ip}` だけ）を git に置き、
# `--ledger` で読ませる。10 万件でも 3.9 MB で収まる。写し本体は 62.8 MB なので
# git には置かない。**「引いたかどうか」だけを残す。**
#
# ## なぜ候補を 1 日以内に絞るのか
#
# 30 日だと候補が 98,880 件あり、1 日 9,000 件では**一巡に 11 日**かかる。
# 11 日前に引いた行の「過去 30 日」はもう古いので、30 日窓の一覧として成立しない。
# **1 日に絞ると候補は 51,245 件**で、今まさに動いている送信元だけが残る。
# 信頼度は Blacklist 側の下限（75）のままで、ここでは絞らない。
set -e

HERE=$(dirname "$0")
MAX_CHECK=${JP_MAX_CHECK:-9000}
SKIP_DAYS=${JP_SKIP_DAYS:-7}
CAND_DAYS=${JP_CANDIDATE_DAYS:-1}
LEDGER=${JP_LEDGER:-reports/jp-attack-sources/state/checked-ledger.jsonl}
REFRESH_BL=1
COMMIT=0
PUSH=0
PR=0
for a in "$@"; do
  case "$a" in
    --commit) COMMIT=1 ;;
    --push)   COMMIT=1; PUSH=1 ;;
    --pr)     COMMIT=1; PUSH=1; PR=1 ;;
    --no-refresh-blacklist) REFRESH_BL=0 ;;
    --max-check) shift; MAX_CHECK=$1 ;;
    --max-check=*) MAX_CHECK=${a#*=} ;;
    --skip-days) shift; SKIP_DAYS=$1 ;;
    --skip-days=*) SKIP_DAYS=${a#*=} ;;
    --candidate-days) shift; CAND_DAYS=$1 ;;
    --candidate-days=*) CAND_DAYS=${a#*=} ;;
  esac
done

say() { printf '\n== %s\n' "$1"; }

# **鍵は有無だけ見る。値は絶対に出さない。**
if [ -z "$ABUSEIPDB_API_KEY" ]; then
  echo "! ABUSEIPDB_API_KEY がありません。取得できないので止めます" >&2
  exit 2
fi

say "取得（上限 ${MAX_CHECK} 件 / 候補は最終通報 ${CAND_DAYS} 日以内 / 直近 ${SKIP_DAYS} 日以内に確認した IP は除外）"
BL=""
if [ "$REFRESH_BL" = 1 ]; then BL="--refresh-blacklist"; fi
# ここだけが外に出る。失敗しても写しは残り、翌日続きから引く
node "$HERE/../global-jp-vuln/build.mjs" $BL \
  --skip-checked-within "$SKIP_DAYS" --max-check "$MAX_CHECK" \
  --candidate-days "$CAND_DAYS" --ledger "$LEDGER"

# ここから先は写ししか見ない。同じ写しからは何度でも同じ結果が出る
say "畳み直す"
node "$HERE/build.mjs"

say "レポートを組む"
node "$HERE/report.mjs"

say "検査"
# **通らなければここで止まる。**壊れた一式を明日の基準にしないため
node "$HERE/validate.mjs"

if [ "$COMMIT" = 1 ]; then
  say "残す"
  # **台帳も必ず入れる。**これが残らないと翌日また同じ IP を引く
  git add "$HERE" "$HERE/../global-jp-vuln"
  if git diff --cached --quiet; then
    echo "  変化がありません。コミットしません"
  else
    N=$(node -e "const s=require('./$HERE/jp_attack_sources_summary.json');const r=s.report_class_30d;console.log(r.multi+' / '+r.single)")
    git commit -q -m "data(reports): 日本からの攻撃報告を収集（マルチ/シングル ${N}）"
    echo "  $(git log --oneline -1)"
    if [ "$PUSH" = 1 ]; then
      B=$(git rev-parse --abbrev-ref HEAD)
      i=1
      until git push -q -u origin "$B"; do
        [ "$i" -gt 4 ] && { echo "! push が 4 回失敗しました" >&2; exit 1; }
        sleep $((i * 2)); i=$((i + 1))
      done
      echo "  push しました（$B）"

      if [ "$PR" = 1 ]; then
        say "PR"
        # **PR 作成の失敗で収集を台無しにしない。**push は済んでいるので、
        # ここが落ちても成果は残る。落ちたことだけ告げて終了コードは 0 にする
        if sh "$HERE/open-pr.sh" "$B"; then :; else
          echo "! PR を作れませんでした。push は済んでいるので手で作ってください" >&2
        fi
      fi
    fi
  fi
fi
