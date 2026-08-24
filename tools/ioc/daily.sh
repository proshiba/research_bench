#!/bin/sh
# 1 日ぶんのエンリッチを通しでやる。**判断が要らないところは全部ここでやる。**
#
#   VT_API_KEYS="k1,k2,k3" ABUSEIPDB_API_KEY="k" sh tools/ioc/daily.sh [--collect] [--track] [--commit] [--push]
#
# 何をするか
#   0. 索引を取り直す（--collect のときだけ。既定は週次なので毎日はやらない）
#   1. 経路表の写しを更新する（BGPTOOLS_CONTACT があるときだけ）
#   2. 攻撃者ドメインの生存確認（--track のときだけ。DNS は枠を使わない）
#   3. VT と AbuseIPDB を、その日の枠を使い切るまで引く（並行）
#   4. 写しから作り直す（enrich-intel → enrich-asn → stats）
#   5. 検査する。**通らなければここで止まる**
#   6. 昨日から何が変わったかを出し、data/ioc/reports/<日付>.json に残す
#   7. コミットして push する（--commit / --push のときだけ）
#
# VT は無料枠だと 1 鍵 500 件/日なので、全件は一度に埋まらない。引く順は
# docs/ioc-enrich-plan.md §4 の段階分けに従うので、**何日目で止まっていても
# 意味のある所まで進んでいる**。
#
# **人（や AI）がやるのは 5 の結果を読むところから。** 取得・突き合わせ・検査・
# 差分の抽出はここで終わっている。残るのは「この食い違いは索引の誤りか、まだ
# 知られていないだけか」のような、機械では決められない判断とピボット調査だけ。
set -e

DIR=${IOC_DIR:-data/ioc/latest}
PREV=${IOC_PREV:-.ioc-prev}
# 日次レポートの置き場。1 日 1 ファイルで、これだけを追って経過が読める
REPORTS=${IOC_REPORTS:-data/ioc/reports}
# 攻撃者ドメインのトラッカー。観測は 1 日 1 ファイルで積み上がる
TRACKER=${IOC_TRACKER:-data/ioc/tracker}
# 生存ドメインの検体を引き直す件数。**VT の枠を先に少しだけ取る**（下記）
TRACK_SAMPLES=${IOC_TRACK_SAMPLES:-120}
COLLECT=0
TRACK=0
COMMIT=0
PUSH=0
for a in "$@"; do
  case "$a" in
    --collect) COLLECT=1 ;;
    --track)   TRACK=1 ;;
    --commit)  COMMIT=1 ;;
    --push)    COMMIT=1; PUSH=1 ;;
    *) echo "知らない引数です: $a" >&2; exit 2 ;;
  esac
done

say() { printf '\n== %s\n' "$1"; }

# 差分の基準は「前回コミットした一式」。写しと違って git には残っているので、
# 環境が変わっても昨日と比べられる
rm -rf "$PREV"
if git rev-parse --verify -q HEAD >/dev/null && git cat-file -e "HEAD:$DIR/stats.json" 2>/dev/null; then
  mkdir -p "$PREV"
  for f in stats.json overlaps.jsonl vt.jsonl abuseipdb.jsonl \
           derived-entities.jsonl derived-aliases.jsonl derived-certs.jsonl derived-iocs.jsonl; do
    git cat-file -e "HEAD:$DIR/$f" 2>/dev/null && git show "HEAD:$DIR/$f" > "$PREV/$f" || true
  done
fi

# **索引より先。** 登録可能ドメインの判定がこの一覧に乗っているので、
# 写しが無いまま collect すると手書きの控えで数えてしまう。写しは追跡していない
# （器が毎回まっさら）ので、**毎回ここで取り直す必要がある**。7 日以内なら即座に返る。
say "公開接尾辞一覧"
node tools/ioc/fetch-psl.mjs || echo "! 一覧が取れませんでした。手書きの控えで数えます" >&2

if [ "$COLLECT" = 1 ]; then
  say "索引を取り直す"
  node tools/ioc/collect.mjs --out "$DIR" --cache data/ioc/.cache
fi

if [ -n "$BGPTOOLS_CONTACT" ]; then
  say "経路表の写し"
  node tools/ioc/fetch-asn.mjs
fi

if [ "$TRACK" = 1 ]; then
  # DNS は鍵も枠も要らないので、毎日全件やって構わない。答えが返らなかったものは
  # 中で引き直す（初回実測で error 622 件のうち大半はこちらの叩きすぎだった）
  say "攻撃者ドメインの生存確認"
  node tools/ioc/fetch-dns.mjs --out "$TRACKER" --in "$DIR"
  node tools/ioc/track-domains.mjs --tracker "$TRACKER" --in "$DIR"

  # 検体の引き直しは **VT より先**。fetch-vt は VT に「今日いくつ使ったか」を
  # 聞いてから予算を決めるので、先に少し取っておけば自動的に譲ってくれる。
  # 逆にすると枠を使い切ったあとで、生存ドメイン側が 1 件も引けない
  if [ -n "$VT_API_KEYS$VT_API_KEYs" ]; then
    say "生きているドメインに付いた検体"
    node tools/ioc/fetch-tracker-samples.mjs --tracker "$TRACKER" --in "$DIR" --limit "$TRACK_SAMPLES" || \
      echo "! 検体の引き直しが落ちました。生死の判定は済んでいます" >&2
  fi
fi

# 外に出るのはこの 2 つだけ。どちらも写しを残す。鍵も枠も別なので並行して走らせる
say "VirusTotal / AbuseIPDB"
node tools/ioc/fetch-vt.mjs --in "$DIR" &
VT=$!
node tools/ioc/fetch-abuseipdb.mjs --in "$DIR" &
AB=$!
# 片方が落ちても、もう片方の写しは残る。落ちたことは終了コードで返す
FAILED=0
wait $VT || FAILED=1
wait $AB || FAILED=1
if [ "$FAILED" != 0 ]; then echo "! 取得のどちらかが落ちました。写しはそのまま次回に続きます" >&2; fi

# ここから先は写ししか見ない。同じ写しからは何度でも同じ結果が出る
say "作り直す"
node tools/ioc/enrich-intel.mjs --in "$DIR"
# AS の付与は enrich-intel のあと。**生えた IP にも AS が要る**（Cloudflare の
# edge に解決するドメイン同士を「同じ所に居る」と言わないため）
if [ -n "$BGPTOOLS_CONTACT" ]; then node tools/ioc/enrich-asn.mjs --in "$DIR"; fi
node tools/ioc/stats.mjs --in "$DIR"

say "検査"
node tools/ioc/validate.mjs --in "$DIR" --strict

# 画面に出すだけだと、何日目に何が出たかが後から追えない。**日付ごとに残す**
say "昨日から何が変わったか"
REPORT="$REPORTS/$(date -u +%F).json"
if [ -d "$PREV" ]; then
  node tools/ioc/daily-report.mjs --in "$DIR" --prev "$PREV" --json "$REPORT"
else
  node tools/ioc/daily-report.mjs --in "$DIR" --json "$REPORT"
fi
rm -rf "$PREV"

if [ "$COMMIT" = 1 ]; then
  say "残す"
  # 検査が通ってからでないとコミットしない。壊れた一式が明日の基準になるのを防ぐ
  git add "$DIR" "$REPORTS"
  if [ "$TRACK" = 1 ]; then git add "$TRACKER"; fi
  if git diff --cached --quiet; then
    echo "  変化がありません。コミットしません"
  else
    RATIO=$(node -e "const s=require('./$DIR/stats.json');console.log((s.coverage.virustotal.ratio*100).toFixed(1))")
    git commit -q -m "data: IOC のエンリッチ（VT ${RATIO}%）"
    echo "  $(git log --oneline -1)"
    if [ "$PUSH" = 1 ]; then
      git push -q -u origin "$(git rev-parse --abbrev-ref HEAD)"
      echo "  push しました"
    fi
  fi
fi
