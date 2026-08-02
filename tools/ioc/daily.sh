#!/bin/sh
# 1 日ぶんのエンリッチを通しでやる。**判断が要らないところは全部ここでやる。**
#
#   VT_API_KEYS="k1,k2,k3" ABUSEIPDB_API_KEY="k" sh tools/ioc/daily.sh [--collect] [--commit] [--push]
#
# 何をするか
#   0. 索引を取り直す（--collect のときだけ。既定は週次なので毎日はやらない）
#   1. 経路表の写しを更新する（BGPTOOLS_CONTACT があるときだけ）
#   2. VT と AbuseIPDB を、その日の枠を使い切るまで引く（並行）
#   3. 写しから作り直す（enrich-intel → stats）
#   4. 検査する。**通らなければここで止まる**
#   5. 昨日から何が変わったかを出す（daily-report.mjs）
#   6. コミットして push する（--commit / --push のときだけ）
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
COLLECT=0
COMMIT=0
PUSH=0
for a in "$@"; do
  case "$a" in
    --collect) COLLECT=1 ;;
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

if [ "$COLLECT" = 1 ]; then
  say "索引を取り直す"
  node tools/ioc/collect.mjs --out "$DIR" --cache data/ioc/.cache
fi

if [ -n "$BGPTOOLS_CONTACT" ]; then
  say "経路表"
  node tools/ioc/fetch-asn.mjs
  node tools/ioc/enrich-asn.mjs --in "$DIR"
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
[ "$FAILED" = 0 ] || echo "! 取得のどちらかが落ちました。写しはそのまま次回に続きます" >&2

# ここから先は写ししか見ない。同じ写しからは何度でも同じ結果が出る
say "作り直す"
node tools/ioc/enrich-intel.mjs --in "$DIR"
node tools/ioc/stats.mjs        --in "$DIR"

say "検査"
node tools/ioc/validate.mjs --in "$DIR" --strict

say "昨日から何が変わったか"
if [ -d "$PREV" ]; then
  node tools/ioc/daily-report.mjs --in "$DIR" --prev "$PREV"
else
  node tools/ioc/daily-report.mjs --in "$DIR"
fi
rm -rf "$PREV"

if [ "$COMMIT" = 1 ]; then
  say "残す"
  # 検査が通ってからでないとコミットしない。壊れた一式が明日の基準になるのを防ぐ
  git add "$DIR"
  if git diff --cached --quiet; then
    echo "  変化がありません。コミットしません"
  else
    RATIO=$(node -e "const s=require('./$DIR/stats.json');console.log((s.coverage.virustotal.ratio*100).toFixed(1))")
    git commit -q -m "data: IOC のエンリッチ（VT ${RATIO}%）"
    echo "  $(git log --oneline -1)"
    [ "$PUSH" = 1 ] && git push -q -u origin "$(git rev-parse --abbrev-ref HEAD)" && echo "  push しました"
  fi
fi
