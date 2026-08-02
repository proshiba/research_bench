#!/bin/sh
# 1 日ぶんのエンリッチ。**枠を使い切るまで引き、写しから作り直して検査する**。
#
#   VT_API_KEYS="k1,k2,k3" ABUSEIPDB_API_KEY="k" sh tools/ioc/daily.sh
#   IOC_DIR=data/ioc/2026-W31 sh tools/ioc/daily.sh
#
# VT は無料枠だと 1 鍵 500 件/日なので、全 18,589 件は一度に埋まらない。
# 引く順は docs/ioc-enrich-plan.md §4 の段階分けに従うので、**途中で止まっていても
# 意味のある所まで進んでいる**。毎日これを回せば、重なりの根拠になる段階 1 から埋まる。
#
# 索引の取り込み（collect.mjs）は週次のまま。ここは判定を足すだけで、
# 索引そのものには触らない。
set -e

DIR=${IOC_DIR:-data/ioc/latest}

# 外に出るのはこの 2 つだけ。どちらも写しを残す
node tools/ioc/fetch-vt.mjs        --in "$DIR" "$@"
node tools/ioc/fetch-abuseipdb.mjs --in "$DIR"

# ここから先は写ししか見ない。同じ写しからは何度でも同じ結果が出る
node tools/ioc/enrich-intel.mjs --in "$DIR"
node tools/ioc/stats.mjs        --in "$DIR"
node tools/ioc/validate.mjs     --in "$DIR" --strict
