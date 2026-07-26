#!/usr/bin/env python3
"""research_bench ポータル連携仕様 v1 の適合チェッカー。

各アプリのリポジトリから、生成した meta.json / search.json を検査するために使う。
標準ライブラリだけで動く。仕様本体は docs/portal-spec.md。

    python3 validate-index.py path/to/api/v1/meta.json path/to/api/v1/search.json
    python3 validate-index.py https://example.github.io/app/api/v1/meta.json

エラーが 1 件でもあれば終了コード 1。警告だけなら 0。
"""

from __future__ import annotations

import argparse
import collections
import gzip
import io
import json
import re
import sys
import urllib.request
from typing import Any

SPEC_TYPES = {
    "ioc.ipv4", "ioc.ipv6", "ioc.domain", "ioc.url", "ioc.endpoint", "ioc.email",
    "ioc.md5", "ioc.sha1", "ioc.sha256",
    "cve", "actor", "malware", "case", "campaign", "product", "vendor", "ttp", "tool", "report",
}

NAME_TYPES = {"actor", "malware", "tool"}

DEFANGED = re.compile(r"\[\.\]|\(\.\)|\[dot\]|\(dot\)|hxxp|\[:\]|\[@\]", re.I)
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
HEX = {"ioc.md5": 32, "ioc.sha1": 40, "ioc.sha256": 64}

errors: list[str] = []
warnings: list[str] = []


def err(msg: str) -> None:
    errors.append(msg)


def warn(msg: str) -> None:
    warnings.append(msg)


def load(path: str) -> tuple[Any, int]:
    """JSON を読み、生バイト数も返す。"""
    if path.startswith(("http://", "https://")):
        with urllib.request.urlopen(path, timeout=120) as res:
            raw = res.read()
            if res.headers.get("content-encoding") == "gzip":
                raw = gzip.decompress(raw)
    else:
        with open(path, "rb") as fh:
            raw = fh.read()
    return json.loads(raw.decode("utf-8")), len(raw)


def join_key(etype: str, value: str) -> str:
    v = str(value or "").strip()
    if not v:
        return ""
    if etype == "cve":
        return v.upper()
    if etype in NAME_TYPES:
        k = re.sub(r"[^a-z0-9]+", "", v.lower())
        return "name:" + k if k else ""
    if etype == "ttp":
        return v.upper()
    return v.lower()


def check_meta(meta: dict) -> None:
    for field in ("spec_version", "app_id", "name", "site_url", "endpoints"):
        if not meta.get(field):
            err(f"meta.json: 必須フィールド `{field}` がありません")

    if meta.get("spec_version") and not str(meta["spec_version"]).startswith("1."):
        warn(f"meta.json: spec_version が {meta['spec_version']} です（このチェッカーは 1.x 用）")

    endpoints = meta.get("endpoints") or {}
    if not endpoints.get("search"):
        err("meta.json: endpoints.search がありません")

    if not str(meta.get("site_url", "")).endswith("/"):
        warn("meta.json: site_url は末尾を `/` にしてください（相対解決がずれます）")

    links = meta.get("deep_links") or {}
    if not links:
        warn("meta.json: deep_links が空です。ポータルから詳細ページへ飛べません")
    for key, tpl in links.items():
        if "{" not in str(tpl):
            warn(f"meta.json: deep_links.{key} に置換変数がありません: {tpl}")
        for var in re.findall(r"\{(\w+)\}", str(tpl)):
            if var not in ("detail", "id", "value", "prefix"):
                warn(f"meta.json: deep_links.{key} の未知の変数 {{{var}}}")
        if key != "_graph" and key not in SPEC_TYPES:
            warn(f"meta.json: deep_links のキー `{key}` は既知のエンティティ型ではありません")


def check_entities(doc: dict, raw_bytes: int) -> None:
    if not doc.get("spec_version"):
        err("search.json: spec_version がありません")
    if not doc.get("app_id"):
        err("search.json: app_id がありません")

    entities = doc.get("entities")
    if not isinstance(entities, list):
        err("search.json: entities が配列ではありません")
        return
    if not entities:
        err("search.json: entities が空です")
        return

    ids: set[str] = set()
    by_type: collections.Counter = collections.Counter()
    ref_targets: list[tuple[str, str]] = []
    joinable = 0
    dup_reported = 0
    defang_reported = 0

    for i, e in enumerate(entities):
        where = f"entities[{i}]"
        if not isinstance(e, dict):
            err(f"{where}: オブジェクトではありません")
            continue

        etype = e.get("type")
        eid = e.get("id")
        label = e.get("label")

        if not etype:
            err(f"{where}: type がありません")
        elif etype not in SPEC_TYPES:
            warn(f"{where}: 語彙にない type `{etype}`（ポータルは「その他」として扱います）")
        if not eid:
            err(f"{where}: id がありません")
        elif eid in ids:
            if dup_reported < 5:
                err(f"{where}: id が重複しています: {eid}")
                dup_reported += 1
        else:
            ids.add(eid)
        if not label:
            err(f"{where}: label がありません")

        by_type[etype] += 1
        value = e.get("value", label)

        if value and DEFANGED.search(str(value)):
            if defang_reported < 5:
                err(f"{where}: value が defang されたままです（refang して入れてください）: {value}")
                defang_reported += 1

        if etype == "cve" and value and not CVE_RE.match(str(value)):
            warn(f"{where}: cve の value が CVE-YYYY-NNNN 形式ではありません: {value}")
        if etype in HEX and value:
            v = str(value)
            if len(v) != HEX[etype] or not re.fullmatch(r"[a-f0-9]+", v):
                warn(f"{where}: {etype} の value が小文字 {HEX[etype]} 桁の 16 進ではありません: {v[:24]}")

        if join_key(etype or "", value or ""):
            joinable += 1

        for r in e.get("refs") or []:
            if not isinstance(r, dict) or not r.get("target"):
                err(f"{where}: refs の要素に target がありません")
                continue
            ref_targets.append((eid or where, r["target"]))

    missing = [(src, tgt) for src, tgt in ref_targets if tgt not in ids]
    if missing:
        err(f"refs の参照先 {len(missing)} 件がこのファイル内に存在しません "
            f"（refs.target は同一ソース内の id を指す必要があります）。例: "
            + ", ".join(f"{s} → {t}" for s, t in missing[:3]))

    gz = len(gzip.compress(json.dumps(doc, ensure_ascii=False).encode("utf-8"), 6))

    print(f"  エンティティ  : {len(entities):,}")
    print(f"  結合キーあり  : {joinable:,} "
          f"({joinable / len(entities) * 100:.0f}% — 横串はこの値の一致で作られます)")
    print(f"  参照(refs)    : {len(ref_targets):,}")
    print(f"  サイズ        : {raw_bytes / 1048576:.2f} MB (gzip 約 {gz / 1048576:.2f} MB)")
    print("  型の内訳      :")
    for t, n in by_type.most_common():
        print(f"      {t or '(なし)':<16} {n:>8,}")

    if gz > 8 * 1048576:
        warn(f"gzip 後 {gz / 1048576:.1f} MB は大きすぎます。本文や長い説明を索引から外してください")


def main() -> int:
    ap = argparse.ArgumentParser(description="ポータル連携仕様 v1 の適合チェック")
    ap.add_argument("meta", help="meta.json のパスまたは URL")
    ap.add_argument("search", nargs="?", help="search.json のパスまたは URL（省略時は meta から解決）")
    args = ap.parse_args()

    print(f"meta   : {args.meta}")
    try:
        meta, _ = load(args.meta)
    except Exception as exc:  # noqa: BLE001 - 入力は外部ファイル
        print(f"読み込めませんでした: {exc}", file=sys.stderr)
        return 1
    check_meta(meta if isinstance(meta, dict) else {})

    search = args.search
    if not search and isinstance(meta, dict):
        ep = (meta.get("endpoints") or {}).get("search")
        if ep:
            if args.meta.startswith(("http://", "https://")):
                from urllib.parse import urljoin
                search = urljoin(meta.get("site_url") or args.meta, ep)
            else:
                import os
                search = os.path.join(os.path.dirname(args.meta), os.path.basename(ep))
    if not search:
        err("search.json の場所を決められませんでした")
    else:
        print(f"search : {search}")
        try:
            doc, raw = load(search)
            check_entities(doc if isinstance(doc, dict) else {}, raw)
        except Exception as exc:  # noqa: BLE001
            err(f"search.json を読み込めませんでした: {exc}")

    print()
    for w in warnings:
        print(f"  警告: {w}")
    for e in errors:
        print(f"  エラー: {e}")
    if errors:
        print(f"\n不適合: エラー {len(errors)} 件 / 警告 {len(warnings)} 件")
        return 1
    print(f"\n適合: 警告 {len(warnings)} 件")
    return 0


if __name__ == "__main__":
    sys.exit(main())
