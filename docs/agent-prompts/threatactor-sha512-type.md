# 依頼: SHA-512 を `ioc.sha512` として索引に出す（threatactor-intel-analysis）

## 背景

ポータル `proshiba/research_bench` が読んでいる索引
`ui/api/v1/search.json` で、**SHA-512 が 18 件 `ioc.sha256` として出ている。**

これは当時の判断としては正しい。`ui/build_portal_index.py` にそう書いてある。

```python
IOC_TYPE_MAP = {
    "sha256": "ioc.sha256",
    "sha512": "ioc.sha256",  # 語彙に ioc.sha512 が無いため sha256 に寄せる
}
```

**その前提が変わった。** ポータル仕様に `ioc.sha512` を追加したので、寄せる必要が無くなった。
ポータル側は既に受け入れられる（`util.js` の型判定・表示名、`adapters.js` の型マップ、
`exchange.js` の STIX / MISP 書き出しすべてに `ioc.sha512` が入っている）。

急ぎではない。ハッシュ長が違うので**誤結合は起きていない**（64 桁と 128 桁が
同じ値になることはない）。直すと表示が正しくなり、STIX 書き出しが
`file:hashes.'SHA-256'` ではなく `'SHA-512'` になる。

---

## 実測（2026-07-30 時点の公開 `search.json`）

```
ioc.md5     全 1883 件  値の長さ: 32 → 1883
ioc.sha1    全 1178 件  値の長さ: 40 → 1178
ioc.sha256  全 1177 件  値の長さ: 64 → 1159, 128 → 18   ← この 18 件
ioc.sha512  全    0 件
```

`profiles/*/iocs.json` 側では 18 件すべて `type: "sha512"` として正しく記録されている。
**索引生成の型マップだけの問題。**

---

## やること

`ui/build_portal_index.py` の 2 箇所。

### ① 型マップ（48 行目）

```python
    "sha512": "ioc.sha512",
```

### ② `HASH_TYPES`（55 行目）— ここを忘れないこと

```python
HASH_TYPES = {"ioc.md5", "ioc.sha1", "ioc.sha256", "ioc.sha512"}
```

**①だけ直すと正規化と検証が丸ごと外れる。** `HASH_TYPES` は
`normalize_ioc()`（194 行目）で小文字化と 16 進チェックのゲートになっているため、
`ioc.sha512` が集合に無いとどの分岐にも入らず、値が素通りする。

```python
    elif spec_type in HASH_TYPES:
        value = value.lower()
        if not re.fullmatch(r"[0-9a-f]{32,128}", value):
            return None
```

今のデータでは `ind.get("normalized_value")` を先に読んでいて（311 行目）、
18 件すべてに `normalized_value` があり小文字なので**すぐには壊れない**。
ただし `value` へのフォールバックが効いたときは大文字で出る
（実際に 18 件のうち 2 件は `value` が大文字）。潜在的な穴なので一緒に閉じる。

---

## 提案（任意・別でよい）

`normalize_ioc()` の 16 進チェックが `{32,128}` の範囲指定なので、
**型と長さの不一致を検出できない**。たとえば 50 桁の 16 進文字列が
`ioc.sha256` として来ても通る。型ごとの厳密な長さにすると弾ける。

```python
HASH_LENGTHS = {"ioc.md5": 32, "ioc.sha1": 40, "ioc.sha256": 64, "ioc.sha512": 128}
...
    elif spec_type in HASH_TYPES:
        value = value.lower()
        if not re.fullmatch(r"[0-9a-f]{%d}" % HASH_LENGTHS[spec_type], value):
            return None
```

これを入れると、**今の 18 件は `ioc.sha256` のままでは弾かれる**ので、
①②と同時に入れる必要がある（順番に入れると 18 件が一時的に消える）。

---

## 確認すること

索引を作り直して、次を確認する。

```
$ python3 ui/build_portal_index.py
$ python3 - <<'PY'
import json, collections
d = json.load(open("ui/api/v1/search.json"))
by = collections.Counter(e["type"] for e in d["entities"])
for t in ("ioc.md5", "ioc.sha1", "ioc.sha256", "ioc.sha512"):
    ls = collections.Counter(len(e["label"]) for e in d["entities"] if e["type"] == t)
    print(f"{t:12} {by[t]:5}  長さ={dict(ls)}")
PY
```

期待する結果。

```
ioc.md5      1883  長さ={32: 1883}
ioc.sha1     1178  長さ={40: 1178}
ioc.sha256   1159  長さ={64: 1159}     ← 18 件減る
ioc.sha512     18  長さ={128: 18}      ← 新設
```

- **どの型でも長さが 1 種類だけ**になること（混在が無いこと）
- ラベルがすべて小文字であること
- エンティティの総数が **15609 件から変わらない**こと（型が変わるだけで、増減しない）
- 既存のテストが通ること

**もう一方の依頼（`threatactor-hash-false-positive.md`）を先に入れた場合**、
`ioc.sha512` は 18 件ではなく **16 件**になる（128 桁の 2 件はハッシュでないため落ちる）。
どちらを先に入れてもよいが、期待値がこの分ずれることは把握しておくこと。

---

## ブランチと PR

- ブランチ: `claude/portal-index-sha512`
- PR タイトル: `SHA-512 を ioc.sha512 として索引に出す`
- PR 本文に上の確認コマンドの出力を貼ること

## やらないこと

- `profiles/` 配下のデータの変更（型は元々 `sha512` で正しい）
- `ui/data/actors.json`（このリポジトリの UI が依存している）への影響
- **IOC 抽出そのものの修正** — 別依頼
  （`threatactor-hash-false-positive.md`）。18 件のうち 2 件は
  そもそもハッシュではないが、それは抽出側の話で、この依頼とは独立に直せる
