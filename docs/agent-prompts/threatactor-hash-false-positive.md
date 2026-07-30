# 依頼: ハッシュに見える「ハッシュでないもの」を取り込まない（threatactor-intel-analysis）

## 背景

`profiles/*/iocs.json` に、**ハッシュではない 16 進のバイト列がファイルハッシュとして
取り込まれている。** 34 件、13 プロファイル。そのうち **9 件は
`disposition: "confirmed"` でレビューを通っている。**

原因は `actor_profile/scripts/ingest_observables.py`。
資料本文から 16 進の連なりを拾い、**長さだけで種別を決めている。**

```python
HASH_RE = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f][ :.-]?){32,128}(?![0-9A-Fa-f])")  # 49 行目
...
def classify_hash(raw: str) -> tuple[str, str] | None:                                   # 318 行目
    compact = re.sub(r"[^0-9A-Fa-f]", "", raw)
    kind_by_length = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}
    kind = kind_by_length.get(len(compact))
    return (kind, compact) if kind else None
```

マルウェア解析の資料には、**逆アセンブル結果・PE ヘッダのダンプ・シェルコード・
スクリプトやファイル名の 16 進表現**が普通に載っている。これらがちょうど
32 / 40 / 64 / 128 桁で区切られると、ハッシュとして取り込まれる。

これは前の依頼（`threatactor-sha512-type.md`、SHA-512 の型付け）とは**別の問題**で、
独立に直せる。型を直しても、これらは「SHA-512 でないもの」が `ioc.sha512` になるだけ。

---

## 実際に何が入っているか

16 進を復号すると正体が分かる。

| 取り込まれた値 | 復号すると | 正体 |
| --- | --- | --- |
| `2072756e20696e20444f53206d6f6465` | `" run in DOS mode"` | **PE の DOS スタブ** |
| `726f6772616d2063616e6e6f74206265` | `"rogram cannot be"` | 同上（`This program cannot be run…`） |
| `203d204765742d4368696c644974656d` | `" = Get-ChildItem"` | **PowerShell の断片** |
| `202d5061746820244c73557656704e48` | `" -Path $LsUvVpNH"` | 同上 |
| `6c43667077202d52656375727365202a` | `"lCfpw -Recurse *"` | 同上 |
| `2e6c6e6b207c2077686572652d6f626a` | `".lnk \| where-obj"` | 同上 |
| `3935312e3534205361666172692f3533372e3336` | `"951.54 Safari/537.36"` | **User-Agent の断片** |
| `6e6f76656d6265725f7363686564756c` | `"november_schedul"` | ファイル名の断片 |
| `e280ade280aee280aee280ae6664702e` | `U+202D` `U+202E`×3 + `"fdp."` | **RLO によるファイル名偽装**（`fdp.` は `.pdf` の逆順） |
| `6a04680020000068000040006a00ffd5` | — | **シェルコード**（`push 4; push 0x2000; push 0x400000; push 0; call ebp`） |
| `0228030000067d12…`（128 桁） | — | **.NET IL**（`fe06`=ldftn、`735b00000a`=newobj、`7d13000004`=stfld） |
| `c744243c256c6f63…`（128 桁） | — | **x86 機械語**（`c74424XX`=`mov dword [esp+XX], imm32` の繰り返し） |
| `11200000000000000000000000000000` | — | ゼロ埋め（16 進の 88% が `0`） |
| `0412da510412da510412da511f8f4451` | — | `0412da51` が 3 回繰り返し |

`.lnk | where-obj` や `-Recurse` が「MD5 ハッシュ」として索引に載っているので、
**ポータルの横串にも出る**（実害は今のところ「意味のない値が 1 件出る」程度）。

---

## やること

`classify_hash()` に**却下条件**を足す。長さの判定は今のままでよい。

### 判定に使う条件（本物のハッシュでは起きえないものだけを選ぶ）

| 条件 | 本物で起きない理由 | 該当 |
| --- | --- | --- |
| **ゼロバイトが 20% 以上** | 1 バイトが `0x00` になる確率は 1/256。16 バイト中 4 個以上は 100 万分の 1 以下 | 21 件 |
| **同じバイトが 4 連以上** | 同上。`01010101` `42424242` はダンプのパディング由来 | 1 件 |
| **3 バイトの並びが 3 回以上** | 3 バイトの空間は 2^24。64 バイトでも同じ並びが 3 回出る確率は無視できる | 3 件 |
| **可読 ASCII が 10 バイト以上続く** | 復号して `[A-Za-z0-9 _./$-]` が 10 バイト連続するのは、文字列を 16 進化したものだけ | 9 件 |

```python
NON_HASH_WORD_RE = re.compile(rb"[A-Za-z0-9 _./$\\-]{10,}")


def looks_like_hash(compact: str) -> bool:
    """本物のファイルハッシュらしいか。

    マルウェア解析の資料には逆アセンブル結果・PE ヘッダ・シェルコード・スクリプトの
    16 進表現が載る。これらがちょうど 32/40/64/128 桁だとハッシュに見えてしまうため、
    「ランダムな 16 バイト以上では起きえない特徴」で弾く。
    偽陰性(本物を弾く)を出さないよう、閾値は確率的に十分余裕のあるところに置く。
    """
    raw = bytes.fromhex(compact)

    # ゼロバイトが多い: 1 バイトが 0x00 になる確率は 1/256
    if raw.count(0) / len(raw) >= 0.20:
        return False

    # 同じバイトの連続: ダンプのパディングや繰り返しパターン
    run = longest = 1
    for prev, cur in zip(raw, raw[1:]):
        run = run + 1 if cur == prev else 1
        longest = max(longest, run)
    if longest >= 4:
        return False

    # 同じ 3 バイトの並びが繰り返す: 機械語の定型命令やファイル名偽装の制御文字
    trigrams = collections.Counter(bytes(raw[i : i + 3]) for i in range(len(raw) - 2))
    if trigrams.most_common(1)[0][1] >= 3:
        return False

    # 復号すると読める: 文字列を 16 進化したもの
    if NON_HASH_WORD_RE.search(raw):
        return False

    return True


def classify_hash(raw: str) -> tuple[str, str] | None:
    compact = re.sub(r"[^0-9A-Fa-f]", "", raw).lower()
    kind_by_length = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}
    kind = kind_by_length.get(len(compact))
    if not kind or not looks_like_hash(compact):
        return None
    return (kind, compact)
```

**3 バイトの並びの条件は落とさないこと。** これが無いと、上の表の
`c744243c…`（x86 機械語）と `e280ad…`（RLO 偽装）と `0412da51…` の 3 件が
すべて通り抜ける。x86 の `c74424XX` は 0 でも繰り返しでもなく、
`pdat` `og_g` のような可読断片も 4 バイトずつで途切れるため、他の条件に掛からない。

### 使ってはいけない判定

**「16 進の偏り」と「印字可能バイトの割合」を単独で使わないこと。** 試したが、
**md5 の長さ（16 バイト）では本物が誤爆する。**

- `印字可能バイト >= 75%` で 17 件引っかかるが、**うち 7 件は本物のハッシュ**
  （`+X.AYày)o"b3~Í|` のように偶然読める文字が多かっただけ）。
  16 バイトなら二項分布で 0.4% 程度は起きるので、1883 件の md5 では 7 件前後出て当然
- `16 進の最多文字が 34% 以上` も同様。長さ 32 の本物の分布は中央値 15.6%・99% 点 25% で
  裾が長い。長さ 64 なら最大 25% に収まるので使えるが、**長さごとに閾値を変えねばならず脆い**

上の 4 条件は 4258 件のハッシュ全体で**引っかかったのが 34 件、すべて誤検知**
（本物の取りこぼしゼロ）だった。「本物では確率的に起きえない」条件だけを選んだ結果。

### 既存データの掃除

`ingest_observables.py` は `iocs.json` を**毎回まるごと書き直す**（847 行目の
`write_json_atomic(iocs_output, dataset)`）。**移行スクリプトは要らない。**
上を直してから、影響のある 13 プロファイルを再取り込みすれば消える。

```
apt28  apt29  konni  oceanlotus  gamaredon  lazarus  sandworm
apt37  fin7  gold-southfield  intellexa  sangria-tempest  sidewinder
```

`disposition` の内訳は `candidate` 25 件・`confirmed` 9 件。
**`confirmed` になっているものも消してよい**（値そのものが指標でないため、
レビュー結果を尊重する理由がない）。ただし PR 本文には
「レビュー済みだったものを 9 件落とした」と明記すること。

---

## 確認すること

この検査スクリプトは実際に走らせて数字を確認したもの。**修正前は 34 件を報告する。**

```
$ python3 - <<'PY'
import collections, json, pathlib, re

NON_HASH_WORD_RE = re.compile(rb"[A-Za-z0-9 _./$\\-]{10,}")

def reject_reason(compact: str) -> str | None:
    raw = bytes.fromhex(compact)
    if raw.count(0) / len(raw) >= 0.20:
        return f"ゼロバイト {round(raw.count(0) / len(raw) * 100)}%"
    run = longest = 1
    for prev, cur in zip(raw, raw[1:]):
        run = run + 1 if cur == prev else 1
        longest = max(longest, run)
    if longest >= 4:
        return f"同一バイト {longest} 連"
    grams = collections.Counter(bytes(raw[i : i + 3]) for i in range(len(raw) - 2))
    gram, n = grams.most_common(1)[0]
    if n >= 3:
        return f"3 バイトの並び {gram.hex()} が {n} 回"
    m = NON_HASH_WORD_RE.search(raw)
    if m:
        return f"可読 {m.group(0)!r}"
    return None

rej, total = [], 0
for p in sorted(pathlib.Path("profiles").glob("*/iocs.json")):
    for ind in json.load(p.open())["indicators"]:
        if ind["type"] not in ("md5", "sha1", "sha256", "sha512"):
            continue
        h = (ind.get("normalized_value") or ind.get("value") or "").lower()
        if not re.fullmatch(r"[0-9a-f]+", h):
            continue
        total += 1
        why = reject_reason(h)
        if why:
            rej.append((p.parent.name, ind["type"], ind["disposition"], h, why))

print(f"全 {total} 件 / 疑わしい {len(rej)} 件")
print("型:", dict(collections.Counter(x[1] for x in rej)))
print("disposition:", dict(collections.Counter(x[2] for x in rej)))
for x in rej:
    print("  ", x)
PY
```

修正前の出力（`main` の `44cffe1` で実測）。

```
全 4258 件 / 疑わしい 34 件
型: {'md5': 20, 'sha1': 12, 'sha512': 2}
disposition: {'candidate': 25, 'confirmed': 9}
```

- 修正後は **`疑わしい 0 件`** になること
- **`全` が 4258 → 4224 件**（34 件だけ減る）。それ以上減っていたら本物を弾いている。
  減った分を PR 本文に列挙すること
- 索引を作り直すと `ui/api/v1/search.json` のハッシュ合計が **4243 → 4211 件**
  （索引側は値で重複排除するので源データの 34 件と一致しない。索引側の該当は 32 件）。
  型ごとの見込みは `ioc.md5` 1870 / `ioc.sha1` 1166 / `ioc.sha256` 1175
  （`ioc.sha512` の型付けを入れていない場合の値。入れたあとなら
  `ioc.sha256` 1159 / `ioc.sha512` 16）
- 既存のテストが通ること。`classify_hash` の単体テストに
  **本物 4 種（32/40/64/128 桁）が通ることと、上の表の値が弾かれること**を足す。
  とくに `c744243c…` と `e280ad…` を入れておく（3 バイトの条件を将来外されないため）

---

## ブランチと PR

- ブランチ: `claude/hash-false-positive`
- PR タイトル: `ハッシュでない 16 進列を IOC として取り込まないようにする`
- PR 本文に、落とした 34 件の一覧（値・プロファイル・復号結果・却下理由・`disposition`）と、
  上の確認コマンドの出力を貼ること

## この判定の限界（PR 本文に書いておくこと）

**ランダムに見える 16 進列は弾けない。** 暗号鍵の一部や、圧縮済みデータの断片が
ちょうど 64 桁で切り出された場合は、本物のハッシュと統計的に区別できない。
この 34 件は「復号すると意味が見える」ものだけで、**取りこぼしがゼロという主張ではない。**
精度（弾いたものが全部誤検知だった）は確認したが、再現率は測れていない。

## やらないこと

- `HASH_RE`（49 行目）の変更 — 拾う範囲は今のままでよい。**判定側で弾く**
- `ioc.sha512` の型付け — 別依頼（`threatactor-sha512-type.md`）。
  どちらを先に入れてもよい
- 資料そのもの（`sources/`）の変更
- ポータル側（research_bench）の変更
