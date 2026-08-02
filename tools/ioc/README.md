# IOC の収集・分析スクリプト

4 つの索引（アクター情報 / 脆弱性 / ニュース / マルウェア解析）から IOC を集め、
実体（アクター・マルウェア・キャンペーン・ケース）の**重なり**を出す。

すべて Node の標準機能だけで動く。依存も、ビルドも、AI も要らない。

```
node tools/ioc/collect.mjs      # 索引 → iocs / links / entities
node tools/ioc/fetch-asn.mjs    # 経路表の写しを取る（ここだけ外に出る。キーは不要）
node tools/ioc/enrich-asn.mjs   # IP に AS を付ける（写しだけを見る）
node tools/ioc/stats.mjs        # → overlaps / graph / subnets / asn-cotenancy / stats
node tools/ioc/validate.mjs     # 出来たものを検査する
node tools/ioc/selftest.mjs     # validate 自体を検査する
```

## 設計上の約束

**同じ入力からは同じバイト列が出る。** キーは常に名前順、行は規定の鍵で整列、
中身に時刻を混ぜない。だから `git diff` に出るのは実際の変化だけになる。
実行時刻と取得元のハッシュは `meta.json` にだけ置く（唯一、毎回変わるファイル）。

**外部に出る工程を 1 つに絞る。** 外へ行くのは `fetch-asn.mjs`（と索引の取得）だけで、
どちらも**写しを残す**。以降の工程は写ししか見ないので、同じ写しからは何度でも同じ結果が
出る。API キーは 1 つも要らない。

**除きたいものは捨てずに印を付ける。** bogon や公開 DNS は `bogon` / `noise` の印を
付けて残し、統計側が既定で除く。捨ててしまうと「なぜ消えたか」が後から分からず、
元データ側の誤りにも気づけない。

## collect.mjs

```
node tools/ioc/collect.mjs [--out data/ioc/latest]
                           [--from <写しの場所>] [--cache <保存先>]
                           [--week 2026-W31] [--now <ISO 日時>]
```

`apps.json` に登録された索引から `meta.json` → `search.json` を辿って IOC を集める。
`--cache` を付けると取った索引をそのまま保存し、次回 `--from` で**ネットワーク無しに
同じ結果を再現**できる。索引が 1 つ落ちても他は集め、落ちたことは `meta.json` に残す
（終了コードは 1）。実測で 7〜8 秒。

| 出力 | 中身 |
| --- | --- |
| `iocs.jsonl` | 1 行 1 IOC。値・型・出典・日付・/24・登録可能ドメイン・除外の印 |
| `links.jsonl` | IOC ↔ 実体の辺。`actor` / `malware` / `campaign` / `case` / `article` / `cve` / `ioc` |
| `entities.jsonl` | 実体の正規形。アクターは別名を畳んだ代表名と別名一覧 |
| `meta.json` | 実行時刻・取得元 URL・索引のハッシュ・件数 |

### 名前の扱いがこの工程の肝

索引の名前欄は人が書いた記事から起こされているので、そのまま使えない。

- **別名を代表名に寄せる。** 寄せないと「アクター間の重なり」の上位が同一アクターの
  別名同士で埋まる。アクター情報が公開している `aliases` を使う。
- **1 つの欄に複数入っているものを分ける。** `"Qilin, TAG-195 (Golden Chickens"` のように
  **閉じ括弧が落ちている**ものが実在する。対になっている括弧は名前の一部として残し、
  片方だけのものは区切りで切れた跡として落とす。
- **但し書きを名前として数えない。** `"medium-to-high confidence"` や `"suspected"` が
  アクター欄に入っていることがある。放置すると、そういう名前のアクターが生まれる。

## fetch-asn.mjs / enrich-asn.mjs

IP の IOC に AS 番号・事業者名・国、そして**その AS の大きさ**を付ける。

```
BGPTOOLS_CONTACT="you@example.com" node tools/ioc/fetch-asn.mjs
                                   [--cache data/ioc/.cache/bgptools]
                                   [--max-age 7200] [--force]

node tools/ioc/enrich-asn.mjs [--in data/ioc/latest] [--cache <同じ場所>]
```

取得元は [bgp.tools](https://bgp.tools/kb/api)。全経路（147 万件・72 MB）と
AS 名（12 万件）を写しとして落とす。IP ごとに問い合わせると 3,000 回を超える外部呼び出しに
なり、再現もできない。写しを 1 つ置けば、同じ写しからは何度でも同じ結果が出る。

取得元の取り決めに合わせてある。**連絡先入りの User-Agent が要る**ので
`BGPTOOLS_CONTACT` で渡す（リポジトリに書き込まないため環境変数にしている）。
経路表は 2 時間、AS 名は 24 時間ほど写しを使う。写しが新しければ取りに行かない。

| 出力 | 中身 |
| --- | --- |
| `ip-asn.jsonl` | IOC → AS 番号・一致した prefix・観測数。経路に無いものは `routed:false` |
| `asns.jsonl` | 出てきた AS。名前・国・区分と、**保有 prefix 数・アドレス数** |
| `asn-meta.json` | 使った写しのハッシュと件数 |

**大きさを一緒に出すのが肝。** 「同じ AS に居る」は、それだけでは何も言えない。
400 万アドレスを持つ事業者に 2 つの実体が居るのは偶然だが、1,024 アドレスしか
持たない AS なら同じ相手から借りているとみてよい。実測 7 秒（経路表の読み込み込み）。

## stats.mjs

```
node tools/ioc/stats.mjs [--in data/ioc/latest] [--out <同じ場所>]
                         [--since <前回のスナップショット>] [--include-noise]
                         [--ubiquity-cap 8] [--min-shared 1]
                         [--asn-max-addresses 4096] [--asn-max-actors 8]
```

重なりの根拠を 4 つ出す。どれも「共有している IOC の数」で測る。

| 根拠 | 意味 |
| --- | --- |
| `ioc` | 同じ IOC を指している（最も強い） |
| `subnet` | 同じ /24 に IP がある。**API を 1 回も呼ばずにインフラの共有が見える** |
| `registrable` | 同じ登録可能ドメイン（eTLD+1）を使っている |
| `asn` | 同じ AS に IP がある。**小さい AS に限る**（`enrich-asn.mjs` があるときだけ） |

総当たりではなく IOC 側から引くので実体数の 2 乗にならない。多数の実体に付く
ありふれた IOC は根拠として弱く組も大量に生むので、`--ubiquity-cap` を超えたら数えない。
`--since` に前回の場所を渡すと `new.jsonl`（今回増えた IOC）も出す。実測 0.5 秒。

出力は `stats.json`（要約）、`overlaps.jsonl`（組ごとの根拠）、`graph.json`（そのまま
描ける形）、`subnets.jsonl` と `asn-cotenancy.jsonl`（同居の全件）。

### AS を根拠に使う条件は 2 つある

大きさだけで決めると足りない。実測すると 5 万アドレス規模の VPS 事業者
（RouterHosting・Private Layer など）に 7〜11 のアクターが同居していた。これは
「みんなが借りる所」であって、結び付きの根拠にはならない。そこで

- **大きさ** … `--asn-max-addresses`（既定 4,096 = /20 相当）以下、かつ
- **アクター数** … その AS で見えたアクターが `--asn-max-actors`（既定 8）以下

の両方を満たす AS だけを根拠にする。**除いたほうも捨てない。** 多くのアクターが
借りている事業者は `stats.json` の `asns.hosting_like` に残す。結び付きの根拠には
ならないが、それ自体が知りたいことになるため。

## validate.mjs

```
node tools/ioc/validate.mjs [--in data/ioc/latest] [--json <報告の書き出し先>]
                            [--strict] [--allow-partial] [--samples 5] [--quiet]
```

出力が機械で使える状態かを確かめる。`error` があれば終了コード 1。`warn` は既定では
通すが `--strict` で失敗にする。同じ壊れ方が何百行も並ぶと読めないので、規則ごとに
まとめて件数と代表例を出す。

見るもの:

1. **正準形** — 各行が `stableStringify` と 1 バイト違わないか（キー順・空白・並びの保証）
2. **並びと重複** — 規定の鍵で整列しているか、同じ鍵が 2 度出ないか
3. **欄** — 必須があるか、**知らない欄が増えていないか**（検査していない情報が載るのを防ぐ）
4. **正規化** — `key = type|joinKey(type,value)`、`value` が正規形、defang が残っていないか
5. **値の形** — `md5=32 / sha1=40 / sha256=64 / sha512=128` 桁、IPv4 の形と印、URL が解けるか
6. **参照** — 辺の指す IOC と実体が実在するか
7. **集計** — `entities.ioc_count` と `meta.counts` を辺から数え直して突き合わせる
8. **AS** — **prefix が本当にその値を含むか**、AS ごとの IOC 数、写しのハッシュの有無
9. **派生物** — `overlaps` / `graph` / `stats` / `new` / 同居の一覧を元データと突き合わせる

8 の prefix 包含は最長一致が効いたかを直接確かめるもので、`45.32.10.7/21` のように
網以外のビットが残った書き方も弾く。

`--allow-partial` は「索引の取得に失敗した一式」を error から warn に落とす。既定で
error にしているのは、**欠けた一式を揃ったものとして週次の系列に混ぜないため**。

ハッシュの桁数検査は実際に見つかった誤りへの対応で、SHA-512 を `ioc.sha256` として
載せている索引があった。型が違うと照合が静かに外れるので、検出できる形にしてある。

## selftest.mjs

```
node tools/ioc/selftest.mjs [--keep]
```

検査scriptは「通る」だけでは意味がない。通ってしまう壊れ方があるなら、検査していない
のと同じ。ここでは小さな正しい一式を作り、**既知の壊し方を 1 つずつ加えて狙った規則が
鳴ることを確かめる**（45 通り）。既存のデータもネットワークも要らない。

## 週次で回す

```sh
WEEK=$(date -u +%G-W%V)
node tools/ioc/collect.mjs    --out data/ioc/$WEEK --cache data/ioc/.cache
node tools/ioc/fetch-asn.mjs                                    # BGPTOOLS_CONTACT が要る
node tools/ioc/enrich-asn.mjs --in  data/ioc/$WEEK
node tools/ioc/stats.mjs      --in  data/ioc/$WEEK --since data/ioc/latest
node tools/ioc/validate.mjs   --in  data/ioc/$WEEK --strict || exit 1
rm -rf data/ioc/latest && cp -r data/ioc/$WEEK data/ioc/latest
```

`validate` が通ってから `latest` を差し替える。壊れた一式が次回の `--since` の基準に
なることを防ぐ。

### 何を残すか

`iocs.jsonl` と `links.jsonl` は合わせて 10 MB あり、毎週そのまま置くと 1 年で 500 MB を
超える。週ごとに残すのは**軽い派生物だけ**にして、大きい 2 つは `latest` の 1 世代だけ
持つのがよい（`meta.json` に索引のハッシュがあるので、同じ索引からいつでも作り直せる）。

| 残す | 大きさ | |
| --- | --- | --- |
| `stats.json` `overlaps.jsonl` `graph.json` `new.jsonl` `meta.json` `asn-meta.json` `subnets.jsonl` `asn-cotenancy.jsonl` `asns.jsonl` | 約 850 KB | 週ごとに残す |
| `iocs.jsonl` `links.jsonl` `entities.jsonl` `ip-asn.jsonl` | 約 10 MB | `latest` だけ |

`data/ioc/.cache/` は索引の写しなので追跡しない（`.gitignore` 済み）。

## いま出ているもの（19,011 IOC）

| | 件数 |
| --- | --- |
| ドメイン / IPv4 / URL | 6,249 / 3,166 / 2,768 |
| SHA-256 / MD5 / SHA-1 / SHA-512 | 2,644 / 2,278 / 1,416 / 16 |
| メール / エンドポイント / IPv6 | 263 / 148 / 63 |

重なりは actor 205 組・malware 144 組・campaign 1 組・case 276 組。
**別アクターが同居している /24 が 83 網。**

IP 3,229 件のうち 3,074 件が経路上にあり、809 の AS に散っている。AS で別アクターが
同居しているのは 180 件だが、相乗りを除くと 12 件に絞られる。上位はこうなる。

| AS | アドレス | | アクター |
| --- | --- | --- | --- |
| AS131279 | 1,024 | KP Ryugyong-dong (DPRK) | APT37 / Lazarus Group |
| AS60602 | 3,840 | MD Inovare-Prim SRL | APT28 / Sandworm Team |
| AS55639 | 3,584 | HK Asia Web Service Ltd | DPRK IT Worker Schemes / Lazarus Group |
| AS207560 | 512 | UA Zubritska Valeriia Nikolae | APT1 / APT28 / APT29 |
| AS214431 | 1,280 | IR Mizban Gostar Dade Alvand | APT28 / APT29 / OceanLotus |

既知の対応（APT37 と Lazarus はどちらも北朝鮮、APT28 と Sandworm はどちらも GRU）が
そのまま出ている。除いたほうでは OVH に 18 アクター、RouterHosting に 11 アクターが
同居していて、こちらは「みんなが借りる所」として `hosting_like` に残る。

## この先

キーの要るエンリッチ（VirusTotal・AbuseIPDB など）とピボットは、`enrich-asn.mjs` と
同じ形で足す。**外に出る工程は写しを残し、分析する工程は写ししか見ない。** キーは
環境変数から読み、結果は同じ形の JSONL として `data/ioc/<週>/` に置く。工程が
分かれているので、キーが無い環境でもここまでは通しで動く。
