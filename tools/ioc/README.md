# IOC の収集・分析スクリプト

4 つの索引（アクター情報 / 脆弱性 / ニュース / マルウェア解析）から IOC を集め、
実体（アクター・マルウェア・キャンペーン・ケース）の**重なり**を出す。

すべて Node の標準機能だけで動く。依存も、ビルドも、AI も要らない。

```
node tools/ioc/collect.mjs         # 索引 → iocs / links / entities
node tools/ioc/fetch-asn.mjs       # 経路表の写しを取る（外に出る。キーは不要）
node tools/ioc/enrich-asn.mjs      # IP に AS を付ける（写しだけを見る）
node tools/ioc/fetch-vt.mjs        # VirusTotal の写しを取る（外に出る。キーが要る）
node tools/ioc/fetch-abuseipdb.mjs # AbuseIPDB の写しを取る（外に出る。キーが要る）
node tools/ioc/enrich-intel.mjs    # 判定を付け、そこから実体と辺を生やす（写しだけを見る）
node tools/ioc/stats.mjs           # → overlaps / graph / subnets / asn-cotenancy / stats
node tools/ioc/validate.mjs        # 出来たものを検査する
node tools/ioc/selftest.mjs        # validate 自体を検査する
node tools/ioc/daily-report.mjs    # 昨日から何が変わったかを出す

sh tools/ioc/daily.sh --push       # 日次はこれ 1 本（上を通しでやる）
```

キーが要るのは `fetch-vt` と `fetch-abuseipdb` の 2 つだけ。**無くても他は全部通しで動く。**

## 設計上の約束

**同じ入力からは同じバイト列が出る。** キーは常に名前順、行は規定の鍵で整列、
中身に時刻を混ぜない。だから `git diff` に出るのは実際の変化だけになる。
実行時刻と取得元のハッシュは `meta.json` にだけ置く（唯一、毎回変わるファイル）。

**外部に出る工程を分ける。** 外へ行くのは `fetch-*.mjs`（と索引の取得）だけで、
どれも**写しを残す**。分析する工程は写ししか見ないので、同じ写しからは何度でも同じ結果が
出る。工程が分かれているので、キーが無い環境でも `stats` まで通しで動く。

**除きたいものは捨てずに印を付ける。** bogon や公開 DNS は `bogon` / `noise` の印を
付けて残し、統計側が既定で除く。捨ててしまうと「なぜ消えたか」が後から分からず、
元データ側の誤りにも気づけない。

**印を付ける根拠は 2 通り持つ。** 帯の一覧（`net.mjs` の `BOGON` / `NOISE`）は
手で足すので必ず漏れる。実測から決まる印（AbuseIPDB の通報の中身から見つける
`sample`、VT の人気順位から見つける `popular`）を併せて持つことで、一覧に無いものも
拾える。1.2.3.4 は両方で引っかかる。

**外したものにも使い道がある。** 正規サービスの印（`popular`）は根拠からは外すが、
名前を騙られている以上そこには**標的**が現れている。`targets.jsonl` に
「なりすまし」と「本物の下にぶら下がる悪用」を分けて出す。

**同じ事実を 2 度数えない。** 両実体が同じ IOC を指しているなら、その IOC の
証明書も署名者も一致して当たり前。証明書と署名者は「**別々の IOC を同じ鍵が
結んでいる**」ときだけ根拠に数える（橋の条件）。実測で、証明書根拠ののべ 159 枚
のうち 133 枚がこの鏡写しだった。

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
- **区切りで切れた断片を名前として数えない。** `N/A` が `A` と `N` に分かれ、しかも
  **索引側に `malware:a` / `malware:n` という実体として載っていた**。放置すると、
  その 2 つが 468 IOC を持つ最大のマルウェアになり、重なりの 1 位を占める。

- **区切りの見分け方。** 読点とセミコロン・全角スラッシュは常に区切り。半角スラッシュは
  **前後に空白があるときだけ**（`Luna Moth / Chatty Spider / UNC3753` は並び、
  `PNG/registry cache loader` は 1 つの名前）。括弧は全角と半角を同じものとして数える。

判定は [`lib/names.mjs`](lib/names.mjs) に集めてある。集める側と検査する側が別々に
持つと、片方だけ直したときに「検査は通るのに中身は壊れている」状態になる。

### ケースの先にあるファミリまで辿る

マルウェア解析の索引は**ファミリ名を IOC ではなくケースに付けている**。

```
ioc.domain|haochisadnka.cc ─[Winos control channel]→ case:ee0ef34a… ─[ファミリ]→ ValleyRAT
```

IOC の `refs` だけを見ていると 1 段先に届かず、**マルウェア解析側のファミリ名を
まるごと取りこぼす**（実測で 590 辺）。ケースを経由して 1 段だけ辿る。再帰はしない
（ケースを介して無関係な IOC 同士が繋がるため）。経由したことは `rel` に残す
（`case.ファミリ`）ので、直接の辺と見分けが付く。

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
| `ip-asn.jsonl` | IOC → AS 番号・一致した prefix・観測数。経路に無いものは `routed:false`。**索引の IOC と、エンリッチから生えた IOC の両方**に付く |
| `asns.jsonl` | 出てきた AS。名前・国・区分と、**保有 prefix 数・アドレス数** |
| `asn-meta.json` | 使った写しのハッシュと件数 |

**大きさを一緒に出すのが肝。** 「同じ AS に居る」は、それだけでは何も言えない。
400 万アドレスを持つ事業者に 2 つの実体が居るのは偶然だが、1,024 アドレスしか
持たない AS なら同じ相手から借りているとみてよい。実測 7 秒（経路表の読み込み込み）。

## fetch-vt.mjs / fetch-abuseipdb.mjs

VirusTotal と AbuseIPDB の判定を写しに取る。**外に出るのはここだけ。**

```
VT_API_KEYS="k1,k2,k3" node tools/ioc/fetch-vt.mjs
                       [--in data/ioc/latest] [--cache data/ioc/.cache/vt]
                       [--limit 1500] [--stage 1] [--plan]
                       [--rpm 4] [--daily 500] [--hourly 240] [--max-age 2592000] [--full]

ABUSEIPDB_API_KEY="k"  node tools/ioc/fetch-abuseipdb.mjs [--limit 1000] [--plan]
```

**1 IOC につき object を 1 回だけ**引く。関係（`/resolutions` など）はここでは引かない
（`fetch-vt-rel.mjs` が対象を絞って別に引く）。
1 IOC あたり呼び出しが 1〜3 回増え、18,589 件では成立しないため。object の応答だけでも
DNS レコード・証明書・JARM・脅威ラベルは入っている。

### 順番が結果を決める

VT の無料枠は 1 鍵 500 件/日。鍵 3 本でも全件に 13 日かかる。だから
**どれから引くか**を決める（[計画 §4](../../docs/ioc-enrich-plan.md)）。`--plan` で引かずに内訳だけ出せる。

| 段階 | 対象 | 実測 |
| --- | --- | --- |
| new | 前回に無かった IOC。常に最優先 | — |
| 1 | **複数の実体に繋がる IOC**。重なりの根拠そのもの | 4,787 |
| 2 | 注目 IP（小さい AS / 別アクター同居の /24） | 294 |
| 3 | ハッシュ（実体 1 つ） | 4,482 |
| 4 | ドメイン（実体 1 つ） | 4,437 |
| 5 | 残りの IP と URL。**IP を先に引く** | 4,094 |
| 6 | 実体に繋がっていない IOC | 490 |

**段階 1 が終われば主目的はほぼ達成する。** 途中で止めても、止まった所までは
意味のある順で埋まっている。

**段階の中は引き先ごとの収穫順**（ドメイン → ファイル → IP → URL）。同じ段階でも
1 回引いて得られる根拠の量が違う。実測で、URL の応答は証明書も JARM も DNS も
返さず（取得済み 749 件で全部 0）、いま根拠に使っている欄を 1 つも持たなかった。
同じ枠を IP に使えば 1,271 件で証明書 604・JARM 708・AS 1,233 が付く。

### 枠は取得元に聞く

始める前に `GET /users/{key}` で「今日もう何件使ったか」を鍵ごとに聞く（この呼び出しは
枠を消費しない）。手元で数えるより確かで、別の用途で使った分も反映される。
1 分あたりの間隔は鍵ごとに持つ。まとめて数えると、鍵 3 本でも 1 本ぶんしか出せない。
1 時間の上限は**待てば戻るもの**なので日の上限と区別する。区別しないと 1 時間ぶんを
使った所で走行が終わる。使い切った鍵は自然に外れ、残った鍵で続く。

### 写しは「射影」であって応答そのものではない

VT のファイル応答は 1 件 50〜200 KB あり、その大半をベンダーごとの判定文字列
（`last_analysis_results`）が占める。18,589 件では 1 GB を超え、写しとして持ち歩ける
大きさでなくなる。そこで**計画が使うと決めた欄だけ**を残し、**版を写しに書く**
（`projection`）。使う欄を増やしたら版を上げれば、版の古い写しだけが取り直される。
全欄が要るときは `--full`。

**版は引き先ごとに持つ。** ファイルの欄を増やしただけでドメインも IP も取り直すのは
無駄なので、`{files, domains, ip_addresses, urls}` で別々に数える。実測で、ファジー
ハッシュを足したときに取り直すのは 2,058 件（ファイルのみ）で済んだ。まとめて 1 つに
していたら 5,433 件だった。

`404` は失敗ではなく**結果**として残す（`known: false`）。索引の独自性の指標になる。
リクエストヘッダは保存しない（写しにキーを混ぜないため）。

## enrich-intel.mjs

```
node tools/ioc/enrich-intel.mjs [--in data/ioc/latest] [--out <同じ場所>]
                                [--vt-cache <写し>] [--abuse-cache <写し>]
                                [--san-cap 100] [--name-cap 8]
```

写しから判定を起こし、そこから**知らなかった実体と辺を生やす**。外部呼び出しなし。

| 出力 | 中身 |
| --- | --- |
| `vt.jsonl` | IOC ごとの判定。VT が知らないものは `known:false` |
| `abuseipdb.jsonl` | IP ごとの通報状況。**通報数ではなくスコアで判断する** |
| `derived-iocs.jsonl` | 写しから生えた IOC（解決先・過去の解決先・通信先の IP）。`origin` で出どころが分かる |
| `derived-links.jsonl` | 生えた辺（`resolves_to` / `resolved_at` / `contacted` / ファミリ）。過去の解決先には `at`（解決日）が付く |
| `derived-verdicts.jsonl` | **生えた IOC に付いた判定。** 索引の `vt.jsonl` / `abuseipdb.jsonl` とは分ける（混ぜるとカバレッジの分子だけが増える） |
| `relation-ips.jsonl` | 関係の守りを通った IP の一覧。**絞ったつもりで何が残ったか**を確かめる出口で、`--relation-ips` が引く相手でもある |
| `derived-entities.jsonl` | 生えた実体（索引に無かった VT のファミリ名） |
| `derived-aliases.jsonl` | ファミリの別名候補 |
| `derived-certs.jsonl` | 証明書ごとの IOC のまとまり |
| `enrich-meta.json` | **カバレッジ**・写しのハッシュ・取得の期間 |

**元のファイルは汚さない。** 生えたものは `derived-*.jsonl` に分ける。索引が主張した
IOC と、そこから導いた IOC を混ぜると「これはどこの主張か」が追えなくなる。
索引と重複したものは索引側を優先し、派生には入れない。

### 生やすものが 3 つある

**マルウェア名の正規化。** `suggested_threat_label`（`trojan.emotet/heur`）から
ファミリを取り出す。索引に同じ名前があれば**索引の表記に寄せる**。寄せないと
`emotet` と `Emotet` が別の実体として並び、正規化した意味が無くなる。
`trojan.generic` のような一般名は畳まない。無関係な検体が 1 つの塊になってしまう。

**ドメイン → IP の辺。** `last_dns_records` の A / AAAA から起こす。索引が持っていた
IOC ↔ IOC の辺は **315 本しかない**。ここが増えると、ドメインしか持たないアクターと
IP しか持たないアクターが繋がる。

生えた IP には `enrich-asn.mjs` で **AS を付け直す**（`enrich-intel` のあとに走らせる）。
付けないと「解決先が edge かどうか」を大きさで判断できない。

**証明書の共有。** `thumbprint_sha256` が一致するものをまとめる。最も強いインフラ共有の
証拠だが、**根拠に使えないものがある**ので印を付ける（捨てはしない）。

- `san` … SAN が `--san-cap`（既定 100）を超える。共用ホスティング
- `wildcard` … **どの IOC も証明書に名前が載っていない**。その host ではなく
  基盤に出された証明書
- `unanchored` … **名前が当たったドメインが 1 つも居ない**。IP だけの群では、
  運用者の証明書か基盤の既定かを見分けられない

2 つ目は実測で 3 度見つかった。

- `*.azurewebsites.net`（SAN 11 と 30）と `*.squarespace.com`（SAN 14・ワイルドカードと
  実名が混在）が、無関係なテナント同士を結んでいた
- `localhost` / `0.0.0.0` / `Fireware web CA` / `letsencrypt-nginx-proxy-companion` の
  自己署名。**同じ image や機器を使っている全員が同じものを出す**

**SAN の数でも「全部ワイルドカードか」でも見分けられない**ので、
**自分の名前が証明書に載っているか**で見る。ドメインなら SAN に literal で入っているか
（SAN が無ければ CN と一致するか）、IP なら実在しうる host 名を主張しているか。
個々の判定は `vt.jsonl` の `cert.wildcard` に付く。

3 つ目の `unanchored` は、それでも足りなかったぶん。`invalid2.invalid`（Cloudflare の
既定）・`*.hstgr.io`（Hostinger の共用）・`cloudflare-dns.com`・
`n.sni-347-default.ssl.fastly.net` が、無関係なアクター同士を strength 9〜10 で
繋いでいた。どれも **IP がその基盤に載っているだけ**で、運用者のものではない。
名前が当たったドメインが 1 つでも群に居れば「その運用者のもの」と言えるので、
それを錨にする。

**錨が無い群も捨てない。** 運用者が名前の合わない証明書を使い回している場合もあり、
それは機械では見分けられない。`daily-report.mjs` が `to_check.cert_excluded` として
毎日そのまま人に渡す。

### AS は経路表と突き合わせる

VT が言う AS 番号と `enrich-asn.mjs` の結果を照合し、食い違ったら `asn_differs` の印を
付けて**両方残す**。経路表の時点差なので、どちらかが誤りとは言えない。食い違いの数は
`enrich-meta.json` の `asn_check` に出る。

## stats.mjs

```
node tools/ioc/stats.mjs [--in data/ioc/latest] [--out <同じ場所>]
                         [--since <前回のスナップショット>] [--include-noise]
                         [--ubiquity-cap 8] [--min-shared 1]
                         [--asn-max-addresses 4096] [--asn-max-actors 8]
                         [--jarm-cap 0.01] [--filename-cap 8]
                         [--hosting-ratio 0.7] [--hosting-min 3]
```

重なりの根拠を 15 通り出す。どれも「共有している IOC の数」で測る。
`enrich-intel.mjs` があるときだけ出るものが多い。

| 根拠 | 意味 | 点 |
| --- | --- | --- |
| `certificate` | 同じ証明書（thumbprint 一致）。**最も強いインフラ共有の証拠** | 9 |
| `ioc` | 同じ IOC を指している | 8 |
| `resolution` | 同じ IP に解決するドメインを持っている（**現在**の DNS） | 7 |
| `signer` | 同じコード署名者。窃取された証明書の共有は偶然では起きない | 7 |
| `vhash` | VT の構造ハッシュが一致。**提供元の判断が入らない** | 6 |
| `subnet` | 同じ /24 に IP がある。**API を 1 回も呼ばずに見える** | 5 |
| `asn` | 同じ AS に IP がある。**小さい AS に限る** | 5 |
| `resolved` | **過去に**同じ IP に解決していた（`/resolutions`、日付つき） | 5 |
| `imphash` | PE のインポート表が一致。パッカーで衝突するので中くらい | 4 |
| `contacted` | 検体が同じ IP と通信した（`/contacted_ips`） | 4 |
| `registered` | 同じ日に一斉登録された。**弱い**（他の根拠と重なって初めて効く） | 3 |
| `family` | VT が同じ脅威ラベルを付けている。**弱い** | 2 |
| `registrable` | 同じ登録可能ドメイン（eTLD+1）を使っている。弱い | 2 |
| `filename` | 珍しいファイル名の共有。**弱い**（2 つ以上揃って初めて数える） | 1 |
| `jarm` | 同じ TLS 指紋。弱い（単独では根拠にしない） | 1 |

### ファジーハッシュのほうが素直

`vhash` と `imphash` は**論理が明示的**で、提供元の判断が入らない。検知名のように
「広く付く札」になることが構造的に少ないので、検知名より上に置く。

- `vhash` … VT の構造ハッシュ。**完全一致**で使える。一致すれば作りが同じ
- `imphash` … PE のインポート表。完全一致だが、**パッカーでよく衝突する**ので一段下

どちらも「みんなが同じ値になる」ことはあるので、他と同じく**何実体にぶら下がっているか**で
上限を掛ける（`--vhash-cap` / `--imphash-cap`、既定 8）。インポートの無い PE の
imphash（空の MD5）のような退化した値は列挙で外す。

`ssdeep` と `tlsh` も写しに残しているが、こちらは**完全一致ではなく距離**を測る必要が
あるのでまだ根拠にしていない。依存を増やさずに比較を実装するのが次の一歩。

### VT の検知名を弱い根拠に置く理由

使っているのは VT が集約した `popular_threat_classification` だけで、
**提供元ごとの検知名（`last_analysis_results`）は写しにも落としていない**。
それでも「同じラベルが付く = 同じ物」ではない。実測で `mikey` が APT28（Sednit）と
Silver Fox（Atlas RAT）を繋いでいたが、変種は `dynamer` / `etset` / `pswdump` と
全部違い、検体も JS・DLL・OCX と種別が違った。**提供元が広く付ける札**だった。

だから `family` は弱い根拠に置き、他の根拠と重なったときだけ意味を持たせる。

**強さを数字にする。** 共有数と割合だけだと、根拠の種類による差が出ない。出てきた
根拠の点を合算して `strength` に持たせ、要約の並べ替えをこれにする。共有数を掛けないのは、
弱い根拠を数で押した組が強い根拠 1 つの組を追い越さないようにするため。
弱い根拠（`family` / `filename` / `registrable` / `jarm`）だけの組には `weak_only` の印を付ける。
**除くのではなく印を付ける**（`bogon` / `noise` と同じ扱い）。

**IOC 集合が完全に一致する組だけは `overlaps.jsonl` に出さない。** 共有率 100% は
構造上そうなるだけで、根拠にならないため。実測で上流の `"マルウェア": "A, N"` が
区切りで割れ、468 IOC を共有する 2 実体の間に shared 1190 / strength 40 の組が
最上位に立っていた。捨てはせず `identical-sets.jsonl` に回す。malware / actor では
**別名の候補**として読める（`CloudSorcerer ↔ DeedRAT` `Gshell ↔ TencShell` が並んだ）。
`case` は 1 つの記事から起こすので集合が一致しやすく、別名ではなく単に同じ括り。

`jarm` と `filename` と `family` は**ありふれた値を外す**。既定の nginx で一致する
JARM や `invoice.doc` を根拠にすると、無関係な実体が総当たりで繋がる。JARM は全体の
`--jarm-cap`（既定 1%）を超えたら、ファイル名は `--filename-cap` 件を超えたら外す。

ファイル名は**置き名と自動命名を先に落とす**。`payload.bin` `stage2.bin` `sample.exe`
のような置き名は解析者やサンドボックスが付けるもので、中身とは関係がない。実測で
`payload.bin` が APT28 と Silver Fox を繋いでいた。ハッシュそのものを名前にしている
ものも同じ（`6922b319….exe` は VT の自動命名）。残ったものも
**2 つ以上揃わないと数えない**（`--filename-min`、既定 2）。1 つだけの一致は偶然が多い。

`enrich-intel.mjs` 側では、**提供元の連番**も落とす。`boiq` `boir` `boiv` `boja` `bokf`
… のように**頭 2 文字と長さが同じ札が何本も並ぶ**のは連番であって、ファミリ名ではない。
実測で 13 本の `bo` + 4 文字が実体として生えていた。名前を列挙して弾くのは一般化しないので、
**並びの数で測る**（`--serial-min`、既定 3）。2 まで下げると `datper` `rokrat`
`muddywater` のような実在のファミリまで巻き込むので、そこが下限。

ファミリ名は **何実体にぶら下がっているか**でも測り、`--family-cap`（既定 8）を超えたら
外す。VT のラベルには `tedy` のように、手口や検出器の都合で付いた**ファミリではない
名前**が混じる。実測では `tedy` が 61 検体・12 実体、`dllhijack` が 10 実体に付いていて、
`APT28 ↔ APT41` のような組を生んでいた。kind をまたいで数えるのが要点で、kind ごとに
数えると 12 実体でも「アクターは 5 つだけ」として通ってしまう。

`enrich-intel.mjs` 側でも、畳む前に一般名を落とす。列挙（`trojan` `stealer` `astraea` など）に
加えて、**人が付けた名前に見えないもの**を落とす。`agent` + 1〜2 文字（Kaspersky の
Agent.a / Agent.b。AgentTesla のような実在のファミリは残る）、`generic` で始まるもの、
そして**母音を含まないもの**（`grhh` `kqil` `vsnw09g25` のような機械生成の札）。

### 解決先・過去の解決先・通信先は同じ守りを通す

`resolution` / `resolved` / `contacted` は形が同じ（IOC → IP）なので、守りも同じものを
一つの関数（`foldTargets`）で掛ける。**引いた関係をそのまま根拠にはしない。**

`resolution` は**誰かの解決先になっている IP だけ**を数える。自分の IP を無条件に
入れると `ioc`（同じ IOC を指している）の写しになってしまう。

さらに **大きい AS に居る解決先は外す**。実測すると Cloudflare（`104.21.x` /
`172.67.x` / `2606:4700::`）や Vercel の edge に 6〜16 の実体が集まっていて、
これを根拠にすると無関係なアクター同士が繋がった（`APT29 ↔ JINX-0164` が実際に出た）。
「同じ AS に居る」が大きさ抜きでは何も言えないのと同じで、**「同じ IP に解決する」も、
その IP が edge なら何も言えない**。境目は `asn` と同じ `--asn-max-addresses`。
これで解決先を根拠にする組は 156 → 22 に絞られた。

**経路に無い IP は外す**（経路表そのものが無い環境では判断できないので、そのときは通す）。
AS が引けないと大きさの守りが素通りするためで、実測ではこの穴から
`93.184.220.29` / `72.21.91.29`（Edgecast / Limelight の CDN）が抜け、
**APT37 ↔ Lazarus Group** という強い主張が通信先の根拠として立っていた。
CDN は使わなくなった網を返上するので、**経路に無いこと自体が「昔の CDN の跡」の印**
になっている。

**索引に無い IP は、VT の検知が 1 以上のものだけ使う。** 索引の IOC には
「これは C2 だ」という人の主張が付いているので検知 0 でも根拠にするが、
関係から生えた IP にはその主張が無い。実測で守りを通った 160 件のうち
**115 件（72%）が検知 0** で、`192.35.177.64`（IdenTrust の証明書失効確認サーバ）が
そこに居た。判定そのものが無い IP は落とさない（未取得は陰性ではなく未知）。

**両実体が別々の IOC から届いていること**（橋の条件）も見る。「両方がこの IP に
解決する」と言っても、その IP を出したドメインが 1 本しか無ければ、それは
「両方がそのドメインを持つ」の言い換えでしかない。実測で、過去の解決先はこの条件だけで
**根拠が全部消えた**（守りを通った 33 IP がすべて 1 ドメイン経由だった）。

**bogon と noise の解決先も外す。** `127.0.0.1` に解決するドメイン同士は
「同じ所に居る」のではなく、**どちらもシンクホールされている**。実測で
`APT28 ↔ STAC4749` と `APT37 ↔ STAC4749` を繋いでいた。生えた IP にも
`bogon` / `noise` の印は付いているので、索引の IOC と同じ扱いにする。

総当たりではなく IOC 側から引くので実体数の 2 乗にならない。多数の実体に付く
ありふれた IOC は根拠として弱く組も大量に生むので、`--ubiquity-cap` を超えたら数えない。
`--since` に前回の場所を渡すと `new.jsonl`（今回増えた IOC）も出す。実測 0.5 秒。

### 根拠は値まで残す

`overlaps.jsonl` の各行に `evidence` を持たせ、**どの証明書・どの IP・どの vhash で
繋がったか**を値のまま残す。「証明書で繋がっている」と言われても、どの証明書かが
分からなければ検算できない。`--evidence-cap`（既定 5）で 1 種類あたりの件数を切るが、
切っても総数は `shared` に残る。

```json
"evidence": {
  "certificate": ["015f8941a37ebc14…", "5105aefc79e5b960…"],
  "ioc": ["ioc.domain|fusu.us.ci", "ioc.domain|110gongan.com"],
  "subnet": ["108.187.7.0/24"], "asn": ["AS215428"], "family": ["spynote"]
}
```

出力は `stats.json`（要約）、`overlaps.jsonl`（組ごとの根拠）、`graph.json`（そのまま
描ける形）、`subnets.jsonl` と `asn-cotenancy.jsonl`（同居の全件）。
`overlaps.jsonl` の行の並びは `kind, a, b` のまま（決定性のため）で、
強さで並べ替えるのは要約側。

### カバレッジを必ず先頭に出す

`stats.json` の先頭は `coverage`。1 キーでは全件が埋まるまで日数がかかり、
その途中の統計は**一部しか見ていない**。

```json
"coverage": {
  "virustotal": { "target": 18589, "done": 1428, "known": 1301, "unknown": 127, "ratio": 0.077,
                  "by_stage": { "1": { "done": 1428, "target": 4787 } } },
  "abuseipdb":  { "target": 3222, "done": 996, "ratio": 0.309 },
  "oldest_fetch": "2026-08-02", "newest_fetch": "2026-08-02"
}
```

「検知されたのは 12%」と「調べた範囲の 12%」は別物で、後者を前者として読むと必ず
間違える。**未エンリッチは陰性ではなく未知**として数える。分母の数え方は
`fetch-*` と `enrich-intel` と同じ関数（`lib/enrich.mjs` の `coverageOf`）を使う。
別々に数えると分母が食い違い、どちらが正しいのか誰にも分からなくなる。

### 時間軸と判定の分布

VT の `first_submission_date` は索引が持っていない「世に出た日」。ここから 3 つ出す。

- **実体ごとの活動期間** — その実体に繋がる IOC が世に出た日の最小と最大
- **キャンペーン間の時間的重なり** — IOC を共有していなくても「同じ時期に動いていた」
- **索引の遅れ** — 索引の観測日と `first_submission_date` の差の分布

判定そのものからは、アクターごとの検知数の中央値、VT が知らない IOC の数、そして
**索引が「C2」と言っているのに検知 0** の件数を出す。どれも索引側の誤りか、
まだ知られていないかのどちらかで、どちらでも見る価値がある。

### 相乗り判定に 3 つ目の観点が入る

`asn-cotenancy.jsonl` に `hosting_ratio` が付く。その AS の IP のうち AbuseIPDB が
`Data Center / Web Hosting / Transit` と言う割合で、`--hosting-ratio`（既定 0.7）を
超えたら相乗りとみなす。ただし判定の付いた IP が `--hosting-min`（既定 3）未満の AS では
割合が当てにならないので使わない。**カバレッジが低い間に効きすぎないための歯止め。**

それでもこの観点は**効きすぎることがある**。攻撃側の基盤はほとんどが事業者の網なので、
小さい専用 AS までまとめて外れる。実測では、根拠に使える小さい AS が 12 件から 8 件に減り、
外れた中に **AS207560（512 アドレス・APT1 / APT28 / APT29）**が入っていた。

だから**外したほうを見えるようにする**。`stats.json` の `asns.hosting_excluded` に
「大きさとアクター数では根拠になるのに、事業者の網と言われて外れた AS」が全部残り、
実行時にも `!` 付きで出る。外れたこと自体に気づけないのが一番まずい。
きつすぎるときは `--hosting-ratio 1.1` で無効にするか、`--hosting-min` を上げる。

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
10. **エンリッチ** — `vt` / `abuseipdb` / `derived-*` の指す先、スコアの範囲、
    `known:false` に判定が入っていないか、**`coverage` の分母と分子が実データと合うか**

8 の prefix 包含は最長一致が効いたかを直接確かめるもので、`45.32.10.7/21` のように
網以外のビットが残った書き方も弾く。

`--allow-partial` は「索引の取得に失敗した一式」を error から warn に落とす。既定で
error にしているのは、**欠けた一式を揃ったものとして週次の系列に混ぜないため**。

ハッシュの桁数検査は実際に見つかった誤りへの対応で、SHA-512 を `ioc.sha256` として
載せている索引があった。型が違うと照合が静かに外れるので、検出できる形にしてある。

10 のカバレッジ検査は、**分母をもう一度データから数え直して突き合わせる**もの。
分母がずれていると「調べた範囲の 12%」を「検知されたのは 12%」として読むことになる。
`known:false` に判定が入っていないかは `routed:false` と同じ扱いで、
「調べたが無かった」を「調べていない」と混ぜないための検査。

## selftest.mjs

```
node tools/ioc/selftest.mjs [--keep]
```

検査scriptは「通る」だけでは意味がない。通ってしまう壊れ方があるなら、検査していない
のと同じ。ここでは小さな正しい一式を作り、**既知の壊し方を 1 つずつ加えて狙った規則が
鳴ることを確かめる**（68 通り）。既存のデータもネットワークも要らない。

一式のうち `entities` `meta` `coverage` と、重なり・同居・グラフは**手で書かない**。
実体は辺から数え直し、カバレッジは本番と同じ `coverageOf` で起こし、重なりは
`stats.mjs` を実際に走らせて作る。手で書くと、数え方がずれる壊れ方を検査できなくなる。

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

## 日次でエンリッチする

VT の無料枠は 1 鍵 500 件/日。索引の取り込みは週次のままで、**判定を足すのは日次**にする。

```sh
VT_API_KEYS="k1,k2,k3" ABUSEIPDB_API_KEY="k" sh tools/ioc/daily.sh --push
```

**判断が要らないところは全部このscriptでやる。**

| | やること |
| --- | --- |
| 0 | 索引を取り直す（`--collect` のときだけ。既定は週次なので毎日はやらない） |
| 1 | 経路表の写しを更新する（`BGPTOOLS_CONTACT` があるときだけ） |
| 2 | VT と AbuseIPDB を、その日の枠を使い切るまで引く（鍵も枠も別なので並行） |
| 3 | 写しから作り直す（`enrich-intel` → `stats`） |
| 4 | 検査する。**通らなければここで止まる** |
| 5 | 昨日から何が変わったかを出し、`data/ioc/reports/<日付>.json` に残す |
| 6 | コミットして push する（`--commit` / `--push` のときだけ） |

引く順は段階分けに従うので、**何日目で止まっていても意味のある所まで進んでいる**。
写しは IOC ごとに 1 ファイルなので、途中で落ちても次回がそのまま続きから引く。
片方の取得が落ちても、もう片方の写しは残る。

進み具合は `stats.json` の `coverage` を見る。全部が埋まるまでの目安は、
鍵 3 本（1,500 件/日）で **13 日**。段階 1（重なりの根拠そのもの）だけなら 4 日。

### 人がやるのは 5 の結果を読むところから

取得・突き合わせ・検査・差分の抽出はscriptで終わっている。残るのは
**機械では決められないもの**だけで、`daily-report.mjs` がそれを選んで出す。

```
node tools/ioc/daily-report.mjs [--in data/ioc/latest] [--prev <前回の一式>]
                                [--json <書き出し先>] [--top 15]
```

| 出すもの | 何のため |
| --- | --- |
| カバレッジが今日どれだけ進んだか | 分母を見ずに割合を読まないため |
| 新しく出た重なり | **強い根拠のものだけ**。弱い根拠だけの組は数だけ |
| 根拠が増えた重なり | 前からある組で `strength` が上がったもの |
| 新しく生えた実体・別名・共有証明書・解決先 | ピボットの入り口 |
| 索引が「C2」と言うのに検知 0 | 索引の誤りか、まだ知られていないか。**人が決める** |
| VT が知らない IOC | 索引の独自性 |
| 経路表と AS が食い違う IP | 時点差なので、どちらが誤りとも言えない |
| 事業者の網で外した AS | 効きすぎていないかを毎日見る |

差分の基準は **前回コミットした一式**（`git show HEAD:...` で取り出す）。写しと違って
git には残っているので、環境が変わっても昨日と比べられる。だから**結果は毎日コミットする**。

レポートは画面に出すだけでなく **`data/ioc/reports/<日付>.json` に残す**。
出すだけだと「何日目に何が出たか」が後から追えない。1 日 1 ファイルなので、
**この場所だけを追えば経過が読める**。1 件あたり 10〜20 KB。

### 写しが消えても枠は使い直さない

`data/ioc/.cache/` は追跡していないので、別の環境で動かすと最初は空になる。
そのまま引き直すと、使った枠がそのまま無駄になる。そこで **`vt.jsonl` と
`abuseipdb.jsonl` を「もう引いた」の控えとして使う**。判定そのものは写しからしか
作らないので、分析の入り口は変わらない。だから**結果は毎日コミットする**。
取り直したいときは `--refresh`、古いものだけなら `--max-age`。

### 何を残すか

`iocs.jsonl` と `links.jsonl` は合わせて 10 MB あり、毎週そのまま置くと 1 年で 500 MB を
超える。週ごとに残すのは**軽い派生物だけ**にして、大きい 2 つは `latest` の 1 世代だけ
持つのがよい（`meta.json` に索引のハッシュがあるので、同じ索引からいつでも作り直せる）。

| 残す | 大きさ | |
| --- | --- | --- |
| `stats.json` `overlaps.jsonl` `graph.json` `new.jsonl` `meta.json` `asn-meta.json` `subnets.jsonl` `asn-cotenancy.jsonl` `asns.jsonl` `enrich-meta.json` `derived-*.jsonl` | 約 1 MB | 週ごとに残す |
| `iocs.jsonl` `links.jsonl` `entities.jsonl` `ip-asn.jsonl` `vt.jsonl` `abuseipdb.jsonl` | 約 10 MB | `latest` だけ |

`data/ioc/.cache/` は取得元の写しなので追跡しない（`.gitignore` 済み）。
VT の写しは 18,589 件ぶんで約 100 MB（射影後）。**キーは写しにも出力にも入らない。**

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

キーの要るエンリッチ（VirusTotal・AbuseIPDB）とピボットは
[`docs/ioc-enrich-plan.md`](../../docs/ioc-enrich-plan.md) に計画としてまとめてある。
`enrich-asn.mjs` と同じ形で足す。**外に出る工程は写しを残し、分析する工程は写ししか見ない。** キーは
環境変数から読み、結果は同じ形の JSONL として `data/ioc/<週>/` に置く。工程が
分かれているので、キーが無い環境でもここまでは通しで動く。
