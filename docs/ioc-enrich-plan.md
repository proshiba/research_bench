# IOC エンリッチとピボットの計画（VirusTotal / AbuseIPDB）

`tools/ioc/` が集めた 19,011 件の IOC に、VirusTotal と AbuseIPDB の判定を付け、
そこから**新しい実体と辺を起こす（ピボット）**。最終的な目的は
「マルウェア間・アクター間・キャンペーン間の重なり」の精度を上げること。

この文書は**何を取り、そこから何を起こし、どう数えるか**だけを決める。
キーは各 1 つを前提にする。

---

## 0. 前提となる今のデータ

| ファイル | 中身 |
| --- | --- |
| `iocs.jsonl` | 19,011 件。`key` は `<type>\|<正規化した値>` |
| `links.jsonl` | 32,187 辺。`{ioc, kind, name, source, rel}`。kind は actor / malware / campaign / case / article / cve / ioc |
| `entities.jsonl` | 999 件。アクター 230・マルウェア 306・キャンペーン 13・ケース 368 |
| `ip-asn.jsonl` `asns.jsonl` | IP → AS と、AS の大きさ |

**守ること。** 外に出る工程は応答の写しを残し、分析する工程は写ししか見ない
（`fetch-asn.mjs` / `enrich-asn.mjs` と同じ分け方）。エンリッチの応答は時刻で変わるので、
写しが無いと同じ結果を二度と作れない。出力は決定的にする（キーは名前順・行は整列・
中身に取得時刻を混ぜない。取得時刻とハッシュは meta にだけ置く）。

**元のファイルは汚さない。** 派生したものは `derived-*.jsonl` に分ける。
索引由来と外部由来を混ぜると、後から「これはどこの主張か」が追えなくなる。

---

## 1. 何を取るか

### 1.1 VirusTotal（対象 18,537 件）

1 IOC につき **object を 1 回**取るだけにする。関係（relationships）は別呼び出しで
枠を倍消費するので、既定では取らない（§4）。object の応答だけでも下の情報が入る。

**ファイル（ハッシュ 6,354 件）** — `GET /api/v3/files/{hash}`

| 取る | 使い道 |
| --- | --- |
| `last_analysis_stats` | 検知ベンダー数。危険度の段階（ポータルと同じ尺度） |
| `popular_threat_classification.suggested_threat_label` | **マルウェア名の正規化**。最重要 |
| `popular_threat_classification.popular_threat_name[]` | 別名の候補 |
| `first_submission_date` | **世に出た日**。索引が持っていない時間軸 |
| `meaningful_name` / `names[]` | ファイル名の共有 |
| `type_description` / `size` | 種別の絞り込み |
| `signature_info` | 署名者。正規署名の悪用を見る |

**ドメイン（6,249 件）** — `GET /api/v3/domains/{domain}`

| 取る | 使い道 |
| --- | --- |
| `last_analysis_stats` / `reputation` | 危険度 |
| `last_dns_records[]` | **A / AAAA から domain → IP の辺**。ピボットの本命 |
| `last_https_certificate` | **証明書の thumbprint と SAN**。最も強いインフラ共有の証拠 |
| `jarm` | TLS スタックの指紋 |
| `creation_date` / `registrar` | 登録の時期と業者 |
| `categories` | 分類（提供元ごとに違うので参考） |

**IP（3,166 件）** — `GET /api/v3/ip_addresses/{ip}`

`last_analysis_stats` / `reputation` / `as_owner` / `asn` / `network` / `country` /
`last_https_certificate` / `jarm`。AS は `enrich-asn.mjs` の結果と**突き合わせる**
（食い違ったら経路表の時点差なので、両方残して差を数える）。

**URL（2,768 件）** — `GET /api/v3/urls/{base64url}`

`last_analysis_stats` / `last_final_url` / `title` / `categories` / `redirection_chain`。

### 1.2 AbuseIPDB（対象 3,159 IP）

`GET /api/v2/check?ipAddress=&maxAgeInDays=365&verbose=`

| 取る | 使い道 |
| --- | --- |
| `abuseConfidenceScore` | 危険度。**通報数ではなくこれで判断する**（通報 97 件でスコア 0 の IP が実在する） |
| `totalReports` / `numDistinctUsers` | スコアの裏付け。通報者が 1 人ならスコアが低い理由になる |
| `lastReportedAt` | 最後に観測された時期 |
| `usageType` / `isp` / `domain` | **Data Center / Web Hosting か ISP か**。相乗り判定の補強（§3.2） |
| `reports[].categories` | 何をして通報されたか（`ポートスキャン 50 / 総当たり 32` のような分布） |
| `isTor` | Tor 出口は別扱い |

bogon と公開 DNS（`bogon` / `noise` の印が付いているもの）は引かない。

---

## 2. ピボット — そこから何を起こすか

エンリッチの価値は判定そのものより、**知らなかった実体と辺が生えること**にある。
以下を優先順に。括弧内は今の規模との比較。

### 2.1 マルウェア名の正規化（最優先）

VT の `suggested_threat_label`（例 `trojan.emotet/heur`）から**ファミリ名**を取り出し、
`derived-links.jsonl` に `{ioc, kind:"malware", name:<ファミリ>, source:"virustotal"}` として足す。
`popular_threat_name[]` は別名として `derived-aliases.jsonl` に置き、既存の
`canonMalware` に流し込む。

**なぜ最優先か。** 今のマルウェア実体 306 件は索引の表記そのままで、同じものが
別名で分かれている。VT ラベルで畳めば「マルウェア間の重なり」の分母がまず正しくなる。
ハッシュ 6,354 件のほとんどにラベルが付くので、効きが大きい。

### 2.2 ドメイン → IP の解決（passive DNS 相当）

`last_dns_records` の A / AAAA から `derived-iocs.jsonl`（新しい IP）と
`derived-links.jsonl` の `{kind:"ioc", rel:"resolves_to"}` を起こす。

**なぜ効くか。** 今の IOC ↔ IOC の辺は **310 件しかない**。ドメイン 6,249 件に
A レコードが付けば、ここが桁で増える。ドメインしか持っていなかったアクターと、
IP しか持っていなかったアクターが繋がる。

新しく出てきた IP は `derived-iocs.jsonl` に入れ、`origin:"vt.dns"` を付ける。
**`iocs.jsonl` には混ぜない。** 索引が主張した IOC と、そこから導いたものは別物。

### 2.3 証明書の共有（最も強い証拠）

`last_https_certificate.thumbprint_sha256` を鍵にして、同じ証明書を出している
ドメイン・IP をまとめる。`derived-certs.jsonl` に
`{thumbprint, serial, issuer, subject, sans[], iocs[]}` として残す。

自己署名や Let's Encrypt の使い回しもあるので、**発行者と SAN 数で重みを変える**。
SAN が 100 を超えるものは共用ホスティングなので根拠にしない（/24 や AS と同じ考え方）。

### 2.4 JARM の一致

`jarm` が同じ = 同じ TLS スタック = 同じ C2 フレームワークの可能性。
ただし既定の nginx / Apache でも一致するので、**JARM 値ごとの出現数を数え、
ありふれたものは外す**（`--jarm-cap`、既定は全体の 1% を超えたら外す）。
単独では弱い根拠なので、他の根拠と重なったときだけ意味を持たせる。

### 2.5 ホスティング種別（相乗り判定の補強）

AbuseIPDB の `usageType` が `Data Center/Web Hosting/Transit` の IP は、
AS の大きさに関わらず**相乗りの疑いを上げる**。今は AS のアドレス数と
アクター数の 2 つで判定しているが、ここに 3 つ目の観点が入る。

### 2.6 ファイル名の共有

`names[]` の共有。ただし `invoice.doc` `setup.exe` のような一般名が大量にあるので、
**全体での出現回数が閾値以下の名前だけ**を根拠にする（`ioc` の ubiquity cap と同じ考え方）。

### 2.7 取らないもの（枠を食うわりに効かない）

- VT の relationships（`/resolutions`, `/contacted_ips`, `/behaviours`）— 1 IOC あたり
  さらに 1〜3 回。18,537 件では成立しない。**§4 の第 2 段階に回す**
- VT の `categories` を根拠に使うこと — 提供元ごとに語彙が違い、突き合わない
- AbuseIPDB の `hostnames` — 逆引きなので当てにならない

### 2.8 見本アドレスを通報の中身から見つける

**信頼度スコアだけでは見本アドレスを弾けない。** 1.2.3.4 は AbuseIPDB の信頼度が
92、通報者 200 人あったが、実際には「適当な IP」として書かれ続けた見本アドレスで、
ISP も `APNIC Debogon Project`（汚染の計測をしている帯）と出る。

`bogon` の一覧は RFC の予約帯なので、経路に乗るこの種のアドレスは拾えない。
`net.mjs` の `NOISE` に帯を手で足す方法もあるが、それだと上流が増えるたびに漏れる。
そこで**通報コメントの中身**を見る。見本アドレスには動作確認や無言の通報が溜まるので、

- コメントを読めた通報が **20 件以上**（`--sample-min`）
- そのうち**中身の無いもの**（空・`...`・`test`・`n/a` など）が **30% 以上**（`--sample-ratio`）

の両方を満たしたら `sample` の印を付け、`stats.mjs` が根拠から外す。件数の下限が要る
のは、通報が 1〜2 件の IP は中身無し率 100% でも珍しくないため（実測で 9 件あり、
いずれもスコア 0〜1）。この条件で印が付いたのは 1.2.3.4 だけだった。

分母は `totalReports` ではなく**実際にコメントを読めた件数**を `comments` として残す。
API が返す通報は上限で切られるので両者は一致せず、判定に使った方を残さないと検算できない。

---

## 3. 統計をどう作るか

### 3.1 重なりの根拠を増やす

今の `overlaps.jsonl` は `via` に `ioc` / `subnet` / `registrable` / `asn` を持つ。
ここに 4 つ足す。

| via | 意味 | 強さ |
| --- | --- | --- |
| `certificate` | 同じ証明書（thumbprint 一致） | **最強** |
| `ioc` | 同じ IOC を指している | 強 |
| `resolution` | 同じ IP に解決するドメイン | 強 |
| `vhash` | VT の構造ハッシュが一致 | 強（§8 で足した） |
| `subnet` | 同じ /24 | 中 |
| `asn` | 同じ小さい AS | 中 |
| `imphash` | PE のインポート表が一致 | 中（§8 で足した） |
| `family` | VT が同じ脅威ラベルを付けている | 弱（§8 で中から下げた） |
| `registrable` | 同じ eTLD+1 | 弱 |
| `filename` | 珍しいファイル名の共有 | 弱（§8 で下げた） |
| `jarm` | 同じ TLS 指紋 | 弱（単独では使わない） |

**`overlaps.jsonl` に `strength` を足す。** 今は `shared`（共有数）と `ratio` しか
無く、根拠の種類による差が数字に出ない。上の順位を点数にして合算し、
`strength` として持たせる。並べ替えの既定を `strength` にする。

弱い根拠だけで成立している組には `weak_only: true` を付ける。
除くのではなく印を付ける（`bogon` / `noise` と同じ扱い）。

### 3.2 相乗り判定を 3 つの観点にする

今: AS のアドレス数 ≤ 4,096 かつ アクター数 ≤ 8。
追加: その AS の IP のうち AbuseIPDB が `Data Center/Web Hosting` と言う割合。
**7 割を超えたら相乗り**とする。`asn-cotenancy.jsonl` に `hosting_ratio` を足す。

### 3.3 時間軸を入れる

VT の `first_submission_date` は、索引が持っていない「世に出た日」。これで
`stats.json` に新しい節を作る。

- **実体ごとの活動期間** — その実体に繋がる IOC の `first_submission_date` の最小と最大
- **キャンペーン間の時間的重なり** — 期間が重なっている組。IOC を共有していなくても
  「同じ時期に動いていた」は手掛かりになる
- **索引の遅れ** — 索引の `観測日` と VT の `first_submission_date` の差の分布。
  自分たちの索引がどれだけ遅れて拾っているかが分かる

### 3.4 判定そのものの統計

- **アクターごとの悪性度の分布** — 検知ベンダー数の中央値。極端に低い実体は、
  索引の誤りか、まだ知られていないかのどちらか。どちらでも見る価値がある
- **VT が知らない IOC の数** — `404` が返ったもの。**これは失敗ではなく結果**なので
  `vt.jsonl` に `known: false` として残す。索引の独自性の指標になる
- **索引の主張と VT の判定の食い違い** — 索引が「C2」と言っているのに検知 0、など

### 3.5 カバレッジを必ず出す（重要）

1 キーでは全件が埋まるまで日数がかかる。その途中の統計は**一部しか見ていない**。

`stats.json` の先頭に必ず入れる。

```json
"coverage": {
  "virustotal": { "target": 18537, "done": 4200, "known": 3980, "unknown": 220, "ratio": 0.227 },
  "abuseipdb":  { "target": 3159,  "done": 3159, "ratio": 1.0 },
  "oldest_fetch": "2026-08-02", "newest_fetch": "2026-08-20"
}
```

**エンリッチ済みだけを母数にした割合を出さない。** 「検知されたのは 12%」と
「調べた範囲の 12%」は別物で、後者を前者として読むと必ず間違える。
未エンリッチは「陰性」ではなく「未知」として数える。

---

## 4. どの順で埋めるか

VT は 1 キーで 500 件/日。全 18,537 件で 38 日かかるので、**順番が結果を決める**。
実測した内訳で分けると次のようになる。

| 段階 | 対象 | 件数 | 日数 | ここで何が分かるか |
| --- | --- | --- | --- | --- |
| 0 | AbuseIPDB 全件 | 3,159 | 4 | IP の危険度と相乗り判定。VT と並行して走る |
| 1 | **複数の実体に繋がる IOC** | 4,789 | 10 | 重なりの根拠そのもの。**ここが終われば主目的はほぼ達成** |
| 2 | 注目 IP（小さい AS / 別アクター同居の /24） | 164 | 1 | 既に怪しいと分かっている IP の裏取り |
| 3 | ハッシュ（実体 1 つ） | 4,652 | 10 | マルウェア名の正規化（§2.1） |
| 4 | ドメイン・URL（実体 1 つ） | 6,797 | 14 | 解決先と証明書（§2.2 §2.3） |
| 5 | 残りの IP | 2,135 | 5 | 埋め合わせ |

**新しく入ってくる分（週 440 件）を常に最優先**にする。1 日 63 件を新規に回し、
残り 437 件を上の順で消化する（全体で 43 日）。

段階 1 が終わる **10 日目に一度、重なりの再計算をする**。ここで
「VT を入れたことで重なりがどう変わったか」が分かるので、以降の優先順を見直す。

---

## 5. 出力するファイル

| ファイル | 中身 |
| --- | --- |
| `vt.jsonl` | `{ioc, known, malicious, suspicious, harmless, undetected, reputation, label?, families?, first_submission?, jarm?, cert?, dns?, analyzed_at}` |
| `abuseipdb.jsonl` | `{ioc, score, reports, reporters, last_reported_at?, usage_type?, isp?, categories?}` |
| `derived-iocs.jsonl` | エンリッチから生えた IOC。`origin` にどこから来たかを持つ |
| `derived-links.jsonl` | 生えた辺。`source` は `virustotal` / `abuseipdb` |
| `derived-certs.jsonl` | 証明書ごとの IOC のまとまり |
| `enrich-meta.json` | 使った枠・件数・写しのハッシュ・取得の期間 |

`vt.jsonl` の `analyzed_at` は**応答に入っている解析時刻**であって取得時刻ではない。
取得時刻は `enrich-meta.json` にだけ置く（決定性のため）。

---

## 6. 検査に足すこと

`validate.mjs` に以下を足す。既存の 45 通りの自己検査（`selftest.mjs`）にも
壊し方を足して、鳴ることを確かめる。

- `vt.jsonl` / `abuseipdb.jsonl` の `ioc` が `iocs.jsonl` か `derived-iocs.jsonl` に実在するか
- スコアの範囲（AbuseIPDB は 0–100、検知数は 0 以上）
- `known:false` の行に判定が入っていないか（`routed:false` と同じ扱い）
- `derived-iocs.jsonl` が `iocs.jsonl` と**重複していないか**（重複したら索引側を優先）
- `derived-links.jsonl` の実体が `entities.jsonl` か派生の実体に実在するか
- `coverage` の分母と分子が実データと合っているか
- 写しのハッシュが `enrich-meta.json` にあるか

---

## 7. キーの扱い

環境変数からのみ読む。リポジトリには一切書かない。

```
VT_API_KEYS         # カンマ区切りで複数入れれば順に回す（1 つでも動く）
ABUSEIPDB_API_KEY
```

応答の写しは `data/ioc/.cache/` の下に置き、`.gitignore` 済み。
**写しに API キーが混ざらないよう、リクエストヘッダは保存しない。**

---

## 8. 実装したときに変えたところ

この計画は `tools/ioc/` に実装した。使い方は
[`tools/ioc/README.md`](../tools/ioc/README.md) にある。計画と変えた点を残しておく。

| 変えたところ | なぜ |
| --- | --- |
| 分析する工程を `enrich-intel.mjs` 1 つにまとめた | `enrich-meta.json`（特にカバレッジ）を 2 つのscriptが書き合うと、どちらが正しいか分からなくなる。取りに行く工程は API ごとに分けたまま |
| `ioc.sha512` を対象から外した | VT が索引していない。引いても必ず外れるので、枠を捨てることになる |
| `ioc.ipv6` を IP の対象に入れた | VT は v6 も引ける。63 件なので枠への影響はほぼ無い |
| 写しを**全欄ではなく射影**にした | ファイル応答は 1 件 50〜200 KB あり、18,589 件で 1 GB を超える。使う欄だけ残し、**版を写しに書いて**増やしたときに取り直せるようにした（`--full` で全欄） |
| 証明書の弱い根拠に `wildcard` を足した | SAN 数だけでは足りなかった。`*.azurewebsites.net` の証明書（SAN 11 と 30）が無関係な 2 つのドメインを結んでいた。**SAN が全部ワイルドカードなら、その host ではなく基盤に出された証明書** |
| `resolution` は「誰かの解決先になっている IP」だけ数える | 実体の IP を無条件に入れると `ioc`（同じ IOC を指している）の写しになり、根拠が二重に数えられる |
| `resolution` から **bogon / noise の解決先を外した** | `127.0.0.1` に解決するドメイン同士は「同じ所に居る」ではなく、**どちらもシンクホールされている**。実測で `APT28 ↔ STAC4749` `APT37 ↔ STAC4749` を繋いでいた |
| `overlaps.jsonl` に **`evidence`（根拠になった値）**を足した | 「証明書で繋がっている」と言われても、どの証明書かが分からなければ検算できない。thumbprint・IP・vhash・ファミリ名を値のまま残す（`--evidence-cap`、既定 5） |
| **ファジーハッシュを根拠に足した**（`vhash` 6 / `imphash` 4） | 検知名と違って**論理が明示的で提供元の判断が入らない**。どちらも完全一致で使えるので、比較の実装も要らない。`ssdeep` と `tlsh` は距離を測る必要があるので写しに残すだけにした |
| **見本アドレスを通報の中身から見つける**（§2.8） | 信頼度スコアだけでは弾けない。`1.2.3.4` はスコア 92 / 通報者 200 人だったが、コメントの一つは `"Test"`、ISP も `APNIC Debogon Project` と出る。経路に乗るので `bogon` では拾えず、帯の一覧は手で足すと必ず漏れるので、**実測から決まる印**を併せて持つ |
| **1 文字の実体名を索引が載せていても捨てる** | 上流の `"マルウェア": "A, N"` が区切りで割れ、`A` と `N` という実体が立って 468 IOC が両方にぶら下がっていた。既知名の抜け道を通っていたので、**長さの判定だけは既知名でも飛ばさない**ようにした |
| **IOC 集合が完全に一致する組を重なりから外した** | 共有率 100% は構造上そうなるだけで根拠にならない。上の `A ↔ N` は shared 1190 / strength 40 で最上位に立っていた。捨てずに `identical-sets.jsonl` に回す。malware / actor では**別名の候補**として使える（実測で `CloudSorcerer ↔ DeedRAT` `Gshell ↔ TencShell` が並んだ）が、`case` は 1 つの記事から起こすので集合が一致しやすく別名ではない |
| **`vhash` を PE のときだけ使う** | PE 以外の vhash は**中身ではなく入れ物の形式**しか見ていなかった。実測で `fe43cc09…` が Hangul 文書 + Outlook + MS Word の 18 検体（12KB〜800KB）に付いて APT37 / APT28 / Lazarus Group / UNC3347 を、`7596fdd0…` が JavaScript + シェルスクリプト（**105B〜1.5MB**）に付いて APT37 / Gorgon Group / APT41 を、`2a85fbef…` が ELF（1.4MB〜6.2MB）に付いて APT29 / APT41 / TAG-100 / CL-STA-1062 を繋いでいた。PE では 1,679 群が安定している。上限を 2 に下げると 77 組 → 16 組になるが、種別で切れば 77 組 → 34 組で誤検知は同じく 0 |
| **解決先に ubiquity cap を入れた**（IP 単位 3 / AS 単位 2） | ドメインパーキングは AS が小さく解決先だけ膨大なので、大きさの上限を素通りする。SEDO GmbH（AS47846、**1,024 アドレス**）の `91.195.240.12` が APT33 / Cytrox / Konni / Lazarus Group など 8 実体を総当たりで繋いでいた。AS 単位を 3 にすると Seznam.cz が、4 にすると Squarespace が残るので 2 にした |
| 射影の版を**引き先ごと**にした | ファジーハッシュを足したときに取り直すのが 2,058 件（ファイルのみ）で済む。まとめて 1 つの版だと 5,433 件（ドメインも IP も）になっていた |
| **`family` を弱い根拠に落とした**（5 → 2） | 使っているのは VT が集約した `popular_threat_classification` だけで、提供元ごとの検知名は写しにも落としていない。それでも「同じラベル = 同じ物」ではない。実測で `mikey` が APT28（Sednit）と Silver Fox（Atlas RAT）を繋いでいたが、変種は `dynamer` / `etset` / `pswdump` と全部違い、検体も JS・DLL・OCX だった |
| **`filename` を弱い根拠に落とし**、置き名を先に除いた（2 → 1） | `payload.bin` `stage2.bin` のような置き名とハッシュそのものの自動命名を落とす。残ったものも 2 つ以上揃わないと数えない（`--filename-min`）。1 つだけの一致は偶然が多い |
| 証明書に `unanchored` を足した | 名前が当たったドメインが群に 1 つも居ないとき。`invalid2.invalid`（Cloudflare の既定）・`*.hstgr.io`・`cloudflare-dns.com`・Fastly の既定が、無関係なアクター同士を strength 9〜10 で繋いでいた。**IP だけの群では運用者の証明書か基盤の既定かを見分けられない**。外したほうは `to_check.cert_excluded` で毎日人に渡す |
| ファミリから **提供元の連番**を落とした | `boiq` `boir` `boiv` … のように頭 2 文字と長さが同じ札が並ぶのは連番。実測で 13 本の `bo` + 4 文字が実体として生えていた。並びの数で測る（`--serial-min`、既定 3） |
| 証明書の `wildcard` を **「名前が載っているか」**に広げた | SAN が無い自己署名（`localhost` `0.0.0.0` `Fireware web CA` `letsencrypt-nginx-proxy-companion`）は、同じ image や機器を使っている全員が同じものを出す。SAN 数でもワイルドカードかでも見分けられない |
| `resolution` から **大きい AS の解決先を外した** | Cloudflare（`104.21.x` / `172.67.x` / `2606:4700::`）や Vercel の edge に 6〜16 の実体が集まっていて、`APT29 ↔ JINX-0164` のような無関係な組が出た。「同じ AS に居る」と同じで、**edge に解決するのは何の根拠にもならない**。156 組 → 22 組に絞られた |
| `enrich-asn.mjs` が **生えた IP にも AS を付ける**ようにした | 上の判断に要る。走らせる順は `enrich-intel` → `enrich-asn` → `stats` |
| `family` にも上限（`--family-cap`）を付けた | VT のラベルには `tedy`（61 検体・12 実体）や `dllhijack`（10 実体）のように、**手口や検出器の都合で付いたファミリではない名前**が混じり、`APT28 ↔ APT41` のような組を生んでいた。何実体にぶら下がるかで測る |
| 畳む前に落とす一般名を増やした | 列挙に加えて、`agent` + 1〜2 文字（Kaspersky の Agent.a／AgentTesla は残る）、`generic` で始まるもの、**母音を含まないもの**（`grhh` `kqil` `vsnw09g25`）。`astraea` は Kaspersky の機械学習エンジンの名前で、**検出器の名前**であってファミリではない |
| `hosting_ratio` に最低件数（既定 3）を付けた | カバレッジが低い間は、AS の IP 1 件だけを見て「7 割が事業者の網」と判定してしまう |
| 事業者の網で外した AS を `hosting_excluded` に残した | この観点は**効きすぎる**。攻撃側の基盤はほとんどが事業者の網なので、小さい専用 AS まで外れる。実測で 12 件 → 8 件に減り、**AS207560（512 アドレス・APT1 / APT28 / APT29）**が外れた。外れたこと自体に気づけないのが一番まずいので、外したほうを全部残して実行時にも出す |
| `overlaps.jsonl` の**行の並びは `kind, a, b` のまま**にした | 並びは出力の一部で、変えると差分がノイズになる。強さで並べ替えるのは要約側 |

段階ごとの実測は次のとおり（19,026 IOC 時点）。計画の見積もりとほぼ一致した。

| 段階 | 件数（計画） | 件数（実測） |
| --- | --- | --- |
| 1 複数の実体に繋がる IOC | 4,789 | 4,787 |
| 2 注目 IP | 164 | 294 |
| 3 ハッシュ（実体 1 つ） | 4,652 | 4,482 |
| 4 ドメイン・URL（実体 1 つ） | 6,797 | 6,470 |
| 5 残りの IP | 2,135 | 2,066 |
| 6 実体に繋がっていない IOC | — | 490 |

鍵 3 本（1,500 件/日）で全 18,589 件に **13 日**、段階 1 だけなら **4 日**。

日次は `sh tools/ioc/daily.sh --push` の 1 本にまとめてある。取得・突き合わせ・検査・
コミットまでを機械側で終わらせ、**人（や AI）は `daily-report.mjs` が出した
「昨日から何が変わったか」を読むところから始める**。レポートに残るのは
「索引が C2 と言っているのに検知 0」のような、機械では決められないものだけ。

---

## 9. 今後の課題

**全件バックフィルが終わってから着手する。** いま入れると段階 3 以降の完了が遅れる。
順は効きの大きい順。

### 9.1 ハッシュの relationship（通信先）を取る

いちばん効きが大きい見込み。`GET /api/v3/files/{hash}/contacted_ips` など。

今のピボットは「ドメイン → 解決先 IP」（§2.2）が主で、**ドメインを持っている実体しか
繋がらない**。ハッシュしか持っていない実体は `family` / `vhash` / `imphash` という
**検体の似姿**でしか繋がっていない。通信先が入ると「この検体はこの IP と話した」という
**動作の証拠**になり、ハッシュ側とドメイン / IP 側が初めて直接つながる。
強さは `certificate` の次、`ioc` と同格に置けるはず。

枠の見積り（鍵 6 本 = 3,000 件/日、ハッシュ 6,357 件）。

| 取るもの | 追加コール | 追加日数 |
| --- | --- | --- |
| `contacted_ips` だけ | 6,357 | 約 3 日 |
| `contacted_ips` + `contacted_domains` + `contacted_urls` | 19,071 | 約 7 日 |

**先に決めておくこと。**

- **サンドボックスの雑音を外す。** Windows Update・DNS・証明書失効確認は全検体に
  共通で出る。`ubiquity-cap` と同じ考え方で「多くの検体が話している宛先」を外さないと、
  いまの `jarm` より悪い根拠になる。実測してから境目を決める
- **写しの版**を今の射影と同じように持つ。relationship は取得時点で変わる
- 全ハッシュに広げる前に、**複数実体に跨るハッシュ（段階 1 相当）だけ**で試す。
  数百件で済み、雑音の境目もそこで測れる

### 9.1b ドメイン / IP の過去の解決先（`/resolutions`）

**object では代替できない唯一の relationship。** `last_dns_records` は**現在**の A / AAAA
しか返さないので、**既に移転したあとのインフラは見えない**。攻撃者が IP を変えたあとに
索引へ載った IOC は、いま解決先を引いても当時の基盤に繋がらない。ここは
`/resolutions` でしか埋まらない。

| 取るもの | 追加コール | 追加日数 |
| --- | --- | --- |
| ドメイン `/resolutions`（6,252 件） | 6,252 | 約 2 日 |
| IP `/resolutions`（3,234 件） | 3,234 | 約 1 日 |

**ドメイン → IP と IP → ドメインはかなり重なる**ので、まずドメイン側だけでよい。

`resolved_at` が付いてくるので、**いつの解決先か**を辺に持たせる。時期の違う解決先を
同じ重みで扱うと、5 年前に同じ共用ホストに居たというだけの組が上位に来る。
§3.3 の時間軸と突き合わせて、**実体の活動期間と重なる解決先だけ**を根拠にするのが筋。

### 9.1c 取らないと決めたもの（§9.1 の裏返し）

- **ドメイン / IP の `/communicating_files`** — §9.1 の `contacted_ips` と**同じ辺を
  逆向きに見ているだけ**。ハッシュ側 6,357 件に対しこちらは 9,486 件で、
  同じものを 1.5 倍の枠で買うことになる。ハッシュ側から取る
- **URL の relationship** — `redirection_chain` と `last_final_url` は object に入っている。
  残る `/downloaded_files` は効きが薄い

### 9.2 ssdeep / tlsh の距離を使う

写し（`.cache`）には射影として残っているので**引き直しは要らない**。
距離の実装だけ。出すのは生の値ではなく**組ごとの距離**にする
（生の値は GitHub の secret scanning が AWS の鍵と誤検知して push を止める。§8 参照）。

### 9.3 DNS / RDAP を正式な工程にする

いまは試作のみ。`fetch-rdap.mjs` として切り出し、`nameserver` を重なりの根拠に足す。
実測で連絡先は約 92% が GDPR で伏せられていたので、**使えるのは業者・登録日・
ネームサーバの 3 つ**。鍵が要らないので枠を食わない。

### 9.4 case 同士の重なりを見直す

`case` は 1 つの記事から起こすので、重なり 128 組の多くが「同じ記事の括り」の
可能性がある。`actor` / `malware` とは別の見方が要る（§8 の `identical-sets.jsonl` で
集合が完全一致する 153 組は既に外した）。
