# 依頼: ポータル連携用の静的インデックスを公開する（threatactor-intel-analysis）

## 背景

別リポジトリ `proshiba/research_bench` に、セキュリティ調査アプリを横断するポータルを作った。
ポータルはサーバーを持たず、各アプリが GitHub Pages に置いた静的 JSON を `fetch()` して
手元で索引し、**同じ値が複数ソースに現れたこと**を検出して横串を作る。

**3 アプリのうち、この対応が一番効く。** 理由を実測とともに書く。

現在このリポジトリが公開している索引は `ui/data/actors.json`（476 KB）だけで、
中身は**アクター名・別名・ファセット・関係だけ**。マルウェア名・IOC・CVE が入っていない。
そのためポータルのクロスサーチでは、**3 ソースを通じて横串が 1 件も成立していない**。

- アクター情報 × マルウェア解析 → 繋ぐ鍵はマルウェア名だが、索引に無い
- アクター情報 × 脆弱性インテル → 繋ぐ鍵は CVE だが、索引に無い
- アクター情報 × マルウェア解析（IOC） → 繋ぐ鍵は IP/ドメイン/ハッシュだが、索引に無い

一方で、**データ自体は `profiles/<slug>/` に揃っている**。実際にプロファイルを直接読むと結合する。

> `profiles/*/actor-profile.json` の `capabilities.malware` を 60 アクターぶんサンプルしたところ、
> **20 件**がマルウェア解析リポジトリのファミリと一致した。
> 例: APT41 → ShadowPad / gh0st RAT / njRAT / Xmrig、Lazarus Group → WannaCry、
> TA505 → Amadey、SilverTerrier → Agent Tesla、APT33 → Quasar RAT / DarkComet。
> `counts.malware > 0` のアクターは 241 件あるので、全体ではもっと増える。

ポータルは暫定策として、ワークベンチでアクターノードを展開したときに
`profiles/<slug>/actor-profile.json` と `iocs.json` を遅延取得している。これで
「APT41 → ShadowPad → マルウェア解析側の 8 ケース」までは辿れる。
ただし 673 ファイルに分散しているためクロスサーチには使えない。

**索引にマルウェア名・IOC・CVE を載せてほしい。** それだけで横串が一気に効くようになる。

## ゴール

公開サイト（`https://proshiba.github.io/threatactor-intel-analysis/ui/`）の直下に 2 ファイルを追加する。

| パス | 内容 |
| --- | --- |
| `ui/api/v1/meta.json` | 自己紹介。ポータルが最初に読む |
| `ui/api/v1/search.json` | 索引本体（全アクター横断で集約） |

目安: エンティティ約 2 万件、gzip 後 1.5 MB 未満。
`ui/data/actors.json` は**現行のまま変更しない**（このリポジトリの UI が依存しているため）。

---

## 仕様 v1

### meta.json

```jsonc
{
  "spec_version": "1.0",
  "app_id": "threatactor-intel-analysis",
  "name": "アクター情報",
  "description": "公開レポートと OSINT データセットから標準化した脅威アクタープロファイルの索引。",
  "generated_at": "2026-07-26T00:00:00Z",
  "repository": "https://github.com/proshiba/threatactor-intel-analysis",
  "site_url": "https://proshiba.github.io/threatactor-intel-analysis/ui/",  // 末尾スラッシュ必須

  "endpoints": { "search": "api/v1/search.json" },     // site_url からの相対

  "deep_links": {
    "actor":  "#/actor/{detail}",       // {detail} に entity.detail を URL エンコードして埋める
    "_graph": "#/relations/{detail}"    // このリポジトリの関係グラフ画面
  },

  "capabilities": ["iframe", "deep-link", "graph"],
  "stats": { "actor": 673, "malware": 1836, "ioc": 17573 }
}
```

`embed_css` を任意で足せる。ポータルは各アプリを iframe で表示するため、アプリ側のヘッダーと
ポータルのクロームが二重になる。GitHub Pages のプロジェクトページは全て同一オリジンなので、
ポータルはここに書いた CSS を iframe 内に注入して重複を隠せる。実際のセレクタは
`ui/index.html` / `ui/assets/style.css` を見て決めること。

### search.json

```jsonc
{
  "spec_version": "1.0",
  "app_id": "threatactor-intel-analysis",
  "generated_at": "2026-07-26T00:00:00Z",
  "entities": [ /* 下記 */ ]
}
```

### エンティティ

```jsonc
{
  "type": "actor",                    // 下の語彙から選ぶ（必須）
  "id": "actor:apt41",                // このファイル内で一意（必須）
  "label": "APT41",                   // 表示用（必須）
  "value": "APT41",                   // 結合キー。省略時は label
  "detail": "apt41",                  // deep_links の {detail} に入る。省略時は id
  "aliases": ["BARIUM", "Wicked Panda"],   // 結合キーとして追加で索引される
  "attrs": { "帰属": "China" },         // 「キー: 値」で表示されるので日本語キー推奨
  "refs": [ { "rel": "使用マルウェア", "target": "malware:shadowpad" } ]
}
```

**`refs[].target` は必ずこのファイル内の `id`。** 他ソースの id を書いてはいけない。
ソースをまたぐ関係はポータルが `value` の一致から自動生成する。

`attrs` のうち意味が決まっているキーは `flags`（文字列配列。バッジ表示）と
`prefix`（`deep_links` の `{prefix}`）だけ。`_` 始まりのキーは使わないこと。

### type の語彙と value の正規化

| type | value の正規化 |
| --- | --- |
| `actor` | アクター名。ポータル側で英数字のみ小文字化して突き合わせる |
| `malware` / `tool` | 同上。**マルウェア名は最重要の結合キー** |
| `cve` | 大文字 `CVE-YYYY-NNNN` |
| `ioc.ipv4` / `ioc.ipv6` | そのまま |
| `ioc.domain` | 小文字化・末尾ドット除去 |
| `ioc.url` | 小文字スキーム |
| `ioc.email` | 小文字化 |
| `ioc.md5` / `ioc.sha1` / `ioc.sha256` / `ioc.sha512` | 小文字 16 進 |
| `ttp` | 大文字 `T####[.###]` |
| `campaign` | 活動名 |

**難読化は必ず解除して入れる。** `1.2.3[.]4` ではなく `1.2.3.4`。
バリデータが defang 残りをエラーにする。

---

## このリポジトリでの具体的な作業

`ui/build_data.py` が `actors.json` を作っているのと同じ流儀で、
`ui/build_portal_index.py` を新設する（標準ライブラリのみで書けるはず）。
入力は `profiles/<slug>/` 配下の 673 ディレクトリ。

### 出すエンティティ

**1. `actor` — 673 件**

`profiles/<slug>/actor-profile.json` と既存の `actors.json` から作れる。

- `id`: `actor:<slug>` / `label`・`value`: `name` / `detail`: `<slug>`
- `aliases`: `actor.aliases[].name` を全部（**922 件ある。横串の精度に直結する**）
- `attrs`: `種別` `帰属` `確度` `動機` `標的分野` `概要`(240 字程度に切る) `更新`
- `refs`: `relationships[]` から他アクターへ（`rel` は `relationship_type`）

**2. `malware` / `tool` — 約 1,836 件（重複排除後はもっと少ない）**

`actor-profile.json` の `capabilities.malware[]` / `capabilities.tools[]` から。
**ここが今回の主目的。**

- **同じ名前は 1 エンティティに畳み、使っているアクター全部を `refs` に並べる**
- `id`: `malware:<正規化した名前>`（例 `malware:shadowpad`）
- `label`・`value`: 元の表記のまま（`gh0st RAT` など。正規化はポータル側でやる）
- `refs`: `{"rel":"使用アクター","target":"actor:<slug>"}` を使用アクターぶん
- `attrs`: `使用アクター数` など

**3. `cve` — `capabilities.vulnerabilities[]` から**

CVE 形式のものだけ拾う。同じ CVE は 1 エンティティに畳み、`refs` でアクターに繋ぐ。
これが脆弱性インテルとの唯一の橋になる。

**4. `ioc.*` — 約 17,573 件**

`profiles/<slug>/iocs.json` を 673 ファイル全部読んで集約する。
このファイルは `{schema_version, actor_ref, generated_at, sources, indicators}` という形で、
実体は `indicators` 配列。各要素に `type` `value` `normalized_value` `disposition`
`observation_count` `campaign_refs` `malware_refs` `roles` がある。

- **同じ値は 1 エンティティに畳み、観測元アクター全部を `refs` に並べる**
- `value` には `normalized_value` を優先して使う
- 型の対応: `md5`→`ioc.md5`, `sha1`→`ioc.sha1`, `sha256`→`ioc.sha256`, `sha512`→`ioc.sha512`,
  `ipv4`→`ioc.ipv4`, `ipv6`→`ioc.ipv6`, `domain`→`ioc.domain`, `url`→`ioc.url`,
  `email`→`ioc.email`
- `certificate-fingerprint` は語彙に無いので**索引に入れない**
- `attrs`: `確度`(disposition) `観測数`(observation_count)
- `disposition` が `rejected` のものは入れない（誤検知として棄却済みのため）

**5. `campaign` — `activities[]` のうち `activity_type` が campaign 相当のもの**

任意。`refs` でアクターに繋ぐ。

**6. `ttp` — 5,327 件**

任意。調査上の価値はあるが横串にはあまり効かない。サイズが厳しければ省いてよい。
入れる場合は `technique_id` を `value` にし、同じテクニックは 1 エンティティに畳むこと。

### サイズについて

`artifacts.csv`（17,401 件の非 IOC アーティファクト）は**索引に入れない**。
コマンドラインやファイル名は誤結合を招きやすく、量のわりに横串の価値が薄い。

`概要` などの長文は切り詰める。gzip 後 1.5 MB を目安にすること。

### CI への組み込み

`.github/workflows/deploy-pages.yml` は現在 `ui/build_data.py` を実行して
`ui/` と `profiles/` を `_site` にコピーしている。ここに索引の生成を足し、
`ui/api/v1/` が `_site` に含まれるようにする。

673 ファイルを読むので数十秒かかる可能性がある。遅ければ並列化してよい。

---

## 検証

```bash
curl -sO https://raw.githubusercontent.com/proshiba/research_bench/main/docs/validate-index.py
python3 validate-index.py ui/api/v1/meta.json ui/api/v1/search.json
```

**エラー 0 件**にすること。あわせて次を確認する。

- `malware` エンティティに `ShadowPad` `gh0st RAT` `njRAT` `Amadey` `WannaCry`
  `Quasar RAT` `DarkComet` `Agent Tesla` が含まれること
  （これらがマルウェア解析リポジトリのファミリと結合する。**この対応の主目的**）
- `APT41` の `refs` から `ShadowPad` に辿れること
- IOC が値で重複排除されており、複数アクターで観測された指標の `refs` が 2 件以上あること
- gzip 後 1.5 MB 未満
- 既存の `python3 -m unittest discover -s actor_profile/tests -v` が通ること

---

## ブランチと PR

- ブランチ: `claude/portal-index-v1`
- PR タイトル: `ポータル連携用の静的インデックス (spec v1) を追加`
- PR 本文に、バリデータの出力（エンティティ数・型の内訳・サイズ）と、
  上のマルウェア名が索引に入ったことの確認結果を貼ること

## やらないこと

- `ui/data/actors.json` の形式変更や削除（このリポジトリの UI が依存している）
- `profiles/` 配下のデータそのものの変更
- 既存 UI の画面・ルーティングの変更
- ポータル側（research_bench）の変更。索引が公開されたらポータル側で
  `apps.json` の `adapter` を `spec-v1` に切り替える
