# 依頼: ポータル連携用の静的インデックスを公開する（ai-security-analysis）

## 背景

別リポジトリ `proshiba/research_bench` に、セキュリティ調査アプリを横断するポータルを作った。
ポータルはサーバーを持たず、各アプリが GitHub Pages に置いた静的 JSON を `fetch()` して
手元で索引し、**同じ値が複数ソースに現れたこと**を検出して横串を作る。

このリポジトリは現在 `ui/data.js`（約 7.0 MB の `window.MALDB`）しか公開していないため、
ポータルは専用アダプタを書いて data.js を丸ごと読んでいる。索引に不要な本文まで含むので重い。

**このリポジトリに、ポータル連携仕様 v1 に準拠した軽量な索引を追加してほしい。**

## ゴール

公開サイト（`https://proshiba.github.io/AI-security-analysis/ui/`）の直下に 2 ファイルを追加する。

| パス | 内容 |
| --- | --- |
| `ui/api/v1/meta.json` | 自己紹介。ポータルが最初に読む |
| `ui/api/v1/search.json` | 索引本体 |

目安: エンティティ約 3,000 件、非圧縮 2 MB 未満。`data.js` は**現行のまま変更しない**
（このリポジトリの UI が依存しているため）。

---

## 仕様 v1

### meta.json

```jsonc
{
  "spec_version": "1.0",
  "app_id": "ai-security-analysis",
  "name": "マルウェア解析",
  "description": "検体の静的解析結果・IOC・検出ルールの索引。",
  "generated_at": "2026-07-26T00:00:00Z",
  "repository": "https://github.com/proshiba/AI-security-analysis",
  "site_url": "https://proshiba.github.io/AI-security-analysis/ui/",   // 末尾スラッシュ必須

  "endpoints": { "search": "api/v1/search.json" },                     // site_url からの相対

  // エンティティ種別 → 詳細ページ。{detail} に entity.detail を URL エンコードして埋める
  "deep_links": {
    "case":        "#/case/{detail}",
    "malware":     "#/family/{detail}",
    "campaign":    "#/intel/{detail}",
    "ioc.ipv4":    "#/iocs?q={detail}",
    "ioc.ipv6":    "#/iocs?q={detail}",
    "ioc.domain":  "#/iocs?q={detail}",
    "ioc.url":     "#/iocs?q={detail}",
    "ioc.endpoint":"#/iocs?q={detail}",
    "ioc.md5":     "#/iocs?q={detail}",
    "ioc.sha1":    "#/iocs?q={detail}",
    "ioc.sha256":  "#/iocs?q={detail}",
    "ioc.email":   "#/iocs?q={detail}",
    "_graph":      "#/graph?root={detail}"        // このリポジトリのグラフ調査画面
  },

  "capabilities": ["iframe", "deep-link", "graph"],
  "stats": { "case": 1125, "malware": 74, "ioc": 1952 }
}
```

`embed_css` を任意で足せる。ポータルは各アプリを iframe で表示するため、アプリ側のヘッダーと
ポータルのクロームが二重になる。GitHub Pages のプロジェクトページは全て同一オリジンなので、
ポータルはここに書いた CSS を iframe 内に注入して重複を隠せる。

```jsonc
"embed_css": "header.topbar, footer { display: none !important; } main { padding-top: 0 }"
```

実際のセレクタは `ui/index.html` / `ui/style.css` を見て決めること。

### search.json

```jsonc
{
  "spec_version": "1.0",
  "app_id": "ai-security-analysis",
  "generated_at": "2026-07-26T00:00:00Z",
  "entities": [ /* 下記 */ ]
}
```

### エンティティ

```jsonc
{
  "type": "ioc.ipv4",              // 下の語彙から選ぶ（必須）
  "id": "ioc.ipv4|45.66.228.114",  // このファイル内で一意（必須）
  "label": "45.66.228.114",        // 表示用（必須）
  "value": "45.66.228.114",        // 結合キー。省略時は label
  "detail": "45.66.228.114",       // deep_links の {detail} に入る。省略時は id
  "aliases": ["別名1"],             // 任意。結合キーとして追加で索引される
  "attrs": { "役割": "C2" },        // 任意。「キー: 値」で表示されるので日本語キー推奨
  "refs": [                        // 任意。同一ソース内の他エンティティへの辺
    { "rel": "C2/通信", "target": "case:8f2a…" }
  ]
}
```

**`refs[].target` は必ずこのファイル内の `id`。** 他ソースの id を書いてはいけない。
ソースをまたぐ関係はポータルが `value` の一致から自動生成する。

`attrs` のうち意味が決まっているキーは `flags`（文字列配列。バッジ表示）と
`prefix`（`deep_links` の `{prefix}`）の 2 つだけ。`_` 始まりのキーは使わないこと。

### type の語彙と value の正規化

| type | value の正規化 |
| --- | --- |
| `ioc.ipv4` / `ioc.ipv6` | そのまま |
| `ioc.domain` | 小文字化・末尾ドット除去 |
| `ioc.url` | 小文字スキーム |
| `ioc.endpoint` | `host:port`、小文字化 |
| `ioc.email` | 小文字化 |
| `ioc.md5` / `ioc.sha1` / `ioc.sha256` | 小文字 16 進 |
| `cve` | 大文字 `CVE-YYYY-NNNN` |
| `malware` | ファミリ名。ポータル側で英数字のみ小文字化して突き合わせる |
| `case` | 検体 1 件の解析ケース。ハッシュなら小文字 16 進 |
| `campaign` | 相関クラスタ |
| その他 | `actor` `product` `vendor` `ttp` `tool` `report` |

**難読化は必ず解除して入れる。** `1.2.3[.]4` ではなく `1.2.3.4`、`hxxp://` ではなく `http://`。
表示用に defang したい場合は `label` 側だけで行う。バリデータが defang 残りをエラーにする。

---

## このリポジトリでの具体的な作業

`ui/generate_ui_data.py` が `data.js` を作っているのと同じ入力から、新しい索引を生成する。
既存スクリプトを拡張してもいいし、`ui/build_portal_index.py` を新設してもよい
（`generate_ui_data.py` に `--check` があるので、同じ流儀で揃えると CI に載せやすい）。

### 出すエンティティ

**1. `case` — 検体 1 件（約 1,125 件）**

- `id`: `case:<sha256>` / `label`・`value`・`detail`: `<sha256>`（小文字）
- `attrs`: `ファミリ` `版` `形式` `初観測` `提供元` `分類`(campaign_type) `判定`(assessment.status) `タグ`
- `refs`: ファミリへ `{"rel":"ファミリ","target":"family:<key>"}`

本文（README / STATIC-LOGIC / FEATURES）は**入れない**。詳細は deep_link で本体に飛ばす。

**2. `malware` — ファミリ（74 件）**

- `id`: `family:<key>` / `label`・`value`: 表示名（`label` or `title`）/ `detail`: `<key>`
- `aliases`: ファミリの別名を全部入れる（**横串の精度に直結する**）
- `attrs`: `ケース数` `ルール数`

**3. `campaign` — 相関キャンペーン候補（26 件）**

- `id`: `intel:<id>` / `label`・`value`・`detail`: `<id>`
- `attrs`: `分類` `確度` `構成数`
- `refs`: 構成ケースへ `相関ケース`、ファミリへ `ファミリ`

**4. `ioc.*` — IOC と C2（約 1,900 件）**

同じ値は 1 エンティティに畳み、観測元のケースを `refs` に並べる。

現行データの種別表記にゆれがあるので、次の対応表で正規化すること。

| data.js の `type` | spec の type |
| --- | --- |
| `sha256`, `SHA-256` | `ioc.sha256` |
| `sha1` | `ioc.sha1` |
| `md5` | `ioc.md5` |
| `url`, `URL` | `ioc.url` |
| `ipv4` | `ioc.ipv4` |
| `ドメイン` | `ioc.domain` |
| `接続先` | 値に `:port` があれば `ioc.endpoint`、無ければ IP/ドメイン判定 |
| `file_name`, `Ethereumアドレス` | **索引に入れない**（結合キーとして役に立たず誤結合の元） |

さらに次の処理が要る。

- **`/TCP` `/UDP` の接尾辞を落とす**（`45.66.228.114:7000/TCP` → `45.66.228.114:7000`）
- **`host:port` は endpoint エンティティに加えて、ホスト単体のエンティティも作り、
  endpoint → host の `refs` を張る。** これがないと `1.2.3.4:8080` と `1.2.3.4` が
  別物のまま残り、IP でのピボットが効かない
- **URL も同様**にホストを取り出して繋ぐ
- **検体自身の SHA-256 と一致する file-hash IOC は捨てる**（`case` エンティティと重複するため）
- `attrs` に `役割`（IOC の role）を入れる
- `refs` の `rel` は role をそのまま使ってよい（`C2/通信` など）

`c2` 配列（273 ケースに計 679 件）も同じ扱いで IOC エンティティにすること。

### CI への組み込み

`.github/workflows/deploy-pages.yml` は現在 `data.js` を再生成して `ui/` だけを
`_site/ui` にコピーしている。ここに索引の生成を足し、`ui/api/v1/` が `_site` に含まれるようにする。
`paths` フィルタの調整も必要なら行うこと。

生成物をコミットするか CI 生成のみにするかは既存の運用（`data.js` の扱い）に合わせる。

---

## 検証

```bash
curl -sO https://raw.githubusercontent.com/proshiba/research_bench/main/docs/validate-index.py
python3 validate-index.py ui/api/v1/meta.json ui/api/v1/search.json
```

必須フィールドの欠落、`id` 重複、`refs.target` の解決漏れ、defang 残り、型ごとの表記ゆれを
検出する。**エラー 0 件**にすること。警告は内容を見て判断してよい。

あわせて次を目視確認する。

- 結合キー率が 95% 以上（バリデータが表示する）
- gzip 後 1 MB 未満
- `ioc.ipv4` の代表値（例 `45.66.228.114`）を `search.json` から grep して、
  `refs` に複数ケースがぶら下がっていること

---

## ブランチと PR

- ブランチ: `claude/portal-index-v1`
- PR タイトル: `ポータル連携用の静的インデックス (spec v1) を追加`
- PR 本文に、生成されたエンティティ数・型ごとの内訳・ファイルサイズ（バリデータの出力）を貼ること

## やらないこと

- `ui/data.js` の形式変更や削除（このリポジトリの UI が依存している）
- 既存 UI の画面・ルーティングの変更
- 解析結果データそのものの変更
- ポータル側（research_bench）の変更。索引が公開されたらポータル側で
  `apps.json` の `adapter` を `spec-v1` に切り替える
