# 依頼: ポータル連携仕様 v1 に合わせる（vuln-intel-agent）

## 背景

別リポジトリ `proshiba/research_bench` に、セキュリティ調査アプリを横断するポータルを作った。
ポータルはサーバーを持たず、各アプリが GitHub Pages に置いた静的 JSON を `fetch()` して
手元で索引し、**同じ値が複数ソースに現れたこと**を検出して横串を作る。

**3 アプリのうち、このリポジトリが一番仕様に近い。**
`web/build_index.py` が既に `api/v1/meta.json` と `api/v1/search.json` を出しており、
CORS も開いていて、OpenAPI 定義まである。ポータルの静的フェデレーション方式は
もともとこのリポジトリの設計を一般化したもの。

残っているのは形式の細部と、下記のデータ品質の問題。

## ゴール

1. `api/v1/search.json` を仕様 v1 のエンティティ形式で出す
2. `api/v1/meta.json` に仕様 v1 の必須フィールドを足す
3. ビューアに CVE 単位のディープリンクを作る
4. 台帳の再生成（`priority` が全件 `INFO` になっている問題を解消する）

---

## 作業 1: `search.json` を仕様 v1 の形式にする

現在の `search.json` は列指向（`fields` + `rows`）で、42,171 行・10.6 MB。
これはビューアには効率的だが、ポータルはエンティティ配列を期待する。

**方針: 仕様準拠のファイルを `api/v1/search.json` とし、
現行の列指向ファイルは `api/v1/viewer.json` に改名してビューア専用にする。**

サイズは実測済みで、オブジェクト形式にしても gzip 後は 1.76 MB → 2.25 MB（+28%）に収まる。
キーが繰り返されるぶんは gzip がほぼ吸収するので、列指向を仕様に持ち込む必要はないと判断した。

### 出力する形

```jsonc
{
  "spec_version": "1.0",
  "app_id": "vuln-intel-agent",
  "generated_at": "2026-07-26T00:00:00Z",
  "entities": [
    {
      "type": "cve",                     // cve が無い内部 ID のみの行は "report"
      "id": "vuln:VW-2022-0293",         // このファイル内で一意
      "label": "CVE-2019-6446",
      "value": "CVE-2019-6446",          // 結合キー。大文字の CVE-YYYY-NNNN
      "detail": "VW-2022-0293",          // deep_links の {detail} に入る
      "attrs": {
        "題名": "Numpy Deserialization of Untrusted Data",
        "ベンダー": "GitHub; SUSE",
        "製品": "Rancher;SLES;SUSE Manager;numpy",
        "CVSS": 9.8,
        "深刻度": "critical",
        "優先度": "P1",
        "公開": "2022-05-24",
        "更新": "2026-07-25",
        "攻撃面": "vpn_gateway",
        "flags": ["kev", "exploited"],   // ビット列を展開した配列。バッジ表示される
        "prefix": "github"               // deep_links の {prefix} に入る
      }
    }
  ]
}
```

ポイント。

- `attrs` は「キー: 値」の形でそのまま表示されるので**日本語キー**にする
- `attrs.flags` は既存のビットマスク（`fixed=1 poc=2 exploited=4 kev=8 ransomware=16`）を
  文字列配列に展開したもの。ポータルはこれをバッジとして描画し、`kev` と `exploited` を警戒色にする
- `attrs.prefix` は現行の `prefix_dictionary` から引いた実際の文字列を入れる（インデックス番号ではなく）
- `_` で始まる `attrs` キーはポータルの内部用なので使わない
- `refs` は不要。CVE から製品・ベンダーへの辺は張らなくてよい
  （42k × 数件で肥大するわりに調査上の価値が薄い。`attrs` に文字列で入っていれば全文検索で引ける）

### 付随して直すもの

- `web/index.html` の fetch 先を `api/v1/viewer.json` に変更
- `web/openapi.yaml` を新しい構成に合わせて更新
- `src/vulnwatch/webapi.py` の共有ヘルパを両方の出力で使えるように整理
- `tests/test_webapi.py` に仕様 v1 出力のテストを足す

---

## 作業 2: `meta.json` に仕様 v1 のフィールドを足す

既存フィールドは残したまま、次を追加・変更する。

```jsonc
{
  "spec_version": "1.0",                 // 追加
  "app_id": "vuln-intel-agent",          // 追加
  "name": "脆弱性インテル",                // 追加（日本語表示名）
  "site_url": "https://proshiba.github.io/vuln-intel-agent/",   // 末尾スラッシュ必須

  "endpoints": {
    "meta": "api/v1/meta.json",
    "search": "api/v1/search.json",      // 仕様 v1 のファイルを指す
    "viewer_index": "api/v1/viewer.json" // ビューア専用（仕様外の拡張）
  },

  "deep_links": {
    "cve": "#/vuln/{detail}"             // 作業 3 で作るハッシュルート
  },

  "capabilities": ["iframe", "deep-link", "postmessage"],

  // 任意。ポータルが iframe 内に注入してヘッダーの二重化を防ぐ
  "embed_css": "…"
}
```

`stats` `attack_surfaces` `cors` などの既存フィールドはそのまま残してよい。

---

## 作業 3: ビューアに CVE 単位のディープリンクを作る

現在の `detail_url_template` は `raw.githubusercontent.com` の生 YAML を指している。
ポータルの検索結果から「詳細」を押すと生 YAML が開くことになり、体験が悪い。

`web/index.html` に `#/vuln/<vuln_id>`（または `#/cve/<CVE-ID>`）のハッシュルーティングを足し、
その ID の行を展開した状態でビューアを開けるようにする。ページ読み込み時に
`location.hash` を見て、該当行までスクロールして詳細行を開く、程度でよい。

実装したら `meta.json` の `deep_links.cve` をそこに向ける。
生 YAML へのリンクは `detail_url_template` として残してよい。

---

## 作業 4: 台帳を再生成する（データ品質）

`src/vulnwatch/vulndb.py` の `CSV_COLUMNS` は 26 列を定義しているが、
コミット済みの `vulndb/index.csv` は**古い 18 列のヘッダのまま**になっている。
そのため公開中の `search.json` では次のようになっている。

- `priority` が **42,171 件すべて `INFO`**（P1/P2/P3 が 1 件も無い）
- `ransomware_use` が全件欠落（stats の `ransomware` が 0）
- `kev_lag_days` が全件欠落（stats の `kev_lag` が 0）
- `attack_surface_class` も CSV には無く、`build_index.py` が分類器で導出して補っている

ポータル側では優先度フィルタが機能せず、ランサム利用の情報も出せない。
台帳を新しい列構成で再生成し、`index.csv` を更新すること。

再生成が重い、または別 PR に分けたい場合は、この作業だけ切り出してもよい。
その場合は PR にその旨を書き、`meta.json` の `stats` に実態が出ることを確認しておくこと。

---

## 検証

```bash
curl -sO https://raw.githubusercontent.com/proshiba/research_bench/main/docs/validate-index.py
python3 validate-index.py web/api/v1/meta.json web/api/v1/search.json
```

**エラー 0 件**にすること。あわせて次を確認する。

- エンティティ数が台帳の行数と一致すること
- gzip 後 3 MB 未満
- `attrs.優先度` に `P1`/`P2`/`P3` が現れること（作業 4 が済んでいれば）
- ビューア（`web/index.html`）が `viewer.json` を読んで従来どおり動くこと
- ビューアの postMessage プロトコル（`vulnwatch:query` など）が壊れていないこと
- 既存の pytest が通ること（`ruff` / `mypy` も含めて CI 相当）

---

## ブランチと PR

- ブランチ: `claude/portal-spec-v1`
- PR タイトル: `ポータル連携仕様 v1 に対応`
- PR 本文にバリデータの出力（エンティティ数・型の内訳・サイズ）を貼ること
- 作業 4 を分割した場合はその理由も書くこと

## やらないこと

- 収集パイプライン（`collect` / `summarize` / `report` / `publish`）のロジック変更
- ビューアの見た目の作り直し（ディープリンク追加以外）
- ポータル側（research_bench）の変更。索引が公開されたらポータル側で
  `apps.json` の `adapter` を `spec-v1` に切り替える
