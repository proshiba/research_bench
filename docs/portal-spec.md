# research_bench ポータル連携仕様 v1

セキュリティ調査用の各アプリを 1 つのポータル（`research_bench`）から横断的に扱うための取り決め。

この仕様は **サーバーを立てないこと** を前提にしている。各アプリはビルド時に静的 JSON を吐き、
ポータルはそれを `fetch()` して手元で索引する。アプリ同士は互いを一切知らない。
横串は「同じ値が複数ソースに現れたこと」をポータル側が検出して作る。

```
  ai-security-analysis ─┐
  vuln-intel-agent     ─┼─→ 各自が静的JSONを公開 ─→ research_bench が取得・正規化・結合
  threatactor-intel-…  ─┘                              （ダッシュボード / クロスサーチ / ワークベンチ）
```

---

## 1. アプリが公開するもの

準拠アプリは公開サイトのルート直下に 2 ファイルを置く。

| パス | 役割 |
| --- | --- |
| `api/v1/meta.json` | 自己紹介。ポータルが最初に読む |
| `api/v1/search.json` | 索引本体。エンティティの配列 |

どちらも CORS が開いていること（GitHub Pages はデフォルトで `access-control-allow-origin: *`）。

### 1.1 `meta.json`

```jsonc
{
  "spec_version": "1.0",
  "app_id": "ai-security-analysis",      // ポータル内で一意。リポジトリ名を推奨
  "name": "マルウェア解析",               // 日本語表示名
  "description": "…",
  "generated_at": "2026-07-26T04:20:21Z",
  "repository": "https://github.com/proshiba/AI-security-analysis",
  "site_url": "https://proshiba.github.io/AI-security-analysis/ui/",

  "endpoints": {
    "search": "api/v1/search.json"        // site_url からの相対
  },

  // エンティティ種別 → 詳細ページの URL テンプレート。
  // {detail} に entity.detail（未指定なら entity.id）を URL エンコードして埋める。
  // site_url からの相対、または絶対 URL。
  "deep_links": {
    "case":     "#/case/{detail}",
    "family":   "#/family/{detail}",
    "campaign": "#/intel/{detail}",
    "ioc.ipv4": "#/iocs?q={detail}"
  },

  // 任意。宣言した機能だけポータルが使う
  "capabilities": ["iframe", "deep-link", "graph", "embed-mode"],

  // 任意。iframe 埋め込み時にポータルが注入する CSS（同一オリジンのときのみ有効）
  "embed_css": "header.site-header, footer { display: none !important; }",

  "stats": { "case": 1125, "ioc": 1952 }   // 任意。ダッシュボードのタイルに使う
}
```

### 1.2 `search.json`

```jsonc
{
  "spec_version": "1.0",
  "app_id": "ai-security-analysis",
  "generated_at": "2026-07-26T04:20:21Z",
  "entities": [ /* §2 */ ]
}
```

大きくなるので gzip 転送前提。目安として 5 MB（非圧縮）を超えるなら
本文（README 全文など）は載せず、`deep_links` で本体に飛ばす。

---

## 2. エンティティ

索引の 1 レコード。**アプリ固有の概念を、横串が刺せる粒度に落としたもの**を並べる。

```jsonc
{
  "type": "ioc.ipv4",              // §2.1 の語彙から選ぶ（必須）
  "id": "ip:45.61.136.14",         // ソース内で一意（必須）
  "label": "45.61.136.14",         // 画面表示用（必須）
  "value": "45.61.136.14",         // 結合キー。省略時は label を使う
  "detail": "45.61.136.14",        // deep_links テンプレートに埋める値。省略時は id
  "attrs": {                       // 表示用の補足。自由キー
    "role": "C2",
    "confidence": "confirmed"
  },
  "refs": [                        // 同一ソース内の他エンティティへの辺
    { "rel": "C2/通信", "target": "case:8f2a1c9d…" }
  ]
}
```

- `refs[].target` は **同じソース内の `id`**。他ソースの id を書いてはいけない。
- ソースをまたぐ関係はポータルが `value` の一致から自動生成する（§3）。

`attrs` は自由キーだが、次の 2 つだけ意味が決まっている。

| キー | 型 | 扱い |
| --- | --- | --- |
| `attrs.flags` | 文字列の配列 | 検索結果でバッジとして表示する（例 `["kev","exploited"]`）。`kev` と `exploited` は警戒色になる |
| `attrs.prefix` | 文字列 | `deep_links` のテンプレート変数 `{prefix}` に入る |

`_` で始まるキーはポータルの内部用。producer 側では使わないこと。
それ以外のキーは「キー名: 値」の形でそのまま表示されるので、**日本語のキー名を推奨**する。

### 2.1 `type` の語彙

| type | 意味 | `value` の正規化 |
| --- | --- | --- |
| `ioc.ipv4` / `ioc.ipv6` | IP アドレス | そのまま |
| `ioc.domain` | ドメイン | 小文字化・defang 解除・末尾ドット除去 |
| `ioc.url` | URL | 小文字スキーム・defang 解除 |
| `ioc.endpoint` | `host:port` | 小文字化 |
| `ioc.email` | メールアドレス | 小文字化 |
| `ioc.md5` / `ioc.sha1` / `ioc.sha256` / `ioc.sha512` | ファイルハッシュ | 小文字 16 進 |
| `cve` | 脆弱性識別子 | 大文字 `CVE-YYYY-NNNN` |
| `actor` | 脅威アクター | 英数字のみ・小文字（§3） |
| `malware` | マルウェアファミリ / ツール名 | 同上 |
| `case` | 検体 1 件の解析ケース | ハッシュなら小文字 16 進 |
| `campaign` | キャンペーン / 相関クラスタ | そのまま |
| `product` / `vendor` | 製品・ベンダー | 小文字化 |
| `ttp` | ATT&CK テクニック | 大文字 `T####[.###]` |
| `report` | レポート・記事 | そのまま |

語彙にないものは `type` を増やす前にポータル側と相談すること。
未知の `type` を受け取ったポータルは、その値を「その他」として表示するだけで落ちてはいけない。

### 2.2 defang の扱い

索引に載せる `value` は **必ず refang 済み**（`1.2.3[.]4` ではなく `1.2.3.4`）にする。
画面表示用に defang したい場合は `label` 側で行う。ポータルは検索時に
入力値の defang を解除してから突き合わせる。

---

## 3. ポータルがやること（ソース横断の結合）

ポータルは全ソースのエンティティを読み込んだあと、`value` を正規化キーに変換して束ねる。

```
normalizeKey(type, value):
  ioc.*        → 小文字化 + refang
  cve          → 大文字化
  actor/malware→ 小文字化して英数字以外を除去   ("ValleyRAT" → "valleyrat")
  それ以外      → 小文字化
```

同じキーに **2 つ以上のソース** のエンティティがぶら下がったら、それは横串。
UI では二重リング・破線エッジ・「ソース横断」バッジで明示する。

これがポータルの中心的な価値なので、**各アプリは結合可能な値をできるだけ索引に載せてほしい**。
特に:

- マルウェアファミリ名（`malware`）— アクター情報とマルウェア解析をつなぐ唯一の橋
- CVE — 脆弱性インテルとアクター情報をつなぐ
- IP / ドメイン / ハッシュ — 全ソース共通

---

## 4. iframe 埋め込み

ポータルはダッシュボードモードで各アプリを iframe 表示する。

- `X-Frame-Options` / CSP `frame-ancestors` を設定しないこと。
- GitHub Pages のプロジェクトページは **すべて同一オリジン**（`https://<user>.github.io`）なので、
  ポータルは iframe の DOM に触れる。`meta.json` の `embed_css` はこれを利用して
  アプリ側のヘッダー/フッターを隠し、クロームの二重化を防ぐ。
- 将来的には各アプリが `?embed=1` を解釈して自前でクロームを省く方式（`capabilities` に
  `embed-mode`）が望ましい。`embed_css` はそれまでの繋ぎ。

---

## 5. 現状と移行

2026-07 時点で **3 アプリとも spec v1 にネイティブ対応済み**。ポータルは `apps.json` で
`adapter: "spec-v1"` を指定し、各アプリの `meta.json` を起動時に読んでから
`search.json` を遅延ロードしている。

| ソース | エンティティ | search.json | 備考 |
| --- | --- | --- | --- |
| ai-security-analysis | 1,778 | 0.84 MB (gzip 0.12) | case 1,125 / malware 74 / campaign 26 / IOC 553 |
| vuln-intel-agent | 42,171 | 18.4 MB (gzip 2.26) | cve 36,377 / report 5,794 |
| threatactor-intel-analysis | 17,163 | 3.9 MB (gzip 0.58) | actor 673 / malware 1,090 / IOC 14,555 / cve 48 |

合計 61,112 エンティティ。ブラウザでの索引構築は 3 ソース並列で約 7 秒。

`assets/js/adapters.js` には旧フォーマット用のアダプタ（`maldb` / `vulnwatch` / `threatactor`）
も残してある。各アプリが spec v1 を出す前の形式に戻す必要が生じたときの退避用で、
`apps.json` の `adapter` を切り替えれば使える。

### 5.1 残っている課題

- **vuln-intel-agent の優先度**: `vulndb/index.csv` は 26 列に移行済みだが、
  `priority` が全 42,171 件 `INFO` のまま。`ransomware_use` は全件 `false`、
  `kev_lag_days` は全件空。KEV 688 件・悪用観測 1,173 件があるので、
  優先度の導出処理が動いていないと思われる。ポータル側では優先度フィルタが機能しない。
- **アクター情報の CVE が 48 件**: `capabilities.vulnerabilities` が入っている
  プロファイルが少ないため。脆弱性インテルとの横串はまだほとんど刺さらない。
- **`ioc.sha512`**: 仕様の初版にこの型が無く、threatactor 側では SHA-512 を
  `ioc.sha256` として出している（18 件）。仕様に型を追加したので、
  次回の索引再生成で `ioc.sha512` に直してもらう。ハッシュ長が違うため誤結合は起きない。

## 5.2 適合チェック

生成した 2 ファイルは [`validate-index.py`](validate-index.py) で検査できる。標準ライブラリだけで動く。

```bash
curl -sO https://raw.githubusercontent.com/proshiba/research_bench/main/docs/validate-index.py
python3 validate-index.py ui/api/v1/meta.json ui/api/v1/search.json
```

必須フィールドの欠落、`id` の重複、`refs.target` の解決漏れ、defang されたままの値、
型ごとの表記ゆれを検出し、エンティティ数・結合キー率・gzip 後のサイズを表示する。
エラーが 1 件でもあれば終了コード 1 を返すので CI に組み込める。

## 6. ポータル側の登録

`apps.json` にソースを 1 件足すだけで増設できる。

```jsonc
{
  "spec_version": "1.0",
  "sources": [
    {
      "app_id": "ai-security-analysis",
      "name": "マルウェア解析",
      "accent": "mal",                 // mal | vuln | actor | 追加時は style.css にも定義
      "site_url": "https://proshiba.github.io/AI-security-analysis/ui/",
      "dashboard_url": "https://proshiba.github.io/AI-security-analysis/ui/#/",
      "adapter": "maldb",              // spec-v1 | maldb | vulnwatch | threatactor
      "index_url": "…",                // adapter が spec-v1 のときは meta.json から解決
      "approx_bytes": 6980509,         // ロード進捗の表示に使う
      "deep_links": { … },             // spec-v1 対応前はここに直書き
      "embed_css": "…"
    }
  ],
  "tools": [
    { "tool_id": "cyberchef", "name": "CyberChef", "url": "cyberchef/build/prod/index.html" }
  ]
}
```

`tools` はダッシュボードのアプリ一覧には出ない。ワークベンチの変換モジュールから使う。

---

## 7. 変換モジュール（CyberChef）

ワークベンチで選択したノードの値を、その場で復号・デコードするための機能。

- ポータルに内蔵の軽量変換（Base64 / Hex / URL / defang / XOR / gunzip / IOC 抽出 など）は
  外部依存なしで即座に動く。
- それ以上は **同梱の CyberChef** に値を渡す。`cyberchef/build/prod/index.html#input=<base64>`。
- 調査対象の値を外部サービスに送らないため、**公開インスタンスにはフォールバックしない**。
  ローカルビルドが無い場合はビルド手順を案内するだけに留める。
