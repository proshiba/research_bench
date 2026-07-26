# research_bench

セキュリティ調査用に別々のリポジトリで作っているアプリを、1 つの画面から横断して扱うためのポータル。

サーバーは立てない。各アプリは静的 JSON を公開し、ポータルはそれを `fetch()` して
手元で索引・結合する。ポータル自身も依存ゼロのバニラ JS で、ビルド工程は無い。

```
  ai-security-analysis ─┐
  vuln-intel-agent     ─┼─→ 各自が静的インデックスを公開 ─→ research_bench が取得・正規化・結合
  threatactor-intel-…  ─┘
```

## 3 つのモード

| | 役割 |
| --- | --- |
| **ダッシュボード** | 各アプリの画面を iframe で表示する。上部のセレクタで切り替え |
| **クロスサーチ** | 全ソースを横断して IP・ドメイン・ハッシュ・CVE・アクター名などを検索 |
| **ワークベンチ** | 検索結果や手入力を起点にグラフで辿る。選択した値をその場で変換できる |

同じ実体が複数のソースに現れたとき、ワークベンチでは 1 つのノードに畳まれ、
二重リングと破線のエッジで「ソース横断」であることを示す。これがポータルの中心的な価値。

配色は、クロームを無彩色に保ち、色は「どのソース由来か」の符号化にだけ使っている。
索引に無い値を手で足したノードは無彩色（灰）で、出所が無いことがそのまま見て分かる。

ワークベンチ左端の**調査対象トレイ**に IP・ドメイン・ハッシュを足すとグラフに載る。
索引に見つかればその全ソースの実体が、見つからなければ手動ノードとして置かれる。
トレイは折りたためる。トレイとグラフの状態は `localStorage` に保存するので、
別のモードに移ってもリロードしても続きから調査できる。「クリア」で消える。

## 動かす

```bash
python3 -m http.server 8000
# → http://localhost:8000/
```

索引はソース別に遅延ロードする（クロスサーチかワークベンチに入ったとき）。
初回は合計 18 MB 前後を取得するので少し待つ。進捗は下部のステータスバーに出る。

変換モジュールは内蔵の軽量変換（Base64 / Hex / URL / Gunzip / XOR / Strings / Refang /
IOC 抽出 など 19 種）だけで動く。外部依存は無い。

同梱の CyberChef は現在ポータルの UI からは呼んでいない。使うなら単体でビルドして開く。

```bash
cd cyberchef && npm ci && npx grunt prod
```

## ソースを増やす

`apps.json` に 1 件足すだけ。書式と、各アプリが公開すべき `meta.json` / `search.json` の
仕様は [`docs/portal-spec.md`](docs/portal-spec.md) にある。

## 現状

**3 アプリとも spec v1 にネイティブ対応済み。** ポータルは起動時に各アプリの `meta.json` を
読み（`deep_links` と `embed_css` はここから来る）、`search.json` は画面に入ったときに遅延ロードする。

| ソース | エンティティ | search.json |
| --- | --- | --- |
| ai-security-analysis | 1,778 | 0.84 MB (gzip 0.12) |
| vuln-intel-agent | 42,171 | 18.4 MB (gzip 2.26) |
| threatactor-intel-analysis | 17,163 | 3.9 MB (gzip 0.58) |

合計 61,112 エンティティ。索引構築は 3 ソース並列で約 4 秒。

横串は実データで成立している。マルウェア名の表記ゆれも正規化で吸収する。

| 検索語 | 結果 |
| --- | --- |
| `ShadowPad` | マルウェア解析 + アクター情報 |
| `gh0st RAT` | マルウェア解析(`gh0strat`) + アクター情報 |
| `Agent Tesla` | マルウェア解析(`agenttesla`) + アクター情報 |
| `WannaCry` / `Amadey` | 2 ソース |

ワークベンチで `ShadowPad` を 2 段展開すると、
**マルウェア解析の 8 ケース ← ShadowPad → アクター情報の 11 アクター** が 1 枚のグラフになる。

残課題は [`docs/portal-spec.md` §5.1](docs/portal-spec.md) にまとめてある
（脆弱性台帳の優先度が全件 INFO のままなど）。

## 中身

```
index.html            ポータルの外枠
apps.json             ソース登録
assets/style.css
assets/js/
  main.js             起動・ルーティング・クローム
  store.js            登録・遅延ロード・索引・クロスサーチ
  adapters.js         各アプリの既存フォーマット → spec v1 の正規化
  graph.js            ワークベンチのグラフ（力学レイアウト + Canvas）
  transform.js        変換モジュール（内蔵変換 + CyberChef 引き渡し）
  view-*.js           各モードの描画
  util.js
docs/portal-spec.md   連携仕様 v1
docs/validate-index.py  各アプリが自分の索引を検査するためのチェッカー
docs/agent-prompts/   各アプリへの依頼内容（spec v1 対応）
docs/mock/            最初に起こした画面イメージ
cyberchef/            同梱の CyberChef（変換モジュールの引き渡し先）
```
