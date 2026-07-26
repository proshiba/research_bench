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
| **ワークベンチ** | 検索結果を起点にグラフで辿る。選択した値をその場で変換できる |

同じ実体が複数のソースに現れたとき、ワークベンチでは 1 つのノードに畳まれ、
二重リングと破線のエッジで「ソース横断」であることを示す。これがポータルの中心的な価値。

配色は、クロームを無彩色に保ち、色は「どのソース由来か」の符号化にだけ使っている。

## 動かす

```bash
python3 -m http.server 8000
# → http://localhost:8000/
```

索引はソース別に遅延ロードする（クロスサーチかワークベンチに入ったとき）。
初回は合計 18 MB 前後を取得するので少し待つ。進捗は下部のステータスバーに出る。

ワークベンチの変換モジュールから CyberChef を開くには、先にビルドが要る。

```bash
cd cyberchef && npm ci && npx grunt prod
```

未ビルドのときは変換パネルにその旨とコマンドが出る。調査対象の値を外部に送らないため、
公開インスタンスにはフォールバックしない。

## ソースを増やす

`apps.json` に 1 件足すだけ。書式と、各アプリが公開すべき `meta.json` / `search.json` の
仕様は [`docs/portal-spec.md`](docs/portal-spec.md) にある。

## 現状

spec v1 にネイティブ対応したアプリはまだ無い。ポータルは**アダプタ**を挟んで
各アプリの既存フォーマットをその場で正規化している（`assets/js/adapters.js`）。
アプリ側が `api/v1/search.json` を出したら `apps.json` の `adapter` を `spec-v1` に
変えるだけで、ポータルのコードは触らない。

実データで確認した索引規模と、いま横串が刺さる範囲:

| ソース | 索引 | 横串の状況 |
| --- | --- | --- |
| ai-security-analysis | 1,785 | IOC・ファミリ名で結合可能 |
| vuln-intel-agent | 42,171 | CVE で結合可能（相手側が CVE を出せば） |
| threatactor-intel-analysis | 673 | 索引はアクター名と別名のみ。マルウェア名・IOC・CVE が無い |

そのため **索引だけでは今のところ横串が 0 件**で、ワークベンチでアクターノードを
展開したときに `profiles/<slug>/` を遅延取得して初めて結合する。
（例: APT41 → ShadowPad → マルウェア解析側の 8 ケース）

これを索引レベルでも効くようにするための各アプリへの要望は
[`docs/portal-spec.md` §5.1](docs/portal-spec.md) にまとめてある。

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
docs/mock/            最初に起こした画面イメージ
cyberchef/            同梱の CyberChef（変換モジュールの引き渡し先）
```
