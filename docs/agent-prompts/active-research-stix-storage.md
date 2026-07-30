# STIX ストレージ連携の状況と、残っている依頼（Active Research API）

## まず: 依頼した分はすべて入りました

`graphTitle` / `graphDescription` / `thumbnail` と、一覧への反映・検索・
公開範囲の適用まで対応いただきました。**ポータル側は実仕様に合わせて実装済み**です。

こちらの当初の想定より良くなった点が 2 つあります。

- **サムネイルを一覧に埋め込まず、取得 URL とメタデータだけ返す形にしていただいた。**
  当初は base64 を一覧に載せる前提で書いていましたが、その形だと 20 件で数 MB になります。
  URL 方式なら一覧は軽いまま、画像は必要になったものだけ取れます
- **検索（`?q=`）が STIX の `name` まで見てくれる。** 題を付け忘れた保存も、
  中身のマルウェア名やアクター名から辿れます

**当初お願いしていた「一覧を 1 リクエストにしたい」は解消しました。**
以前は一覧を出すのに保存件数ぶんの GET が要りましたが、いまは 1 回で済んでいます。
STIX 本体も、画像を外に出したぶん **1 件あたり 8 KB → 3 KB** に減りました。

---

## ポータルが今どう使っているか

| 操作 | 呼んでいるもの |
| --- | --- |
| 保存 | `POST`（`visibility` / `graphTitle` / `graphDescription` / `thumbnail` / `stix`） |
| 更新 | `PUT ?id=`。**題・説明・画像は毎回送る**（省略＝現在値保持の仕様は理解した上で、UI 上は常に入力があるため） |
| 一覧 | `GET ?visibility=…&limit=100&q=…` |
| 絞り込み | 同上の `q`。**200 文字で切ってから送る**（超えると 400 になるため） |
| 画像 | `GET ?id=…&asset=thumbnail` を `fetch` して blob → オブジェクト URL |
| 復元 | `GET ?id=…` の `stix` から後述の `x_rb_graph` を読む |
| 削除 | `DELETE ?id=` |

サムネイルは **PNG/JPEG/WebP のうち WebP を優先**して送っています
（Canvas が WebP を吐けない環境では JPEG に落とす）。640px 幅・品質 0.8 で、
実測 **4 KiB 前後**。上限 512 KiB には十分収まっています。

### STIX の中に 1 つだけ足しているもの

束の先頭に `report` オブジェクトを 1 つ入れています。**これは消さないでください。**

```jsonc
{ "type": "report", "spec_version": "2.1",
  "name": "…", "description": "…", "published": "…",
  "object_refs": [ /* 束の中の全オブジェクト */ ],
  "x_rb_app": "research_bench",
  "x_rb_graph": { /* ノードの配置・ピン・調査対象トレイ */ } }
```

用途は 2 つです。

1. **`x_rb_graph`** — グラフの配置と調査対象トレイ。API 側にこれを置く欄は無く、
   これが無いと「復元」が「STIX の取り込み直し」に落ちて配置が変わります
2. **`name` / `description`** — API 側にも同じものが入りますが、
   **束だけを他の STIX ツールへ渡したときにも題と説明が読めるように**残しています

画像は `report` には入れていません（API 側と二重持ちになるため）。
なお**以前のポータルが保存した分には `x_rb_screenshot` が入っています**。
互換のため読み側だけ残してあります。

---

## 残っている依頼

### ① 一覧のページング（優先度: 中）

`limit` の上限が 100 で、**オフセットやカーソルが無い**ようです。
保存が 100 件を超えると、ポータルからは古いものに到達できなくなります。

いますぐ困ってはいませんが、貯まると効いてくるので、どこかで次のどちらかを
入れていただけると助かります。

- `cursor`（`next_cursor` を返す方式）
- あるいは `offset` + 応答に `total`

どちらでも構いません。**`total` だけでも先に欲しい**です。
「100 件出しているが全部ではない」ことを画面で断れるようになります。

### ② サムネイルのキャッシュ指示（優先度: 低）

`?id=…&asset=thumbnail` の応答に `ETag` か `Cache-Control` は付いていますか。

`me` の画像は `Authorization` が要る関係で、ポータルは `<img src>` ではなく
`fetch` で取ってオブジェクト URL にしています。**一覧を開き直すたびに
取り直しになる**ので、`ETag` があれば条件付き GET で 304 に落とせます。

（`raw=true` の STIX 取得には `ETag` を付けていただいているので、
画像にも同じ扱いがあると嬉しい、という程度の話です。）

### ③ `/api/meta` にサムネイルの制約も載せる（優先度: 低）

`search_fields` を載せていただいたのは助かりました。同じように、
**サムネイルの上限と受け付ける形式**も機械可読にしていただけると、
ポータル側で数値を二重に持たずに済みます。

```jsonc
{
  "id": "stix",
  "search_fields": ["graphTitle", "graphDescription", "name"],
  "thumbnail": { "max_bytes": 524288, "content_types": ["image/png", "image/jpeg", "image/webp"] },
  "limits": { "stix_max_bytes": 10485760, "title_max": 200, "description_max": 5000, "q_max": 200 }
}
```

いまはポータル側に同じ数字を直書きしています（`assets/js/stix-store.js`）。
**API 側が変わったときに気づけない**のが唯一の懸念です。

---

## こちらで確認したこと

公開環境（`https://hellow-world.hiroshiba.chatgpt.site`）に対して、匿名でできる範囲を実測しました。

| | 結果 |
| --- | --- |
| `GET ?visibility=public&limit=50` | ✅ 200 `{"ok":true,"visibility":"public","count":0,"query":"","objects":[]}` |
| `GET ?visibility=public&q=operation` | ✅ 200・`query` がそのまま返る |
| `GET ?q=`（201 文字） | ✅ 400 `q must be at most 200 characters` |
| `GET ?id=…&asset=thumbnail`（無い id） | ✅ 404 `STIX object not found` |
| `GET ?visibility=me`（匿名） | ✅ 401 `authentication_required` |
| `POST` / `PUT`（匿名） | ✅ 401 `authentication_required` |
| `www-authenticate` の露出 | ✅ `Access-Control-Expose-Headers` に入っている |
| プリフライト | ✅ `GET, POST, PUT, DELETE, OPTIONS` |

**書き込みは実 API では試せていません。** ログインが必要で、
こちらの確認環境から GitHub の認証画面を通せないためです。
`/api-docs` の契約に合わせたモックを実 UI に通して、
**ポータルが送る要求の中身が仕様どおりであること**までは確認しています。

実キーでの通し確認をされる際、次の 3 点だけ見ていただけると確実です。

1. `POST` した直後の一覧に、**題・説明・`thumbnail.url` が載ること**
2. `PUT` で**題だけ変えたとき、画像が消えないこと**
   （ポータルは毎回 3 つとも送るので普段は起きませんが、仕様の確認として）
3. `me` で保存したものの `asset=thumbnail` が、**別アカウントからは 404 になること**
