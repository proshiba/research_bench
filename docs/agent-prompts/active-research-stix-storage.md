# STIX ストレージ連携の状況（Active Research API）

**依頼した分はすべて入りました。ポータル側も実仕様に合わせて実装済みで、
現時点で API 側にお願いしたいことはありません。**

このファイルは、何をどう使っているかの記録として残します。
仕様を変えるときにここを見れば、ポータルのどこが壊れるか分かるようにしてあります。

---

## 対応いただいた経緯

| 依頼 | 状態 |
| --- | --- |
| 題・説明・サムネイルを一次情報として持つ | ✅ `graphTitle` / `graphDescription` / `thumbnail` |
| 一覧にそれらを載せる（一覧を 1 リクエストにしたい） | ✅ 載った |
| `/api/meta` で対応を知らせる | ✅ `search_fields` / `thumbnail` / `limits` / `pagination` |
| 一覧のページング | ✅ `offset` + `total` + `hasMore` |
| サムネイルの `ETag` | ✅ `ETag` = 画像の SHA-256、`If-None-Match` で 304 |

こちらの当初案より良くなった点が 3 つありました。

- **サムネイルを一覧に埋め込まず、取得 URL とメタデータだけ返す形。**
  当初は base64 を一覧に載せる前提で書いていましたが、それだと 20 件で数 MB になります
- **検索（`?q=`）が STIX の `name` まで見る。** 題を付け忘れた保存も、
  中身のマルウェア名やアクター名から辿れます
- **一覧の `thumbnail.sha256` が `ETag` と同じ値。**
  ポータルはこれを画像の控えの鍵に使っていて、**中身が変わっていない画像は
  条件付き GET すら発生しません**（下記）

---

## ポータルが今どう使っているか

| 操作 | 呼んでいるもの |
| --- | --- |
| 保存 | `POST`（`visibility` / `graphTitle` / `graphDescription` / `thumbnail` / `stix`） |
| 更新 | `PUT ?id=`。題・説明・画像は毎回送る（UI 上は常に入力があるため） |
| 一覧 | `GET ?visibility=…&limit=…&offset=…&q=…` |
| 続きを読む | 応答の `hasMore` が真なら「さらに読み込む」を出し、`offset` に今の件数を渡す |
| 画像 | `GET ?id=…&asset=thumbnail` を `fetch` して blob → オブジェクト URL |
| 復元 | `GET ?id=…` の `stix` から後述の `x_rb_graph` を読む |
| 削除 | `DELETE ?id=` |

### 上限は `/api/meta` から取る

`limits` / `thumbnail` / `pagination` を起動後に読み込み、
**ポータル側の既定値を上書き**します（`assets/js/stix-store.js` の `loadLimits()`）。

そのため、**API 側で上限を変えてもポータルは追従します。**
取得に失敗したときだけ、実測に合わせた既定値のまま動きます。

送る前に確かめているもの。

- STIX 本体が `limits.stix_max_bytes` を超えていないか
- サムネイルが `thumbnail.max_bytes` を超えていないか
- サムネイルの形式が `thumbnail.content_types` に入っているか
  （入っていなければ**画像だけ諦めて本体は保存する**。保存ごと失敗させない）
- 題を `limits.title_max`、説明を `limits.description_max`、`q` を `limits.q_max` で切る

サムネイルは **WebP を優先**して送っています（Canvas が WebP を吐けない環境では JPEG）。
640px 幅・品質 0.8 で、実測 **4 KiB 前後**。

### 画像のキャッシュ

**ポータル側では条件付き GET を組んでいません。** `ETag` と `Cache-Control` を
付けていただいたので、2 回目以降の `fetch` はブラウザが自動で `If-None-Match` を
付けて 304 に落とします。

> 実測: `private, max-age=0, must-revalidate` + `Authorization` の組み合わせでも、
> Chromium は保存して再検証し **304 になります**。`public, max-age=300` のほうは
> そもそも再要求しません。（`Authorization` 付きの応答が私用キャッシュに入るか
> 確信が持てなかったので、実ネットワーク経路で確かめました。）

その手前に、**`id:sha256` を鍵にしたオブジェクト URL の控え**を持っています。
一覧を開き直しても、画像の中身が変わっていなければ**要求そのものが出ません**。
`thumbnail.sha256` を返していただいたおかげです。

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
   これが無いと「復元」が「STIX の取り込み直し」に落ちて配置が変わります。
   **ここは今のままで結構です**（API に持たせるべき情報とは思っていません）
2. **`name` / `description`** — API 側にも同じものが入りますが、
   **束だけを他の STIX ツールへ渡したときにも題と説明が読めるように**残しています

画像は `report` には入れていません（API 側と二重持ちになるため）。
なお**初期のポータルが保存した分には `x_rb_screenshot` が入っています**。
互換のため読み側だけ残してあります。

---

## こちらで確認したこと

公開環境（`https://hellow-world.hiroshiba.chatgpt.site`）に対して、匿名でできる範囲を実測しました。

| | 結果 |
| --- | --- |
| `GET ?visibility=public&limit=5&offset=0` | ✅ `{"ok":true,"count":0,"total":0,"limit":5,"offset":0,"hasMore":false,…}` |
| `GET ?offset=2000000` | ✅ 400 `offset must be an integer from 0 to 1000000` |
| `GET ?offset=-1` | ✅ 400（同上） |
| `GET ?limit=500` | ✅ 400 `limit must be an integer from 1 to 100` |
| `GET ?q=`（201 文字） | ✅ 400 `q must be at most 200 characters` |
| `GET ?id=…&asset=thumbnail`（無い id） | ✅ 404・`cache-control: no-store` |
| `Access-Control-Expose-Headers` | ✅ `etag` が入っている |
| `GET ?visibility=me` / `POST` / `PUT`（匿名） | ✅ 401 `authentication_required` |

**上記の 400 はいずれもポータルからは踏みません**（`limit` / `offset` / `q` を
送る前に丸めています）。API 側が弾いてくれること自体は確認しました。

**書き込みは実 API では試せていません。** ログインが必要で、
こちらの確認環境から GitHub の認証画面を通せないためです。
`/api-docs` の契約に合わせたモックを実 UI に通して、
**ポータルが送る要求の中身が仕様どおりであること**までは確認しています。

実キーでの通し確認をされる際、次の 3 点だけ見ていただけると確実です。

1. `POST` した直後の一覧に、**題・説明・`thumbnail.url` と `thumbnail.sha256` が載ること**
2. `PUT` で**題だけ変えたとき、画像が消えないこと**
   （ポータルは毎回 3 つとも送るので普段は起きませんが、仕様の確認として）
3. `me` で保存したものの `asset=thumbnail` が、**別アカウントからは 404 になること**
