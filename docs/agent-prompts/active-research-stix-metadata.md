# 依頼: STIX ストレージに題・説明・サムネイルを持たせる（Active Research API）

## 背景

ポータル `proshiba/research_bench` から `/api/stix/objects` を使い、
**ワークベンチで作った調査グラフを保存・一覧・復元・削除**できるようにした。
実装は済んでいて、今の API のまま動く。

ただ 1 点だけ、一覧の作りが苦しい。

**API が保存するのは STIX JSON だけで、題・説明・画面写真を入れる欄が無い。**
そのため今はそれらを **STIX bundle の中の `report` オブジェクト**に載せている。

```jsonc
{
  "type": "bundle",
  "id": "bundle--…",
  "objects": [
    {
      "type": "report", "spec_version": "2.1", "id": "report--…",
      "name": "APT41 の C2 インフラ",              // ← 題
      "description": "45.66.228.114 を起点に…",     // ← 説明
      "published": "2026-07-30T05:20:00.000Z",
      "object_refs": ["ipv4-addr--…", "domain-name--…"],
      "x_rb_app": "research_bench",
      "x_rb_screenshot": "data:image/jpeg;base64,…",  // ← 画面写真（約 6 KB）
      "x_rb_graph": { /* ノードの配置など、ポータル側の復元用 */ }
    },
    /* 以下、調査結果の実体と関係 */
  ]
}
```

`report` は STIX 2.1 の正規の SDO なので、**他の STIX ツールから読んでも題と説明が
そのまま見える。**この構造自体は変えるつもりがない。

## 何が困っているか

**一覧を出すのに、保存件数ぶんの GET が要る。**

`GET /api/stix/objects?visibility=me` が返すのはメタデータだけで、
題・説明・画面写真はどれも STIX 本体の中にある。よって一覧画面は

1. 一覧を 1 回引く
2. **1 件ずつ `?id=…` を引いて本体を取り、report から題を読む**

という形になる。20 件保存していれば 21 リクエスト、しかも本体には画面写真と
配置情報が入っているので 1 件あたり数十 KB〜。

ポータル側は控えを `localStorage` に持って 2 回目以降を省いているが、
**初回と別端末では毎回これが走る。**

---

## お願いしたいこと

### ① 書き込み時に、題・説明・サムネイルを受け取る

`POST /api/stix/objects` と `PUT /api/stix/objects?id=…` の本文に、
既存の `visibility` / `stix` と並べて次を受け付けてほしい。

| 名前 | 型 | 必須 | 備考 |
| --- | --- | --- | --- |
| `name` | string | いいえ | 題。200 文字程度で切ってよい |
| `description` | string | いいえ | 説明。2,000 文字程度で切ってよい |
| `thumbnail` | string (data URI) | いいえ | `data:image/jpeg;base64,…`。**200 KB を上限にしてよい**（ポータルが送るのは 5〜30 KB 程度） |

**いずれも無指定を許してほしい。** ポータル以外が素の STIX を置くこともあるため。

> **代案**: `name` と `description` は、bundle の中に `report` があればそこから
> サーバー側で写し取る、という作りでも構いません（ポータルは必ず `report` を入れます）。
> その場合 `thumbnail` だけ明示的に受け取ってください。画像は本体から抜き出すのが
> 重くなるためです。どちらが実装しやすいかで選んでください。

### ② 一覧に、その 3 つを載せる

`GET /api/stix/objects?visibility=…` の `objects[]` に `name` / `description` /
`thumbnail` を含めてほしい。**これが本題です。**これだけで一覧が 1 リクエストになります。

```jsonc
{
  "ok": true, "visibility": "me", "count": 2,
  "objects": [
    {
      "id": "550e8400-…",
      "name": "APT41 の C2 インフラ",          // ← 追加
      "description": "45.66.228.114 を起点に…",  // ← 追加
      "thumbnail": "data:image/jpeg;base64,…",  // ← 追加
      "stixId": "bundle--…", "stixType": "bundle", "visibility": "me",
      "owner": { "login": "example-user" },
      "sha256": "…", "sizeBytes": 8192, "objectCount": 5,
      "createdAt": "…", "updatedAt": "…", "canWrite": true
    }
  ]
}
```

`thumbnail` が一覧を重くするのが気になる場合は、
**`?include=thumbnail` のような明示指定でも構いません。**その場合はその旨を
`/api/meta` に書いてください（下記③）。

### ③ `/api/meta` で対応を知らせる

ポータルは**移行期間中も壊れないように作ってあります**。一覧に `name` があれば
それを使い、無ければ本体を取りに行きます。書き込み側だけは、対応が入ったことを
知ってから送りたいので、`stix` ツールの定義に足してください。

```jsonc
{
  "id": "stix",
  "path": "/api/stix/objects",
  "visibility": ["public", "me"],
  "metadata_fields": ["name", "description", "thumbnail"],   // ← これ
  "thumbnail_max_bytes": 204800,                             // ← 任意
  "operations": { /* 既存のまま */ }
}
```

これがあれば、ポータルは自動で書き込み側も切り替えます。

---

## やらないでほしいこと

- **`stix` 本文の構造には触れないでください。** `report` オブジェクトはポータルが
  自分で組み立てて入れます。サーバー側で足したり消したりしないでください
- **既存の応答フィールドを消さないでください。** `sizeBytes` / `objectCount` /
  `sha256` / `canWrite` は今の一覧画面が使っています
- 認証の要件は今のままで結構です（public の読み取りだけ匿名、
  me の読み取りと書き込みは常に必須）。**この切り分けは適切だと思います**

---

## ポータル側の現状（参考）

実装済みで、今の API のまま動いています。

| 操作 | 使っている API |
| --- | --- |
| 保存 | `POST /api/stix/objects`（`visibility` + `stix`） |
| 更新 | `PUT /api/stix/objects?id=…` |
| 一覧 | `GET /api/stix/objects?visibility=me&limit=100` → **不足分を 1 件ずつ `?id=`** |
| 復元 | `GET /api/stix/objects?id=…` の `stix` から `x_rb_graph` を読む |
| 削除 | `DELETE /api/stix/objects?id=…` |

実測で確認できていること。

- `www-authenticate` が `Access-Control-Expose-Headers` に入っているので、
  **この API が出した 401 と外部サービスの 401 を区別**して自動リフレッシュできています
- プリフライトが `GET, POST, PUT, DELETE, OPTIONS` を許可していること
- 匿名の `visibility=me` と匿名の `POST` がどちらも 401 `authentication_required` を返すこと

---

## 確認してほしいこと

- `name` / `description` / `thumbnail` を**付けずに** POST しても、これまでどおり保存できる
- 付けて POST したあと、`GET ?visibility=me` の `objects[]` にその 3 つが載る
- `PUT` で `name` だけ変えたとき、`thumbnail` が消えない（あるいは「消える」仕様なら明記する）
- 他ユーザーの `me` データは、`name` などが載っても**引き続き 404**（存在が漏れない）
- `thumbnail` に `data:` 以外や巨大な値を渡したときの挙動（拒否するなら 400 と理由）
