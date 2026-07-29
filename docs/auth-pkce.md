# Active Research API の認証（OAuth 2.0 + PKCE）

ポータル（`https://proshiba.github.io/research_bench/`）から Active Research API
（`https://hellow-world.hiroshiba.chatgpt.site`）を認証付きで叩くための取り決め。

**Cookie は使わない。** ポータルと API は別サイト（`github.io` と `chatgpt.site`）なので、
セッション Cookie はサードパーティ Cookie になり、Safari と Firefox では届かない。
代わりに、ブラウザの中だけにトークンを持ち `Authorization: Bearer` で送る。

---

## 1. なぜ PKCE が要るのか

ポータルは GitHub Pages の静的配信で、**サーバーを持たない**。つまり
クライアントシークレットを隠せない（JS に埋めれば誰でも読める）。
OAuth ではこれを **パブリッククライアント** と呼び、シークレットの代わりに
PKCE（RFC 7636）で「同じブラウザが始めた手続きか」を証明する。

仕組みは単純で、**毎回その場で作る使い捨ての合言葉**を使う。

```
1. ブラウザが乱数 code_verifier を作る（この値はブラウザから出ない）
2. その SHA-256 ハッシュ code_challenge だけを認証開始時に渡す
3. 認証後に返ってくる code を、code_verifier と一緒に出して交換する
4. サーバーは SHA-256(code_verifier) == code_challenge を確かめる
```

**何を守るか**: 認証後のリダイレクト URL に載る `code` が漏れても
（履歴・アクセスログ・拡張機能など）、`code_verifier` を知らない者は交換できない。

**何を守らないか**: ポータル自身に XSS があればトークンは読まれる。
ブラウザにトークンを置く以上これは避けられないので、
**アクセストークンを短命にする + リフレッシュを回転させる + 失効できるようにする**
で被害範囲を絞る。

---

## 2. 全体の流れ

```
 ブラウザ（ポータル）                       Active Research API
 ─────────────────                       ───────────────────

 [ログイン] を押す
   │
   │ ① code_verifier を乱数で作る（43〜128 文字）
   │   code_challenge = BASE64URL(SHA256(code_verifier))
   │   state         = 乱数（CSRF 対策）
   │   → verifier と state を sessionStorage に置く
   │
   │ ② トップレベル遷移（画面ごと移動する。fetch ではない）
   └──────────────────────────────────────────▶  GET /api/oauth/authorize
                                                    ?response_type=code
                                                    &client_id=research_bench
                                                    &redirect_uri=https://proshiba.github.io/research_bench/
                                                    &state=…
                                                    &code_challenge=…
                                                    &code_challenge_method=S256
                                                    &scope=tools
                                                          │
                                                          │ ③ redirect_uri を許可リストと照合
                                                          │   ログイン画面を出す → ログイン
                                                          │   code を発行して保存
                                                          │   （challenge / redirect_uri / user と一緒に、TTL 60 秒）
                                                          │
   ④ 302 で戻ってくる                                      │
   ◀──────────────────────────────────────────────────────┘
     https://proshiba.github.io/research_bench/?code=…&state=…

   │ ⑤ state を照合（違えば中断）
   │   URL から code を消す（history.replaceState）
   │
   │ ⑥ code + code_verifier を交換（ここは fetch）
   └──────────────────────────────────────────▶  POST /api/oauth/token
                                                    grant_type=authorization_code
                                                    &code=…
                                                    &redirect_uri=…
                                                    &client_id=research_bench
                                                    &code_verifier=…
                                                          │
                                                          │ ⑦ code を使用済みにする（1 回だけ）
                                                          │   SHA256(code_verifier) == code_challenge を確認
                                                          │   redirect_uri / client_id の一致も確認
                                                          │
   ⑧ トークンを受け取る                                     │
   ◀──────────────────────────────────────────────────────┘
     { access_token, token_type: "Bearer", expires_in: 3600, refresh_token, scope }

   │ ⑨ 以後の呼び出し
   └──────────────────────────────────────────▶  GET /api/tools/dns?…
                                                 Authorization: Bearer <access_token>

   ⑩ 期限が切れたら
   └──────────────────────────────────────────▶  POST /api/oauth/token
                                                    grant_type=refresh_token
                                                    &refresh_token=…
                                                    &client_id=research_bench
                                                 → 新しいアクセストークン + **新しいリフレッシュトークン**
```

ポイントは 2 つ。

- **②だけが画面遷移**で、それ以外は全部 `fetch`。②を `fetch` にすると
  ログイン画面が出せないので、`location.assign()` で本当にページを移す。
- **`code` はクエリ文字列で返す**（RFC 6749 のとおり）。ログに残るのは事実だが、
  `code_verifier` が無ければ使えないので問題にならない。それが PKCE の効能。

---

## 3. バックエンドが用意するもの

### 3.1 エンドポイント 3 つ

| | 用途 |
| --- | --- |
| `GET /api/oauth/authorize` | ログイン画面を出して `code` を発行する（画面遷移で来る） |
| `POST /api/oauth/token` | `code` → トークン、リフレッシュトークン → トークン |
| `POST /api/oauth/revoke` | ログアウト（任意だが、あると安心） |

### 3.2 保存するもの

| 保存先 | 中身 | TTL |
| --- | --- | --- |
| 認可コード | `code`, `client_id`, `redirect_uri`, `code_challenge`, `method`, `user_id`, `scope`, `used` | **60 秒** |
| リフレッシュトークン | `token`（ハッシュで保存）, `user_id`, `client_id`, `scope`, `family_id`, `used` | 30 日程度 |
| アクセストークン | JWT にすれば保存不要。不透明トークンなら `token`(ハッシュ), `user_id`, `scope` | **1 時間** |

- **トークンは平文で保存しない。** SHA-256 のハッシュを保存して、照合はハッシュ同士で。
- Vercel なら KV / Upstash Redis などで足りる。認可コードは TTL 付きで置けるものが楽。

### 3.3 クライアント登録（設定ファイルで十分）

```jsonc
{
  "client_id": "research_bench",
  "client_type": "public",              // シークレットなし
  "redirect_uris": [
    "https://proshiba.github.io/research_bench/",
    "http://localhost:8000/"            // ローカル開発用。本番と分けるなら別 client_id
  ],
  "scopes": ["tools"]
}
```

---

## 4. 各エンドポイントの仕様

### 4.1 `GET /api/oauth/authorize`

**受け取るクエリ**

| | 必須 | |
| --- | --- | --- |
| `response_type` | ✅ | `code` 固定。他は `unsupported_response_type` |
| `client_id` | ✅ | 登録済みか照合 |
| `redirect_uri` | ✅ | 登録済み URI と**完全一致**で照合（前方一致は不可） |
| `state` | ✅ | そのまま返す。中身は見ない |
| `code_challenge` | ✅ | 43 文字の BASE64URL |
| `code_challenge_method` | ✅ | `S256` のみ。**`plain` は拒否する** |
| `scope` | | 省略時は既定スコープ |

**処理の順序（この順序が大事）**

1. `client_id` と `redirect_uri` を**先に**照合する。
   不正なら **リダイレクトせず**、その場でエラー画面を出す。
   （不正な `redirect_uri` へ飛ばすと、そのままオープンリダイレクトになる）
2. 以降のパラメータ不備は `redirect_uri?error=invalid_request&state=…` へ戻して伝える。
3. 未ログインならログイン画面。ログイン後にこの手続きへ戻る。
4. 同意画面（個人利用なら省略可）。
5. `code` を発行（不透明な乱数・128 bit 以上）して保存し、
   `302 Location: <redirect_uri>?code=…&state=…` で戻す。

**拒否するとき**は `redirect_uri?error=access_denied&state=…` へ戻す。
ポータル側で「認証をキャンセルしました」と出せる。

### 4.2 `POST /api/oauth/token`（`grant_type=authorization_code`）

`Content-Type: application/x-www-form-urlencoded`

```
grant_type=authorization_code
code=…
redirect_uri=https://proshiba.github.io/research_bench/
client_id=research_bench
code_verifier=…
```

**検証（すべて通ったときだけ発行）**

1. `code` を引く。無い／期限切れ／`used` なら `invalid_grant`
2. **引いた直後に `used=true` にする（アトミックに）。**
   同じ `code` が 2 回来たら盗まれた可能性が高いので、
   **そのコードから出したトークンを全部失効させる**
3. `BASE64URL(SHA256(ASCII(code_verifier))) === code_challenge`
   （**固定時間比較**で）
4. `redirect_uri` と `client_id` が発行時と一致するか

**応答**

```json
{
  "access_token": "…",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "…",
  "scope": "tools"
}
```

**エラー**は RFC 6749 の形で。ポータルはこれを見て文言を出し分ける。

```json
{ "error": "invalid_grant", "error_description": "code は使用済みか期限切れです" }
```

`invalid_request` / `invalid_grant` / `invalid_client` / `unauthorized_client` /
`unsupported_grant_type` / `invalid_scope` を使う。HTTP は 400（`invalid_client` は 401）。

### 4.3 `POST /api/oauth/token`（`grant_type=refresh_token`）

```
grant_type=refresh_token
refresh_token=…
client_id=research_bench
```

**回転（rotation）を必ず入れる。**

- 新しいアクセストークンと**新しいリフレッシュトークン**を返し、古い方は即座に無効化
- **使用済みのリフレッシュトークンが再提示されたら盗難とみなし、
  その `family_id` に属するトークンを全部失効させる**（ユーザーは再ログインになる）

パブリッククライアントはリフレッシュトークンを守れないので、この回転が実質的な防御になる。

### 4.4 `POST /api/oauth/revoke`（任意）

```
token=…
token_type_hint=refresh_token
```

成功・失敗にかかわらず `200` を返す（トークンの存在を教えないため）。
ポータルのログアウトボタンから叩く。

### 4.5 `/api/tools/*` の保護

`Authorization: Bearer <access_token>` を検証する。

| 状況 | 応答 |
| --- | --- |
| ヘッダなし | `401` + `WWW-Authenticate: Bearer` |
| 期限切れ | `401` + `WWW-Authenticate: Bearer error="invalid_token"` |
| スコープ不足 | `403` + `error="insufficient_scope"` |

**期限切れは「期限切れだと分かる形」で返してほしい。**
そうするとポータルが自動でリフレッシュして 1 回だけ再試行できる。
区別が付かないと、毎回ログイン画面に飛ばすことになる。

---

## 5. CORS の設定

**Cookie を使わないので `Access-Control-Allow-Origin: *` のままでよい。**
`Access-Control-Allow-Credentials` は不要。今の設定からの変更は次の 2 点だけ。

| | 現在 | 必要 |
| --- | --- | --- |
| `Access-Control-Allow-Methods` | `GET, POST, OPTIONS` | そのままで可 |
| `Access-Control-Allow-Headers` | `content-type, accept, authorization, …` | **`x-virustotal-key` と `x-github-token` を追加**（§6） |

`/api/oauth/token` と `/api/oauth/revoke` も **`OPTIONS` に 204 を返す**こと。
`/api/oauth/authorize` は画面遷移で来るので CORS は関係ない。

---

## 6. `Authorization` ヘッダの取り合いを解く（要対応）

いまこの API は **`Authorization: Bearer` を「外部サービスの API キー」に使っている**。
ここに Active Research のセッショントークンが入ると衝突する。

2026-07 時点の実測:

| ツール | 専用ヘッダ | 状況 |
| --- | --- | --- |
| AbuseIPDB | `X-AbuseIPDB-Key` | ✅ 使える |
| urlscan | `X-Urlscan-API-Key` | ✅ 使える |
| VirusTotal | — | ❌ `Authorization: Bearer header is required` |
| GitHub | — | ❌ `Authorization: Bearer header is required` |

AbuseIPDB と urlscan は既に分離済みなので、**同じ形に VirusTotal と GitHub も揃える**のが
いちばん手戻りが少ない。

```
Authorization: Bearer <access_token>   ← Active Research のセッション（これだけ）
X-VirusTotal-Key:  <VT のキー>          ← 追加してほしい
X-GitHub-Token:    <GitHub のトークン>   ← 追加してほしい
X-AbuseIPDB-Key:   <AbuseIPDB のキー>   ← 既にある
X-Urlscan-API-Key: <urlscan のキー>     ← 既にある
```

CORS の `Access-Control-Allow-Headers` にも `x-virustotal-key`, `x-github-token` を足す。

**移行のあいだは両方受け付ける**のがおすすめ。
`Authorization` にセッショントークンが来たらセッションとして扱い、
外部サービスのキーは専用ヘッダから読む。専用ヘッダが無ければ従来どおり
`Authorization` を外部キーとして扱う、という順序にすれば、ポータル側を
入れ替える前後どちらでも動く。

---

## 7. セキュリティのチェックリスト

- [ ] `redirect_uri` は**完全一致**で照合する（前方一致・ワイルドカードは使わない）
- [ ] `redirect_uri` が不正なときは**リダイレクトせず**エラー画面を出す
- [ ] `code_challenge_method` は `S256` のみ。`plain` を拒否する
- [ ] `code` は 1 回だけ使える。2 回目が来たら発行済みトークンを失効させる
- [ ] `code` の TTL は 60 秒程度
- [ ] `code` / トークンは 128 bit 以上の乱数（`crypto.randomBytes` 等）
- [ ] トークンはハッシュで保存する
- [ ] `code_challenge` の比較は固定時間比較
- [ ] リフレッシュトークンは回転させ、再利用検知でファミリごと失効
- [ ] アクセストークンは 1 時間程度
- [ ] `authorize` にレート制限
- [ ] 全部 HTTPS

---

## 8. ポータル側でやること

`assets/js/` に `auth-active-research.js` を足す。既にある
「キーをブラウザの中だけに持つ」仕組み（`osint.js` の 3 段階の置き場所）に乗せる。

1. モジュール画面と OSINT 設定に **「Active Research にログイン」** ボタン
2. `crypto.getRandomValues` で `code_verifier` / `state`、
   `crypto.subtle.digest("SHA-256", …)` で `code_challenge`
3. `code_verifier` と `state` は `sessionStorage`（タブを閉じれば消える）
4. 戻ってきたら `state` を照合 → `code` を交換 → トークンを保管 →
   `history.replaceState` で URL から `code` を消す
5. `api-active-research.js` の `call()` に `Authorization: Bearer` を足す
6. `401 invalid_token` を受けたら 1 回だけリフレッシュして再試行。
   それでも駄目なら「ログインし直してください」を出す
7. ログイン状態はステータスバーに出す（いまの `OSINT 未設定` の隣）

**トークンの置き場所の既定は「このタブだけ」（`sessionStorage`）にする。**
「メモリだけ」だとリロードのたびにログインし直しになり、
「このブラウザに保存」は共有端末で危ない。

---

## 9. 段階的に入れるなら

1. **§6 のヘッダ分離だけ先に入れる。** 認証と関係なく実施でき、
   これが済んでいれば認証を入れるときに壊れない
2. `authorize` + `token`（authorization_code）を実装。
   リフレッシュ無し・アクセストークン長め（1 日）でも動く
3. ポータル側のログインボタンを実装して疎通を確認
4. リフレッシュトークンと回転を足す
5. `revoke` とログアウトボタン

1 と 2 が済んだ時点で「ログインしないと調査 API が使えない」状態にはできる。
