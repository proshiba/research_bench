# 依頼: GitHub ログインによる認証と、API キーのヘッダ分離（Active Research API）

## 背景

このリポジトリ（`hellow-world`, `https://hellow-world.hiroshiba.chatgpt.site`）が公開している
調査 API を、**ポータル `research_bench` から利用者ごとに認証して呼べるようにしたい。**

ポータルは `https://proshiba.github.io/research_bench/` にある **GitHub Pages の静的サイト**。
サーバーを持たないので、クライアントシークレットを隠す場所が無い。
そのため **OAuth 2.0 の認可コードフロー + PKCE（RFC 7636）のパブリッククライアント**として扱う。

利用者の身元は **GitHub ログイン（フェデレーション）**で確認する。

現状は認証が一切無く、`Authorization: Bearer` は「外部サービス（VirusTotal / GitHub）の
API キー」を渡す用途に使われている。ここにセッショントークンを載せると衝突するので、
**そのヘッダの整理も一緒にやる。**

---

## この依頼の範囲

| やること | |
| --- | --- |
| ① | 外部サービスの API キーを専用ヘッダに移す（`Authorization` を空ける） |
| ② | GitHub ログインを入り口にした認可サーバーを実装する |
| ③ | ツールごとに「匿名で使える／認証が必要」を宣言できるようにする |

**やらないこと**: 各ツール（dns / rdap / port-scan …）のロジックそのものには手を入れない。
入り口の認証・認可と、キーの受け渡し方だけを変える。

---

## ① API キーのヘッダ分離（先にこれだけでも入れられる）

### 現状（2026-07 実測）

| ツール | 専用ヘッダ | 状況 |
| --- | --- | --- |
| AbuseIPDB | `X-AbuseIPDB-Key` | ✅ 対応済み |
| urlscan | `X-Urlscan-API-Key` | ✅ 対応済み |
| VirusTotal | — | ❌ `Authorization: Bearer header is required` |
| GitHub 調査 | — | ❌ 同上 |

AbuseIPDB と urlscan は既に分離できているので、**同じ形に VirusTotal と GitHub も揃える。**

### あるべき姿

```
Authorization: Bearer <access_token>   ← Active Research のセッション。これ専用にする
X-VirusTotal-Key:  <VT の API キー>     ← 追加する
X-GitHub-Token:    <GitHub のトークン>   ← 追加する
X-AbuseIPDB-Key:   <AbuseIPDB のキー>   ← 既にある
X-Urlscan-API-Key: <urlscan のキー>     ← 既にある
```

### 移行期間の互換

ポータル側の入れ替えと同時にはできないので、**しばらく両方受け付ける。**
外部サービスのキーを解決する順序は次のとおり。

```
1. 専用ヘッダ（X-VirusTotal-Key など）があればそれを使う
2. 無ければ Authorization: Bearer の値を「外部サービスのキー」として使う（従来の動作）
3. ただし Authorization の値が自分が発行したセッショントークンとして
   検証できた場合は、外部サービスのキーとしては使わない
```

3 が要る理由: セッショントークンを外部サービスに転送してしまうと、
VirusTotal に自分の API のトークンを送ることになる。**必ず先に自前トークンとして検証する。**

互換の受付をいつ切るかは、ポータル側の切り替えが済んでから決める。
切るときは `Authorization` に外部キーが来たら `400` + 「専用ヘッダを使ってください」と返す。

### CORS

`Access-Control-Allow-Headers` に `x-virustotal-key`, `x-github-token` を追加する。
Cookie は使わないので `Access-Control-Allow-Origin: *` のままでよい
（`Access-Control-Allow-Credentials` は**付けない**）。

---

## ② 認証（GitHub ログイン → 自前トークン）

### 全体の構造

このサーバーは **2 つの役**を持つ。混ぜないこと。

```
 ポータル（静的・秘密を持てない）          このサーバー                        GitHub
 ────────────────────────                ──────────                        ──────
 パブリッククライアント          ──▶  役1: 認可サーバー
   PKCE でトークンを取る              （ポータルにトークンを発行）
                                     役2: OAuth クライアント        ──▶  IdP
                                     （client_secret を持つ機密クライアント）
```

- **役1 の相手（ポータル）は秘密を持てない** → PKCE で「同じブラウザが始めた手続きか」を検証
- **役2 では自分が秘密を持てる** → `client_secret` を普通に使う（PKCE も併用してよい）

### 流れ

```
① ポータル → GET /api/oauth/authorize
                ?response_type=code
                &client_id=research_bench
                &redirect_uri=https://proshiba.github.io/research_bench/
                &state=<ポータルの乱数>
                &code_challenge=<BASE64URL(SHA256(verifier))>
                &code_challenge_method=S256
                &scope=tools
                   │
                   │ client_id と redirect_uri を「先に」照合（★不正ならリダイレクトしない）
                   │ ポータルの要求内容を保持（後述）
                   ▼
②           302 → https://github.com/login/oauth/authorize
                     ?client_id=<GitHub OAuth App>
                     &redirect_uri=https://hellow-world.hiroshiba.chatgpt.site/api/oauth/github/callback
                     &state=<自分の乱数>
                     &scope=read:user
                   │
                   │ 利用者が GitHub でログイン・承認
                   ▼
③           GET /api/oauth/github/callback?code=…&state=…
                   │
                   │ state を照合
                   │ POST https://github.com/login/oauth/access_token
                   │   （client_id + client_secret + code）
                   │ GET https://api.github.com/user → 数値の id を得る
                   │ ★★ 許可リストと照合（後述）
                   │ ①で保持したポータルの要求を取り出す
                   │ ポータル向けの認可コードを発行（TTL 60 秒）
                   ▼
④           302 → https://proshiba.github.io/research_bench/?code=…&state=…

⑤ ポータル → POST /api/oauth/token
                grant_type=authorization_code
                &code=…&redirect_uri=…&client_id=research_bench&code_verifier=…
                   │
                   │ code を使用済みにする（アトミックに）
                   │ SHA256(code_verifier) == code_challenge を固定時間比較
                   ▼
⑥           { access_token, token_type: "Bearer", expires_in: 3600, refresh_token, scope }

⑦ ポータル → GET /api/tools/dns?…    Authorization: Bearer <access_token>
```

### ①→③ をまたぐ状態の保持

GitHub を 1 往復するあいだ、ポータルの要求（`redirect_uri` / `state` / `code_challenge` /
`scope`）を保持する必要がある。どちらでもよい。

**A. サーバー側に保存**（推奨）
乱数キーで KV に保存し、そのキーを GitHub の `state` に入れる。TTL 10 分。

**B. 自分のドメインの Cookie**
署名付き・短命の Cookie。**これは一人称 Cookie なので問題ない**
（ブラウザがこのサーバーのページにトップレベルで居るあいだだけ使う）。

> **B を選ぶ場合の落とし穴**: GitHub からの `③` は**クロスサイトのトップレベル遷移**。
> `SameSite=Lax` なら送られるが、**`SameSite=Strict` だと送られない**。
> Strict にすると「ログインしても終わらない」無限ループになる。
> `SameSite=Lax; HttpOnly; Secure; Max-Age=600` にすること。

### ★★ 認証と認可は別（最重要）

**GitHub ログインは「誰か」しか教えない。「使ってよいか」は別に決める。**

この API は**ポートスキャンと任意 HTTP リクエスト**を実行できる。素通しにすると
GitHub アカウントを持つ誰でもそれを使える状態になる。

- 環境変数の許可リスト `ALLOWED_GITHUB_USER_IDS` と照合する
- **ユーザー名（`login`）ではなく数値の `id` で照合する。**`login` は変更できる。
  自分の id は `https://api.github.com/users/<ユーザー名>` の `id` で取れる
- 外れていれば認可コードを発行せず、`redirect_uri?error=access_denied&state=…` へ戻す

### GitHub 側で気をつける点

- **GitHub のアクセストークンをポータルに渡さない。**このサーバーの中に留める。
  渡すと、静的サイトが利用者の GitHub 権限を持つトークンを抱えることになる
- **スコープは最小に。**ログイン目的なら `read:user` のみ。`repo` は要求しない
- **GitHub は OIDC プロバイダではない。**ID トークンは出ないので、身元は
  `GET https://api.github.com/user` で取る。OIDC 前提のライブラリは噛み合わない
- OAuth App の callback URL は 1 つだけ。**ローカル開発用に別の OAuth App を作る**
  （または複数 callback を登録できる GitHub App を使う）
- OAuth App の token エンドポイントは `client_secret` が必須。PKCE にも対応しているので
  `code_challenge` / `code_verifier` を付けてもよい（上乗せの防御）

---

## エンドポイント仕様

### `GET /api/oauth/authorize`

| クエリ | 必須 | |
| --- | --- | --- |
| `response_type` | ✅ | `code` 固定。他は `unsupported_response_type` |
| `client_id` | ✅ | 登録済みか照合 |
| `redirect_uri` | ✅ | 登録済み URI と**完全一致**（前方一致・ワイルドカードは不可） |
| `state` | ✅ | そのまま返す。中身は見ない |
| `code_challenge` | ✅ | 43 文字の BASE64URL |
| `code_challenge_method` | ✅ | **`S256` のみ。`plain` は拒否する** |
| `scope` | | 省略時は既定 |

**処理の順序が大事**

1. `client_id` と `redirect_uri` を**最初に**照合する。
   不正なら **リダイレクトせず**その場でエラー画面を出す
   （不正な `redirect_uri` へ飛ばすとオープンリダイレクトになる）
2. それ以降の不備は `redirect_uri?error=invalid_request&state=…` へ戻して伝える
3. GitHub へ飛ばす（②）

### `POST /api/oauth/token`

`Content-Type: application/x-www-form-urlencoded`。**`OPTIONS` に 204 を返すこと。**

**`grant_type=authorization_code`**

```
grant_type=authorization_code
code=…
redirect_uri=https://proshiba.github.io/research_bench/
client_id=research_bench
code_verifier=…
```

検証（全部通ったときだけ発行）

1. `code` を引く。無い／期限切れ／使用済みなら `invalid_grant`
2. **引いた直後に使用済みにする（アトミックに）。**
   同じ `code` が 2 回来たら盗難の可能性が高いので、
   **そのコードから発行したトークンを全部失効させる**
3. `BASE64URL(SHA256(ASCII(code_verifier))) === code_challenge`（**固定時間比較**）
4. `redirect_uri` と `client_id` が発行時と一致するか

**`grant_type=refresh_token`**

```
grant_type=refresh_token
refresh_token=…
client_id=research_bench
```

**回転（rotation）を必ず入れる。**

- 新しいアクセストークンと**新しいリフレッシュトークン**を返し、古い方は即無効化
- **使用済みのリフレッシュトークンが再提示されたら盗難とみなし、
  同じ family のトークンを全部失効させる**（利用者は再ログインになる）

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

**エラーは RFC 6749 の形で。**ポータルがこれを見て文言を出し分ける。

```json
{ "error": "invalid_grant", "error_description": "code は使用済みか期限切れです" }
```

`invalid_request` / `invalid_grant` / `invalid_client` / `unauthorized_client` /
`unsupported_grant_type` / `invalid_scope`。HTTP は 400（`invalid_client` は 401）。

### `POST /api/oauth/revoke`

```
token=…
token_type_hint=refresh_token
```

成功・失敗にかかわらず `200`（トークンの存在を教えないため）。
ポータルのログアウトボタンから叩く。

### `GET /api/oauth/userinfo`（あると便利）

`Authorization: Bearer` で、いま誰としてログインしているかを返す。
ポータルがステータスバーに出す。

```json
{ "ok": true, "user": { "login": "proshiba", "name": "…", "avatar_url": "…" }, "scope": "tools" }
```

---

## ③ ツールごとの権限

**匿名でも動くツールと、認証が必要なツールがある**という現状の方針を維持する。
ポータルが「どれがログイン必須か」を事前に知れるように、**機械可読で公開してほしい。**

### `GET /api/meta`（新規・匿名で読める）

```jsonc
{
  "ok": true,
  "auth": {
    "type": "oauth2",
    "authorize": "/api/oauth/authorize",
    "token": "/api/oauth/token",
    "revoke": "/api/oauth/revoke",
    "userinfo": "/api/oauth/userinfo",
    "client_id": "research_bench",
    "scopes_supported": ["tools", "tools:active"],
    "code_challenge_methods_supported": ["S256"]
  },
  "tools": [
    { "id": "dns",            "auth": "anonymous", "path": "/api/tools/dns" },
    { "id": "rdap",           "auth": "anonymous", "path": "/api/tools/rdap" },
    { "id": "certificate",    "auth": "anonymous", "path": "/api/tools/certificate" },
    { "id": "port-scan",      "auth": "required",  "scope": "tools:active", "path": "/api/tools/port-scan" },
    { "id": "open-directory", "auth": "required",  "scope": "tools:active", "path": "/api/tools/open-directory" },
    { "id": "request",        "auth": "required",  "scope": "tools:active", "path": "/api/request" },
    { "id": "virustotal",     "auth": "anonymous", "path": "/api/tools/virustotal", "key_header": "X-VirusTotal-Key" },
    { "id": "abuseipdb",      "auth": "anonymous", "path": "/api/tools/abuseipdb",  "key_header": "X-AbuseIPDB-Key" }
  ]
}
```

`auth` は `anonymous`（ログイン不要）／`optional`（ログインすると制限が緩む）／
`required`（ログイン必須）の 3 値。**どのツールをどれにするかはそちらの判断で決めてよい。**
上の例は「外部に能動的に触るもの（ポートスキャン・任意リクエスト・ディレクトリ探索）は
認証必須」という置き方の例。

ポータルはこれを読んで、**ログイン前は認証必須のツールを灰色にして
「ログインが必要です」と出す**（今の「キー未設定」と同じ扱い）。

### `/api/tools/*` の応答

| 状況 | 応答 |
| --- | --- |
| `auth: required` でヘッダなし | `401` + `WWW-Authenticate: Bearer` |
| トークンが期限切れ | `401` + `WWW-Authenticate: Bearer error="invalid_token"` |
| スコープ不足 | `403` + `WWW-Authenticate: Bearer error="insufficient_scope"` |

**期限切れは「期限切れだと分かる形」で返してほしい。**
そうするとポータルが自動でリフレッシュして 1 回だけ再試行できる。
区別が付かないと毎回ログイン画面に飛ばすことになる。

`auth: anonymous` のツールは、**トークンが無くても今と同じように動くこと**（回帰させない）。
不正なトークンが付いていた場合は `401` を返す（無視して匿名として通さない）。

---

## 保存するもの

| | 中身 | TTL |
| --- | --- | --- |
| 認可コード | `code`, `client_id`, `redirect_uri`, `code_challenge`, `method`, `github_user_id`, `scope`, `used` | **60 秒** |
| アクセストークン | JWT なら保存不要。不透明なら `hash`, `user_id`, `scope`, `expires_at` | **1 時間** |
| リフレッシュトークン | `hash`, `user_id`, `client_id`, `scope`, `family_id`, `used` | 30 日 |
| GitHub のトークン | `user_id` に紐付けて保存（**ポータルには出さない**） | GitHub 側の寿命に従う |
| 進行中の認可要求（方式 A） | ポータルの要求一式 | 10 分 |

- **トークンは平文で保存しない。**SHA-256 のハッシュを保存し、照合はハッシュ同士で
- Vercel なら KV / Upstash Redis で足りる。TTL 付きで置けるものが楽

## クライアント登録（設定ファイルで十分）

```jsonc
{
  "client_id": "research_bench",
  "client_type": "public",
  "redirect_uris": [
    "https://proshiba.github.io/research_bench/",
    "http://localhost:8000/"
  ],
  "scopes": ["tools", "tools:active"]
}
```

ローカル開発用を本番と分けたいなら `client_id` を別にする。

## 環境変数

```
GITHUB_OAUTH_CLIENT_ID
GITHUB_OAUTH_CLIENT_SECRET
ALLOWED_GITHUB_USER_IDS      # カンマ区切りの数値 id。https://api.github.com/users/<名前> の id
TOKEN_SIGNING_KEY            # JWT を使う場合
```

**`ALLOWED_GITHUB_USER_IDS` が未設定のときは全員拒否**にする（空 = 全員許可にしない）。
この文書に実際の id は書かない（フォークした人がそのまま使ってしまうため）。

---

## 秘密の扱い

このリポジトリは公開されている。**設計は公開してよいが、値は絶対に入れないこと。**

### コミットしてはいけないもの

| | |
| --- | --- |
| `GITHUB_OAUTH_CLIENT_SECRET` | GitHub OAuth App のシークレット |
| `TOKEN_SIGNING_KEY` | 自前トークンの署名鍵 |
| 発行済みのアクセス/リフレッシュトークン | テスト用の実物も含めて |
| 外部サービスの API キー | VirusTotal / AbuseIPDB / urlscan / GitHub PAT |
| `ALLOWED_GITHUB_USER_IDS` の実際の値 | 設定例には書かない |

すべて環境変数で渡す。`.env*` を `.gitignore` に入れる。
テストコードにもキーを直書きせず、環境変数から読む。

### ログに出してはいけないもの

**`Authorization` ヘッダを丸ごと出さないこと。** この手の実装でいちばん多い事故。

- リクエストのログを取るなら、`authorization` と `x-*-key` 系のヘッダは
  **キー名だけ残して値は `[redacted]` に置き換える**
- 例外を投げるとき、リクエストオブジェクトをそのまま `console.error` に渡さない
  （ヘッダごと Vercel のログに残る）
- `code` / `code_verifier` / `refresh_token` もログに出さない。
  デバッグで追いたいときはハッシュの先頭 8 文字などに落とす
- トークンの検証失敗時のエラーメッセージに、受け取った値を含めない

外部サービスへの中継でも同じで、**上流のエラー応答をそのまま返すと
キーが含まれていることがある**（URL にキーを載せる API の場合）。
そちらの応答を転送するときは URL とヘッダを確認する。

---

## セキュリティのチェックリスト

- [ ] `redirect_uri` は**完全一致**で照合（前方一致・ワイルドカードを使わない）
- [ ] `redirect_uri` が不正なときは**リダイレクトせず**エラー画面
- [ ] `code_challenge_method` は `S256` のみ。`plain` を拒否
- [ ] `code` は 1 回だけ。2 回目で発行済みトークンを失効
- [ ] `code` の TTL は 60 秒
- [ ] `code` / トークンは 128 bit 以上の乱数（`crypto.randomBytes` 等）
- [ ] トークンはハッシュで保存
- [ ] `code_challenge` の比較は固定時間
- [ ] リフレッシュトークンは回転し、再利用検知で family ごと失効
- [ ] GitHub の `state` を照合する
- [ ] GitHub の数値 `id` で許可リスト照合（`login` ではない）
- [ ] GitHub のアクセストークンをポータルに返していない
- [ ] セッショントークンを外部サービスへ転送していない（①の 3）
- [ ] `authorize` にレート制限
- [ ] ログに `Authorization` / `x-*-key` / `code` / `code_verifier` /
      `refresh_token` の値が出ていない（キー名だけ残して `[redacted]`）
- [ ] 上流サービスのエラー応答を転送するとき、キーが混ざっていない
- [ ] 秘密が全部環境変数で、`.env*` が `.gitignore` に入っている
- [ ] 全部 HTTPS

---

## 進め方（この順で入れると途中でも壊れない）

1. **①のヘッダ分離だけ入れる。**認証と無関係に実施でき、互換受付があるので
   ポータル側は無変更で動き続ける
2. `GET /api/meta` を追加。全ツール `auth: "anonymous"` で出す（挙動は変えない）
3. GitHub OAuth App を作り、`authorize` → GitHub → `callback` → `token`
   （`authorization_code` のみ）を実装。**リフレッシュ無し・アクセストークン 1 日**でも動く
4. 認証必須にしたいツールを `auth: "required"` に変え、`401` / `403` を返すようにする
5. リフレッシュトークンと回転を足す
6. `revoke` と `userinfo`

**3 が済んだ時点でポータル側の実装に入れる**ので、そこまで済んだら教えてほしい。

---

## 完了の確認に使ってほしいこと

- `curl` で `GET /api/meta` が匿名で読め、`auth` と `tools` が上の形で返る
- `authorize` に不正な `redirect_uri` を渡すと**リダイレクトせず**エラーになる
- `code_challenge_method=plain` が拒否される
- 同じ `code` を 2 回 `token` に出すと 2 回目が `invalid_grant` になり、
  1 回目で得たトークンも失効している
- 許可リストに無い GitHub アカウントでログインすると `error=access_denied` で戻る
- `auth: anonymous` のツールが**トークン無しで従来どおり動く**
- `auth: required` のツールがトークン無しで `401` + `WWW-Authenticate: Bearer` を返す
- 期限切れトークンで `error="invalid_token"` が返る
- `X-VirusTotal-Key` / `X-GitHub-Token` で動き、`Authorization` に外部キーを入れる
  従来の呼び方でも（互換期間中は）動く
- `Authorization` に**自前のセッショントークン**を入れたとき、それが
  VirusTotal へ転送されていない
- `OPTIONS /api/oauth/token` が 204 を返し、`Access-Control-Allow-Headers` に
  `x-virustotal-key` と `x-github-token` が入っている

---

## 参考

ポータル側の設計メモ:
[`docs/auth-pkce.md`](https://github.com/proshiba/research_bench/blob/main/docs/auth-pkce.md)
（なぜ Cookie を使わないか、PKCE が何を守るかの背景）

ポータル側は既に「キーをブラウザの中だけに持つ」仕組み（3 段階の置き場所）と
`Authorization: Bearer` を送る経路を持っているので、上の仕様が固まればそこに乗せる。
