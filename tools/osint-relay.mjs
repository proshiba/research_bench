#!/usr/bin/env node
// VirusTotal と abuse.ch はブラウザからの呼び出しに CORS を許可していないため、
// この 2 つだけは中継を通す必要がある。これはそのための最小の素通し中継。
//
//   node tools/osint-relay.mjs
//
// 使うときの性質:
//   - 127.0.0.1 にだけ待ち受ける（外部からは繋がらない）
//   - API キーは保持しない。ブラウザから毎回渡ってきたものをそのまま転送するだけ
//   - 起動時に出るトークンを持たないリクエストは弾く（他のサイトに使われないため）
//   - 転送先は下の ALLOWED に列挙したホストだけ（SSRF 防止）
//   - ログにキーやトークンは出さない
//
// 依存なし。Node 18 以降。

import { createServer } from "node:http";
import { randomBytes } from "node:crypto";

const PORT = Number(process.env.RB_RELAY_PORT || 8787);
const TOKEN = process.env.RB_RELAY_TOKEN || randomBytes(16).toString("hex");

const ALLOWED = new Set([
  "www.virustotal.com",
  "threatfox-api.abuse.ch",
  "urlhaus-api.abuse.ch",
  "mb-api.abuse.ch",
  "api.shodan.io",
]);

// 転送を許す要求ヘッダ。ここに無いものは落とす。
const FORWARDABLE = new Set(["x-apikey", "auth-key", "content-type", "accept"]);

const CORS = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "POST, OPTIONS",
  "access-control-allow-headers": "content-type, x-relay-token",
  "access-control-max-age": "600",
};

function send(res, status, body, extra = {}) {
  const text = typeof body === "string" ? body : JSON.stringify(body);
  res.writeHead(status, { "content-type": "application/json; charset=utf-8", ...CORS, ...extra });
  res.end(text);
}

async function readBody(req, limit = 1_000_000) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > limit) throw new Error("リクエストが大きすぎます");
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

const server = createServer(async (req, res) => {
  if (req.method === "OPTIONS") return send(res, 204, "");

  const url = new URL(req.url, "http://127.0.0.1");

  if (url.pathname === "/health") {
    if (req.headers["x-relay-token"] !== TOKEN) return send(res, 401, { error: "トークンが違います" });
    return send(res, 200, { ok: true, allowed: [...ALLOWED] });
  }

  if (url.pathname !== "/relay" || req.method !== "POST") {
    return send(res, 404, { error: "POST /relay または GET /health を使ってください" });
  }
  if (req.headers["x-relay-token"] !== TOKEN) {
    return send(res, 401, { error: "トークンが違います" });
  }

  let spec;
  try {
    spec = JSON.parse(await readBody(req));
  } catch (err) {
    return send(res, 400, { error: `リクエストを読めません: ${err.message}` });
  }

  let target;
  try {
    target = new URL(spec.url);
  } catch {
    return send(res, 400, { error: "url が URL として読めません" });
  }
  if (target.protocol !== "https:" || !ALLOWED.has(target.hostname)) {
    return send(res, 403, { error: `転送を許可していない宛先です: ${target.hostname}` });
  }

  const headers = {};
  for (const [k, v] of Object.entries(spec.headers || {})) {
    if (FORWARDABLE.has(k.toLowerCase())) headers[k] = v;
  }

  // キーが出ないように、宛先とメソッドだけを残す
  console.log(`${new Date().toISOString()}  ${spec.method || "GET"} ${target.origin}${target.pathname}`);

  try {
    const upstream = await fetch(target, {
      method: spec.method || "GET",
      headers,
      body: spec.body ?? undefined,
      redirect: "follow",
    });
    const text = await upstream.text();
    return send(res, 200, { status: upstream.status, body: text });
  } catch (err) {
    return send(res, 502, { error: `転送に失敗しました: ${err.message}` });
  }
});

server.listen(PORT, "127.0.0.1", () => {
  console.log("research_bench OSINT 中継を起動しました");
  console.log(`  URL      : http://127.0.0.1:${PORT}`);
  console.log(`  トークン : ${TOKEN}`);
  console.log("");
  console.log("ポータルの「OSINT 設定」に上の 2 つを入れてください。");
  console.log("キーはこの中継には保存されません（毎回ブラウザから渡ってきたものを転送するだけ）。");
  console.log("転送先は次のホストに限定しています:");
  for (const h of ALLOWED) console.log(`  - ${h}`);
});
