// ワークベンチの変換モジュール。
//
// 選択したノードの値をその場でデコード・復号するための軽量な変換を内蔵し、
// それ以上は同梱の CyberChef に引き渡す。
// 調査対象の値を外部に送らないため、公開インスタンスへのフォールバックはしない。

const enc = new TextEncoder();
const dec = new TextDecoder("utf-8", { fatal: false });

export function toBytes(str) { return enc.encode(str); }
export function toText(bytes) { return dec.decode(bytes); }

function b64encode(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  }
  return btoa(s);
}

function b64decode(str) {
  const clean = String(str).replace(/[\s\r\n]+/g, "").replace(/-/g, "+").replace(/_/g, "/");
  const pad = clean.length % 4 ? "=".repeat(4 - (clean.length % 4)) : "";
  const bin = atob(clean + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function decompress(bytes, format) {
  if (typeof DecompressionStream === "undefined") {
    throw new Error("このブラウザは展開に対応していません");
  }
  const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream(format));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

const PRINTABLE = /[\x20-\x7e]{4,}/g;

const IOC_PATTERNS = [
  ["IPv4", /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g],
  ["URL", /\b[a-z][a-z0-9+.-]*:\/\/[^\s"'<>)\]]+/gi],
  ["ドメイン", /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|jp|ru|cn|info|xyz|top|online|site|shop|cc|su|biz|club|life|live|icu|onion)\b/gi],
  ["SHA-256", /\b[a-f0-9]{64}\b/gi],
  ["SHA-1", /\b[a-f0-9]{40}\b/gi],
  ["MD5", /\b[a-f0-9]{32}\b/gi],
  ["メール", /\b[\w.+-]+@[\w-]+\.[\w.-]+\b/g],
];

/**
 * 内蔵変換。すべて バイト列 → バイト列。
 * `cc` は CyberChef のレシピ表現（引き渡し時に使う。無いものは引き渡せない）。
 */
export const OPS = {
  fromB64: {
    label: "From Base64", cc: "From_Base64('A-Za-z0-9+/=',true,false)",
    run: (b) => b64decode(toText(b).trim()),
  },
  toB64: {
    label: "To Base64", cc: "To_Base64('A-Za-z0-9+/=')",
    run: (b) => toBytes(b64encode(b)),
  },
  fromHex: {
    label: "From Hex", cc: "From_Hex('Auto')",
    run: (b) => {
      const h = toText(b).replace(/(?:0x|\\x|%|\s|,|;|:)/gi, "");
      if (!h || h.length % 2 || /[^a-f0-9]/i.test(h)) throw new Error("16 進として読めません");
      const out = new Uint8Array(h.length / 2);
      for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
      return out;
    },
  },
  toHex: {
    label: "To Hex", cc: "To_Hex('Space',0)",
    run: (b) => toBytes(Array.from(b, (x) => x.toString(16).padStart(2, "0")).join(" ")),
  },
  urlDec: {
    label: "URL Decode", cc: "URL_Decode()",
    run: (b) => toBytes(decodeURIComponent(toText(b).replace(/\+/g, " "))),
  },
  urlEnc: {
    label: "URL Encode", cc: "URL_Encode(false)",
    run: (b) => toBytes(encodeURIComponent(toText(b))),
  },
  xor: {
    label: "XOR", cc: null, needsKey: true,
    run: (b, key) => {
      const k = /^[a-f0-9\s]+$/i.test(key) && key.replace(/\s/g, "").length % 2 === 0
        ? OPS.fromHex.run(toBytes(key))
        : toBytes(key);
      if (!k.length) throw new Error("鍵が空です");
      const out = new Uint8Array(b.length);
      for (let i = 0; i < b.length; i++) out[i] = b[i] ^ k[i % k.length];
      return out;
    },
    ccWithKey: (key) => `XOR({'option':'${/^[a-f0-9\s]+$/i.test(key) ? "Hex" : "UTF8"}','string':'${key.replace(/'/g, "\\'")}'},'Standard',false)`,
  },
  rot13: {
    label: "ROT13", cc: "ROT13(true,true,false,13)",
    run: (b) => Uint8Array.from(b, (c) => {
      if (c >= 65 && c <= 90) return ((c - 65 + 13) % 26) + 65;
      if (c >= 97 && c <= 122) return ((c - 97 + 13) % 26) + 97;
      return c;
    }),
  },
  gunzip: {
    label: "Gunzip", cc: "Gunzip()", async: true,
    run: (b) => decompress(b, "gzip"),
  },
  inflate: {
    label: "Inflate", cc: "Raw_Inflate(0,0,'Adaptive',false,false)", async: true,
    run: async (b) => {
      try { return await decompress(b, "deflate"); }
      catch { return decompress(b, "deflate-raw"); }
    },
  },
  reverse: {
    label: "Reverse", cc: "Reverse('Character')",
    run: (b) => Uint8Array.from(b).reverse(),
  },
  strings: {
    label: "Strings", cc: "Strings('Single byte',4,'All printable chars (A)',false,false,false)",
    run: (b) => toBytes((toText(b).match(PRINTABLE) || []).join("\n")),
  },
  utf16le: {
    label: "UTF-16LE", cc: "Decode_text('UTF-16LE (1200)')",
    run: (b) => toBytes(new TextDecoder("utf-16le").decode(b)),
  },
  lower: { label: "小文字", cc: "To_Lower_case('All')", run: (b) => toBytes(toText(b).toLowerCase()) },
  upper: { label: "大文字", cc: "To_Upper_case('All')", run: (b) => toBytes(toText(b).toUpperCase()) },
  refang: {
    label: "Refang", cc: null,
    run: (b) => toBytes(toText(b)
      .replace(/\[\.\]|\(\.\)|\{\.\}/g, ".")
      .replace(/\[dot\]|\(dot\)/gi, ".")
      .replace(/\[:\]/g, ":")
      .replace(/h(?:xx|XX)(ps?):/gi, "http$1:")),
  },
  defang: {
    label: "Defang", cc: "Defang_URL(true,true,true,'Valid domains and full URLs')",
    run: (b) => toBytes(toText(b)
      .replace(/\./g, "[.]")
      .replace(/https?:/gi, (m) => m.replace(/^http/i, "hxxp"))),
  },
  json: {
    label: "JSON 整形", cc: "JSON_Beautify('    ',false,true)",
    run: (b) => toBytes(JSON.stringify(JSON.parse(toText(b)), null, 2)),
  },
  iocs: {
    label: "IOC 抽出", cc: null,
    run: (b) => {
      const text = toText(b);
      const lines = [];
      for (const [name, re] of IOC_PATTERNS) {
        const hits = [...new Set(text.match(re) || [])];
        if (hits.length) lines.push(`# ${name} (${hits.length})`, ...hits, "");
      }
      return toBytes(lines.length ? lines.join("\n") : "（指標は見つかりませんでした）");
    },
  },
};

/** 変換チェーンを順に適用する。失敗した段でエラーを返す。 */
export async function runChain(input, chain) {
  let bytes = toBytes(input);
  for (let i = 0; i < chain.length; i++) {
    const step = chain[i];
    const op = OPS[step.op];
    if (!op) throw new Error(`未知の変換: ${step.op}`);
    try {
      bytes = await op.run(bytes, step.key);
    } catch (err) {
      const e = new Error(`${i + 1} 段目「${op.label}」で失敗: ${err.message || err}`);
      e.stepIndex = i;
      throw e;
    }
  }
  return toText(bytes);
}

/* ---------------- CyberChef への引き渡し ---------------- */
//
// 現在ワークベンチの UI からは呼んでいない（内蔵変換で足りるため引き渡しボタンを外した）。
// 再度つなぐときは view-workbench.js の変換タブからこの 3 つを呼べばよい。

let cyberchefUrl = null;
let availability = null;

export function configureCyberchef(tool) {
  cyberchefUrl = tool?.url || null;
  availability = null;
  return cyberchefUrl;
}

/** 同梱 CyberChef がビルド済みかを一度だけ確認する。 */
export function cyberchefAvailable() {
  if (!cyberchefUrl) return Promise.resolve(false);
  if (availability === null) {
    availability = fetch(cyberchefUrl, { method: "HEAD" })
      .then((res) => res.ok)
      .catch(() => false);
  }
  return availability;
}

/**
 * CyberChef に渡す URL を組み立てる。
 *
 * チェーン全段が CyberChef のオペレーションに対応づくなら、元の入力とレシピを渡して
 * 向こう側でも同じ手順が見えるようにする。対応しない変換が混ざっている場合は、
 * ここまでの出力だけを入力として渡し、続きを CyberChef で組んでもらう。
 *
 * CyberChef の parseURIParams は値を `=` で split し `+` を空白に変えるため、
 * パディング無しの Base64 を encodeURIComponent したものを渡す必要がある。
 */
export function cyberchefLink({ input, output, chain = [] }) {
  if (!cyberchefUrl) return null;
  const mappable = chain.length > 0 && chain.every((s) => {
    const op = OPS[s.op];
    return op && (op.cc || (op.ccWithKey && s.key));
  });

  const parts = [];
  if (mappable) {
    const recipe = chain
      .map((s) => (OPS[s.op].ccWithKey && s.key ? OPS[s.op].ccWithKey(s.key) : OPS[s.op].cc))
      .join("\n");
    parts.push("recipe=" + encodeURIComponent(recipe));
  }
  const payload = mappable ? input : (output ?? input);
  const b64 = b64encode(toBytes(String(payload ?? ""))).replace(/=+$/, "");
  parts.push("input=" + encodeURIComponent(b64));
  return `${cyberchefUrl}#${parts.join("&")}`;
}

export function cyberchefBuildHint(tool) {
  return tool?.build_hint || "cd cyberchef && npm ci && npx grunt prod";
}
