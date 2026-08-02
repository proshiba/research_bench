// 決定的な読み書き。
//
// 同じ入力からは同じバイト列が出ることを保証したい（差分がノイズにならないように）。
// そのために ①キーを常に整列 ②配列は明示的に整列してから渡す ③時刻を中身に混ぜない、
// の 3 つを守る。実行時刻や取得元のハッシュは meta.json にだけ置く。

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

/** キーを名前順に並べた JSON。中身が同じなら常に同じ文字列になる。 */
export function stableStringify(value, indent = 2) {
  const walk = (v) => {
    if (Array.isArray(v)) return v.map(walk);
    if (v && typeof v === "object" && !(v instanceof Date)) {
      const out = {};
      for (const k of Object.keys(v).sort()) {
        if (v[k] === undefined) continue;
        out[k] = walk(v[k]);
      }
      return out;
    }
    return v;
  };
  return JSON.stringify(walk(value), null, indent) + "\n";
}

export function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, stableStringify(value));
}

/** 1 行 1 レコード。呼ぶ側が並べ替えてから渡すこと（並びも出力の一部）。 */
export function writeJsonl(file, rows) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, rows.map((r) => stableStringify(r, 0)).join(""));
}

export function readJsonl(file) {
  if (!fs.existsSync(file)) return [];
  return fs.readFileSync(file, "utf8")
    .split("\n")
    .filter((l) => l.trim())
    .map((l, i) => {
      try {
        return JSON.parse(l);
      } catch (err) {
        throw new Error(`${file}:${i + 1} が JSON として読めません: ${err.message}`);
      }
    });
}

export function readJson(file, fallback = null) {
  if (!fs.existsSync(file)) return fallback;
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

export const sha256 = (buf) => crypto.createHash("sha256").update(buf).digest("hex");

/**
 * ISO 週（YYYY-Www）。木曜日基準の ISO 8601。
 * 週次スナップショットの置き場所の名前に使う。
 */
export function isoWeek(date) {
  const d = new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate()));
  // 木曜日に寄せると、その年が週の属する年になる
  d.setUTCDate(d.getUTCDate() + 4 - (d.getUTCDay() || 7));
  const first = new Date(Date.UTC(d.getUTCFullYear(), 0, 1));
  const week = Math.ceil(((d - first) / 86400000 + 1) / 7);
  return `${d.getUTCFullYear()}-W${String(week).padStart(2, "0")}`;
}

/** 素朴な引数解析。--key value と --flag だけ。依存を増やさないため。 */
export function parseArgs(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith("--")) { out._.push(a); continue; }
    const k = a.slice(2);
    const next = argv[i + 1];
    if (next === undefined || next.startsWith("--")) out[k] = true;
    else { out[k] = next; i++; }
  }
  return out;
}

/** 整列の比較。undefined/null を後ろに寄せて、同点は次の鍵で比べる。 */
export function byKeys(...keys) {
  return (a, b) => {
    for (const k of keys) {
      const x = a[k], y = b[k];
      if (x === y) continue;
      if (x == null) return 1;
      if (y == null) return -1;
      return x < y ? -1 : 1;
    }
    return 0;
  };
}
