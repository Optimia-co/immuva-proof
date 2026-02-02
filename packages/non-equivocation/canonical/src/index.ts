import { createHash } from "node:crypto";

type JSONValue =
  | null
  | boolean
  | number
  | string
  | JSONValue[]
  | { [k: string]: JSONValue };

/**
 * Enforce JSON-only values.
 */
function toJsonValue(value: unknown): JSONValue {
  if (value === null) return null;

  const t = typeof value;
  if (t === "boolean" || t === "string") return value as any;

  if (t === "number") {
    // JSON forbids NaN/Infinity
    if (!Number.isFinite(value)) {
      throw new Error("canonicalizeJson: non-finite number is not allowed");
    }
    return value as JSONValue;
  }

  if (Array.isArray(value)) {
    return value.map((v) => toJsonValue(v));
  }

  if (t === "object") {
    const obj = value as Record<string, unknown>;
    const out: Record<string, JSONValue> = {};
    for (const k of Object.keys(obj).sort()) {
      out[k] = toJsonValue(obj[k]);
    }
    return out;
  }

  // undefined, bigint, symbol, function, etc.
  throw new Error("canonicalizeJson: non-JSON type is not allowed");
}

/**
 * Deterministic minified JSON with lexicographically sorted object keys.
 */
export function canonicalizeJson(value: unknown): {
  canonical: string;
  sha256: string;
} {
  const v = toJsonValue(value);
  const canonical = JSON.stringify(v);
  const sha256 = createHash("sha256")
    .update(Buffer.from(canonical, "utf8"))
    .digest("hex");
  return { canonical, sha256 };
}

/**
 * Low-level helper (used by verifier v1)
 */
export function sha256HexUtf8(input: string): string {
  return createHash("sha256")
    .update(Buffer.from(input, "utf8"))
    .digest("hex");
}
