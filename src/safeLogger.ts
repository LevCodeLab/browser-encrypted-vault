/**
 * Safe redacting logger for browser and Node apps.
 * Strips 64-hex private keys, BIP-39 12-to-24 word mnemonics, passwords,
 * and sensitive object fields before anything hits console or crash logs.
 */

const HEX_KEY_REGEX = /\b(0x)?[a-fA-F0-9]{64}\b/g;
const BIP39_REGEX = /\b([a-z]{3,8}\s+){11,23}[a-z]{3,8}\b/gi;

const SENSITIVE_KEYS = new Set([
  "privatekey",
  "mnemonic",
  "password",
  "secret",
  "seed",
  "keymaterial",
  "ciphertext",
  "ciphertexthex"
]);

export function redactString(str: string): string {
  if (!str || typeof str !== "string") return str;
  return str
    .replace(HEX_KEY_REGEX, "[REDACTED_PRIVATE_KEY]")
    .replace(BIP39_REGEX, "[REDACTED_MNEMONIC]");
}

export function redactSensitive<T>(val: T, seen: WeakSet<object> = new WeakSet()): T {
  if (val === null || val === undefined) return val;

  if (typeof val === "string") {
    return redactString(val) as unknown as T;
  }

  if (val instanceof Error) {
    const cleanErr = new Error(redactString(val.message));
    cleanErr.name = val.name;
    if (val.stack) {
      cleanErr.stack = redactString(val.stack);
    }
    return cleanErr as unknown as T;
  }

  if (typeof val !== "object") {
    return val;
  }

  if (seen.has(val as object)) {
    return "[Circular]" as unknown as T;
  }
  seen.add(val as object);

  if (Array.isArray(val)) {
    return val.map((item) => redactSensitive(item, seen)) as unknown as T;
  }

  const result: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(val as Record<string, unknown>)) {
    const lowerKey = k.toLowerCase();
    if (SENSITIVE_KEYS.has(lowerKey)) {
      result[k] = "[REDACTED]";
    } else if (typeof v === "string") {
      result[k] = redactString(v);
    } else if (typeof v === "object" && v !== null) {
      result[k] = redactSensitive(v, seen);
    } else {
      result[k] = v;
    }
  }
  return result as T;
}

export const safeLogger = {
  info(...args: unknown[]): void {
    console.info(...args.map((arg) => redactSensitive(arg)));
  },
  warn(...args: unknown[]): void {
    console.warn(...args.map((arg) => redactSensitive(arg)));
  },
  error(...args: unknown[]): void {
    console.error(...args.map((arg) => redactSensitive(arg)));
  },
  debug(...args: unknown[]): void {
    console.debug(...args.map((arg) => redactSensitive(arg)));
  }
};
