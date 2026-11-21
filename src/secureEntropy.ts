import { BIP39_ENGLISH_WORDLIST } from "./bip39Words";

export interface MemoryKeyStoreApi {
  registerKey: (address: string, privateKey: string) => void;
  getKey: (address: string) => string | undefined;
  hasKey: (address: string) => boolean;
  getAllAddresses: () => string[];
  size: () => number;
  clear: () => void;
}

export function getWebCrypto(): Crypto {
  if (typeof globalThis !== "undefined" && globalThis.crypto && globalThis.crypto.subtle) {
    return globalThis.crypto;
  }
  if (typeof window !== "undefined" && window.crypto && window.crypto.subtle) {
    return window.crypto;
  }
  throw new Error("Web Crypto API is not available in this runtime");
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0) {
    throw new Error("Invalid hex string length");
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    const parsed = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(parsed)) {
      throw new Error("Invalid hex byte sequence");
    }
    out[i] = parsed;
  }
  return out;
}

/**
 * Creates a lexical closure RAM keystore.
 * Keys live only inside the closure Map and are never exposed on `this`
 * or written as plaintext to localStorage/sessionStorage.
 */
export function createMemoryKeyStore(): MemoryKeyStoreApi {
  const keys = new Map<string, string>();

  return Object.freeze({
    registerKey(address: string, privateKey: string): void {
      if (address && privateKey) {
        keys.set(address.toLowerCase(), privateKey);
      }
    },
    getKey(address: string): string | undefined {
      if (!address) return undefined;
      return keys.get(address.toLowerCase());
    },
    hasKey(address: string): boolean {
      if (!address) return false;
      return keys.has(address.toLowerCase());
    },
    getAllAddresses(): string[] {
      return Array.from(keys.keys());
    },
    size(): number {
      return keys.size;
    },
    clear(): void {
      keys.clear();
    }
  });
}

export const memoryKeyStore: MemoryKeyStoreApi = createMemoryKeyStore();

/**
 * Generates fresh cryptographically random bytes via WebCrypto.
 */
export function generateSecureEntropy(byteLength: 16 | 32 = 16): Uint8Array {
  const crypto = getWebCrypto();
  const entropy = new Uint8Array(byteLength);
  crypto.getRandomValues(entropy);
  return entropy;
}

/**
 * Converts 16-byte (128-bit) or 32-byte (256-bit) entropy into a standard BIP-39 mnemonic
 * with real SHA-256 checksum bits using WebCrypto.
 */
export async function entropyToMnemonic(entropy: Uint8Array): Promise<string> {
  if (entropy.length !== 16 && entropy.length !== 32) {
    throw new Error("Entropy must be 16 bytes (12 words) or 32 bytes (24 words)");
  }
  const crypto = getWebCrypto();
  const hashBuf = await crypto.subtle.digest("SHA-256", entropy as unknown as BufferSource);
  const hashByte = new Uint8Array(hashBuf)[0];
  const checksumBitLength = (entropy.length * 8) / 32; // 4 bits for 128-bit, 8 bits for 256-bit

  let bits = "";
  for (let i = 0; i < entropy.length; i++) {
    bits += entropy[i].toString(2).padStart(8, "0");
  }
  bits += hashByte.toString(2).padStart(8, "0").slice(0, checksumBitLength);

  const words: string[] = [];
  for (let i = 0; i < bits.length; i += 11) {
    const index = Number.parseInt(bits.slice(i, i + 11), 2);
    words.push(BIP39_ENGLISH_WORDLIST[index]);
  }
  return words.join(" ");
}

/**
 * Generates a fresh 12-word (128-bit) or 24-word (256-bit) BIP-39 mnemonic.
 */
export async function generateSecureMnemonic(wordCount: 12 | 24 = 12): Promise<string> {
  const entropy = generateSecureEntropy(wordCount === 24 ? 32 : 16);
  return entropyToMnemonic(entropy);
}

/**
 * Validates a 12-word or 24-word BIP-39 English mnemonic and its SHA-256 checksum.
 */
export async function validateMnemonic(phrase: string): Promise<boolean> {
  if (!phrase || typeof phrase !== "string") return false;
  const words = phrase.trim().toLowerCase().split(/\s+/);
  if (words.length !== 12 && words.length !== 24) return false;

  let bits = "";
  for (const w of words) {
    const idx = BIP39_ENGLISH_WORDLIST.indexOf(w);
    if (idx === -1) return false;
    bits += idx.toString(2).padStart(11, "0");
  }

  const divider = Math.floor((bits.length / 33) * 32);
  const entropyBits = bits.slice(0, divider);
  const checksumBits = bits.slice(divider);

  const entropy = new Uint8Array(entropyBits.length / 8);
  for (let i = 0; i < entropy.length; i++) {
    entropy[i] = Number.parseInt(entropyBits.slice(i * 8, i * 8 + 8), 2);
  }

  const crypto = getWebCrypto();
  const hashBuf = await crypto.subtle.digest("SHA-256", entropy as unknown as BufferSource);
  const expectedChecksum = new Uint8Array(hashBuf)[0]
    .toString(2)
    .padStart(8, "0")
    .slice(0, checksumBits.length);

  return checksumBits === expectedChecksum;
}

/**
 * Derives a deterministic child account private key and pseudo-address identifier
 * from a mnemonic phrase and account index using WebCrypto PBKDF2 + HMAC-SHA512,
 * and registers the key inside the closure-isolated memoryKeyStore.
 */
export async function deriveSecureAccount(
  mnemonicPhrase: string,
  index: number
): Promise<{
  id: string;
  address: string;
  short: string;
}> {
  const crypto = getWebCrypto();
  const enc = new TextEncoder();

  // Standard BIP-39 seed stretch (2048 rounds PBKDF2-HMAC-SHA512)
  const baseKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(mnemonicPhrase.normalize("NFKD")),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const seedBits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: enc.encode("mnemonic"),
      iterations: 2048,
      hash: "SHA-512"
    },
    baseKey,
    512
  );

  const hmacKey = await crypto.subtle.importKey(
    "raw",
    seedBits,
    { name: "HMAC", hash: "SHA-512" },
    false,
    ["sign"]
  );

  const pathBytes = enc.encode(`m/44'/60'/0'/0/${index}`);
  const derived = new Uint8Array(await crypto.subtle.sign("HMAC", hmacKey, pathBytes));
  const privBytes = derived.slice(0, 32);
  const privateKey = "0x" + bytesToHex(privBytes);

  // Derive deterministic 20-byte account address digest from public material slice
  const addrDigest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", derived.slice(32, 64))
  );
  const address = "0x" + bytesToHex(addrDigest.slice(12, 32));
  memoryKeyStore.registerKey(address, privateKey);

  return {
    id: String(index + 1),
    address,
    short: address.slice(2, 6)
  };
}
