/**
 * Authenticated WebCrypto vault encryption primitives.
 * Uses AES-GCM 256-bit authenticated encryption with PBKDF2 (100,000 iterations, SHA-256).
 * Zero XOR tricks, zero Base64 obfuscation, zero plaintext key storage.
 */

import { bytesToHex, getWebCrypto, hexToBytes } from "./secureEntropy";
import { EncryptedVaultBlob, VaultPayload } from "./vaultTypes";

export const PBKDF2_ITERATIONS = 100_000;

/**
 * Derives an non-extractable AES-GCM-256 CryptoKey from password + 16-byte salt.
 */
export async function deriveVaultKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
  const crypto = getWebCrypto();
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt as BufferSource,
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256"
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

/**
 * Encrypts a VaultPayload into an authenticated AES-GCM-256 blob.
 */
export async function encryptVault(
  payload: VaultPayload,
  password: string
): Promise<EncryptedVaultBlob> {
  if (!password || password.length < 4) {
    throw new Error("Vault password must be at least 4 characters");
  }

  const crypto = getWebCrypto();
  const salt = new Uint8Array(16);
  const iv = new Uint8Array(12);
  crypto.getRandomValues(salt);
  crypto.getRandomValues(iv);

  const key = await deriveVaultKey(password, salt);
  const enc = new TextEncoder();
  const encoded = enc.encode(JSON.stringify(payload));

  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv as BufferSource
    },
    key,
    encoded as BufferSource
  );

  return {
    version: 1,
    cipher: "AES-GCM-256",
    kdf: "PBKDF2",
    kdfParams: {
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256",
      saltHex: bytesToHex(salt)
    },
    ivHex: bytesToHex(iv),
    ciphertextHex: bytesToHex(new Uint8Array(ciphertext))
  };
}

/**
 * Decrypts an authenticated vault blob using the user password.
 * Throws if the password is wrong or if any byte of ciphertext/IV/salt was tampered with.
 */
export async function decryptVault(
  blob: EncryptedVaultBlob,
  password: string
): Promise<VaultPayload> {
  if (blob.version !== 1 || blob.cipher !== "AES-GCM-256" || blob.kdf !== "PBKDF2") {
    throw new Error("Unsupported vault version or cipher");
  }

  const crypto = getWebCrypto();
  const salt = hexToBytes(blob.kdfParams.saltHex);
  const iv = hexToBytes(blob.ivHex);
  const ciphertext = hexToBytes(blob.ciphertextHex);

  const key = await deriveVaultKey(password, salt);

  try {
    const decrypted = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: iv as BufferSource
      },
      key,
      ciphertext as BufferSource
    );

    const dec = new TextDecoder();
    return JSON.parse(dec.decode(decrypted)) as VaultPayload;
  } catch {
    throw new Error("Incorrect password or corrupted vault blob");
  }
}
