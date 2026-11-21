/**
 * KeyringManager
 * - Deterministic hierarchical account key derivation from a controller secret/signature.
 * - Pure WebCrypto SHA-256 / HMAC-SHA512 + AES-GCM-256 + PBKDF2 (100,000 rounds).
 * - Local-only IndexedDB persistence and instant O(1) RAM auto-restore on reload.
 */

import { deriveVaultKey, PBKDF2_ITERATIONS } from "./encryptedVault";
import {
  bytesToHex,
  entropyToMnemonic,
  getWebCrypto,
  hexToBytes,
  memoryKeyStore
} from "./secureEntropy";
import { vaultDb } from "./storage/vaultDb";
import { PersistedVaultRecord } from "./vaultTypes";

export interface DerivedKeyringAccount {
  id: string;
  address: string;
  privateKey: string;
  short: string;
  groupIndex: number;
  index: number;
}

export interface EncryptedKeyringPayload {
  version: 2;
  controllerAddress: string;
  namespace?: string;
  createdAt: number;
  accounts: Array<{
    address: string;
    privateKey: string;
    index?: number;
    isActive?: boolean;
    label?: string;
  }>;
}

const STORAGE_KEYRING_PREFIX = "bev_enc_keyring_v2_";

export class KeyringManager {
  private static instance: KeyringManager;
  private cachedSecret: string | null = null;
  private cachedMasterKey: CryptoKey | null = null;
  private derivedAddressMap = new Map<
    string,
    { privateKey: string; groupIndex: number; accountIndex: number }
  >();
  private hasScannedGroups = false;

  public static getInstance(): KeyringManager {
    if (!KeyringManager.instance) {
      KeyringManager.instance = new KeyringManager();
    }
    return KeyringManager.instance;
  }

  /**
   * Deterministically derives a 12-word BIP-39 mnemonic from a controller secret or EIP-191 signature.
   */
  public async getDeterministicMnemonic(controllerSecret: string): Promise<string> {
    const crypto = getWebCrypto();
    const enc = new TextEncoder();
    const cleanSecret = controllerSecret.trim();
    const digest = await crypto.subtle.digest(
      "SHA-256",
      enc.encode("KEYRING_DETERMINISTIC_HD_ENTROPY_V2:" + cleanSecret.toLowerCase()) as BufferSource
    );
    const entropyBytes = new Uint8Array(digest).slice(0, 16);
    return entropyToMnemonic(entropyBytes);
  }

  private async getMasterHmacKey(controllerSecret: string): Promise<CryptoKey> {
    const cleanSecret = controllerSecret.trim();
    if (this.cachedSecret === cleanSecret && this.cachedMasterKey) {
      return this.cachedMasterKey;
    }

    const crypto = getWebCrypto();
    const enc = new TextEncoder();
    const seedDigest = await crypto.subtle.digest(
      "SHA-512",
      enc.encode("KEYRING_MASTER_NODE_V2:" + cleanSecret) as BufferSource
    );
    const masterKey = await crypto.subtle.importKey(
      "raw",
      seedDigest,
      { name: "HMAC", hash: "SHA-512" },
      false,
      ["sign"]
    );

    this.cachedSecret = cleanSecret;
    this.cachedMasterKey = masterKey;
    this.derivedAddressMap.clear();
    this.hasScannedGroups = false;
    return masterKey;
  }

  private async deriveChildNode(
    masterKey: CryptoKey,
    groupIndex: number,
    accountIndex: number
  ): Promise<{ address: string; privateKey: string }> {
    const crypto = getWebCrypto();
    const enc = new TextEncoder();
    const path = enc.encode(`m/44'/60'/0'/${groupIndex}/${accountIndex}`);
    const mac = new Uint8Array(
      await crypto.subtle.sign("HMAC", masterKey, path as BufferSource)
    );
    const privBytes = mac.slice(0, 32);
    const addrHash = new Uint8Array(
      await crypto.subtle.digest("SHA-256", mac.slice(32, 64) as BufferSource)
    );
    const address = "0x" + bytesToHex(addrHash.slice(12, 32));
    const privateKey = "0x" + bytesToHex(privBytes);
    return { address, privateKey };
  }

  /**
   * Derives `count` deterministic child accounts for a given group index
   * and registers them in the RAM-isolated memoryKeyStore.
   */
  public async deriveAccounts(
    controllerSecret: string,
    count: number = 16,
    groupIndex: number = 0
  ): Promise<DerivedKeyringAccount[]> {
    if (!controllerSecret || !controllerSecret.trim()) {
      throw new Error("Controller secret is required for keyring derivation");
    }

    const masterKey = await this.getMasterHmacKey(controllerSecret);
    const results: DerivedKeyringAccount[] = [];

    for (let i = 0; i < count; i++) {
      const child = await this.deriveChildNode(masterKey, groupIndex, i);
      const addrLower = child.address.toLowerCase();

      this.derivedAddressMap.set(addrLower, {
        privateKey: child.privateKey,
        groupIndex,
        accountIndex: i
      });
      memoryKeyStore.registerKey(child.address, child.privateKey);

      results.push({
        id: `acct_${groupIndex}_${i}_${child.address.slice(2, 6)}`,
        address: child.address,
        privateKey: child.privateKey,
        short: child.address.slice(2, 6),
        groupIndex,
        index: i
      });
    }

    return results;
  }

  /**
   * Instant O(1) lookup via RAM cache, with a one-time scan across groups 0..5 if not yet indexed.
   */
  public async tryAutoRestoreKeyForAddress(
    controllerSecret: string,
    targetAddress: string
  ): Promise<string | null> {
    if (!controllerSecret || !targetAddress) return null;
    const cleanTarget = targetAddress.toLowerCase();

    const existing = memoryKeyStore.getKey(targetAddress);
    if (existing) return existing;

    const cached = this.derivedAddressMap.get(cleanTarget);
    if (cached) {
      memoryKeyStore.registerKey(targetAddress, cached.privateKey);
      return cached.privateKey;
    }

    if (!this.hasScannedGroups) {
      const masterKey = await this.getMasterHmacKey(controllerSecret);
      for (let gIdx = 0; gIdx <= 5; gIdx++) {
        for (let aIdx = 0; aIdx < 32; aIdx++) {
          const child = await this.deriveChildNode(masterKey, gIdx, aIdx);
          this.derivedAddressMap.set(child.address.toLowerCase(), {
            privateKey: child.privateKey,
            groupIndex: gIdx,
            accountIndex: aIdx
          });
        }
      }
      this.hasScannedGroups = true;

      const found = this.derivedAddressMap.get(cleanTarget);
      if (found) {
        memoryKeyStore.registerKey(targetAddress, found.privateKey);
        return found.privateKey;
      }
    }

    return null;
  }

  /**
   * Encrypts and persists keyring accounts into local IndexedDB (plus optional localStorage ciphertext mirror).
   * Uses AES-GCM-256 + PBKDF2 (100,000 SHA-256 iterations). Zero network calls.
   */
  public async persistEncryptedKeyring(
    controllerSecret: string,
    controllerAddress: string,
    accounts: Array<{
      address: string;
      privateKey: string;
      index?: number;
      isActive?: boolean;
      label?: string;
    }>,
    namespace?: string
  ): Promise<PersistedVaultRecord> {
    const cleanSecret = controllerSecret.trim();
    if (!cleanSecret) {
      throw new Error("Controller secret is required to encrypt keyring");
    }
    const cleanController = (controllerAddress || "default_controller").toLowerCase();

    const payload: EncryptedKeyringPayload = {
      version: 2,
      controllerAddress: cleanController,
      namespace: namespace ? namespace.toLowerCase() : undefined,
      createdAt: Date.now(),
      accounts: accounts.map((acc, idx) => ({
        address: acc.address.toLowerCase(),
        privateKey: acc.privateKey,
        index: acc.index !== undefined ? acc.index : idx,
        isActive: acc.isActive !== undefined ? acc.isActive : true,
        label: acc.label || `Account #${idx + 1}`
      }))
    };

    const crypto = getWebCrypto();
    const salt = new Uint8Array(16);
    const iv = new Uint8Array(12);
    crypto.getRandomValues(salt);
    crypto.getRandomValues(iv);

    const cryptoKey = await deriveVaultKey(cleanSecret, salt);
    const enc = new TextEncoder();
    const ciphertextBuf = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv as BufferSource },
      cryptoKey,
      enc.encode(JSON.stringify(payload)) as BufferSource
    );

    const recordId = namespace
      ? `keyring_${cleanController}_${namespace.toLowerCase()}`
      : `keyring_${cleanController}`;

    const now = Date.now();
    const vaultRecord: PersistedVaultRecord = {
      id: recordId,
      version: 2,
      cipher: "AES-GCM-256",
      kdf: "PBKDF2",
      kdfParams: {
        iterations: PBKDF2_ITERATIONS,
        hash: "SHA-256",
        saltHex: bytesToHex(salt)
      },
      ivHex: bytesToHex(iv),
      ciphertextHex: bytesToHex(new Uint8Array(ciphertextBuf)),
      createdAt: now,
      updatedAt: now
    };

    await vaultDb.put(vaultRecord);

    try {
      if (typeof localStorage !== "undefined") {
        localStorage.setItem(`${STORAGE_KEYRING_PREFIX}${recordId}`, JSON.stringify(vaultRecord));
      }
    } catch {
      // ignore localStorage quota/iframe errors
    }

    return vaultRecord;
  }

  /**
   * Restores an encrypted keyring from IndexedDB / localStorage into closure RAM.
   * Returns the number of restored accounts.
   */
  public async restoreEncryptedKeyring(
    controllerSecret: string,
    controllerAddress: string,
    namespace?: string
  ): Promise<number> {
    const cleanSecret = controllerSecret.trim();
    if (!cleanSecret) return 0;

    const cleanController = (controllerAddress || "default_controller").toLowerCase();
    const recordId = namespace
      ? `keyring_${cleanController}_${namespace.toLowerCase()}`
      : `keyring_${cleanController}`;

    let record = await vaultDb.get(recordId);
    if (!record && namespace) {
      record = await vaultDb.get(`keyring_${cleanController}`);
    }

    if (!record) {
      try {
        if (typeof localStorage !== "undefined") {
          const raw = localStorage.getItem(`${STORAGE_KEYRING_PREFIX}${recordId}`);
          if (raw) {
            record = JSON.parse(raw) as PersistedVaultRecord;
          }
        }
      } catch {
        // ignore
      }
    }

    if (!record || !record.ciphertextHex) return 0;

    try {
      const crypto = getWebCrypto();
      const salt = hexToBytes(record.kdfParams.saltHex);
      const iv = hexToBytes(record.ivHex);
      const ciphertext = hexToBytes(record.ciphertextHex);

      const cryptoKey = await deriveVaultKey(cleanSecret, salt);
      const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv as BufferSource },
        cryptoKey,
        ciphertext as BufferSource
      );

      const dec = new TextDecoder();
      const payload = JSON.parse(dec.decode(decrypted)) as EncryptedKeyringPayload;

      let restoredCount = 0;
      if (payload && Array.isArray(payload.accounts)) {
        for (const acc of payload.accounts) {
          if (acc.address && acc.privateKey) {
            memoryKeyStore.registerKey(acc.address, acc.privateKey);
            restoredCount++;
          }
        }
      }

      return restoredCount;
    } catch {
      return 0;
    }
  }

  /**
   * Derives deterministic accounts and restores any persisted encrypted keyrings for the controller.
   */
  public async syncWithController(
    controllerSecret: string,
    controllerAddress: string,
    count: number = 16
  ): Promise<DerivedKeyringAccount[]> {
    if (!controllerSecret || !controllerAddress) return [];
    const derived = await this.deriveAccounts(controllerSecret, count, 0);
    await this.restoreEncryptedKeyring(controllerSecret, controllerAddress).catch(() => 0);
    return derived;
  }
}

export const keyringManager = KeyringManager.getInstance();
