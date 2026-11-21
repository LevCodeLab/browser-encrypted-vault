/**
 * Authenticated WebCrypto Vault Manager
 * - AES-GCM 256-bit encryption with PBKDF2 (100,000 iterations, SHA-256).
 * - Fast canary check for zero-leak password verification without full payload unwrap.
 * - Automatic 30-minute inactivity lock that wipes RAM closure keys.
 * - Persists encrypted blobs into IndexedDB via vaultDb.
 */

import { deriveVaultKey, PBKDF2_ITERATIONS } from "./encryptedVault";
import { safeLogger } from "./safeLogger";
import { bytesToHex, getWebCrypto, hexToBytes, memoryKeyStore } from "./secureEntropy";
import { vaultDb } from "./storage/vaultDb";
import {
  ExportableBackupPayload,
  PersistedVaultRecord,
  VaultAccountEntry,
  VaultPayload,
  VaultUnlockSession
} from "./vaultTypes";

const CANARY_PLAINTEXT = "VAULT_CANARY_V1";
export const DEFAULT_AUTO_LOCK_TIMEOUT_MS = 30 * 60 * 1000; // 30 minutes
export const PRIMARY_VAULT_ID = "main_vault";

export class VaultManager {
  private static instance: VaultManager;
  private autoLockTimeoutMs: number = DEFAULT_AUTO_LOCK_TIMEOUT_MS;
  private autoLockTimer: ReturnType<typeof setTimeout> | null = null;
  private session: VaultUnlockSession = {
    isUnlocked: false,
    unlockedAt: null,
    expiresAt: null
  };
  private listeners: Set<(unlocked: boolean) => void> = new Set();

  public constructor(autoLockTimeoutMs: number = DEFAULT_AUTO_LOCK_TIMEOUT_MS) {
    this.autoLockTimeoutMs = autoLockTimeoutMs;
    this.setupInactivityListener();
  }

  public static getInstance(): VaultManager {
    if (!VaultManager.instance) {
      VaultManager.instance = new VaultManager();
    }
    return VaultManager.instance;
  }

  public setAutoLockTimeoutMs(timeoutMs: number): void {
    this.autoLockTimeoutMs = Math.max(1000, timeoutMs);
    if (this.session.isUnlocked) {
      this.renewSession();
    }
  }

  public subscribe(listener: (unlocked: boolean) => void): () => void {
    this.listeners.add(listener);
    listener(this.session.isUnlocked);
    return () => {
      this.listeners.delete(listener);
    };
  }

  private notifyListeners(): void {
    this.listeners.forEach((listener) => {
      try {
        listener(this.session.isUnlocked);
      } catch (err) {
        safeLogger.error("Error in vault listener:", err);
      }
    });
  }

  private setupInactivityListener(): void {
    if (typeof window !== "undefined" && typeof window.addEventListener === "function") {
      const reset = () => {
        if (this.session.isUnlocked) {
          this.renewSession();
        }
      };
      window.addEventListener("pointerdown", reset, { passive: true });
      window.addEventListener("keydown", reset, { passive: true });
    }
  }

  public renewSession(): void {
    if (!this.session.isUnlocked) return;
    if (this.autoLockTimer) clearTimeout(this.autoLockTimer);
    this.session.expiresAt = Date.now() + this.autoLockTimeoutMs;
    this.autoLockTimer = setTimeout(() => {
      safeLogger.info("Vault auto-locked due to inactivity");
      this.lockVault();
    }, this.autoLockTimeoutMs);
  }

  public isUnlocked(): boolean {
    if (!this.session.isUnlocked) return false;
    if (this.session.expiresAt && Date.now() > this.session.expiresAt) {
      this.lockVault();
      return false;
    }
    return true;
  }

  public getSessionInfo(): VaultUnlockSession {
    return { ...this.session };
  }

  public lockVault(): void {
    if (this.autoLockTimer) {
      clearTimeout(this.autoLockTimer);
      this.autoLockTimer = null;
    }
    this.session = {
      isUnlocked: false,
      unlockedAt: null,
      expiresAt: null
    };
    memoryKeyStore.clear();
    this.notifyListeners();
  }

  public async hasVault(vaultId: string = PRIMARY_VAULT_ID): Promise<boolean> {
    try {
      const record = await vaultDb.get(vaultId);
      return Boolean(record);
    } catch {
      return false;
    }
  }

  public async getVaultRecord(
    vaultId: string = PRIMARY_VAULT_ID
  ): Promise<PersistedVaultRecord | undefined> {
    return vaultDb.get(vaultId);
  }

  /**
   * Initializes or updates an encrypted vault with AES-GCM-256 + PBKDF2 (100k rounds).
   * Persists ciphertext into IndexedDB and loads signing keys into closure RAM.
   */
  public async initializeVault(
    password: string,
    payload: VaultPayload,
    vaultId: string = PRIMARY_VAULT_ID
  ): Promise<PersistedVaultRecord> {
    if (!password || password.length < 4) {
      throw new Error("Vault password must be at least 4 characters long");
    }

    const crypto = getWebCrypto();
    const salt = new Uint8Array(16);
    const iv = new Uint8Array(12);
    const canaryIv = new Uint8Array(12);

    crypto.getRandomValues(salt);
    crypto.getRandomValues(iv);
    crypto.getRandomValues(canaryIv);

    const key = await deriveVaultKey(password, salt);
    const enc = new TextEncoder();

    const encodedPayload = enc.encode(JSON.stringify(payload));
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv as BufferSource },
      key,
      encodedPayload as BufferSource
    );

    const encodedCanary = enc.encode(CANARY_PLAINTEXT);
    const canaryCiphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: canaryIv as BufferSource },
      key,
      encodedCanary as BufferSource
    );

    const fullCanaryHex =
      bytesToHex(canaryIv) + ":" + bytesToHex(new Uint8Array(canaryCiphertext));

    const now = Date.now();
    const record: PersistedVaultRecord = {
      id: vaultId,
      version: 1,
      cipher: "AES-GCM-256",
      kdf: "PBKDF2",
      kdfParams: {
        iterations: PBKDF2_ITERATIONS,
        hash: "SHA-256",
        saltHex: bytesToHex(salt)
      },
      ivHex: bytesToHex(iv),
      ciphertextHex: bytesToHex(new Uint8Array(ciphertext)),
      canaryCiphertextHex: fullCanaryHex,
      createdAt: now,
      updatedAt: now
    };

    await vaultDb.put(record);

    for (const acc of payload.accounts) {
      if (acc.address && acc.privateKey) {
        memoryKeyStore.registerKey(acc.address, acc.privateKey);
      }
    }

    this.session = {
      isUnlocked: true,
      unlockedAt: now,
      expiresAt: now + this.autoLockTimeoutMs
    };
    this.renewSession();
    this.notifyListeners();

    safeLogger.info("Encrypted vault initialized with AES-GCM-256");
    return record;
  }

  /**
   * Fast verification of password using encrypted canary token without unwrapping full vault.
   */
  public async verifyPassword(
    password: string,
    vaultId: string = PRIMARY_VAULT_ID
  ): Promise<boolean> {
    const record = await this.getVaultRecord(vaultId);
    if (!record) return false;

    try {
      const crypto = getWebCrypto();
      const salt = hexToBytes(record.kdfParams.saltHex);
      const key = await deriveVaultKey(password, salt);

      if (record.canaryCiphertextHex && record.canaryCiphertextHex.includes(":")) {
        const [canaryIvHex, canaryCipherHex] = record.canaryCiphertextHex.split(":");
        const canaryIv = hexToBytes(canaryIvHex);
        const canaryCipher = hexToBytes(canaryCipherHex);

        const decryptedCanary = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv: canaryIv as BufferSource },
          key,
          canaryCipher as BufferSource
        );
        const dec = new TextDecoder();
        return dec.decode(decryptedCanary) === CANARY_PLAINTEXT;
      }

      const iv = hexToBytes(record.ivHex);
      const ciphertext = hexToBytes(record.ciphertextHex);
      await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv as BufferSource },
        key,
        ciphertext as BufferSource
      );
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Unlocks the vault, hydrates keys into closure-isolated RAM, and starts inactivity auto-lock.
   */
  public async unlockVault(
    password: string,
    vaultId: string = PRIMARY_VAULT_ID
  ): Promise<VaultPayload> {
    const record = await this.getVaultRecord(vaultId);
    if (!record) {
      throw new Error("No encrypted vault found in local database");
    }

    const crypto = getWebCrypto();
    const salt = hexToBytes(record.kdfParams.saltHex);
    const iv = hexToBytes(record.ivHex);
    const ciphertext = hexToBytes(record.ciphertextHex);

    const key = await deriveVaultKey(password, salt);

    let decryptedBuffer: ArrayBuffer;
    try {
      decryptedBuffer = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv as BufferSource },
        key,
        ciphertext as BufferSource
      );
    } catch {
      throw new Error("Incorrect vault password or corrupted vault data");
    }

    const dec = new TextDecoder();
    const payload = JSON.parse(dec.decode(decryptedBuffer)) as VaultPayload;

    for (const acc of payload.accounts) {
      if (acc.address && acc.privateKey) {
        memoryKeyStore.registerKey(acc.address, acc.privateKey);
      }
    }

    const now = Date.now();
    this.session = {
      isUnlocked: true,
      unlockedAt: now,
      expiresAt: now + this.autoLockTimeoutMs
    };
    this.renewSession();
    this.notifyListeners();

    safeLogger.info(`Vault unlocked. ${payload.accounts.length} account keys hydrated in RAM.`);
    return payload;
  }

  /**
   * Appends or updates accounts inside an existing encrypted vault.
   */
  public async addAccountsToVault(
    password: string,
    newAccounts: VaultAccountEntry[],
    vaultId: string = PRIMARY_VAULT_ID
  ): Promise<void> {
    const existing = await this.unlockVault(password, vaultId);
    const addressMap = new Map<string, VaultAccountEntry>();

    for (const acc of existing.accounts) {
      addressMap.set(acc.address.toLowerCase(), acc);
    }
    for (const nextAcc of newAccounts) {
      addressMap.set(nextAcc.address.toLowerCase(), nextAcc);
    }

    existing.accounts = Array.from(addressMap.values());
    await this.initializeVault(password, existing, vaultId);
  }

  /**
   * Exports an encrypted JSON backup string safe to save offline.
   */
  public async exportBackup(
    vaultId: string = PRIMARY_VAULT_ID,
    network: string = "evm"
  ): Promise<string> {
    const record = await this.getVaultRecord(vaultId);
    if (!record) throw new Error("No vault record to export");

    const backup: ExportableBackupPayload = {
      app: "browser-encrypted-vault",
      exportedAt: Date.now(),
      network,
      version: 1,
      cipher: "AES-GCM-256",
      kdf: "PBKDF2",
      kdfParams: record.kdfParams,
      ivHex: record.ivHex,
      ciphertextHex: record.ciphertextHex,
      canaryCiphertextHex: record.canaryCiphertextHex
    };

    return JSON.stringify(backup, null, 2);
  }

  /**
   * Imports an encrypted JSON backup, verifies password decryption, and saves to IndexedDB.
   */
  public async importBackup(
    password: string,
    jsonStr: string,
    vaultId: string = PRIMARY_VAULT_ID
  ): Promise<VaultPayload> {
    let parsed: Partial<ExportableBackupPayload>;
    try {
      parsed = JSON.parse(jsonStr) as Partial<ExportableBackupPayload>;
    } catch {
      throw new Error("Invalid backup file: not valid JSON");
    }

    if (
      parsed.app !== "browser-encrypted-vault" ||
      parsed.cipher !== "AES-GCM-256" ||
      !parsed.ciphertextHex ||
      !parsed.ivHex ||
      !parsed.kdfParams
    ) {
      throw new Error("Invalid or incompatible encrypted vault backup format");
    }

    const record: PersistedVaultRecord = {
      id: vaultId,
      version: 1,
      cipher: "AES-GCM-256",
      kdf: "PBKDF2",
      kdfParams: parsed.kdfParams,
      ivHex: parsed.ivHex,
      ciphertextHex: parsed.ciphertextHex,
      canaryCiphertextHex: parsed.canaryCiphertextHex,
      createdAt: parsed.exportedAt || Date.now(),
      updatedAt: Date.now()
    };

    await vaultDb.put(record);
    return this.unlockVault(password, vaultId);
  }

  /**
   * Wipes both RAM closure keys and the IndexedDB record for the target vault.
   */
  public async resetVault(vaultId: string = PRIMARY_VAULT_ID): Promise<void> {
    this.lockVault();
    await vaultDb.delete(vaultId);
    safeLogger.info("Vault wiped from IndexedDB and RAM.");
  }
}

export const vaultManager = VaultManager.getInstance();
