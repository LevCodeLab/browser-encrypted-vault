/**
 * Zero-dependency IndexedDB store for encrypted vault records.
 * Automatically falls back to an in-memory Map in headless environments without IndexedDB.
 */

import { PersistedVaultRecord } from "../vaultTypes";

const DB_NAME = "BrowserEncryptedVaultDB";
const DB_VERSION = 1;
const STORE_NAME = "vaultRecords";

export class VaultDatabase {
  private memoryFallback = new Map<string, PersistedVaultRecord>();

  private hasIndexedDb(): boolean {
    return typeof indexedDB !== "undefined" && indexedDB !== null;
  }

  private openDb(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(DB_NAME, DB_VERSION);

      request.onupgradeneeded = () => {
        const db = request.result;
        if (!db.objectStoreNames.contains(STORE_NAME)) {
          db.createObjectStore(STORE_NAME, { keyPath: "id" });
        }
      };

      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error || new Error("Failed to open IndexedDB"));
    });
  }

  public async get(id: string): Promise<PersistedVaultRecord | undefined> {
    if (!this.hasIndexedDb()) {
      return this.memoryFallback.get(id);
    }

    const db = await this.openDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, "readonly");
      const store = tx.objectStore(STORE_NAME);
      const req = store.get(id);

      req.onsuccess = () => {
        db.close();
        resolve((req.result as PersistedVaultRecord | undefined) ?? undefined);
      };
      req.onerror = () => {
        db.close();
        reject(req.error || new Error("Failed to read vault record"));
      };
    });
  }

  public async put(record: PersistedVaultRecord): Promise<void> {
    if (!this.hasIndexedDb()) {
      this.memoryFallback.set(record.id, { ...record });
      return;
    }

    const db = await this.openDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, "readwrite");
      const store = tx.objectStore(STORE_NAME);
      const req = store.put(record);

      req.onsuccess = () => {
        db.close();
        resolve();
      };
      req.onerror = () => {
        db.close();
        reject(req.error || new Error("Failed to persist vault record"));
      };
    });
  }

  public async delete(id: string): Promise<void> {
    if (!this.hasIndexedDb()) {
      this.memoryFallback.delete(id);
      return;
    }

    const db = await this.openDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, "readwrite");
      const store = tx.objectStore(STORE_NAME);
      const req = store.delete(id);

      req.onsuccess = () => {
        db.close();
        resolve();
      };
      req.onerror = () => {
        db.close();
        reject(req.error || new Error("Failed to delete vault record"));
      };
    });
  }

  public async clearAll(): Promise<void> {
    this.memoryFallback.clear();
    if (!this.hasIndexedDb()) return;

    const db = await this.openDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, "readwrite");
      const store = tx.objectStore(STORE_NAME);
      const req = store.clear();

      req.onsuccess = () => {
        db.close();
        resolve();
      };
      req.onerror = () => {
        db.close();
        reject(req.error || new Error("Failed to clear vault store"));
      };
    });
  }
}

export const vaultDb = new VaultDatabase();
