import "fake-indexeddb/auto";
import { beforeEach, describe, expect, it } from "vitest";
import { createMemoryKeyStore, memoryKeyStore } from "../src/secureEntropy";
import { vaultDb } from "../src/storage/vaultDb";
import { VaultManager } from "../src/vaultManager";
import { VaultPayload } from "../src/vaultTypes";

describe("VaultManager + IndexedDB + RAM closure isolation", () => {
  beforeEach(async () => {
    memoryKeyStore.clear();
    await vaultDb.clearAll();
  });

  it("isolates private keys inside lexical closure with zero exposed fields", () => {
    const store = createMemoryKeyStore();
    const pk = "0x" + "12".repeat(32);
    store.registerKey("0xAbCd000000000000000000000000000000001234", pk);

    expect(Object.keys(store)).toEqual([
      "registerKey",
      "getKey",
      "hasKey",
      "getAllAddresses",
      "size",
      "clear"
    ]);
    expect((store as unknown as Record<string, unknown>).keys).toBeUndefined();
    expect(store.getKey("0xabcd000000000000000000000000000000001234")).toBe(pk);
  });

  it("initializes IndexedDB vault, fast-verifies canary password, locks & unlocks", async () => {
    const manager = new VaultManager(5000);
    const addr1 = "0x1111111111111111111111111111111111111111";
    const addr2 = "0x2222222222222222222222222222222222222222";
    const pk1 = "0x" + "aa".repeat(32);
    const pk2 = "0x" + "bb".repeat(32);

    const payload: VaultPayload = {
      version: 1,
      chainId: 8453,
      createdAt: Date.now(),
      accounts: [{ id: "1", address: addr1, short: "1111", privateKey: pk1 }]
    };

    await manager.initializeVault("super-safe-pass", payload, "test_vault");
    expect(await manager.hasVault("test_vault")).toBe(true);
    expect(manager.isUnlocked()).toBe(true);
    expect(memoryKeyStore.getKey(addr1)).toBe(pk1);

    // Canary verification check
    expect(await manager.verifyPassword("super-safe-pass", "test_vault")).toBe(true);
    expect(await manager.verifyPassword("wrong-pass", "test_vault")).toBe(false);

    // Lock wipes RAM closure keys
    manager.lockVault();
    expect(manager.isUnlocked()).toBe(false);
    expect(memoryKeyStore.size()).toBe(0);

    // Append second account and export/import backup
    await manager.addAccountsToVault(
      "super-safe-pass",
      [{ id: "2", address: addr2, short: "2222", privateKey: pk2 }],
      "test_vault"
    );
    expect(memoryKeyStore.getKey(addr2)).toBe(pk2);

    const backupJson = await manager.exportBackup("test_vault", "base");
    await manager.resetVault("test_vault");
    expect(await manager.hasVault("test_vault")).toBe(false);
    expect(memoryKeyStore.size()).toBe(0);

    const imported = await manager.importBackup("super-safe-pass", backupJson, "restored_vault");
    expect(imported.accounts).toHaveLength(2);
    expect(memoryKeyStore.getKey(addr1)).toBe(pk1);
    expect(memoryKeyStore.getKey(addr2)).toBe(pk2);
  });

  it("auto-locks and wipes RAM keys when inactivity timer expires", async () => {
    const manager = new VaultManager(60);
    await manager.initializeVault(
      "timer-pass",
      {
        version: 1,
        chainId: 1,
        createdAt: Date.now(),
        accounts: [
          {
            id: "1",
            address: "0x3333333333333333333333333333333333333333",
            short: "3333",
            privateKey: "0x" + "cc".repeat(32)
          }
        ]
      },
      "timer_vault"
    );

    expect(manager.isUnlocked()).toBe(true);
    expect(memoryKeyStore.size()).toBe(1);

    await new Promise((resolve) => setTimeout(resolve, 120));

    expect(manager.isUnlocked()).toBe(false);
    expect(memoryKeyStore.size()).toBe(0);
  });
});
