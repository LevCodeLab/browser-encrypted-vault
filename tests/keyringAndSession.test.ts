import "fake-indexeddb/auto";
import { beforeEach, describe, expect, it } from "vitest";
import { KeyringManager } from "../src/keyringManager";
import { memoryKeyStore } from "../src/secureEntropy";
import { SessionRecoveryManager } from "../src/storage/sessionRecovery";
import { vaultDb } from "../src/storage/vaultDb";

describe("KeyringManager & SessionRecoveryManager", () => {
  beforeEach(async () => {
    memoryKeyStore.clear();
    SessionRecoveryManager.clearSession();
    await vaultDb.clearAll();
  });

  it("deterministically derives child keyring accounts and auto-restores by address", async () => {
    const keyring = new KeyringManager();
    const secret = "eip191-controller-signature-seed-001";

    const firstBatch = await keyring.deriveAccounts(secret, 4, 0);
    expect(firstBatch).toHaveLength(4);

    // Wipe RAM and verify deterministic re-derivation + scan auto-restore
    memoryKeyStore.clear();
    const freshKeyring = new KeyringManager();
    const restoredPk = await freshKeyring.tryAutoRestoreKeyForAddress(
      secret,
      firstBatch[3].address
    );

    expect(restoredPk).toBe(firstBatch[3].privateKey);
    expect(memoryKeyStore.getKey(firstBatch[3].address)).toBe(firstBatch[3].privateKey);
  });

  it("persists and restores encrypted keyring records in IndexedDB", async () => {
    const keyring = new KeyringManager();
    const controllerAddr = "0x9999999999999999999999999999999999999999";
    const secret = "controller-vault-passphrase";

    const accounts = await keyring.deriveAccounts(secret, 3, 1);
    await keyring.persistEncryptedKeyring(secret, controllerAddr, accounts, "trading");

    memoryKeyStore.clear();
    expect(memoryKeyStore.size()).toBe(0);

    const count = await keyring.restoreEncryptedKeyring(secret, controllerAddr, "trading");
    expect(count).toBe(3);
    expect(memoryKeyStore.getKey(accounts[1].address)).toBe(accounts[1].privateKey);
  });

  it("isolates session recovery strictly to matching controllerAddress and reconciles receipts", async () => {
    const controllerA = "0xAAAA00000000000000000000000000000000AAAA";
    const controllerB = "0xBBBB00000000000000000000000000000000BBBB";

    SessionRecoveryManager.saveSession({
      version: 2,
      txHash: "0x" + "dd".repeat(32),
      chainId: 8453,
      label: "Active Batch",
      timestamp: Date.now(),
      accountAddresses: ["0x1111111111111111111111111111111111111111"],
      controllerAddress: controllerA
    });

    expect(SessionRecoveryManager.getSavedSession(null)).toBeNull();
    expect(SessionRecoveryManager.getSavedSession(controllerB)).toBeNull();

    const matched = SessionRecoveryManager.getSavedSession(controllerA.toLowerCase());
    expect(matched).not.toBeNull();
    expect(matched?.label).toBe("Active Batch");

    const check = await SessionRecoveryManager.reconcileSessionOnChain(matched!, {
      getTransactionReceipt: async () => ({ status: 1 }),
      getBlockNumber: async () => 19_420_000
    });
    expect(check).toEqual({ isValid: true, currentBlock: 19_420_000 });
  });
});
