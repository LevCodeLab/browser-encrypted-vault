/**
 * Controller-bound browser session recovery manager.
 * Ensures session metadata is only returned when the active connected address
 * matches the controller address that created the session.
 */

export interface PersistedAccountSession {
  version: 2;
  txHash?: string;
  chainId: number;
  label?: string;
  startedAtBlock?: number;
  timestamp: number;
  accountAddresses: string[];
  controllerAddress: string;
}

export interface RpcReceiptProvider {
  getTransactionReceipt: (txHash: string) => Promise<{ status: number | bigint | null } | null>;
  getBlockNumber: () => Promise<number>;
}

const STORAGE_KEY_RECOVERY_V2 = "bev_active_session_recovery_v2";
const LEGACY_STORAGE_KEY_V1 = "bev_active_session_recovery_v1";

const fallbackStorage = new Map<string, string>();

function readStorage(key: string): string | null {
  try {
    if (typeof localStorage !== "undefined") {
      return localStorage.getItem(key);
    }
  } catch {
    // ignore storage permission errors in strict iframes
  }
  return fallbackStorage.get(key) ?? null;
}

function writeStorage(key: string, value: string): void {
  try {
    if (typeof localStorage !== "undefined") {
      localStorage.setItem(key, value);
      return;
    }
  } catch {
    // fallback to RAM map
  }
  fallbackStorage.set(key, value);
}

function removeStorage(key: string): void {
  try {
    if (typeof localStorage !== "undefined") {
      localStorage.removeItem(key);
    }
  } catch {
    // ignore
  }
  fallbackStorage.delete(key);
}

export class SessionRecoveryManager {
  /**
   * Purges legacy v1 storage keys so stale unverified sessions cannot linger.
   */
  public static purgeLegacyStorage(): void {
    removeStorage(LEGACY_STORAGE_KEY_V1);
  }

  /**
   * Saves confirmed session metadata bound to the controller address.
   */
  public static saveSession(session: PersistedAccountSession): void {
    this.purgeLegacyStorage();
    writeStorage(STORAGE_KEY_RECOVERY_V2, JSON.stringify(session));
  }

  /**
   * Reads raw last session regardless of connected wallet (useful for UI hints).
   */
  public static getAnyLastSession(): PersistedAccountSession | null {
    try {
      const data = readStorage(STORAGE_KEY_RECOVERY_V2);
      if (data) {
        return JSON.parse(data) as PersistedAccountSession;
      }
    } catch {
      return null;
    }
    return null;
  }

  /**
   * Returns saved session ONLY if connectedAddress matches session.controllerAddress.
   * Prevents cross-account metadata leakage when switching wallets.
   */
  public static getSavedSession(connectedAddress?: string | null): PersistedAccountSession | null {
    try {
      this.purgeLegacyStorage();
      if (!connectedAddress) {
        return null;
      }

      const data = readStorage(STORAGE_KEY_RECOVERY_V2);
      if (!data) return null;

      const parsed = JSON.parse(data) as PersistedAccountSession;
      if (
        parsed &&
        parsed.controllerAddress &&
        parsed.controllerAddress.toLowerCase() === connectedAddress.toLowerCase()
      ) {
        return parsed;
      }
    } catch {
      return null;
    }
    return null;
  }

  /**
   * Clears saved session state.
   */
  public static clearSession(): void {
    this.purgeLegacyStorage();
    removeStorage(STORAGE_KEY_RECOVERY_V2);
  }

  /**
   * Reconciles a restored session against live RPC transaction receipt status.
   */
  public static async reconcileSessionOnChain(
    session: PersistedAccountSession,
    provider: RpcReceiptProvider
  ): Promise<{ isValid: boolean; currentBlock: number }> {
    if (!session.txHash) {
      return { isValid: false, currentBlock: 0 };
    }
    try {
      const [receipt, currentBlock] = await Promise.all([
        provider.getTransactionReceipt(session.txHash),
        provider.getBlockNumber()
      ]);

      const statusNum = receipt && receipt.status !== null ? Number(receipt.status) : 0;
      return {
        isValid: receipt !== null && statusNum === 1,
        currentBlock
      };
    } catch {
      return { isValid: false, currentBlock: 0 };
    }
  }
}
