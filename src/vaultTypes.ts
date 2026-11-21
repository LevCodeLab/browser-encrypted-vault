export interface VaultAccountEntry {
  id: string;
  address: string;
  short: string;
  privateKey?: string;
  isWatchOnly?: boolean;
  label?: string;
  index?: number;
}

export interface VaultPayload {
  version: 1;
  chainId: number;
  createdAt: number;
  mnemonic?: string;
  accounts: VaultAccountEntry[];
}

export interface EncryptedVaultBlob {
  version: 1;
  cipher: "AES-GCM-256";
  kdf: "PBKDF2";
  kdfParams: {
    iterations: number;
    hash: "SHA-256";
    saltHex: string;
  };
  ivHex: string;
  ciphertextHex: string;
  canaryCiphertextHex?: string;
}

export interface PersistedVaultRecord {
  id: string;
  version: number;
  cipher: "AES-GCM-256";
  kdf: "PBKDF2";
  kdfParams: {
    iterations: number;
    hash: "SHA-256";
    saltHex: string;
  };
  ivHex: string;
  ciphertextHex: string;
  canaryCiphertextHex?: string;
  createdAt: number;
  updatedAt: number;
}

export interface VaultUnlockSession {
  isUnlocked: boolean;
  unlockedAt: number | null;
  expiresAt: number | null;
}

export interface ExportableBackupPayload extends EncryptedVaultBlob {
  app: "browser-encrypted-vault";
  exportedAt: number;
  network: string;
}
