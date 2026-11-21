import {
  deriveSecureAccount,
  encryptVault,
  decryptVault,
  generateSecureMnemonic,
  memoryKeyStore,
  safeLogger
} from "../src";

async function main() {
  const mnemonic = await generateSecureMnemonic(12);
  const account = await deriveSecureAccount(mnemonic, 0);

  const blob = await encryptVault(
    {
      version: 1,
      chainId: 8453,
      createdAt: Date.now(),
      mnemonic,
      accounts: [
        {
          id: account.id,
          address: account.address,
          short: account.short,
          privateKey: memoryKeyStore.getKey(account.address)
        }
      ]
    },
    "masala_chai_secret"
  );

  const unlocked = await decryptVault(blob, "masala_chai_secret");
  safeLogger.info("Unlocked accounts:", unlocked.accounts.length, "Seed:", mnemonic);
}

main().catch((err) => safeLogger.error(err));
