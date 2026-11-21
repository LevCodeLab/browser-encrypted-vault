import { describe, expect, it } from "vitest";
import { decryptVault, encryptVault, PBKDF2_ITERATIONS } from "../src/encryptedVault";
import { VaultPayload } from "../src/vaultTypes";

describe("encryptedVault (AES-GCM-256 + PBKDF2)", () => {
  const samplePayload: VaultPayload = {
    version: 1,
    chainId: 1,
    createdAt: 1_700_000_000_000,
    accounts: [
      {
        id: "1",
        address: "0x1111111111111111111111111111111111111111",
        short: "1111",
        privateKey: "0x" + "ab".repeat(32),
        label: "Primary Signer"
      }
    ]
  };

  it("encrypts and decrypts payload with 100k PBKDF2 rounds", async () => {
    const blob = await encryptVault(samplePayload, "masala-chai-9000");

    expect(blob.version).toBe(1);
    expect(blob.cipher).toBe("AES-GCM-256");
    expect(blob.kdf).toBe("PBKDF2");
    expect(blob.kdfParams.iterations).toBe(PBKDF2_ITERATIONS);
    expect(blob.kdfParams.saltHex).toHaveLength(32); // 16 bytes
    expect(blob.ivHex).toHaveLength(24); // 12 bytes
    expect(blob.ciphertextHex).not.toContain("ab".repeat(16));

    const decrypted = await decryptVault(blob, "masala-chai-9000");
    expect(decrypted).toEqual(samplePayload);
  });

  it("produces fresh salt and IV on every encryption call", async () => {
    const first = await encryptVault(samplePayload, "same-password");
    const second = await encryptVault(samplePayload, "same-password");

    expect(first.kdfParams.saltHex).not.toBe(second.kdfParams.saltHex);
    expect(first.ivHex).not.toBe(second.ivHex);
    expect(first.ciphertextHex).not.toBe(second.ciphertextHex);
  });

  it("rejects wrong password and tampered ciphertext", async () => {
    const blob = await encryptVault(samplePayload, "correct-password");

    await expect(decryptVault(blob, "wrong-password")).rejects.toThrow(
      /Incorrect password or corrupted vault blob/
    );

    const flippedLastNibble =
      blob.ciphertextHex.slice(0, -1) +
      (blob.ciphertextHex.endsWith("0") ? "1" : "0");
    const tampered = { ...blob, ciphertextHex: flippedLastNibble };

    await expect(decryptVault(tampered, "correct-password")).rejects.toThrow(
      /Incorrect password or corrupted vault blob/
    );
  });
});
