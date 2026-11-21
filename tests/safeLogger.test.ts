import { describe, expect, it, vi } from "vitest";
import { redactSensitive, redactString, safeLogger } from "../src/safeLogger";
import { generateSecureMnemonic, validateMnemonic } from "../src/secureEntropy";

describe("safeLogger & BIP-39 entropy", () => {
  it("generates valid checksummed 12-word and 24-word BIP-39 mnemonics", async () => {
    const m12 = await generateSecureMnemonic(12);
    const m24 = await generateSecureMnemonic(24);

    expect(m12.split(" ")).toHaveLength(12);
    expect(m24.split(" ")).toHaveLength(24);
    expect(await validateMnemonic(m12)).toBe(true);
    expect(await validateMnemonic(m24)).toBe(true);
    expect(await validateMnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon zoo")).toBe(false);
  });

  it("scrubs 64-hex private keys with and without 0x prefix", () => {
    const rawHex = "a1b2c3d4".repeat(8);
    const msg = `Signer failed for key 0x${rawHex} and backup ${rawHex} on RPC`;
    const scrubbed = redactString(msg);

    expect(scrubbed).not.toContain(rawHex);
    expect(scrubbed).toBe(
      "Signer failed for key [REDACTED_PRIVATE_KEY] and backup [REDACTED_PRIVATE_KEY] on RPC"
    );
  });

  it("scrubs 12-word BIP-39 phrases in strings, nested objects, and Error traces", async () => {
    const mnemonic = await generateSecureMnemonic(12);
    const hexKey = "0x" + "f0".repeat(32);

    const nested = {
      status: "failed",
      privateKey: "not-even-hex-still-redacted",
      nestedArr: [`seed leak: ${mnemonic}`, { rawNote: `pk=${hexKey}` }],
      err: new Error(`Crash while importing ${mnemonic}`)
    };

    const sanitized = redactSensitive(nested);
    expect(sanitized.privateKey).toBe("[REDACTED]");
    expect(sanitized.nestedArr[0]).toBe("seed leak: [REDACTED_MNEMONIC]");
    expect((sanitized.nestedArr[1] as { rawNote: string }).rawNote).toBe(
      "pk=[REDACTED_PRIVATE_KEY]"
    );
    expect((sanitized.err as Error).message).toBe(
      "Crash while importing [REDACTED_MNEMONIC]"
    );
  });

  it("intercepts console calls via safeLogger without leaking secrets", () => {
    const spy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const secretKey = "0x" + "99".repeat(32);

    safeLogger.warn("Watch out:", { secret: "top-secret", msg: secretKey });
    expect(spy).toHaveBeenCalledWith("Watch out:", {
      secret: "[REDACTED]",
      msg: "[REDACTED_PRIVATE_KEY]"
    });

    spy.mockRestore();
  });
});
