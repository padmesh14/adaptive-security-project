import { describe, expect, it } from "vitest";
import { createRecoveryKey, encryptFile, importRecoveryKey } from "./encrypt";
import { decryptFile } from "./decrypt";
import { decodeFile, encodeFile } from "./file-format";

const syntheticFile = (data: Uint8Array, name = "sample.bin") => ({ name, size: data.length, arrayBuffer: async () => data.slice().buffer }) as File;

describe("versioned browser encrypted format", () => {
  it.each(["Low", "Medium", "High"] as const)("round-trips binary data at %s tier in a separately imported recovery context", async tier => {
    const data = new Uint8Array([0, 1, 2, 128, 255, 65]);
    const { exportCode } = await createRecoveryKey();
    const encrypted = await encryptFile(syntheticFile(data), tier, await importRecoveryKey(exportCode));
    const recovered = await decryptFile(encrypted.encrypted.buffer, await importRecoveryKey(exportCode));
    expect(recovered.tier).toBe(tier);
    expect(Array.from(new Uint8Array(recovered.plaintext))).toEqual(Array.from(data));
  });

  it("uses unique nonces and independent file keys", async () => {
    const { key } = await createRecoveryKey(), file = syntheticFile(new Uint8Array([9, 8, 7]));
    const first = await encryptFile(file, "Low", key), second = await encryptFile(file, "Low", key);
    expect(first.header.contentNonce).not.toBe(second.header.contentNonce);
    expect(first.header.wrappedKey).not.toBe(second.header.wrappedKey);
  });

  it("rejects wrong recovery keys and changed authenticated metadata/ciphertext", async () => {
    const { key } = await createRecoveryKey(), encrypted = await encryptFile(syntheticFile(new Uint8Array([1, 2, 3])), "Medium", key);
    const wrong = await createRecoveryKey();
    await expect(decryptFile(encrypted.encrypted.buffer, wrong.key)).rejects.toThrow();
    const decoded = decodeFile(encrypted.encrypted.buffer);
    const tamperedHeader = { ...decoded.header, tier: "High" as const };
    await expect(decryptFile(encodeFile(tamperedHeader, decoded.ciphertext).buffer, key)).rejects.toThrow();
    const changedSize = { ...decoded.header, plaintextSize: decoded.header.plaintextSize + 1 };
    expect(() => encodeFile(changedSize, decoded.ciphertext)).toThrow(/length/);
    const changedWrapped = { ...decoded.header, wrappedKey: `${decoded.header.wrappedKey.slice(0, -1)}${decoded.header.wrappedKey.endsWith("A") ? "B" : "A"}` };
    await expect(decryptFile(encodeFile(changedWrapped, decoded.ciphertext).buffer, key)).rejects.toThrow();
    const tamperedBytes = encrypted.encrypted.slice(); tamperedBytes[tamperedBytes.length - 1] ^= 1;
    await expect(decryptFile(tamperedBytes.buffer, key)).rejects.toThrow();
  });

  it("rejects malformed envelopes", async () => {
    await expect(decryptFile(new Uint8Array([0, 1, 2]).buffer, (await createRecoveryKey()).key)).rejects.toThrow(/signature|size/i);
    const { key } = await createRecoveryKey();
    const encrypted = await encryptFile(syntheticFile(new Uint8Array([1])), "Low", key);
    await expect(importRecoveryKey("not-a-recovery-code")).rejects.toThrow();
    const bad = encrypted.encrypted.slice(); bad[7] = 255;
    await expect(decryptFile(bad.buffer, key)).rejects.toThrow(/header/i);
  });
});
