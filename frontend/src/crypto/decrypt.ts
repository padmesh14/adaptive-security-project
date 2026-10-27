import { decodeFile, fromBase64Url, Tier } from "./file-format";
import { importRecoveryKey } from "./encrypt";

const encoder = new TextEncoder();
const aad = (fileId: string, tier: Tier, size: number, usage: string) => encoder.encode(JSON.stringify({ format: 1, algorithm: "AES-256-GCM", fileId, tier, plaintextSize: size, usage }));

export async function decryptFile(input: ArrayBuffer, recoveryKey: CryptoKey): Promise<{ plaintext: ArrayBuffer; tier: Tier }> {
  const { header, ciphertext } = decodeFile(input);
  const salt = fromBase64Url(header.wrapSalt);
  const kek = await crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt, info: encoder.encode("adaptive-security/file-key-wrap/v1") }, recoveryKey, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
  const rawDataKey = await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromBase64Url(header.wrapNonce), additionalData: aad(header.fileId, header.tier, header.plaintextSize, "wrapped-key"), tagLength: 128 }, kek, fromBase64Url(header.wrappedKey));
  const dataKey = await crypto.subtle.importKey("raw", rawDataKey, "AES-GCM", false, ["decrypt"]);
  new Uint8Array(rawDataKey).fill(0);
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromBase64Url(header.contentNonce), additionalData: aad(header.fileId, header.tier, header.plaintextSize, "content"), tagLength: 128 }, dataKey, ciphertext);
  if (plaintext.byteLength !== header.plaintextSize) throw new Error("Decrypted size does not match authenticated metadata");
  return { plaintext, tier: header.tier };
}

export { importRecoveryKey };
