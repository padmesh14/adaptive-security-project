import { encodeFile, FileHeader, MAX_FILE_BYTES, Tier, toBase64Url } from "./file-format";

const encoder = new TextEncoder();
const aad = (fileId: string, tier: Tier, size: number, usage: string) => encoder.encode(JSON.stringify({ format: 1, algorithm: "AES-256-GCM", fileId, tier, plaintextSize: size, usage }));

async function wrappingKey(recoveryKey: CryptoKey, salt: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt, info: encoder.encode("adaptive-security/file-key-wrap/v1") }, recoveryKey, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

export async function createRecoveryKey(): Promise<{ key: CryptoKey; exportCode: string }> {
  const raw = crypto.getRandomValues(new Uint8Array(32));
  const exportCode = toBase64Url(raw);
  const key = await crypto.subtle.importKey("raw", raw, "HKDF", false, ["deriveKey"]);
  raw.fill(0);
  return { key, exportCode };
}

export async function importRecoveryKey(exportCode: string): Promise<CryptoKey> {
  const normalized = exportCode.trim();
  if (!/^[A-Za-z0-9_-]{43}$/.test(normalized)) throw new Error("Recovery code is invalid");
  const padded = normalized.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - normalized.length % 4) % 4);
  const raw = Uint8Array.from(atob(padded), c => c.charCodeAt(0));
  if (raw.length !== 32) throw new Error("Recovery code is invalid");
  const key = await crypto.subtle.importKey("raw", raw, "HKDF", false, ["deriveKey"]);
  raw.fill(0);
  return key;
}

export async function encryptFile(file: File, tier: Tier, recoveryKey: CryptoKey, fileId: string = crypto.randomUUID()): Promise<{ encrypted: Uint8Array; header: FileHeader; digest: string }> {
  if (file.size > MAX_FILE_BYTES) throw new Error("File exceeds the 50 MiB limit");
  const plain = await file.arrayBuffer();
  const dataKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  const contentNonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv: contentNonce, additionalData: aad(fileId, tier, file.size, "content"), tagLength: 128 }, dataKey, plain);
  const rawDataKey = new Uint8Array(await crypto.subtle.exportKey("raw", dataKey));
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const wrapNonce = crypto.getRandomValues(new Uint8Array(12));
  const kek = await wrappingKey(recoveryKey, salt);
  const wrappedKey = await crypto.subtle.encrypt({ name: "AES-GCM", iv: wrapNonce, additionalData: aad(fileId, tier, file.size, "wrapped-key"), tagLength: 128 }, kek, rawDataKey);
  rawDataKey.fill(0);
  const header: FileHeader = { version: 1, algorithm: "AES-256-GCM", tier, fileId, contentNonce: toBase64Url(contentNonce), wrapSalt: toBase64Url(salt), wrapNonce: toBase64Url(wrapNonce), wrappedKey: toBase64Url(new Uint8Array(wrappedKey)), plaintextSize: file.size };
  const encrypted = encodeFile(header, ciphertext);
  const digest = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", encrypted))).map(b => b.toString(16).padStart(2, "0")).join("");
  return { encrypted, header, digest };
}
