export const FORMAT_VERSION = 1;
export const MAGIC = new Uint8Array([0x41, 0x4d, 0x4c, 0x53]); // AMLS
export const MAX_HEADER_BYTES = 16 * 1024;
export const MAX_FILE_BYTES = 50 * 1024 * 1024;

export type Tier = "Low" | "Medium" | "High";
export type FileHeader = {
  version: 1;
  algorithm: "AES-256-GCM";
  tier: Tier;
  fileId: string;
  contentNonce: string;
  wrapSalt: string;
  wrapNonce: string;
  wrappedKey: string;
  plaintextSize: number;
};

export function encodeFile(header: FileHeader, ciphertext: ArrayBuffer): Uint8Array {
  validateHeader(header);
  if (ciphertext.byteLength !== header.plaintextSize + 16) throw new Error("Encrypted file length does not match metadata");
  if (ciphertext.byteLength > MAX_FILE_BYTES + 16) throw new Error("Encrypted file exceeds the size limit");
  const headerBytes = new TextEncoder().encode(JSON.stringify(header));
  if (headerBytes.length > MAX_HEADER_BYTES) throw new Error("Encrypted file header is too large");
  const result = new Uint8Array(8 + headerBytes.length + ciphertext.byteLength);
  result.set(MAGIC, 0);
  new DataView(result.buffer).setUint32(4, headerBytes.length, false);
  result.set(headerBytes, 8);
  result.set(new Uint8Array(ciphertext), 8 + headerBytes.length);
  return result;
}

export function decodeFile(input: ArrayBuffer): { header: FileHeader; ciphertext: ArrayBuffer } {
  const bytes = new Uint8Array(input);
  if (bytes.length < 24 || bytes.length > MAX_FILE_BYTES + MAX_HEADER_BYTES + 24) throw new Error("Encrypted file size is invalid");
  if (!MAGIC.every((byte, index) => bytes[index] === byte)) throw new Error("Encrypted file signature is invalid");
  const headerLength = new DataView(input).getUint32(4, false);
  if (headerLength < 2 || headerLength > MAX_HEADER_BYTES || 8 + headerLength + 16 > bytes.length) throw new Error("Encrypted file header length is invalid");
  let header: FileHeader;
  try { header = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes.slice(8, 8 + headerLength))); }
  catch { throw new Error("Encrypted file header is malformed"); }
  validateHeader(header);
  const ciphertext = bytes.slice(8 + headerLength);
  if (ciphertext.length !== header.plaintextSize + 16) throw new Error("Encrypted file length does not match authenticated metadata");
  return { header, ciphertext: ciphertext.buffer };
}

export function validateHeader(value: unknown): asserts value is FileHeader {
  if (!value || typeof value !== "object") throw new Error("Encrypted file metadata is invalid");
  const h = value as Partial<FileHeader>;
  if (h.version !== FORMAT_VERSION || h.algorithm !== "AES-256-GCM" || !["Low", "Medium", "High"].includes(h.tier ?? "")) throw new Error("Encrypted file format is unsupported");
  if (typeof h.fileId !== "string" || !/^[0-9a-f-]{36}$/i.test(h.fileId)) throw new Error("Encrypted file ID is invalid");
  for (const field of [h.contentNonce, h.wrapSalt, h.wrapNonce, h.wrappedKey]) {
    if (typeof field !== "string" || !/^[A-Za-z0-9_-]+$/.test(field)) throw new Error("Encrypted key envelope is malformed");
  }
  if (typeof h.plaintextSize !== "number" || !Number.isSafeInteger(h.plaintextSize) || h.plaintextSize < 0 || h.plaintextSize > MAX_FILE_BYTES) throw new Error("Encrypted file size metadata is invalid");
  if (fromBase64Url(h.contentNonce!).length !== 12 || fromBase64Url(h.wrapSalt!).length !== 16 || fromBase64Url(h.wrapNonce!).length !== 12 || fromBase64Url(h.wrappedKey!).length !== 48) throw new Error("Encrypted key envelope lengths are invalid");
}

export const toBase64Url = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
export const fromBase64Url = (value: string) => Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - value.length % 4) % 4)), c => c.charCodeAt(0));
