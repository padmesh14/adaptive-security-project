import { api, API } from "./client";
import { FileHeader } from "../crypto/file-format";
export type FileRecord = { id: string; tier: string; format_version: number; cid: string; storage_provider: string; integrity_sha256: string; ciphertext_size: number; created_at: string; blockchain_chain_id: number | null; blockchain_tx_hash: string | null; blockchain_record_id: string | null; blockchain_contract_address: string | null; blockchain_status: string };
export const initiateUpload = (tier: string, publishOnchain: boolean) => api<{ file_id: string; upload_token: string }>("/api/files/initiate", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ tier, format_version: 1, publish_onchain: publishOnchain }) });
export async function uploadEncrypted(file: Uint8Array, header: FileHeader, digest: string, uploadToken: string, onProgress: (percent: number) => void = () => {}): Promise<FileRecord> {
  return new Promise((resolve, reject) => {
    const csrf = decodeURIComponent(document.cookie.split(";").map(x => x.trim()).find(x => x.startsWith("adaptive_csrf="))?.slice("adaptive_csrf=".length) ?? "");
    const xhr = new XMLHttpRequest();
    xhr.open("POST", `${API}/api/files/${header.fileId}/complete`);
    xhr.withCredentials = true;
    xhr.setRequestHeader("Content-Type", "application/octet-stream");
    xhr.setRequestHeader("X-Upload-Token", uploadToken);
    xhr.setRequestHeader("X-CSRF-Token", csrf);
    xhr.setRequestHeader("X-Content-SHA256", digest);
    xhr.upload.onprogress = event => { if (event.lengthComputable) onProgress(Math.round(event.loaded * 100 / event.total)); };
    xhr.onerror = () => reject(new Error("Encrypted upload failed"));
    xhr.onload = () => {
      if (xhr.status < 200 || xhr.status >= 300) { try { reject(new Error(JSON.parse(xhr.responseText).detail ?? "Encrypted upload failed")); } catch { reject(new Error("Encrypted upload failed")); } return; }
      try { resolve(JSON.parse(xhr.responseText) as FileRecord); } catch { reject(new Error("Upload response was invalid")); }
    };
    xhr.send(file);
  });
}
export const listFiles = () => api<FileRecord[]>("/api/files");
export const verifyFile = (id: string) => api<{ valid: boolean; computed_sha256: string }>(`/api/files/${id}/verify`, { method: "POST" });
export const downloadCiphertext = (id: string) => api<ArrayBuffer>(`/api/files/${id}/ciphertext`);
export const deleteFile = (id: string) => api<void>(`/api/files/${id}`, { method: "DELETE" });
export const registerBlockchain = (id: string) => api<FileRecord>(`/api/files/${id}/register-blockchain`, { method: "POST" });
export const verifyBlockchain = (id: string) => api<{ valid: boolean; chain_id: number; contract_address: string }>(`/api/files/${id}/verify-blockchain`, { method: "POST" });
