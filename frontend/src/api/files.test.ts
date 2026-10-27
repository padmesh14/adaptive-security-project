import { afterEach, describe, expect, it, vi } from "vitest";
import { createRecoveryKey, encryptFile } from "../crypto/encrypt";
import { initiateUpload, uploadEncrypted } from "./files";

describe("client upload payload", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("sends an encrypted container and wrapped key, never the original bytes or recovery code", async () => {
    vi.stubGlobal("document", { cookie: "adaptive_csrf=csrf-token" });
    const calls: Array<{ input: RequestInfo | URL; init?: RequestInit }> = [];
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ input, init });
      return new Response(JSON.stringify({ file_id: "550e8400-e29b-41d4-a716-446655440000", upload_token: "temporary-upload-token" }), { status: 201, headers: { "Content-Type": "application/json" } });
    }));
    const sent: { body?: Uint8Array; url?: string; headers: Record<string, string>; progress?: number } = { headers: {} };
    class FakeXHR {
      upload: { onprogress: ((event: ProgressEvent) => void) | null } = { onprogress: null };
      status = 201; responseText = JSON.stringify({ id: "file-id" }); withCredentials = false;
      onload: (() => void) | null = null; onerror: (() => void) | null = null;
      open(_method: string, url: string) { sent.url = url; }
      setRequestHeader(name: string, value: string) { sent.headers[name] = value; }
      send(body: Uint8Array) { sent.body = body; this.upload.onprogress?.({ lengthComputable: true, loaded: body.length, total: body.length } as ProgressEvent); this.onload?.(); }
    }
    vi.stubGlobal("XMLHttpRequest", FakeXHR);
    const plain = new TextEncoder().encode("local synthetic plaintext sentinel");
    const { key, exportCode } = await createRecoveryKey();
    const initiated = await initiateUpload("Low", false);
    const encrypted = await encryptFile({ size: plain.length, arrayBuffer: async () => plain.slice().buffer } as File, "Low", key, initiated.file_id);
    await uploadEncrypted(encrypted.encrypted, encrypted.header, encrypted.digest, initiated.upload_token, percent => { sent.progress = percent; });
    expect(calls).toHaveLength(1);
    const initBody = String(calls[0].init?.body);
    const uploaded = sent.body!;
    const uploadedText = new TextDecoder().decode(uploaded);
    expect(uploadedText).toContain('"wrappedKey"');
    expect(uploadedText).not.toContain("local synthetic plaintext sentinel");
    expect(uploadedText).not.toContain(exportCode);
    expect(initBody).not.toContain(exportCode);
    expect(sent.url).not.toContain(exportCode);
    expect(sent.headers["X-Upload-Token"]).toBe("temporary-upload-token");
    expect(sent.progress).toBe(100);
  });
});
