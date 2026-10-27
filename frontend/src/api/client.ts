const API = import.meta.env.VITE_API_BASE_URL ?? "";
function cookie(name: string): string | undefined { return document.cookie.split("; ").map(x => x.trim()).find(x => x.startsWith(`${name}=`))?.slice(name.length + 1); }
export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const method = (init.method ?? "GET").toUpperCase();
  const headers = new Headers(init.headers);
  if (["POST", "DELETE", "PUT", "PATCH"].includes(method)) { const csrf = cookie("adaptive_csrf"); if (csrf) headers.set("X-CSRF-Token", decodeURIComponent(csrf)); }
  const response = await fetch(`${API}${path}`, { ...init, headers, credentials: "include" });
  if (!response.ok) { const message = await response.json().catch(() => ({ detail: "Request failed" })); throw new Error(message.detail ?? "Request failed"); }
  if (response.status === 204) return undefined as T;
  const type = response.headers.get("content-type") ?? "";
  return (type.includes("application/json") ? response.json() : response.arrayBuffer()) as Promise<T>;
}
export { API };
