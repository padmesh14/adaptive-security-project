import { api } from "./client";
export type User = { id: string; email: string };
export const register = (email: string, password: string) => api<User>("/api/auth/register", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email, password }) });
export const login = (email: string, password: string) => api<User>("/api/auth/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email, password }) });
export const me = () => api<User>("/api/auth/me");
export const logout = () => api<void>("/api/auth/logout", { method: "POST" });
