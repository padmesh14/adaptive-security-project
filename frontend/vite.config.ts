import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
const apiTarget = process.env.VITE_API_PROXY_TARGET ?? "http://127.0.0.1:8001";
export default defineConfig({ plugins: [react()], server: { fs: { allow: [".."] }, proxy: { "/api": apiTarget, "/health": apiTarget } }, test: { environment: "node" } });
