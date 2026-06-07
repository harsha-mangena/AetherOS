import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// AetherOS desktop UI. Talks to the local control-plane API (FastAPI) on :8765.
// In dev, /api is proxied to the backend so the frontend code uses relative paths
// and works identically whether hosted by Vite or packaged inside Tauri.
export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8765",
        changeOrigin: true,
        rewrite: (p) => p.replace(/^\/api/, ""),
      },
    },
  },
  build: {
    outDir: "dist",
    target: "es2021",
  },
});
