import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The SPA is embedded into the Go binary from dist/. During development, API
// calls are proxied to a locally running xgress instance on :8088.
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
  server: {
    port: 5173,
    proxy: {
      "/api": "http://127.0.0.1:8088",
    },
  },
});
