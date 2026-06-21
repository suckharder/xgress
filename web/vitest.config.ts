import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

// Test runner config. Kept separate from vite.config.ts so the production build
// (vite.config.ts) carries no test concerns. Vitest picks this file first.
//
// The SPA's only backend coupling is api.ts (fetch, same-origin, relative
// "/api/..." paths). We mock at that seam with MSW, so the environment URL must
// be set for the relative URLs to resolve.
export default defineConfig({
  plugins: [react()],
  test: {
    globals: true,
    environment: "jsdom",
    environmentOptions: {
      jsdom: { url: "http://localhost" },
    },
    setupFiles: ["./src/test/setup.ts"],
    css: false,
    restoreMocks: true,
    clearMocks: true,
    include: ["src/**/*.test.{ts,tsx}"],
    coverage: {
      provider: "v8",
      reportsDirectory: "./coverage",
      reporter: ["text", "html"],
      include: ["src/**/*.{ts,tsx}"],
      exclude: [
        "src/main.tsx",
        "src/icons.tsx",
        "src/test/**",
        "src/**/*.test.{ts,tsx}",
        "src/types.ts",
      ],
    },
  },
});
