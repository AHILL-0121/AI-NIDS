import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [react()],
  resolve: { tsconfigPaths: true },
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    include: ["src/**/*.test.{ts,tsx}"],
    coverage: {
      provider: "v8",
      include: ["src/components/**"],
      exclude: ["src/**/*.test.{ts,tsx}"],
      // Gate from the checklist (Phase 9): frontend components >= 70 %.
      thresholds: { lines: 70, statements: 70 },
    },
  },
});
