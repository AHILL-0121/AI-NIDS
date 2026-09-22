/**
 * End-to-end tests against the full stack (audit QA-03): the real FastAPI backend serving the
 * built UI (`npm run build` first, or `npm run e2e`), a fresh database per run, and a browser.
 *
 * On Windows the installed Microsoft Edge is used, so nothing is downloaded; elsewhere run
 * `npx playwright install chromium` once. Setup runs first (the real first-run wizard) and saves
 * the signed-in session for the other specs.
 */
import { defineConfig, devices } from "@playwright/test";
import { tmpdir } from "node:os";
import path from "node:path";

const PORT = Number(process.env.E2E_PORT ?? 8766);
// One fresh data directory per run; workers inherit the variable, so they agree on it.
process.env.E2E_RUN ??= String(Date.now());
const dataDir = path.join(tmpdir(), `nids-e2e-${process.env.E2E_RUN}`);
export const AUTH_FILE = path.join(dataDir, "admin.json");
const channel = process.platform === "win32" ? "msedge" : undefined;

export default defineConfig({
  testDir: "./tests/e2e",
  testMatch: "*.e2e.ts",
  fullyParallel: false,
  workers: 1, // one backend, one database: specs share state on purpose
  retries: process.env.CI ? 1 : 0,
  timeout: 90_000,
  reporter: process.env.CI ? [["list"], ["html", { open: "never" }]] : "list",
  use: {
    baseURL: `http://127.0.0.1:${PORT}`,
    trace: "retain-on-failure",
    ...devices["Desktop Chrome"],
    channel,
  },
  projects: [
    { name: "setup", testMatch: "setup.e2e.ts" },
    {
      name: "app",
      testMatch: "flow.e2e.ts",
      dependencies: ["setup"],
      use: { storageState: AUTH_FILE },
    },
    // After the flow, so pages are audited with real alerts, sessions and reports on them.
    {
      name: "a11y",
      testMatch: "a11y.e2e.ts",
      dependencies: ["app"],
      use: { storageState: AUTH_FILE },
    },
  ],
  webServer: {
    command: "uv run nids api",
    cwd: path.resolve(__dirname, "../backend"),
    url: `http://127.0.0.1:${PORT}/readyz`,
    reuseExistingServer: false,
    timeout: 120_000,
    env: {
      NIDS_PORT: String(PORT),
      NIDS_DATABASE_URL: `sqlite:///${path.join(dataDir, "nids.db").replaceAll("\\", "/")}`,
      NIDS_DATA_DIR: dataDir,
      NIDS_ARTIFACTS_DIR: path.join(dataDir, "artifacts"),
      NIDS_FRONTEND_DIR: path.resolve(__dirname, "out"),
    },
  },
});
