/**
 * README screenshots (`npm run screenshots`), not a test: fills a fresh stack with the labelled
 * fixture replays, then captures pages in both themes into ../docs/images/. Runs after the E2E
 * flow, so there is already an acknowledged alert and a session report.
 *
 * If ../backend/artifacts holds the headline model, it is copied in and activated so the Model
 * page shows real results.
 */
import { cp, mkdir, stat } from "node:fs/promises";
import path from "node:path";

import { expect, type Page, test } from "@playwright/test";

import { fixture } from "./helpers";

const OUT = path.resolve(__dirname, "../../../docs/images");
const MODEL = "cicids2017-day-full-20260922T133639Z";
const CAPTURES = [
  "benign_browsing.pcap",
  "nmap_syn_scan.pcap",
  "host_sweep_445.pcap",
  "hping3_syn_flood.pcap",
];

// en-US digit grouping for the README, whatever the machine running this uses.
test.use({ viewport: { width: 1440, height: 900 }, locale: "en-US", reducedMotion: "reduce" });

async function shoot(page: Page, route: string, theme: "light" | "dark", name: string) {
  await page.addInitScript((t) => localStorage.setItem("nids.theme", t), theme);
  await page.goto(route);
  await page.waitForLoadState("networkidle");
  await page.screenshot({ path: path.join(OUT, `${name}-${theme}.png`), animations: "disabled" });
}

test("capture README screenshots", async ({ page }) => {
  test.setTimeout(300_000);
  await mkdir(OUT, { recursive: true });

  // More traffic and alert types than the E2E flow's single nmap replay, shifted to the present
  // so the Overview's live ranges show them. One at a time: the API caps concurrent jobs.
  await page.goto("/jobs/");
  await page.getByText("Replay as if captured just now").click();
  await expect(page.getByRole("switch", { name: /as if captured just now/ })).toBeChecked();
  for (const name of CAPTURES) {
    await page.locator('input[type="file"]').setInputFiles(fixture(name));
    const upload = page.getByRole("listitem").filter({ hasText: name }).first();
    await upload.getByRole("button", { name: "Replay" }).click();
    await expect(page.getByText(`Replaying ${name}`)).toBeVisible();
    await expect
      .poll(
        async () => {
          const jobs: { status: string }[] = await (await page.request.get("/api/jobs")).json();
          return jobs.some((job) => job.status === "running" || job.status === "queued");
        },
        { timeout: 120_000 },
      )
      .toBe(false);
  }
  await page.goto("/alerts/");
  await expect(page.getByRole("row").filter({ hasText: /flood/i }).first()).toBeVisible({
    timeout: 120_000,
  });
  await expect(page.getByRole("row").filter({ hasText: /sweep/i }).first()).toBeVisible({
    timeout: 120_000,
  });

  const source = path.resolve(__dirname, "../../../backend/artifacts", MODEL);
  const hasModel = await stat(source).then(
    () => true,
    () => false,
  );
  if (hasModel) {
    const target = path.join(process.env.NIDS_E2E_DATA_DIR!, "artifacts", MODEL);
    await cp(source, target, { recursive: true });
    await page.goto("/model/");
    await page.getByRole("button", { name: "Activate" }).click();
    await expect(page.getByText(`${MODEL} is active`)).toBeVisible();
  }

  for (const theme of ["light", "dark"] as const) {
    await shoot(page, "/", theme, "overview");
    await shoot(page, "/alerts/", theme, "alerts");
    await page.getByRole("row").filter({ hasText: "Port scan" }).first().click();
    await expect(page.getByRole("dialog")).toBeVisible();
    await page.waitForLoadState("networkidle");
    await page.screenshot({
      path: path.join(OUT, `alert-drawer-${theme}.png`),
      animations: "disabled",
    });
    if (hasModel) await shoot(page, "/model/", theme, "model");
  }
});
