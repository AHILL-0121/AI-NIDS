import { readFile } from "node:fs/promises";

import { expect, test } from "@playwright/test";

import { fixture } from "./helpers";

test("replay a scan, see the alert arrive live, acknowledge it, download the report", async ({
  page,
}) => {
  // Keep the Alerts page open while the replay runs: the alert must arrive over the WebSocket.
  const alerts = await page.context().newPage();
  await alerts.goto("/alerts/");
  await expect(alerts.getByText("No alerts match")).toBeVisible();

  await page.goto("/jobs/");
  await page.locator('input[type="file"]').setInputFiles(fixture("nmap_syn_scan.pcap"));
  const upload = page.getByRole("listitem").filter({ hasText: "nmap_syn_scan.pcap" });
  await upload.getByRole("button", { name: "Replay" }).click();

  const row = alerts.getByRole("row").filter({ hasText: "Port scan" });
  await expect(row).toBeVisible({ timeout: 60_000 }); // no reload: pushed live
  await expect(row).toContainText("192.168.1.66");
  await expect(alerts.getByRole("row").filter({ hasText: /flood|sweep/i })).toHaveCount(0);

  await row.click();
  const drawer = alerts.getByRole("dialog");
  await expect(drawer).toContainText("Port scan");
  await drawer.getByRole("button", { name: "Acknowledge" }).click();
  await expect(row).toContainText("Acknowledged");

  await alerts.goto("/sessions/");
  await alerts.getByRole("row").filter({ hasText: "nmap_syn_scan.pcap" }).click();
  const session = alerts.getByRole("dialog");
  await session.getByRole("button", { name: "Generate report" }).click();
  const view = session.getByRole("link", { name: "View" });
  await expect(view).toBeVisible({ timeout: 60_000 });

  const report = await alerts.request.get((await view.getAttribute("href"))!);
  expect(report.ok()).toBe(true);
  const html = await report.text();
  expect(html).toContain("Port scan");
  expect(html).toContain("Acknowledged");

  // The PDF exists only where the server has Edge/Chrome/Chromium; otherwise the reason shows.
  const pdf = session.getByRole("link", { name: "PDF" });
  if (await pdf.isVisible()) {
    const [download] = await Promise.all([alerts.waitForEvent("download"), pdf.click()]);
    const bytes = await readFile((await download.path())!);
    expect(bytes.subarray(0, 4).toString()).toBe("%PDF");
  } else {
    await expect(session).toContainText("No PDF:");
  }
});
