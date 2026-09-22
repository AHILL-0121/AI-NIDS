/**
 * Accessibility sweep (WCAG 2.2 AA via axe) over every page, in both themes. Signed out pages
 * (login) use a fresh context; the rest use the admin session from setup.
 */
import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

import { APP_ROUTES } from "./helpers";

const TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"];

async function audit(page: Page, route: string, theme: "light" | "dark") {
  await page.addInitScript((t) => window.localStorage.setItem("nids.theme", t), theme);
  await page.goto(route);
  await page.waitForLoadState("networkidle");
  await expect(page.locator("html")).toHaveAttribute("data-theme", theme);
  const { violations } = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = violations.map(
    (v) =>
      `${v.id} (${v.impact}): ${v.help} — ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`,
  );
  expect(summary, `${route} in ${theme}`).toEqual([]);
}

for (const theme of ["light", "dark"] as const) {
  for (const route of APP_ROUTES) {
    test(`${route} has no WCAG AA violations (${theme})`, async ({ page }) => {
      await audit(page, route, theme);
    });
  }

  test(`/login/ has no WCAG AA violations (${theme})`, async ({ browser }) => {
    const context = await browser.newContext({ storageState: undefined });
    await audit(await context.newPage(), "/login/", theme);
    await context.close();
  });
}
