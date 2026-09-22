import { expect, test } from "@playwright/test";

import { AUTH_FILE } from "../../playwright.config";
import { PASSWORD } from "./helpers";

test("first run: create the admin, walk the wizard, land on the overview", async ({ page }) => {
  await page.goto("/");
  await expect(page).toHaveURL(/\/setup\/?$/); // no admin yet: everything leads to setup

  await page.getByLabel("Username").fill("admin");
  await page.getByLabel("Password", { exact: true }).fill(PASSWORD);
  await page.getByLabel("Confirm password").fill(PASSWORD);
  await page.getByRole("button", { name: "Create account" }).click();

  // Capture check: this machine may or may not be able to capture; replay works either way.
  await page.getByRole("button", { name: /^Continue( anyway)?$/ }).click();
  await page.getByRole("button", { name: "Skip for now" }).click();
  await page.getByRole("button", { name: "Skip" }).click(); // no trained model in a fresh run

  await expect(page).toHaveURL(/\/$/);
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  await page.context().storageState({ path: AUTH_FILE });
});
