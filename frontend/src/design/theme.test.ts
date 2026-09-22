import { describe, expect, it } from "vitest";

import { THEME_BOOT_SCRIPT, THEME_STORAGE_KEY, parsePreference, resolveTheme } from "./theme";

function runBootScript() {
  new Function(THEME_BOOT_SCRIPT)();
  return document.documentElement.dataset.theme;
}

describe("parsePreference", () => {
  it("defaults to light for missing or unknown values", () => {
    expect(parsePreference(null)).toBe("light");
    expect(parsePreference("purple")).toBe("light");
  });

  it("accepts the three known preferences", () => {
    expect(parsePreference("dark")).toBe("dark");
    expect(parsePreference("system")).toBe("system");
  });
});

describe("resolveTheme", () => {
  it("follows the OS only in system mode", () => {
    expect(resolveTheme("system", true)).toBe("dark");
    expect(resolveTheme("system", false)).toBe("light");
    expect(resolveTheme("light", true)).toBe("light");
  });
});

describe("THEME_BOOT_SCRIPT", () => {
  it("paints light when nothing is stored", () => {
    expect(runBootScript()).toBe("light");
  });

  it("paints the stored explicit choice", () => {
    window.localStorage.setItem(THEME_STORAGE_KEY, "dark");
    expect(runBootScript()).toBe("dark");
  });
});
