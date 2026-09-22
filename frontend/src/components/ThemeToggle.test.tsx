import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { THEME_STORAGE_KEY } from "@/design/theme";

import { ThemeToggle } from "./ThemeToggle";

describe("ThemeToggle", () => {
  it("starts on Light and switches the document to dark", async () => {
    const user = userEvent.setup();
    render(<ThemeToggle />);

    expect(screen.getByRole("radio", { name: "Light" })).toBeChecked();

    await user.click(screen.getByRole("radio", { name: "Dark" }));

    expect(screen.getByRole("radio", { name: "Dark" })).toBeChecked();
    expect(document.documentElement.dataset.theme).toBe("dark");
    expect(window.localStorage.getItem(THEME_STORAGE_KEY)).toBe("dark");
  });
});
