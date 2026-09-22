"use client";

import { DesktopIcon, MoonIcon, SunIcon, type Icon } from "@phosphor-icons/react";
import { useEffect, useSyncExternalStore } from "react";
import { ToggleButton, ToggleButtonGroup, type Key } from "react-aria-components";

import {
  DEFAULT_PREFERENCE,
  applyTheme,
  parsePreference,
  readPreference,
  resolveTheme,
  subscribePreference,
  writePreference,
  type ThemePreference,
} from "@/design/theme";

const OPTIONS: { id: ThemePreference; label: string; icon: Icon }[] = [
  { id: "light", label: "Light", icon: SunIcon },
  { id: "dark", label: "Dark", icon: MoonIcon },
  { id: "system", label: "System", icon: DesktopIcon },
];

const DARK_QUERY = "(prefers-color-scheme: dark)";

export function ThemeToggle() {
  // The server snapshot is the default; the boot script has already painted the stored theme,
  // and the control picks up the stored choice on hydration.
  const preference = useSyncExternalStore(
    subscribePreference,
    readPreference,
    () => DEFAULT_PREFERENCE,
  );

  useEffect(() => {
    const media = window.matchMedia(DARK_QUERY);
    const sync = () => applyTheme(resolveTheme(preference, media.matches));
    sync();
    if (preference !== "system") return;
    media.addEventListener("change", sync);
    return () => media.removeEventListener("change", sync);
  }, [preference]);

  function handleChange(keys: Set<Key>) {
    const [next] = keys;
    if (next !== undefined) writePreference(parsePreference(String(next)));
  }

  return (
    <ToggleButtonGroup
      aria-label="Colour theme"
      selectionMode="single"
      disallowEmptySelection
      selectedKeys={[preference]}
      onSelectionChange={handleChange}
      className="inline-flex rounded-[var(--radius-control)] border border-line-strong bg-surface p-0.5"
    >
      {OPTIONS.map(({ id, label, icon: IconComponent }) => (
        <ToggleButton
          key={id}
          id={id}
          className="inline-flex h-7 items-center gap-1.5 rounded-[3px] px-2.5 text-meta font-medium text-ink-muted transition-colors duration-100 outline-none data-[focus-visible]:outline-2 data-[focus-visible]:outline-accent data-[hovered]:text-ink data-[selected]:bg-accent-wash data-[selected]:text-ink"
        >
          <IconComponent size={14} aria-hidden />
          {label}
        </ToggleButton>
      ))}
    </ToggleButtonGroup>
  );
}
