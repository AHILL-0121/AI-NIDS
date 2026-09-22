"use client";

import { useSyncExternalStore } from "react";

/** Chart colours come from the same CSS tokens as the UI, so charts re-theme with the page. */
export interface ChartTheme {
  mode: "light" | "dark";
  ink: string;
  inkMuted: string;
  inkSubtle: string;
  line: string;
  surface: string;
  surfaceSunken: string;
  accent: string;
  accentWash: string;
  critical: string;
  high: string;
  medium: string;
  low: string;
  ok: string;
  /** Ordered, colour-blind-safe series palette (design §5.3). */
  series: string[];
  fontSans: string;
  fontMono: string;
}

function subscribe(onChange: () => void): () => void {
  const observer = new MutationObserver(onChange);
  observer.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
  return () => observer.disconnect();
}

const readMode = () => (document.documentElement.dataset.theme === "dark" ? "dark" : "light");

let cache: { mode: string; theme: ChartTheme } | null = null;

export function readChartTheme(): ChartTheme {
  const mode = readMode();
  if (cache?.mode === mode) return cache.theme;
  const style = getComputedStyle(document.documentElement);
  const v = (name: string) => style.getPropertyValue(name).trim();
  const theme: ChartTheme = {
    mode,
    ink: v("--ink"),
    inkMuted: v("--ink-muted"),
    inkSubtle: v("--ink-subtle"),
    line: v("--line"),
    surface: v("--surface"),
    surfaceSunken: v("--surface-sunken"),
    accent: v("--accent"),
    accentWash: v("--accent-wash"),
    critical: v("--sev-critical"),
    high: v("--sev-high"),
    medium: v("--sev-medium"),
    low: v("--sev-low"),
    ok: v("--ok"),
    series: [
      v("--accent"),
      v("--sev-low"),
      mode === "dark" ? "#B79BE0" : "#7A5AA6",
      mode === "dark" ? "#A9BC6A" : "#6B7A3A",
      v("--ink-muted"),
    ],
    fontSans: style.fontFamily || "sans-serif",
    fontMono: v("--font-plex-mono") || "monospace",
  };
  cache = { mode, theme };
  return theme;
}

/** Current chart theme; null during server rendering (charts render on the client only). */
export function useChartTheme(): ChartTheme | null {
  return useSyncExternalStore(subscribe, readChartTheme, () => null);
}
