/**
 * Theme preference handling (plan/design.md §5.8).
 * The user picks Light, Dark or System; `data-theme` on <html> always holds the resolved theme.
 */

export type ThemePreference = "light" | "dark" | "system";
export type ResolvedTheme = "light" | "dark";

export const THEME_STORAGE_KEY = "nids.theme";
export const DEFAULT_PREFERENCE: ThemePreference = "light";

export function parsePreference(value: string | null | undefined): ThemePreference {
  return value === "light" || value === "dark" || value === "system" ? value : DEFAULT_PREFERENCE;
}

export function resolveTheme(
  preference: ThemePreference,
  systemPrefersDark: boolean,
): ResolvedTheme {
  if (preference === "system") return systemPrefersDark ? "dark" : "light";
  return preference;
}

// Fallback when storage is unavailable (private mode, blocked site data): the choice still
// applies for the rest of the session.
let sessionPreference: ThemePreference | null = null;
const listeners = new Set<() => void>();

export function readPreference(): ThemePreference {
  try {
    const stored = window.localStorage.getItem(THEME_STORAGE_KEY);
    if (stored !== null) return parsePreference(stored);
  } catch {
    // fall through to the session value
  }
  return sessionPreference ?? DEFAULT_PREFERENCE;
}

export function writePreference(preference: ThemePreference): void {
  sessionPreference = preference;
  try {
    window.localStorage.setItem(THEME_STORAGE_KEY, preference);
  } catch {
    // keep the session value only
  }
  listeners.forEach((notify) => notify());
}

/** Subscribe to preference changes from this tab (writePreference) and other tabs (storage). */
export function subscribePreference(notify: () => void): () => void {
  const onStorage = (event: StorageEvent) => {
    if (event.key === THEME_STORAGE_KEY) notify();
  };
  listeners.add(notify);
  window.addEventListener("storage", onStorage);
  return () => {
    listeners.delete(notify);
    window.removeEventListener("storage", onStorage);
  };
}

export function applyTheme(theme: ResolvedTheme): void {
  document.documentElement.dataset.theme = theme;
}

/**
 * Inline <head> script that sets `data-theme` before first paint, so there's no flash of the
 * wrong theme. It must stay dependency-free and mirror parsePreference/resolveTheme above.
 */
export const THEME_BOOT_SCRIPT = `(function(){var d=document.documentElement,t="light";try{var p=localStorage.getItem("${THEME_STORAGE_KEY}");if(p==="dark"||p==="light")t=p;else if(p==="system"&&matchMedia("(prefers-color-scheme: dark)").matches)t="dark";}catch(e){}d.dataset.theme=t;})();`;
