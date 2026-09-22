/**
 * Desktop notifications for new and escalated alerts (audit OPS-04), shown by this browser from
 * the live WebSocket. The permission belongs to the browser, so the preference is stored per
 * device (localStorage) rather than on the server. Only shown while the tab is in the background;
 * in front, the alert list itself updates.
 */
import type { Schemas } from "@/lib/api/client";

type Alert = Schemas["AlertOut"];
type Severity = Alert["severity"];

export interface DesktopPrefs {
  enabled: boolean;
  minSeverity: Severity;
}

const KEY = "nids.desktopNotifications";
const RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
const DEFAULTS: DesktopPrefs = { enabled: false, minSeverity: "high" };
/** Replays keep their original (old) timestamps; don't pop up for those. */
const MAX_AGE_S = 600;

export function loadPrefs(): DesktopPrefs {
  try {
    const raw = window.localStorage.getItem(KEY);
    if (!raw) return DEFAULTS;
    const parsed = JSON.parse(raw) as Partial<DesktopPrefs>;
    return {
      enabled: parsed.enabled === true,
      minSeverity: parsed.minSeverity && parsed.minSeverity in RANK ? parsed.minSeverity : "high",
    };
  } catch {
    return DEFAULTS;
  }
}

const listeners = new Set<() => void>();

export function savePrefs(prefs: DesktopPrefs): void {
  try {
    window.localStorage.setItem(KEY, JSON.stringify(prefs));
  } catch {
    // storage unavailable (private mode): nothing is remembered
  }
  listeners.forEach((listener) => listener());
}

export function supported(): boolean {
  return typeof window !== "undefined" && "Notification" in window;
}

export type Permission = NotificationPermission | "unsupported";

/** Ask the browser for permission (once per site) and tell subscribers the answer. */
export async function requestPermission(): Promise<Permission> {
  if (!supported()) return "unsupported";
  const answer = await Notification.requestPermission();
  listeners.forEach((listener) => listener());
  return answer;
}

/** For useSyncExternalStore: preferences and permission as one comparable string. */
export function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  window.addEventListener("storage", listener);
  return () => {
    listeners.delete(listener);
    window.removeEventListener("storage", listener);
  };
}

export function snapshot(): string {
  const permission: Permission = supported() ? Notification.permission : "unsupported";
  return JSON.stringify({ ...loadPrefs(), permission });
}

export const SERVER_SNAPSHOT = JSON.stringify({ ...DEFAULTS, permission: "default" });

/** Should `next` pop up? True when its severity reaches the minimum for the first time. */
export function shouldNotify(
  previous: Alert | undefined,
  next: Alert,
  prefs: DesktopPrefs,
  now = Date.now() / 1000,
): boolean {
  if (!prefs.enabled || now - next.last_seen > MAX_AGE_S) return false;
  if (next.status === "resolved" || next.status === "false_positive") return false;
  const minimum = RANK[prefs.minSeverity];
  const was = previous ? RANK[previous.severity] : -1;
  return RANK[next.severity] >= minimum && was < minimum;
}

/** Pop up `alert`; clicking it brings this tab forward and calls `open`. */
export function showAlert(alert: Alert, open: (id: string) => void): void {
  if (!supported() || Notification.permission !== "granted" || !document.hidden) return;
  const where = `${alert.src ?? "*"} → ${alert.dst ?? "*"}`;
  const notification = new Notification(`${alert.severity.toUpperCase()} · ${alert.title}`, {
    body: `${where}\n${alert.explanation}`,
    tag: alert.id, // one notification per alert, replaced on escalation
  });
  notification.onclick = () => {
    window.focus();
    open(alert.id);
    notification.close();
  };
}
