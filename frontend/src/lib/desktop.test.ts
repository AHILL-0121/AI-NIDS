import { beforeEach, describe, expect, it } from "vitest";

import type { Schemas } from "./api/client";
import { loadPrefs, savePrefs, shouldNotify, type DesktopPrefs } from "./desktop";

type Alert = Schemas["AlertOut"];

const NOW = 1_800_000_000;
const alert = (severity: Alert["severity"], extra: Partial<Alert> = {}): Alert =>
  ({ id: "A-1", severity, status: "new", last_seen: NOW - 5, ...extra }) as Alert;
const on: DesktopPrefs = { enabled: true, minSeverity: "high" };

describe("desktop notifications", () => {
  beforeEach(() => window.localStorage.clear());

  it("fires once, when an alert first reaches the minimum severity", () => {
    expect(shouldNotify(undefined, alert("high"), on, NOW)).toBe(true);
    expect(shouldNotify(undefined, alert("medium"), on, NOW)).toBe(false);
    expect(shouldNotify(alert("medium"), alert("critical"), on, NOW)).toBe(true); // escalated
    expect(shouldNotify(alert("high"), alert("critical"), on, NOW)).toBe(false); // already shown
  });

  it("stays quiet when off, for old replayed alerts and for dismissed ones", () => {
    expect(shouldNotify(undefined, alert("critical"), { ...on, enabled: false }, NOW)).toBe(false);
    expect(shouldNotify(undefined, alert("critical", { last_seen: 1000 }), on, NOW)).toBe(false);
    expect(shouldNotify(undefined, alert("critical", { status: "false_positive" }), on, NOW)).toBe(
      false,
    );
  });

  it("remembers the choice in this browser and ignores junk", () => {
    expect(loadPrefs()).toEqual({ enabled: false, minSeverity: "high" });
    savePrefs({ enabled: true, minSeverity: "medium" });
    expect(loadPrefs()).toEqual({ enabled: true, minSeverity: "medium" });
    window.localStorage.setItem("nids.desktopNotifications", '{"minSeverity":"loud"}');
    expect(loadPrefs()).toEqual({ enabled: false, minSeverity: "high" });
  });
});
