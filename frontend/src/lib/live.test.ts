import { QueryClient } from "@tanstack/react-query";
import { describe, expect, it } from "vitest";

import type { Schemas } from "./api/client";
import { authRedirect } from "./auth";
import { LIVE_TRAFFIC_KEY, applyEvent } from "./live";

const bucket = (ts: number, bytes = 100): Schemas["Bucket"] => ({
  ts,
  bytes,
  packets: 1,
  tcp: 1,
  udp: 0,
  icmp: 0,
  other: 0,
  flows_started: 0,
  flows_ended: 0,
  alerts: 0,
});

describe("live events", () => {
  it("keeps traffic ticks ordered and replaces a repeated second", () => {
    const qc = new QueryClient();
    applyEvent(qc, { type: "stats.tick", data: bucket(12) });
    applyEvent(qc, { type: "stats.tick", data: bucket(10) });
    applyEvent(qc, { type: "stats.tick", data: bucket(12, 999) });

    const ticks = qc.getQueryData<Schemas["Bucket"][]>(LIVE_TRAFFIC_KEY)!;
    expect(ticks.map((b) => b.ts)).toEqual([10, 12]);
    expect(ticks[1]!.bytes).toBe(999);
  });

  it("stores a new alert and marks alert lists stale", async () => {
    const qc = new QueryClient();
    qc.setQueryData(["alerts", {}], { items: [], total: 0, limit: 100, offset: 0 });
    const alert = { id: "a1", title: "Port scan" } as Schemas["AlertOut"];

    applyEvent(qc, { type: "alert.new", data: alert });

    expect(qc.getQueryData(["alert", "a1"])).toEqual(alert);
    expect(qc.getQueryState(["alerts", {}])?.isInvalidated).toBe(true);
  });
});

describe("auth redirects", () => {
  it("sends a fresh install to setup and a signed-out browser to login", () => {
    expect(authRedirect({ setup_required: true, authenticated: false }, "/alerts/")).toBe(
      "/setup/",
    );
    expect(authRedirect({ setup_required: false, authenticated: false }, "/alerts/")).toBe(
      "/login/",
    );
    expect(authRedirect({ setup_required: false, authenticated: false }, "/login/")).toBeNull();
    expect(authRedirect({ setup_required: false, authenticated: true }, "/alerts/")).toBeNull();
    expect(authRedirect(undefined, "/")).toBeNull();
  });
});
