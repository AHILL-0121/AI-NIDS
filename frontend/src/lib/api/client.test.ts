import { afterEach, describe, expect, it, vi } from "vitest";

import { ApiError, client, setCsrfToken, unwrap } from "./client";

function respond(status: number, body: unknown) {
  return vi.fn(async (request: Request) => {
    void request;
    return new Response(body === undefined ? null : JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    });
  });
}

afterEach(() => {
  vi.unstubAllGlobals();
  setCsrfToken(null);
});

describe("api client", () => {
  it("adds the CSRF token to writes only", async () => {
    const fetch = respond(200, { values: {}, apply: {} });
    vi.stubGlobal("fetch", fetch);
    setCsrfToken("token-1");

    await client.GET("/api/settings");
    await client.PATCH("/api/settings", { body: { scan_min_ports: 30 } });

    const [read, write] = fetch.mock.calls.map(([request]) => request as Request);
    expect(read!.headers.get("X-CSRF-Token")).toBeNull();
    expect(write!.headers.get("X-CSRF-Token")).toBe("token-1");
    expect(write!.credentials).toBe("same-origin");
  });

  it("turns the error envelope into an ApiError", async () => {
    vi.stubGlobal(
      "fetch",
      respond(404, { error: { code: "not_found", message: "Alert x not found.", details: null } }),
    );

    const error = await unwrap(
      client.GET("/api/alerts/{alert_id}", { params: { path: { alert_id: "x" } } }),
    ).catch((e: unknown) => e);

    expect(error).toBeInstanceOf(ApiError);
    expect(error).toMatchObject({ status: 404, code: "not_found", message: "Alert x not found." });
  });

  it("reports an unreachable server", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("Failed to fetch")));

    const error = await unwrap(client.GET("/api/sensor/status")).catch((e: unknown) => e);

    expect(error).toMatchObject({ status: 0, code: "network" });
  });
});
