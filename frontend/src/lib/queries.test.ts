import { describe, expect, it } from "vitest";

import { exportUrl, reportUrl } from "./queries";

describe("download links", () => {
  it("exports every match: filters kept, paging dropped, lists repeated", () => {
    const url = exportUrl("alerts", "csv", {
      severity: ["high", "critical"],
      status: [],
      src: "10.0.0.5",
      dst: undefined,
      session_id: "",
      limit: 200,
      offset: 400,
    });

    expect(url).toBe("/api/alerts/export?format=csv&severity=high&severity=critical&src=10.0.0.5");
  });

  it("keeps a zero port and encodes values", () => {
    expect(exportUrl("flows", "json", { port: 0, ip: "fe80::1" })).toBe(
      "/api/flows/export?format=json&port=0&ip=fe80%3A%3A1",
    );
  });

  it("opens HTML reports and downloads PDFs", () => {
    expect(reportUrl("abc", "html")).toBe("/api/reports/abc/html");
    expect(reportUrl("abc", "pdf", true)).toBe("/api/reports/abc/pdf?download=true");
  });
});
