import { describe, expect, it } from "vitest";

import {
  bitrate,
  bytes,
  clock,
  count,
  duration,
  endpoint,
  humanize,
  percent,
  protocolName,
  relativeTime,
} from "./format";

describe("format", () => {
  it("names protocols instead of showing numbers", () => {
    expect(protocolName(6)).toBe("TCP");
    expect(protocolName(58)).toBe("ICMPv6");
    expect(protocolName(99)).toBe("IP 99");
    expect(protocolName(null)).toBe("—");
  });

  it("formats sizes and rates", () => {
    expect(bytes(512)).toBe("512 B");
    expect(bytes(1_530)).toBe("1.5 KB");
    expect(bytes(18_400_000)).toBe("18 MB");
    expect(bitrate(2_300_000)).toBe("18 Mb/s");
    expect(bitrate(50)).toBe("400 b/s");
    expect(count(9_100)).toBe("9.1k");
    expect(percent(0.9123)).toBe("91.2%");
    expect(percent(undefined)).toBe("—");
  });

  it("formats durations and clocks", () => {
    expect(duration(42)).toBe("42s");
    expect(duration(125)).toBe("2m 05s");
    expect(duration(3_700)).toBe("1h 01m");
    expect(clock(4_364)).toBe("01:12:44");
  });

  it("gives relative times", () => {
    expect(relativeTime(1_000, 1_010)).toBe("just now");
    expect(relativeTime(1_000, 1_000 + 120)).toMatch(/2 min/);
  });

  it("writes endpoints, bracketing IPv6", () => {
    expect(endpoint("10.0.0.1", 443)).toBe("10.0.0.1:443");
    expect(endpoint("fe80::1", 22)).toBe("[fe80::1]:22");
    expect(endpoint("10.0.0.1", 0)).toBe("10.0.0.1");
    expect(endpoint(null)).toBe("*");
    expect(humanize("false_positive")).toBe("False positive");
  });
});
