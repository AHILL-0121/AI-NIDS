/** Formatting for people (audit UI-05): names instead of protocol numbers, readable sizes and
 * rates, relative times with the exact time available on hover. */

const PROTOCOLS: Record<number, string> = {
  1: "ICMP",
  2: "IGMP",
  6: "TCP",
  17: "UDP",
  47: "GRE",
  50: "ESP",
  58: "ICMPv6",
  89: "OSPF",
  132: "SCTP",
};

export function protocolName(protocol: number | null | undefined): string {
  if (protocol === null || protocol === undefined) return "—";
  return PROTOCOLS[protocol] ?? `IP ${protocol}`;
}

const UNITS = ["B", "KB", "MB", "GB", "TB"];

export function bytes(value: number): string {
  let v = value;
  let unit = 0;
  while (Math.abs(v) >= 1000 && unit < UNITS.length - 1) {
    v /= 1000;
    unit += 1;
  }
  return `${unit === 0 ? Math.round(v) : v.toFixed(v < 10 ? 1 : 0)} ${UNITS[unit]}`;
}

/** Bytes per second as bits per second, the way network rates are usually quoted. */
export function bitrate(bytesPerSecond: number): string {
  const bits = bytesPerSecond * 8;
  if (bits < 1000) return `${Math.round(bits)} b/s`;
  const units = ["Kb/s", "Mb/s", "Gb/s"];
  let v = bits / 1000;
  let unit = 0;
  while (v >= 1000 && unit < units.length - 1) {
    v /= 1000;
    unit += 1;
  }
  return `${v.toFixed(v < 10 ? 1 : 0)} ${units[unit]}`;
}

export function count(value: number): string {
  if (Math.abs(value) < 1000) return String(Math.round(value));
  const units = ["k", "M", "B"];
  let v = value / 1000;
  let unit = 0;
  while (Math.abs(v) >= 1000 && unit < units.length - 1) {
    v /= 1000;
    unit += 1;
  }
  return `${v.toFixed(v < 10 ? 1 : 0)}${units[unit]}`;
}

export function percent(value: number | null | undefined, digits = 1): string {
  if (value === null || value === undefined || Number.isNaN(value)) return "—";
  return `${(value * 100).toFixed(digits)}%`;
}

export function duration(seconds: number): string {
  const s = Math.max(0, Math.round(seconds));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const rest = s % 60;
  if (h > 0) return `${h}h ${String(m).padStart(2, "0")}m`;
  if (m > 0) return `${m}m ${String(rest).padStart(2, "0")}s`;
  return `${rest}s`;
}

/** Clock-style elapsed time for live timers: 01:12:44. */
export function clock(seconds: number): string {
  const s = Math.max(0, Math.floor(seconds));
  const parts = [Math.floor(s / 3600), Math.floor((s % 3600) / 60), s % 60];
  return parts.map((p) => String(p).padStart(2, "0")).join(":");
}

const RELATIVE = new Intl.RelativeTimeFormat("en", { numeric: "auto", style: "short" });

/** "2 min ago" from an epoch in seconds. */
export function relativeTime(epochSeconds: number, now = Date.now() / 1000): string {
  const diff = epochSeconds - now;
  const abs = Math.abs(diff);
  if (abs < 45) return "just now";
  if (abs < 3600) return RELATIVE.format(Math.round(diff / 60), "minute");
  if (abs < 86400) return RELATIVE.format(Math.round(diff / 3600), "hour");
  return RELATIVE.format(Math.round(diff / 86400), "day");
}

export function absoluteTime(epochSeconds: number): string {
  return new Date(epochSeconds * 1000).toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function endpoint(ip: string | null | undefined, port?: number | null): string {
  if (!ip) return "*";
  if (port === null || port === undefined || port <= 0) return ip;
  return ip.includes(":") ? `[${ip}]:${port}` : `${ip}:${port}`;
}

const ACRONYMS: Record<string, string> = { ddos: "DDoS", dos: "DoS" };

export function humanize(identifier: string): string {
  const text = identifier
    .split("_")
    .map((word) => ACRONYMS[word] ?? word)
    .join(" ");
  return text.charAt(0).toUpperCase() + text.slice(1);
}
