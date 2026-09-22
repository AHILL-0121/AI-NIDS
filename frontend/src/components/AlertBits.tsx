import NextLink from "next/link";

import { absoluteTime, endpoint, relativeTime } from "@/lib/format";
import type { Alert } from "@/lib/queries";

import { SeverityChip } from "./Badges";

export function alertDestination(alert: Alert): string {
  const ports = alert.ports ?? [];
  if (ports.length === 1) return endpoint(alert.dst, ports[0]);
  if (ports.length > 1) return `${alert.dst ?? "*"} · ${ports.length} ports`;
  return alert.dst ?? "*";
}

export function RelativeTime({ epoch }: { epoch: number }) {
  return (
    <time
      dateTime={new Date(epoch * 1000).toISOString()}
      title={absoluteTime(epoch)}
      className="tabular-nums"
    >
      {relativeTime(epoch)}
    </time>
  );
}

/** Compact alert line for feeds (Overview, host view). */
export function AlertListItem({ alert }: { alert: Alert }) {
  return (
    <li>
      <NextLink
        href={`/alerts/?id=${alert.id}`}
        className="flex flex-col gap-0.5 px-4 py-2.5 hover:bg-surface-sunken focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-accent"
      >
        <span className="flex items-center gap-2">
          <SeverityChip severity={alert.severity} compact />
          <span className="truncate font-medium">{alert.title}</span>
        </span>
        <span className="flex items-center gap-1.5 text-meta text-ink-muted">
          <span className="truncate font-mono">
            {alert.src ?? "*"} → {alertDestination(alert)}
          </span>
          <span aria-hidden>·</span>
          <span className="shrink-0 text-ink-subtle">
            <RelativeTime epoch={alert.last_seen} />
          </span>
          {alert.occurrences > 1 && (
            <span className="shrink-0 text-ink-subtle">· ×{alert.occurrences}</span>
          )}
        </span>
      </NextLink>
    </li>
  );
}
