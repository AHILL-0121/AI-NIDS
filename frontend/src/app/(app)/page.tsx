"use client";

import { ArrowRightIcon, ShieldCheckIcon, WaveformIcon } from "@phosphor-icons/react";
import { useQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";

import { AlertListItem } from "@/components/AlertBits";
import { TextLink } from "@/components/Button";
import { SegmentedControl } from "@/components/Overlays";
import { Kpi, PageHeader, Panel } from "@/components/Panel";
import { EmptyState, QueryView, Skeleton } from "@/components/States";
import { BarList, Strip, type StripLevel } from "@/charts/BarList";
import { Sparkline, TrafficChart } from "@/charts/charts";
import type { Schemas } from "@/lib/api/client";
import { bitrate, bytes, count } from "@/lib/format";
import { LIVE_TRAFFIC_KEY } from "@/lib/live";
import { useAlerts, useSummary, useTimeseries } from "@/lib/queries";

type Bucket = Schemas["Bucket"];
type Range = "15m" | "1h" | "24h";

const RANGES: Record<Range, { resolution: 1 | 60; span: number }> = {
  "15m": { resolution: 1, span: 900 },
  "1h": { resolution: 60, span: 3600 },
  "24h": { resolution: 60, span: 86400 },
};

const NO_BUCKETS: Bucket[] = [];

/** Merge stored buckets with live WebSocket ticks (live wins on the same second). The live
 * buffer holds at most 15 minutes, the span of the per-second view. */
function merge(stored: Bucket[], live: Bucket[]): Bucket[] {
  const byTs = new Map<number, Bucket>();
  for (const b of stored) byTs.set(b.ts, b);
  for (const b of live) byTs.set(b.ts, b);
  return [...byTs.values()].sort((a, b) => a.ts - b.ts);
}

function useLiveTicks(): Bucket[] {
  const { data } = useQuery({
    queryKey: LIVE_TRAFFIC_KEY,
    queryFn: () => NO_BUCKETS,
    initialData: NO_BUCKETS,
    staleTime: Infinity,
    gcTime: Infinity,
  });
  return data;
}

export default function OverviewPage() {
  const [range, setRange] = useState<Range>("15m");
  const { resolution, span } = RANGES[range];
  const series = useTimeseries({
    resolution,
    span,
    refetchInterval: resolution === 60 ? 60_000 : undefined,
  });
  const minutes = useTimeseries({ resolution: 60, span: 3600, refetchInterval: 60_000 });
  const live = useLiveTicks();
  const summary = useSummary();
  const latest = useAlerts({ limit: 8, status: ["new", "acknowledged"] });

  const buckets = useMemo(() => {
    const stored = series.data ?? NO_BUCKETS;
    return resolution === 1 ? merge(stored, live) : stored;
  }, [series.data, live, resolution]);

  // KPIs from the most recent minute of per-second data (the live stream when capturing).
  const recent = useMemo(() => {
    const secondly = resolution === 1 ? buckets : live;
    const window = secondly.slice(-60);
    const seconds = Math.max(window.length, 1);
    const sum = (key: keyof Bucket) => window.reduce((total, b) => total + b[key], 0);
    return {
      throughput: sum("bytes") / seconds,
      flowRate: sum("flows_started") / seconds,
      spark: secondly.slice(-120),
      has: window.length > 0,
    };
  }, [buckets, live, resolution]);

  const openAlerts = summary.data
    ? Object.values(summary.data.open_alerts).reduce((a, b) => a + b, 0)
    : null;
  const urgent = (summary.data?.open_alerts.critical ?? 0) + (summary.data?.open_alerts.high ?? 0);

  return (
    <>
      <PageHeader title="Overview" />

      <section
        aria-label="Key figures"
        className="grid grid-cols-2 divide-line rounded-[var(--radius-panel)] border border-line bg-surface sm:grid-cols-3 lg:grid-cols-5 lg:divide-x"
      >
        <Kpi
          label="Throughput"
          value={recent.has ? bitrate(recent.throughput) : "—"}
          detail="last minute"
        >
          {recent.spark.length > 1 && (
            <Sparkline
              values={recent.spark.map((b) => b.bytes)}
              label="Throughput, last two minutes"
            />
          )}
        </Kpi>
        <Kpi
          label="New flows / s"
          value={recent.has ? recent.flowRate.toFixed(1) : "—"}
          detail="last minute"
        >
          {recent.spark.length > 1 && (
            <Sparkline
              values={recent.spark.map((b) => b.flows_started)}
              label="New flows per second, last two minutes"
            />
          )}
        </Kpi>
        <Kpi
          label="Open alerts"
          value={openAlerts ?? <Skeleton className="h-8 w-12" />}
          tone={urgent > 0 ? "critical" : undefined}
          detail={summary.data ? `${urgent} critical or high` : undefined}
        />
        <Kpi
          label="Alerts · 24 h"
          value={
            summary.data ? count(summary.data.alerts_last_24h) : <Skeleton className="h-8 w-12" />
          }
        />
        <Kpi
          label="Flows · 1 h"
          value={
            summary.data ? count(summary.data.flows_last_hour) : <Skeleton className="h-8 w-12" />
          }
        />
      </section>

      <Panel
        title={`Traffic · last ${range}`}
        actions={
          <SegmentedControl
            label="Time range"
            value={range}
            onChange={setRange}
            options={[
              { id: "15m", label: "15m" },
              { id: "1h", label: "1h" },
              { id: "24h", label: "24h" },
            ]}
          />
        }
        bodyClassName="px-2 pt-2 pb-1"
      >
        <QueryView
          query={series}
          loading={<Skeleton className="m-2 h-[240px]" />}
          empty={() =>
            buckets.length === 0 ? (
              <EmptyState icon={WaveformIcon} title="No traffic in this window">
                Start a capture from the top bar, or replay a .pcap from Jobs. Replays keep their
                original timestamps; open them from Sessions.
              </EmptyState>
            ) : null
          }
        >
          {() => <TrafficChart buckets={buckets} resolution={resolution} />}
        </QueryView>
        <div className="flex flex-col gap-1.5 border-t border-line px-2 pt-3 pb-2">
          <span className="text-label font-medium text-ink-subtle uppercase">
            Alerts per minute · last hour
          </span>
          <AlertStrip buckets={minutes.data ?? NO_BUCKETS} fetchedAt={minutes.dataUpdatedAt} />
        </div>
      </Panel>

      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
        <Panel
          title="Open alerts"
          actions={
            <TextLink href="/alerts/" className="inline-flex items-center gap-1 text-meta">
              View all <ArrowRightIcon size={12} aria-hidden />
            </TextLink>
          }
        >
          <QueryView
            query={latest}
            empty={(page) =>
              page.items.length === 0 ? (
                <EmptyState icon={ShieldCheckIcon} title="Nothing open">
                  New detections appear here as they happen.
                </EmptyState>
              ) : null
            }
          >
            {(page) => (
              <ul className="divide-y divide-line">
                {page.items.map((alert) => (
                  <AlertListItem key={alert.id} alert={alert} />
                ))}
              </ul>
            )}
          </QueryView>
        </Panel>

        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-1 xl:grid-cols-2">
          <Panel title="Top talkers · 15 min" bodyClassName="p-4">
            <QueryView
              query={summary}
              empty={(s) =>
                s.top_talkers.length === 0 ? <EmptyState title="No flows yet" /> : null
              }
            >
              {(s) => (
                <BarList
                  label="Hosts sending the most bytes"
                  format={bytes}
                  items={s.top_talkers.map((t) => {
                    const ip = String(t.ip);
                    return {
                      key: ip,
                      value: Number(t.bytes),
                      label: (
                        <TextLink
                          href={`/hosts/?ip=${encodeURIComponent(ip)}`}
                          className="font-mono"
                        >
                          {ip}
                        </TextLink>
                      ),
                    };
                  })}
                />
              )}
            </QueryView>
          </Panel>
          <Panel title="Protocol mix · 15 min" bodyClassName="p-4">
            <QueryView
              query={summary}
              empty={(s) =>
                Object.values(s.protocols_last_15m).every((v) => v === 0) ? (
                  <EmptyState title="No packets yet" />
                ) : null
              }
            >
              {(s) => (
                <BarList
                  label="Packets by protocol"
                  format={(v) => `${count(v)} pkts`}
                  items={Object.entries(s.protocols_last_15m)
                    .filter(([, v]) => v > 0)
                    .sort((a, b) => b[1] - a[1])
                    .map(([name, value]) => ({ key: name, value, label: name.toUpperCase() }))}
                />
              )}
            </QueryView>
          </Panel>
        </div>
      </div>
    </>
  );
}

function AlertStrip({ buckets, fetchedAt }: { buckets: Bucket[]; fetchedAt: number }) {
  const cells = useMemo(() => {
    const byMinute = new Map(buckets.map((b) => [b.ts, b.alerts]));
    // The newest minute is the one the data was fetched in (0 until the first fetch).
    const last = Math.floor(Math.max(fetchedAt / 1000, buckets.at(-1)?.ts ?? 0) / 60) * 60;
    return Array.from({ length: 60 }, (_, i) => {
      const ts = last - (59 - i) * 60;
      const n = byMinute.get(ts) ?? 0;
      const level: StripLevel = n === 0 ? "none" : n === 1 ? "low" : n < 5 ? "medium" : "high";
      const time = new Date(ts * 1000).toLocaleTimeString(undefined, {
        hour: "2-digit",
        minute: "2-digit",
      });
      return { key: String(ts), level, title: `${time}: ${n} alert${n === 1 ? "" : "s"}` };
    });
  }, [buckets, fetchedAt]);
  return <Strip cells={cells} label="Alerts per minute over the last hour" />;
}
