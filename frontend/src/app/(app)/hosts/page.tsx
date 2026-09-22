"use client";

import { DesktopTowerIcon, ShieldCheckIcon } from "@phosphor-icons/react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { Suspense, useMemo, useState } from "react";
import { Form } from "react-aria-components";

import { AlertListItem, RelativeTime } from "@/components/AlertBits";
import { ProtocolTag } from "@/components/Badges";
import { Button, TextLink } from "@/components/Button";
import { TextField } from "@/components/Field";
import { Kpi, PageHeader, Panel } from "@/components/Panel";
import { EmptyState, QueryView, SkeletonRows } from "@/components/States";
import { BarList } from "@/charts/BarList";
import { bytes, count, endpoint } from "@/lib/format";
import { useAlerts, useFlows, useSummary, type Alert, type Flow } from "@/lib/queries";

function HostLookup({ initial }: { initial: string }) {
  const router = useRouter();
  const pathname = usePathname();
  const [value, setValue] = useState(initial);
  return (
    <Form
      className="flex items-end gap-2"
      onSubmit={(event) => {
        event.preventDefault();
        const ip = value.trim();
        router.replace(ip ? `${pathname}?ip=${encodeURIComponent(ip)}` : pathname);
      }}
    >
      <TextField
        label="IP address"
        mono
        value={value}
        onChange={setValue}
        placeholder="10.0.0.23"
        className="w-64"
      />
      <Button type="submit" variant="primary">
        Look up
      </Button>
    </Form>
  );
}

function Overview() {
  const summary = useSummary();
  return (
    <Panel title="Most active hosts · 15 min" bodyClassName="p-4">
      <QueryView
        query={summary}
        empty={(s) =>
          s.top_talkers.length === 0 ? (
            <EmptyState icon={DesktopTowerIcon} title="No hosts seen recently">
              Enter an IP address above to see its history.
            </EmptyState>
          ) : null
        }
      >
        {(s) => (
          <BarList
            label="Most active hosts"
            format={bytes}
            items={s.top_talkers.map((t) => {
              const ip = String(t.ip);
              return {
                key: ip,
                value: Number(t.bytes),
                label: (
                  <TextLink href={`/hosts/?ip=${encodeURIComponent(ip)}`} className="font-mono">
                    {ip}
                  </TextLink>
                ),
              };
            })}
          />
        )}
      </QueryView>
    </Panel>
  );
}

function summarise(ip: string, flows: Flow[]) {
  let sent = 0;
  let received = 0;
  const peers = new Map<string, number>();
  const ports = new Map<string, { protocol: number; port: number; flows: number }>();
  for (const f of flows) {
    const outbound = f.src_ip === ip;
    const peer = outbound ? f.dst_ip : f.src_ip;
    // Payload counts both directions; attribute by who opened the flow.
    if (outbound) sent += f.payload_bytes;
    else received += f.payload_bytes;
    peers.set(peer, (peers.get(peer) ?? 0) + 1);
    const key = `${f.protocol}/${f.dst_port}`;
    const entry = ports.get(key) ?? { protocol: f.protocol, port: f.dst_port, flows: 0 };
    entry.flows += 1;
    ports.set(key, entry);
  }
  return {
    sent,
    received,
    peers: [...peers.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8),
    ports: [...ports.values()].sort((a, b) => b.flows - a.flows).slice(0, 10),
  };
}

type TimelineItem =
  { kind: "alert"; ts: number; alert: Alert } | { kind: "flow"; ts: number; flow: Flow };

function dayLabel(ts: number): string {
  return new Date(ts * 1000).toLocaleDateString(undefined, {
    weekday: "short",
    month: "short",
    day: "numeric",
  });
}

function HostDetail({ ip }: { ip: string }) {
  const flows = useFlows({ ip, limit: 500 });
  const asSource = useAlerts({ src: ip, limit: 100 });
  const asTarget = useAlerts({ dst: ip, limit: 100 });

  const alerts = useMemo(() => {
    const all = new Map<string, Alert>();
    for (const a of [...(asSource.data?.items ?? []), ...(asTarget.data?.items ?? [])])
      all.set(a.id, a);
    return [...all.values()].sort((a, b) => b.last_seen - a.last_seen);
  }, [asSource.data, asTarget.data]);

  const stats = useMemo(() => summarise(ip, flows.data?.items ?? []), [ip, flows.data]);

  const timeline = useMemo(() => {
    const items: TimelineItem[] = [
      ...alerts.map((alert) => ({ kind: "alert" as const, ts: alert.last_seen, alert })),
      ...(flows.data?.items ?? [])
        .slice(0, 60)
        .map((flow) => ({ kind: "flow" as const, ts: flow.last_seen, flow })),
    ].sort((a, b) => b.ts - a.ts);
    const days = new Map<string, TimelineItem[]>();
    for (const item of items.slice(0, 120)) {
      const day = dayLabel(item.ts);
      days.set(day, [...(days.get(day) ?? []), item]);
    }
    return [...days.entries()];
  }, [alerts, flows.data]);

  const openAlerts = alerts.filter((a) => a.status === "new" || a.status === "acknowledged").length;

  return (
    <>
      <section
        aria-label="Host figures"
        className="grid grid-cols-2 rounded-[var(--radius-panel)] border border-line bg-surface lg:grid-cols-4 lg:divide-x lg:divide-line"
      >
        <Kpi
          label="Flows"
          value={flows.data ? count(flows.data.total) : "—"}
          detail={
            flows.data && flows.data.total > 500 ? "figures below use the latest 500" : undefined
          }
        />
        <Kpi
          label="Sent"
          value={flows.data ? bytes(stats.sent) : "—"}
          detail="payload, flows it opened"
        />
        <Kpi
          label="Received"
          value={flows.data ? bytes(stats.received) : "—"}
          detail="payload, flows opened to it"
        />
        <Kpi
          label="Open alerts"
          value={openAlerts}
          tone={openAlerts > 0 ? "critical" : undefined}
          detail={`${alerts.length} total`}
        />
      </section>

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Talks to" bodyClassName="p-4">
          {stats.peers.length === 0 ? (
            <EmptyState title="No flows stored for this host" />
          ) : (
            <BarList
              label="Peers by number of flows"
              format={(v) => `${v} flows`}
              items={stats.peers.map(([peer, value]) => ({
                key: peer,
                value,
                label: (
                  <TextLink href={`/hosts/?ip=${encodeURIComponent(peer)}`} className="font-mono">
                    {peer}
                  </TextLink>
                ),
              }))}
            />
          )}
        </Panel>
        <Panel title="Destination ports" bodyClassName="p-4">
          {stats.ports.length === 0 ? (
            <EmptyState title="No ports yet" />
          ) : (
            <BarList
              label="Destination ports by flow count"
              format={(v) => `${v} flows`}
              items={stats.ports.map((p) => ({
                key: `${p.protocol}/${p.port}`,
                value: p.flows,
                label: (
                  <span className="inline-flex items-center gap-1.5">
                    <ProtocolTag protocol={p.protocol} />
                    <span className="font-mono">{p.port}</span>
                  </span>
                ),
              }))}
            />
          )}
        </Panel>
      </div>

      <Panel title="Timeline">
        {flows.isPending || asSource.isPending ? (
          <SkeletonRows rows={6} />
        ) : timeline.length === 0 ? (
          <EmptyState icon={ShieldCheckIcon} title="Nothing recorded for this address" />
        ) : (
          <div className="flex flex-col">
            {timeline.map(([day, items]) => (
              <section key={day} className="border-b border-line last:border-b-0">
                <h3 className="sticky top-12 bg-surface px-4 pt-3 pb-1 text-label font-medium text-ink-subtle uppercase">
                  {day}
                </h3>
                <ul className="divide-y divide-line">
                  {items.map((item) =>
                    item.kind === "alert" ? (
                      <AlertListItem key={`a${item.alert.id}`} alert={item.alert} />
                    ) : (
                      <li
                        key={`f${item.flow.id}`}
                        className="flex items-center gap-2 px-4 py-2 text-dense"
                      >
                        <ProtocolTag protocol={item.flow.protocol} />
                        <span className="min-w-0 flex-1 truncate font-mono text-ink-muted">
                          {endpoint(item.flow.src_ip, item.flow.src_port)} →{" "}
                          {endpoint(item.flow.dst_ip, item.flow.dst_port)}
                        </span>
                        <span className="shrink-0 text-meta text-ink-subtle">
                          {bytes(item.flow.payload_bytes)} ·{" "}
                          <RelativeTime epoch={item.flow.last_seen} />
                        </span>
                      </li>
                    ),
                  )}
                </ul>
              </section>
            ))}
          </div>
        )}
      </Panel>
    </>
  );
}

function HostsView() {
  const params = useSearchParams();
  const ip = params.get("ip")?.trim() ?? "";
  return (
    <>
      <PageHeader
        title={ip ? ip : "Hosts"}
        description={
          ip
            ? "Everything the sensor has stored about this address."
            : "Look up any address the sensor has seen."
        }
        actions={<HostLookup key={ip} initial={ip} />}
      />
      {ip ? <HostDetail ip={ip} /> : <Overview />}
    </>
  );
}

export default function HostsPage() {
  return (
    <Suspense fallback={<SkeletonRows rows={8} />}>
      <HostsView />
    </Suspense>
  );
}
