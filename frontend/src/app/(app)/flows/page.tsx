"use client";

import { ShuffleIcon } from "@phosphor-icons/react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { Suspense, useMemo, useState } from "react";

import { RelativeTime } from "@/components/AlertBits";
import { ProtocolTag, Tag } from "@/components/Badges";
import { Button, TextLink } from "@/components/Button";
import { DataTable, Pager, columnHelper } from "@/components/DataTable";
import { SearchField, Select } from "@/components/Field";
import { Drawer } from "@/components/Overlays";
import { Facts, PageHeader, Panel } from "@/components/Panel";
import { EmptyState, ErrorState, SkeletonRows } from "@/components/States";
import { absoluteTime, bytes, duration, endpoint, humanize, protocolName } from "@/lib/format";
import { useFlows, type Flow } from "@/lib/queries";

const PAGE = 200;
const col = columnHelper<Flow>();

const columns = col.columns([
  col.accessor("last_seen", { header: "Seen", cell: (c) => <RelativeTime epoch={c.getValue()} /> }),
  col.display({
    id: "src",
    header: "Source",
    cell: (c) => (
      <span className="font-mono">{endpoint(c.row.original.src_ip, c.row.original.src_port)}</span>
    ),
  }),
  col.display({
    id: "dst",
    header: "Destination",
    cell: (c) => (
      <span className="font-mono">{endpoint(c.row.original.dst_ip, c.row.original.dst_port)}</span>
    ),
  }),
  col.accessor("protocol", {
    header: "Proto",
    cell: (c) => <ProtocolTag protocol={c.getValue()} />,
  }),
  col.accessor("app_protocol", {
    header: "App",
    cell: (c) => <span className="text-ink-muted">{c.getValue() ?? "—"}</span>,
  }),
  col.accessor("packets", {
    header: () => <span className="block text-right">Packets</span>,
    cell: (c) => (
      <span className="block text-right tabular-nums">{c.getValue().toLocaleString()}</span>
    ),
  }),
  col.accessor("payload_bytes", {
    header: () => <span className="block text-right">Payload</span>,
    cell: (c) => <span className="block text-right tabular-nums">{bytes(c.getValue())}</span>,
  }),
  col.display({
    id: "duration",
    header: () => <span className="block text-right">Duration</span>,
    cell: (c) => (
      <span className="block text-right tabular-nums">
        {duration(c.row.original.last_seen - c.row.original.first_seen)}
      </span>
    ),
  }),
  col.accessor("end_reason", {
    header: "Ended",
    cell: (c) => <span className="text-ink-muted">{humanize(c.getValue())}</span>,
  }),
]);

const PROTOCOL_OPTIONS = [
  { id: "any", label: "Any protocol" },
  { id: "6", label: "TCP" },
  { id: "17", label: "UDP" },
  { id: "1", label: "ICMP" },
  { id: "58", label: "ICMPv6" },
];

function FlowsView() {
  const params = useSearchParams();
  const router = useRouter();
  const pathname = usePathname();
  const sessionId = params.get("session") ?? undefined;
  const [ip, setIp] = useState(params.get("ip") ?? "");
  const [port, setPort] = useState("");
  const [protocol, setProtocol] = useState("any");
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState<Flow | null>(null);

  const portNumber = /^\d{1,5}$/.test(port.trim()) ? Number(port.trim()) : undefined;
  const filters = useMemo(
    () => ({
      session_id: sessionId,
      ip: ip.trim() || undefined,
      port: portNumber !== undefined && portNumber <= 65535 ? portNumber : undefined,
      protocol: protocol === "any" ? undefined : Number(protocol),
      limit: PAGE,
      offset,
    }),
    [sessionId, ip, portNumber, protocol, offset],
  );
  const flows = useFlows(filters);
  const reset =
    <T,>(set: (v: T) => void) =>
    (v: T) => {
      set(v);
      setOffset(0);
    };

  return (
    <>
      <PageHeader
        title="Flows"
        description={
          sessionId ? (
            <>
              Session <span className="font-mono">{sessionId}</span>
            </>
          ) : (
            "Bidirectional connections seen by the sensor. Flows are sampled for storage; every flow tied to an alert is kept."
          )
        }
      />
      <Panel bodyClassName="flex flex-col">
        <div className="flex flex-wrap items-center gap-2 border-b border-line px-3 py-2.5">
          <SearchField
            label="IP address (either end)"
            placeholder="IP address"
            value={ip}
            onChange={reset(setIp)}
            className="w-48"
          />
          <SearchField
            label="Port"
            placeholder="port"
            value={port}
            onChange={reset(setPort)}
            className="w-28"
          />
          <Select
            label="Protocol"
            hideLabel
            options={PROTOCOL_OPTIONS}
            value={protocol}
            onChange={reset(setProtocol)}
            className="w-40"
          />
          {sessionId && (
            <Button size="dense" variant="ghost" onPress={() => router.replace(pathname)}>
              Clear session filter
            </Button>
          )}
        </div>
        {flows.isPending ? (
          <SkeletonRows rows={10} />
        ) : flows.error ? (
          <ErrorState error={flows.error} onRetry={() => void flows.refetch()} />
        ) : (
          <>
            <DataTable
              label="Flows"
              data={flows.data.items}
              columns={columns}
              template="96px minmax(170px,1.3fr) minmax(170px,1.3fr) 72px minmax(70px,0.6fr) 84px 88px 88px minmax(90px,0.8fr)"
              rowKey={(f) => String(f.id)}
              selectedKey={selected ? String(selected.id) : null}
              onOpen={setSelected}
              empty={
                <EmptyState icon={ShuffleIcon} title="No flows match">
                  Flows appear once a capture or replay has run.
                </EmptyState>
              }
            />
            <Pager total={flows.data.total} limit={PAGE} offset={offset} onChange={setOffset} />
          </>
        )}
      </Panel>
      <FlowDrawer flow={selected} onClose={() => setSelected(null)} />
    </>
  );
}

function statValue(value: unknown): string {
  if (typeof value === "number")
    return Number.isInteger(value) ? value.toLocaleString() : value.toFixed(4);
  if (value && typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function FlowDrawer({ flow, onClose }: { flow: Flow | null; onClose: () => void }) {
  return (
    <Drawer
      isOpen={flow !== null}
      onClose={onClose}
      title={flow ? `${protocolName(flow.protocol)} flow` : "Flow"}
      subtitle={
        flow && (
          <span className="font-mono">
            {endpoint(flow.src_ip, flow.src_port)} → {endpoint(flow.dst_ip, flow.dst_port)}
          </span>
        )
      }
    >
      {flow && (
        <div className="flex flex-col gap-5">
          <Facts
            items={[
              ["First seen", absoluteTime(flow.first_seen)],
              ["Last seen", absoluteTime(flow.last_seen)],
              ["Duration", duration(flow.last_seen - flow.first_seen)],
              ["Ended by", humanize(flow.end_reason)],
              ["Packets", flow.packets.toLocaleString()],
              ["Payload", bytes(flow.payload_bytes)],
              ["IP bytes", flow.ip_bytes === null ? "—" : bytes(flow.ip_bytes)],
              ["Application", flow.app_protocol ?? "—"],
            ]}
          />
          <p className="flex flex-wrap gap-3 text-meta">
            <TextLink href={`/hosts/?ip=${encodeURIComponent(flow.src_ip)}`}>Source host</TextLink>
            <TextLink href={`/hosts/?ip=${encodeURIComponent(flow.dst_ip)}`}>
              Destination host
            </TextLink>
            <TextLink
              href={`/alerts/?session=${flow.session_id}&src=${encodeURIComponent(flow.src_ip)}`}
            >
              Alerts from source
            </TextLink>
          </p>
          <section className="flex flex-col gap-2">
            <h3 className="text-label font-medium text-ink-subtle uppercase">Flow statistics</h3>
            <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-1 rounded-[var(--radius-control)] bg-surface-sunken p-3 text-dense">
              {Object.entries(flow.stats ?? {}).map(([key, value]) => (
                <div key={key} className="contents">
                  <dt className="text-ink-muted">{key}</dt>
                  <dd className="font-mono break-words tabular-nums">{statValue(value)}</dd>
                </div>
              ))}
            </dl>
          </section>
          <p className="text-meta text-ink-subtle">
            Flow id <Tag>{flow.flow_id}</Tag>
          </p>
        </div>
      )}
    </Drawer>
  );
}

export default function FlowsPage() {
  return (
    <Suspense fallback={<SkeletonRows rows={10} />}>
      <FlowsView />
    </Suspense>
  );
}
