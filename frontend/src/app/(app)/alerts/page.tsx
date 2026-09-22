"use client";

import { DownloadSimpleIcon, ShieldCheckIcon } from "@phosphor-icons/react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { Suspense, useMemo, useState } from "react";

import { AlertDetail } from "@/app/(app)/alerts/AlertDetail";
import { RelativeTime, alertDestination } from "@/components/AlertBits";
import {
  ALERT_STATUSES,
  SEVERITIES,
  SeverityChip,
  StatusBadge,
  severityLabel,
  statusLabel,
} from "@/components/Badges";
import { Button } from "@/components/Button";
import { DataTable, Pager, columnHelper } from "@/components/DataTable";
import { SearchField } from "@/components/Field";
import { FilterChips } from "@/components/FilterChips";
import { PageHeader, Panel } from "@/components/Panel";
import { EmptyState, ErrorState, SkeletonRows } from "@/components/States";
import { percent } from "@/lib/format";
import { useAlerts, type Alert, type AlertStatus, type Severity } from "@/lib/queries";

const PAGE = 200;
const col = columnHelper<Alert>();

const columns = col.columns([
  col.accessor("severity", {
    header: "Severity",
    cell: (c) => <SeverityChip severity={c.getValue()} compact />,
  }),
  col.accessor("title", {
    header: "Detection",
    cell: (c) => <span className="font-medium">{c.getValue()}</span>,
  }),
  col.accessor("src", {
    header: "Source",
    cell: (c) => <span className="font-mono">{c.getValue() ?? "*"}</span>,
  }),
  col.display({
    id: "dst",
    header: "Destination",
    cell: (c) => <span className="font-mono">{alertDestination(c.row.original)}</span>,
  }),
  col.accessor("occurrences", {
    header: () => <span className="block text-right">Hits</span>,
    cell: (c) => (
      <span className="block text-right tabular-nums">{c.getValue().toLocaleString()}</span>
    ),
  }),
  col.accessor("confidence", {
    header: () => <span className="block text-right">Conf.</span>,
    cell: (c) => <span className="block text-right tabular-nums">{percent(c.getValue(), 0)}</span>,
  }),
  col.accessor("last_seen", { header: "Seen", cell: (c) => <RelativeTime epoch={c.getValue()} /> }),
  col.accessor("status", { header: "Status", cell: (c) => <StatusBadge status={c.getValue()} /> }),
]);

function csvCell(value: unknown): string {
  const text = value === null || value === undefined ? "" : String(value);
  // Neutralise spreadsheet formulas and quote everything.
  const safe = /^[=+\-@]/.test(text) ? `'${text}` : text;
  return `"${safe.replace(/"/g, '""')}"`;
}

function exportCsv(alerts: Alert[]) {
  const header = [
    "id",
    "severity",
    "type",
    "title",
    "src",
    "dst",
    "ports",
    "occurrences",
    "confidence",
    "created_at",
    "last_seen",
    "status",
    "mitre",
  ];
  const rows = alerts.map((a) =>
    [
      a.id,
      a.severity,
      a.type,
      a.title,
      a.src,
      a.dst,
      a.ports.join(" "),
      a.occurrences,
      a.confidence.toFixed(3),
      new Date(a.created_at * 1000).toISOString(),
      new Date(a.last_seen * 1000).toISOString(),
      a.status,
      a.mitre_technique,
    ]
      .map(csvCell)
      .join(","),
  );
  const blob = new Blob([[header.join(","), ...rows].join("\n")], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const link = Object.assign(document.createElement("a"), {
    href: url,
    download: `alerts-${Date.now()}.csv`,
  });
  link.click();
  URL.revokeObjectURL(url);
}

function AlertsView() {
  const params = useSearchParams();
  const router = useRouter();
  const pathname = usePathname();
  const selectedId = params.get("id");
  const sessionId = params.get("session") ?? undefined;

  const [severity, setSeverity] = useState<Severity[]>([]);
  const [status, setStatus] = useState<AlertStatus[]>(["new", "acknowledged"]);
  const [src, setSrc] = useState(params.get("src") ?? "");
  const [dst, setDst] = useState("");
  const [offset, setOffset] = useState(0);

  const filters = useMemo(
    () => ({
      severity,
      status,
      src: src.trim() || undefined,
      dst: dst.trim() || undefined,
      session_id: sessionId,
      limit: PAGE,
      offset,
    }),
    [severity, status, src, dst, sessionId, offset],
  );
  const alerts = useAlerts(filters);

  const setParam = (key: string, value: string | null) => {
    const next = new URLSearchParams(params.toString());
    if (value === null) next.delete(key);
    else next.set(key, value);
    const query = next.toString();
    router.replace(query ? `${pathname}?${query}` : pathname, { scroll: false });
  };
  const resetPage =
    <T,>(set: (v: T) => void) =>
    (v: T) => {
      set(v);
      setOffset(0);
    };

  return (
    <>
      <PageHeader
        title="Alerts"
        description={
          sessionId ? (
            <>
              Filtered to session <span className="font-mono">{sessionId}</span>
            </>
          ) : undefined
        }
        actions={
          <Button
            size="dense"
            icon={<DownloadSimpleIcon size={14} aria-hidden />}
            isDisabled={!alerts.data?.items.length}
            onPress={() => alerts.data && exportCsv(alerts.data.items)}
          >
            Export CSV
          </Button>
        }
      />

      <Panel bodyClassName="flex flex-col">
        <div className="flex flex-wrap items-center gap-x-5 gap-y-2 border-b border-line px-3 py-2.5">
          <FilterChips
            label="Severity"
            value={severity}
            onChange={resetPage(setSeverity)}
            options={SEVERITIES.map((s) => ({ id: s, label: severityLabel(s) }))}
          />
          <FilterChips
            label="Status"
            value={status}
            onChange={resetPage(setStatus)}
            options={ALERT_STATUSES.map((s) => ({ id: s, label: statusLabel(s) }))}
          />
          <div className="flex flex-wrap gap-2">
            <SearchField
              label="Source IP"
              placeholder="src"
              value={src}
              onChange={resetPage(setSrc)}
              className="w-40"
            />
            <SearchField
              label="Destination IP"
              placeholder="dst"
              value={dst}
              onChange={resetPage(setDst)}
              className="w-40"
            />
          </div>
          {sessionId && (
            <Button size="dense" variant="ghost" onPress={() => setParam("session", null)}>
              Clear session filter
            </Button>
          )}
        </div>

        {alerts.isPending ? (
          <SkeletonRows rows={10} />
        ) : alerts.error ? (
          <ErrorState error={alerts.error} onRetry={() => void alerts.refetch()} />
        ) : (
          <>
            <DataTable
              label="Alerts"
              data={alerts.data.items}
              columns={columns}
              template="104px minmax(180px,2fr) minmax(130px,1fr) minmax(150px,1.2fr) 72px 64px 96px 128px"
              rowKey={(a) => a.id}
              selectedKey={selectedId}
              onOpen={(a) => setParam("id", a.id)}
              empty={
                <EmptyState icon={ShieldCheckIcon} title="No alerts match">
                  Clear a filter to see more. Resolved and false-positive alerts are hidden by
                  default.
                </EmptyState>
              }
            />
            <Pager total={alerts.data.total} limit={PAGE} offset={offset} onChange={setOffset} />
          </>
        )}
      </Panel>

      <AlertDetail id={selectedId} onClose={() => setParam("id", null)} />
    </>
  );
}

export default function AlertsPage() {
  return (
    <Suspense fallback={<SkeletonRows rows={10} />}>
      <AlertsView />
    </Suspense>
  );
}
