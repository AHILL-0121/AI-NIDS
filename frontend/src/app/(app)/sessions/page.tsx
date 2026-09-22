"use client";

import {
  ClockCounterClockwiseIcon,
  FilePdfIcon,
  FileTextIcon,
  TrashIcon,
} from "@phosphor-icons/react";
import { useState } from "react";

import { RelativeTime } from "@/components/AlertBits";
import { Dot, Tag } from "@/components/Badges";
import { Button, FileLink, IconButton, LinkButton } from "@/components/Button";
import { DataTable, columnHelper } from "@/components/DataTable";
import { Drawer } from "@/components/Overlays";
import { Facts, PageHeader, Panel } from "@/components/Panel";
import { EmptyState, FormError, QueryView } from "@/components/States";
import { useToast } from "@/components/Toast";
import { TrafficChart } from "@/charts/charts";
import { absoluteTime, count, duration, humanize } from "@/lib/format";
import {
  reportUrl,
  useCreateReport,
  useDeleteReport,
  useReports,
  useSessions,
  useTimeseries,
  type Report,
  type Session,
} from "@/lib/queries";

const col = columnHelper<Session>();

function metric(session: Session, key: string): number | null {
  const value = session.metrics?.[key];
  return typeof value === "number" ? value : null;
}

function StatusCell({ session }: { session: Session }) {
  const tone = session.status === "running" ? "ok" : session.status === "failed" ? "bad" : "off";
  return (
    <span className="inline-flex items-center gap-1.5" title={session.error ?? undefined}>
      <Dot tone={tone} pulse={session.status === "running"} />
      {humanize(session.status)}
    </span>
  );
}

const columns = col.columns([
  col.accessor("started_at", {
    header: "Started",
    cell: (c) => <span className="tabular-nums">{absoluteTime(c.getValue())}</span>,
  }),
  col.accessor("kind", {
    header: "Kind",
    cell: (c) => <Tag mono={false}>{humanize(c.getValue())}</Tag>,
  }),
  col.accessor("source", {
    header: "Source",
    cell: (c) => <span className="font-mono">{c.getValue()}</span>,
  }),
  col.display({
    id: "duration",
    header: "Duration",
    cell: (c) => {
      const s = c.row.original;
      return (
        <span className="tabular-nums">
          {s.stopped_at ? duration(s.stopped_at - s.started_at) : "running"}
        </span>
      );
    },
  }),
  col.display({
    id: "packets",
    header: () => <span className="block text-right">Packets</span>,
    cell: (c) => {
      const n = metric(c.row.original, "packets_seen");
      return <span className="block text-right tabular-nums">{n === null ? "—" : count(n)}</span>;
    },
  }),
  col.display({
    id: "flows",
    header: () => <span className="block text-right">Flows</span>,
    cell: (c) => {
      const n = metric(c.row.original, "flows_created");
      return <span className="block text-right tabular-nums">{n === null ? "—" : count(n)}</span>;
    },
  }),
  col.accessor("model_version", {
    header: "Model",
    cell: (c) => <span className="text-ink-muted">{c.getValue() ?? "rules only"}</span>,
  }),
  col.accessor("status", {
    header: "Status",
    cell: (c) => <StatusCell session={c.row.original} />,
  }),
]);

export default function SessionsPage() {
  const sessions = useSessions(200);
  const [selected, setSelected] = useState<Session | null>(null);
  return (
    <>
      <PageHeader
        title="Sessions"
        description="Every live capture and .pcap replay, newest first."
      />
      <Panel>
        <QueryView query={sessions}>
          {(page) => (
            <DataTable
              label="Capture sessions"
              data={page.items}
              columns={columns}
              template="minmax(170px,1.2fr) 96px minmax(140px,1.4fr) 96px 80px 72px minmax(120px,1fr) 112px"
              rowKey={(s) => s.id}
              selectedKey={selected?.id}
              onOpen={setSelected}
              empty={
                <EmptyState icon={ClockCounterClockwiseIcon} title="No sessions yet">
                  Start a capture from the top bar or replay a .pcap from Jobs.
                </EmptyState>
              }
            />
          )}
        </QueryView>
      </Panel>
      <SessionDrawer session={selected} onClose={() => setSelected(null)} />
    </>
  );
}

function SessionDrawer({ session, onClose }: { session: Session | null; onClose: () => void }) {
  return (
    <Drawer
      isOpen={session !== null}
      onClose={onClose}
      title={session ? `${humanize(session.kind)} · ${session.source}` : "Session"}
      subtitle={session && <span className="font-mono">{session.id}</span>}
      footer={
        session && (
          <>
            <LinkButton size="dense" variant="primary" href={`/alerts/?session=${session.id}`}>
              Alerts
            </LinkButton>
            <LinkButton size="dense" href={`/flows/?session=${session.id}`}>
              Flows
            </LinkButton>
          </>
        )
      }
    >
      {session && <SessionBody session={session} />}
    </Drawer>
  );
}

function SessionBody({ session }: { session: Session }) {
  // Replays keep original packet timestamps, so ask for the session's own window.
  const traffic = useTimeseries({ resolution: 60, since: 0, session_id: session.id });
  const metrics = Object.entries(session.metrics ?? {}).filter(
    ([, v]) => typeof v === "number" || typeof v === "string",
  );
  return (
    <div className="flex flex-col gap-5">
      <Facts
        items={[
          ["Status", <StatusCell key="s" session={session} />],
          ["Backend", session.backend],
          ["Started", absoluteTime(session.started_at)],
          ["Stopped", session.stopped_at ? absoluteTime(session.stopped_at) : "—"],
          ["Model", session.model_version ?? "rules only"],
        ]}
      />
      {session.error && (
        <p
          role="alert"
          className="rounded-[var(--radius-control)] bg-[var(--sev-critical-wash)] px-3 py-2 text-meta text-sev-critical"
        >
          {session.error}
        </p>
      )}
      <section className="flex flex-col gap-2">
        <h3 className="text-label font-medium text-ink-subtle uppercase">Traffic (per minute)</h3>
        <QueryView
          query={traffic}
          empty={(b) =>
            b.length === 0 ? (
              <p className="text-meta text-ink-subtle">No traffic recorded.</p>
            ) : null
          }
        >
          {(buckets) => <TrafficChart buckets={buckets} resolution={60} height={200} />}
        </QueryView>
      </section>
      <SessionReports session={session} />
      {metrics.length > 0 && (
        <section className="flex flex-col gap-2">
          <h3 className="text-label font-medium text-ink-subtle uppercase">Counters</h3>
          <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-1 text-dense">
            {metrics.map(([key, value]) => (
              <div key={key} className="contents">
                <dt className="text-ink-muted">{humanize(key)}</dt>
                <dd className="font-mono tabular-nums">
                  {typeof value === "number" ? value.toLocaleString() : String(value)}
                </dd>
              </div>
            ))}
          </dl>
        </section>
      )}
    </div>
  );
}

function reportTone(report: Report): "ok" | "warn" | "bad" | "off" {
  if (report.status === "running") return "warn";
  if (report.status === "done") return "ok";
  return report.status === "failed" ? "bad" : "off";
}

function SessionReports({ session }: { session: Session }) {
  const reports = useReports(session.id);
  const create = useCreateReport();
  const remove = useDeleteReport();
  const notify = useToast();
  const running = reports.data?.some((r) => r.status === "running") ?? false;
  return (
    <section className="flex flex-col gap-2" aria-labelledby="session-reports">
      <div className="flex items-center justify-between gap-2">
        <h3 id="session-reports" className="text-label font-medium text-ink-subtle uppercase">
          Reports
        </h3>
        <Button
          size="dense"
          loading={create.isPending || running}
          isDisabled={session.status === "running"}
          onPress={() =>
            create.mutate(session.id, {
              onSuccess: () => notify("Generating the report…", { tone: "ok" }),
            })
          }
        >
          Generate report
        </Button>
      </div>
      {session.status === "running" && (
        <p className="text-meta text-ink-subtle">
          Stop the capture to report on the whole session.
        </p>
      )}
      <FormError error={create.error ?? remove.error} />
      <QueryView
        query={reports}
        empty={(list) =>
          list.length === 0 ? (
            <p className="text-meta text-ink-subtle">
              No reports yet. A report summarises the session with its alerts, what to do about them
              and a glossary, as a web page and a PDF.
            </p>
          ) : null
        }
      >
        {(list) => (
          <ul className="divide-y divide-line rounded-[var(--radius-panel)] border border-line">
            {list.map((report) => (
              <li key={report.id} className="flex flex-col gap-1.5 px-3 py-2">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="inline-flex min-w-0 flex-1 items-center gap-1.5 text-dense">
                    <Dot tone={reportTone(report)} pulse={report.status === "running"} />
                    {report.status === "running" ? "Generating…" : humanize(report.status)}
                    <span className="text-ink-subtle">
                      · <RelativeTime epoch={report.created_at} />
                    </span>
                  </span>
                  {report.html && (
                    <FileLink
                      href={reportUrl(report.id, "html")}
                      target="_blank"
                      rel="noopener noreferrer"
                    >
                      <FileTextIcon size={14} aria-hidden /> View
                    </FileLink>
                  )}
                  {report.pdf && (
                    <FileLink href={reportUrl(report.id, "pdf", true)} download>
                      <FilePdfIcon size={14} aria-hidden /> PDF
                    </FileLink>
                  )}
                  {report.status !== "running" && (
                    <IconButton
                      label="Delete report"
                      icon={<TrashIcon size={14} aria-hidden />}
                      onPress={() => remove.mutate(report.id)}
                    />
                  )}
                </div>
                {report.error && <p className="text-meta text-sev-critical">{report.error}</p>}
                {report.status === "done" && !report.pdf && report.pdf_error && (
                  <p className="text-meta text-ink-subtle">No PDF: {report.pdf_error}</p>
                )}
              </li>
            ))}
          </ul>
        )}
      </QueryView>
    </section>
  );
}
