"use client";

import { ArrowClockwiseIcon } from "@phosphor-icons/react";

import { RelativeTime } from "@/components/AlertBits";
import { Dot, HealthIcon } from "@/components/Badges";
import { Button, TextLink } from "@/components/Button";
import { LogTail } from "@/components/LogTail";
import { Facts, PageHeader, Panel } from "@/components/Panel";
import { EmptyState, QueryView } from "@/components/States";
import { absoluteTime, humanize } from "@/lib/format";
import { useConnection } from "@/lib/live";
import { useAudit, useCapabilities, useJobs, useLogs, useSensor } from "@/lib/queries";

export default function SystemPage() {
  const capabilities = useCapabilities();
  const sensor = useSensor();
  const jobs = useJobs();
  const logs = useLogs("api", 300);
  const audit = useAudit(50);
  const connection = useConnection();
  const running = jobs.data?.filter((j) => j.status === "running" || j.status === "queued") ?? [];

  return (
    <>
      <PageHeader
        title="System"
        description="Whether this machine can capture, what's running, and what happened."
      />

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel
          title="Capture capabilities"
          actions={
            <Button
              size="dense"
              variant="ghost"
              icon={<ArrowClockwiseIcon size={14} aria-hidden />}
              loading={capabilities.isFetching}
              onPress={() => void capabilities.refetch()}
            >
              Check again
            </Button>
          }
        >
          <QueryView query={capabilities}>
            {(report) => (
              <>
                <p className="border-b border-line px-4 py-2 text-meta text-ink-muted">
                  {report.platform} · capture backend {report.backend ?? "none available"}
                </p>
                <ul className="divide-y divide-line">
                  {report.checks.map((check) => (
                    <li key={check.name} className="flex gap-3 px-4 py-2.5">
                      <HealthIcon health={check.status} />
                      <div className="flex min-w-0 flex-col gap-0.5">
                        <span className="font-medium">{check.name}</span>
                        <span className="text-meta text-ink-muted">{check.detail}</span>
                        {check.fix && check.status !== "ok" && (
                          <span className="text-meta">Fix: {check.fix}</span>
                        )}
                      </div>
                    </li>
                  ))}
                </ul>
              </>
            )}
          </QueryView>
        </Panel>

        <Panel title="Sensor and services" bodyClassName="p-4 flex flex-col gap-4">
          <QueryView query={sensor}>
            {(state) => (
              <Facts
                items={[
                  [
                    "Capture",
                    <span key="c" className="inline-flex items-center gap-1.5">
                      <Dot tone={state.running ? "ok" : "off"} pulse={state.running} />
                      {state.running ? "Running" : "Stopped"}
                    </span>,
                  ],
                  ["Interface", state.interface ?? "—"],
                  ["Started", state.started_at ? absoluteTime(state.started_at) : "—"],
                  ["Model", state.model_version ?? "rules only"],
                  ["Process id", state.pid ?? "—"],
                  [
                    "Live updates",
                    <span key="l" className="inline-flex items-center gap-1.5">
                      <Dot
                        tone={
                          connection === "live"
                            ? "ok"
                            : connection === "connecting"
                              ? "warn"
                              : "bad"
                        }
                      />
                      {humanize(connection)}
                    </span>,
                  ],
                ]}
              />
            )}
          </QueryView>
          <div className="flex flex-col gap-1">
            <span className="text-label font-medium text-ink-subtle uppercase">Running jobs</span>
            {running.length === 0 ? (
              <span className="text-meta text-ink-muted">None.</span>
            ) : (
              <ul className="text-meta">
                {running.map((j) => (
                  <li key={j.id}>
                    <TextLink href="/jobs/">{humanize(j.kind)}</TextLink> · started{" "}
                    <RelativeTime epoch={j.started_at ?? j.created_at} />
                  </li>
                ))}
              </ul>
            )}
          </div>
          {sensor.data?.job_id && (
            <div className="flex flex-col gap-1">
              <span className="text-label font-medium text-ink-subtle uppercase">Sensor log</span>
              <SensorLog jobId={sensor.data.job_id} />
            </div>
          )}
        </Panel>
      </div>

      <Panel title="API log">
        <div className="p-3">
          <QueryView query={logs}>{(tail) => <LogTail lines={tail.lines} />}</QueryView>
        </div>
      </Panel>

      <Panel title="Audit log">
        <QueryView
          query={audit}
          empty={(rows) => (rows.length === 0 ? <EmptyState title="Nothing recorded yet" /> : null)}
        >
          {(rows) => (
            <ul className="divide-y divide-line text-dense">
              {rows.map((row, i) => (
                <li
                  key={`${row.ts}-${i}`}
                  className="grid grid-cols-[110px_minmax(0,1fr)] gap-3 px-4 py-2 sm:grid-cols-[140px_120px_minmax(0,1fr)]"
                >
                  <span className="text-ink-subtle" title={absoluteTime(row.ts)}>
                    <RelativeTime epoch={row.ts} />
                  </span>
                  <span className="hidden truncate text-ink-muted sm:block">{row.actor}</span>
                  <span className="min-w-0 truncate">
                    <span className="font-mono">{row.action}</span>
                    {row.target && <span className="text-ink-muted"> · {row.target}</span>}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </QueryView>
      </Panel>
    </>
  );
}

function SensorLog({ jobId }: { jobId: string }) {
  const log = useLogs(`job:${jobId}`, 100);
  return <LogTail lines={log.data?.lines ?? []} className="max-h-48" />;
}
