"use client";

import { ArrowCounterClockwiseIcon, CheckIcon, EyeIcon, ProhibitIcon } from "@phosphor-icons/react";
import { useState } from "react";

import { RelativeTime } from "@/components/AlertBits";
import { MitreTag, ProtocolTag, SeverityChip, StatusBadge, Tag } from "@/components/Badges";
import { Button, TextLink } from "@/components/Button";
import { TextField } from "@/components/Field";
import { Drawer } from "@/components/Overlays";
import { Facts } from "@/components/Panel";
import { ErrorState, FormError, SkeletonRows } from "@/components/States";
import { useToast } from "@/components/Toast";
import { absoluteTime, bytes, endpoint, humanize, percent, protocolName } from "@/lib/format";
import { useAlert, useFlows, useUpdateAlert, type Alert, type AlertStatus } from "@/lib/queries";

function evidenceValue(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (typeof value === "number")
    return Number.isInteger(value) ? value.toLocaleString() : value.toFixed(3);
  if (Array.isArray(value))
    return (
      value.slice(0, 20).map(evidenceValue).join(", ") +
      (value.length > 20 ? ` … (+${value.length - 20})` : "")
    );
  if (value && typeof value === "object") return JSON.stringify(value);
  return String(value);
}

export function AlertDetail({ id, onClose }: { id: string | null; onClose: () => void }) {
  const alert = useAlert(id);
  const data = alert.data;
  return (
    <Drawer
      isOpen={Boolean(id)}
      onClose={onClose}
      title={
        data ? (
          <span className="flex items-center gap-2">
            <SeverityChip severity={data.severity} />
            {data.title}
          </span>
        ) : (
          "Alert"
        )
      }
      subtitle={
        data && (
          <span className="font-mono">
            {data.src ?? "*"} → {data.dst ?? "*"} · #{data.id.slice(0, 8)}
          </span>
        )
      }
      footer={data && <Actions alert={data} />}
    >
      {alert.isPending ? (
        <SkeletonRows rows={8} />
      ) : alert.error || !data ? (
        <ErrorState error={alert.error} onRetry={() => void alert.refetch()} />
      ) : (
        <Body alert={data} />
      )}
    </Drawer>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="flex flex-col gap-2 border-b border-line py-4 first:pt-0 last:border-b-0">
      <h3 className="text-label font-medium text-ink-subtle uppercase">{title}</h3>
      {children}
    </section>
  );
}

function Body({ alert }: { alert: Alert }) {
  const evidence = Object.entries(alert.evidence ?? {});
  return (
    <div className="flex flex-col">
      <Section title="What happened">
        <p>{alert.explanation}</p>
      </Section>

      {evidence.length > 0 && (
        <Section title="Why it was flagged">
          <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-1 text-dense">
            {evidence.map(([key, value]) => (
              <div key={key} className="contents">
                <dt className="text-ink-muted">{humanize(key)}</dt>
                <dd className="font-mono break-words tabular-nums">{evidenceValue(value)}</dd>
              </div>
            ))}
          </dl>
        </Section>
      )}

      <Section title="How sure">
        <div className="flex items-center gap-3">
          <div
            role="meter"
            aria-label="Confidence"
            aria-valuemin={0}
            aria-valuemax={1}
            aria-valuenow={alert.confidence}
            className="h-2 flex-1 overflow-hidden rounded-full bg-surface-sunken"
          >
            <div className="h-full bg-accent" style={{ width: `${alert.confidence * 100}%` }} />
          </div>
          <span className="font-mono tabular-nums">{percent(alert.confidence, 0)}</span>
        </div>
        <div className="flex flex-wrap gap-1.5">
          <Tag>{alert.source}</Tag>
          {alert.family && <Tag>{alert.family}</Tag>}
          {alert.model_version && <Tag>{alert.model_version}</Tag>}
          <MitreTag technique={alert.mitre_technique} />
        </div>
      </Section>

      <Section title="What to do">
        <p>{alert.recommendation}</p>
      </Section>

      <Section title="Details">
        <Facts
          items={[
            ["Status", <StatusBadge key="s" status={alert.status} />],
            ["Hits", alert.occurrences.toLocaleString()],
            ["First seen", absoluteTime(alert.created_at)],
            ["Last seen", <RelativeTime key="l" epoch={alert.last_seen} />],
            ["Protocol", alert.protocol === null ? "—" : protocolName(alert.protocol)],
            [
              "Ports",
              alert.ports.length ? (
                <span className="font-mono">
                  {alert.ports.slice(0, 12).join(", ")}
                  {alert.ports.length > 12 ? ` +${alert.ports.length - 12}` : ""}
                </span>
              ) : (
                "—"
              ),
            ],
          ]}
        />
        {alert.src && (
          <p className="text-meta">
            <TextLink href={`/hosts/?ip=${encodeURIComponent(alert.src)}`}>
              Open source host
            </TextLink>
            {alert.session_id && (
              <>
                {" · "}
                <TextLink
                  href={`/flows/?session=${alert.session_id}&ip=${encodeURIComponent(alert.src)}`}
                >
                  Flows from this host
                </TextLink>
              </>
            )}
          </p>
        )}
      </Section>

      <RelatedFlows ids={alert.flow_ids} />
      <Note key={alert.id} alert={alert} />
    </div>
  );
}

function RelatedFlows({ ids }: { ids: string[] }) {
  const shown = ids.slice(0, 25);
  const flows = useFlows({ flow_id: shown, limit: 25 }, shown.length > 0);
  if (ids.length === 0) return null;
  return (
    <Section title={`Related flows (${ids.length})`}>
      {flows.isPending ? (
        <SkeletonRows rows={3} />
      ) : flows.error ? (
        <ErrorState error={flows.error} />
      ) : flows.data.items.length === 0 ? (
        <p className="text-meta text-ink-subtle">
          These flows weren’t kept (flow sampling or retention).
        </p>
      ) : (
        <ul className="flex flex-col divide-y divide-line rounded-[var(--radius-control)] border border-line text-dense">
          {flows.data.items.map((flow) => (
            <li key={flow.id} className="flex items-center gap-2 px-2.5 py-1.5">
              <ProtocolTag protocol={flow.protocol} />
              <span className="min-w-0 flex-1 truncate font-mono">
                {endpoint(flow.src_ip, flow.src_port)} → {endpoint(flow.dst_ip, flow.dst_port)}
              </span>
              <span className="shrink-0 text-meta text-ink-subtle tabular-nums">
                {flow.packets} pkts · {bytes(flow.payload_bytes)}
              </span>
            </li>
          ))}
        </ul>
      )}
    </Section>
  );
}

function Note({ alert }: { alert: Alert }) {
  const update = useUpdateAlert();
  const notify = useToast();
  const [note, setNote] = useState(alert.note);
  return (
    <Section title="Note">
      <TextField
        label="Note"
        multiline
        value={note}
        onChange={setNote}
        placeholder="What you found, who you told…"
      />
      <div>
        <Button
          size="dense"
          isDisabled={note === alert.note}
          loading={update.isPending}
          onPress={() =>
            update.mutate(
              { id: alert.id, note },
              { onSuccess: () => notify("Note saved.", { tone: "ok" }) },
            )
          }
        >
          Save note
        </Button>
      </div>
    </Section>
  );
}

function Actions({ alert }: { alert: Alert }) {
  const update = useUpdateAlert();
  const notify = useToast();
  const set = (status: AlertStatus, message: string) =>
    update.mutate({ id: alert.id, status }, { onSuccess: () => notify(message, { tone: "ok" }) });
  const busy = update.isPending;
  return (
    <>
      {alert.status === "new" && (
        <Button
          size="dense"
          variant="primary"
          isDisabled={busy}
          icon={<EyeIcon size={14} aria-hidden />}
          onPress={() => set("acknowledged", "Alert acknowledged.")}
        >
          Acknowledge
        </Button>
      )}
      {(alert.status === "new" || alert.status === "acknowledged") && (
        <>
          <Button
            size="dense"
            isDisabled={busy}
            icon={<CheckIcon size={14} aria-hidden />}
            onPress={() => set("resolved", "Alert resolved.")}
          >
            Resolve
          </Button>
          <Button
            size="dense"
            variant="danger"
            isDisabled={busy}
            icon={<ProhibitIcon size={14} aria-hidden />}
            onPress={() =>
              set(
                "false_positive",
                "Marked as false positive; repeats are suppressed (see Settings).",
              )
            }
          >
            False positive
          </Button>
        </>
      )}
      {(alert.status === "resolved" || alert.status === "false_positive") && (
        <Button
          size="dense"
          isDisabled={busy}
          icon={<ArrowCounterClockwiseIcon size={14} aria-hidden />}
          onPress={() => set("new", "Alert reopened.")}
        >
          Reopen
        </Button>
      )}
      <div className="w-full">
        <FormError error={update.error} />
      </div>
    </>
  );
}
