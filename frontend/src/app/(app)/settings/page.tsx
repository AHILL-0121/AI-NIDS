"use client";

import { ProhibitIcon, TrashIcon } from "@phosphor-icons/react";
import { useState, type ReactNode } from "react";
import { Form } from "react-aria-components";

import { NotificationsPanel } from "@/app/(app)/settings/Notifications";
import { RelativeTime } from "@/components/AlertBits";
import { Tag } from "@/components/Badges";
import { Button, IconButton, TextLink } from "@/components/Button";
import { NumberField, Switch, TextField } from "@/components/Field";
import { PageHeader, Panel } from "@/components/Panel";
import { EmptyState, FormError, QueryView } from "@/components/States";
import { ThemeToggle } from "@/components/ThemeToggle";
import { useToast } from "@/components/Toast";
import type { Schemas } from "@/lib/api/client";
import { protocolName } from "@/lib/format";
import {
  useAddSuppression,
  useChangePassword,
  useDisableSuppression,
  useSettings,
  useSuppressions,
  useUpdateSettings,
  type RuntimeSettings,
} from "@/lib/queries";

export default function SettingsPage() {
  const settings = useSettings();
  return (
    <>
      <PageHeader title="Settings" />
      <QueryView query={settings}>
        {/* Remount the form when the server copy changes, so the draft starts from saved values. */}
        {(data) => (
          <RuntimeForm key={JSON.stringify(data.values)} values={data.values} apply={data.apply} />
        )}
      </QueryView>
      <Suppressions />
      <NotificationsPanel />
      <div className="grid gap-4 lg:grid-cols-2">
        <PasswordForm />
        <Panel title="Appearance" bodyClassName="p-4 flex flex-col gap-2">
          <p className="text-ink-muted">
            Light is the default. System follows your operating system.
          </p>
          <div>
            <ThemeToggle />
          </div>
        </Panel>
      </div>
    </>
  );
}

function ApplyTag({ mode }: { mode: string | undefined }) {
  return (
    <span
      className={
        mode === "live"
          ? "shrink-0 rounded-[3px] bg-accent-wash px-1 text-label font-medium whitespace-nowrap text-accent uppercase"
          : "shrink-0 rounded-[3px] bg-surface-sunken px-1 text-label font-medium whitespace-nowrap text-ink-subtle uppercase"
      }
      title={
        mode === "live" ? "Takes effect immediately" : "Takes effect the next time capture starts"
      }
    >
      {mode === "live" ? "live" : "on restart"}
    </span>
  );
}

function Group({ title, children }: { title: string; children: ReactNode }) {
  return (
    <fieldset className="flex flex-col gap-3 border-t border-line px-4 pt-3 pb-4 first:border-t-0">
      <legend className="sr-only">{title}</legend>
      <h3 aria-hidden className="text-label font-medium text-ink-subtle uppercase">
        {title}
      </h3>
      <div className="grid gap-x-6 gap-y-4 sm:grid-cols-2 xl:grid-cols-3">{children}</div>
    </fieldset>
  );
}

type Numeric = {
  [K in keyof RuntimeSettings]-?: RuntimeSettings[K] extends number ? K : never;
}[keyof RuntimeSettings];

function RuntimeForm({
  values,
  apply,
}: {
  values: RuntimeSettings;
  apply: Schemas["SettingsOut"]["apply"];
}) {
  const [draft, setDraft] = useState<RuntimeSettings>(values);
  const [protocols, setProtocols] = useState(values.allowed_protocols.join(", "));
  const update = useUpdateSettings();
  const notify = useToast();

  const parsedProtocols = protocols
    .split(/[\s,]+/)
    .filter(Boolean)
    .map(Number);
  const protocolsValid = parsedProtocols.every((p) => Number.isInteger(p) && p >= 0 && p <= 255);

  const changes: Partial<RuntimeSettings> = {};
  for (const key of Object.keys(draft) as (keyof RuntimeSettings)[]) {
    if (key !== "allowed_protocols" && draft[key] !== values[key])
      Object.assign(changes, { [key]: draft[key] });
  }
  const sortedProtocols = [...new Set(parsedProtocols)].sort((a, b) => a - b);
  if (protocolsValid && sortedProtocols.join() !== values.allowed_protocols.join())
    changes.allowed_protocols = sortedProtocols;
  const dirty = Object.keys(changes).length > 0;
  const needsRestart = Object.keys(changes).some((k) => apply[k] !== "live");

  const num = (
    key: Numeric,
    label: string,
    unit: string | undefined,
    bounds: { min: number; max: number; step?: number },
    description?: string,
  ) => (
    <NumberField
      label={label}
      unit={unit}
      description={
        <span className="inline-flex flex-wrap items-center gap-1.5">
          <ApplyTag mode={apply[key]} /> {description}
        </span>
      }
      minValue={bounds.min}
      maxValue={bounds.max}
      step={bounds.step}
      value={draft[key] as number}
      onChange={(v) => !Number.isNaN(v) && setDraft({ ...draft, [key]: v })}
    />
  );

  const threshold = (
    key: "attack_threshold" | "novelty_threshold",
    label: string,
    min: number,
    fallback: number,
  ) => (
    <div className="flex flex-col gap-2">
      <Switch
        isSelected={draft[key] === null || draft[key] === undefined}
        onChange={(useDefault) => setDraft({ ...draft, [key]: useDefault ? null : fallback })}
      >
        {label}: use the model’s tuned value
      </Switch>
      {draft[key] !== null && draft[key] !== undefined && (
        <NumberField
          label={label}
          minValue={min}
          maxValue={1}
          step={0.001}
          formatOptions={{ maximumFractionDigits: 4 }}
          value={draft[key] ?? fallback}
          onChange={(v) => !Number.isNaN(v) && setDraft({ ...draft, [key]: v })}
          description={<ApplyTag mode={apply[key]} />}
        />
      )}
    </div>
  );

  return (
    <Panel title="Detection" bodyClassName="flex flex-col">
      <Form
        onSubmit={(event) => {
          event.preventDefault();
          update.mutate(changes, {
            onSuccess: () =>
              notify(
                needsRestart
                  ? "Saved. Restart capture to apply the marked settings."
                  : "Saved and applied.",
                { tone: "ok" },
              ),
          });
        }}
      >
        <Group title="Scans and sweeps">
          {num(
            "scan_window_s",
            "Time window",
            "s",
            { min: 5, max: 600 },
            "Port scan / sweep window",
          )}
          {num("scan_min_ports", "Ports for a scan", "ports", { min: 5, max: 5000 })}
          {num("sweep_min_hosts", "Hosts for a sweep", "hosts", { min: 5, max: 5000 })}
        </Group>
        <Group title="Floods">
          {num("flood_min_syn_rate", "SYN flood floor", "SYN/s", { min: 10, max: 1e7 })}
          {num("flood_min_pps", "UDP/ICMP flood floor", "pkt/s", { min: 100, max: 1e8 })}
          {num("flood_z", "Above normal by", "σ", { min: 2, max: 50, step: 0.5 })}
        </Group>
        <Group title="Alerts">
          {num("dedup_window_s", "Merge repeats within", "s", { min: 60, max: 86400 })}
          <TextField
            label="Allowed IP protocols"
            mono
            value={protocols}
            onChange={setProtocols}
            isInvalid={!protocolsValid}
            errorMessage="Protocol numbers are 0–255, separated by commas."
            description={
              <span className="inline-flex flex-wrap items-center gap-1.5">
                <ApplyTag mode={apply.allowed_protocols} />
                {protocolsValid && sortedProtocols.map((p) => <Tag key={p}>{protocolName(p)}</Tag>)}
              </span>
            }
          />
        </Group>
        <Group title="Machine learning">
          {threshold("attack_threshold", "Attack threshold", 0, 0.5)}
          {threshold("novelty_threshold", "Novelty threshold", 0.5, 0.99)}
          <p className="text-meta text-ink-subtle sm:col-span-2 xl:col-span-1">
            Each model ships thresholds tuned on validation data for a false-alarm budget. See{" "}
            <TextLink href="/model/">Model</TextLink> for the trade-off curve before overriding
            them.
          </p>
        </Group>
        <Group title="Storage and privacy">
          {num(
            "flow_sample_rate",
            "Flows stored",
            "share",
            { min: 0, max: 1, step: 0.05 },
            "Flows tied to alerts are always kept",
          )}
          {num("retention_flows_days", "Keep flows", "days", { min: 0.1, max: 3650 })}
          {num("retention_alerts_days", "Keep alerts", "days", { min: 0.1, max: 3650 })}
          <div className="flex flex-col gap-1">
            <Switch
              isSelected={draft.pseudonymize_ips}
              onChange={(v) => setDraft({ ...draft, pseudonymize_ips: v })}
            >
              Store IP addresses as keyed hashes
            </Switch>
            <span className="inline-flex items-center gap-1.5 text-meta text-ink-subtle">
              <ApplyTag mode={apply.pseudonymize_ips} /> Hides real addresses in stored data;
              lookups by IP stop matching.
            </span>
          </div>
        </Group>
        <div className="flex flex-wrap items-center gap-3 border-t border-line px-4 py-3">
          <Button
            type="submit"
            variant="primary"
            isDisabled={!dirty || !protocolsValid}
            loading={update.isPending}
          >
            Save changes
          </Button>
          <Button
            variant="ghost"
            isDisabled={!dirty}
            onPress={() => {
              setDraft(values);
              setProtocols(values.allowed_protocols.join(", "));
            }}
          >
            Discard
          </Button>
          {dirty && (
            <span className="text-meta text-ink-muted">
              {Object.keys(changes).length} unsaved change(s)
            </span>
          )}
          <div className="w-full">
            <FormError error={update.error} />
          </div>
        </div>
      </Form>
    </Panel>
  );
}

function Suppressions() {
  const rules = useSuppressions();
  const disable = useDisableSuppression();
  const add = useAddSuppression();
  const notify = useToast();
  const [src, setSrc] = useState("");
  const [dst, setDst] = useState("");
  const [type, setType] = useState("");
  const [reason, setReason] = useState("");

  return (
    <Panel title="Suppression rules" id="suppressions" bodyClassName="flex flex-col">
      <p className="px-4 pt-3 text-meta text-ink-muted">
        Matching detections are dropped before they become alerts. Marking an alert as a false
        positive adds a rule here.
      </p>
      <QueryView
        query={rules}
        empty={(list) =>
          list.filter((r) => r.active).length === 0 ? (
            <EmptyState icon={ProhibitIcon} title="No active rules" />
          ) : null
        }
      >
        {(list) => (
          <ul className="mt-2 divide-y divide-line border-y border-line">
            {list
              .filter((r) => r.active)
              .map((rule) => (
                <li key={rule.id} className="flex items-center gap-3 px-4 py-2">
                  <div className="flex min-w-0 flex-1 flex-col gap-0.5">
                    <span className="flex flex-wrap gap-1">
                      {rule.type && <Tag>type={rule.type}</Tag>}
                      {rule.src && <Tag>src={rule.src}</Tag>}
                      {rule.dst && <Tag>dst={rule.dst}</Tag>}
                      {rule.dst_port !== null && rule.dst_port !== undefined && (
                        <Tag>port={rule.dst_port}</Tag>
                      )}
                    </span>
                    <span className="truncate text-meta text-ink-subtle">
                      {rule.reason} · {rule.created_by} · <RelativeTime epoch={rule.created_at} />
                    </span>
                  </div>
                  <IconButton
                    label={`Remove rule ${rule.id}`}
                    icon={<TrashIcon size={14} aria-hidden />}
                    onPress={() =>
                      disable.mutate(rule.id, {
                        onSuccess: () => notify("Rule removed.", { tone: "ok" }),
                      })
                    }
                  />
                </li>
              ))}
          </ul>
        )}
      </QueryView>
      <Form
        className="flex flex-wrap items-end gap-2 px-4 py-3"
        onSubmit={(event) => {
          event.preventDefault();
          add.mutate(
            {
              type: type.trim() || null,
              src: src.trim() || null,
              dst: dst.trim() || null,
              reason: reason.trim(),
            },
            {
              onSuccess: () => {
                notify("Rule added.", { tone: "ok" });
                setSrc("");
                setDst("");
                setType("");
                setReason("");
              },
            },
          );
        }}
      >
        <TextField
          label="Detection type"
          mono
          placeholder="port_scan"
          value={type}
          onChange={setType}
          className="w-36"
        />
        <TextField
          label="Source"
          mono
          placeholder="10.0.0.5"
          value={src}
          onChange={setSrc}
          className="w-36"
        />
        <TextField
          label="Destination"
          mono
          placeholder="any"
          value={dst}
          onChange={setDst}
          className="w-36"
        />
        <TextField
          label="Reason"
          isRequired
          placeholder="Our vulnerability scanner"
          value={reason}
          onChange={setReason}
          className="min-w-48 flex-1"
        />
        <Button
          type="submit"
          loading={add.isPending}
          isDisabled={!reason.trim() || !(src.trim() || dst.trim() || type.trim())}
        >
          Add rule
        </Button>
        <div className="w-full">
          <FormError error={add.error ?? disable.error} />
        </div>
      </Form>
    </Panel>
  );
}

function PasswordForm() {
  const change = useChangePassword();
  const notify = useToast();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const mismatch = confirm.length > 0 && confirm !== next;
  return (
    <Panel title="Password" id="password" bodyClassName="p-4">
      <Form
        className="flex flex-col gap-3"
        onSubmit={(event) => {
          event.preventDefault();
          if (mismatch) return;
          change.mutate(
            { current_password: current, new_password: next },
            {
              onSuccess: () => {
                notify("Password changed. Other sessions were signed out.", { tone: "ok" });
                setCurrent("");
                setNext("");
                setConfirm("");
              },
            },
          );
        }}
      >
        <TextField
          label="Current password"
          type="password"
          autoComplete="current-password"
          isRequired
          value={current}
          onChange={setCurrent}
        />
        <TextField
          label="New password"
          type="password"
          autoComplete="new-password"
          isRequired
          minLength={12}
          value={next}
          onChange={setNext}
          description="At least 12 characters."
        />
        <TextField
          label="Confirm new password"
          type="password"
          autoComplete="new-password"
          isRequired
          value={confirm}
          onChange={setConfirm}
          isInvalid={mismatch}
          errorMessage="The passwords don't match."
        />
        <FormError error={change.error} />
        <div>
          <Button type="submit" loading={change.isPending}>
            Change password
          </Button>
        </div>
      </Form>
    </Panel>
  );
}
