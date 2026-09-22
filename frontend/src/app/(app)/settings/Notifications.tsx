"use client";

import { useState, useSyncExternalStore, type ReactNode } from "react";
import { Form } from "react-aria-components";

import { RelativeTime } from "@/components/AlertBits";
import { SEVERITIES, severityLabel } from "@/components/Badges";
import { Button } from "@/components/Button";
import { NumberField, Select, Switch, TextField } from "@/components/Field";
import { Panel } from "@/components/Panel";
import { FormError, QueryView } from "@/components/States";
import { useToast } from "@/components/Toast";
import type { Schemas } from "@/lib/api/client";
import {
  SERVER_SNAPSHOT,
  requestPermission,
  savePrefs,
  snapshot,
  subscribe,
  type DesktopPrefs,
  type Permission,
} from "@/lib/desktop";
import {
  useNotifications,
  useTestNotification,
  useUpdateNotifications,
  type NotificationSettings,
  type Severity,
} from "@/lib/queries";

const SEVERITY_OPTIONS = SEVERITIES.filter((s) => s !== "info").map((s) => ({
  id: s,
  label: s === "critical" ? "Critical only" : `${severityLabel(s)} and above`,
}));

function Group({
  title,
  children,
  aside,
}: {
  title: string;
  children: ReactNode;
  aside?: ReactNode;
}) {
  return (
    <fieldset className="flex flex-col gap-3 border-t border-line px-4 pt-3 pb-4 first:border-t-0">
      <legend className="sr-only">{title}</legend>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 aria-hidden className="text-label font-medium text-ink-subtle uppercase">
          {title}
        </h3>
        {aside}
      </div>
      <div className="grid gap-x-6 gap-y-4 sm:grid-cols-2 xl:grid-cols-3">{children}</div>
    </fieldset>
  );
}

export function NotificationsPanel() {
  const notifications = useNotifications();
  return (
    <Panel title="Notifications" id="notifications" bodyClassName="flex flex-col">
      <DesktopGroup />
      <QueryView query={notifications}>
        {(data) => <ServerForm key={JSON.stringify(data.values)} data={data} />}
      </QueryView>
    </Panel>
  );
}

// --- this browser ----------------------------------------------------------------------------

function DesktopGroup() {
  const state = JSON.parse(
    useSyncExternalStore(subscribe, snapshot, () => SERVER_SNAPSHOT),
  ) as DesktopPrefs & { permission: Permission };
  const { permission, ...prefs } = state;

  const enable = async (on: boolean) => {
    if (on && permission === "default" && (await requestPermission()) !== "granted") return;
    savePrefs({ ...prefs, enabled: on });
  };

  const note =
    permission === "unsupported"
      ? "This browser can't show desktop notifications."
      : permission === "denied"
        ? "Notifications are blocked for this site. Allow them in the browser's site settings."
        : "Shown while this tab is in the background. Stored in this browser only.";
  return (
    <Group title="Desktop (this browser)">
      <div className="flex flex-col gap-1">
        <Switch
          isSelected={prefs.enabled && permission === "granted"}
          isDisabled={permission === "unsupported" || permission === "denied"}
          onChange={(on) => void enable(on)}
        >
          Show desktop notifications
        </Switch>
        <span className="text-meta text-ink-subtle">{note}</span>
      </div>
      <Select
        label="Notify for"
        options={SEVERITY_OPTIONS}
        value={prefs.minSeverity}
        onChange={(v) => savePrefs({ ...prefs, minSeverity: v as Severity })}
        isDisabled={!prefs.enabled}
      />
    </Group>
  );
}

// --- email, webhook, delivery (stored on the server) ------------------------------------------

function ChannelStatus({ status }: { status: Schemas["ChannelStatus"] | undefined }) {
  if (!status?.last_ok_at && !status?.last_error_at) {
    return <span className="text-meta text-ink-subtle">Nothing sent yet</span>;
  }
  const failedLast = (status.last_error_at ?? 0) > (status.last_ok_at ?? 0);
  return failedLast ? (
    <span className="text-meta text-sev-critical" role="status">
      Last attempt failed <RelativeTime epoch={status.last_error_at!} />: {status.last_error}
    </span>
  ) : (
    <span className="text-meta text-ok" role="status">
      Last sent <RelativeTime epoch={status.last_ok_at!} />
    </span>
  );
}

function ServerForm({ data }: { data: Schemas["NotificationSettingsOut"] }) {
  const values = data.values;
  const [draft, setDraft] = useState<NotificationSettings>(values);
  const [recipients, setRecipients] = useState(values.email_to.join(", "));
  const [password, setPassword] = useState("");
  const [secret, setSecret] = useState("");
  const update = useUpdateNotifications();
  const test = useTestNotification();
  const notify = useToast();

  const set = <K extends keyof NotificationSettings>(key: K, value: NotificationSettings[K]) =>
    setDraft({ ...draft, [key]: value });

  const changes: Partial<NotificationSettings> = {};
  for (const key of Object.keys(draft) as (keyof NotificationSettings)[]) {
    if (key === "email_to" || key === "smtp_password" || key === "webhook_secret") continue;
    if (draft[key] !== values[key]) Object.assign(changes, { [key]: draft[key] });
  }
  const to = recipients
    .split(/[\s,;]+/)
    .map((r) => r.trim())
    .filter(Boolean);
  if (to.join() !== values.email_to.join()) changes.email_to = to;
  if (password) changes.smtp_password = password;
  if (secret) changes.webhook_secret = secret;
  const dirty = Object.keys(changes).length > 0;

  const sendTest = (channel: "email" | "webhook") =>
    test.mutate(channel, {
      onSuccess: (result) => notify(result.message, { tone: "ok" }),
    });

  const testButton = (channel: "email" | "webhook") => (
    <div className="flex flex-wrap items-center gap-3">
      <ChannelStatus status={data.status[channel]} />
      <Button
        size="dense"
        isDisabled={dirty}
        loading={test.isPending && test.variables === channel}
        onPress={() => sendTest(channel)}
      >
        Send test
      </Button>
    </div>
  );

  const clearable = (isSet: boolean, key: "smtp_password" | "webhook_secret", label: string) =>
    isSet ? (
      <span className="inline-flex flex-wrap items-center gap-1">
        Saved. Leave blank to keep it.
        <Button
          size="dense"
          variant="ghost"
          onPress={() =>
            update.mutate(
              { [key]: "" },
              { onSuccess: () => notify(`${label} removed.`, { tone: "ok" }) },
            )
          }
        >
          Remove
        </Button>
      </span>
    ) : (
      "Optional."
    );

  return (
    <Form
      onSubmit={(event) => {
        event.preventDefault();
        update.mutate(changes, {
          onSuccess: () => {
            setPassword("");
            setSecret("");
            notify("Notification settings saved.", { tone: "ok" });
          },
        });
      }}
    >
      <Group title="Email" aside={testButton("email")}>
        <Switch isSelected={draft.email_enabled} onChange={(v) => set("email_enabled", v)}>
          Send email alerts
        </Switch>
        <Select
          label="Notify for"
          options={SEVERITY_OPTIONS}
          value={draft.email_min_severity}
          onChange={(v) => set("email_min_severity", v as Severity)}
        />
        <TextField
          label="Recipients"
          description="Up to 10, separated by commas."
          placeholder="you@example.com"
          value={recipients}
          onChange={setRecipients}
        />
        <TextField
          label="SMTP server"
          mono
          placeholder="smtp.example.com"
          value={draft.smtp_host}
          onChange={(v) => set("smtp_host", v.trim())}
        />
        <NumberField
          label="Port"
          minValue={1}
          maxValue={65535}
          formatOptions={{ useGrouping: false }}
          value={draft.smtp_port}
          onChange={(v) => !Number.isNaN(v) && set("smtp_port", v)}
        />
        <Select
          label="Security"
          options={[
            { id: "starttls", label: "STARTTLS", description: "Usually port 587" },
            { id: "tls", label: "TLS", description: "Usually port 465" },
            { id: "none", label: "None", description: "Local relays only; not encrypted" },
          ]}
          value={draft.smtp_security}
          onChange={(v) => set("smtp_security", v as NotificationSettings["smtp_security"])}
        />
        <TextField
          label="Sender address"
          placeholder="nids@example.com"
          value={draft.email_from}
          onChange={(v) => set("email_from", v.trim())}
        />
        <TextField
          label="SMTP username"
          autoComplete="off"
          value={draft.smtp_username}
          onChange={(v) => set("smtp_username", v)}
        />
        <TextField
          label="SMTP password"
          type="password"
          autoComplete="new-password"
          value={password}
          onChange={setPassword}
          description={clearable(data.smtp_password_set, "smtp_password", "Password")}
        />
      </Group>

      <Group title="Webhook" aside={testButton("webhook")}>
        <Switch isSelected={draft.webhook_enabled} onChange={(v) => set("webhook_enabled", v)}>
          Post alerts to a webhook
        </Switch>
        <Select
          label="Notify for"
          options={SEVERITY_OPTIONS}
          value={draft.webhook_min_severity}
          onChange={(v) => set("webhook_min_severity", v as Severity)}
        />
        <Select
          label="Format"
          options={[
            { id: "json", label: "JSON", description: "Full alert data, for your own receiver" },
            { id: "slack", label: "Slack", description: "Incoming-webhook message" },
            { id: "discord", label: "Discord", description: "Channel webhook message" },
          ]}
          value={draft.webhook_format}
          onChange={(v) => set("webhook_format", v as NotificationSettings["webhook_format"])}
        />
        <TextField
          label="URL"
          mono
          placeholder="https://hooks.example.com/…"
          value={draft.webhook_url}
          onChange={(v) => set("webhook_url", v.trim())}
          className="sm:col-span-2"
        />
        <TextField
          label="Signing secret"
          type="password"
          autoComplete="new-password"
          value={secret}
          onChange={setSecret}
          description={
            <>
              {clearable(data.webhook_secret_set, "webhook_secret", "Secret")} Requests carry an
              HMAC-SHA256 signature in <code className="font-mono">X-NIDS-Signature</code>.
            </>
          }
        />
      </Group>

      <Group title="Delivery">
        <NumberField
          label="Messages per hour, per channel"
          description="Alerts over the limit are counted and mentioned in the next message."
          minValue={1}
          maxValue={600}
          value={draft.max_per_hour}
          onChange={(v) => !Number.isNaN(v) && set("max_per_hour", v)}
        />
        <div className="flex flex-col gap-1">
          <Switch isSelected={draft.include_replays} onChange={(v) => set("include_replays", v)}>
            Also notify for .pcap replays
          </Switch>
          <span className="text-meta text-ink-subtle">
            Off by default: replaying an old capture shouldn’t page anyone.
          </span>
        </div>
        <TextField
          label="Link address in messages"
          mono
          description="Where this dashboard is reached from the recipient’s device."
          value={draft.link_base_url}
          onChange={(v) => set("link_base_url", v.trim())}
        />
        <div className="flex flex-col gap-1">
          <Switch isSelected={draft.digest_enabled} onChange={(v) => set("digest_enabled", v)}>
            Daily digest
          </Switch>
          <span className="text-meta text-ink-subtle">
            A summary of the last 24 hours on every enabled channel.
          </span>
        </div>
        <NumberField
          label="Digest hour"
          unit="h"
          description="Server’s local time, 0–23."
          minValue={0}
          maxValue={23}
          value={draft.digest_hour}
          isDisabled={!draft.digest_enabled}
          onChange={(v) => !Number.isNaN(v) && set("digest_hour", v)}
        />
      </Group>

      <div className="flex flex-wrap items-center gap-3 border-t border-line px-4 py-3">
        <Button type="submit" variant="primary" isDisabled={!dirty} loading={update.isPending}>
          Save notifications
        </Button>
        <Button
          variant="ghost"
          isDisabled={!dirty}
          onPress={() => {
            setDraft(values);
            setRecipients(values.email_to.join(", "));
            setPassword("");
            setSecret("");
          }}
        >
          Discard
        </Button>
        {dirty ? (
          <span className="text-meta text-ink-muted">Save before sending a test.</span>
        ) : (
          <span className="text-meta text-ink-subtle">
            Only alerts raised after a channel is turned on are sent.
          </span>
        )}
        <div className="w-full">
          <FormError error={update.error ?? test.error} />
        </div>
      </div>
    </Form>
  );
}
