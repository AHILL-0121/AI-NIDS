import {
  CheckCircleIcon,
  CircleIcon,
  DiamondIcon,
  InfoIcon,
  TriangleIcon,
  WarningCircleIcon,
  type Icon,
} from "@phosphor-icons/react";

import type { AlertStatus, Severity } from "@/lib/queries";
import { protocolName } from "@/lib/format";

import { cx } from "./cx";

/** Severity is never colour alone: each level has its own glyph and label (design §5.1 #6). */
const SEVERITY: Record<
  Severity,
  { label: string; short: string; icon: Icon; text: string; wash: string }
> = {
  critical: {
    label: "Critical",
    short: "CRIT",
    icon: DiamondIcon,
    text: "text-sev-critical",
    wash: "bg-[var(--sev-critical-wash)]",
  },
  high: {
    label: "High",
    short: "HIGH",
    icon: TriangleIcon,
    text: "text-sev-high",
    wash: "bg-[var(--sev-high-wash)]",
  },
  medium: {
    label: "Medium",
    short: "MED",
    icon: CircleIcon,
    text: "text-sev-medium",
    wash: "bg-[var(--sev-medium-wash)]",
  },
  low: {
    label: "Low",
    short: "LOW",
    icon: InfoIcon,
    text: "text-sev-low",
    wash: "bg-[var(--sev-low-wash)]",
  },
  info: {
    label: "Info",
    short: "INFO",
    icon: InfoIcon,
    text: "text-sev-info",
    wash: "bg-surface-sunken",
  },
};

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export function severityLabel(severity: Severity): string {
  return SEVERITY[severity].label;
}

export function SeverityChip({
  severity,
  compact = false,
}: {
  severity: Severity;
  compact?: boolean;
}) {
  const s = SEVERITY[severity];
  const IconComponent = s.icon;
  return (
    <span
      className={cx(
        "inline-flex items-center gap-1 rounded-[var(--radius-control)] px-1.5 py-px text-meta font-medium uppercase",
        s.text,
        s.wash,
      )}
    >
      <IconComponent size={12} weight="fill" aria-hidden />
      {compact ? s.short : s.label}
    </span>
  );
}

const STATUS: Record<AlertStatus, { label: string; className: string }> = {
  new: { label: "New", className: "border-accent text-accent" },
  acknowledged: { label: "Acknowledged", className: "border-line-strong text-ink" },
  resolved: { label: "Resolved", className: "border-line text-ink-subtle" },
  false_positive: {
    label: "False positive",
    className: "border-line text-ink-subtle line-through decoration-1",
  },
};

export const ALERT_STATUSES: AlertStatus[] = ["new", "acknowledged", "resolved", "false_positive"];

export function statusLabel(status: AlertStatus): string {
  return STATUS[status].label;
}

export function StatusBadge({ status }: { status: AlertStatus }) {
  const s = STATUS[status];
  return (
    <span
      className={cx(
        "inline-flex rounded-[var(--radius-control)] border px-1.5 py-px text-meta",
        s.className,
      )}
    >
      {s.label}
    </span>
  );
}

export function Tag({ children, mono = true }: { children: React.ReactNode; mono?: boolean }) {
  return (
    <span
      className={cx(
        "inline-flex items-center rounded-[var(--radius-control)] border border-line bg-surface-sunken px-1.5 py-px text-meta text-ink-muted",
        mono && "font-mono",
      )}
    >
      {children}
    </span>
  );
}

export function ProtocolTag({ protocol }: { protocol: number | null | undefined }) {
  return <Tag>{protocolName(protocol)}</Tag>;
}

export function MitreTag({ technique }: { technique: string | null | undefined }) {
  if (!technique) return null;
  return (
    <a
      href={`https://attack.mitre.org/techniques/${technique.replace(".", "/")}/`}
      target="_blank"
      rel="noreferrer noopener"
      className="inline-flex items-center rounded-[var(--radius-control)] border border-line bg-surface-sunken px-1.5 py-px font-mono text-meta text-accent hover:underline"
    >
      MITRE {technique}
    </a>
  );
}

export type Health = "ok" | "warning" | "error" | "idle";

const HEALTH: Record<Health, { icon: Icon; className: string }> = {
  ok: { icon: CheckCircleIcon, className: "text-ok" },
  warning: { icon: WarningCircleIcon, className: "text-sev-medium" },
  error: { icon: WarningCircleIcon, className: "text-sev-critical" },
  idle: { icon: CircleIcon, className: "text-ink-subtle" },
};

export function HealthIcon({ health, size = 16 }: { health: Health; size?: number }) {
  const h = HEALTH[health];
  const IconComponent = h.icon;
  return (
    <IconComponent size={size} weight="fill" aria-hidden className={cx("shrink-0", h.className)} />
  );
}

/** A small status dot. `pulse` animates it (turned off under reduced motion by globals.css). */
export function Dot({
  tone,
  pulse = false,
}: {
  tone: "ok" | "warn" | "off" | "bad";
  pulse?: boolean;
}) {
  const colour = {
    ok: "bg-ok",
    warn: "bg-sev-medium",
    off: "bg-ink-subtle",
    bad: "bg-sev-critical",
  }[tone];
  return (
    <span className="relative inline-flex size-2 shrink-0" aria-hidden>
      {pulse && (
        <span
          className={cx(
            "absolute inset-0 animate-ping rounded-full opacity-60 [animation-duration:2s]",
            colour,
          )}
        />
      )}
      <span className={cx("relative inline-flex size-2 rounded-full", colour)} />
    </span>
  );
}
