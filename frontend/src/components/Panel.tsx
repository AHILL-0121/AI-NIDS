import type { ReactNode } from "react";

import { cx } from "./cx";

export function Panel({
  title,
  actions,
  children,
  className,
  bodyClassName,
  id,
}: {
  title?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
  id?: string;
}) {
  const headingId = id ? `${id}-title` : undefined;
  return (
    <section
      aria-labelledby={title ? headingId : undefined}
      className={cx(
        "flex min-w-0 flex-col rounded-[var(--radius-panel)] border border-line bg-surface",
        className,
      )}
    >
      {(title || actions) && (
        <header className="flex min-h-10 items-center justify-between gap-2 border-b border-line px-4 py-2">
          {title && (
            <h2 id={headingId} className="text-label font-medium text-ink-subtle uppercase">
              {title}
            </h2>
          )}
          {actions && <div className="flex items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className={cx("min-w-0 flex-1", bodyClassName)}>{children}</div>
    </section>
  );
}

export function PageHeader({
  title,
  description,
  actions,
}: {
  title: string;
  description?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <div className="flex flex-wrap items-end justify-between gap-3">
      <div className="flex min-w-0 flex-col gap-0.5">
        <h1 className="text-page font-semibold">{title}</h1>
        {description && <p className="max-w-prose text-ink-muted">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

export function Kpi({
  label,
  value,
  detail,
  tone,
  children,
}: {
  label: string;
  value: ReactNode;
  detail?: ReactNode;
  tone?: "critical" | "ok";
  children?: ReactNode;
}) {
  return (
    <div className="flex min-w-0 flex-col gap-1 px-4 py-3">
      <span className="text-label font-medium text-ink-subtle uppercase">{label}</span>
      <span
        className={cx(
          "truncate text-kpi font-semibold tabular-nums",
          tone === "critical" && "text-sev-critical",
          tone === "ok" && "text-ok",
        )}
      >
        {value}
      </span>
      {detail && <span className="truncate text-meta text-ink-subtle">{detail}</span>}
      {children}
    </div>
  );
}

/** Label/value pairs for detail views. */
export function Facts({
  items,
  columns = 2,
}: {
  items: [string, ReactNode][];
  columns?: 1 | 2 | 3;
}) {
  return (
    <dl
      className={cx(
        "grid gap-x-6 gap-y-3",
        columns === 1 && "grid-cols-1",
        columns === 2 && "grid-cols-1 sm:grid-cols-2",
        columns === 3 && "grid-cols-2 sm:grid-cols-3",
      )}
    >
      {items.map(([term, value]) => (
        <div key={term} className="flex min-w-0 flex-col gap-0.5">
          <dt className="text-label font-medium text-ink-subtle uppercase">{term}</dt>
          <dd className="min-w-0 break-words tabular-nums">{value}</dd>
        </div>
      ))}
    </dl>
  );
}
