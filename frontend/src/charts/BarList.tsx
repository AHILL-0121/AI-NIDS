import type { ReactNode } from "react";

import { cx } from "@/components/cx";

/** Ranked horizontal bars: easier to read than a donut (design §5.6). Plain HTML, so it's
 * accessible as a list and needs no chart runtime. */
export function BarList({
  items,
  format,
  label,
}: {
  items: { key: string; label: ReactNode; value: number; href?: string }[];
  format: (value: number) => string;
  label: string;
}) {
  const total = items.reduce((sum, item) => sum + item.value, 0) || 1;
  const max = Math.max(...items.map((i) => i.value), 1);
  return (
    <ul aria-label={label} className="flex flex-col gap-1.5">
      {items.map((item) => (
        <li
          key={item.key}
          className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-x-3 text-dense"
        >
          <div className="relative min-w-0">
            <span
              aria-hidden
              className="absolute inset-y-0 left-0 rounded-[2px] bg-accent-wash"
              style={{ width: `${(item.value / max) * 100}%` }}
            />
            <span className="relative block truncate px-1.5 py-0.5">{item.label}</span>
          </div>
          <span className="text-meta text-ink-muted tabular-nums">
            {format(item.value)}{" "}
            <span className="text-ink-subtle">· {Math.round((item.value / total) * 100)}%</span>
          </span>
        </li>
      ))}
    </ul>
  );
}

export type StripLevel = "none" | "low" | "medium" | "high";

/** Per-bucket strip (e.g. alerts per minute). Each cell has a text label for hover and screen readers. */
export function Strip({
  cells,
  label,
}: {
  cells: { key: string; level: StripLevel; title: string }[];
  label: string;
}) {
  const tone: Record<StripLevel, string> = {
    none: "bg-surface-sunken",
    low: "bg-sev-low",
    medium: "bg-sev-medium",
    high: "bg-sev-critical",
  };
  return (
    <ol aria-label={label} className="flex h-6 items-stretch gap-px">
      {cells.map((cell) => (
        <li
          key={cell.key}
          title={cell.title}
          className={cx("min-w-0 flex-1 rounded-[1px]", tone[cell.level])}
        >
          <span className="sr-only">{cell.title}</span>
        </li>
      ))}
    </ol>
  );
}
