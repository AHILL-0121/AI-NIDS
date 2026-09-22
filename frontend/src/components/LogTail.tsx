"use client";

import { useEffect, useRef } from "react";

import { cx } from "./cx";

const LEVEL = /\b(ERROR|CRITICAL|WARNING|INFO|DEBUG)\b/;

/** Timestamped log lines with a level dot; sticks to the bottom while new lines arrive. */
export function LogTail({ lines, className }: { lines: string[]; className?: string }) {
  const box = useRef<HTMLPreElement>(null);
  useEffect(() => {
    const el = box.current;
    if (el && el.scrollHeight - el.scrollTop - el.clientHeight < 80) el.scrollTop = el.scrollHeight;
  }, [lines]);
  return (
    <pre
      ref={box}
      tabIndex={0}
      aria-label="Log output"
      className={cx(
        "max-h-[420px] overflow-auto rounded-[var(--radius-control)] bg-surface-sunken p-3 font-mono text-meta leading-5 text-ink-muted focus-visible:outline-2 focus-visible:outline-accent",
        className,
      )}
    >
      {lines.length === 0 ? (
        <span className="text-ink-subtle">No log lines yet.</span>
      ) : (
        lines.map((line, i) => {
          const level = LEVEL.exec(line)?.[1];
          const tone =
            level === "ERROR" || level === "CRITICAL"
              ? "text-sev-critical"
              : level === "WARNING"
                ? "text-sev-medium"
                : undefined;
          return (
            <div key={i} className={cx("break-all whitespace-pre-wrap", tone)}>
              {line}
            </div>
          );
        })
      )}
    </pre>
  );
}
