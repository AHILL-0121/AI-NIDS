"use client";

import { ToggleButton, ToggleButtonGroup, type Key } from "react-aria-components";

import { cx, focusRing } from "./cx";

/** Multi-select quick filters (e.g. severity: high, critical). None selected means "any". */
export function FilterChips<T extends string>({
  label,
  options,
  value,
  onChange,
}: {
  label: string;
  options: { id: T; label: string }[];
  value: T[];
  onChange: (value: T[]) => void;
}) {
  return (
    <div className="flex items-center gap-2">
      <span className="text-label font-medium text-ink-subtle uppercase">{label}</span>
      <ToggleButtonGroup
        aria-label={label}
        selectionMode="multiple"
        selectedKeys={value}
        onSelectionChange={(keys: Set<Key>) => onChange([...keys].map(String) as T[])}
        className="flex flex-wrap gap-1"
      >
        {options.map((option) => (
          <ToggleButton
            key={option.id}
            id={option.id}
            className={cx(
              "inline-flex h-7 items-center rounded-[var(--radius-control)] border border-line-strong bg-surface px-2 text-meta text-ink-muted transition-colors duration-100",
              "data-[hovered]:text-ink data-[selected]:border-accent data-[selected]:bg-accent-wash data-[selected]:text-ink",
              focusRing,
            )}
          >
            {option.label}
          </ToggleButton>
        ))}
      </ToggleButtonGroup>
    </div>
  );
}
