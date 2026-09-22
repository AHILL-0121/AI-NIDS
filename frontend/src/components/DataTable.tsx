"use client";

/**
 * Virtualised data table (TanStack Table v9 for the column model, TanStack Virtual for rows).
 * ARIA table semantics on a CSS grid; rows are keyboard-navigable (Up/Down/Home/End, Enter opens).
 */
import {
  createColumnHelper,
  tableFeatures,
  useTable,
  type ColumnDef,
  type RowData,
} from "@tanstack/react-table";
import { useVirtualizer } from "@tanstack/react-virtual";
import { useRef, useState, type KeyboardEvent, type ReactNode } from "react";

import { cx } from "./cx";

export const baseFeatures = tableFeatures({});
export type Columns<T extends RowData> = ColumnDef<typeof baseFeatures, T, unknown>[];

const ROW_HEIGHT = 32;

export function DataTable<T extends RowData>({
  label,
  data,
  columns,
  template,
  rowKey,
  onOpen,
  selectedKey,
  empty,
  height = "min(70vh, 720px)",
  rowTone,
}: {
  label: string;
  data: T[];
  columns: Columns<T>;
  /** CSS grid-template-columns, one track per column. */
  template: string;
  rowKey: (row: T) => string;
  onOpen?: (row: T) => void;
  selectedKey?: string | null;
  empty?: ReactNode;
  height?: string;
  rowTone?: (row: T) => string | undefined;
}) {
  const table = useTable({ features: baseFeatures, columns, data });
  const rows = table.getRowModel().rows;
  const scroller = useRef<HTMLDivElement>(null);
  const [focused, setFocused] = useState(0);

  // TanStack Virtual returns functions that the React compiler can't memoise; that's expected.
  // eslint-disable-next-line react-hooks/incompatible-library
  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scroller.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 12,
  });

  const focusRow = (index: number) => {
    const clamped = Math.max(0, Math.min(rows.length - 1, index));
    setFocused(clamped);
    virtualizer.scrollToIndex(clamped);
    requestAnimationFrame(() => {
      scroller.current?.querySelector<HTMLElement>(`[data-index="${clamped}"]`)?.focus();
    });
  };

  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>, index: number, row: T) => {
    const moves: Record<string, number> = {
      ArrowDown: index + 1,
      ArrowUp: index - 1,
      Home: 0,
      End: rows.length - 1,
      PageDown: index + 15,
      PageUp: index - 15,
    };
    if (event.key in moves) {
      event.preventDefault();
      focusRow(moves[event.key]!);
    } else if ((event.key === "Enter" || event.key === " ") && onOpen) {
      event.preventDefault();
      onOpen(row);
    }
  };

  const gridStyle = { gridTemplateColumns: template };

  return (
    <div
      role="table"
      aria-label={label}
      aria-rowcount={rows.length + 1}
      className="flex min-w-0 flex-col"
    >
      <div className="overflow-x-auto">
        <div className="min-w-[720px]">
          <div role="rowgroup">
            {table.getHeaderGroups().map((group) => (
              <div
                role="row"
                aria-rowindex={1}
                key={group.id}
                style={gridStyle}
                className="grid border-b border-line bg-surface-sunken"
              >
                {group.headers.map((header) => (
                  <div
                    role="columnheader"
                    key={header.id}
                    className="truncate px-3 py-2 text-label font-medium text-ink-subtle uppercase"
                  >
                    {header.isPlaceholder ? null : <table.FlexRender header={header} />}
                  </div>
                ))}
              </div>
            ))}
          </div>
          {rows.length === 0 ? (
            <div role="rowgroup">
              <div role="row">
                <div role="cell">{empty}</div>
              </div>
            </div>
          ) : (
            <div
              ref={scroller}
              role="rowgroup"
              className="overflow-y-auto"
              style={{ maxHeight: height }}
            >
              <div className="relative" style={{ height: virtualizer.getTotalSize() }}>
                {virtualizer.getVirtualItems().map((item) => {
                  const row = rows[item.index]!;
                  const key = rowKey(row.original);
                  const selected = selectedKey === key;
                  return (
                    <div
                      role="row"
                      key={key}
                      data-index={item.index}
                      aria-rowindex={item.index + 2}
                      aria-selected={onOpen ? selected : undefined}
                      tabIndex={item.index === focused ? 0 : -1}
                      onFocus={() => setFocused(item.index)}
                      onClick={() => onOpen?.(row.original)}
                      onKeyDown={(event) => onKeyDown(event, item.index, row.original)}
                      style={{
                        ...gridStyle,
                        height: item.size,
                        transform: `translateY(${item.start}px)`,
                      }}
                      className={cx(
                        "absolute inset-x-0 top-0 grid items-center border-b border-line text-dense outline-none",
                        onOpen && "cursor-pointer hover:bg-surface-sunken",
                        "focus-visible:bg-surface-sunken focus-visible:shadow-[inset_2px_0_0_var(--accent)]",
                        selected && "bg-accent-wash hover:bg-accent-wash",
                        rowTone?.(row.original),
                      )}
                    >
                      {row.getAllCells().map((cell) => (
                        <div role="cell" key={cell.id} className="min-w-0 truncate px-3">
                          <table.FlexRender cell={cell} />
                        </div>
                      ))}
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

/** Previous/next paging for server-side pages. */
export function Pager({
  total,
  limit,
  offset,
  onChange,
}: {
  total: number;
  limit: number;
  offset: number;
  onChange: (offset: number) => void;
}) {
  const from = total === 0 ? 0 : offset + 1;
  const to = Math.min(offset + limit, total);
  return (
    <div className="flex items-center justify-between gap-3 border-t border-line px-3 py-2 text-meta text-ink-subtle">
      <span className="tabular-nums">
        {from.toLocaleString()}–{to.toLocaleString()} of {total.toLocaleString()}
      </span>
      <div className="flex gap-1">
        <button
          type="button"
          disabled={offset === 0}
          onClick={() => onChange(Math.max(0, offset - limit))}
          className="rounded-[var(--radius-control)] border border-line-strong px-2 py-0.5 text-ink disabled:opacity-40"
        >
          Previous
        </button>
        <button
          type="button"
          disabled={to >= total}
          onClick={() => onChange(offset + limit)}
          className="rounded-[var(--radius-control)] border border-line-strong px-2 py-0.5 text-ink disabled:opacity-40"
        >
          Next
        </button>
      </div>
    </div>
  );
}

/** Column helper bound to this table's feature set. */
export function columnHelper<T extends RowData>() {
  return createColumnHelper<typeof baseFeatures, T>();
}
