"use client";

import { ArrowClockwiseIcon, type Icon, WarningIcon } from "@phosphor-icons/react";
import type { ReactNode } from "react";

import { ApiError } from "@/lib/api/client";

import { Button } from "./Button";
import { cx } from "./cx";

/** Every data widget shows one of: skeleton, error, empty or data (audit UI-06). */

export function Skeleton({ className }: { className?: string }) {
  return (
    <span
      aria-hidden
      className={cx("block animate-pulse rounded-[3px] bg-surface-sunken", className)}
    />
  );
}

export function SkeletonRows({ rows = 6 }: { rows?: number }) {
  return (
    <div role="status" aria-label="Loading" className="flex flex-col gap-2 p-4">
      {Array.from({ length: rows }, (_, i) => (
        <Skeleton key={i} className="h-5" />
      ))}
    </div>
  );
}

export function EmptyState({
  icon: IconComponent,
  title,
  children,
  action,
  className,
}: {
  icon?: Icon;
  title: string;
  children?: ReactNode;
  action?: ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cx(
        "flex flex-col items-center justify-center gap-2 px-6 py-10 text-center",
        className,
      )}
    >
      {IconComponent && <IconComponent size={24} aria-hidden className="text-ink-subtle" />}
      <p className="font-medium">{title}</p>
      {children && <div className="max-w-sm text-meta text-ink-muted">{children}</div>}
      {action && <div className="mt-2">{action}</div>}
    </div>
  );
}

export function errorMessage(error: unknown): string {
  if (error instanceof ApiError) return error.message;
  if (error instanceof Error) return error.message;
  return "Something went wrong.";
}

export function ErrorState({
  error,
  onRetry,
  className,
}: {
  error: unknown;
  onRetry?: () => void;
  className?: string;
}) {
  return (
    <div
      role="alert"
      className={cx(
        "flex flex-col items-center justify-center gap-2 px-6 py-10 text-center",
        className,
      )}
    >
      <WarningIcon size={24} aria-hidden className="text-sev-critical" />
      <p className="font-medium">Couldn’t load this.</p>
      <p className="max-w-sm text-meta text-ink-muted">{errorMessage(error)}</p>
      {onRetry && (
        <Button size="dense" onPress={onRetry} icon={<ArrowClockwiseIcon size={14} aria-hidden />}>
          Retry
        </Button>
      )}
    </div>
  );
}

/** Pick the right state for a query result. */
export function QueryView<T>({
  query,
  empty,
  loading,
  children,
}: {
  query: { data: T | undefined; error: unknown; isPending: boolean; refetch: () => unknown };
  empty?: (data: T) => ReactNode | null;
  loading?: ReactNode;
  children: (data: T) => ReactNode;
}) {
  if (query.isPending) return <>{loading ?? <SkeletonRows />}</>;
  if (query.error || query.data === undefined) {
    return <ErrorState error={query.error} onRetry={() => void query.refetch()} />;
  }
  const emptyView = empty?.(query.data);
  if (emptyView) return <>{emptyView}</>;
  return <>{children(query.data)}</>;
}

/** Inline form error, announced. */
export function FormError({ error }: { error: unknown }) {
  if (!error) return null;
  return (
    <p
      role="alert"
      className="rounded-[var(--radius-control)] bg-[var(--sev-critical-wash)] px-3 py-2 text-meta text-sev-critical"
    >
      {errorMessage(error)}
    </p>
  );
}
