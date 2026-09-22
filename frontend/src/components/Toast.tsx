"use client";

import { CheckCircleIcon, WarningIcon, XIcon } from "@phosphor-icons/react";
import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";

import { IconButton } from "./Button";
import { cx } from "./cx";

type Tone = "ok" | "error" | "info";

interface Toast {
  id: number;
  tone: Tone;
  message: string;
  action?: { label: string; onAction: () => void };
}

type Notify = (message: string, options?: { tone?: Tone; action?: Toast["action"] }) => void;

const ToastContext = createContext<Notify>(() => {});

/** Toasts sit in a polite live region: announced without stealing focus. */
export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const next = useRef(1);

  const dismiss = useCallback(
    (id: number) => setToasts((all) => all.filter((t) => t.id !== id)),
    [],
  );

  const notify = useCallback<Notify>(
    (message, options) => {
      const id = next.current++;
      setToasts((all) => [
        ...all.slice(-3),
        { id, message, tone: options?.tone ?? "info", action: options?.action },
      ]);
      setTimeout(() => dismiss(id), options?.tone === "error" ? 8000 : 5000);
    },
    [dismiss],
  );

  const value = useMemo(() => notify, [notify]);

  return (
    <ToastContext value={value}>
      {children}
      <div
        role="status"
        aria-live="polite"
        className="pointer-events-none fixed right-4 bottom-4 z-[60] flex w-[min(360px,calc(100vw-2rem))] flex-col gap-2"
      >
        {toasts.map((toast) => (
          <div
            key={toast.id}
            className="pointer-events-auto flex items-start gap-2 rounded-[var(--radius-panel)] border border-line bg-surface-raised px-3 py-2.5 shadow-[var(--shadow-float)]"
          >
            {toast.tone === "error" ? (
              <WarningIcon size={16} aria-hidden className="mt-0.5 shrink-0 text-sev-critical" />
            ) : (
              <CheckCircleIcon
                size={16}
                aria-hidden
                className={cx("mt-0.5 shrink-0", toast.tone === "ok" ? "text-ok" : "text-accent")}
              />
            )}
            <p className="flex-1 text-body">{toast.message}</p>
            {toast.action && (
              <button
                type="button"
                onClick={() => {
                  toast.action?.onAction();
                  dismiss(toast.id);
                }}
                className="shrink-0 text-meta font-medium text-accent hover:underline"
              >
                {toast.action.label}
              </button>
            )}
            <IconButton
              label="Dismiss"
              icon={<XIcon size={12} aria-hidden />}
              onPress={() => dismiss(toast.id)}
              className="-my-1.5 -mr-1.5"
            />
          </div>
        ))}
      </div>
    </ToastContext>
  );
}

export function useToast(): Notify {
  return useContext(ToastContext);
}
