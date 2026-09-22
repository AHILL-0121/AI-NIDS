"use client";

import { XIcon } from "@phosphor-icons/react";
import type { ReactNode } from "react";
import {
  Dialog,
  Heading,
  Modal,
  ModalOverlay,
  ToggleButton,
  ToggleButtonGroup,
  type Key,
} from "react-aria-components";

import { IconButton } from "./Button";
import { cx, focusRing } from "./cx";

/** Right-hand detail drawer (520 px). Esc and outside-click close it; React Aria traps and restores focus. */
export function Drawer({
  isOpen,
  onClose,
  title,
  subtitle,
  children,
  footer,
}: {
  isOpen: boolean;
  onClose: () => void;
  title: ReactNode;
  subtitle?: ReactNode;
  children: ReactNode;
  footer?: ReactNode;
}) {
  return (
    <ModalOverlay
      isOpen={isOpen}
      onOpenChange={(open) => !open && onClose()}
      isDismissable
      className="fixed inset-0 z-40 bg-[rgb(20_22_26/0.2)] data-[entering]:animate-[fade-in_180ms_ease-out]"
    >
      <Modal className="fixed inset-y-0 right-0 flex w-full max-w-[520px] border-l border-line bg-surface-raised shadow-[var(--shadow-float)] outline-none data-[entering]:animate-[slide-in_180ms_ease-out]">
        <Dialog className="flex h-full w-full flex-col outline-none">
          <header className="flex items-start justify-between gap-3 border-b border-line px-5 py-4">
            <div className="flex min-w-0 flex-col gap-1">
              <Heading slot="title" className="text-section font-semibold">
                {title}
              </Heading>
              {subtitle && <div className="text-meta text-ink-muted">{subtitle}</div>}
            </div>
            <IconButton label="Close" icon={<XIcon size={16} aria-hidden />} onPress={onClose} />
          </header>
          <div className="flex-1 overflow-y-auto px-5 py-4">{children}</div>
          {footer && (
            <footer className="flex flex-wrap gap-2 border-t border-line px-5 py-3">
              {footer}
            </footer>
          )}
        </Dialog>
      </Modal>
    </ModalOverlay>
  );
}

/** Centred modal dialog for confirmations and small forms. */
export function DialogBox({
  isOpen,
  onClose,
  title,
  children,
  width = "max-w-md",
}: {
  isOpen: boolean;
  onClose: () => void;
  title: string;
  children: ReactNode;
  width?: string;
}) {
  return (
    <ModalOverlay
      isOpen={isOpen}
      onOpenChange={(open) => !open && onClose()}
      isDismissable
      className="fixed inset-0 z-50 flex items-start justify-center bg-[rgb(20_22_26/0.25)] px-4 pt-[12vh]"
    >
      <Modal
        className={cx(
          "w-full rounded-[var(--radius-panel)] border border-line bg-surface-raised shadow-[var(--shadow-float)] outline-none",
          width,
        )}
      >
        <Dialog className="flex flex-col gap-4 p-5 outline-none">
          <Heading slot="title" className="text-section font-semibold">
            {title}
          </Heading>
          {children}
        </Dialog>
      </Modal>
    </ModalOverlay>
  );
}

export function SegmentedControl<T extends string>({
  label,
  options,
  value,
  onChange,
}: {
  label: string;
  options: { id: T; label: string }[];
  value: T;
  onChange: (value: T) => void;
}) {
  return (
    <ToggleButtonGroup
      aria-label={label}
      selectionMode="single"
      disallowEmptySelection
      selectedKeys={[value]}
      onSelectionChange={(keys: Set<Key>) => {
        const [next] = keys;
        if (next !== undefined) onChange(String(next) as T);
      }}
      className="inline-flex rounded-[var(--radius-control)] border border-line-strong bg-surface p-0.5"
    >
      {options.map((option) => (
        <ToggleButton
          key={option.id}
          id={option.id}
          className={cx(
            "inline-flex h-6 items-center rounded-[3px] px-2 text-meta font-medium text-ink-muted transition-colors duration-100",
            "data-[hovered]:text-ink data-[selected]:bg-accent-wash data-[selected]:text-ink",
            focusRing,
          )}
        >
          {option.label}
        </ToggleButton>
      ))}
    </ToggleButtonGroup>
  );
}
