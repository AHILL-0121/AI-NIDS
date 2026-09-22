"use client";

import { CircleNotchIcon } from "@phosphor-icons/react";
import NextLink from "next/link";
import type { ComponentProps, ReactNode } from "react";
import { Button as AriaButton, type ButtonProps as AriaButtonProps } from "react-aria-components";

import { cx, focusRing } from "./cx";

export type Variant = "primary" | "secondary" | "ghost" | "danger";
export type Size = "dense" | "default";

const VARIANTS: Record<Variant, string> = {
  primary:
    "bg-accent text-accent-ink border border-accent data-[hovered]:brightness-110 data-[pressed]:brightness-95",
  secondary:
    "bg-surface text-ink border border-line-strong data-[hovered]:bg-surface-sunken data-[pressed]:bg-surface-sunken",
  ghost:
    "bg-transparent text-ink-muted border border-transparent data-[hovered]:bg-surface-sunken data-[hovered]:text-ink",
  danger:
    "bg-surface text-sev-critical border border-line-strong data-[hovered]:bg-[var(--sev-critical-wash)]",
};

const SIZES: Record<Size, string> = {
  dense: "h-8 px-3 gap-1.5 text-meta",
  default: "h-9 px-3.5 gap-2 text-body",
};

// Square icon-only buttons: no horizontal padding (mixing px-3 and px-0 is order-dependent).
const ICON_SIZES: Record<Size, string> = {
  dense: "size-8",
  default: "size-9",
};

export function buttonClass(
  variant: Variant = "secondary",
  size: Size = "default",
  extra?: string,
  iconOnly = false,
) {
  return cx(
    "relative inline-flex shrink-0 items-center justify-center rounded-[var(--radius-control)] font-medium whitespace-nowrap",
    "transition-[background-color,color,filter] duration-100 ease-out cursor-default",
    "data-[disabled]:opacity-50 aria-disabled:opacity-50",
    focusRing,
    VARIANTS[variant],
    iconOnly ? ICON_SIZES[size] : SIZES[size],
    extra,
  );
}

interface ButtonProps extends Omit<AriaButtonProps, "className" | "children"> {
  variant?: Variant;
  size?: Size;
  icon?: ReactNode;
  loading?: boolean;
  className?: string;
  children?: ReactNode;
}

export function Button({
  variant = "secondary",
  size = "default",
  icon,
  loading = false,
  className,
  children,
  isDisabled,
  ...props
}: ButtonProps) {
  return (
    <AriaButton
      {...props}
      isDisabled={isDisabled || loading}
      isPending={loading}
      className={buttonClass(variant, size, className)}
    >
      {/* Loading keeps the width: the label stays in place, hidden, under the spinner. */}
      <span className={cx("inline-flex items-center gap-[inherit]", loading && "invisible")}>
        {icon}
        {children}
      </span>
      {loading && <CircleNotchIcon size={16} aria-hidden className="absolute animate-spin" />}
    </AriaButton>
  );
}

interface IconButtonProps extends Omit<AriaButtonProps, "className" | "children"> {
  label: string;
  icon: ReactNode;
  size?: Size;
  className?: string;
}

export function IconButton({ label, icon, size = "dense", className, ...props }: IconButtonProps) {
  return (
    <AriaButton
      {...props}
      aria-label={label}
      className={buttonClass("ghost", size, className, true)}
    >
      {icon}
    </AriaButton>
  );
}

export function LinkButton({
  variant = "secondary",
  size = "default",
  className,
  ...props
}: ComponentProps<typeof NextLink> & { variant?: Variant; size?: Size }) {
  return (
    <NextLink {...props} className={buttonClass(variant, size, cx("no-underline", className))} />
  );
}

export function TextLink({ className, ...props }: ComponentProps<typeof NextLink>) {
  return (
    <NextLink
      {...props}
      className={cx(
        "text-accent underline-offset-2 hover:underline focus-visible:outline-2 focus-visible:outline-accent",
        className,
      )}
    />
  );
}
