"use client";

import { CaretDownIcon, CheckIcon, MagnifyingGlassIcon, XIcon } from "@phosphor-icons/react";
import type { ReactNode } from "react";
import {
  Button as AriaButton,
  Checkbox as AriaCheckbox,
  FieldError,
  Group,
  Input,
  Label,
  ListBox,
  ListBoxItem,
  NumberField as AriaNumberField,
  Popover,
  SearchField as AriaSearchField,
  Select as AriaSelect,
  SelectValue,
  Switch as AriaSwitch,
  Text,
  TextArea,
  TextField as AriaTextField,
  type Key,
  type NumberFieldProps,
  type TextFieldProps as AriaTextFieldProps,
} from "react-aria-components";

import { cx, focusRing } from "./cx";

export const inputClass = cx(
  "h-9 w-full min-w-0 rounded-[var(--radius-control)] border border-line-strong bg-surface px-2.5 text-body text-ink",
  "placeholder:text-ink-subtle outline-none",
  "data-[focused]:outline-2 data-[focused]:outline-offset-1 data-[focused]:outline-accent",
  "data-[invalid]:border-sev-critical data-[disabled]:opacity-50",
);

export const labelClass = "text-meta font-medium text-ink-muted";

function Help({ description }: { description?: ReactNode }) {
  if (!description) return null;
  return (
    <Text slot="description" className="text-meta text-ink-subtle">
      {description}
    </Text>
  );
}

function Errors({ message }: { message?: string }) {
  return <FieldError className="text-meta text-sev-critical">{message}</FieldError>;
}

interface TextFieldProps extends Omit<AriaTextFieldProps, "className"> {
  label: string;
  description?: ReactNode;
  placeholder?: string;
  multiline?: boolean;
  mono?: boolean;
  errorMessage?: string;
  className?: string;
}

export function TextField({
  label,
  description,
  placeholder,
  multiline,
  mono,
  errorMessage,
  className,
  ...props
}: TextFieldProps) {
  return (
    <AriaTextField {...props} className={cx("flex flex-col gap-1", className)}>
      <Label className={labelClass}>{label}</Label>
      {multiline ? (
        <TextArea
          placeholder={placeholder}
          className={cx(inputClass, "h-auto min-h-20 py-2", mono && "font-mono text-dense")}
        />
      ) : (
        <Input
          placeholder={placeholder}
          className={cx(inputClass, mono && "font-mono text-dense")}
        />
      )}
      <Help description={description} />
      <Errors message={errorMessage} />
    </AriaTextField>
  );
}

export function SearchField({
  label,
  placeholder,
  value,
  onChange,
  className,
}: {
  label: string;
  placeholder?: string;
  value: string;
  onChange: (value: string) => void;
  className?: string;
}) {
  return (
    <AriaSearchField
      aria-label={label}
      value={value}
      onChange={onChange}
      className={cx("group relative flex items-center", className)}
    >
      <MagnifyingGlassIcon
        size={14}
        aria-hidden
        className="pointer-events-none absolute left-2.5 text-ink-subtle"
      />
      <Input
        placeholder={placeholder}
        className={cx(
          inputClass,
          "h-8 pr-8 pl-8 font-mono text-dense [&::-webkit-search-cancel-button]:hidden",
        )}
      />
      <AriaButton
        aria-label="Clear"
        className={cx(
          "absolute right-1 inline-flex size-6 items-center justify-center rounded-[3px] text-ink-subtle group-data-[empty]:hidden data-[hovered]:text-ink",
          focusRing,
        )}
      >
        <XIcon size={12} aria-hidden />
      </AriaButton>
    </AriaSearchField>
  );
}

interface NumberInputProps extends Omit<NumberFieldProps, "className"> {
  label: string;
  description?: ReactNode;
  unit?: string;
  className?: string;
}

export function NumberField({ label, description, unit, className, ...props }: NumberInputProps) {
  return (
    <AriaNumberField {...props} className={cx("flex flex-col gap-1", className)}>
      <Label className={labelClass}>{label}</Label>
      <Group className="flex items-center gap-2">
        <Input className={cx(inputClass, "font-mono tabular-nums")} />
        {unit && <span className="shrink-0 text-meta text-ink-subtle">{unit}</span>}
      </Group>
      <Help description={description} />
      <Errors />
    </AriaNumberField>
  );
}

export interface Option {
  id: string;
  label: string;
  description?: string;
}

export function Select({
  label,
  options,
  value,
  onChange,
  description,
  placeholder = "Choose…",
  isDisabled,
  hideLabel,
  className,
}: {
  label: string;
  options: Option[];
  value: string | null;
  onChange: (value: string) => void;
  description?: ReactNode;
  placeholder?: string;
  isDisabled?: boolean;
  hideLabel?: boolean;
  className?: string;
}) {
  return (
    <AriaSelect
      aria-label={hideLabel ? label : undefined}
      selectedKey={value}
      onSelectionChange={(key: Key | null) => key !== null && onChange(String(key))}
      placeholder={placeholder}
      isDisabled={isDisabled}
      className={cx("flex flex-col gap-1", className)}
    >
      {!hideLabel && <Label className={labelClass}>{label}</Label>}
      <AriaButton
        className={cx(
          inputClass,
          "flex items-center justify-between gap-2 text-left data-[focus-visible]:outline-2 data-[focus-visible]:outline-accent",
        )}
      >
        {/* Only the label: the option's description belongs in the list, not the closed field. */}
        <SelectValue className="truncate data-[placeholder]:text-ink-subtle">
          {({ selectedText, isPlaceholder, defaultChildren }) =>
            isPlaceholder ? defaultChildren : selectedText
          }
        </SelectValue>
        <CaretDownIcon size={14} aria-hidden className="shrink-0 text-ink-subtle" />
      </AriaButton>
      <Help description={description} />
      <Popover className="min-w-[var(--trigger-width)] rounded-[var(--radius-panel)] border border-line bg-surface-raised p-1 shadow-[var(--shadow-float)]">
        <ListBox items={options} className="max-h-72 overflow-auto outline-none">
          {(option) => (
            <ListBoxItem
              id={option.id}
              textValue={option.label}
              className="group flex cursor-default items-start gap-2 rounded-[3px] px-2 py-1.5 text-body outline-none data-[focused]:bg-surface-sunken data-[selected]:text-ink"
            >
              <CheckIcon
                size={14}
                aria-hidden
                className="mt-0.5 shrink-0 text-accent opacity-0 group-data-[selected]:opacity-100"
              />
              <span className="flex flex-col">
                <span>{option.label}</span>
                {option.description && (
                  <span className="text-meta text-ink-subtle">{option.description}</span>
                )}
              </span>
            </ListBoxItem>
          )}
        </ListBox>
      </Popover>
    </AriaSelect>
  );
}

export function Switch({
  children,
  isSelected,
  onChange,
  isDisabled,
}: {
  children: ReactNode;
  isSelected: boolean;
  onChange: (value: boolean) => void;
  isDisabled?: boolean;
}) {
  return (
    <AriaSwitch
      isSelected={isSelected}
      onChange={onChange}
      isDisabled={isDisabled}
      className="group inline-flex cursor-default items-center gap-2 text-body data-[disabled]:opacity-50"
    >
      <span
        className={cx(
          "relative inline-flex h-5 w-9 shrink-0 rounded-full border border-line-strong bg-surface-sunken transition-colors duration-100",
          "group-data-[selected]:border-accent group-data-[selected]:bg-accent",
          "group-data-[focus-visible]:outline-2 group-data-[focus-visible]:outline-offset-2 group-data-[focus-visible]:outline-accent",
        )}
      >
        <span className="absolute top-0.5 left-0.5 size-3.5 rounded-full bg-ink-muted transition-transform duration-100 group-data-[selected]:translate-x-4 group-data-[selected]:bg-accent-ink" />
      </span>
      {children}
    </AriaSwitch>
  );
}

export function Checkbox({
  children,
  isSelected,
  onChange,
  "aria-label": ariaLabel,
}: {
  children?: ReactNode;
  isSelected: boolean;
  onChange: (value: boolean) => void;
  "aria-label"?: string;
}) {
  return (
    <AriaCheckbox
      isSelected={isSelected}
      onChange={onChange}
      aria-label={ariaLabel}
      className="group inline-flex cursor-default items-center gap-2 text-body"
    >
      <span
        className={cx(
          "inline-flex size-4 items-center justify-center rounded-[3px] border border-line-strong bg-surface",
          "group-data-[selected]:border-accent group-data-[selected]:bg-accent group-data-[selected]:text-accent-ink",
          "group-data-[focus-visible]:outline-2 group-data-[focus-visible]:outline-offset-2 group-data-[focus-visible]:outline-accent",
        )}
      >
        <CheckIcon
          size={11}
          weight="bold"
          aria-hidden
          className="hidden group-data-[selected]:block"
        />
      </span>
      {children}
    </AriaCheckbox>
  );
}
