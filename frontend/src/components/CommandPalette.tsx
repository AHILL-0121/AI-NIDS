"use client";

import {
  MagnifyingGlassIcon,
  MoonIcon,
  PlayIcon,
  SignOutIcon,
  StopIcon,
  SunIcon,
} from "@phosphor-icons/react";
import { useRouter } from "next/navigation";
import { useEffect, useMemo, useState, type ReactNode } from "react";
import {
  Autocomplete,
  Dialog,
  Header,
  Input,
  Menu,
  MenuItem,
  MenuSection,
  Modal,
  ModalOverlay,
  SearchField,
  useFilter,
} from "react-aria-components";

import { writePreference } from "@/design/theme";

import { NAV } from "./nav";

export interface PaletteAction {
  id: string;
  label: string;
  icon?: ReactNode;
  keywords?: string;
  run: () => void;
}

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;
const IPV6 = /^[0-9a-f:]+:[0-9a-f:]*$/i;

/** Ctrl/⌘+K: jump to a page, run an action, or look up an IP or alert id. */
export function CommandPalette({
  isOpen,
  onOpenChange,
  sensorRunning,
  onStartSensor,
  onStopSensor,
  onSignOut,
}: {
  isOpen: boolean;
  onOpenChange: (open: boolean) => void;
  sensorRunning: boolean;
  onStartSensor: () => void;
  onStopSensor: () => void;
  onSignOut: () => void;
}) {
  const router = useRouter();
  const { contains } = useFilter({ sensitivity: "base" });
  const [query, setQuery] = useState("");

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        onOpenChange(!isOpen);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [isOpen, onOpenChange]);

  const close = () => {
    onOpenChange(false);
    setQuery("");
  };

  const lookups = useMemo<PaletteAction[]>(() => {
    const q = query.trim();
    if (!q) return [];
    const found: PaletteAction[] = [];
    if (IPV4.test(q) || IPV6.test(q)) {
      found.push({
        id: "host",
        label: `Open host ${q}`,
        run: () => router.push(`/hosts/?ip=${encodeURIComponent(q)}`),
      });
    }
    if (/^[0-9a-f]{8,}$/i.test(q)) {
      found.push({
        id: "alert",
        label: `Open alert ${q}`,
        run: () => router.push(`/alerts/?id=${encodeURIComponent(q)}`),
      });
    }
    return found;
  }, [query, router]);

  const actions: PaletteAction[] = [
    sensorRunning
      ? {
          id: "stop",
          label: "Stop capture",
          icon: <StopIcon size={16} aria-hidden />,
          run: onStopSensor,
        }
      : {
          id: "start",
          label: "Start capture…",
          icon: <PlayIcon size={16} aria-hidden />,
          run: onStartSensor,
        },
    {
      id: "light",
      label: "Switch theme: Light",
      icon: <SunIcon size={16} aria-hidden />,
      keywords: "appearance",
      run: () => writePreference("light"),
    },
    {
      id: "dark",
      label: "Switch theme: Dark",
      icon: <MoonIcon size={16} aria-hidden />,
      keywords: "appearance",
      run: () => writePreference("dark"),
    },
    {
      id: "system",
      label: "Switch theme: System",
      keywords: "appearance",
      run: () => writePreference("system"),
    },
    {
      id: "signout",
      label: "Sign out",
      icon: <SignOutIcon size={16} aria-hidden />,
      run: onSignOut,
    },
  ];

  const pages: PaletteAction[] = NAV.map((item) => {
    const IconComponent = item.icon;
    return {
      id: `go:${item.href}`,
      label: `Go to ${item.label}`,
      keywords: item.keywords,
      icon: <IconComponent size={16} aria-hidden />,
      run: () => router.push(item.href),
    };
  });

  const byId = new Map([...lookups, ...pages, ...actions].map((a) => [a.id, a]));
  const itemClass =
    "flex cursor-default items-center gap-2.5 rounded-[3px] px-2.5 py-2 text-body text-ink outline-none data-[focused]:bg-accent-wash";
  const sectionHeader = "px-2.5 pt-2 pb-1 text-label font-medium text-ink-subtle uppercase";

  const renderItems = (items: PaletteAction[]) =>
    items.map((action) => (
      <MenuItem
        key={action.id}
        id={action.id}
        textValue={`${action.label} ${action.keywords ?? ""}`}
        className={itemClass}
      >
        <span className="text-ink-muted">{action.icon}</span>
        {action.label}
      </MenuItem>
    ));

  return (
    <ModalOverlay
      isOpen={isOpen}
      onOpenChange={(open) => (open ? onOpenChange(true) : close())}
      isDismissable
      className="fixed inset-0 z-50 flex items-start justify-center bg-[rgb(20_22_26/0.25)] px-4 pt-[14vh]"
    >
      <Modal className="w-full max-w-xl rounded-[var(--radius-panel)] border border-line bg-surface-raised shadow-[var(--shadow-float)] outline-none">
        <Dialog aria-label="Command palette" className="outline-none">
          <Autocomplete
            inputValue={query}
            onInputChange={setQuery}
            // Look-ups ("Open host …") always match what was typed.
            filter={(text, input) => text.startsWith("Open ") || contains(text, input)}
          >
            <SearchField
              aria-label="Search commands"
              autoFocus
              className="flex items-center gap-2 border-b border-line px-3"
            >
              <MagnifyingGlassIcon size={16} aria-hidden className="text-ink-subtle" />
              <Input
                placeholder="Search pages and actions, or type an IP or alert id…"
                className="h-12 flex-1 bg-transparent text-body outline-none placeholder:text-ink-subtle [&::-webkit-search-cancel-button]:hidden"
              />
              <kbd className="rounded-[3px] border border-line px-1.5 font-mono text-meta text-ink-subtle">
                Esc
              </kbd>
            </SearchField>
            <Menu
              aria-label="Commands"
              onAction={(key) => {
                const action = byId.get(String(key));
                close();
                action?.run();
              }}
              renderEmptyState={() => (
                <p className="px-3 py-6 text-center text-meta text-ink-subtle">No matches.</p>
              )}
              className="max-h-[50vh] overflow-y-auto p-1.5 outline-none"
            >
              {lookups.length > 0 && (
                <MenuSection>
                  <Header className={sectionHeader}>Look up</Header>
                  {renderItems(lookups)}
                </MenuSection>
              )}
              <MenuSection>
                <Header className={sectionHeader}>Pages</Header>
                {renderItems(pages)}
              </MenuSection>
              <MenuSection>
                <Header className={sectionHeader}>Actions</Header>
                {renderItems(actions)}
              </MenuSection>
            </Menu>
          </Autocomplete>
        </Dialog>
      </Modal>
    </ModalOverlay>
  );
}
