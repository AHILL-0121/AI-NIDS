"use client";

import {
  CaretDownIcon,
  CommandIcon,
  KeyIcon,
  PlayIcon,
  SignOutIcon,
  StopIcon,
} from "@phosphor-icons/react";
import NextLink from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useState, type ReactNode } from "react";
import { Button as AriaButton, Menu, MenuItem, MenuTrigger, Popover } from "react-aria-components";

import { RequireAuth, useAuth } from "@/lib/auth";
import { clock } from "@/lib/format";
import { LiveProvider, useConnection } from "@/lib/live";
import { useSensor, useSensorControl } from "@/lib/queries";

import { Dot } from "./Badges";
import { SonarMark } from "./Brand";
import { Button } from "./Button";
import { CommandPalette } from "./CommandPalette";
import { cx, focusRing } from "./cx";
import { NAV, isActive } from "./nav";
import { StartCaptureDialog } from "./StartCapture";
import { SkeletonRows } from "./States";
import { ThemeToggle } from "./ThemeToggle";
import { useToast } from "./Toast";

export function AppShell({ children }: { children: ReactNode }) {
  return (
    <RequireAuth
      fallback={
        <div className="mx-auto max-w-md pt-[20vh]">
          <SkeletonRows rows={3} />
        </div>
      }
    >
      <LiveProvider enabled>
        <Shell>{children}</Shell>
      </LiveProvider>
    </RequireAuth>
  );
}

function Shell({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const { status, logout } = useAuth();
  const sensor = useSensor();
  const { stop } = useSensorControl();
  const notify = useToast();
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [startOpen, setStartOpen] = useState(false);
  const running = sensor.data?.running ?? false;

  const signOut = () => void logout().then(() => router.replace("/login/"));
  const stopCapture = () =>
    stop.mutate(undefined, { onSuccess: () => notify("Capture stopped.", { tone: "ok" }) });

  return (
    <div className="flex min-h-dvh">
      <a
        href="#main"
        className="sr-only z-50 rounded-[var(--radius-control)] bg-accent px-3 py-2 text-accent-ink focus:not-sr-only focus:fixed focus:top-2 focus:left-2"
      >
        Skip to content
      </a>

      <nav
        aria-label="Main"
        className="sticky top-0 hidden h-dvh w-14 shrink-0 flex-col border-r border-line bg-surface md:flex lg:w-52"
      >
        <NextLink
          href="/"
          className="flex h-12 items-center gap-2 border-b border-line px-4"
          aria-label="AI-NIDS home"
        >
          <SonarMark />
          <span className="hidden text-section font-semibold tracking-tight lg:inline">
            AI-NIDS
          </span>
        </NextLink>
        <ul className="flex flex-1 flex-col gap-0.5 p-2">
          {NAV.map((item) => {
            const active = isActive(pathname, item.href);
            const IconComponent = item.icon;
            return (
              <li key={item.href}>
                <NextLink
                  href={item.href}
                  aria-current={active ? "page" : undefined}
                  title={item.label}
                  className={cx(
                    "flex h-9 items-center gap-2.5 rounded-[var(--radius-control)] px-2.5 text-body text-ink-muted transition-colors duration-100",
                    "hover:bg-surface-sunken hover:text-ink focus-visible:outline-2 focus-visible:outline-accent",
                    active && "bg-accent-wash font-medium text-ink hover:bg-accent-wash",
                  )}
                >
                  <IconComponent
                    size={18}
                    weight={active ? "fill" : "regular"}
                    aria-hidden
                    className="shrink-0"
                  />
                  <span className="sr-only lg:not-sr-only">{item.label}</span>
                </NextLink>
              </li>
            );
          })}
        </ul>
      </nav>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 flex h-12 items-center gap-3 border-b border-line bg-bg/95 px-4 backdrop-blur-none md:px-6">
          <NextLink href="/" className="md:hidden" aria-label="AI-NIDS home">
            <SonarMark />
          </NextLink>
          <SensorStatus
            running={running}
            iface={sensor.data?.interface ?? null}
            startedAt={sensor.data?.started_at ?? null}
            onStart={() => setStartOpen(true)}
            onStop={stopCapture}
            stopping={stop.isPending}
          />
          <div className="ml-auto flex items-center gap-2">
            <ConnectionBadge />
            <AriaButton
              onPress={() => setPaletteOpen(true)}
              aria-label="Open command palette (Ctrl+K)"
              className={cx(
                "hidden h-8 items-center gap-2 rounded-[var(--radius-control)] border border-line-strong bg-surface px-2.5 text-meta text-ink-muted data-[hovered]:text-ink sm:inline-flex",
                focusRing,
              )}
            >
              <CommandIcon size={14} aria-hidden />
              <span>Search</span>
              <kbd className="font-mono text-ink-subtle">Ctrl K</kbd>
            </AriaButton>
            <div className="hidden lg:block">
              <ThemeToggle />
            </div>
            <MenuTrigger>
              <AriaButton
                aria-label="Account"
                className={cx(
                  "inline-flex h-8 items-center gap-1 rounded-[var(--radius-control)] px-2 text-meta text-ink-muted data-[hovered]:bg-surface-sunken data-[hovered]:text-ink",
                  focusRing,
                )}
              >
                <span className="max-w-24 truncate">{status?.username ?? "admin"}</span>
                <CaretDownIcon size={12} aria-hidden />
              </AriaButton>
              <Popover
                placement="bottom end"
                className="min-w-44 rounded-[var(--radius-panel)] border border-line bg-surface-raised p-1 shadow-[var(--shadow-float)]"
              >
                <Menu
                  className="outline-none"
                  onAction={(key) =>
                    key === "signout" ? signOut() : router.push("/settings/#password")
                  }
                >
                  <MenuItem
                    id="password"
                    className="flex items-center gap-2 rounded-[3px] px-2.5 py-1.5 outline-none data-[focused]:bg-surface-sunken"
                  >
                    <KeyIcon size={14} aria-hidden /> Change password
                  </MenuItem>
                  <MenuItem
                    id="signout"
                    className="flex items-center gap-2 rounded-[3px] px-2.5 py-1.5 outline-none data-[focused]:bg-surface-sunken"
                  >
                    <SignOutIcon size={14} aria-hidden /> Sign out
                  </MenuItem>
                </Menu>
              </Popover>
            </MenuTrigger>
          </div>
        </header>

        <nav
          aria-label="Main (compact)"
          className="flex gap-1 overflow-x-auto border-b border-line bg-surface px-2 py-1.5 md:hidden"
        >
          {NAV.map((item) => (
            <NextLink
              key={item.href}
              href={item.href}
              aria-current={isActive(pathname, item.href) ? "page" : undefined}
              className="shrink-0 rounded-[var(--radius-control)] px-2.5 py-1 text-meta text-ink-muted aria-[current=page]:bg-accent-wash aria-[current=page]:text-ink"
            >
              {item.label}
            </NextLink>
          ))}
        </nav>

        <main
          id="main"
          className="mx-auto flex w-full max-w-[1600px] min-w-0 flex-1 flex-col gap-4 px-4 py-5 md:px-6"
        >
          {children}
        </main>
      </div>

      <CommandPalette
        isOpen={paletteOpen}
        onOpenChange={setPaletteOpen}
        sensorRunning={running}
        onStartSensor={() => setStartOpen(true)}
        onStopSensor={stopCapture}
        onSignOut={signOut}
      />
      <StartCaptureDialog isOpen={startOpen} onClose={() => setStartOpen(false)} />
    </div>
  );
}

function useNow(active: boolean): number {
  const [now, setNow] = useState(() => Date.now() / 1000);
  useEffect(() => {
    if (!active) return;
    const timer = setInterval(() => setNow(Date.now() / 1000), 1000);
    return () => clearInterval(timer);
  }, [active]);
  return now;
}

function SensorStatus({
  running,
  iface,
  startedAt,
  onStart,
  onStop,
  stopping,
}: {
  running: boolean;
  iface: string | null;
  startedAt: number | null;
  onStart: () => void;
  onStop: () => void;
  stopping: boolean;
}) {
  const now = useNow(running);
  return (
    <div className="flex min-w-0 items-center gap-2 text-meta">
      {running ? (
        <>
          <Dot tone="ok" pulse />
          <span className="font-medium text-ink">Capturing</span>
          <span className="hidden truncate font-mono text-ink-muted sm:inline">{iface}</span>
          {startedAt && (
            <span className="font-mono text-ink-subtle tabular-nums">{clock(now - startedAt)}</span>
          )}
          <Button
            size="dense"
            variant="ghost"
            onPress={onStop}
            loading={stopping}
            icon={<StopIcon size={12} weight="fill" aria-hidden />}
          >
            Stop
          </Button>
        </>
      ) : (
        <>
          <Dot tone="off" />
          <span className="text-ink-muted">Not capturing</span>
          <Button
            size="dense"
            variant="ghost"
            onPress={onStart}
            icon={<PlayIcon size={12} weight="fill" aria-hidden />}
          >
            Start
          </Button>
        </>
      )}
    </div>
  );
}

export function ConnectionBadge() {
  const state = useConnection();
  const text = { live: "Live", connecting: "Connecting…", offline: "Offline" }[state];
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-[var(--radius-control)] border border-line px-2 py-0.5 text-meta text-ink-muted"
      title={
        state === "offline"
          ? "Live updates are paused; data refreshes when you reload or navigate."
          : undefined
      }
    >
      <Dot tone={state === "live" ? "ok" : state === "connecting" ? "warn" : "bad"} />
      <span aria-live="polite">{text}</span>
    </span>
  );
}
