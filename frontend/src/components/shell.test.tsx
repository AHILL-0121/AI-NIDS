/** App shell, command palette and start-capture dialog, with the data hooks mocked. */
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const router = { push: vi.fn(), replace: vi.fn() };
const sensor = {
  data: { running: false, interface: null, started_at: null } as Record<string, unknown>,
};
const start = { mutate: vi.fn(), isPending: false, error: null };
const stop = { mutate: vi.fn(), isPending: false, error: null };
const logout = vi.fn(() => Promise.resolve());

vi.mock("next/navigation", () => ({
  usePathname: () => "/alerts/",
  useRouter: () => router,
}));
vi.mock("@/lib/auth", () => ({
  RequireAuth: ({ children }: { children: ReactNode }) => children,
  useAuth: () => ({ status: { username: "admin" }, logout }),
}));
vi.mock("@/lib/live", () => ({
  LiveProvider: ({ children }: { children: ReactNode }) => children,
  useConnection: () => "live",
}));
vi.mock("@/lib/queries", () => ({
  useSensor: () => sensor,
  useSensorControl: () => ({ start, stop }),
  useInterfaces: () => ({
    isPending: false,
    error: null,
    data: [
      { name: "eth0", label: "Ethernet", ipv4: ["192.168.1.20"], loopback: false },
      { name: "lo", label: "", ipv4: ["127.0.0.1"], loopback: true },
    ],
  }),
}));

const { AppShell } = await import("./AppShell");
const { CommandPalette } = await import("./CommandPalette");
const { StartCaptureDialog, interfaceOptions } = await import("./StartCapture");
const { ToastProvider } = await import("./Toast");

const shell = () =>
  render(
    <ToastProvider>
      <AppShell>
        <p>page body</p>
      </AppShell>
    </ToastProvider>,
  );

beforeEach(() => {
  vi.clearAllMocks();
  sensor.data = { running: false, interface: null, started_at: null };
});

describe("app shell", () => {
  it("has a skip link, marks the current page and shows the live connection", () => {
    shell();
    expect(screen.getByRole("link", { name: "Skip to content" })).toHaveAttribute("href", "#main");
    const nav = screen.getByRole("navigation", { name: "Main" });
    expect(within(nav).getByRole("link", { name: "Alerts" })).toHaveAttribute(
      "aria-current",
      "page",
    );
    expect(screen.getByText("Live")).toBeInTheDocument();
    expect(screen.getByRole("main")).toHaveTextContent("page body");
  });

  it("starts capture through the interface dialog", async () => {
    shell();
    await userEvent.click(screen.getByRole("button", { name: "Start" }));
    const dialog = await screen.findByRole("dialog", { name: "Start capture" });
    await userEvent.click(within(dialog).getByRole("button", { name: "Start" }));
    expect(start.mutate).toHaveBeenCalledWith(
      { interface: "eth0", backend: "auto" },
      expect.anything(),
    );
  });

  it("shows a running capture with its interface and stops it", async () => {
    sensor.data = { running: true, interface: "eth0", started_at: Date.now() / 1000 - 65 };
    shell();
    expect(screen.getByText("Capturing")).toBeInTheDocument();
    expect(screen.getByText("eth0")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Stop" }));
    expect(stop.mutate).toHaveBeenCalled();
  });

  it("hides start/stop when the sensor is its own service (Docker)", () => {
    sensor.data = { running: false, managed: false, interface: null, started_at: null };
    shell();
    expect(screen.getByText("Sensor service not running")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Start" })).not.toBeInTheDocument();
  });

  it("signs out from the account menu", async () => {
    shell();
    await userEvent.click(screen.getByRole("button", { name: "Account" }));
    await userEvent.click(await screen.findByRole("menuitem", { name: /Sign out/ }));
    await vi.waitFor(() => expect(router.replace).toHaveBeenCalledWith("/login/"));
    expect(logout).toHaveBeenCalled();
  });

  it("opens the command palette with Ctrl+K", async () => {
    shell();
    await userEvent.keyboard("{Control>}k{/Control}");
    expect(await screen.findByRole("dialog", { name: "Command palette" })).toBeInTheDocument();
  });
});

describe("command palette", () => {
  const props = {
    isOpen: true,
    onOpenChange: vi.fn(),
    sensorRunning: false,
    onStartSensor: vi.fn(),
    onStopSensor: vi.fn(),
    onSignOut: vi.fn(),
  };

  it("jumps to a page", async () => {
    render(<CommandPalette {...props} />);
    await userEvent.type(screen.getByRole("searchbox"), "sessions");
    await userEvent.click(screen.getByRole("menuitem", { name: /Go to Sessions/ }));
    expect(router.push).toHaveBeenCalledWith("/sessions/");
  });

  it("looks up a typed IP address", async () => {
    render(<CommandPalette {...props} />);
    await userEvent.type(screen.getByRole("searchbox"), "10.0.0.5");
    await userEvent.click(screen.getByRole("menuitem", { name: "Open host 10.0.0.5" }));
    expect(router.push).toHaveBeenCalledWith("/hosts/?ip=10.0.0.5");
  });

  it("offers stop while capturing", async () => {
    render(<CommandPalette {...props} sensorRunning />);
    await userEvent.click(screen.getByRole("menuitem", { name: /Stop capture/ }));
    expect(props.onStopSensor).toHaveBeenCalled();
  });

  it("switches theme", async () => {
    render(<CommandPalette {...props} />);
    await userEvent.type(screen.getByRole("searchbox"), "dark");
    await userEvent.click(screen.getByRole("menuitem", { name: /Switch theme: Dark/ }));
    expect(window.localStorage.getItem("nids.theme")).toBe("dark");
  });
});

describe("start capture", () => {
  it("labels interfaces with their addresses", () => {
    expect(
      interfaceOptions([{ name: "lo", label: "", ipv4: ["127.0.0.1"], loopback: true }]),
    ).toEqual([{ id: "lo", label: "lo", description: "127.0.0.1 · loopback" }]);
    expect(interfaceOptions(undefined)).toEqual([]);
  });

  it("cancels without starting", async () => {
    const onClose = vi.fn();
    render(
      <ToastProvider>
        <StartCaptureDialog isOpen onClose={onClose} />
      </ToastProvider>,
    );
    await userEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(onClose).toHaveBeenCalled();
    expect(start.mutate).not.toHaveBeenCalled();
  });
});
