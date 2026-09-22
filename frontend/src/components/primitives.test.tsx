import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { describe, expect, it, vi } from "vitest";

import type { Alert } from "@/lib/queries";

// Outside the Next runtime next/link renders no href; a plain anchor keeps the tests about ours.
vi.mock("next/link", () => ({
  default: ({ href, ...props }: { href: string } & Record<string, unknown>) => (
    <a href={href} {...props} />
  ),
}));

import { AlertListItem, RelativeTime, alertDestination } from "./AlertBits";
import { Dot, HealthIcon, MitreTag, ProtocolTag, SeverityChip, Tag } from "./Badges";
import { SonarMark } from "./Brand";
import { Button, FileLink, IconButton, LinkButton, TextLink } from "./Button";
import { Checkbox, NumberField, SearchField, Select, Switch, TextField } from "./Field";
import { FilterChips } from "./FilterChips";
import { LogTail } from "./LogTail";
import { NAV, isActive } from "./nav";
import { DialogBox, Drawer, SegmentedControl } from "./Overlays";
import { Facts, Kpi, PageHeader, Panel } from "./Panel";
import { ToastProvider, useToast } from "./Toast";

const alert = (extra: Partial<Alert> = {}): Alert =>
  ({
    id: "A-1",
    severity: "high",
    title: "Port scan",
    src: "10.0.0.66",
    dst: "10.0.0.5",
    ports: [22, 80],
    occurrences: 3,
    last_seen: Date.now() / 1000 - 120,
    ...extra,
  }) as Alert;

describe("alert bits", () => {
  it("describes the destination by its ports", () => {
    expect(alertDestination(alert({ ports: [] }))).toBe("10.0.0.5");
    expect(alertDestination(alert({ ports: [443] }))).toBe("10.0.0.5:443");
    expect(alertDestination(alert())).toBe("10.0.0.5 · 2 ports");
    expect(alertDestination(alert({ dst: null, ports: [1, 2] }))).toBe("* · 2 ports");
  });

  it("links a feed item to its alert with severity, route and hit count", () => {
    render(
      <ul>
        <AlertListItem alert={alert()} />
      </ul>,
    );
    const link = screen.getByRole("link");
    expect(link).toHaveAttribute("href", "/alerts/?id=A-1");
    expect(link).toHaveTextContent("Port scan");
    expect(link).toHaveTextContent("10.0.0.66 → 10.0.0.5 · 2 ports");
    expect(link).toHaveTextContent("×3");
  });

  it("shows relative time with the absolute time as a machine-readable value", () => {
    render(<RelativeTime epoch={1_700_000_000} />);
    expect(screen.getByRole("time")).toHaveAttribute("datetime", "2023-11-14T22:13:20.000Z");
  });
});

describe("badges and brand", () => {
  it("pairs every tag with text", () => {
    render(
      <>
        <SeverityChip severity="medium" compact />
        <Tag>raw</Tag>
        <ProtocolTag protocol={17} />
        <MitreTag technique="T1046 Network Service Discovery" />
        <MitreTag technique={null} />
        <HealthIcon health="warning" />
        <Dot tone="ok" pulse />
        <SonarMark />
      </>,
    );
    expect(screen.getByText("UDP")).toBeInTheDocument();
    expect(screen.getByText("raw")).toBeInTheDocument();
    const mitre = screen.getByRole("link", { name: /T1046/ });
    expect(mitre).toHaveAttribute("href", expect.stringContaining("attack.mitre.org"));
  });
});

describe("buttons and links", () => {
  it("fires presses, blocks them while loading and names icon buttons", async () => {
    const onPress = vi.fn();
    const { rerender } = render(<Button onPress={onPress}>Save</Button>);
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(onPress).toHaveBeenCalledTimes(1);

    rerender(
      <Button onPress={onPress} loading>
        Save
      </Button>,
    );
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(onPress).toHaveBeenCalledTimes(1);

    render(<IconButton label="Close" icon={<span />} onPress={onPress} />);
    await userEvent.click(screen.getByRole("button", { name: "Close" }));
    expect(onPress).toHaveBeenCalledTimes(2);
  });

  it("renders app links and file links", () => {
    render(
      <>
        <LinkButton href="/alerts/">Alerts</LinkButton>
        <TextLink href="/model/">Model</TextLink>
        <FileLink href="/api/x.csv" download>
          CSV
        </FileLink>
      </>,
    );
    expect(screen.getByRole("link", { name: "Alerts" })).toHaveAttribute("href", "/alerts/");
    expect(screen.getByRole("link", { name: "Model" }).className).toContain("underline");
    expect(screen.getByRole("link", { name: "CSV" })).toHaveAttribute("download");
  });
});

describe("form fields", () => {
  it("text and search fields report what is typed and can be cleared", async () => {
    function Fields() {
      const [text, setText] = useState("");
      const [search, setSearch] = useState("");
      return (
        <>
          <TextField label="Name" description="Who" value={text} onChange={setText} mono />
          <TextField label="Notes" multiline value="" onChange={() => {}} />
          <SearchField label="Source IP" value={search} onChange={setSearch} />
          <output>{`${text}|${search}`}</output>
        </>
      );
    }
    render(<Fields />);
    await userEvent.type(screen.getByLabelText("Name"), "admin");
    await userEvent.type(screen.getByRole("searchbox", { name: "Source IP" }), "10.0.0.5");
    expect(screen.getByRole("status")).toHaveTextContent("admin|10.0.0.5");
    expect(screen.getByText("Who")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Clear" }));
    expect(screen.getByRole("status")).toHaveTextContent("admin|");
  });

  it("number fields keep to their range", async () => {
    const onChange = vi.fn();
    render(
      <NumberField label="Port" unit="port" minValue={1} maxValue={65535} onChange={onChange} />,
    );
    const input = screen.getByLabelText("Port");
    await userEvent.type(input, "70000");
    await userEvent.tab();
    expect(onChange).toHaveBeenLastCalledWith(65535);
    expect(screen.getByText("port")).toBeInTheDocument();
  });

  it("select picks an option", async () => {
    const onChange = vi.fn();
    render(
      <Select
        label="Format"
        value="json"
        onChange={onChange}
        description="How"
        options={[
          { id: "json", label: "JSON" },
          { id: "slack", label: "Slack", description: "Incoming webhook" },
        ]}
      />,
    );
    await userEvent.click(screen.getByRole("button", { name: /JSON/ }));
    await userEvent.click(await screen.findByRole("option", { name: /Slack/ }));
    expect(onChange).toHaveBeenCalledWith("slack");
  });

  it("switch and checkbox toggle", async () => {
    const onSwitch = vi.fn();
    const onCheck = vi.fn();
    render(
      <>
        <Switch isSelected={false} onChange={onSwitch}>
          Enabled
        </Switch>
        <Checkbox isSelected onChange={onCheck} aria-label="Select row" />
      </>,
    );
    await userEvent.click(screen.getByRole("switch", { name: "Enabled" }));
    await userEvent.click(screen.getByRole("checkbox", { name: "Select row" }));
    expect(onSwitch).toHaveBeenCalledWith(true);
    expect(onCheck).toHaveBeenCalledWith(false);
  });
});

describe("filters and segmented control", () => {
  it("filter chips toggle several values", async () => {
    const onChange = vi.fn();
    render(
      <FilterChips
        label="Severity"
        value={["high"]}
        onChange={onChange}
        options={[
          { id: "high", label: "High" },
          { id: "low", label: "Low" },
        ]}
      />,
    );
    await userEvent.click(screen.getByRole("button", { name: "Low" }));
    expect(onChange).toHaveBeenCalledWith(["high", "low"]);
  });

  it("segmented control always keeps one choice", async () => {
    const onChange = vi.fn();
    render(
      <SegmentedControl
        label="Range"
        value="15m"
        onChange={onChange}
        options={[
          { id: "15m", label: "15m" },
          { id: "1h", label: "1h" },
        ]}
      />,
    );
    await userEvent.click(screen.getByRole("radio", { name: "1h" }));
    expect(onChange).toHaveBeenCalledWith("1h");
  });
});

describe("overlays", () => {
  it("drawer shows its content and closes with Esc", async () => {
    const onClose = vi.fn();
    render(
      <Drawer isOpen onClose={onClose} title="Alert" subtitle="A-1" footer={<span>foot</span>}>
        body
      </Drawer>,
    );
    const dialog = screen.getByRole("dialog", { name: "Alert" });
    expect(within(dialog).getByText("body")).toBeInTheDocument();
    expect(within(dialog).getByText("foot")).toBeInTheDocument();
    await userEvent.keyboard("{Escape}");
    expect(onClose).toHaveBeenCalled();
  });

  it("dialog box has a title and closes from its close path", async () => {
    const onClose = vi.fn();
    render(
      <DialogBox isOpen onClose={onClose} title="Start capture">
        <button type="button" onClick={onClose}>
          Cancel
        </button>
      </DialogBox>,
    );
    await userEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(screen.getByRole("dialog", { name: "Start capture" })).toBeInTheDocument();
    expect(onClose).toHaveBeenCalled();
  });
});

describe("layout", () => {
  it("panels are labelled regions; KPIs and facts show values", () => {
    render(
      <>
        <PageHeader title="Overview" description="Live" actions={<button>Go</button>} />
        <Panel id="p" title="Traffic" actions={<span>act</span>}>
          <Kpi label="Open alerts" value={7} detail="3 new" tone="critical">
            <span>spark</span>
          </Kpi>
          <Kpi label="Drops" value="0 %" tone="ok" />
          <Facts columns={3} items={[["Status", "Stopped"]]} />
          <Facts columns={1} items={[["Model", "rules only"]]} />
        </Panel>
      </>,
    );
    expect(screen.getByRole("heading", { level: 1, name: "Overview" })).toBeInTheDocument();
    expect(screen.getByRole("region", { name: "Traffic" })).toHaveTextContent("7");
    expect(screen.getByText("Stopped")).toBeInTheDocument();
  });
});

describe("log tail", () => {
  it("colours lines by level and says when empty", () => {
    const { rerender } = render(<LogTail lines={[]} />);
    expect(screen.getByText("No log lines yet.")).toBeInTheDocument();
    rerender(<LogTail lines={["12:00 ERROR boom", "12:01 WARNING hmm", "12:02 INFO ok"]} />);
    expect(screen.getByText("12:00 ERROR boom").className).toContain("text-sev-critical");
    expect(screen.getByText("12:01 WARNING hmm").className).toContain("text-sev-medium");
  });
});

describe("toasts", () => {
  function Trigger() {
    const notify = useToast();
    return (
      <button
        type="button"
        onClick={() =>
          notify("Report ready", { tone: "ok", action: { label: "Open", onAction: opened } })
        }
      >
        go
      </button>
    );
  }
  const opened = vi.fn();

  it("announces politely, runs the action, and can be dismissed", async () => {
    render(
      <ToastProvider>
        <Trigger />
      </ToastProvider>,
    );
    await userEvent.click(screen.getByRole("button", { name: "go" }));
    expect(screen.getByRole("status")).toHaveTextContent("Report ready");
    await userEvent.click(screen.getByRole("button", { name: "Open" }));
    expect(opened).toHaveBeenCalled();
    expect(screen.queryByText("Report ready")).not.toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "go" }));
    await userEvent.click(screen.getByRole("button", { name: "Dismiss" }));
    await waitFor(() => expect(screen.queryByText("Report ready")).not.toBeInTheDocument());
  });
});

describe("navigation", () => {
  it("marks the current section, including nested pages", () => {
    expect(NAV.map((n) => n.label)).toContain("Settings");
    expect(isActive("/", "/")).toBe(true);
    expect(isActive("/alerts", "/alerts/")).toBe(true);
    expect(isActive("/alerts/", "/")).toBe(false);
    expect(isActive("/hosts/", "/alerts/")).toBe(false);
  });
});
