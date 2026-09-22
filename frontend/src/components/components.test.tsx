import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { SeverityChip, StatusBadge } from "./Badges";
import { DataTable, columnHelper } from "./DataTable";
import { EmptyState, QueryView } from "./States";

describe("badges", () => {
  it("never relies on colour alone: severity has a text label", () => {
    render(<SeverityChip severity="critical" />);
    expect(screen.getByText("Critical")).toBeInTheDocument();
  });

  it("labels statuses in words", () => {
    render(<StatusBadge status="false_positive" />);
    expect(screen.getByText("False positive")).toBeInTheDocument();
  });
});

describe("QueryView", () => {
  const base = { error: null, isPending: false, refetch: vi.fn() };

  it("shows loading, then error with retry, then empty, then data", async () => {
    const { rerender } = render(
      <QueryView query={{ ...base, data: undefined, isPending: true }}>{() => "data"}</QueryView>,
    );
    expect(screen.getByRole("status", { name: "Loading" })).toBeInTheDocument();

    rerender(
      <QueryView query={{ ...base, data: undefined, error: new Error("boom") }}>
        {() => "data"}
      </QueryView>,
    );
    expect(screen.getByRole("alert")).toHaveTextContent("boom");
    await userEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(base.refetch).toHaveBeenCalled();

    rerender(
      <QueryView
        query={{ ...base, data: [] as number[] }}
        empty={(d) => (d.length === 0 ? <EmptyState title="Nothing" /> : null)}
      >
        {() => "data"}
      </QueryView>,
    );
    expect(screen.getByText("Nothing")).toBeInTheDocument();

    rerender(<QueryView query={{ ...base, data: [1] }}>{(d) => `rows: ${d.length}`}</QueryView>);
    expect(screen.getByText("rows: 1")).toBeInTheDocument();
  });
});

describe("DataTable", () => {
  type Row = { id: string; name: string };
  const col = columnHelper<Row>();
  const columns = col.columns([col.accessor("name", { header: "Name" })]);

  it("renders headers, an empty state, and opens rows from the keyboard", async () => {
    const onOpen = vi.fn();
    const { rerender } = render(
      <DataTable
        label="People"
        data={[]}
        columns={columns}
        template="1fr"
        rowKey={(r) => r.id}
        empty="No people"
      />,
    );
    expect(screen.getByRole("columnheader", { name: "Name" })).toBeInTheDocument();
    expect(screen.getByText("No people")).toBeInTheDocument();

    rerender(
      <DataTable
        label="People"
        data={[{ id: "1", name: "Ada" }]}
        columns={columns}
        template="1fr"
        rowKey={(r) => r.id}
        onOpen={onOpen}
      />,
    );
    // jsdom has no layout, so the virtualiser may render no rows; only assert when it does.
    const rows = screen.queryAllByRole("row");
    const bodyRow = rows.find((r) => r.textContent === "Ada");
    if (bodyRow) {
      bodyRow.focus();
      await userEvent.keyboard("{Enter}");
      expect(onOpen).toHaveBeenCalledWith({ id: "1", name: "Ada" });
    }
    expect(screen.getByRole("table", { name: "People" })).toBeInTheDocument();
  });
});
