import { http, HttpResponse } from "msw";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { Config } from "./Config";
import { server } from "../test/server";
import { makeSnapshot } from "../test/factories";

describe("Config (snapshots / rollback)", () => {
  it("shows the empty snapshots state", async () => {
    server.use(http.get("/api/config/snapshots", () => HttpResponse.json([])));
    render(<Config />);
    expect(await screen.findByText("No snapshots yet")).toBeInTheDocument();
  });

  it("lists snapshots, marking the live one and offering rollback on the rest", async () => {
    server.use(http.get("/api/config/snapshots", () => HttpResponse.json([
      makeSnapshot({ version: 3, current: true }),
      makeSnapshot({ version: 2, current: false }),
    ])));
    render(<Config />);
    expect(await screen.findByText("#3")).toBeInTheDocument();
    expect(screen.getByText("live")).toBeInTheDocument();
    // Only the non-current snapshot is rollback-able.
    expect(screen.getAllByRole("button", { name: "Roll back" })).toHaveLength(1);
  });

  it("rollback is confirm-gated and posts the chosen version", async () => {
    server.use(http.get("/api/config/snapshots", () => HttpResponse.json([
      makeSnapshot({ version: 3, current: true }),
      makeSnapshot({ version: 2, current: false }),
    ])));
    let rolledTo = 0;
    server.use(http.post("/api/config/rollback/:v", ({ params }) => { rolledTo = Number(params.v); return HttpResponse.json({ version: rolledTo }); }));
    render(<Config />);
    await screen.findByText("#3");
    await userEvent.click(screen.getByRole("button", { name: "Roll back" }));
    await waitFor(() => expect(rolledTo).toBe(2));
  });

  it("opens a diff modal summarising added/removed lines between versions", async () => {
    server.use(
      http.get("/api/config/snapshots", () => HttpResponse.json([
        makeSnapshot({ version: 3, current: true }),
        makeSnapshot({ version: 2, current: false }),
      ])),
      http.get("/api/config/snapshots/2", () => HttpResponse.json({ version: 2, hash: "h2", config: { a: 1 } })),
      http.get("/api/config/snapshots/3", () => HttpResponse.json({ version: 3, hash: "h3", config: { a: 1, b: 2 } })),
    );
    render(<Config />);
    await screen.findByText("#3");
    // The live snapshot (#3) diffs against the previous (#2).
    await userEvent.click(screen.getByRole("button", { name: "Diff" }));
    expect(await screen.findByRole("heading", { name: "Diff v2 → v3" })).toBeInTheDocument();
    expect(await screen.findByText(/added/)).toBeInTheDocument();
  });

  it("does not roll back when the confirm is cancelled", async () => {
    vi.spyOn(window, "confirm").mockReturnValue(false);
    server.use(http.get("/api/config/snapshots", () => HttpResponse.json([
      makeSnapshot({ version: 3, current: true }),
      makeSnapshot({ version: 2, current: false }),
    ])));
    let rolled = false;
    server.use(http.post("/api/config/rollback/:v", () => { rolled = true; return HttpResponse.json({ version: 2 }); }));
    render(<Config />);
    await screen.findByText("#3");
    await userEvent.click(screen.getByRole("button", { name: "Roll back" }));
    expect(rolled).toBe(false);
  });
});
