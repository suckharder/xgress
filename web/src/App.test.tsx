import { http, HttpResponse } from "msw";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";
import App from "./App";
import { flush } from "./test/render";
import { server } from "./test/server";
import { makeTraefikStatus, makeUser } from "./test/factories";

function renderApp(route = "/") {
  return render(<MemoryRouter initialEntries={[route]} future={{ v7_startTransition: true, v7_relativeSplatPath: true }}><App /></MemoryRouter>);
}

describe("App auth gate", () => {
  it("renders the auth screen when not logged in (me → 401)", async () => {
    server.use(
      http.get("/api/me", () => HttpResponse.json({ error: "unauthorized" }, { status: 401 })),
      http.get("/api/setup", () => HttpResponse.json({ needsSetup: false })),
    );
    renderApp();
    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
  });

  it("renders the shell when authenticated", async () => {
    server.use(http.get("/api/me", () => HttpResponse.json(makeUser({ name: "Ada", role: "admin" }))));
    renderApp();
    // The user chip (unique) confirms the shell rendered; "Dashboard" appears in
    // both the nav and the topbar title, so assert on the chip + nav link role.
    expect(await screen.findByText("Ada")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Dashboard" })).toBeInTheDocument();
  });

  it("logs out and returns to the auth screen", async () => {
    server.use(
      http.get("/api/me", () => HttpResponse.json(makeUser({ name: "Ada" }))),
      http.get("/api/setup", () => HttpResponse.json({ needsSetup: false })),
      http.post("/api/logout", () => new HttpResponse(null, { status: 204 })),
    );
    renderApp();
    await screen.findByText("Ada");
    await userEvent.click(screen.getByLabelText("Sign out"));
    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
  });

  it("redirects an unknown route to the dashboard", async () => {
    server.use(http.get("/api/me", () => HttpResponse.json(makeUser())));
    renderApp("/nonsense");
    // The Dashboard's resources card renders → we landed on "/".
    expect(await screen.findByText("Resources")).toBeInTheDocument();
  });
});

describe("EngineStatus top-bar badge", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it("shows the engine state and polls every 8s", async () => {
    let n = 0;
    server.use(
      http.get("/api/me", () => HttpResponse.json(makeUser())),
      http.get("/api/traefik/status", () => { n++; return HttpResponse.json(makeTraefikStatus({ state: "running", managed: true })); }),
    );
    // Route to a page that doesn't itself poll traefik/status, so EngineStatus is
    // the only consumer and the poll count is unambiguous.
    render(<MemoryRouter initialEntries={["/middlewares"]} future={{ v7_startTransition: true, v7_relativeSplatPath: true }}><App /></MemoryRouter>);
    await flush();
    // findBy* polls on timers, which are faked here — use the sync getter after flush.
    const badge = screen.getByTitle(/Traefik engine/);
    expect(badge).toHaveClass("green");
    expect(badge).toHaveTextContent("running");
    expect(n).toBe(1);
    await flush(8000);
    expect(n).toBe(2);
  });

  it("labels an external engine and colors a crashed state red", async () => {
    server.use(
      http.get("/api/me", () => HttpResponse.json(makeUser())),
      http.get("/api/traefik/status", () => HttpResponse.json(makeTraefikStatus({ state: "crashed", managed: false }))),
    );
    render(<MemoryRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}><App /></MemoryRouter>);
    await flush();
    const badge = screen.getByTitle(/Traefik engine/);
    expect(badge).toHaveClass("red");
    expect(badge).toHaveTextContent("external · crashed");
  });
});
