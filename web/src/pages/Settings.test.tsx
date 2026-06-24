import { http, HttpResponse } from "msw";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { Settings } from "./Settings";
import { server } from "../test/server";
import { makeTraefikStatus, makeUser } from "../test/factories";

// "Save & apply" appears on both the WAF card and the Raw-config card, so scope
// queries to the WAF card by its title.
const wafCard = () => within(screen.getByText(/WAF & server-side cache/).closest(".card") as HTMLElement);

describe("Settings RBAC", () => {
  it("hides admin-only cards from a viewer", async () => {
    render(<Settings user={makeUser({ role: "viewer" })} />);
    await screen.findByText("ACME / Let's Encrypt"); // base card always present
    expect(screen.queryByText("Users")).not.toBeInTheDocument();
    expect(screen.queryByText(/WAF & server-side cache/)).not.toBeInTheDocument();
    expect(screen.queryByText("Notifications")).not.toBeInTheDocument();
    expect(screen.queryByText(/Backup & restore/)).not.toBeInTheDocument();
  });

  it("shows admin-only cards for an admin", async () => {
    render(<Settings user={makeUser({ role: "admin" })} />);
    expect(await screen.findByText("Users")).toBeInTheDocument();
    expect(screen.getByText("Notifications")).toBeInTheDocument();
    expect(screen.getByText(/Backup & restore/)).toBeInTheDocument();
  });
});

describe("Settings — ACME / Traefik options card", () => {
  it("loads settings and saves the form, showing a Saved tick", async () => {
    server.use(http.get("/api/settings", () => HttpResponse.json({ "acme.email": "ops@example.com" })));
    let saved: any;
    server.use(http.put("/api/settings", async ({ request }) => { saved = await request.json(); return new HttpResponse(null, { status: 204 }); }));
    render(<Settings user={makeUser({ role: "operator" })} />);
    const email = (await screen.findByLabelText("Contact email")) as HTMLInputElement;
    await waitFor(() => expect(email.value).toBe("ops@example.com"));
    await userEvent.click(screen.getByRole("button", { name: "Save settings" }));
    await waitFor(() => expect(saved).toBeTruthy());
    expect(saved["acme.email"]).toBe("ops@example.com");
    expect(await screen.findByText("Saved")).toBeInTheDocument();
  });
});

describe("Settings — Traefik engine card (external mode)", () => {
  it("disables Restart and explains why when Traefik is external", async () => {
    server.use(http.get("/api/traefik/status", () => HttpResponse.json(makeTraefikStatus({ managed: false, state: "running" }))));
    render(<Settings user={makeUser({ role: "operator" })} />);
    const btn = await screen.findByRole("button", { name: /Restart Traefik/ });
    expect(btn).toBeDisabled();
    expect(screen.getByText(/only available when xgress supervises Traefik/)).toBeInTheDocument();
  });

  it("restart is confirm-gated and posts when managed", async () => {
    server.use(http.get("/api/traefik/status", () => HttpResponse.json(makeTraefikStatus({ managed: true }))));
    let restarted = false;
    server.use(http.post("/api/traefik/restart", () => { restarted = true; return new HttpResponse(null, { status: 204 }); }));
    render(<Settings user={makeUser({ role: "operator" })} />);
    const btn = await screen.findByRole("button", { name: /Restart Traefik/ });
    expect(btn).toBeEnabled();
    await userEvent.click(btn);
    await waitFor(() => expect(restarted).toBe(true));
  });
});

describe("Settings — WAF/cache plugins card", () => {
  it("enabling the WAF saves and hot-reloads (no Traefik restart) with paranoia/anomaly", async () => {
    server.use(
      http.get("/api/traefik/status", () => HttpResponse.json(makeTraefikStatus({ managed: true }))),
      http.get("/api/plugins", () => HttpResponse.json({ wafEnabled: false, wafParanoia: 1, wafAnomaly: 5, wafDirectives: [], cacheEnabled: false, cacheBackend: "memory" })),
    );
    let body: any;
    server.use(http.put("/api/plugins", async ({ request }) => { body = await request.json(); return new HttpResponse(null, { status: 204 }); }));
    render(<Settings user={makeUser({ role: "admin" })} />);
    const wafToggle = await screen.findByRole("checkbox", { name: /WAF — block common exploits/ });
    await userEvent.click(wafToggle); // flip from disabled → enabled
    // The native WAF exposes paranoia + anomaly controls (not a curated/CRS selector).
    expect(await screen.findByText(/Paranoia level/)).toBeInTheDocument();
    await userEvent.click(wafCard().getByRole("button", { name: "Save & apply" }));
    await waitFor(() => expect(body).toBeTruthy());
    expect(body.wafEnabled).toBe(true);
    expect(body.wafParanoia).toBe(1);
    expect(body.wafAnomaly).toBe(5);
    expect(await screen.findByText("Saved ✓")).toBeInTheDocument();
  });

  it("works the same in external mode — the WAF is in-process, so no restart prompt", async () => {
    server.use(
      http.get("/api/traefik/status", () => HttpResponse.json(makeTraefikStatus({ managed: false }))),
      http.get("/api/plugins", () => HttpResponse.json({ wafEnabled: false, wafParanoia: 1, wafAnomaly: 5, wafDirectives: [], cacheEnabled: false, cacheBackend: "memory" })),
      http.put("/api/plugins", () => new HttpResponse(null, { status: 204 })),
    );
    render(<Settings user={makeUser({ role: "admin" })} />);
    const wafToggle = await screen.findByRole("checkbox", { name: /WAF — block common exploits/ });
    await userEvent.click(wafToggle);
    await userEvent.click(wafCard().getByRole("button", { name: "Save & apply" }));
    expect(await screen.findByText("Saved ✓")).toBeInTheDocument();
  });
});

describe("Settings — Backup & restore", () => {
  it("restore is confirm-gated and reports counts on success", async () => {
    server.use(http.post("/api/restore", () => HttpResponse.json({ hosts: 3, middlewares: 1, accessLists: 2 })));
    render(<Settings user={makeUser({ role: "admin" })} />);
    await screen.findByText(/Backup & restore/);
    const file = new File([JSON.stringify({ hosts: [] })], "backup.json", { type: "application/json" });
    const input = document.querySelector('input[type="file"]') as HTMLInputElement;
    await userEvent.upload(input, file);
    expect(await screen.findByText(/Restored 3 hosts, 1 middlewares, 2 access lists/)).toBeInTheDocument();
  });

  it("does not restore when the confirm is cancelled", async () => {
    vi.spyOn(window, "confirm").mockReturnValue(false);
    let restored = false;
    server.use(http.post("/api/restore", () => { restored = true; return HttpResponse.json({ hosts: 0, middlewares: 0, accessLists: 0 }); }));
    render(<Settings user={makeUser({ role: "admin" })} />);
    await screen.findByText(/Backup & restore/);
    const file = new File(["{}"], "backup.json", { type: "application/json" });
    await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, file);
    expect(restored).toBe(false);
  });
});
