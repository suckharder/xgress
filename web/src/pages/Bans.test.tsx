import { http, HttpResponse } from "msw";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { Bans } from "./Bans";
import { server } from "../test/server";
import { makeBan, makeBanConfig, makeTraefikStatus } from "../test/factories";

describe("Bans", () => {
  it("shows the active-bans empty state and lists bans", async () => {
    server.use(http.get("/api/bans", () => HttpResponse.json([])));
    const { unmount } = render(<Bans />);
    expect(await screen.findByText("No IPs are currently banned")).toBeInTheDocument();
    unmount();

    server.use(http.get("/api/bans", () => HttpResponse.json([makeBan({ ip: "203.0.113.7", manual: true, reason: "abuse" })])));
    render(<Bans />);
    expect(await screen.findByText("203.0.113.7")).toBeInTheDocument();
    expect(screen.getByText("manual")).toBeInTheDocument();
  });

  it("manual ban submits the trimmed IP and reason", async () => {
    server.use(http.get("/api/bans", () => HttpResponse.json([])));
    let body: any;
    server.use(http.post("/api/bans", async ({ request }) => { body = await request.json(); return HttpResponse.json({}); }));
    render(<Bans />);
    await screen.findByText("No IPs are currently banned");
    await userEvent.type(screen.getByPlaceholderText(/203\.0\.113\.7 or/), "  203.0.113.9  ");
    await userEvent.type(screen.getByPlaceholderText("abuse"), "scanner");
    await userEvent.click(screen.getByRole("button", { name: "Ban" }));
    await waitFor(() => expect(body).toBeTruthy());
    expect(body.ip).toBe("203.0.113.9");
    expect(body.reason).toBe("scanner");
  });

  it("unban deletes the IP", async () => {
    server.use(http.get("/api/bans", () => HttpResponse.json([makeBan({ ip: "203.0.113.7" })])));
    let unbanned = "";
    server.use(http.delete("/api/bans/:ip", ({ params }) => { unbanned = String(params.ip); return new HttpResponse(null, { status: 204 }); }));
    render(<Bans />);
    await screen.findByText("203.0.113.7");
    await userEvent.click(screen.getByRole("button", { name: "Unban" }));
    await waitFor(() => expect(unbanned).toBe("203.0.113.7"));
  });

  it("disables the auto-ban controls in external mode", async () => {
    server.use(
      http.get("/api/bans", () => HttpResponse.json([])),
      http.get("/api/bans-config", () => HttpResponse.json(makeBanConfig({ enabled: true }))),
      http.get("/api/traefik/status", () => HttpResponse.json(makeTraefikStatus({ managed: false }))),
    );
    render(<Bans />);
    expect(await screen.findByText(/Automatic banning needs managed/i)).toBeInTheDocument();
    // The auto-ban enable toggle is disabled when Traefik is external.
    expect(screen.getByRole("checkbox")).toBeDisabled();
  });
});
