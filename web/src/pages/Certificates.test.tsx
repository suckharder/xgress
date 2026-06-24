import { http, HttpResponse } from "msw";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { Certificates } from "./Certificates";
import { server } from "../test/server";
import { makeCert } from "../test/factories";

describe("Certificates", () => {
  it("shows the empty state with no certs", async () => {
    server.use(http.get("/api/certificates", () => HttpResponse.json([])));
    render(<Certificates />);
    expect(await screen.findByText("No certificates yet")).toBeInTheDocument();
  });

  it("lists certs with their status; only ACME certs offer a Renew action", async () => {
    server.use(http.get("/api/certificates", () => HttpResponse.json([
      makeCert({ type: "acme", status: "valid", domains: ["a.example.com"] }),
      makeCert({ type: "uploaded", status: "valid", domains: ["b.example.com"] }),
    ])));
    render(<Certificates />);
    expect(await screen.findByText("a.example.com")).toBeInTheDocument();
    expect(screen.getAllByTitle("Renew now")).toHaveLength(1);
  });

  it("renew posts to the cert endpoint", async () => {
    let renewed = false;
    server.use(
      http.get("/api/certificates", () => HttpResponse.json([makeCert({ type: "acme", status: "valid" })])),
      http.post("/api/certificates/:id/renew", () => { renewed = true; return HttpResponse.json(makeCert()); }),
    );
    render(<Certificates />);
    await userEvent.click(await screen.findByTitle("Renew now"));
    await waitFor(() => expect(renewed).toBe(true));
  });

  it("opens the request-certificate modal and switches to DNS-01 for wildcards", async () => {
    server.use(http.get("/api/certificates", () => HttpResponse.json([])));
    render(<Certificates />);
    await screen.findByText("No certificates yet");
    await userEvent.click(screen.getAllByRole("button", { name: /Request certificate/ })[0]);
    expect(await screen.findByRole("heading", { name: "Request certificate" })).toBeInTheDocument();
    // Default challenge is HTTP-01; selecting DNS-01 reveals the provider picker.
    await userEvent.selectOptions(screen.getByLabelText("Challenge"), "dns-01");
    expect(screen.getByLabelText("DNS provider")).toBeInTheDocument();
  });

  it("requests an ACME cert, parsing domains and sending the challenge type", async () => {
    server.use(http.get("/api/certificates", () => HttpResponse.json([])));
    let body: any;
    server.use(http.post("/api/certificates", async ({ request }) => { body = await request.json(); return HttpResponse.json(makeCert()); }));
    render(<Certificates />);
    await screen.findByText("No certificates yet");
    await userEvent.click(screen.getAllByRole("button", { name: /Request certificate/ })[0]);
    await screen.findByRole("heading", { name: "Request certificate" });
    await userEvent.type(screen.getByLabelText("Domains"), "a.example.com, b.example.com");
    await userEvent.click(screen.getByRole("button", { name: "Request" }));
    await waitFor(() => expect(body).toBeTruthy());
    expect(body.type).toBe("acme");
    expect(body.domains).toEqual(["a.example.com", "b.example.com"]);
    expect(body.challengeType).toBe("http-01");
  });

  it("adds a DNS provider from the catalog, collecting its required fields", async () => {
    server.use(
      http.get("/api/certificates", () => HttpResponse.json([])),
      http.get("/api/dns-providers", () => HttpResponse.json([])),
      http.get("/api/dns-catalog", () => HttpResponse.json([
        { code: "cloudflare", label: "Cloudflare", docs: "https://x", fields: [{ key: "CF_API_TOKEN", label: "API token", secret: true, optional: false }] },
      ])),
    );
    let body: any;
    server.use(http.post("/api/dns-providers", async ({ request }) => { body = await request.json(); return HttpResponse.json({ id: "d1", ...body }); }));
    render(<Certificates />);
    await screen.findByText("No certificates yet");
    await userEvent.click(screen.getByRole("button", { name: /^Add$/ }));
    await screen.findByRole("heading", { name: "Add DNS provider" });
    await userEvent.type(screen.getByLabelText("API token"), "secret-token");
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(body).toBeTruthy());
    expect(body.provider).toBe("cloudflare");
    expect(body.config.CF_API_TOKEN).toBe("secret-token");
  });

  it("blocks DNS provider save when a required field is empty", async () => {
    server.use(
      http.get("/api/certificates", () => HttpResponse.json([])),
      http.get("/api/dns-catalog", () => HttpResponse.json([
        { code: "cloudflare", label: "Cloudflare", docs: "https://x", fields: [{ key: "CF_API_TOKEN", label: "API token", secret: true, optional: false }] },
      ])),
    );
    let posted = false;
    server.use(http.post("/api/dns-providers", () => { posted = true; return HttpResponse.json({}); }));
    render(<Certificates />);
    await screen.findByText("No certificates yet");
    await userEvent.click(screen.getByRole("button", { name: /^Add$/ }));
    await screen.findByRole("heading", { name: "Add DNS provider" });
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(await screen.findByText("API token is required")).toBeInTheDocument();
    expect(posted).toBe(false);
  });
});
