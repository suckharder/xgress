import { http, HttpResponse } from "msw";
import { screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { Dashboard } from "./Dashboard";
import { renderWithRouter } from "../test/render";
import { server } from "../test/server";
import { makeCert, makeHost, makeTraefikStatus } from "../test/factories";

describe("Dashboard", () => {
  it("summarises resource counts and reports all-nominal when healthy", async () => {
    server.use(
      http.get("/api/traefik/status", () => HttpResponse.json(makeTraefikStatus({ state: "running", managed: true }))),
      http.get("/api/hosts", () => HttpResponse.json([makeHost({ enabled: true }), makeHost({ enabled: false })])),
      http.get("/api/certificates", () => HttpResponse.json([makeCert({ status: "valid" })])),
    );
    renderWithRouter(<Dashboard />);
    expect(await screen.findByText("All systems nominal")).toBeInTheDocument();
    expect(screen.getByText("Proxy & stream hosts")).toBeInTheDocument();
    expect(screen.getByText("1 enabled")).toBeInTheDocument();
  });

  it("raises an attention row for a failed certificate", async () => {
    server.use(
      http.get("/api/traefik/status", () => HttpResponse.json(makeTraefikStatus({ state: "running" }))),
      http.get("/api/certificates", () => HttpResponse.json([makeCert({ status: "failed", lastError: "dns timeout", domains: ["bad.example.com"] })])),
    );
    renderWithRouter(<Dashboard />);
    expect(await screen.findByText("Needs attention")).toBeInTheDocument();
    expect(screen.getByText("bad.example.com")).toBeInTheDocument();
  });

  it("flags a non-running engine state", async () => {
    server.use(http.get("/api/traefik/status", () => HttpResponse.json(makeTraefikStatus({ state: "crashed", lastError: "boom" }))));
    renderWithRouter(<Dashboard />);
    expect(await screen.findByText("Needs attention")).toBeInTheDocument();
    expect(screen.getByText(/Traefik engine is/)).toBeInTheDocument();
  });
});
