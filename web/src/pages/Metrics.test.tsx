import { http, HttpResponse } from "msw";
import { render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Metrics } from "./Metrics";
import { flush } from "../test/render";
import { apiError, server } from "../test/server";

beforeEach(() => vi.useFakeTimers());
afterEach(() => vi.useRealTimers());

describe("Metrics", () => {
  it("shows the unavailable banner when Traefik's API errors", async () => {
    server.use(
      http.get("/api/traefik/overview", () => apiError(503, "down")),
      http.get("/api/traefik/routers", () => apiError(503, "down")),
    );
    render(<Metrics />);
    await flush();
    expect(screen.getByText(/Traefik’s API is unavailable/i)).toBeInTheDocument();
  });

  it("renders only user routers (drops xgress- internal + acme challenge)", async () => {
    server.use(
      http.get("/api/traefik/overview", () => HttpResponse.json({ http: { routers: { total: 3 }, services: { total: 2 }, middlewares: { total: 1 } } })),
      http.get("/api/traefik/routers", () => HttpResponse.json([
        { name: "app@http", rule: "Host(`a`)", service: "app-svc", status: "enabled" },
        { name: "xgress-banned-ipv4@http", rule: "x", service: "y", status: "enabled" },
        { name: "acme-http-challenge@internal", rule: "x", service: "y", status: "enabled" },
      ])),
      http.get("/api/traefik/services", () => HttpResponse.json([{ serverStatus: { "http://a": "UP", "http://b": "DOWN" } }])),
    );
    render(<Metrics />);
    await flush();
    expect(screen.getByText("app")).toBeInTheDocument(); // router name (app@http → app)
    expect(screen.getByText("app-svc")).toBeInTheDocument(); // its service
    expect(screen.queryByText(/xgress-banned/)).not.toBeInTheDocument();
    expect(screen.queryByText(/acme-http-challenge/)).not.toBeInTheDocument();
    expect(screen.getByText("1/2")).toBeInTheDocument(); // backends up: 1 up of 2
  });

  it("polls live state every 5s", async () => {
    let calls = 0;
    server.use(http.get("/api/traefik/overview", () => { calls++; return HttpResponse.json({}); }));
    render(<Metrics />);
    await flush();
    expect(calls).toBe(1);
    await flush(5000);
    expect(calls).toBe(2);
  });
});
