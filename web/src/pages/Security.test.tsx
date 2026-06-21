import { http, HttpResponse } from "msw";
import { render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Security } from "./Security";
import { flush } from "../test/render";
import { server } from "../test/server";
import { makeTraefikStatus } from "../test/factories";

beforeEach(() => vi.useFakeTimers());
afterEach(() => vi.useRealTimers());

const statusManaged = (managed: boolean) =>
  http.get("/api/traefik/status", () => HttpResponse.json(makeTraefikStatus({ managed })));

describe("Security (external-mode gating + metrics)", () => {
  it("external mode shows the notice and does not poll metrics", async () => {
    let calls = 0;
    server.use(
      statusManaged(false),
      http.get("/api/security/metrics", () => { calls++; return HttpResponse.json({}); }),
    );
    render(<Security />);
    await flush();
    expect(screen.getByText(/WAF metrics need managed/i)).toBeInTheDocument();
    const afterMount = calls;
    await flush(15000);
    expect(calls).toBe(afterMount);
  });

  it("warns when the WAF is disabled", async () => {
    server.use(
      statusManaged(true),
      http.get("/api/security/metrics", () => HttpResponse.json({ wafEnabled: false, metrics: {} })),
    );
    render(<Security />);
    await flush();
    expect(screen.getByText(/The WAF is disabled/i)).toBeInTheDocument();
  });

  it("renders stat counters and the recent-blocks table from metrics", async () => {
    server.use(
      statusManaged(true),
      http.get("/api/security/metrics", () =>
        HttpResponse.json({
          wafEnabled: true,
          metrics: {
            blocked: 12,
            total: 30,
            topIps: [{ name: "1.2.3.4", count: 9 }],
            categories: [{ name: "sqli", count: 5 }],
            series: [{ hour: "08:00", count: 3 }],
            recent: [{ at: "2026-01-01T08:00:00Z", clientIp: "1.2.3.4", host: "app", method: "GET", uri: "/x", ruleId: "942100", message: "sqli", category: "sqli" }],
          },
        }),
      ),
    );
    render(<Security />);
    await flush();
    expect(screen.getByText("12")).toBeInTheDocument(); // blocked
    expect(screen.getByText("Requests blocked")).toBeInTheDocument();
    expect(screen.getByText("942100")).toBeInTheDocument(); // recent row rule id
  });

  it("managed mode polls metrics every 5s", async () => {
    let calls = 0;
    server.use(
      statusManaged(true),
      http.get("/api/security/metrics", () => { calls++; return HttpResponse.json({ wafEnabled: true, metrics: {} }); }),
    );
    render(<Security />);
    await flush();
    expect(calls).toBe(1);
    await flush(5000);
    expect(calls).toBe(2);
  });
});
