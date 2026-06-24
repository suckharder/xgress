import { http, HttpResponse } from "msw";
import { render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Logs } from "./Logs";
import { flush } from "../test/render";
import { server } from "../test/server";
import { makeLogLine, makeTraefikStatus } from "../test/factories";

beforeEach(() => vi.useFakeTimers());
afterEach(() => vi.useRealTimers());

function withStatus(managed: boolean, onLogs?: () => void) {
  server.use(
    http.get("/api/traefik/status", () => HttpResponse.json(makeTraefikStatus({ managed }))),
    http.get("/api/traefik/logs", () => {
      onLogs?.();
      return HttpResponse.json([makeLogLine({ message: "started ok" })]);
    }),
  );
}

describe("Logs (external-mode gating)", () => {
  it("external mode shows the notice and an empty state", async () => {
    withStatus(false);
    render(<Logs />);
    await flush();
    expect(screen.getByText(/Traefik logs need managed/i)).toBeInTheDocument();
    expect(screen.getByText(/No logs in external mode/i)).toBeInTheDocument();
  });

  it("external mode does not poll for logs", async () => {
    let calls = 0;
    withStatus(false, () => calls++);
    render(<Logs />);
    await flush();
    const afterMount = calls;
    await flush(9000); // three poll windows
    expect(calls).toBe(afterMount); // no further fetches
  });

  it("managed mode renders log lines and polls every 3s", async () => {
    let calls = 0;
    withStatus(true, () => calls++);
    render(<Logs />);
    await flush();
    expect(screen.getByText(/started ok/)).toBeInTheDocument();
    expect(calls).toBe(1);
    await flush(3000);
    expect(calls).toBe(2);
    await flush(3000);
    expect(calls).toBe(3);
  });

  it("stops polling after unmount (no leak)", async () => {
    let calls = 0;
    withStatus(true, () => calls++);
    const { unmount } = render(<Logs />);
    await flush();
    const atUnmount = calls;
    unmount();
    await flush(9000);
    expect(calls).toBe(atUnmount);
  });
});
