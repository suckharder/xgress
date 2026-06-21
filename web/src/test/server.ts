// MSW server + default handlers. The SPA's only backend coupling is api.ts, so a
// faithful fake at the HTTP boundary lets pages render and exercises the real
// api.ts code path (fetch, ApiErr envelope) — higher fidelity than mocking the
// module. Tests override per-case with `server.use(...)`.
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { makeTraefikStatus, makeUser } from "./factories";

const json = (data: unknown) => HttpResponse.json(data as object);
const noContent = () => new HttpResponse(null, { status: 204 });
async function echo({ request }: { request: Request }) {
  const text = await request.text();
  const body = text ? JSON.parse(text) : {};
  return HttpResponse.json({ id: "generated", ...body });
}

// Default handlers: lists empty, singletons sensible, mutations echo. Enough for
// any page to mount without noise; tests narrow what they actually assert.
export const handlers = [
  // auth / setup
  http.get("/api/setup", () => json({ needsSetup: false })),
  http.post("/api/setup", () => json(makeUser())),
  http.post("/api/login", () => json(makeUser())),
  http.post("/api/logout", () => noContent()),
  http.get("/api/me", () => json(makeUser())),

  // hosts
  http.get("/api/hosts", () => json([])),
  http.get("/api/hosts/:id", ({ params }) => json({ id: params.id })),
  http.post("/api/hosts", echo),
  http.put("/api/hosts/:id", echo),
  http.delete("/api/hosts/:id", () => noContent()),

  // middlewares
  http.get("/api/middlewares", () => json([])),
  http.get("/api/middleware-catalog", () => json([])),
  http.post("/api/middlewares", echo),
  http.put("/api/middlewares/:id", echo),
  http.delete("/api/middlewares/:id", () => noContent()),

  // certificates
  http.get("/api/certificates", () => json([])),
  http.post("/api/certificates", echo),
  http.post("/api/certificates/:id/renew", echo),
  http.delete("/api/certificates/:id", () => noContent()),

  // dns providers
  http.get("/api/dns-providers", () => json([])),
  http.get("/api/dns-catalog", () => json([])),
  http.post("/api/dns-providers", echo),
  http.delete("/api/dns-providers/:id", () => noContent()),

  // listeners (read-only)
  http.get("/api/listeners", () => json([])),

  // traefik
  http.get("/api/traefik/status", () => json(makeTraefikStatus())),
  http.get("/api/traefik/logs", () => json([])),
  http.post("/api/traefik/restart", () => noContent()),
  http.get("/api/traefik/overview", () => json({})),
  http.get("/api/traefik/routers", () => json([])),
  http.get("/api/traefik/services", () => json([])),

  // access lists
  http.get("/api/access-lists", () => json([])),
  http.post("/api/access-lists", echo),
  http.put("/api/access-lists/:id", echo),
  http.delete("/api/access-lists/:id", () => noContent()),
  http.post("/api/util/htpasswd", () => json({ line: "user:$apr1$hash" })),

  // default site + raw config
  http.get("/api/default-site", () => json({ mode: "404" })),
  http.put("/api/default-site", () => noContent()),
  http.get("/api/raw-config", () => json({ yaml: "" })),
  http.put("/api/raw-config", () => noContent()),

  // snapshots / rollback
  http.get("/api/config/preview", () => json({ version: 1, hash: "h", config: {} })),
  http.get("/api/config/snapshots", () => json([])),
  http.get("/api/config/snapshots/:v", ({ params }) => json({ version: Number(params.v), hash: "h", config: {} })),
  http.post("/api/config/rollback/:v", ({ params }) => json({ version: Number(params.v) })),

  // plugins (WAF + cache)
  http.get("/api/plugins", () => json({})),
  http.put("/api/plugins", () => noContent()),
  http.get("/api/security/metrics", () => json({})),

  // bans
  http.get("/api/bans", () => json([])),
  http.post("/api/bans", echo),
  http.delete("/api/bans/:ip", () => noContent()),
  http.get("/api/bans-config", () => json({ enabled: true, threshold: 5, windowSec: 60, durationSec: 3600 })),
  http.put("/api/bans-config", echo),

  // schedules
  http.get("/api/hosts/:id/schedules", () => json([])),
  http.post("/api/hosts/:id/schedules", echo),
  http.delete("/api/schedules/:id", () => noContent()),

  // docker import
  http.get("/api/import/docker", () => json([])),
  http.post("/api/import/docker", () => json({ imported: 0 })),

  // backup / restore + notifications
  http.post("/api/restore", () => json({ hosts: 0, middlewares: 0, accessLists: 0 })),
  http.get("/api/notifications", () => json({})),
  http.put("/api/notifications", () => noContent()),
  http.post("/api/notifications/test", () => noContent()),
  http.get("/api/audit", () => json([])),

  // users
  http.get("/api/users", () => json([])),
  http.post("/api/users", echo),
  http.put("/api/users/:id", echo),
  http.delete("/api/users/:id", () => noContent()),

  // settings
  http.get("/api/settings", () => json({})),
  http.put("/api/settings", () => noContent()),
];

export const server = setupServer(...handlers);

// Convenience: an error envelope matching api.ts's ApiErr contract.
export function apiError(status: number, error: string, issues?: { field: string; message: string }[]) {
  return HttpResponse.json({ error, ...(issues ? { issues } : {}) }, { status });
}
