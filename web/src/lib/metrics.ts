// Live-state helpers for the Metrics page, reading Traefik's own API shape.

// Drop xgress's internal plumbing routers (bans, ACME challenge, default site, …) so
// the table shows only the user's routers.
export function filterLiveRouters<T extends { name?: string }>(routers: T[]): T[] {
  return routers.filter(
    (r) => r.name && !r.name.startsWith("xgress-") && r.name !== "acme-http-challenge@internal",
  );
}

// Aggregate backend health from each service's serverStatus map ("UP"/anything).
export function aggregateBackendHealth(services: { serverStatus?: Record<string, string> }[]): { up: number; down: number } {
  let up = 0, down = 0;
  for (const s of services ?? []) {
    const ss = s.serverStatus || {};
    for (const v of Object.values(ss)) v === "UP" ? up++ : down++;
  }
  return { up, down };
}
