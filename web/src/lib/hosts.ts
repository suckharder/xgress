import type { Upstream } from "../types";

// Parse a comma-separated domain/SNI input into a clean list (trim, drop blanks).
// Used for both proxy domains and stream SNI hostnames.
export function parseDomains(text: string): string[] {
  return text.split(",").map((d) => d.trim()).filter(Boolean);
}

// Load-balancing weights are relative; a blank or non-positive weight counts as 1
// (Traefik's default), so every backend gets a fair share.
export function effWeight(u: Pick<Upstream, "weight">): number {
  return u.weight && u.weight > 0 ? u.weight : 1;
}

export function weightSum(ups: Pick<Upstream, "weight">[]): number {
  return ups.reduce((a, u) => a + effWeight(u), 0) || 1;
}

// Each backend's share of traffic as a whole percent.
export function trafficShare(u: Pick<Upstream, "weight">, ups: Pick<Upstream, "weight">[]): number {
  return Math.round((effWeight(u) / weightSum(ups)) * 100);
}

// CORS can't combine a wildcard origin with credentials — the browser rejects it.
export function corsWildcardConflict(enabled: boolean | undefined, credentials: boolean | undefined, origins: string[] | undefined): boolean {
  return !!enabled && !!credentials && (origins ?? []).includes("*");
}
