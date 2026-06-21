// Domain-state → pill color. Color never carries meaning alone (a text label is
// always shown alongside), but it must be consistent across the app.
export const STATUS_COLOR: Record<string, string> = {
  valid: "green", running: "green", active: "green", enabled: "green",
  pending: "amber", restarting: "amber", reloading: "amber", expiring: "amber",
  failed: "red", crashed: "red", expired: "red", stopped: "gray", disabled: "gray",
  external: "blue",
};

export function statusColor(status: string): string {
  return STATUS_COLOR[status] || "gray";
}

// The top-bar engine dot: green when running, red for a hard-down state, amber
// for anything transitional/unknown.
export function engineColor(state: string): "green" | "red" | "amber" {
  if (state === "running") return "green";
  if (state === "stopped" || state === "crashed" || state === "failed") return "red";
  return "amber";
}

// Engine label: external Traefik is prefixed so the badge reads "external · running".
export function engineLabel(state: string, managed: boolean): string {
  return managed ? state : `external · ${state}`;
}
