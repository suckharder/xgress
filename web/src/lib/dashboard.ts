import type { Certificate } from "../types";

export type Attn = { id: string; domains: string; status: string; statusLabel: string; note: string };

// Surface certificates that need a human: failed issuance, expired, or expiring
// within 21 days. Drives the dashboard "needs attention" list.
export function certAttention(certs: Certificate[], now: number = Date.now()): Attn[] {
  const out: Attn[] = [];
  for (const c of certs) {
    const domains = c.domains.join(", ");
    if (c.status === "failed") out.push({ id: c.id, domains, status: "failed", statusLabel: "failed", note: c.lastError || "issuance failed" });
    else if (c.status === "expired") out.push({ id: c.id, domains, status: "expired", statusLabel: "expired", note: "certificate has expired" });
    else if (c.expiresAt) {
      const days = Math.round((new Date(c.expiresAt).getTime() - now) / 86400000);
      if (days <= 21) out.push({ id: c.id, domains, status: "expiring", statusLabel: `${days}d left`, note: `expires ${new Date(c.expiresAt).toLocaleDateString()}` });
    }
  }
  return out;
}

// Human-friendly uptime since an ISO timestamp. Empty string for an unknown /
// zero / pre-2001 / future time (so the UI can omit it).
export function since(iso?: string, now: number = Date.now()): string {
  const t = iso ? new Date(iso).getTime() : NaN;
  if (!isFinite(t) || t < 978307200000) return ""; // zero-time / pre-2001 → unknown
  const ms = now - t;
  if (ms < 0) return "";
  const m = Math.floor(ms / 60000), h = Math.floor(m / 60), d = Math.floor(h / 24);
  if (d > 0) return `${d}d ${h % 24}h`;
  if (h > 0) return `${h}h ${m % 60}m`;
  return `${m}m`;
}
