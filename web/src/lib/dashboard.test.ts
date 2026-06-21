import { describe, expect, it } from "vitest";
import { certAttention, since } from "./dashboard";
import { makeCert } from "../test/factories";

const NOW = Date.parse("2026-06-20T00:00:00Z");
const inDays = (d: number) => new Date(NOW + d * 86400000).toISOString();

describe("certAttention", () => {
  it("flags failed and expired certs", () => {
    const out = certAttention([
      makeCert({ status: "failed", lastError: "dns timeout" }),
      makeCert({ status: "expired" }),
    ], NOW);
    expect(out.map((a) => a.status)).toEqual(["failed", "expired"]);
    expect(out[0].note).toBe("dns timeout");
  });

  it("flags a cert expiring within 21 days but not one further out", () => {
    const out = certAttention([
      makeCert({ status: "valid", expiresAt: inDays(10) }),
      makeCert({ status: "valid", expiresAt: inDays(40) }),
    ], NOW);
    expect(out).toHaveLength(1);
    expect(out[0].status).toBe("expiring");
    expect(out[0].statusLabel).toBe("10d left");
  });

  it("ignores healthy certs with no expiry pressure", () => {
    expect(certAttention([makeCert({ status: "valid" })], NOW)).toEqual([]);
  });
});

describe("since", () => {
  it("returns empty for unknown / zero / future times", () => {
    expect(since(undefined, NOW)).toBe("");
    expect(since("0001-01-01T00:00:00Z", NOW)).toBe("");
    expect(since(new Date(NOW + 60000).toISOString(), NOW)).toBe("");
  });
  it("formats minutes, hours, and days", () => {
    expect(since(new Date(NOW - 5 * 60000).toISOString(), NOW)).toBe("5m");
    expect(since(new Date(NOW - (2 * 3600000 + 3 * 60000)).toISOString(), NOW)).toBe("2h 3m");
    expect(since(new Date(NOW - (1 * 86400000 + 4 * 3600000)).toISOString(), NOW)).toBe("1d 4h");
  });
});
