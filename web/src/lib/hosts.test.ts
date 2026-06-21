import { describe, expect, it } from "vitest";
import { corsWildcardConflict, effWeight, parseDomains, trafficShare, weightSum } from "./hosts";

describe("parseDomains", () => {
  it("trims, splits on comma, and drops blanks", () => {
    expect(parseDomains(" a.com , b.com ,, ")).toEqual(["a.com", "b.com"]);
  });
  it("returns [] for an empty / whitespace string", () => {
    expect(parseDomains("")).toEqual([]);
    expect(parseDomains("  ,  ")).toEqual([]);
  });
});

describe("effWeight", () => {
  it("treats blank, zero, and negative as 1 (Traefik default)", () => {
    expect(effWeight({})).toBe(1);
    expect(effWeight({ weight: 0 })).toBe(1);
    expect(effWeight({ weight: -5 })).toBe(1);
  });
  it("returns a positive weight as-is", () => {
    expect(effWeight({ weight: 3 })).toBe(3);
  });
});

describe("weightSum", () => {
  it("sums effective weights", () => {
    expect(weightSum([{ weight: 2 }, { weight: 3 }])).toBe(5);
  });
  it("counts blanks as 1 each", () => {
    expect(weightSum([{}, {}, { weight: 4 }])).toBe(6);
  });
  it("never returns 0 (guards divide-by-zero)", () => {
    expect(weightSum([])).toBe(1);
  });
});

describe("trafficShare", () => {
  it("splits evenly when all weights are blank", () => {
    const ups = [{}, {}, {}, {}];
    expect(trafficShare({}, ups)).toBe(25);
  });
  it("reflects relative weights", () => {
    const ups = [{ weight: 3 }, { weight: 1 }];
    expect(trafficShare({ weight: 3 }, ups)).toBe(75);
    expect(trafficShare({ weight: 1 }, ups)).toBe(25);
  });
});

describe("corsWildcardConflict", () => {
  it("flags wildcard origin combined with credentials", () => {
    expect(corsWildcardConflict(true, true, ["*"])).toBe(true);
  });
  it("is false without credentials", () => {
    expect(corsWildcardConflict(true, false, ["*"])).toBe(false);
  });
  it("is false with explicit origins", () => {
    expect(corsWildcardConflict(true, true, ["https://a.com"])).toBe(false);
  });
  it("is false when CORS is disabled", () => {
    expect(corsWildcardConflict(false, true, ["*"])).toBe(false);
  });
  it("handles undefined origins", () => {
    expect(corsWildcardConflict(true, true, undefined)).toBe(false);
  });
});
