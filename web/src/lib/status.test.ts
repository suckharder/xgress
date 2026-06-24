import { describe, expect, it } from "vitest";
import { engineColor, engineLabel, statusColor } from "./status";

describe("statusColor", () => {
  it("maps known states to their color", () => {
    expect(statusColor("valid")).toBe("green");
    expect(statusColor("pending")).toBe("amber");
    expect(statusColor("expired")).toBe("red");
    expect(statusColor("disabled")).toBe("gray");
    expect(statusColor("external")).toBe("blue");
  });
  it("falls back to gray for unknown states", () => {
    expect(statusColor("nonsense")).toBe("gray");
  });
});

describe("engineColor", () => {
  it("is green only when running", () => {
    expect(engineColor("running")).toBe("green");
  });
  it("is red for hard-down states", () => {
    for (const s of ["stopped", "crashed", "failed"]) expect(engineColor(s)).toBe("red");
  });
  it("is amber for transitional / unknown states", () => {
    for (const s of ["starting", "restarting", "", "weird"]) expect(engineColor(s)).toBe("amber");
  });
});

describe("engineLabel", () => {
  it("shows the bare state when managed", () => {
    expect(engineLabel("running", true)).toBe("running");
  });
  it("prefixes external when not managed", () => {
    expect(engineLabel("running", false)).toBe("external · running");
  });
});
