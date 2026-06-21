import { describe, expect, it } from "vitest";
import { diffLines, stringify } from "./diff";

describe("diffLines", () => {
  it("marks identical inputs as all 'same'", () => {
    const lines = diffLines("a\nb\nc", "a\nb\nc");
    expect(lines.every((l) => l.type === "same")).toBe(true);
    expect(lines.map((l) => l.text)).toEqual(["a", "b", "c"]);
  });

  it("detects an added line", () => {
    const lines = diffLines("a\nc", "a\nb\nc");
    expect(lines).toEqual([
      { type: "same", text: "a" },
      { type: "add", text: "b" },
      { type: "same", text: "c" },
    ]);
  });

  it("detects a removed line", () => {
    const lines = diffLines("a\nb\nc", "a\nc");
    expect(lines.filter((l) => l.type === "del")).toEqual([{ type: "del", text: "b" }]);
  });

  it("handles a full replacement", () => {
    const lines = diffLines("x", "y");
    expect(lines).toEqual([
      { type: "del", text: "x" },
      { type: "add", text: "y" },
    ]);
  });

  it("stringify pretty-prints JSON", () => {
    expect(stringify({ a: 1 })).toBe('{\n  "a": 1\n}');
  });
});
