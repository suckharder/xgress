import { describe, expect, it } from "vitest";
import { aggregateBackendHealth, filterLiveRouters } from "./metrics";

describe("filterLiveRouters", () => {
  it("drops xgress-internal and ACME-challenge routers", () => {
    const routers = [
      { name: "app@http" },
      { name: "xgress-banned-ipv4@http" },
      { name: "acme-http-challenge@internal" },
      { name: "api@http" },
    ];
    expect(filterLiveRouters(routers).map((r) => r.name)).toEqual(["app@http", "api@http"]);
  });
  it("drops nameless routers", () => {
    expect(filterLiveRouters([{}, { name: "ok@http" }]).map((r) => r.name)).toEqual(["ok@http"]);
  });
});

describe("aggregateBackendHealth", () => {
  it("counts UP vs everything else across services", () => {
    const services = [
      { serverStatus: { "http://a": "UP", "http://b": "DOWN" } },
      { serverStatus: { "http://c": "UP" } },
      {},
    ];
    expect(aggregateBackendHealth(services)).toEqual({ up: 2, down: 1 });
  });
  it("returns zeroes for no services", () => {
    expect(aggregateBackendHealth([])).toEqual({ up: 0, down: 0 });
  });
});
