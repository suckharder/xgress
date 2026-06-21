import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import { api, ApiErr } from "./api";
import { server } from "./test/server";

describe("api.req (the backend contract spine)", () => {
  it("parses a JSON body on success", async () => {
    server.use(http.get("/api/me", () => HttpResponse.json({ id: "u1", email: "a@b.c", role: "admin" })));
    const u = await api.me();
    expect(u.email).toBe("a@b.c");
  });

  it("returns null for an empty (204) body", async () => {
    server.use(http.post("/api/logout", () => new HttpResponse(null, { status: 204 })));
    await expect(api.logout()).resolves.toBeNull();
  });

  it("throws ApiErr carrying status and the error message from the envelope", async () => {
    server.use(http.get("/api/me", () => HttpResponse.json({ error: "nope" }, { status: 401 })));
    await expect(api.me()).rejects.toMatchObject({ message: "nope", status: 401 });
    await expect(api.me()).rejects.toBeInstanceOf(ApiErr);
  });

  it("carries validation issues[] through ApiErr", async () => {
    server.use(
      http.post("/api/hosts", () =>
        HttpResponse.json({ error: "invalid", issues: [{ field: "domains", message: "required" }] }, { status: 400 }),
      ),
    );
    try {
      await api.createHost({});
      expect.unreachable("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(ApiErr);
      expect((e as ApiErr).issues).toEqual([{ field: "domains", message: "required" }]);
    }
  });

  it("falls back to statusText when the body has no error field", async () => {
    server.use(http.get("/api/me", () => new HttpResponse("", { status: 500, statusText: "Internal Server Error" })));
    await expect(api.me()).rejects.toMatchObject({ status: 500 });
  });

  it("sends a JSON content-type only when there is a body", async () => {
    let getCT: string | null = "unset";
    let postCT: string | null = "unset";
    server.use(
      http.get("/api/me", ({ request }) => {
        getCT = request.headers.get("content-type");
        return HttpResponse.json({ id: "u1" });
      }),
      http.post("/api/login", async ({ request }) => {
        postCT = request.headers.get("content-type");
        return HttpResponse.json({ id: "u1" });
      }),
    );
    await api.me();
    await api.login({ email: "a@b.c", password: "x" });
    expect(getCT).toBeNull();
    expect(postCT).toContain("application/json");
  });

  it("encodes path + query params correctly", async () => {
    let seenUrl = "";
    server.use(
      http.get("/api/hosts", ({ request }) => {
        seenUrl = new URL(request.url).search;
        return HttpResponse.json([]);
      }),
    );
    await api.listHosts("stream");
    expect(seenUrl).toBe("?kind=stream");
  });
});
