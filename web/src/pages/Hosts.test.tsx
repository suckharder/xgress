import { http, HttpResponse } from "msw";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { Hosts } from "./Hosts";
import { apiError, server } from "../test/server";
import { makeHost, makeListener } from "../test/factories";

// Hosts fans out to several list endpoints on mount; default handlers cover the
// ones a test doesn't care about. Seed only what each test asserts.
function seedHosts(hosts = []) {
  server.use(http.get("/api/hosts", () => HttpResponse.json(hosts)));
}

describe("Hosts list", () => {
  it("shows the empty state when there are no hosts", async () => {
    seedHosts([]);
    render(<Hosts />);
    expect(await screen.findByText("No hosts yet")).toBeInTheDocument();
  });

  it("renders a row per host with its kind badge and destination", async () => {
    seedHosts([
      makeHost({ domains: ["a.example.com"], kind: "proxy", upstreams: [{ scheme: "http", host: "be", port: 8080 }] }),
      makeHost({ domains: ["r.example.com"], kind: "redirection", redirectTo: "https://x.com", upstreams: [] }),
    ]);
    render(<Hosts />);
    expect(await screen.findByText("a.example.com")).toBeInTheDocument();
    expect(screen.getByText("proxy")).toBeInTheDocument();
    expect(screen.getByText("http://be:8080")).toBeInTheDocument();
    expect(screen.getByText("redirect")).toBeInTheDocument();
    expect(screen.getByText("→ https://x.com")).toBeInTheDocument();
  });

  it("toggling enabled PUTs the host with the flipped flag", async () => {
    const host = makeHost({ enabled: true });
    seedHosts([host]);
    let body: any;
    server.use(http.put("/api/hosts/:id", async ({ request }) => { body = await request.json(); return HttpResponse.json(body); }));
    render(<Hosts />);
    await screen.findByText(host.domains[0]);
    await userEvent.click(screen.getByRole("checkbox"));
    await waitFor(() => expect(body).toBeTruthy());
    expect(body.enabled).toBe(false);
  });

  it("delete asks for confirmation and DELETEs on confirm", async () => {
    const host = makeHost();
    seedHosts([host]);
    let deleted = false;
    server.use(http.delete("/api/hosts/:id", () => { deleted = true; return new HttpResponse(null, { status: 204 }); }));
    render(<Hosts />);
    await screen.findByText(host.domains[0]);
    await userEvent.click(screen.getByTitle("Delete"));
    await waitFor(() => expect(deleted).toBe(true));
  });

  it("delete is aborted when the user cancels the confirm", async () => {
    vi.spyOn(window, "confirm").mockReturnValue(false);
    const host = makeHost();
    seedHosts([host]);
    let deleted = false;
    server.use(http.delete("/api/hosts/:id", () => { deleted = true; return new HttpResponse(null, { status: 204 }); }));
    render(<Hosts />);
    await screen.findByText(host.domains[0]);
    await userEvent.click(screen.getByTitle("Delete"));
    expect(deleted).toBe(false);
  });
});

describe("HostModal", () => {
  it("creates a proxy host, parsing the comma-separated domains into an array", async () => {
    seedHosts([]);
    let body: any;
    server.use(http.post("/api/hosts", async ({ request }) => { body = await request.json(); return HttpResponse.json({ id: "new", ...body }); }));
    render(<Hosts />);
    await screen.findByText("No hosts yet");
    await userEvent.click(screen.getAllByRole("button", { name: /Add host/ })[0]);

    await userEvent.type(screen.getByLabelText("Domain names"), "a.example.com, b.example.com");
    await userEvent.type(screen.getByPlaceholderText("host or IP"), "backend");
    await userEvent.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => expect(body).toBeTruthy());
    expect(body.kind).toBe("proxy");
    expect(body.domains).toEqual(["a.example.com", "b.example.com"]);
    expect(body.upstreams[0].host).toBe("backend");
  });

  it("renders backend-validation issues as field errors", async () => {
    seedHosts([]);
    server.use(http.post("/api/hosts", () => apiError(400, "invalid", [{ field: "domains", message: "at least one domain is required" }])));
    render(<Hosts />);
    await screen.findByText("No hosts yet");
    await userEvent.click(screen.getAllByRole("button", { name: /Add host/ })[0]);
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(await screen.findByText(/at least one domain is required/)).toBeInTheDocument();
  });

  it("switches sections by host type (stream shows entrypoint + protocol)", async () => {
    seedHosts([]);
    server.use(http.get("/api/listeners", () => HttpResponse.json([makeListener({ name: "mysql", kind: "stream", proto: "tcp", port: 3306 })])));
    render(<Hosts />);
    await screen.findByText("No hosts yet");
    await userEvent.click(screen.getAllByRole("button", { name: /Add host/ })[0]);

    // Switch the Type select to stream.
    const typeSelect = screen.getByLabelText("Type");
    await userEvent.selectOptions(typeSelect, "stream");
    expect(screen.getByLabelText("Protocol")).toBeInTheDocument();
    expect(screen.getByText(/Entrypoint/)).toBeInTheDocument();
    // The TCP stream entrypoint we seeded is offered.
    expect(await screen.findByRole("option", { name: /mysql/ })).toBeInTheDocument();
  });

  it("weighted mode reveals backend groups", async () => {
    seedHosts([]);
    render(<Hosts />);
    await screen.findByText("No hosts yet");
    await userEvent.click(screen.getAllByRole("button", { name: /Add host/ })[0]);
    await userEvent.selectOptions(screen.getByLabelText("Traffic mode"), "weighted");
    expect(screen.getByText(/Backend groups/)).toBeInTheDocument();
  });

  it("edits an existing host (modal pre-filled, PUT on save)", async () => {
    const host = makeHost({ domains: ["edit.example.com"] });
    seedHosts([host]);
    let body: any;
    server.use(http.put("/api/hosts/:id", async ({ request }) => { body = await request.json(); return HttpResponse.json(body); }));
    render(<Hosts />);
    await screen.findByText("edit.example.com");
    await userEvent.click(screen.getByTitle("Edit"));
    const domains = screen.getByLabelText("Domain names") as HTMLInputElement;
    expect(domains.value).toBe("edit.example.com");
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(body).toBeTruthy());
    expect(body.domains).toEqual(["edit.example.com"]);
  });

  it("creates a stream (L4) host with protocol, entrypoint and single backend", async () => {
    seedHosts([]);
    server.use(http.get("/api/listeners", () => HttpResponse.json([makeListener({ name: "mysql", kind: "stream", proto: "tcp", port: 3306 })])));
    let body: any;
    server.use(http.post("/api/hosts", async ({ request }) => { body = await request.json(); return HttpResponse.json({ id: "s1", ...body }); }));
    render(<Hosts />);
    await screen.findByText("No hosts yet");
    await userEvent.click(screen.getAllByRole("button", { name: /Add host/ })[0]);
    await userEvent.selectOptions(screen.getByLabelText("Type"), "stream");
    await userEvent.selectOptions(screen.getByLabelText(/Entrypoint/), "mysql");
    await userEvent.type(screen.getByPlaceholderText("host or IP"), "db.internal");
    const portInput = screen.getByPlaceholderText("port");
    await userEvent.clear(portInput);
    await userEvent.type(portInput, "3306");
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(body).toBeTruthy());
    expect(body.kind).toBe("stream");
    expect(body.streamEntryPoint).toBe("mysql");
    expect(body.upstreams[0]).toMatchObject({ host: "db.internal", port: 3306 });
  });

  it("adds a second upstream and shows the load-balanced share", async () => {
    seedHosts([]);
    render(<Hosts />);
    await screen.findByText("No hosts yet");
    await userEvent.click(screen.getAllByRole("button", { name: /Add host/ })[0]);
    await userEvent.click(screen.getByRole("button", { name: /Add upstream/ }));
    // Two upstreams → the per-backend traffic share appears.
    expect(screen.getAllByText(/≈\d+%/).length).toBeGreaterThanOrEqual(2);
  });

  it("adds a custom location through the Advanced section and includes it on save", async () => {
    seedHosts([]);
    let body: any;
    server.use(http.post("/api/hosts", async ({ request }) => { body = await request.json(); return HttpResponse.json({ id: "h", ...body }); }));
    render(<Hosts />);
    await screen.findByText("No hosts yet");
    await userEvent.click(screen.getAllByRole("button", { name: /Add host/ })[0]);
    await userEvent.type(screen.getByLabelText("Domain names"), "app.example.com");
    await userEvent.click(screen.getByText(/Advanced: locations/));
    await userEvent.click(screen.getByRole("button", { name: /Add location/ }));
    await userEvent.type(screen.getByPlaceholderText("/api"), "/api");
    await userEvent.type(screen.getByPlaceholderText("backend host"), "api-be");
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(body).toBeTruthy());
    expect(body.locations[0]).toMatchObject({ pathPrefix: "/api" });
    expect(body.locations[0].upstreams[0].host).toBe("api-be");
  });

  it("failover mode adds backend groups and a group can be removed", async () => {
    seedHosts([]);
    render(<Hosts />);
    await screen.findByText("No hosts yet");
    await userEvent.click(screen.getAllByRole("button", { name: /Add host/ })[0]);
    await userEvent.selectOptions(screen.getByLabelText("Traffic mode"), "failover");
    await userEvent.click(screen.getByRole("button", { name: /Add group/ }));
    expect(screen.getAllByPlaceholderText("name").length).toBeGreaterThanOrEqual(1);
    await userEvent.click(screen.getAllByRole("button", { name: "Remove" })[0]);
  });

  it("warns when CORS combines a wildcard origin with credentials", async () => {
    seedHosts([]);
    render(<Hosts />);
    await screen.findByText("No hosts yet");
    await userEvent.click(screen.getAllByRole("button", { name: /Add host/ })[0]);
    await userEvent.click(screen.getByText(/Enable CORS/));
    const origins = screen.getByLabelText(/Allowed origins/);
    await userEvent.type(origins, "*");
    await userEvent.click(screen.getByText(/Allow credentials/));
    expect(await screen.findByText(/can't be combined with credentials/)).toBeInTheDocument();
  });
});
