import { http, HttpResponse } from "msw";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { Middlewares } from "./Middlewares";
import { apiError, server } from "../test/server";
import { makeMiddleware } from "../test/factories";

const catalog = [
  { type: "headers", label: "Headers", description: "Set headers", example: { customRequestHeaders: { X: "y" } }, fields: [] },
  { type: "ratelimit", label: "Rate limit", description: "Limit", example: { average: 100 }, fields: [{ key: "average", label: "Average", type: "number" }] },
];

describe("Middlewares", () => {
  it("shows the empty state when there are none", async () => {
    server.use(http.get("/api/middlewares", () => HttpResponse.json([])));
    render(<Middlewares />);
    expect(await screen.findByText("No middleware yet")).toBeInTheDocument();
  });

  it("lists middlewares with type badge", async () => {
    server.use(http.get("/api/middlewares", () => HttpResponse.json([makeMiddleware({ name: "gzip", type: "compress" })])));
    render(<Middlewares />);
    expect(await screen.findByText("gzip")).toBeInTheDocument();
    expect(screen.getByText("compress")).toBeInTheDocument();
  });

  it("creates a middleware via the raw-JSON editor", async () => {
    server.use(
      http.get("/api/middlewares", () => HttpResponse.json([])),
      http.get("/api/middleware-catalog", () => HttpResponse.json(catalog)),
    );
    let body: any;
    server.use(http.post("/api/middlewares", async ({ request }) => { body = await request.json(); return HttpResponse.json({ id: "m1", ...body }); }));
    render(<Middlewares />);
    await screen.findByText("No middleware yet");
    await userEvent.click(screen.getAllByRole("button", { name: /Add middleware/ })[0]);
    await userEvent.type(screen.getByLabelText("Name"), "my-headers");
    // headers type has no fields → the raw JSON editor is shown by default ({}).
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(body).toBeTruthy());
    expect(body.name).toBe("my-headers");
    expect(body.type).toBe("headers");
  });

  it("surfaces a JSON syntax error before calling the API", async () => {
    server.use(
      http.get("/api/middlewares", () => HttpResponse.json([])),
      http.get("/api/middleware-catalog", () => HttpResponse.json(catalog)),
    );
    let posted = false;
    server.use(http.post("/api/middlewares", () => { posted = true; return HttpResponse.json({}); }));
    render(<Middlewares />);
    await screen.findByText("No middleware yet");
    await userEvent.click(screen.getAllByRole("button", { name: /Add middleware/ })[0]);
    await userEvent.type(screen.getByLabelText("Name"), "broken");
    const editor = document.querySelector("textarea.code") as HTMLTextAreaElement;
    await userEvent.clear(editor);
    await userEvent.type(editor, "{{not json");
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(await screen.findByText("Params must be valid JSON")).toBeInTheDocument();
    expect(posted).toBe(false);
  });

  it("builds params from the guided form (number field) on save", async () => {
    server.use(
      http.get("/api/middlewares", () => HttpResponse.json([])),
      http.get("/api/middleware-catalog", () => HttpResponse.json(catalog)),
    );
    let body: any;
    server.use(http.post("/api/middlewares", async ({ request }) => { body = await request.json(); return HttpResponse.json({ id: "m", ...body }); }));
    render(<Middlewares />);
    await screen.findByText("No middleware yet");
    await userEvent.click(screen.getAllByRole("button", { name: /Add middleware/ })[0]);
    await userEvent.type(screen.getByLabelText("Name"), "rl");
    // Switch to the ratelimit type which has a guided numeric "average" field.
    await userEvent.selectOptions(screen.getByLabelText("Type"), "ratelimit");
    // The guided "Average" field is a numeric input (spinbutton).
    await userEvent.type(screen.getByRole("spinbutton"), "100");
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(body).toBeTruthy());
    expect(body.type).toBe("ratelimit");
    expect(body.params).toEqual({ average: 100 });
  });

  it("renders backend validation issues", async () => {
    server.use(
      http.get("/api/middlewares", () => HttpResponse.json([])),
      http.get("/api/middleware-catalog", () => HttpResponse.json(catalog)),
      http.post("/api/middlewares", () => apiError(400, "invalid", [{ field: "params", message: "unknown field foo" }])),
    );
    render(<Middlewares />);
    await screen.findByText("No middleware yet");
    await userEvent.click(screen.getAllByRole("button", { name: /Add middleware/ })[0]);
    await userEvent.type(screen.getByLabelText("Name"), "x");
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(await screen.findByText("unknown field foo")).toBeInTheDocument();
  });
});
