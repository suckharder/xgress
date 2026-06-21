import { http, HttpResponse } from "msw";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { AccessLists } from "./AccessLists";
import { server } from "../test/server";
import { makeAccessList } from "../test/factories";

describe("AccessLists", () => {
  it("shows the empty state", async () => {
    server.use(http.get("/api/access-lists", () => HttpResponse.json([])));
    render(<AccessLists />);
    expect(await screen.findByText("No access lists yet")).toBeInTheDocument();
  });

  it("lists access lists with their users and IPs", async () => {
    server.use(http.get("/api/access-lists", () => HttpResponse.json([
      makeAccessList({ name: "staff", users: [{ username: "alice" }], allowIps: ["10.0.0.0/8"] }),
    ])));
    render(<AccessLists />);
    expect(await screen.findByText("staff")).toBeInTheDocument();
    expect(screen.getByText("alice")).toBeInTheDocument();
    expect(screen.getByText("10.0.0.0/8")).toBeInTheDocument();
  });

  it("creates an access list, splitting the IP textarea into a CIDR list", async () => {
    server.use(http.get("/api/access-lists", () => HttpResponse.json([])));
    let body: any;
    server.use(http.post("/api/access-lists", async ({ request }) => { body = await request.json(); return HttpResponse.json({ id: "a1", ...body }); }));
    render(<AccessLists />);
    await screen.findByText("No access lists yet");
    await userEvent.click(screen.getAllByRole("button", { name: /Add access list/ })[0]);
    await userEvent.type(screen.getByLabelText("Name"), "ops");
    await userEvent.type(screen.getByLabelText(/IP allow-list/), "10.0.0.0/8\n192.168.1.0/24");
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(body).toBeTruthy());
    expect(body.name).toBe("ops");
    expect(body.allowIps).toEqual(["10.0.0.0/8", "192.168.1.0/24"]);
    expect(body.satisfyAny).toBe(false);
  });
});
