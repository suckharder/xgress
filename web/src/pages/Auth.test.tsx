import { http, HttpResponse } from "msw";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { Auth } from "./Auth";
import { apiError, server } from "../test/server";
import { makeUser } from "../test/factories";

describe("Auth", () => {
  it("shows the login form when setup is already done", async () => {
    server.use(http.get("/api/setup", () => HttpResponse.json({ needsSetup: false })));
    render(<Auth onAuthed={() => {}} />);
    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Sign in" })).toBeInTheDocument();
  });

  it("shows the setup form on first run", async () => {
    server.use(http.get("/api/setup", () => HttpResponse.json({ needsSetup: true })));
    render(<Auth onAuthed={() => {}} />);
    expect(await screen.findByText("Create your admin account")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Create account" })).toBeInTheDocument();
  });

  it("logs in and calls onAuthed with the user", async () => {
    const user = makeUser({ email: "me@example.com" });
    server.use(
      http.get("/api/setup", () => HttpResponse.json({ needsSetup: false })),
      http.post("/api/login", () => HttpResponse.json(user)),
    );
    const onAuthed = vi.fn();
    render(<Auth onAuthed={onAuthed} />);
    await screen.findByRole("heading", { name: "Sign in" });
    await userEvent.type(screen.getByLabelText("Email"), "me@example.com");
    await userEvent.type(screen.getByLabelText("Password"), "secret123");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    await waitFor(() => expect(onAuthed).toHaveBeenCalledWith(user));
  });

  it("renders a login error and does not call onAuthed", async () => {
    server.use(
      http.get("/api/setup", () => HttpResponse.json({ needsSetup: false })),
      http.post("/api/login", () => apiError(401, "invalid credentials")),
    );
    const onAuthed = vi.fn();
    render(<Auth onAuthed={onAuthed} />);
    await screen.findByRole("heading", { name: "Sign in" });
    await userEvent.type(screen.getByLabelText("Email"), "me@example.com");
    await userEvent.type(screen.getByLabelText("Password"), "wrong");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByText("invalid credentials")).toBeInTheDocument();
    expect(onAuthed).not.toHaveBeenCalled();
  });

  it("setup chains create-account then login", async () => {
    const user = makeUser();
    const calls: string[] = [];
    server.use(
      http.get("/api/setup", () => HttpResponse.json({ needsSetup: true })),
      http.post("/api/setup", () => { calls.push("setup"); return HttpResponse.json(user); }),
      http.post("/api/login", () => { calls.push("login"); return HttpResponse.json(user); }),
    );
    const onAuthed = vi.fn();
    render(<Auth onAuthed={onAuthed} />);
    await screen.findByText("Create your admin account");
    await userEvent.type(screen.getByLabelText("Name"), "Admin");
    await userEvent.type(screen.getByLabelText("Email"), "admin@example.com");
    await userEvent.type(screen.getByLabelText("Password"), "supersecret");
    await userEvent.click(screen.getByRole("button", { name: "Create account" }));
    await waitFor(() => expect(onAuthed).toHaveBeenCalledWith(user));
    expect(calls).toEqual(["setup", "login"]);
  });

  it("treats a failed setup-status probe as not-needing-setup (login)", async () => {
    server.use(http.get("/api/setup", () => apiError(500, "down")));
    render(<Auth onAuthed={() => {}} />);
    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
  });
});
