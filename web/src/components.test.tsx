import React from "react";
import { render, renderHook, screen, waitFor, act } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import {
  Banner,
  Copyable,
  Empty,
  ExternalModeNotice,
  Modal,
  StatusBadge,
  TableSkeleton,
  Toggle,
  useAsync,
} from "./components";

describe("Toggle", () => {
  it("reflects checked and emits the flipped value", async () => {
    const onChange = vi.fn();
    render(<Toggle checked={false} onChange={onChange} />);
    const box = screen.getByRole("checkbox");
    expect(box).not.toBeChecked();
    await userEvent.click(box);
    expect(onChange).toHaveBeenCalledWith(true);
  });
  it("does not emit when disabled", async () => {
    const onChange = vi.fn();
    render(<Toggle checked={false} onChange={onChange} disabled />);
    await userEvent.click(screen.getByRole("checkbox"));
    expect(onChange).not.toHaveBeenCalled();
  });
});

describe("Modal", () => {
  it("renders title + content with dialog semantics", () => {
    render(<Modal title="Edit host" onClose={() => {}}>body</Modal>);
    const dialog = screen.getByRole("dialog");
    expect(dialog).toHaveAttribute("aria-modal", "true");
    expect(dialog).toHaveAttribute("aria-label", "Edit host");
    expect(screen.getByText("body")).toBeInTheDocument();
  });

  it("closes on Escape", async () => {
    const onClose = vi.fn();
    render(<Modal title="T" onClose={onClose}>x</Modal>);
    await userEvent.keyboard("{Escape}");
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("closes on the close button and on overlay click, but not on inner click", async () => {
    const onClose = vi.fn();
    render(<Modal title="T" onClose={onClose}>x</Modal>);
    await userEvent.click(screen.getByLabelText("Close"));
    expect(onClose).toHaveBeenCalledTimes(1);

    // Inner mousedown must not bubble to the overlay handler.
    await userEvent.click(screen.getByRole("dialog"));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("removes its keydown listener on unmount (no leak / no post-unmount close)", async () => {
    const onClose = vi.fn();
    const { unmount } = render(<Modal title="T" onClose={onClose}>x</Modal>);
    unmount();
    await userEvent.keyboard("{Escape}");
    expect(onClose).not.toHaveBeenCalled();
  });
});

describe("StatusBadge", () => {
  it("colors by status and shows an optional label override", () => {
    const { rerender } = render(<StatusBadge status="valid" />);
    expect(screen.getByText("valid")).toHaveClass("green");
    rerender(<StatusBadge status="running" label="up" />);
    const badge = screen.getByText("up");
    expect(badge).toHaveClass("green");
  });
  it("falls back to gray for an unknown status", () => {
    render(<StatusBadge status="???" />);
    expect(screen.getByText("???")).toHaveClass("gray");
  });
});

describe("Banner / ExternalModeNotice / Empty", () => {
  it("Banner applies its kind class", () => {
    const { container } = render(<Banner kind="warn">careful</Banner>);
    expect(container.querySelector(".banner.warn")).toBeInTheDocument();
  });
  it("ExternalModeNotice is a warn banner with a bold lead", () => {
    const { container } = render(<ExternalModeNotice lead="Needs managed mode.">why</ExternalModeNotice>);
    expect(container.querySelector(".banner.warn")).toBeInTheDocument();
    expect(screen.getByText("Needs managed mode.").tagName).toBe("STRONG");
  });
  it("Empty shows title, body and action", () => {
    render(<Empty title="Nothing" action={<button>Add</button>}>go add one</Empty>);
    expect(screen.getByText("Nothing")).toBeInTheDocument();
    expect(screen.getByText("go add one")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Add" })).toBeInTheDocument();
  });
});

describe("Copyable", () => {
  it("copies on click", async () => {
    render(<Copyable text="token-123" />);
    await userEvent.click(screen.getByText("token-123"));
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith("token-123");
  });
  it("copies via keyboard (Enter)", async () => {
    render(<Copyable text="kbd" />);
    screen.getByRole("button").focus();
    await userEvent.keyboard("{Enter}");
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith("kbd");
  });
});

describe("TableSkeleton", () => {
  it("renders the requested number of rows", () => {
    const { container } = render(<TableSkeleton rows={3} />);
    expect(container.querySelectorAll(".sk-row")).toHaveLength(3);
  });
});

describe("useAsync", () => {
  it("transitions loading → data and clears error", async () => {
    const { result } = renderHook(() => useAsync(() => Promise.resolve(42), []));
    expect(result.current.loading).toBe(true);
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.data).toBe(42);
    expect(result.current.error).toBeNull();
  });

  it("captures the error message on rejection", async () => {
    const { result } = renderHook(() => useAsync(() => Promise.reject(new Error("boom")), []));
    await waitFor(() => expect(result.current.error).toBe("boom"));
    expect(result.current.data).toBeNull();
  });

  it("reload() re-runs the fetcher", async () => {
    let n = 0;
    const { result } = renderHook(() => useAsync(() => Promise.resolve(++n), []));
    await waitFor(() => expect(result.current.data).toBe(1));
    await act(async () => result.current.reload());
    await waitFor(() => expect(result.current.data).toBe(2));
  });

  it("setData mutates locally without a fetch", async () => {
    const { result } = renderHook(() => useAsync(() => Promise.resolve("a"), []));
    await waitFor(() => expect(result.current.data).toBe("a"));
    act(() => result.current.setData("b"));
    expect(result.current.data).toBe("b");
  });
});
