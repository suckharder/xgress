import React from "react";
import { act, render } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { vi } from "vitest";

// Flush pending promises + due timers inside act(). Pair with vi.useFakeTimers().
// `await flush()` settles mount fetches; `await flush(ms)` also fires intervals.
export async function flush(ms = 0) {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(ms);
  });
}

// Pages use NavLink / useNavigate, so they need a Router in context. This wraps
// render() with a MemoryRouter at an optional initial path.
const routerFuture = { v7_startTransition: true, v7_relativeSplatPath: true } as const;

export function renderWithRouter(ui: React.ReactElement, { route = "/" }: { route?: string } = {}) {
  return render(<MemoryRouter initialEntries={[route]} future={routerFuture}>{ui}</MemoryRouter>);
}
