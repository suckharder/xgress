import "@testing-library/jest-dom/vitest";
import { afterAll, afterEach, beforeAll, beforeEach, vi } from "vitest";
import { cleanup } from "@testing-library/react";
import { server } from "./server";

// jsdom's Blob/File doesn't implement text(); BackupCard reads an uploaded file
// with file.text(). Polyfill via FileReader so the restore flow is testable.
if (typeof Blob.prototype.text !== "function") {
  Blob.prototype.text = function (this: Blob) {
    return new Promise<string>((resolve, reject) => {
      const fr = new FileReader();
      fr.onload = () => resolve(String(fr.result));
      fr.onerror = () => reject(fr.error);
      fr.readAsText(this);
    });
  };
}

// MSW lifecycle. `error` on unhandled means a page hit an endpoint we forgot to
// stub — surfaces contract drift loudly instead of a silent network hang.
beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => {
  cleanup();
  server.resetHandlers();
});
afterAll(() => server.close());

// jsdom doesn't implement these; several components depend on them.
beforeEach(() => {
  // confirm() defaults to "Yes" so destructive flows proceed; tests that need a
  // cancelled confirm override with vi.spyOn(window, "confirm").mockReturnValue(false).
  vi.spyOn(window, "confirm").mockReturnValue(true);

  // Copyable uses navigator.clipboard.writeText. jsdom exposes clipboard as a
  // getter-only prop, so define it rather than assign.
  Object.defineProperty(navigator, "clipboard", {
    configurable: true,
    value: { writeText: vi.fn().mockResolvedValue(undefined) },
  });

  // Logs autoscrolls via scrollHeight/scrollTop; jsdom's scrollHeight is 0 (fine).
  Element.prototype.scrollIntoView = vi.fn();
});
