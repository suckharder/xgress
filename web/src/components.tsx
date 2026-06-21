import React from "react";
import { Icon, IconName } from "./icons";
import { statusColor } from "./lib/status";

export function Toggle({ checked, onChange, disabled }: { checked: boolean; onChange: (v: boolean) => void; disabled?: boolean }) {
  return (
    <label className="toggle">
      <input type="checkbox" checked={checked} disabled={disabled} onChange={(e) => onChange(e.target.checked)} />
      <span className="track" />
    </label>
  );
}

export function Field({ label, help, children }: { label: string; help?: string; children: React.ReactNode }) {
  // Associate the label with its control for accessibility (and so screen readers
  // + tests can find the input by its label). We inject a generated id onto a
  // single element child unless it already has one.
  const autoId = React.useId();
  const child = children as React.ReactElement<{ id?: string }> | undefined;
  const hasSingleElement = React.isValidElement(child);
  const controlId = hasSingleElement ? child!.props.id ?? autoId : undefined;
  return (
    <div className="field">
      <label htmlFor={controlId}>{label}</label>
      {hasSingleElement ? React.cloneElement(child!, { id: controlId }) : children}
      {help && <span className="field-help">{help}</span>}
    </div>
  );
}

// Modal: native-feeling dialog with header + close, Escape-to-close, and focus
// restore. Children carry their own `.modal-actions` footer (flushed by CSS).
export function Modal({ title, children, onClose, wide }: { title: string; children: React.ReactNode; onClose: () => void; wide?: boolean }) {
  const ref = React.useRef<HTMLDivElement>(null);
  React.useEffect(() => {
    const prev = document.activeElement as HTMLElement | null;
    ref.current?.focus();
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    document.addEventListener("keydown", onKey);
    return () => { document.removeEventListener("keydown", onKey); prev?.focus?.(); };
  }, [onClose]);
  return (
    <div className="modal-overlay" onMouseDown={onClose}>
      <div
        className="modal" role="dialog" aria-modal="true" aria-label={title} tabIndex={-1} ref={ref}
        style={wide ? { width: 720 } : undefined}
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className="modal-head">
          <h2>{title}</h2>
          <button className="icon-btn" onClick={onClose} aria-label="Close"><Icon name="close" size={18} /></button>
        </div>
        <div className="modal-body">{children}</div>
      </div>
    </div>
  );
}

// StatusBadge: maps a domain state to a dotted pill with consistent color +
// label. Color never carries meaning alone — the text label is always present.
// The color map lives in lib/status so it's unit-testable and shared.
export function StatusBadge({ status, label }: { status: string; label?: string }) {
  return <span className={`badge dot ${statusColor(status)}`}>{label ?? status}</span>;
}

export function Banner({ kind = "info", children }: { kind?: "info" | "warn" | "danger"; children: React.ReactNode }) {
  const icon: IconName = kind === "info" ? "info" : "alert";
  return (
    <div className={`banner ${kind}`}>
      <Icon name={icon} size={17} />
      <div>{children}</div>
    </div>
  );
}

// ExternalModeNotice — the standard warning for a feature that only works when xgress
// supervises Traefik (managed / single-container). In external-Traefik mode xgress doesn't
// run the process, so anything fed by its log stream or process control is unavailable.
// `lead` is the bold headline; children explain why and what to do instead.
export function ExternalModeNotice({ lead, children }: { lead: string; children?: React.ReactNode }) {
  return (
    <Banner kind="warn">
      <strong>{lead}</strong> {children}
    </Banner>
  );
}

export function Empty({ icon = "info", title, children, action }: { icon?: IconName; title: string; children?: React.ReactNode; action?: React.ReactNode }) {
  return (
    <div className="empty">
      <div className="empty-icon"><Icon name={icon} size={22} /></div>
      <h4>{title}</h4>
      {children && <p>{children}</p>}
      {action}
    </div>
  );
}

// Copyable: a mono value that copies to clipboard on click with a brief tick.
export function Copyable({ text, className }: { text: string; className?: string }) {
  const [done, setDone] = React.useState(false);
  const copy = async () => {
    try { await navigator.clipboard.writeText(text); setDone(true); setTimeout(() => setDone(false), 1100); } catch { /* clipboard unavailable */ }
  };
  return (
    <span className={`tag copyable ${className ?? ""}`} onClick={copy} title="Copy" role="button" tabIndex={0}
      onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && copy()}>
      {text}<Icon name={done ? "check" : "copy"} size={12} />
    </span>
  );
}

export function TableSkeleton({ rows = 4 }: { rows?: number }) {
  return (
    <div className="sk-table">
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="sk sk-row" style={{ width: `${88 - (i % 3) * 14}%` }} />
      ))}
    </div>
  );
}

export function useAsync<T>(fn: () => Promise<T>, deps: unknown[] = []) {
  const [data, setData] = React.useState<T | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const [loading, setLoading] = React.useState(true);
  const reload = React.useCallback(() => {
    setLoading(true);
    fn()
      .then((d) => { setData(d); setError(null); })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  React.useEffect(() => { reload(); }, [reload]);
  return { data, error, loading, reload, setData };
}
