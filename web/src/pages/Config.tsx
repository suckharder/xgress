import React from "react";
import { api } from "../api";
import type { Snapshot } from "../types";
import { Banner, Empty, Modal, useAsync } from "../components";
import { Icon } from "../icons";
import { diffLines, stringify, type DiffLine } from "../lib/diff";

export function Config() {
  const preview = useAsync(() => api.configPreview(), []);
  const snaps = useAsync(() => api.listSnapshots(), []);
  const [busy, setBusy] = React.useState(false);
  const [diff, setDiff] = React.useState<{ from: number; to: number } | null>(null);

  const rollback = async (v: number) => {
    if (!confirm(`Roll back to config version ${v}? This becomes the live config immediately.`)) return;
    setBusy(true);
    try { await api.rollback(v); } finally { setBusy(false); snaps.reload(); preview.reload(); }
  };

  // The "previous" snapshot is the next-lower version in the (desc-sorted) list.
  const prevOf = (v: number): number | null => {
    const list = snaps.data ?? [];
    const i = list.findIndex((s) => s.version === v);
    return i >= 0 && i + 1 < list.length ? list[i + 1].version : null;
  };

  return (
    <div className="content">
      <Banner kind="info">
        The rendered Traefik configuration xgress serves over the HTTP provider. Every change is snapshotted as
        last-known-good; you can diff against the previous version or roll back to any version (private keys are never shown).
      </Banner>

      <div className="card flush">
        <div className="card-head"><span className="card-title">Snapshots</span></div>
        {snaps.data && snaps.data.length === 0 && <Empty icon="config" title="No snapshots yet">Each configuration change is captured here as a last-known-good snapshot.</Empty>}
        {snaps.data && snaps.data.length > 0 && (
          <div className="table-wrap">
            <table>
              <thead><tr><th>Version</th><th>Created</th><th>Hash</th><th></th></tr></thead>
              <tbody>
                {snaps.data.map((s: Snapshot) => (
                  <tr key={s.version}>
                    <td><strong className="t-num">#{s.version}</strong> {s.current && <span className="badge dot green">live</span>}</td>
                    <td className="muted t-num">{s.createdAt}</td>
                    <td><span className="tag">{s.hash.slice(0, 12)}</span></td>
                    <td className="t-right">
                      <span className="row-acts" style={{ gap: 8 }}>
                        {prevOf(s.version) !== null && (
                          <button className="btn ghost small" onClick={() => setDiff({ from: prevOf(s.version)!, to: s.version })}>Diff</button>
                        )}
                        {!s.current && <button className="btn secondary small" disabled={busy} onClick={() => rollback(s.version)}>Roll back</button>}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="card">
        <div className="card-head" style={{ marginBottom: 12 }}>
          <span className="card-title">Rendered configuration {preview.data && <span className="muted" style={{ fontWeight: 400, fontSize: "var(--t-sm)" }}>· v{preview.data.version}</span>}</span>
          <button className="btn secondary small" onClick={preview.reload}><Icon name="refresh" size={15} />Refresh</button>
        </div>
        {preview.error && <div className="error">{preview.error}</div>}
        {preview.data && (
          <pre className="logs" style={{ maxHeight: 460 }}>{JSON.stringify(preview.data.config, null, 2)}</pre>
        )}
      </div>
      {diff && <DiffModal from={diff.from} to={diff.to} onClose={() => setDiff(null)} />}
    </div>
  );
}

function DiffModal({ from, to, onClose }: { from: number; to: number; onClose: () => void }) {
  const [lines, setLines] = React.useState<DiffLine[] | null>(null);
  const [error, setError] = React.useState("");

  React.useEffect(() => {
    Promise.all([api.getSnapshot(from), api.getSnapshot(to)])
      .then(([a, b]) => setLines(diffLines(stringify(a.config), stringify(b.config))))
      .catch((e) => setError(e.message));
  }, [from, to]);

  const added = lines?.filter((l) => l.type === "add").length ?? 0;
  const removed = lines?.filter((l) => l.type === "del").length ?? 0;

  return (
    <Modal title={`Diff v${from} → v${to}`} onClose={onClose} wide>
      {error && <div className="error">{error}</div>}
      {!lines && !error && <div className="muted">Loading…</div>}
      {lines && (
        <>
          <p className="muted" style={{ fontSize: "var(--t-sm)" }}>
            <span style={{ color: "var(--ok-ink)", fontWeight: 600 }}>+{added} added</span> ·{" "}
            <span style={{ color: "var(--danger-ink)", fontWeight: 600 }}>−{removed} removed</span>
            {added + removed === 0 && " · identical"}
          </p>
          <pre className="logs" style={{ maxHeight: 520 }}>
            {lines.map((l, i) => (
              <div key={i} className={l.type === "add" ? "diff-add" : l.type === "del" ? "diff-del" : ""}>
                {l.type === "add" ? "+ " : l.type === "del" ? "− " : "  "}{l.text}
              </div>
            ))}
          </pre>
        </>
      )}
      <div className="modal-actions">
        <button className="btn" onClick={onClose}>Close</button>
      </div>
    </Modal>
  );
}

