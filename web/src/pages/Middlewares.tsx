import React from "react";
import { api, ApiErr } from "../api";
import type { CatalogEntry, Middleware } from "../types";
import { Empty, Field, Modal, useAsync } from "../components";
import { Icon } from "../icons";

export function Middlewares() {
  const mws = useAsync(() => api.listMiddlewares(), []);
  const catalog = useAsync(() => api.middlewareCatalog(), []);
  const [editing, setEditing] = React.useState<Middleware | "new" | null>(null);

  const del = async (id: string) => { if (confirm("Delete middleware?")) { await api.deleteMiddleware(id); mws.reload(); } };

  return (
    <div className="content">
      <div className="content-actions">
        <button className="btn" onClick={() => setEditing("new")}><Icon name="plus" size={16} />Add middleware</button>
      </div>
      <div className="card flush">
        {mws.data && mws.data.length === 0 && (
          <Empty icon="middleware" title="No middleware yet"
            action={<button className="btn" onClick={() => setEditing("new")}><Icon name="plus" size={16} />Add middleware</button>}>
            Add auth, rate limiting, headers, forward-auth and more — then attach them to hosts.
          </Empty>
        )}
        {mws.data && mws.data.length > 0 && (
          <div className="table-wrap">
            <table>
              <thead><tr><th>Name</th><th>Type</th><th>Config</th><th></th></tr></thead>
              <tbody>
                {mws.data.map((m) => (
                  <tr key={m.id}>
                    <td><strong>{m.name}</strong></td>
                    <td><span className="badge blue">{m.type}</span></td>
                    <td><code style={{ fontSize: "var(--t-sm)", color: "var(--muted)" }}>{JSON.stringify(m.params).slice(0, 64)}</code></td>
                    <td className="t-right">
                      <span className="row-acts">
                        <button className="row-act" title="Edit" onClick={() => setEditing(m)}><Icon name="edit" size={16} /></button>
                        <button className="row-act danger" title="Delete" onClick={() => del(m.id)}><Icon name="trash" size={16} /></button>
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
      {editing && (
        <MiddlewareModal mw={editing === "new" ? null : editing} catalog={catalog.data ?? []}
          onClose={() => setEditing(null)} onSaved={() => { setEditing(null); mws.reload(); }} />
      )}
    </div>
  );
}

type BAUser = { username: string; password: string; line?: string };

function MiddlewareModal({ mw, catalog, onClose, onSaved }: {
  mw: Middleware | null; catalog: CatalogEntry[]; onClose: () => void; onSaved: () => void;
}) {
  const [name, setName] = React.useState(mw?.name ?? "");
  const [type, setType] = React.useState(mw?.type ?? (catalog[0]?.type ?? "headers"));
  const entry = catalog.find((c) => c.type === type);
  const guided = !!entry?.fields && entry.fields.length > 0;

  const [raw, setRaw] = React.useState(!guided);
  const [paramsText, setParamsText] = React.useState(JSON.stringify(mw?.params ?? {}, null, 2));
  // Guided field values (one entry per catalog field).
  const [fieldVals, setFieldVals] = React.useState<Record<string, any>>(mw?.params ?? {});
  const [baUsers, setBaUsers] = React.useState<BAUser[]>(
    ((mw?.params?.users as string[]) ?? []).map((l) => ({ username: String(l).split(":")[0], password: "", line: String(l) })),
  );
  const [error, setError] = React.useState("");
  const [issues, setIssues] = React.useState<{ field: string; message: string }[]>([]);
  const [busy, setBusy] = React.useState(false);

  React.useEffect(() => {
    // When switching type, reset guided values; keep when editing existing mw.
    if (!mw) { setFieldVals({}); setBaUsers([]); setParamsText("{}"); setRaw(!(catalog.find((c) => c.type === type)?.fields?.length)); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [type]);

  const setField = (k: string, v: any) => setFieldVals((c) => ({ ...c, [k]: v }));

  const buildParams = async (): Promise<Record<string, unknown>> => {
    if (raw) return JSON.parse(paramsText || "{}");
    const params: Record<string, unknown> = {};
    for (const f of entry?.fields ?? []) {
      if (f.type === "users") {
        const lines: string[] = [];
        for (const u of baUsers) {
          if (!u.username) continue;
          if (u.password) {
            const { line } = await api.htpasswd({ username: u.username, password: u.password });
            lines.push(line);
          } else if (u.line) {
            lines.push(u.line);
          }
        }
        if (lines.length) params[f.key] = lines;
      } else if (f.type === "list") {
        const v = fieldVals[f.key];
        const arr = Array.isArray(v) ? v : String(v ?? "").split("\n").map((s) => s.trim()).filter(Boolean);
        if (arr.length) params[f.key] = arr;
      } else if (f.type === "number") {
        if (fieldVals[f.key] !== undefined && fieldVals[f.key] !== "") params[f.key] = Number(fieldVals[f.key]);
      } else if (f.type === "bool") {
        if (fieldVals[f.key]) params[f.key] = true;
      } else {
        if (fieldVals[f.key]) params[f.key] = fieldVals[f.key];
      }
    }
    return params;
  };

  const submit = async () => {
    setError(""); setIssues([]); setBusy(true);
    try {
      const params = await buildParams();
      const body = { name, type, params };
      if (mw) await api.updateMiddleware(mw.id, body);
      else await api.createMiddleware(body);
      onSaved();
    } catch (err) {
      if (err instanceof SyntaxError) { setError("Params must be valid JSON"); }
      else {
        if (err instanceof ApiErr && err.issues) setIssues(err.issues);
        setError((err as Error).message);
      }
    } finally { setBusy(false); }
  };

  const listVal = (k: string) => {
    const v = fieldVals[k];
    return Array.isArray(v) ? v.join("\n") : (v ?? "");
  };

  return (
    <Modal title={mw ? "Edit middleware" : "Add middleware"} onClose={onClose}>
      <Field label="Name"><input value={name} onChange={(e) => setName(e.target.value)} placeholder="my-auth" /></Field>
      <Field label="Type" help={entry?.description}>
        <select value={type} onChange={(e) => setType(e.target.value)} disabled={!!mw}>
          {catalog.map((c) => <option key={c.type} value={c.type}>{c.label} ({c.type})</option>)}
          {!catalog.find((c) => c.type === type) && <option value={type}>{type}</option>}
        </select>
      </Field>

      <div className="flex between" style={{ marginBottom: 8 }}>
        <label style={{ margin: 0 }}>Parameters</label>
        {guided && <button className="btn ghost small" onClick={() => setRaw((v) => !v)}>{raw ? "Guided form" : "Edit as JSON"}</button>}
      </div>

      {!raw && guided && (entry?.fields ?? []).map((f) => (
        <div className="field" key={f.key}>
          {f.type === "bool" ? (
            <label className="check"><input type="checkbox" checked={!!fieldVals[f.key]} onChange={(e) => setField(f.key, e.target.checked)} /> {f.label}</label>
          ) : f.type === "users" ? (
            <>
              <label>{f.label}</label>
              <div className="stack" style={{ marginBottom: 8 }}>
                {baUsers.map((u, i) => (
                  <div className="flex gap-sm" key={i}>
                    <input placeholder="username" value={u.username} onChange={(e) => { const n = [...baUsers]; n[i] = { ...n[i], username: e.target.value }; setBaUsers(n); }} />
                    <input type="password" placeholder={u.line ? "(unchanged)" : "password"} value={u.password} onChange={(e) => { const n = [...baUsers]; n[i] = { ...n[i], password: e.target.value }; setBaUsers(n); }} />
                    <button className="row-act danger" title="Remove" onClick={() => setBaUsers(baUsers.filter((_, j) => j !== i))}><Icon name="close" size={16} /></button>
                  </div>
                ))}
              </div>
              <button className="btn secondary small" onClick={() => setBaUsers([...baUsers, { username: "", password: "" }])}><Icon name="plus" size={15} />Add user</button>
            </>
          ) : f.type === "list" ? (
            <>
              <label>{f.label}</label>
              <textarea rows={3} value={listVal(f.key)} onChange={(e) => setField(f.key, e.target.value)} placeholder="one per line" />
            </>
          ) : (
            <>
              <label>{f.label}</label>
              <input type={f.type === "number" ? "number" : "text"} value={fieldVals[f.key] ?? ""} onChange={(e) => setField(f.key, e.target.value)} />
            </>
          )}
          {f.help && <span className="field-help">{f.help}</span>}
        </div>
      ))}

      {(raw || !guided) && (
        <>
          <div className="flex between" style={{ marginBottom: 6 }}>
            <span className="muted" style={{ fontSize: "var(--t-sm)" }}>Raw JSON</span>
            {entry && <button className="btn ghost small" onClick={() => setParamsText(JSON.stringify(entry.example, null, 2))}>Use example</button>}
          </div>
          <textarea className="code" rows={7} value={paramsText} onChange={(e) => setParamsText(e.target.value)} />
        </>
      )}

      <p className="muted" style={{ fontSize: "var(--t-sm)", marginTop: 10 }}>Validated against the real Traefik <span className="tag">{type}</span> struct on save — unknown fields are rejected.</p>
      {issues.map((is, i) => <div className="error" key={i}>{is.message}</div>)}
      {error && issues.length === 0 && <div className="error">{error}</div>}
      <div className="modal-actions">
        <button className="btn secondary" onClick={onClose}>Cancel</button>
        <button className={`btn${busy ? " loading" : ""}`} onClick={submit} disabled={busy}>Save</button>
      </div>
    </Modal>
  );
}
