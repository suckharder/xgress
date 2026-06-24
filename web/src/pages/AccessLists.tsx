import React from "react";
import { api } from "../api";
import type { AccessList, AccessListUser } from "../types";
import { Banner, Empty, Field, Modal, Toggle, useAsync } from "../components";
import { Icon } from "../icons";

export function AccessLists() {
  const lists = useAsync(() => api.listAccessLists(), []);
  const [editing, setEditing] = React.useState<AccessList | "new" | null>(null);

  const del = async (id: string) => { if (confirm("Delete access list? Hosts using it lose that protection.")) { await api.deleteAccessList(id); lists.reload(); } };

  return (
    <div className="content">
      <div className="content-actions">
        <button className="btn" onClick={() => setEditing("new")}><Icon name="plus" size={16} />Add access list</button>
      </div>
      <Banner kind="info">
        A reusable bundle of <strong>basic-auth users</strong> and/or an <strong>IP allow-list</strong>. Attach it to any
        host (in the host editor) to protect it. Passwords are hashed (bcrypt) and never stored in plain text.
      </Banner>
      <div className="card flush">
        {lists.data && lists.data.length === 0 && (
          <Empty icon="access" title="No access lists yet"
            action={<button className="btn" onClick={() => setEditing("new")}><Icon name="plus" size={16} />Add access list</button>}>
            Bundle basic-auth users and IP allow-lists, then attach them to hosts.
          </Empty>
        )}
        {lists.data && lists.data.length > 0 && (
          <div className="table-wrap">
            <table>
              <thead><tr><th>Name</th><th>Users</th><th>Allowed IPs</th><th></th></tr></thead>
              <tbody>
                {lists.data.map((a) => (
                  <tr key={a.id}>
                    <td><strong>{a.name}</strong></td>
                    <td className="muted">{a.users.length ? a.users.map((u) => u.username).join(", ") : "—"}</td>
                    <td className="muted">{a.allowIps?.length ? <span className="tag">{a.allowIps.join(", ")}</span> : "any"}</td>
                    <td className="t-right">
                      <span className="row-acts">
                        <button className="row-act" title="Edit" onClick={() => setEditing(a)}><Icon name="edit" size={16} /></button>
                        <button className="row-act danger" title="Delete" onClick={() => del(a.id)}><Icon name="trash" size={16} /></button>
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
      {editing && <AccessListModal acl={editing === "new" ? null : editing} onClose={() => setEditing(null)} onSaved={() => { setEditing(null); lists.reload(); }} />}
    </div>
  );
}

type UserRow = { username: string; password: string; hash?: string };

function AccessListModal({ acl, onClose, onSaved }: { acl: AccessList | null; onClose: () => void; onSaved: () => void }) {
  const [name, setName] = React.useState(acl?.name ?? "");
  const [users, setUsers] = React.useState<UserRow[]>(
    (acl?.users ?? []).map((u: AccessListUser) => ({ username: u.username, password: "", hash: u.hash })),
  );
  const [ips, setIps] = React.useState((acl?.allowIps ?? []).join("\n"));
  const [satisfyAny, setSatisfyAny] = React.useState(!!acl?.satisfyAny);
  const [error, setError] = React.useState("");
  const [busy, setBusy] = React.useState(false);

  const setUser = (i: number, patch: Partial<UserRow>) => {
    const next = [...users]; next[i] = { ...next[i], ...patch }; setUsers(next);
  };

  const submit = async () => {
    setBusy(true); setError("");
    const payload = {
      name,
      users: users.filter((u) => u.username).map((u) => ({ username: u.username, password: u.password, hash: u.hash })),
      allowIps: ips.split("\n").map((s) => s.trim()).filter(Boolean),
      satisfyAny,
    };
    try {
      if (acl) await api.updateAccessList(acl.id, payload);
      else await api.createAccessList(payload);
      onSaved();
    } catch (err) { setError((err as Error).message); }
    finally { setBusy(false); }
  };

  return (
    <Modal title={acl ? "Edit access list" : "Add access list"} onClose={onClose}>
      <Field label="Name"><input value={name} onChange={(e) => setName(e.target.value)} placeholder="staff-only" /></Field>

      <label>Basic-auth users</label>
      <div className="stack" style={{ marginBottom: 10 }}>
        {users.map((u, i) => (
          <div className="flex gap-sm" key={i}>
            <input placeholder="username" value={u.username} onChange={(e) => setUser(i, { username: e.target.value })} />
            <input type="password" placeholder={u.hash ? "(unchanged)" : "password"} value={u.password} onChange={(e) => setUser(i, { password: e.target.value })} />
            <button className="row-act danger" title="Remove" onClick={() => setUsers(users.filter((_, j) => j !== i))}><Icon name="close" size={16} /></button>
          </div>
        ))}
      </div>
      <button className="btn secondary small" style={{ marginBottom: 16 }} onClick={() => setUsers([...users, { username: "", password: "" }])}><Icon name="plus" size={15} />Add user</button>

      <Field label="IP allow-list" help="CIDR, one per line. Empty = allow any.">
        <textarea className="code" rows={3} value={ips} onChange={(e) => setIps(e.target.value)} placeholder={"10.0.0.0/8\n192.168.1.0/24"} />
      </Field>

      <label className="check" style={{ marginBottom: 4 }}>
        <input type="checkbox" checked={satisfyAny} onChange={(e) => setSatisfyAny(e.target.checked)} />
        <span>Satisfy <strong>any</strong> — allow if the client IP is trusted <em>or</em> they authenticate (default: require both)</span>
      </label>

      {error && <div className="error">{error}</div>}
      <div className="modal-actions">
        <button className="btn secondary" onClick={onClose}>Cancel</button>
        <button className={`btn${busy ? " loading" : ""}`} onClick={submit} disabled={busy}>Save</button>
      </div>
    </Modal>
  );
}
