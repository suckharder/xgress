import React from "react";
import { api } from "../api";
import type { Listener, User } from "../types";
import { Banner, Field, Modal, StatusBadge, useAsync } from "../components";
import { Icon } from "../icons";

export function Settings({ user }: { user: User }) {
  const settings = useAsync(() => api.getSettings(), []);
  const listeners = useAsync(() => api.listListeners(), []);
  const users = useAsync(() => (user.role === "admin" ? api.listUsers() : Promise.resolve([])), []);
  const [form, setForm] = React.useState<Record<string, string>>({});
  const [saved, setSaved] = React.useState(false);

  React.useEffect(() => { if (settings.data) setForm(settings.data); }, [settings.data]);

  const save = async () => { await api.setSettings(form); setSaved(true); setTimeout(() => setSaved(false), 2000); };
  const set = (k: string, v: string) => setForm((c) => ({ ...c, [k]: v }));

  return (
    <div className="content">
      <div className="card">
        <div className="card-title" style={{ marginBottom: 14 }}>ACME / Let's Encrypt</div>
        <Field label="Contact email"><input type="email" value={form["acme.email"] ?? ""} onChange={(e) => set("acme.email", e.target.value)} placeholder="you@example.com" /></Field>
        <label className="check"><input type="checkbox" checked={form["acme.staging"] === "true"} onChange={(e) => set("acme.staging", e.target.checked ? "true" : "false")} /> Use staging CA (for testing, avoids rate limits)</label>

        <div className="card-title" style={{ margin: "22px 0 12px" }}>Traefik options</div>
        <div className="stack">
          <label className="check"><input type="checkbox" checked={form["traefik.accessLog"] !== "false"} onChange={(e) => set("traefik.accessLog", e.target.checked ? "true" : "false")} /> Access log</label>
          <label className="check"><input type="checkbox" checked={form["traefik.metrics"] !== "false"} onChange={(e) => set("traefik.metrics", e.target.checked ? "true" : "false")} /> Prometheus metrics</label>
        </div>
        <div className="flex" style={{ marginTop: 18 }}>
          <button className="btn" onClick={save}>{saved ? <><Icon name="check" size={16} />Saved</> : "Save settings"}</button>
          <span className="muted" style={{ fontSize: "var(--t-sm)" }}>Traefik options apply on next restart.</span>
        </div>
      </div>

      <DefaultSiteCard />
      <TraefikCard />
      <ListenersCard listeners={listeners.data ?? []} reload={listeners.reload} />
      <DockerImportCard />

      {user.role === "admin" && <PluginsCard />}
      {user.role === "admin" && <NotificationsCard />}
      {user.role === "admin" && <RawConfigCard />}
      {user.role === "admin" && <BackupCard />}
      {user.role === "admin" && <UsersCard users={users.data ?? []} reload={users.reload} me={user} />}
    </div>
  );
}

function TraefikCard() {
  const status = useAsync(() => api.traefikStatus(), []);
  const [restarting, setRestarting] = React.useState(false);

  React.useEffect(() => {
    const t = setInterval(status.reload, 5000);
    return () => clearInterval(t);
  }, [status.reload]);

  const restart = async () => {
    if (!confirm("Gracefully restart the Traefik process? Active connections drain first; the container and UI stay up.")) return;
    setRestarting(true);
    try { await api.traefikRestart(); } finally { setTimeout(() => { status.reload(); setRestarting(false); }, 2000); }
  };

  const managed = status.data?.managed ?? false;
  return (
    <div className="card">
      <div className="card-head">
        <span className="card-title">Traefik engine</span>
        {status.data && <StatusBadge status={status.data.state} />}
      </div>
      <div className="muted" style={{ margin: "8px 0 14px", fontSize: "var(--t-13)" }}>
        {managed ? "Managed — supervised child process" : "External — not managed by xgress"}
        {status.data?.pid ? <> · pid <span className="t-num">{status.data.pid}</span></> : ""}
      </div>
      {status.data?.lastError && <div className="error">{status.data.lastError}</div>}
      <div className="flex">
        <button className={`btn secondary${restarting ? " loading" : ""}`} onClick={restart} disabled={restarting || !managed}>
          <Icon name="refresh" size={16} />Restart Traefik
        </button>
        {!managed && <span className="muted" style={{ fontSize: "var(--t-sm)" }}>Restart is only available when xgress supervises Traefik.</span>}
      </div>
    </div>
  );
}

function ListenersCard({ listeners }: { listeners: Listener[]; reload: () => void }) {
  return (
    <div className="card">
      <div className="card-title" style={{ marginBottom: 10 }}>Entrypoints</div>
      <Banner kind="info">
        Entrypoints are the ports Traefik listens on. They’re declared in your compose / env
        (<span className="tag">XGRESS_STREAM_ENTRYPOINTS</span>) and must be published by Docker — so they’re
        read-only here. Add a stream entrypoint, publish the port in compose, then create a Stream Host that uses it.
      </Banner>
      <div className="table-wrap" style={{ border: "1px solid var(--border)", borderRadius: "var(--r)" }}>
        <table>
          <thead><tr><th>Name</th><th>Kind</th><th>Proto</th><th>Port</th></tr></thead>
          <tbody>
            {listeners.map((l) => (
              <tr key={l.name}>
                <td><strong>{l.name}</strong></td>
                <td><span className="badge blue">{l.kind}</span></td>
                <td className="muted">{l.proto}</td><td className="t-num">{l.port}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function UsersCard({ users, reload, me }: { users: User[]; reload: () => void; me: User }) {
  const [adding, setAdding] = React.useState(false);
  const del = async (id: string) => { if (confirm("Delete user?")) { await api.deleteUser(id); reload(); } };
  return (
    <div className="card">
      <div className="card-head" style={{ marginBottom: 12 }}>
        <span className="card-title">Users</span>
        <button className="btn secondary small" onClick={() => setAdding(true)}><Icon name="plus" size={15} />Add user</button>
      </div>
      <div className="table-wrap" style={{ border: "1px solid var(--border)", borderRadius: "var(--r)" }}>
        <table>
          <thead><tr><th>Email</th><th>Name</th><th>Role</th><th></th></tr></thead>
          <tbody>
            {users.map((u) => (
              <tr key={u.id}>
                <td><strong>{u.email}</strong></td><td className="muted">{u.name}</td><td><span className="badge blue">{u.role}</span></td>
                <td className="t-right">{u.id !== me.id && <button className="row-act danger" title="Delete" onClick={() => del(u.id)}><Icon name="trash" size={16} /></button>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {adding && <UserModal onClose={() => setAdding(false)} onSaved={() => { setAdding(false); reload(); }} />}
    </div>
  );
}

function UserModal({ onClose, onSaved }: { onClose: () => void; onSaved: () => void }) {
  const [email, setEmail] = React.useState("");
  const [name, setName] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [role, setRole] = React.useState("viewer");
  const [error, setError] = React.useState("");
  const submit = async () => {
    setError("");
    try { await api.createUser({ email, name, password, role }); onSaved(); }
    catch (err) { setError((err as Error).message); }
  };
  return (
    <Modal title="Add user" onClose={onClose}>
      <Field label="Email"><input type="email" value={email} onChange={(e) => setEmail(e.target.value)} /></Field>
      <Field label="Name"><input value={name} onChange={(e) => setName(e.target.value)} /></Field>
      <Field label="Password" help="Minimum 8 characters."><input type="password" value={password} onChange={(e) => setPassword(e.target.value)} /></Field>
      <Field label="Role"><select value={role} onChange={(e) => setRole(e.target.value)}><option value="admin">Admin</option><option value="operator">Operator</option><option value="viewer">Viewer</option></select></Field>
      {error && <div className="error">{error}</div>}
      <div className="modal-actions">
        <button className="btn secondary" onClick={onClose}>Cancel</button>
        <button className="btn" onClick={submit}>Create</button>
      </div>
    </Modal>
  );
}

function DefaultSiteCard() {
  const ds = useAsync(() => api.getDefaultSite(), []);
  const [form, setForm] = React.useState<Record<string, string>>({});
  const [saved, setSaved] = React.useState(false);
  React.useEffect(() => { if (ds.data) setForm(ds.data); }, [ds.data]);
  const set = (k: string, v: string) => setForm((c) => ({ ...c, [k]: v }));
  const save = async () => { await api.setDefaultSite(form); setSaved(true); setTimeout(() => setSaved(false), 2000); };
  const mode = form.mode || "404";
  return (
    <div className="card">
      <div className="card-title" style={{ marginBottom: 10 }}>Default site <span className="muted" style={{ fontWeight: 400, fontSize: "var(--t-sm)" }}>unknown hosts</span></div>
      <Banner kind="info">What to serve when a request hits a domain with no matching host.</Banner>
      <Field label="Behavior">
        <select value={mode} onChange={(e) => set("mode", e.target.value)}>
          <option value="404">404 page</option>
          <option value="welcome">Welcome placeholder page</option>
          <option value="redirect">Redirect to a URL</option>
          <option value="custom">Custom HTML page</option>
          <option value="close">No response (close connection)</option>
          <option value="off">Disabled (let Traefik 404)</option>
        </select>
      </Field>
      {mode === "redirect" && <Field label="Redirect to"><input value={form.redirectTo ?? ""} onChange={(e) => set("redirectTo", e.target.value)} placeholder="https://example.com" /></Field>}
      {mode === "custom" && (
        <>
          <Field label="Status code"><input type="number" value={form.statusCode ?? "200"} onChange={(e) => set("statusCode", e.target.value)} /></Field>
          <Field label="HTML"><textarea className="code" rows={5} value={form.html ?? ""} onChange={(e) => set("html", e.target.value)} placeholder="<h1>Nothing here</h1>" /></Field>
        </>
      )}
      <button className="btn" onClick={save}>{saved ? <><Icon name="check" size={16} />Saved</> : "Save"}</button>
    </div>
  );
}

function DockerImportCard() {
  const disc = useAsync(() => api.dockerDiscover().catch(() => []), []);
  const [sel, setSel] = React.useState<Record<string, boolean>>({});
  const [msg, setMsg] = React.useState("");
  const items = disc.data ?? [];
  const importSel = async () => {
    const names = Object.keys(sel).filter((n) => sel[n]);
    if (!names.length) return;
    const res = await api.dockerImport(names);
    setMsg(`Imported ${res.imported} host(s) (disabled — review and enable them in Hosts).`);
    disc.reload();
  };
  return (
    <div className="card">
      <div className="card-title" style={{ marginBottom: 10 }}>Import from Docker labels</div>
      <Banner kind="info">Discovers routers Traefik learned from Docker labels. Imported hosts are created <strong>disabled</strong> so you can review them.</Banner>
      {disc.error && <div className="muted" style={{ fontSize: "var(--t-13)" }}>Traefik API unavailable.</div>}
      {items.length === 0 && !disc.error && <div className="muted" style={{ fontSize: "var(--t-13)" }}>No Docker-label routers discovered.</div>}
      <div className="stack">
        {items.map((r: any) => (
          <label className="check" key={r.name}>
            <input type="checkbox" checked={!!sel[r.name]} onChange={(e) => setSel((c) => ({ ...c, [r.name]: e.target.checked }))} />
            <span>{r.domains?.join(", ") || r.rule} <span className="muted">→ {r.upstream || r.service}</span></span>
          </label>
        ))}
      </div>
      {items.length > 0 && <button className="btn" style={{ marginTop: 12 }} onClick={importSel}><Icon name="download" size={16} />Import selected</button>}
      {msg && <p className="muted" style={{ fontSize: "var(--t-sm)", marginTop: 8 }}>{msg}</p>}
    </div>
  );
}

function NotificationsCard() {
  const n = useAsync(() => api.getNotifications(), []);
  const [form, setForm] = React.useState<any>({});
  const [msg, setMsg] = React.useState("");
  React.useEffect(() => { if (n.data) setForm(n.data); }, [n.data]);
  const set = (k: string, v: string) => setForm((c: any) => ({ ...c, [k]: v }));
  const save = async () => { await api.setNotifications(form); setMsg("Saved"); setTimeout(() => setMsg(""), 2000); };
  const test = async () => {
    setMsg("Sending…");
    try { await api.testNotification(); setMsg("Test sent ✓"); }
    catch (e) { setMsg("Test failed: " + (e as Error).message); }
  };
  return (
    <div className="card">
      <div className="card-title" style={{ marginBottom: 10 }}>Notifications</div>
      <Banner kind="info">Alerts for certificate renewal failures and successes, via webhook and/or email.</Banner>
      <Field label="Webhook URL (JSON POST)"><input value={form.webhookUrl ?? ""} onChange={(e) => set("webhookUrl", e.target.value)} placeholder="https://hooks.example.com/…" /></Field>
      <div className="row">
        <Field label="Email to"><input type="email" value={form.email ?? ""} onChange={(e) => set("email", e.target.value)} placeholder="alerts@example.com" /></Field>
        <Field label="SMTP host"><input value={form.smtpHost ?? ""} onChange={(e) => set("smtpHost", e.target.value)} /></Field>
      </div>
      <div className="row">
        <Field label="SMTP port"><input value={form.smtpPort ?? ""} onChange={(e) => set("smtpPort", e.target.value)} placeholder="587" /></Field>
        <Field label="SMTP user"><input value={form.smtpUser ?? ""} onChange={(e) => set("smtpUser", e.target.value)} /></Field>
      </div>
      <div className="row">
        <Field label={`SMTP password ${form.hasSmtpPass ? "(set — leave blank to keep)" : ""}`}><input type="password" value={form.smtpPass ?? ""} onChange={(e) => set("smtpPass", e.target.value)} /></Field>
        <Field label="From address"><input value={form.smtpFrom ?? ""} onChange={(e) => set("smtpFrom", e.target.value)} /></Field>
      </div>
      <div className="flex">
        <button className="btn" onClick={save}>Save</button>
        <button className="btn secondary" onClick={test}>Send test</button>
        {msg && <span className="muted" style={{ fontSize: "var(--t-sm)" }}>{msg}</span>}
      </div>
    </div>
  );
}

function RawConfigCard() {
  const rc = useAsync(() => api.getRawConfig(), []);
  const [yaml, setYaml] = React.useState("");
  const [msg, setMsg] = React.useState("");
  const [err, setErr] = React.useState("");
  React.useEffect(() => { if (rc.data) setYaml(rc.data.yaml); }, [rc.data]);
  const save = async () => {
    setErr(""); setMsg("");
    try { await api.setRawConfig(yaml); setMsg("Saved & applied ✓"); setTimeout(() => setMsg(""), 2000); }
    catch (e) { setErr((e as Error).message); }
  };
  return (
    <div className="card">
      <div className="card-title" style={{ marginBottom: 10 }}>Raw dynamic config <span className="muted" style={{ fontWeight: 400, fontSize: "var(--t-sm)" }}>advanced</span></div>
      <Banner kind="warn">Extra Traefik dynamic configuration (YAML) merged into the served config. Validated against the real structs — a bad snippet is rejected and the live config is kept.</Banner>
      <textarea className="code" rows={8} value={yaml} onChange={(e) => setYaml(e.target.value)} placeholder={"http:\n  middlewares:\n    my-mw:\n      compress: {}"} />
      {err && <div className="error">{err}</div>}
      <button className="btn" style={{ marginTop: 12 }} onClick={save}>{msg || "Save & apply"}</button>
    </div>
  );
}

function BackupCard() {
  const fileRef = React.useRef<HTMLInputElement>(null);
  const [msg, setMsg] = React.useState("");
  const restore = async (file: File) => {
    if (!confirm("Restore will REPLACE all hosts, middlewares, access lists, DNS providers and settings with the backup. Continue?")) return;
    const text = await file.text();
    try {
      const res = await api.restore(JSON.parse(text));
      setMsg(`Restored ${res.hosts} hosts, ${res.middlewares} middlewares, ${res.accessLists} access lists.`);
    } catch (e) { setMsg("Restore failed: " + (e as Error).message); }
  };
  return (
    <div className="card">
      <div className="card-title" style={{ marginBottom: 10 }}>Backup &amp; restore</div>
      <Banner kind="info">Logical export/import of hosts, middleware, access lists, DNS providers and settings. Same-instance restore (DNS credentials are tied to this install’s secret key).</Banner>
      <div className="flex wrap">
        <a className="btn" href="/api/backup"><Icon name="download" size={16} />Download backup</a>
        <button className="btn secondary" onClick={() => fileRef.current?.click()}><Icon name="upload" size={16} />Restore from file…</button>
        <input ref={fileRef} type="file" accept="application/json" style={{ display: "none" }} onChange={(e) => e.target.files?.[0] && restore(e.target.files[0])} />
      </div>
      {msg && <p className="muted" style={{ fontSize: "var(--t-sm)", marginTop: 8 }}>{msg}</p>}
    </div>
  );
}

function PluginsCard() {
  const p = useAsync(() => api.getPlugins(), []);
  const status = useAsync(() => api.traefikStatus(), []);
  const external = status.data?.managed === false; // external Traefik: xgress can't restart it
  const [waf, setWaf] = React.useState(false);
  const [ruleset, setRuleset] = React.useState("curated");
  const [cache, setCache] = React.useState(false);
  const [directives, setDirectives] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const [msg, setMsg] = React.useState("");
  const initialWaf = React.useRef(false); // last-saved global WAF enable state
  React.useEffect(() => {
    if (p.data) {
      setWaf(!!p.data.wafEnabled);
      initialWaf.current = !!p.data.wafEnabled;
      setRuleset(p.data.wafRuleset || "curated");
      setCache(!!p.data.cacheEnabled);
      setDirectives((p.data.wafDirectives || []).join("\n"));
    }
  }, [p.data]);
  const save = async () => {
    setBusy(true);
    // Only toggling the global WAF enable/disable restarts Traefik (it loads the
    // plugin at startup). Ruleset/rule/cache changes are an instant hot-reload.
    const willRestart = waf !== initialWaf.current;
    setMsg(willRestart && !external ? "Applying — Traefik restarts to load/unload the WAF plugin…" : "Applying…");
    try {
      await api.setPlugins({ wafEnabled: waf, wafRuleset: ruleset, cacheEnabled: cache, wafDirectives: directives.split("\n").filter((l) => l.trim()) });
      initialWaf.current = waf;
      if (willRestart && external) {
        setMsg("Saved — restart the external Traefik to load/unload the WAF plugin."); setTimeout(() => setMsg(""), 6000);
      } else {
        setMsg("Saved ✓"); setTimeout(() => setMsg(""), 3000);
      }
    } catch (e) { setMsg("Failed: " + (e as Error).message); }
    finally { setBusy(false); }
  };
  return (
    <div className="card">
      <div className="card-title" style={{ marginBottom: 10 }}><Icon name="shield" size={16} />WAF &amp; server-side cache</div>
      <Banner kind="warn">
        The WAF (Coraza) is <strong>loaded by default</strong> so you can turn it on per host with no extra setup. It’s
        fetched from the Traefik plugin catalog at startup (needs outbound internet once, then cached on the data
        volume). Uncheck to disable it everywhere; otherwise just opt in per host in the host editor.{" "}
        {external
          ? <>Toggling the global switch rewrites Traefik’s static config — <strong>restart the external Traefik</strong> for it to take effect.</>
          : <>Toggling the global switch restarts Traefik to load/unload the plugin.</>}
      </Banner>
      <label className="check" style={{ marginBottom: 4 }}>
        <input type="checkbox" checked={waf} onChange={(e) => setWaf(e.target.checked)} />
        <span><strong>WAF — block common exploits</strong> <span className="muted">— loaded &amp; ready (opt in per host) · {p.data?.wafModule}</span></span>
      </label>
      {waf && (
        <div style={{ margin: "12px 0 4px" }}>
          <Field label="Ruleset">
            <select value={ruleset} onChange={(e) => setRuleset(e.target.value)}>
              <option value="curated">Curated (lightweight, fast)</option>
              <option value="owasp-crs">OWASP Core Rule Set (bundled, full)</option>
            </select>
          </Field>
          {ruleset === "owasp-crs"
            ? <p className="muted" style={{ fontSize: "var(--t-sm)" }}>The full OWASP CRS is bundled into the image and inlined for the WASM plugin (data-file rules resolved to <span className="tag">@pm</span>). More thorough, heavier per request.</p>
            : (
              <Field label="WAF rules" help="Coraza seclang, one directive per line.">
                <textarea className="code" rows={7} value={directives} onChange={(e) => setDirectives(e.target.value)} />
              </Field>
            )}
        </div>
      )}
      <label className="check" style={{ margin: "12px 0 6px" }}>
        <input type="checkbox" checked={cache} onChange={(e) => setCache(e.target.checked)} />
        <span><strong>Server-side HTTP cache</strong> <span className="muted">— enable per host in the host editor</span></span>
      </label>
      <p className="muted" style={{ fontSize: "var(--t-sm)", marginBottom: 12 }}>
        Caches responses in <strong>{p.data?.cacheBackend === "redis" ? "Redis (shared across instances)" : "memory (this instance)"}</strong>
        {" "}— currently <span className="tag">{p.data?.cacheBackend ?? "…"}</span>.
        {p.data?.cacheBackend !== "redis" && <> To use Redis (shared cache), deploy with <span className="tag">XGRESS_REDIS_URL</span> (e.g. <span className="tag">docker-compose.redis.yml</span>).</>}
      </p>
      <div className="flex">
        <button className={`btn${busy ? " loading" : ""}`} onClick={save} disabled={busy}>Save &amp; apply</button>
        {msg && <span className="muted" style={{ fontSize: "var(--t-sm)" }}>{msg}</span>}
      </div>
    </div>
  );
}
