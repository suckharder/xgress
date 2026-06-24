import React from "react";
import { api, ApiErr } from "../api";
import type { AccessList, BackendGroup, Certificate, ErrorPage, Host, Listener, Location, Middleware, Upstream } from "../types";
import { Banner, Empty, Field, Modal, Toggle, useAsync } from "../components";
import { Icon } from "../icons";
import { corsWildcardConflict, effWeight, parseDomains, trafficShare, weightSum } from "../lib/hosts";

export function Hosts() {
  const hosts = useAsync(() => api.listHosts(), []);
  const certs = useAsync(() => api.listCerts(), []);
  const mws = useAsync(() => api.listMiddlewares(), []);
  const listeners = useAsync(() => api.listListeners(), []);
  const accessLists = useAsync(() => api.listAccessLists(), []);
  const [editing, setEditing] = React.useState<Host | "new" | null>(null);

  const save = async () => { setEditing(null); hosts.reload(); };
  const toggle = async (h: Host) => { await api.updateHost(h.id, { ...h, enabled: !h.enabled }); hosts.reload(); };
  const del = async (h: Host) => {
    if (!confirm(`Delete host ${h.domains.join(", ")}?`)) return;
    await api.deleteHost(h.id);
    hosts.reload();
  };

  return (
    <div className="content">
      <div className="content-actions">
        <button className="btn" onClick={() => setEditing("new")}><Icon name="plus" size={16} />Add host</button>
      </div>
      {hosts.error && <div className="error">{hosts.error}</div>}
      <div className="card flush">
        {hosts.data && hosts.data.length === 0 && (
          <Empty icon="hosts" title="No hosts yet"
            action={<button className="btn" onClick={() => setEditing("new")}><Icon name="plus" size={16} />Add host</button>}>
            Proxy a domain to a backend, redirect it, or route raw TCP/UDP. Changes hot-reload in ~1s — no restart.
          </Empty>
        )}
        {hosts.data && hosts.data.length > 0 && (
          <div className="table-wrap">
            <table>
              <thead><tr><th>Name / Domains</th><th>Type</th><th>Destination</th><th>TLS</th><th>Enabled</th><th></th></tr></thead>
              <tbody>
                {hosts.data.map((h) => (
                  <tr key={h.id}>
                    <td><strong className="t-num">{h.kind === "stream" ? (h.domains.length ? h.domains.join(", ") : `${h.streamEntryPoint} :${(h.streamProto || "tcp").toUpperCase()}`) : h.domains.join(", ")}</strong></td>
                    <td>
                      {h.kind === "proxy" && <span className="badge blue">proxy</span>}
                      {h.kind === "redirection" && <span className="badge gray">redirect</span>}
                      {h.kind === "stream" && <span className="badge amber">L4 {h.streamProto || "tcp"}</span>}
                    </td>
                    <td className="muted t-num" style={{ fontSize: "var(--t-sm)" }}>
                      {h.kind === "proxy" && h.upstreams?.map((u) => `${u.scheme}://${u.host}:${u.port}`).join(", ")}
                      {h.kind === "redirection" && `→ ${h.redirectTo}`}
                      {h.kind === "stream" && h.upstreams?.[0] && `${h.streamEntryPoint} → ${h.upstreams[0].host}:${h.upstreams[0].port}`}
                    </td>
                    <td>{h.kind === "stream" ? <span className="badge gray">—</span> : h.tls === "none" ? <span className="badge gray">http</span> : <span className="badge dot green">{h.tls}</span>}</td>
                    <td><Toggle checked={h.enabled} onChange={() => toggle(h)} /></td>
                    <td className="t-right">
                      <span className="row-acts">
                        <button className="row-act" title="Edit" onClick={() => setEditing(h)}><Icon name="edit" size={16} /></button>
                        <button className="row-act danger" title="Delete" onClick={() => del(h)}><Icon name="trash" size={16} /></button>
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
        <HostModal
          host={editing === "new" ? null : editing}
          certs={certs.data ?? []}
          middlewares={mws.data ?? []}
          accessLists={accessLists.data ?? []}
          streamEntryPoints={(listeners.data ?? []).filter((l) => l.kind === "stream")}
          onClose={() => setEditing(null)}
          onSaved={save}
        />
      )}
    </div>
  );
}

const EMPTY: Partial<Host> = {
  kind: "proxy", enabled: true, domains: [], tls: "none",
  upstreams: [{ scheme: "http", host: "", port: 80 }],
};

function HostModal({ host, certs, middlewares, accessLists, streamEntryPoints, onClose, onSaved }: {
  host: Host | null; certs: Certificate[]; middlewares: Middleware[]; accessLists: AccessList[]; streamEntryPoints: Listener[]; onClose: () => void; onSaved: () => void;
}) {
  const [h, setH] = React.useState<Partial<Host>>(host ?? EMPTY);
  const [domainsText, setDomainsText] = React.useState((host?.domains ?? []).join(", "));
  const [error, setError] = React.useState("");
  const [issues, setIssues] = React.useState<{ field: string; message: string }[]>([]);
  const [busy, setBusy] = React.useState(false);

  const up = (patch: Partial<Host>) => setH((c) => ({ ...c, ...patch }));
  const setUpstream = (i: number, patch: Partial<Upstream>) => {
    const list = [...(h.upstreams ?? [])];
    list[i] = { ...list[i], ...patch };
    up({ upstreams: list });
  };

  const submit = async () => {
    setBusy(true); setError(""); setIssues([]);
    const domains = parseDomains(domainsText);
    const payload: Partial<Host> = { ...h, domains };
    try {
      if (host) await api.updateHost(host.id, payload);
      else await api.createHost(payload);
      onSaved();
    } catch (err) {
      if (err instanceof ApiErr && err.issues) setIssues(err.issues);
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const isStream = h.kind === "stream";
  const proto = h.streamProto || "tcp";

  // Load-balancing helpers: weights are relative, so show each upstream's live
  // share of traffic. A blank/zero weight counts as 1 (Traefik's default).
  const ups = h.upstreams ?? [];
  const multi = ups.length > 1;
  const share = (u: Upstream) => trafficShare(u, ups);

  const mode = h.serviceMode || "single";
  const single = mode === "single";
  const pluginsA = useAsync(() => api.getPlugins().catch(() => ({})), []);
  const plugins = pluginsA.data as { wafEnabled?: boolean; cacheEnabled?: boolean } | null;

  const actions = (
    <div className="modal-actions">
      <button className="btn secondary" onClick={onClose}>Cancel</button>
      <button className={`btn${busy ? " loading" : ""}`} onClick={submit} disabled={busy}>Save</button>
    </div>
  );

  return (
    <Modal title={host ? "Edit host" : "Add host"} onClose={onClose} wide>
      <Field label="Type">
        <select value={h.kind} onChange={(e) => {
          const kind = e.target.value as Host["kind"];
          up(kind === "stream" ? { kind, tls: "none", streamProto: h.streamProto || "tcp" } : { kind });
        }}>
          <option value="proxy">Proxy host (HTTP/HTTPS, L7)</option>
          <option value="redirection">Redirection</option>
          <option value="stream">Stream host (TCP/UDP, L4)</option>
        </select>
      </Field>

      {isStream && (
        <>
          <div className="row">
            <Field label="Protocol">
              <select value={proto} onChange={(e) => up({ streamProto: e.target.value })}>
                <option value="tcp">TCP</option><option value="udp">UDP</option>
              </select>
            </Field>
            <Field label="Entrypoint (published port)">
              <select value={h.streamEntryPoint ?? ""} onChange={(e) => up({ streamEntryPoint: e.target.value })}>
                <option value="">— select —</option>
                {streamEntryPoints.filter((l) => l.proto === proto).map((l) => (
                  <option key={l.name} value={l.name}>{l.name} (:{l.port}/{l.proto})</option>
                ))}
              </select>
            </Field>
          </div>
          {streamEntryPoints.filter((l) => l.proto === proto).length === 0 && (
            <Banner kind="warn">
              No {proto.toUpperCase()} entrypoints. Add one via <span className="tag">XGRESS_STREAM_ENTRYPOINTS</span> in
              compose and publish the port, then it’ll appear here.
            </Banner>
          )}
          <label>Backend (single destination)</label>
          <div className="flex gap-sm" style={{ marginBottom: 14 }}>
            <input placeholder="host or IP" value={h.upstreams?.[0]?.host ?? ""} onChange={(e) => up({ upstreams: [{ scheme: "tcp", host: e.target.value, port: h.upstreams?.[0]?.port ?? 0 }] })} />
            <input style={{ maxWidth: 110 }} type="number" placeholder="port" value={h.upstreams?.[0]?.port || ""} onChange={(e) => up({ upstreams: [{ scheme: "tcp", host: h.upstreams?.[0]?.host ?? "", port: parseInt(e.target.value) || 0 }] })} />
          </div>
          {proto === "tcp" && (
            <Field label="SNI hostnames" help="Comma separated — required for TLS passthrough.">
              <input value={domainsText} onChange={(e) => setDomainsText(e.target.value)} placeholder="db.example.com (leave blank to match all)" />
            </Field>
          )}
          {proto === "tcp" && (
            <label className="check" style={{ alignItems: "center", marginBottom: 12 }}>
              <Toggle checked={!!h.tlsPassthrough} onChange={(v) => up({ tlsPassthrough: v })} /> <span>TLS passthrough (route by SNI, forward raw TLS — backend terminates it)</span>
            </label>
          )}
          {error && <div className="error">{error}</div>}
          {actions}
        </>
      )}

      {!isStream && (<>
      <Field label="Domain names" help="Comma separated.">
        <input value={domainsText} onChange={(e) => setDomainsText(e.target.value)} placeholder="app.example.com, www.example.com" />
      </Field>

      {h.kind === "proxy" && (
        <>
          <Field label="Traffic mode">
            <select value={mode} onChange={(e) => up({ serviceMode: e.target.value })}>
              <option value="single">Single / load-balanced</option>
              <option value="weighted">Canary / blue-green (weighted)</option>
              <option value="failover">Failover (active / passive)</option>
              <option value="mirroring">Mirroring (shadow traffic)</option>
            </select>
          </Field>
          {single && (<>
          <label>
            {multi ? "Upstreams" : "Upstream"}
            {multi && <span className="muted" style={{ fontWeight: 400 }}> · load-balanced across {ups.length} backends</span>}
          </label>
          <div className="stack" style={{ marginBottom: 10 }}>
            {ups.map((u, i) => (
              <div className="flex gap-sm" key={i}>
                <select style={{ maxWidth: 84 }} value={u.scheme} onChange={(e) => setUpstream(i, { scheme: e.target.value })}>
                  <option>http</option><option>https</option><option>h2c</option>
                </select>
                <input placeholder="host or IP" value={u.host} onChange={(e) => setUpstream(i, { host: e.target.value })} />
                <input style={{ maxWidth: 84 }} type="number" placeholder="port" value={u.port || ""} onChange={(e) => setUpstream(i, { port: parseInt(e.target.value) || 0 })} />
                {multi && (
                  <>
                    <input style={{ maxWidth: 80 }} type="number" min={0} placeholder="weight" title="Relative weight — bigger = more traffic" value={u.weight || ""} onChange={(e) => setUpstream(i, { weight: parseInt(e.target.value) || 0 })} />
                    <span className="muted t-num" style={{ minWidth: 42, textAlign: "right", fontSize: "var(--t-sm)" }} title="Share of traffic">≈{share(u)}%</span>
                    <button className="row-act danger" title="Remove" onClick={() => up({ upstreams: ups.filter((_, j) => j !== i) })}><Icon name="close" size={16} /></button>
                  </>
                )}
              </div>
            ))}
          </div>
          <button className="btn secondary small" style={{ marginBottom: 14 }}
            onClick={() => up({ upstreams: [...ups, { scheme: ups[0]?.scheme ?? "http", host: "", port: 80 }] })}>
            <Icon name="plus" size={15} />Add upstream
          </button>

          {multi && (
            <>
              <p className="muted" style={{ fontSize: "var(--t-sm)", margin: "0 0 12px" }}>
                Weights are <strong>relative</strong> — each backend’s share is its weight ÷ the total. Blank = 1 (even split).
              </p>
              <div className="row">
                <Field label="Health-check path (optional)">
                  <input value={h.healthCheckUrl ?? ""} onChange={(e) => up({ healthCheckUrl: e.target.value })} placeholder="/health" />
                </Field>
                <Field label="Balancing strategy">
                  <select value={h.loadBalancer || "wrr"} onChange={(e) => up({ loadBalancer: e.target.value })}>
                    <option value="wrr">Weighted round-robin</option>
                    <option value="p2c">Power of two choices</option>
                    <option value="leasttime">Least time</option>
                  </select>
                </Field>
              </div>
              <label className="check" style={{ alignItems: "center", marginBottom: 12 }}>
                <Toggle checked={!!h.sticky} onChange={(v) => up({ sticky: v })} /> <span>Sticky sessions (pin clients to one backend via a <span className="tag">xgress_lb</span> cookie)</span>
              </label>
            </>
          )}
          </>)}

          {!single && <BackendGroupsEditor host={h} up={up} mode={mode} />}
          {mode === "weighted" && (
            <label className="check" style={{ alignItems: "center", marginBottom: 12 }}>
              <Toggle checked={!!h.sticky} onChange={(v) => up({ sticky: v })} /> <span>Sticky (pin a client to its assigned version)</span>
            </label>
          )}
          {mode === "failover" && !h.healthCheckUrl && (
            <Field label="Health-check path (required for failover)">
              <input value={h.healthCheckUrl ?? ""} onChange={(e) => up({ healthCheckUrl: e.target.value })} placeholder="/health" />
            </Field>
          )}

          <div className="stack" style={{ marginBottom: 10 }}>
            <label className="check" style={{ alignItems: "center" }}>
              <Toggle checked={!!h.cacheAssets} onChange={(v) => up({ cacheAssets: v })} /> <span>Cache static assets (adds a long <span className="tag">Cache-Control</span> to JS/CSS/images/fonts)</span>
            </label>
            {plugins?.wafEnabled && (
              <label className="check" style={{ alignItems: "center" }}>
                <Toggle checked={!!h.waf} onChange={(v) => up({ waf: v })} /> <span>Block common exploits (WAF)</span>
              </label>
            )}
            {plugins?.cacheEnabled && (
              <label className="check" style={{ alignItems: "center" }}>
                <Toggle checked={!!h.cache} onChange={(v) => up({ cache: v })} /> <span>Server-side cache (responses cached &amp; served by xgress)</span>
              </label>
            )}
          </div>
          <p className="muted" style={{ fontSize: "var(--t-sm)", margin: "0 0 4px" }}>WebSockets are supported automatically — Traefik proxies them with no configuration needed.</p>
        </>
      )}

      {h.kind === "redirection" && (
        <div className="row">
          <Field label="Redirect to (URL)"><input value={h.redirectTo ?? ""} onChange={(e) => up({ redirectTo: e.target.value })} placeholder="https://example.com" /></Field>
          <Field label="Code"><select value={h.redirectCode ?? 308} onChange={(e) => up({ redirectCode: parseInt(e.target.value) })}><option>301</option><option>302</option><option>307</option><option>308</option></select></Field>
        </div>
      )}

      <Field label="TLS">
        <select value={h.tls} onChange={(e) => up({ tls: e.target.value as Host["tls"] })}>
          <option value="none">None (HTTP only)</option>
          <option value="acme">Let's Encrypt (ACME)</option>
          <option value="custom">Custom certificate</option>
        </select>
      </Field>
      {h.tls === "custom" && (
        <Field label="Certificate">
          <select value={h.certificateId ?? ""} onChange={(e) => up({ certificateId: e.target.value })}>
            <option value="">— select —</option>
            {certs.map((c) => <option key={c.id} value={c.id}>{c.domains.join(", ")}</option>)}
          </select>
        </Field>
      )}

      {h.tls !== "none" && (
        <div className="flex" style={{ gap: 24, marginBottom: 14 }}>
          <label className="check" style={{ alignItems: "center" }}><Toggle checked={!!h.forceTls} onChange={(v) => up({ forceTls: v })} /> Force HTTPS</label>
          <label className="check" style={{ alignItems: "center" }}><Toggle checked={!!h.hsts} onChange={(v) => up({ hsts: v })} /> HSTS</label>
        </div>
      )}

      {h.kind === "proxy" && (
        <div style={{ marginBottom: 14 }}>
          <label className="check" style={{ alignItems: "center", marginBottom: h.corsEnabled ? 10 : 0 }}>
            <Toggle checked={!!h.corsEnabled} onChange={(v) => up({ corsEnabled: v })} /> Enable CORS
          </label>
          {h.corsEnabled && (
            <div className="subcard">
              <Field label="Allowed origins (one per line)">
                <textarea
                  rows={3}
                  value={(h.corsAllowOrigins ?? []).join("\n")}
                  placeholder={"https://app.example.com\nhttps://admin.example.com"}
                  onChange={(e) =>
                    up({ corsAllowOrigins: e.target.value.split(/[\n,]/).map((o) => o.trim()).filter(Boolean) })
                  }
                />
              </Field>
              <label className="check" style={{ alignItems: "center" }}><Toggle checked={!!h.corsAllowCredentials} onChange={(v) => up({ corsAllowCredentials: v })} /> Allow credentials (cookies / auth headers)</label>
              {corsWildcardConflict(h.corsEnabled, h.corsAllowCredentials, h.corsAllowOrigins) && (
                <Banner kind="warn">A wildcard origin <span className="tag">*</span> can't be combined with credentials — list explicit origins.</Banner>
              )}
            </div>
          )}
        </div>
      )}

      {accessLists.length > 0 && (
        <Field label="Access lists (auth / IP allow)">
          <select multiple value={h.accessListIds ?? []} style={{ height: 64 }}
            onChange={(e) => up({ accessListIds: Array.from(e.target.selectedOptions).map((o) => o.value) })}>
            {accessLists.map((a) => <option key={a.id} value={a.id}>{a.name}</option>)}
          </select>
        </Field>
      )}

      {middlewares.length > 0 && (
        <Field label="Middleware">
          <select multiple value={h.middlewareIds ?? []} style={{ height: 90 }}
            onChange={(e) => up({ middlewareIds: Array.from(e.target.selectedOptions).map((o) => o.value) })}>
            {middlewares.map((m) => <option key={m.id} value={m.id}>{m.name} ({m.type})</option>)}
          </select>
        </Field>
      )}

      {h.kind === "proxy" && (
        <details className="adv">
          <summary>Advanced: locations, error pages, schedule, raw config</summary>
          <LocationsEditor host={h} up={up} />
          <ErrorPagesEditor host={h} up={up} />
          {host && <SchedulesEditor hostId={host.id} />}
          <Field label="Per-host raw config (YAML)" help="Extra middlewares, namespaced &amp; attached to this host.">
            <textarea className="code" rows={4} value={h.rawYaml ?? ""} onChange={(e) => up({ rawYaml: e.target.value })} placeholder={"http:\n  middlewares:\n    my-headers:\n      headers:\n        customRequestHeaders:\n          X-Custom: hi"} />
          </Field>
        </details>
      )}

      {issues.map((is, i) => <div className="error" key={i}>{is.field}: {is.message}</div>)}
      {error && issues.length === 0 && <div className="error">{error}</div>}
      {actions}
      </>)}
    </Modal>
  );
}

type UpFn = (patch: Partial<Host>) => void;

function LocationsEditor({ host, up }: { host: Partial<Host>; up: UpFn }) {
  const locs = host.locations ?? [];
  const setLoc = (i: number, patch: Partial<Location>) => {
    const next = [...locs];
    next[i] = { ...next[i], ...patch };
    up({ locations: next });
  };
  const setLocUp = (i: number, patch: Partial<Upstream>) => {
    const next = [...locs];
    const u = { ...(next[i].upstreams?.[0] ?? { scheme: "http", host: "", port: 80 }), ...patch };
    next[i] = { ...next[i], upstreams: [u] };
    up({ locations: next });
  };
  return (
    <div style={{ marginBottom: 14 }}>
      <label>Custom locations <span className="muted" style={{ fontWeight: 400 }}>— route a path prefix to a different backend</span></label>
      {locs.map((loc, i) => (
        <div key={i} className="subcard">
          <div className="flex gap-sm" style={{ marginBottom: 8 }}>
            <input placeholder="/api" value={loc.pathPrefix} onChange={(e) => setLoc(i, { pathPrefix: e.target.value })} />
            <input placeholder="backend host" value={loc.upstreams?.[0]?.host ?? ""} onChange={(e) => setLocUp(i, { host: e.target.value })} />
            <input style={{ maxWidth: 90 }} type="number" placeholder="port" value={loc.upstreams?.[0]?.port || ""} onChange={(e) => setLocUp(i, { port: parseInt(e.target.value) || 0 })} />
          </div>
          <div className="flex between">
            <label className="check" style={{ alignItems: "center", fontSize: "var(--t-sm)" }}><Toggle checked={!!loc.stripPrefix} onChange={(v) => setLoc(i, { stripPrefix: v })} /> Strip prefix</label>
            <button className="btn ghost small danger subtle" onClick={() => up({ locations: locs.filter((_, j) => j !== i) })}>Remove</button>
          </div>
        </div>
      ))}
      <button className="btn secondary small" onClick={() => up({ locations: [...locs, { pathPrefix: "", upstreams: [{ scheme: "http", host: "", port: 80 }] }] })}><Icon name="plus" size={15} />Add location</button>
    </div>
  );
}

function ErrorPagesEditor({ host, up }: { host: Partial<Host>; up: UpFn }) {
  const pages = host.errorPages ?? [];
  const setPage = (i: number, patch: Partial<ErrorPage>) => {
    const next = [...pages];
    next[i] = { ...next[i], ...patch };
    up({ errorPages: next });
  };
  return (
    <div style={{ marginBottom: 14 }}>
      <label>Custom error pages <span className="muted" style={{ fontWeight: 400 }}>— serve HTML when the backend returns an error</span></label>
      {pages.map((ep, i) => (
        <div key={i} className="subcard">
          <div className="flex between" style={{ marginBottom: 8 }}>
            <input style={{ maxWidth: 180 }} placeholder="404 or 500-599" value={ep.status} onChange={(e) => setPage(i, { status: e.target.value })} />
            <button className="btn ghost small danger subtle" onClick={() => up({ errorPages: pages.filter((_, j) => j !== i) })}>Remove</button>
          </div>
          <textarea className="code" rows={3} placeholder="<h1>Custom error</h1>" value={ep.html} onChange={(e) => setPage(i, { html: e.target.value })} />
        </div>
      ))}
      <button className="btn secondary small" onClick={() => up({ errorPages: [...pages, { status: "", html: "" }] })}><Icon name="plus" size={15} />Add error page</button>
    </div>
  );
}

function BackendGroupsEditor({ host, up, mode }: { host: Partial<Host>; up: UpFn; mode: string }) {
  const groups = host.backendGroups ?? [];
  const setGroup = (i: number, patch: Partial<BackendGroup>) => {
    const next = [...groups]; next[i] = { ...next[i], ...patch }; up({ backendGroups: next });
  };
  const setGroupUp = (i: number, patch: Partial<Upstream>) => {
    const next = [...groups];
    const u = { ...(next[i].upstreams?.[0] ?? { scheme: "http", host: "", port: 80 }), ...patch };
    next[i] = { ...next[i], upstreams: [u] };
    up({ backendGroups: next });
  };
  const addGroup = () => up({ backendGroups: [...groups, { name: mode === "weighted" ? `v${groups.length + 1}` : groups.length === 0 ? "primary" : mode === "failover" ? "fallback" : "mirror", upstreams: [{ scheme: "http", host: "", port: 80 }], weight: mode === "weighted" ? 1 : undefined, percent: mode === "mirroring" ? 10 : undefined }] });

  const hint = mode === "weighted" ? "Each group gets weight ÷ total of traffic." : mode === "failover" ? "First group is primary; second is the fallback (needs a health-check path)." : "First group is primary; the rest receive a % copy of traffic (client sees only primary).";
  return (
    <div style={{ marginBottom: 14 }}>
      <label>Backend groups <span className="muted" style={{ fontWeight: 400 }}>— {hint}</span></label>
      {groups.map((g, i) => (
        <div key={i} className="subcard">
          <div className="flex gap-sm" style={{ marginBottom: 8 }}>
            <input placeholder="name" value={g.name} onChange={(e) => setGroup(i, { name: e.target.value })} style={{ maxWidth: 120 }} />
            <input placeholder="backend host" value={g.upstreams?.[0]?.host ?? ""} onChange={(e) => setGroupUp(i, { host: e.target.value })} />
            <input style={{ maxWidth: 84 }} type="number" placeholder="port" value={g.upstreams?.[0]?.port || ""} onChange={(e) => setGroupUp(i, { port: parseInt(e.target.value) || 0 })} />
            {mode === "weighted" && <input style={{ maxWidth: 74 }} type="number" placeholder="weight" value={g.weight ?? ""} onChange={(e) => setGroup(i, { weight: parseInt(e.target.value) || 0 })} />}
            {mode === "mirroring" && i > 0 && <input style={{ maxWidth: 74 }} type="number" placeholder="%" value={g.percent ?? ""} onChange={(e) => setGroup(i, { percent: parseInt(e.target.value) || 0 })} />}
          </div>
          <div className="t-right">
            <button className="btn ghost small danger subtle" onClick={() => up({ backendGroups: groups.filter((_, j) => j !== i) })}>Remove</button>
          </div>
        </div>
      ))}
      <button className="btn secondary small" onClick={addGroup}><Icon name="plus" size={15} />Add group</button>
    </div>
  );
}

function SchedulesEditor({ hostId }: { hostId: string }) {
  const scheds = useAsync(() => api.listSchedules(hostId), []);
  const [action, setAction] = React.useState("disable");
  const [cron, setCron] = React.useState("0 2 * * *");
  const [err, setErr] = React.useState("");
  const add = async () => {
    setErr("");
    try { await api.createSchedule(hostId, { action, cron }); scheds.reload(); }
    catch (e) { setErr((e as Error).message); }
  };
  const del = async (id: string) => { await api.deleteSchedule(id); scheds.reload(); };
  return (
    <div style={{ marginBottom: 14 }}>
      <label>Schedule <span className="muted" style={{ fontWeight: 400 }}>— enable/disable on a cron schedule (min hour dom month dow)</span></label>
      <div className="stack" style={{ marginBottom: 8 }}>
        {(scheds.data ?? []).map((s) => (
          <div className="flex between" key={s.id}>
            <span className="flex gap-sm"><span className="badge blue">{s.action}</span> <span className="tag">{s.cron}</span></span>
            <button className="btn ghost small danger subtle" onClick={() => del(s.id)}>Remove</button>
          </div>
        ))}
      </div>
      <div className="flex gap-sm">
        <select value={action} onChange={(e) => setAction(e.target.value)} style={{ maxWidth: 120 }}>
          <option value="disable">disable</option><option value="enable">enable</option>
        </select>
        <input value={cron} onChange={(e) => setCron(e.target.value)} placeholder="0 2 * * *" />
        <button className="btn secondary small" onClick={add}>Add</button>
      </div>
      {err && <div className="error">{err}</div>}
      <p className="muted" style={{ fontSize: "var(--t-xs)", margin: "6px 0 0" }}>Examples: <span className="tag">0 2 * * *</span> daily 02:00 · <span className="tag">0 9 * * 1-5</span> weekdays 09:00</p>
    </div>
  );
}
