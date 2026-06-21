import React from "react";
import { NavLink } from "react-router-dom";
import { api } from "../api";
import { Banner, StatusBadge, useAsync } from "../components";
import { Icon, IconName } from "../icons";
import { certAttention, since } from "../lib/dashboard";

export function Dashboard() {
  const status = useAsync(() => api.traefikStatus(), []);
  const hosts = useAsync(() => api.listHosts(), []);
  const certs = useAsync(() => api.listCerts(), []);
  const mws = useAsync(() => api.listMiddlewares(), []);
  const bans = useAsync(() => api.listBans().catch(() => []), []);

  React.useEffect(() => {
    const t = setInterval(status.reload, 5000);
    return () => clearInterval(t);
  }, [status.reload]);

  const enabledHosts = hosts.data?.filter((h) => h.enabled).length ?? 0;
  const validCerts = certs.data?.filter((c) => c.status === "valid").length ?? 0;
  const attention = certAttention(certs.data ?? []);
  const engineBad = status.data && status.data.state !== "running";

  return (
    <div className="content">
      <EngineCard status={status.data} />

      <div className="card flush">
        <div className="card-head"><span className="card-title">Resources</span></div>
        <ResourceRow to="/hosts" icon="hosts" label="Proxy & stream hosts"
          value={hosts.data?.length} sub={`${enabledHosts} enabled`} />
        <ResourceRow to="/certificates" icon="certificates" label="Certificates"
          value={certs.data?.length} sub={`${validCerts} valid`} tone={attention.length ? "warn" : undefined} />
        <ResourceRow to="/middlewares" icon="middleware" label="Middleware" value={mws.data?.length} sub="reusable" />
        <ResourceRow to="/bans" icon="bans" label="Banned IPs"
          value={bans.data?.length} sub={bans.data?.length ? "active" : "none"} tone={bans.data?.length ? "warn" : undefined} />
      </div>

      <div className="card">
        <div className="card-title" style={{ marginBottom: 12 }}>
          <Icon name={attention.length || engineBad ? "alert" : "check"} size={17}
            style={{ color: attention.length || engineBad ? "var(--warn-ink)" : "var(--ok-ink)" }} />
          {attention.length || engineBad ? "Needs attention" : "All systems nominal"}
        </div>
        {!attention.length && !engineBad && (
          <p className="muted mb-0">No certificate or engine issues. Configuration is live and hot-reloading.</p>
        )}
        {engineBad && (
          <div className="attn">
            <StatusBadge status={status.data!.state} />
            <span>Traefik engine is <strong>{status.data!.state}</strong>{status.data?.lastError ? ` — ${status.data.lastError}` : ""}.</span>
            <NavLink to="/settings" className="attn-link">Settings<Icon name="arrowRight" size={14} /></NavLink>
          </div>
        )}
        {attention.map((a) => (
          <div className="attn" key={a.id}>
            <StatusBadge status={a.status} label={a.statusLabel} />
            <span><strong className="t-num">{a.domains}</strong> — {a.note}</span>
            <NavLink to="/certificates" className="attn-link">Certificates<Icon name="arrowRight" size={14} /></NavLink>
          </div>
        ))}
      </div>

      <Banner kind="info">
        Configuration is served to Traefik over the HTTP provider and hot-reloads within ~1s — hosts, certificates and
        middleware all apply with <strong>no restart</strong>. Entrypoints and ports are fixed at container startup
        (defined in your compose), so nothing you change here ever restarts Traefik.
      </Banner>
    </div>
  );
}

function EngineCard({ status }: { status: import("../types").TraefikStatus | null }) {
  const uptime = status?.managed ? since(status.startedAt) : "";
  return (
    <div className="card engine-card">
      <div className="engine-main">
        <span className="brand-mark" style={{ width: 38, height: 38, borderRadius: 10 }}><Icon name="shield" size={22} /></span>
        <div>
          <div className="flex gap-sm" style={{ marginBottom: 2 }}>
            <strong style={{ fontSize: "var(--t-md)" }}>Traefik engine</strong>
            {status && <StatusBadge status={status.state} />}
          </div>
          <div className="muted" style={{ fontSize: "var(--t-sm)" }}>
            {status?.managed ? "Managed — supervised child process" : "External — not supervised by xgress"}
            {status?.pid ? <> · pid <span className="t-num">{status.pid}</span></> : ""}
            {uptime && <> · up {uptime}</>}
          </div>
        </div>
      </div>
      {status?.lastError && <div className="error mb-0" style={{ marginTop: 10 }}>{status.lastError}</div>}
    </div>
  );
}

function ResourceRow({ to, icon, label, value, sub, tone }: {
  to: string; icon: IconName; label: string; value?: number; sub: string; tone?: "warn";
}) {
  return (
    <NavLink to={to} className="resource-row">
      <span className="resource-ico"><Icon name={icon} size={18} /></span>
      <span className="resource-label">{label}<small>{sub}</small></span>
      <span className={`resource-val t-num${tone === "warn" ? " warn" : ""}`}>{value ?? "—"}</span>
      <Icon name="chevronRight" size={16} style={{ color: "var(--muted)" }} />
    </NavLink>
  );
}

