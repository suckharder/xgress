import React from "react";
import { api } from "../api";
import { Banner, Empty, useAsync } from "../components";
import { aggregateBackendHealth, filterLiveRouters } from "../lib/metrics";

export function Metrics() {
  const overview = useAsync(() => api.traefikOverview(), []);
  const routers = useAsync(() => api.traefikRoutersLive(), []);
  const services = useAsync(() => api.traefikServicesLive(), []);

  React.useEffect(() => {
    const t = setInterval(() => { overview.reload(); routers.reload(); services.reload(); }, 5000);
    return () => clearInterval(t);
  }, [overview.reload, routers.reload, services.reload]);

  const unavailable = overview.error || routers.error;
  const ov = overview.data;

  // Aggregate backend health from services' serverStatus.
  const { up, down } = aggregateBackendHealth(services.data ?? []);

  const liveRouters = filterLiveRouters(routers.data ?? []);

  return (
    <div className="content">
      <p className="page-intro">Live state read directly from Traefik’s own API — routers, services, and backend health as Traefik sees them right now.</p>
      {unavailable && (
        <Banner kind="warn">
          Traefik’s API is unavailable. It’s exposed on a loopback entrypoint (<span className="tag">XGRESS_TRAEFIK_API_LISTEN</span>);
          this view needs the managed / single-container mode.
        </Banner>
      )}
      {ov && (
        <div className="stat-grid">
          <Stat v={ov.http?.routers?.total ?? "—"} k="HTTP routers" />
          <Stat v={ov.http?.services?.total ?? "—"} k="HTTP services" />
          <Stat v={ov.http?.middlewares?.total ?? "—"} k="Middlewares" />
          <Stat v={`${up}/${up + down}`} k="Backends up" tone={down > 0 ? "warn" : up > 0 ? "ok" : undefined} />
        </div>
      )}

      <div className="card flush">
        <div className="card-head"><span className="card-title">Active routers</span><span className="muted" style={{ fontSize: "var(--t-sm)" }}>{liveRouters.length} routing</span></div>
        {liveRouters.length === 0 ? (
          <Empty icon="metrics" title="No routers reported">When hosts are enabled and Traefik is reachable, its live routers appear here.</Empty>
        ) : (
          <div className="table-wrap">
            <table>
              <thead><tr><th>Router</th><th>Rule</th><th>Service</th><th>Status</th></tr></thead>
              <tbody>
                {liveRouters.map((r: any) => (
                  <tr key={r.name}>
                    <td><strong>{r.name.replace("@http", "")}</strong></td>
                    <td><code style={{ fontSize: "var(--t-sm)", color: "var(--ink-2)" }}>{r.rule}</code></td>
                    <td className="muted">{r.service}</td>
                    <td>{r.status === "enabled"
                      ? <span className="badge dot green">enabled</span>
                      : <span className="badge dot red">{r.status}</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

function Stat({ v, k, tone }: { v: React.ReactNode; k: string; tone?: "ok" | "warn" | "bad" }) {
  return <div className="stat"><div className={`v${tone ? " " + tone : ""}`}>{v}</div><div className="k">{k}</div></div>;
}
