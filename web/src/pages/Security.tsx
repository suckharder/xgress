import React from "react";
import { api } from "../api";
import { Banner, Empty, ExternalModeNotice, useAsync } from "../components";

export function Security() {
  const status = useAsync(() => api.traefikStatus(), []);
  const external = status.data?.managed === false;
  const data = useAsync(() => api.securityMetrics(), []);
  React.useEffect(() => {
    if (external) return; // metrics come from the supervised Traefik's logs
    const t = setInterval(data.reload, 5000);
    return () => clearInterval(t);
  }, [external, data.reload]);

  if (external) {
    return (
      <div className="content">
        <ExternalModeNotice lead="WAF metrics need managed (single-container) mode.">
          The external Traefik still enforces the WAF, but xgress can’t read its logs — so
          these counters would stay at zero even while attacks are being blocked. Check
          blocked requests on the Traefik container.
        </ExternalModeNotice>
        <Empty icon="security" title="Metrics unavailable in external mode">
          WAF enforcement is unaffected — only the live metrics shown here depend on xgress
          supervising Traefik.
        </Empty>
      </div>
    );
  }

  const wafEnabled = data.data?.wafEnabled;
  const m = data.data?.metrics ?? {};
  const series: { hour: string; count: number }[] = m.series ?? [];
  const peak = Math.max(1, ...series.map((p) => p.count));

  return (
    <div className="content">
      {!wafEnabled && (
        <Banner kind="warn">
          The WAF is disabled, so no security events are being collected. Enable it in
          <strong> Settings → WAF &amp; server-side cache</strong>, then turn it on per host.
        </Banner>
      )}
      {wafEnabled && (m.total ?? 0) === 0 && (
        <Banner kind="info">
          WAF is active and watching. No blocked requests recorded yet (since this instance last started).
          Metrics appear here as the WAF blocks attacks.
        </Banner>
      )}

      <div className="stat-grid">
        <Stat v={m.blocked ?? 0} k="Requests blocked" tone={(m.blocked ?? 0) > 0 ? "bad" : undefined} />
        <Stat v={m.total ?? 0} k="Rule detections" />
        <Stat v={(m.topIps ?? []).length} k="Distinct source IPs" />
        <Stat v={(m.categories ?? []).length} k="Attack categories" />
      </div>

      <div className="card">
        <div className="card-title" style={{ marginBottom: 14 }}>Blocks (last 24h)</div>
        <div style={{ display: "flex", alignItems: "flex-end", gap: 3, height: 92 }}>
          {series.map((p, i) => (
            <div key={i} title={`${p.hour}: ${p.count}`} style={{ flex: 1, display: "flex", flexDirection: "column", justifyContent: "flex-end", height: "100%" }}>
              <div style={{ height: `${(p.count / peak) * 100}%`, background: p.count ? "var(--danger)" : "var(--surface-3)", borderRadius: "3px 3px 0 0", minHeight: 3 }} />
            </div>
          ))}
        </div>
        <div className="muted" style={{ fontSize: "var(--t-xs)", marginTop: 6, display: "flex", justifyContent: "space-between" }}>
          <span>{series[0]?.hour}</span><span>now</span>
        </div>
      </div>

      <div className="row" style={{ alignItems: "flex-start" }}>
        <TopList title="Top rules" items={(m.topRules ?? []).map((r: any) => ({ name: r.name, label: r.label, count: r.count }))} mono />
        <TopList title="Attack categories" items={m.categories ?? []} />
      </div>
      <div className="row" style={{ alignItems: "flex-start" }}>
        <TopList title="Top source IPs" items={m.topIps ?? []} mono />
        <TopList title="Top targeted hosts" items={m.topHosts ?? []} />
      </div>

      <div className="card flush">
        <div className="card-head"><span className="card-title">Recent blocked requests</span></div>
        {(m.recent ?? []).length === 0
          ? <Empty icon="security" title="Nothing blocked yet">Blocked requests are listed here as the WAF intercepts them.</Empty>
          : (
            <div className="table-wrap">
              <table>
                <thead><tr><th>Time</th><th>Source</th><th>Host</th><th>Request</th><th>Rule</th><th>Category</th></tr></thead>
                <tbody>
                  {(m.recent ?? []).slice(0, 50).map((e: any, i: number) => (
                    <tr key={i}>
                      <td className="muted t-num">{e.at ? new Date(e.at).toLocaleTimeString() : ""}</td>
                      <td><span className="tag">{e.clientIp || "—"}</span></td>
                      <td className="muted">{e.host || "—"}</td>
                      <td><code style={{ fontSize: "var(--t-sm)", color: "var(--ink-2)" }}>{(e.method || "") + " " + (e.uri || "")}</code></td>
                      <td><span className="tag">{e.ruleId}</span> <span className="muted" style={{ fontSize: "var(--t-sm)" }}>{e.message}</span></td>
                      <td><span className="badge dot red">{e.category}</span></td>
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

function TopList({ title, items, mono }: { title: string; items: { name: string; label?: string; count: number }[]; mono?: boolean }) {
  const max = Math.max(1, ...items.map((i) => i.count));
  return (
    <div className="card">
      <div className="card-title" style={{ marginBottom: 12 }}>{title}</div>
      {items.length === 0 && <div className="muted" style={{ fontSize: "var(--t-13)" }}>No data yet.</div>}
      <div className="stack" style={{ gap: 10 }}>
        {items.map((it, i) => (
          <div key={i}>
            <div className="flex between" style={{ fontSize: "var(--t-13)", marginBottom: 4 }}>
              <span className={mono ? "tag" : ""}>{it.name}{it.label ? <span className="muted" style={{ marginLeft: 6, fontFamily: "var(--font-sans)" }}>{it.label}</span> : null}</span>
              <strong className="t-num">{it.count}</strong>
            </div>
            <div className="meter danger"><i style={{ transform: `scaleX(${it.count / max})` }} /></div>
          </div>
        ))}
      </div>
    </div>
  );
}
