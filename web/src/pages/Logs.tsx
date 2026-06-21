import React from "react";
import { api } from "../api";
import { Empty, ExternalModeNotice, Toggle, useAsync } from "../components";
import { Icon } from "../icons";

export function Logs() {
  const status = useAsync(() => api.traefikStatus(), []);
  const external = status.data?.managed === false;
  const logs = useAsync(() => api.traefikLogs(300), []);
  const [auto, setAuto] = React.useState(true);
  const boxRef = React.useRef<HTMLDivElement>(null);

  React.useEffect(() => {
    if (!auto || external) return; // nothing to poll without a supervised process
    const t = setInterval(logs.reload, 3000);
    return () => clearInterval(t);
  }, [auto, external, logs.reload]);

  React.useEffect(() => {
    if (auto && boxRef.current) boxRef.current.scrollTop = boxRef.current.scrollHeight;
  }, [logs.data, auto]);

  if (external) {
    return (
      <div className="content">
        <ExternalModeNotice lead="Traefik logs need managed (single-container) mode.">
          xgress only captures logs from a Traefik process it supervises. With an external
          Traefik it has no log stream to show.
        </ExternalModeNotice>
        <Empty icon="logs" title="No logs in external mode">
          View Traefik’s output on that container directly — e.g. <span className="tag">docker logs traefik</span>.
        </Empty>
      </div>
    );
  }

  return (
    <div className="content">
      <div className="content-actions" style={{ justifyContent: "space-between" }}>
        <span className="muted" style={{ fontSize: "var(--t-sm)" }}>
          Last {logs.data?.length ?? 0} lines from the supervised Traefik process.
        </span>
        <div className="flex gap-sm">
          <button className="btn secondary small" onClick={logs.reload}><Icon name="refresh" size={15} />Refresh</button>
          <label className="check" style={{ alignItems: "center" }}>
            <Toggle checked={auto} onChange={setAuto} /> Auto-refresh
          </label>
        </div>
      </div>
      <div className="logs" ref={boxRef} style={{ maxHeight: "calc(100vh - 180px)" }}>
        {logs.data && logs.data.length === 0 && <span className="muted">No logs captured yet.</span>}
        {logs.data?.map((l, i) => (
          <div key={i} className={l.level === "error" ? "log-error" : l.level === "warn" ? "log-warn" : ""}>
            <span className="muted">{new Date(l.at).toLocaleTimeString()} </span>
            [{l.level}] {l.message}
          </div>
        ))}
      </div>
    </div>
  );
}
