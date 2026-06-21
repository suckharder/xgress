import React from "react";
import { api } from "../api";
import { Empty, ExternalModeNotice, Toggle, useAsync } from "../components";
import { Icon } from "../icons";
import type { BanConfig } from "../types";

export function Bans() {
  const bans = useAsync(() => api.listBans(), []);
  const cfg = useAsync(() => api.getBanConfig(), []);
  const status = useAsync(() => api.traefikStatus(), []);
  const external = status.data?.managed === false;

  React.useEffect(() => {
    const t = setInterval(bans.reload, 5000);
    return () => clearInterval(t);
  }, [bans.reload]);

  return (
    <div className="content">
      <AutoBanCard cfg={cfg} external={external} />
      <ManualBanForm onAdded={bans.reload} />
      <BanList bans={bans} />
    </div>
  );
}

function AutoBanCard({ cfg, external }: { cfg: ReturnType<typeof useAsync<BanConfig>>; external: boolean }) {
  const c = cfg.data;
  const [saving, setSaving] = React.useState(false);
  const [msg, setMsg] = React.useState("");
  const [draft, setDraft] = React.useState<BanConfig | null>(null);
  React.useEffect(() => { if (c) setDraft(c); }, [c]);

  if (!draft) return <div className="card"><div className="sk sk-row" style={{ width: "40%" }} /></div>;

  const save = async (next: BanConfig) => {
    setSaving(true); setMsg("");
    try {
      const saved = await api.setBanConfig(next);
      setDraft(saved);
      setMsg("Saved.");
    } catch (e: any) {
      setMsg(e.message || "Failed to save.");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="card">
      <div className="card-head">
        <span className="card-title">Automatic banning <span className="muted" style={{ fontWeight: 400, fontSize: "var(--t-sm)" }}>fail2ban-style</span></span>
        <label className="check" style={{ alignItems: "center" }}>
          <Toggle checked={draft.enabled} disabled={saving || external} onChange={(v) => save({ ...draft, enabled: v })} />
          {draft.enabled ? "Enabled" : "Disabled"}
        </label>
      </div>
      {external && (
        <div style={{ margin: "12px 0 4px" }}>
          <ExternalModeNotice lead="Automatic banning needs managed (single-container) mode.">
            xgress detects offenders from the supervised Traefik’s logs, which aren’t available
            with an external Traefik — so auto-ban can’t fire here. Manual bans below still
            work and are enforced normally.
          </ExternalModeNotice>
        </div>
      )}
      <p className="muted" style={{ margin: "10px 0 14px", fontSize: "var(--t-13)" }}>
        When enabled, an IP that triggers the WAF too many times in a short window is automatically added to the ban list
        below. Bans are enforced instantly at the edge with no Traefik restart, and expire on their own. Requires the WAF
        to be active on the targeted hosts.
      </p>
      <div className="row" style={{ opacity: draft.enabled ? 1 : 0.55 }}>
        <div className="field mb-0">
          <label>Block threshold</label>
          <input type="number" min={1} value={draft.threshold} disabled={!draft.enabled || saving || external}
            onChange={(e) => setDraft({ ...draft, threshold: Number(e.target.value) })} onBlur={() => save(draft)} />
          <span className="field-help">WAF blocks before banning</span>
        </div>
        <div className="field mb-0">
          <label>Within window (seconds)</label>
          <input type="number" min={1} value={draft.windowSec} disabled={!draft.enabled || saving || external}
            onChange={(e) => setDraft({ ...draft, windowSec: Number(e.target.value) })} onBlur={() => save(draft)} />
          <span className="field-help">sliding time window</span>
        </div>
        <div className="field mb-0">
          <label>Ban duration (seconds)</label>
          <input type="number" min={0} value={draft.durationSec} disabled={!draft.enabled || saving || external}
            onChange={(e) => setDraft({ ...draft, durationSec: Number(e.target.value) })} onBlur={() => save(draft)} />
          <span className="field-help">0 = permanent</span>
        </div>
      </div>
      {msg && <div className="muted" style={{ marginTop: 10, fontSize: "var(--t-sm)" }}>{msg}</div>}
    </div>
  );
}

function ManualBanForm({ onAdded }: { onAdded: () => void }) {
  const [ip, setIp] = React.useState("");
  const [reason, setReason] = React.useState("");
  const [duration, setDuration] = React.useState("0");
  const [busy, setBusy] = React.useState(false);
  const [err, setErr] = React.useState("");

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true); setErr("");
    try {
      await api.createBan({ ip: ip.trim(), reason: reason.trim(), durationSec: Number(duration) || 0 });
      setIp(""); setReason(""); setDuration("0");
      onAdded();
    } catch (e: any) {
      setErr(e.message || "Failed to ban.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="card">
      <div className="card-title" style={{ marginBottom: 12 }}>Ban an IP manually</div>
      <form onSubmit={submit} className="flex wrap" style={{ alignItems: "flex-end", gap: 12 }}>
        <div className="field mb-0" style={{ flex: 2, minWidth: 200 }}>
          <label>IP address or CIDR</label>
          <input value={ip} onChange={(e) => setIp(e.target.value)} placeholder="203.0.113.7 or 203.0.113.0/24" required />
        </div>
        <div className="field mb-0" style={{ flex: 2, minWidth: 160 }}>
          <label>Reason (optional)</label>
          <input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="abuse" />
        </div>
        <div className="field mb-0" style={{ flex: 1, minWidth: 110 }}>
          <label>Duration (s)</label>
          <input type="number" min={0} value={duration} onChange={(e) => setDuration(e.target.value)} />
        </div>
        <button className={`btn danger${busy ? " loading" : ""}`} disabled={busy} type="submit"><Icon name="bans" size={16} />Ban</button>
      </form>
      {err && <div className="error">{err}</div>}
    </div>
  );
}

function BanList({ bans }: { bans: ReturnType<typeof useAsync<import("../types").Ban[]>> }) {
  const list = bans.data ?? [];
  const unban = async (ip: string) => {
    await api.deleteBan(ip);
    bans.reload();
  };
  return (
    <div className="card flush">
      <div className="card-head"><span className="card-title">Active bans</span><span className="badge gray t-num">{list.length}</span></div>
      {list.length === 0
        ? <Empty icon="security" title="No IPs are currently banned">Manual and auto-bans appear here. Bans expire on their own unless permanent.</Empty>
        : (
          <div className="table-wrap">
            <table>
              <thead><tr><th>IP / CIDR</th><th>Source</th><th>Reason</th><th>Hits</th><th>Banned</th><th>Expires</th><th></th></tr></thead>
              <tbody>
                {list.map((b) => (
                  <tr key={b.ip}>
                    <td><span className="tag">{b.ip}</span></td>
                    <td><span className={"badge dot " + (b.manual ? "blue" : "amber")}>{b.manual ? "manual" : "auto"}</span></td>
                    <td className="muted">{b.reason || "—"}</td>
                    <td className="t-num">{b.hits || "—"}</td>
                    <td className="muted t-num">{b.createdAt ? new Date(b.createdAt).toLocaleString() : "—"}</td>
                    <td className="muted t-num">{b.expiresAt ? new Date(b.expiresAt).toLocaleString() : "permanent"}</td>
                    <td className="t-right"><button className="btn secondary small" onClick={() => unban(b.ip)}>Unban</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
    </div>
  );
}
