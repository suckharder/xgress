import React from "react";
import { api, ApiErr } from "../api";
import type { DNSProvider } from "../types";
import { Empty, Field, Modal, StatusBadge, useAsync } from "../components";
import { Icon } from "../icons";

export function Certificates() {
  const certs = useAsync(() => api.listCerts(), []);
  const dns = useAsync(() => api.listDNS(), []);
  const [adding, setAdding] = React.useState(false);

  React.useEffect(() => {
    const t = setInterval(certs.reload, 4000);
    return () => clearInterval(t);
  }, [certs.reload]);

  const renew = async (id: string) => { await api.renewCert(id); certs.reload(); };
  const del = async (id: string) => { if (confirm("Delete certificate?")) { await api.deleteCert(id); certs.reload(); } };

  return (
    <div className="content">
      <div className="content-actions">
        <button className="btn" onClick={() => setAdding(true)}><Icon name="plus" size={16} />Request certificate</button>
      </div>
      <div className="card flush">
        {certs.data && certs.data.length === 0 && (
          <Empty icon="certificates" title="No certificates yet"
            action={<button className="btn" onClick={() => setAdding(true)}><Icon name="plus" size={16} />Request certificate</button>}>
            Issue a Let’s Encrypt certificate or upload your own. xgress obtains and renews them — Traefik never restarts.
          </Empty>
        )}
        {certs.data && certs.data.length > 0 && (
          <div className="table-wrap">
            <table>
              <thead><tr><th>Domains</th><th>Type</th><th>Status</th><th>Expires</th><th></th></tr></thead>
              <tbody>
                {certs.data.map((c) => (
                  <tr key={c.id}>
                    <td>
                      <strong className="t-num">{c.domains.join(", ")}</strong>
                      {c.lastError && <div className="error" style={{ fontSize: "var(--t-sm)", margin: "3px 0 0" }}>{c.lastError}</div>}
                    </td>
                    <td><span className="badge gray">{c.type}{c.challengeType ? ` · ${c.challengeType}` : ""}</span></td>
                    <td><StatusBadge status={c.status} /></td>
                    <td className="muted t-num">{c.expiresAt ? new Date(c.expiresAt).toLocaleDateString() : "—"}</td>
                    <td className="t-right">
                      <span className="row-acts">
                        {c.type === "acme" && <button className="row-act" title="Renew now" onClick={() => renew(c.id)}><Icon name="refresh" size={16} /></button>}
                        <button className="row-act danger" title="Delete" onClick={() => del(c.id)}><Icon name="trash" size={16} /></button>
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <DNSProviders dns={dns.data ?? []} reload={dns.reload} />
      {adding && <CertModal dns={dns.data ?? []} onClose={() => setAdding(false)} onSaved={() => { setAdding(false); certs.reload(); }} />}
    </div>
  );
}

function CertModal({ dns, onClose, onSaved }: { dns: DNSProvider[]; onClose: () => void; onSaved: () => void }) {
  const [type, setType] = React.useState<"acme" | "uploaded">("acme");
  const [domains, setDomains] = React.useState("");
  const [challenge, setChallenge] = React.useState("http-01");
  const [dnsId, setDnsId] = React.useState("");
  const [certPem, setCertPem] = React.useState("");
  const [keyPem, setKeyPem] = React.useState("");
  const [error, setError] = React.useState("");
  const [busy, setBusy] = React.useState(false);

  const submit = async () => {
    setBusy(true); setError("");
    try {
      await api.createCert({
        type,
        domains: domains.split(",").map((d) => d.trim()).filter(Boolean),
        challengeType: challenge,
        dnsProviderId: dnsId,
        certPem, keyPem,
      });
      onSaved();
    } catch (err) {
      setError(err instanceof ApiErr ? err.message : (err as Error).message);
    } finally { setBusy(false); }
  };

  return (
    <Modal title="Request certificate" onClose={onClose}>
      <Field label="Type">
        <select value={type} onChange={(e) => setType(e.target.value as "acme" | "uploaded")}>
          <option value="acme">Let's Encrypt (ACME)</option>
          <option value="uploaded">Upload existing</option>
        </select>
      </Field>
      <Field label="Domains" help="Comma separated. Use *.example.com for a wildcard (requires DNS-01).">
        <input value={domains} onChange={(e) => setDomains(e.target.value)} placeholder="example.com, www.example.com" />
      </Field>
      {type === "acme" && (
        <>
          <Field label="Challenge">
            <select value={challenge} onChange={(e) => setChallenge(e.target.value)}>
              <option value="http-01">HTTP-01 (served through Traefik on :80)</option>
              <option value="dns-01">DNS-01 (required for wildcards)</option>
            </select>
          </Field>
          {challenge === "dns-01" && (
            <Field label="DNS provider">
              <select value={dnsId} onChange={(e) => setDnsId(e.target.value)}>
                <option value="">— select —</option>
                {dns.map((d) => <option key={d.id} value={d.id}>{d.name} ({d.provider})</option>)}
              </select>
            </Field>
          )}
        </>
      )}
      {type === "uploaded" && (
        <>
          <Field label="Certificate (PEM, full chain)"><textarea className="code" rows={4} value={certPem} onChange={(e) => setCertPem(e.target.value)} /></Field>
          <Field label="Private key (PEM)"><textarea className="code" rows={4} value={keyPem} onChange={(e) => setKeyPem(e.target.value)} /></Field>
        </>
      )}
      {error && <div className="error">{error}</div>}
      <div className="modal-actions">
        <button className="btn secondary" onClick={onClose}>Cancel</button>
        <button className={`btn${busy ? " loading" : ""}`} onClick={submit} disabled={busy}>Request</button>
      </div>
    </Modal>
  );
}

function DNSProviders({ dns, reload }: { dns: DNSProvider[]; reload: () => void }) {
  const [adding, setAdding] = React.useState(false);
  const del = async (id: string) => { if (confirm("Delete DNS provider?")) { await api.deleteDNS(id); reload(); } };
  return (
    <div className="card">
      <div className="card-head" style={{ marginBottom: dns.length ? 12 : 8 }}>
        <span className="card-title"><Icon name="globe" size={16} />DNS providers <span className="muted" style={{ fontWeight: 400, fontSize: "var(--t-sm)" }}>for DNS-01 / wildcards</span></span>
        <button className="btn secondary small" onClick={() => setAdding(true)}><Icon name="plus" size={15} />Add</button>
      </div>
      {dns.length === 0 && <div className="muted" style={{ fontSize: "var(--t-13)" }}>None configured. Adding one is a runtime change — no Traefik restart.</div>}
      <div className="stack">
        {dns.map((d) => (
          <div className="flex between" key={d.id} style={{ padding: "7px 0", borderTop: "1px solid var(--border)" }}>
            <div className="flex gap-sm"><strong>{d.name}</strong> <span className="tag">{d.provider}</span> <span className="muted" style={{ fontSize: "var(--t-sm)" }}>{d.configKeys.join(", ")}</span></div>
            <button className="row-act danger" title="Delete" onClick={() => del(d.id)}><Icon name="trash" size={16} /></button>
          </div>
        ))}
      </div>
      {adding && <DNSModal onClose={() => setAdding(false)} onSaved={() => { setAdding(false); reload(); }} />}
    </div>
  );
}

const OTHER = "__other__";

function DNSModal({ onClose, onSaved }: { onClose: () => void; onSaved: () => void }) {
  const catalog = useAsync(() => api.dnsCatalog(), []);
  const [name, setName] = React.useState("");
  const [code, setCode] = React.useState("cloudflare");
  const [values, setValues] = React.useState<Record<string, string>>({});
  const [otherCode, setOtherCode] = React.useState("");
  const [otherKeys, setOtherKeys] = React.useState("KEY=value");
  const [error, setError] = React.useState("");
  const [busy, setBusy] = React.useState(false);

  const spec = catalog.data?.find((s) => s.code === code);

  const setVal = (k: string, v: string) => setValues((c) => ({ ...c, [k]: v }));

  const submit = async () => {
    setBusy(true); setError("");
    let provider = code;
    const config: Record<string, string> = {};
    if (code === OTHER) {
      provider = otherCode.trim();
      otherKeys.split("\n").forEach((line) => {
        const idx = line.indexOf("=");
        if (idx > 0) config[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
      });
    } else if (spec) {
      for (const f of spec.fields) {
        const v = (values[f.key] ?? "").trim();
        if (v) config[f.key] = v;
        else if (!f.optional) { setError(`${f.label} is required`); setBusy(false); return; }
      }
    }
    if (!provider) { setError("Provider is required"); setBusy(false); return; }
    try { await api.createDNS({ name: name || provider, provider, config }); onSaved(); }
    catch (err) { setError((err as Error).message); }
    finally { setBusy(false); }
  };

  return (
    <Modal title="Add DNS provider" onClose={onClose}>
      <Field label="Name"><input value={name} onChange={(e) => setName(e.target.value)} placeholder="My Cloudflare account" /></Field>
      <Field label="Provider">
        <select value={code} onChange={(e) => { setCode(e.target.value); setValues({}); }}>
          {catalog.data?.map((s) => <option key={s.code} value={s.code}>{s.label}</option>)}
          <option value={OTHER}>Other (manual)…</option>
        </select>
      </Field>

      {code !== OTHER && spec && (
        <>
          {spec.fields.map((f) => (
            <Field key={f.key} label={`${f.label}${f.optional ? " (optional)" : ""}`} help={f.help}>
              <input
                type={f.secret ? "password" : "text"}
                value={values[f.key] ?? ""}
                onChange={(e) => setVal(f.key, e.target.value)}
                placeholder={f.key}
                autoComplete="off"
              />
            </Field>
          ))}
          <p className="muted" style={{ fontSize: "var(--t-sm)" }}>
            Credentials are encrypted at rest (AES-256-GCM). <a href={spec.docs} target="_blank" rel="noreferrer">Provider docs <Icon name="external" size={12} style={{ verticalAlign: "-1px" }} /></a>
          </p>
        </>
      )}

      {code === OTHER && (
        <>
          <Field label="lego provider code"><input value={otherCode} onChange={(e) => setOtherCode(e.target.value)} placeholder="e.g. dreamhost" /></Field>
          <Field label="Credentials" help="KEY=value, one per line."><textarea className="code" rows={4} value={otherKeys} onChange={(e) => setOtherKeys(e.target.value)} /></Field>
          <p className="muted" style={{ fontSize: "var(--t-sm)" }}>Any of lego's 100+ providers: <a href="https://go-acme.github.io/lego/dns/" target="_blank" rel="noreferrer">go-acme.github.io/lego/dns <Icon name="external" size={12} style={{ verticalAlign: "-1px" }} /></a></p>
        </>
      )}

      {error && <div className="error">{error}</div>}
      <div className="modal-actions">
        <button className="btn secondary" onClick={onClose}>Cancel</button>
        <button className={`btn${busy ? " loading" : ""}`} onClick={submit} disabled={busy}>Save</button>
      </div>
    </Modal>
  );
}
