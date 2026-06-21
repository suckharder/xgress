import React from "react";
import { api } from "../api";
import type { User } from "../types";
import { Field } from "../components";
import { Icon } from "../icons";

export function Auth({ onAuthed }: { onAuthed: (u: User) => void }) {
  const [needsSetup, setNeedsSetup] = React.useState<boolean | null>(null);
  React.useEffect(() => {
    api.setupStatus().then((s) => setNeedsSetup(s.needsSetup)).catch(() => setNeedsSetup(false));
  }, []);

  if (needsSetup === null) return <div className="center-screen muted">Loading…</div>;
  return (
    <div className="auth-wrap">
      <div className="card auth-card">
        <div className="brand">
          <span className="brand-mark"><Icon name="shield" size={18} /></span>
          <span className="brand-name">xgress<small>proxy manager</small></span>
        </div>
        <h2 className="auth-title">{needsSetup ? "Create your admin account" : "Sign in"}</h2>
        <p className="auth-sub">{needsSetup ? "First run — set up the first administrator." : "Welcome back. Enter your credentials."}</p>
        {needsSetup ? <SetupForm onAuthed={onAuthed} /> : <LoginForm onAuthed={onAuthed} />}
      </div>
    </div>
  );
}

function LoginForm({ onAuthed }: { onAuthed: (u: User) => void }) {
  const [email, setEmail] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [error, setError] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true); setError("");
    try {
      onAuthed(await api.login({ email, password }));
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <form onSubmit={submit}>
      <Field label="Email"><input type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoFocus /></Field>
      <Field label="Password"><input type="password" value={password} onChange={(e) => setPassword(e.target.value)} /></Field>
      {error && <div className="error">{error}</div>}
      <button className={`btn block${busy ? " loading" : ""}`} disabled={busy}>Sign in</button>
    </form>
  );
}

function SetupForm({ onAuthed }: { onAuthed: (u: User) => void }) {
  const [name, setName] = React.useState("");
  const [email, setEmail] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [error, setError] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true); setError("");
    try {
      await api.setup({ name, email, password });
      onAuthed(await api.login({ email, password }));
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <form onSubmit={submit}>
      <Field label="Name"><input value={name} onChange={(e) => setName(e.target.value)} autoFocus /></Field>
      <Field label="Email"><input type="email" value={email} onChange={(e) => setEmail(e.target.value)} /></Field>
      <Field label="Password" help="Minimum 8 characters."><input type="password" value={password} onChange={(e) => setPassword(e.target.value)} /></Field>
      {error && <div className="error">{error}</div>}
      <button className={`btn block${busy ? " loading" : ""}`} disabled={busy}>Create account</button>
    </form>
  );
}
