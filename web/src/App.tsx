import React from "react";
import { NavLink, Navigate, Route, Routes, useLocation, useNavigate } from "react-router-dom";
import { api } from "./api";
import type { User } from "./types";
import { Icon, IconName } from "./icons";
import { useAsync } from "./components";
import { engineColor, engineLabel } from "./lib/status";
import { Auth } from "./pages/Auth";
import { Dashboard } from "./pages/Dashboard";
import { Hosts } from "./pages/Hosts";
import { Certificates } from "./pages/Certificates";
import { Middlewares } from "./pages/Middlewares";
import { AccessLists } from "./pages/AccessLists";
import { Config } from "./pages/Config";
import { Metrics } from "./pages/Metrics";
import { Security } from "./pages/Security";
import { Bans } from "./pages/Bans";
import { Logs } from "./pages/Logs";
import { Settings } from "./pages/Settings";

type NavItem = { to: string; label: string; icon: IconName; end?: boolean };
type NavGroup = { label: string; items: NavItem[] };

const NAV: NavGroup[] = [
  { label: "Overview", items: [{ to: "/", label: "Dashboard", icon: "dashboard", end: true }] },
  { label: "Traffic", items: [
    { to: "/hosts", label: "Hosts", icon: "hosts" },
    { to: "/certificates", label: "Certificates", icon: "certificates" },
    { to: "/middlewares", label: "Middleware", icon: "middleware" },
    { to: "/access-lists", label: "Access Lists", icon: "access" },
  ] },
  { label: "Security", items: [
    { to: "/security", label: "Security", icon: "security" },
    { to: "/bans", label: "Banned IPs", icon: "bans" },
  ] },
  { label: "System", items: [
    { to: "/metrics", label: "Metrics", icon: "metrics" },
    { to: "/config", label: "Config", icon: "config" },
    { to: "/logs", label: "Traefik Logs", icon: "logs" },
    { to: "/settings", label: "Settings", icon: "settings" },
  ] },
];

const TITLES: Record<string, string> = Object.fromEntries(
  NAV.flatMap((g) => g.items).map((i) => [i.to, i.label]),
);

export default function App() {
  const [user, setUser] = React.useState<User | null>(null);
  const [loading, setLoading] = React.useState(true);

  React.useEffect(() => {
    api.me().then(setUser).catch(() => setUser(null)).finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="center-screen muted">Loading…</div>;
  if (!user) return <Auth onAuthed={setUser} />;

  return <Shell user={user} onLogout={() => setUser(null)} />;
}

function Shell({ user, onLogout }: { user: User; onLogout: () => void }) {
  const nav = useNavigate();
  const loc = useLocation();
  const [navOpen, setNavOpen] = React.useState(false);

  React.useEffect(() => { setNavOpen(false); }, [loc.pathname]);

  const logout = async () => { await api.logout(); onLogout(); nav("/"); };
  const title = TITLES[loc.pathname] ?? "xgress";
  const initial = (user.name || user.email || "?").trim().charAt(0).toUpperCase();

  return (
    <div className={`app${navOpen ? " nav-open" : ""}`}>
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark"><Icon name="shield" size={18} /></span>
          <span className="brand-name">xgress<small>proxy manager</small></span>
        </div>
        <nav className="nav">
          {NAV.map((group) => (
            <div className="nav-group" key={group.label}>
              <div className="nav-group-label">{group.label}</div>
              {group.items.map((item) => (
                <NavLink key={item.to} to={item.to} end={item.end}>
                  <Icon name={item.icon} size={17} />
                  {item.label}
                </NavLink>
              ))}
            </div>
          ))}
        </nav>
        <div className="user-chip">
          <span className="avatar">{initial}</span>
          <span className="who">
            <b>{user.name || user.email}</b>
            <span>{user.role}</span>
          </span>
          <button className="icon-btn" onClick={logout} aria-label="Sign out" title="Sign out">
            <Icon name="logout" size={17} />
          </button>
        </div>
      </aside>

      <main className="main">
        <header className="topbar">
          <button className="icon-btn topbar-toggle" onClick={() => setNavOpen((v) => !v)} aria-label="Toggle navigation">
            <Icon name="panelLeft" size={18} />
          </button>
          <h1>{title}</h1>
          <div className="spacer" />
          <EngineStatus />
        </header>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/hosts" element={<Hosts />} />
          <Route path="/certificates" element={<Certificates />} />
          <Route path="/middlewares" element={<Middlewares />} />
          <Route path="/access-lists" element={<AccessLists />} />
          <Route path="/security" element={<Security />} />
          <Route path="/bans" element={<Bans />} />
          <Route path="/metrics" element={<Metrics />} />
          <Route path="/config" element={<Config />} />
          <Route path="/logs" element={<Logs />} />
          <Route path="/settings" element={<Settings user={user} />} />
          <Route path="*" element={<Navigate to="/" />} />
        </Routes>
      </main>
    </div>
  );
}

// Compact, always-visible engine state in the top bar — the system's pulse.
function EngineStatus() {
  const status = useAsync(() => api.traefikStatus(), []);
  React.useEffect(() => {
    const t = setInterval(status.reload, 8000);
    return () => clearInterval(t);
  }, [status.reload]);

  const s = status.data;
  if (!s) return null;
  const color = engineColor(s.state);
  const label = engineLabel(s.state, s.managed);
  return (
    <NavLink to="/" className={`badge dot ${color}`} title="Traefik engine — open dashboard" style={{ textDecoration: "none" }}>
      {label}
    </NavLink>
  );
}
