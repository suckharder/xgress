// Typed builders for test data. Each takes a Partial override so tests state only
// what matters. Built off the real contract in ../types so they can't drift.
import type {
  AccessList,
  Ban,
  BanConfig,
  Certificate,
  DNSProvider,
  Host,
  Listener,
  LogLine,
  Middleware,
  Schedule,
  Snapshot,
  TraefikStatus,
  Upstream,
  User,
} from "../types";

let seq = 0;
const id = (p: string) => `${p}-${++seq}`;

export function makeUser(over: Partial<User> = {}): User {
  return {
    id: id("user"),
    email: "admin@example.com",
    name: "Admin",
    role: "admin",
    disabled: false,
    createdAt: "2026-01-01T00:00:00Z",
    updatedAt: "2026-01-01T00:00:00Z",
    ...over,
  };
}

export function makeUpstream(over: Partial<Upstream> = {}): Upstream {
  return { scheme: "http", host: "backend", port: 8080, ...over };
}

export function makeHost(over: Partial<Host> = {}): Host {
  return {
    id: id("host"),
    kind: "proxy",
    enabled: true,
    domains: ["app.example.com"],
    upstreams: [makeUpstream()],
    tls: "none",
    createdAt: "2026-01-01T00:00:00Z",
    updatedAt: "2026-01-01T00:00:00Z",
    ...over,
  };
}

export function makeCert(over: Partial<Certificate> = {}): Certificate {
  return {
    id: id("cert"),
    type: "uploaded",
    domains: ["app.example.com"],
    status: "valid",
    autoRenew: false,
    createdAt: "2026-01-01T00:00:00Z",
    updatedAt: "2026-01-01T00:00:00Z",
    ...over,
  };
}

export function makeMiddleware(over: Partial<Middleware> = {}): Middleware {
  return {
    id: id("mw"),
    name: "compress",
    type: "compress",
    params: {},
    createdAt: "2026-01-01T00:00:00Z",
    updatedAt: "2026-01-01T00:00:00Z",
    ...over,
  };
}

export function makeAccessList(over: Partial<AccessList> = {}): AccessList {
  return {
    id: id("acl"),
    name: "team",
    users: [],
    allowIps: [],
    satisfyAny: false,
    createdAt: "2026-01-01T00:00:00Z",
    updatedAt: "2026-01-01T00:00:00Z",
    ...over,
  };
}

export function makeListener(over: Partial<Listener> = {}): Listener {
  return { name: "web", proto: "tcp", port: 80, kind: "http", builtin: true, ...over };
}

export function makeTraefikStatus(over: Partial<TraefikStatus> = {}): TraefikStatus {
  return { state: "running", pid: 1234, startedAt: "2026-01-01T00:00:00Z", managed: true, ...over };
}

export function makeBan(over: Partial<Ban> = {}): Ban {
  return {
    ip: "203.0.113.7",
    reason: "manual",
    manual: true,
    hits: 0,
    createdAt: "2026-01-01T00:00:00Z",
    expiresAt: null,
    ...over,
  };
}

export function makeBanConfig(over: Partial<BanConfig> = {}): BanConfig {
  return { enabled: true, threshold: 5, windowSec: 60, durationSec: 3600, ...over };
}

export function makeSnapshot(over: Partial<Snapshot> = {}): Snapshot {
  return { version: 1, hash: "abc123", createdAt: "2026-01-01T00:00:00Z", current: true, ...over };
}

export function makeLogLine(over: Partial<LogLine> = {}): LogLine {
  return { at: "2026-01-01T00:00:00Z", level: "info", message: "ready", raw: "ready", ...over };
}

export function makeSchedule(over: Partial<Schedule> = {}): Schedule {
  return {
    id: id("sched"),
    hostId: "host-1",
    action: "disable",
    cron: "0 2 * * *",
    createdAt: "2026-01-01T00:00:00Z",
    ...over,
  };
}

export function makeDNSProvider(over: Partial<DNSProvider> = {}): DNSProvider {
  return {
    id: id("dns"),
    name: "cloudflare",
    provider: "cloudflare",
    configKeys: ["CF_API_TOKEN"],
    createdAt: "2026-01-01T00:00:00Z",
    ...over,
  };
}
