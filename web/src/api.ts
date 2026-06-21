import type {
  AccessList,
  AuditEntry,
  Ban,
  BanConfig,
  CatalogEntry,
  Certificate,
  DNSProvider,
  DNSProviderSpec,
  Host,
  Listener,
  LogLine,
  Middleware,
  Schedule,
  Snapshot,
  TraefikStatus,
  User,
} from "./types";

export class ApiErr extends Error {
  issues?: { field: string; message: string }[];
  status: number;
  constructor(message: string, status: number, issues?: { field: string; message: string }[]) {
    super(message);
    this.status = status;
    this.issues = issues;
  }
}

async function req<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(path, {
    method,
    headers: body ? { "Content-Type": "application/json" } : {},
    body: body ? JSON.stringify(body) : undefined,
    credentials: "same-origin",
  });
  const text = await res.text();
  const data = text ? JSON.parse(text) : null;
  if (!res.ok) {
    throw new ApiErr(data?.error || res.statusText, res.status, data?.issues);
  }
  return data as T;
}

export const api = {
  // auth / setup
  setupStatus: () => req<{ needsSetup: boolean }>("GET", "/api/setup"),
  setup: (b: { email: string; name: string; password: string }) => req<User>("POST", "/api/setup", b),
  login: (b: { email: string; password: string }) => req<User>("POST", "/api/login", b),
  logout: () => req<unknown>("POST", "/api/logout"),
  me: () => req<User>("GET", "/api/me"),

  // hosts
  listHosts: (kind?: string) => req<Host[]>("GET", `/api/hosts${kind ? `?kind=${kind}` : ""}`),
  getHost: (id: string) => req<Host>("GET", `/api/hosts/${id}`),
  createHost: (h: Partial<Host>) => req<Host>("POST", "/api/hosts", h),
  updateHost: (id: string, h: Partial<Host>) => req<Host>("PUT", `/api/hosts/${id}`, h),
  deleteHost: (id: string) => req<unknown>("DELETE", `/api/hosts/${id}`),

  // middlewares
  listMiddlewares: () => req<Middleware[]>("GET", "/api/middlewares"),
  middlewareCatalog: () => req<CatalogEntry[]>("GET", "/api/middleware-catalog"),
  createMiddleware: (m: Partial<Middleware>) => req<Middleware>("POST", "/api/middlewares", m),
  updateMiddleware: (id: string, m: Partial<Middleware>) => req<Middleware>("PUT", `/api/middlewares/${id}`, m),
  deleteMiddleware: (id: string) => req<unknown>("DELETE", `/api/middlewares/${id}`),

  // certificates
  listCerts: () => req<Certificate[]>("GET", "/api/certificates"),
  createCert: (b: unknown) => req<Certificate>("POST", "/api/certificates", b),
  renewCert: (id: string) => req<Certificate>("POST", `/api/certificates/${id}/renew`),
  deleteCert: (id: string) => req<unknown>("DELETE", `/api/certificates/${id}`),

  // dns providers
  listDNS: () => req<DNSProvider[]>("GET", "/api/dns-providers"),
  dnsCatalog: () => req<DNSProviderSpec[]>("GET", "/api/dns-catalog"),
  createDNS: (b: { name: string; provider: string; config: Record<string, string> }) =>
    req<DNSProvider>("POST", "/api/dns-providers", b),
  deleteDNS: (id: string) => req<unknown>("DELETE", `/api/dns-providers/${id}`),

  // listeners (read-only; declared in process config / compose)
  listListeners: () => req<Listener[]>("GET", "/api/listeners"),

  // traefik
  traefikStatus: () => req<TraefikStatus>("GET", "/api/traefik/status"),
  traefikLogs: (n = 200) => req<LogLine[]>("GET", `/api/traefik/logs?n=${n}`),
  traefikRestart: () => req<unknown>("POST", "/api/traefik/restart"),

  // access lists
  listAccessLists: () => req<AccessList[]>("GET", "/api/access-lists"),
  createAccessList: (b: unknown) => req<AccessList>("POST", "/api/access-lists", b),
  updateAccessList: (id: string, b: unknown) => req<AccessList>("PUT", `/api/access-lists/${id}`, b),
  deleteAccessList: (id: string) => req<unknown>("DELETE", `/api/access-lists/${id}`),
  htpasswd: (b: { username: string; password: string }) => req<{ line: string }>("POST", "/api/util/htpasswd", b),

  // default site + raw config
  getDefaultSite: () => req<Record<string, string>>("GET", "/api/default-site"),
  setDefaultSite: (b: Record<string, string>) => req<unknown>("PUT", "/api/default-site", b),
  getRawConfig: () => req<{ yaml: string }>("GET", "/api/raw-config"),
  setRawConfig: (yaml: string) => req<unknown>("PUT", "/api/raw-config", { yaml }),

  // config snapshots / rollback
  configPreview: () => req<{ version: number; hash: string; config: unknown }>("GET", "/api/config/preview"),
  listSnapshots: () => req<Snapshot[]>("GET", "/api/config/snapshots"),
  getSnapshot: (v: number) => req<{ version: number; hash: string; config: unknown }>("GET", `/api/config/snapshots/${v}`),
  rollback: (v: number) => req<{ version: number }>("POST", `/api/config/rollback/${v}`),

  // plugins (WAF + cache)
  getPlugins: () => req<any>("GET", "/api/plugins"),
  setPlugins: (b: unknown) => req<unknown>("PUT", "/api/plugins", b),
  securityMetrics: () => req<any>("GET", "/api/security/metrics"),

  // IP bans (fail2ban-style)
  listBans: () => req<Ban[]>("GET", "/api/bans"),
  createBan: (b: { ip: string; reason?: string; durationSec?: number }) =>
    req<unknown>("POST", "/api/bans", b),
  deleteBan: (ip: string) => req<unknown>("DELETE", `/api/bans/${ip}`),
  getBanConfig: () => req<BanConfig>("GET", "/api/bans-config"),
  setBanConfig: (b: BanConfig) => req<BanConfig>("PUT", "/api/bans-config", b),

  // host schedules
  listSchedules: (hostId: string) => req<Schedule[]>("GET", `/api/hosts/${hostId}/schedules`),
  createSchedule: (hostId: string, b: { action: string; cron: string }) =>
    req<Schedule>("POST", `/api/hosts/${hostId}/schedules`, b),
  deleteSchedule: (id: string) => req<unknown>("DELETE", `/api/schedules/${id}`),

  // metrics / live state
  traefikOverview: () => req<any>("GET", "/api/traefik/overview"),
  traefikRoutersLive: () => req<any[]>("GET", "/api/traefik/routers"),
  traefikServicesLive: () => req<any[]>("GET", "/api/traefik/services"),

  // docker import
  dockerDiscover: () => req<any[]>("GET", "/api/import/docker"),
  dockerImport: (names: string[]) => req<{ imported: number }>("POST", "/api/import/docker", { names }),

  // backup / restore + notifications
  restore: (doc: unknown) => req<any>("POST", "/api/restore", doc),
  getNotifications: () => req<any>("GET", "/api/notifications"),
  setNotifications: (b: unknown) => req<unknown>("PUT", "/api/notifications", b),
  testNotification: () => req<unknown>("POST", "/api/notifications/test"),
  audit: (limit = 200) => req<AuditEntry[]>("GET", `/api/audit?limit=${limit}`),
  listUsers: () => req<User[]>("GET", "/api/users"),
  createUser: (b: unknown) => req<User>("POST", "/api/users", b),
  updateUser: (id: string, b: unknown) => req<User>("PUT", `/api/users/${id}`, b),
  deleteUser: (id: string) => req<unknown>("DELETE", `/api/users/${id}`),
  getSettings: () => req<Record<string, string>>("GET", "/api/settings"),
  setSettings: (b: Record<string, string>) => req<unknown>("PUT", "/api/settings", b),
};
