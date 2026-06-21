export type Role = "admin" | "operator" | "viewer";

export interface User {
  id: string;
  email: string;
  name: string;
  role: Role;
  disabled: boolean;
  createdAt: string;
  updatedAt: string;
}

export type HostKind = "proxy" | "redirection" | "dead" | "stream";
export type TLSMode = "none" | "acme" | "custom" | "external";

export interface Upstream {
  scheme: string;
  host: string;
  port: number;
  weight?: number;
}

export interface Location {
  pathPrefix: string;
  upstreams: Upstream[];
  stripPrefix?: boolean;
}

export interface ErrorPage {
  status: string;
  html: string;
}

export interface BackendGroup {
  name: string;
  upstreams: Upstream[];
  weight?: number;
  percent?: number;
}

export interface Schedule {
  id: string;
  hostId: string;
  action: "enable" | "disable";
  cron: string;
  createdAt: string;
}

export interface Host {
  id: string;
  kind: HostKind;
  enabled: boolean;
  domains: string[];
  upstreams?: Upstream[];
  healthCheckUrl?: string;
  loadBalancer?: string; // strategy: wrr | p2c | leasttime
  sticky?: boolean;
  cacheAssets?: boolean;
  serviceMode?: string; // single | weighted | failover | mirroring
  backendGroups?: BackendGroup[];
  waf?: boolean;
  cache?: boolean;
  tlsPassthrough?: boolean;
  locations?: Location[];
  errorPages?: ErrorPage[];
  accessListIds?: string[];
  redirectTo?: string;
  redirectCode?: number;
  redirectKeepPath?: boolean;
  streamProto?: string;
  streamEntryPoint?: string;
  tls: TLSMode;
  certificateId?: string;
  forceTls?: boolean;
  hsts?: boolean;
  corsEnabled?: boolean;
  corsAllowOrigins?: string[];
  corsAllowCredentials?: boolean;
  middlewareIds?: string[];
  rawYaml?: string;
  notes?: string;
  createdAt: string;
  updatedAt: string;
}

export interface AccessListUser {
  username: string;
  hash?: string;
  password?: string;
}
export interface AccessList {
  id: string;
  name: string;
  users: AccessListUser[];
  allowIps: string[];
  satisfyAny: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface CatalogField {
  key: string;
  label: string;
  type: "text" | "number" | "bool" | "list" | "users";
  help?: string;
}

export interface Snapshot {
  version: number;
  hash: string;
  createdAt: string;
  current: boolean;
}

export interface Ban {
  ip: string;
  reason: string;
  manual: boolean;
  hits: number;
  createdAt: string;
  expiresAt?: string | null;
}

export interface BanConfig {
  enabled: boolean;
  threshold: number;
  windowSec: number;
  durationSec: number;
}

export interface Middleware {
  id: string;
  name: string;
  type: string;
  params: Record<string, unknown>;
  createdAt: string;
  updatedAt: string;
}

export interface CatalogEntry {
  type: string;
  label: string;
  description: string;
  example: Record<string, unknown>;
  fields?: CatalogField[];
}

export type CertType = "acme" | "uploaded";
export type CertStatus = "pending" | "valid" | "failed" | "expired";

export interface Certificate {
  id: string;
  type: CertType;
  domains: string[];
  status: CertStatus;
  challengeType?: string;
  dnsProviderId?: string;
  issuedAt?: string;
  expiresAt?: string;
  lastError?: string;
  autoRenew: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface DNSProvider {
  id: string;
  name: string;
  provider: string;
  configKeys: string[];
  createdAt: string;
}

export interface DNSField {
  key: string;
  label: string;
  secret: boolean;
  optional: boolean;
  help?: string;
}

export interface DNSProviderSpec {
  code: string;
  label: string;
  fields: DNSField[];
  docs: string;
}

export interface Listener {
  name: string;
  proto: string;
  port: number;
  kind: "http" | "https" | "stream";
  builtin: boolean;
}

export interface TraefikStatus {
  state: string;
  pid: number;
  startedAt: string;
  lastError?: string;
  managed: boolean;
}

export interface LogLine {
  at: string;
  level: string;
  message: string;
  raw: string;
}

export interface AuditEntry {
  id: string;
  at: string;
  userEmail: string;
  action: string;
  target: string;
  detail: string;
}

export interface ApiIssue {
  field: string;
  message: string;
}
export interface ApiError {
  error: string;
  issues?: ApiIssue[];
}
