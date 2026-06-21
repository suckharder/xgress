package store

import "time"

// Role enumerates RBAC roles. Admins can do everything; operators manage proxy
// configuration but not users/settings; viewers are read-only.
type Role string

const (
	RoleAdmin    Role = "admin"
	RoleOperator Role = "operator"
	RoleViewer   Role = "viewer"
)

// User is an authenticated account.
type User struct {
	ID           string    `json:"id"`
	Email        string    `json:"email"`
	Name         string    `json:"name"`
	PasswordHash string    `json:"-"`
	Role         Role      `json:"role"`
	Disabled     bool      `json:"disabled"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
}

// Session is a server-side login session (revocable, unlike a stateless JWT).
type Session struct {
	Token     string    `json:"-"`
	UserID    string    `json:"userId"`
	UserAgent string    `json:"userAgent"`
	IP        string    `json:"ip"`
	CreatedAt time.Time `json:"createdAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// Upstream is a single backend server for a proxy host.
type Upstream struct {
	Scheme string `json:"scheme"` // http | https | h2c
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Weight int    `json:"weight,omitempty"`
}

// Location is a path-scoped route within a proxy host (NPM "custom locations"):
// requests matching PathPrefix go to a different set of upstreams.
type Location struct {
	PathPrefix  string     `json:"pathPrefix"`
	Upstreams   []Upstream `json:"upstreams"`
	StripPrefix bool       `json:"stripPrefix,omitempty"`
}

// ErrorPage is a per-host custom error page: when the backend returns a status in
// Status (e.g. "404" or "500-599"), xgress serves HTML instead.
type ErrorPage struct {
	Status string `json:"status"` // "404", "500,502", "500-599"
	HTML   string `json:"html"`
}

// BackendGroup is a named set of upstreams used by the service-composition modes
// (weighted/canary, failover, mirroring). In single mode the host uses Upstreams
// directly and ignores groups.
type BackendGroup struct {
	Name      string     `json:"name"`
	Upstreams []Upstream `json:"upstreams"`
	Weight    int        `json:"weight,omitempty"`  // weighted mode: relative weight
	Percent   int        `json:"percent,omitempty"` // mirroring mode: % of traffic mirrored (mirror groups)
}

// HostKind distinguishes the flavours of host we manage.
type HostKind string

const (
	HostKindProxy       HostKind = "proxy"       // domain -> upstream(s)
	HostKindRedirection HostKind = "redirection" // domain -> redirect target
	HostKindDead        HostKind = "dead"        // 404/static response (default host)
	HostKindStream      HostKind = "stream"      // TCP/UDP passthrough
)

// TLSMode controls certificate selection for a host.
type TLSMode string

const (
	TLSNone     TLSMode = "none"     // plain HTTP only
	TLSACME     TLSMode = "acme"     // certificate obtained by xgress via ACME
	TLSCustom   TLSMode = "custom"   // user-uploaded certificate
	TLSExternal TLSMode = "external" // terminate elsewhere / passthrough
)

// Host is the central object: a domain (or set of domains) routed somewhere.
// Kind-specific fields are carried in the embedded JSON blobs so a single table
// and code path handles every host flavour.
type Host struct {
	ID      string   `json:"id"`
	Kind    HostKind `json:"kind"`
	Enabled bool     `json:"enabled"`
	Domains []string `json:"domains"`

	// Proxy fields.
	Upstreams      []Upstream  `json:"upstreams,omitempty"`
	UpstreamPath   string      `json:"upstreamPath,omitempty"`   // optional path prefix on the backend
	PreservePath   bool        `json:"preservePath,omitempty"`   //
	CacheAssets    bool        `json:"cacheAssets,omitempty"`    // add Cache-Control to static-asset responses
	LoadBalancer   string      `json:"loadBalancer,omitempty"`   // balancer strategy: wrr | p2c | leasttime
	Sticky         bool        `json:"sticky,omitempty"`         // sticky sessions (cookie)
	HealthCheckURL string      `json:"healthCheckUrl,omitempty"` // optional active health check path
	Locations      []Location  `json:"locations,omitempty"`      // path-scoped sub-routes
	ErrorPages     []ErrorPage `json:"errorPages,omitempty"`     // custom error pages
	AccessListIDs  []string    `json:"accessListIds,omitempty"`  // attached reusable access lists

	// Service composition. ServiceMode: "" / "single" (use Upstreams) | "weighted"
	// (canary/blue-green) | "failover" (active/passive) | "mirroring" (shadow).
	// For failover/mirroring, BackendGroups[0] is the primary.
	ServiceMode   string         `json:"serviceMode,omitempty"`
	BackendGroups []BackendGroup `json:"backendGroups,omitempty"`

	// Plugin toggles (Round 2). Attach baked-in Traefik plugin middlewares.
	WAF   bool `json:"waf,omitempty"`   // Coraza WAF — "block common exploits"
	Cache bool `json:"cache,omitempty"` // route through xgress's native server-side cache (internal/edge)

	// Redirection fields.
	RedirectTo       string `json:"redirectTo,omitempty"`
	RedirectCode     int    `json:"redirectCode,omitempty"`     // 301/302/307/308
	RedirectKeepPath bool   `json:"redirectKeepPath,omitempty"` //

	// Stream (TCP/UDP) fields.
	StreamProto      string `json:"streamProto,omitempty"`      // tcp | udp
	StreamEntryPoint string `json:"streamEntryPoint,omitempty"` // entrypoint name (static, port owned by a Listener)
	TLSPassthrough   bool   `json:"tlsPassthrough,omitempty"`   // TCP: route by SNI, forward raw TLS (no termination)

	// TLS.
	TLS           TLSMode `json:"tls"`
	CertificateID string  `json:"certificateId,omitempty"`
	ForceTLS      bool    `json:"forceTls,omitempty"` // redirect HTTP->HTTPS
	HSTS          bool    `json:"hsts,omitempty"`     // add HSTS header
	HTTP2On       bool    `json:"http2On,omitempty"`  //

	// CORS. When enabled, xgress generates a headers middleware that allows the
	// listed origins (exact match). Methods/allowed-headers use sensible defaults.
	CORSEnabled          bool     `json:"corsEnabled,omitempty"`
	CORSAllowOrigins     []string `json:"corsAllowOrigins,omitempty"`
	CORSAllowCredentials bool     `json:"corsAllowCredentials,omitempty"`

	// Cross-cutting.
	MiddlewareIDs []string `json:"middlewareIds,omitempty"`
	RawYAML       string   `json:"rawYaml,omitempty"` // advanced passthrough, validated+namespaced
	Notes         string   `json:"notes,omitempty"`

	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// Middleware is a reusable Traefik middleware definition. Params is the raw
// Traefik middleware config (one of basicAuth, ipAllowList, headers, …) stored
// as JSON and validated against the real Traefik struct on save.
type Middleware struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	Type      string         `json:"type"` // basicAuth | ipAllowList | headers | compress | rateLimit | forwardAuth | redirectScheme | ...
	Params    map[string]any `json:"params"`
	CreatedAt time.Time      `json:"createdAt"`
	UpdatedAt time.Time      `json:"updatedAt"`
}

// AccessListUser is a username + bcrypt/apr1 password hash (htpasswd-style).
type AccessListUser struct {
	Username string `json:"username"`
	Hash     string `json:"hash"` // password hash; never the plaintext
}

// AccessList is a reusable bundle of basic-auth users and/or an IP allow-list
// (NPM "Access Lists"). Attached to hosts; compiles to basicAuth + ipAllowList
// middlewares at render time.
type AccessList struct {
	ID         string           `json:"id"`
	Name       string           `json:"name"`
	Users      []AccessListUser `json:"users"`      // basic-auth users
	AllowIPs   []string         `json:"allowIps"`   // CIDR allow-list (empty = no IP restriction)
	SatisfyAny bool             `json:"satisfyAny"` // reserved; currently both auth+IP are required ("all")
	CreatedAt  time.Time        `json:"createdAt"`
	UpdatedAt  time.Time        `json:"updatedAt"`
}

// CertType distinguishes ACME-managed certs from user-uploaded ones.
type CertType string

const (
	CertTypeACME     CertType = "acme"
	CertTypeUploaded CertType = "uploaded"
)

// CertStatus tracks the lifecycle of a certificate.
type CertStatus string

const (
	CertStatusPending CertStatus = "pending"
	CertStatusValid   CertStatus = "valid"
	CertStatusFailed  CertStatus = "failed"
	CertStatusExpired CertStatus = "expired"
)

// Certificate is a TLS certificate xgress owns. For ACME certs, the private key and
// chain are obtained by xgress (via lego) and stored encrypted; they are then
// served to Traefik as dynamic TLS certificates — no Traefik restart required.
type Certificate struct {
	ID            string     `json:"id"`
	Type          CertType   `json:"type"`
	Domains       []string   `json:"domains"`
	Status        CertStatus `json:"status"`
	ChallengeType string     `json:"challengeType,omitempty"` // http-01 | dns-01 (acme only)
	DNSProviderID string     `json:"dnsProviderId,omitempty"` // for dns-01
	ACMEAccountID string     `json:"acmeAccountId,omitempty"`
	CertPEM       string     `json:"-"` // public chain (PEM)
	KeyPEMEnc     string     `json:"-"` // private key, encrypted at rest
	IssuedAt      *time.Time `json:"issuedAt,omitempty"`
	ExpiresAt     *time.Time `json:"expiresAt,omitempty"`
	LastError     string     `json:"lastError,omitempty"`
	LastAttemptAt *time.Time `json:"lastAttemptAt,omitempty"`
	AutoRenew     bool       `json:"autoRenew"`
	CreatedAt     time.Time  `json:"createdAt"`
	UpdatedAt     time.Time  `json:"updatedAt"`
}

// ACMEAccount is a registered ACME account (one per CA/email pair).
type ACMEAccount struct {
	ID            string    `json:"id"`
	Email         string    `json:"email"`
	CADirURL      string    `json:"caDirUrl"`
	Registration  string    `json:"-"` // JSON registration resource
	PrivateKeyEnc string    `json:"-"` // account private key, encrypted
	CreatedAt     time.Time `json:"createdAt"`
}

// DNSProvider holds encrypted credentials for a lego DNS-01 provider.
type DNSProvider struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Provider   string    `json:"provider"`   // lego provider code, e.g. "cloudflare"
	ConfigEnc  string    `json:"-"`          // encrypted JSON of env-style credentials
	ConfigKeys []string  `json:"configKeys"` // names of provided credential keys (no values) for UI
	CreatedAt  time.Time `json:"createdAt"`
	UpdatedAt  time.Time `json:"updatedAt"`
}

// Schedule enables/disables a host on a cron schedule (5-field cron:
// "min hour day-of-month month day-of-week").
type Schedule struct {
	ID        string    `json:"id"`
	HostID    string    `json:"hostId"`
	Action    string    `json:"action"` // enable | disable
	Cron      string    `json:"cron"`
	CreatedAt time.Time `json:"createdAt"`
}

// Setting is a typed key/value app setting.
type Setting struct {
	Key       string    `json:"key"`
	Value     string    `json:"value"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// AuditEntry records a mutating action for change history.
type AuditEntry struct {
	ID        string    `json:"id"`
	At        time.Time `json:"at"`
	UserID    string    `json:"userId"`
	UserEmail string    `json:"userEmail"`
	Action    string    `json:"action"` // e.g. "host.create"
	Target    string    `json:"target"` // object id
	Detail    string    `json:"detail"` // JSON diff/summary
}

// ConfigSnapshot is a last-known-good rendered dynamic configuration, kept for
// rollback. Version increments on every successful render.
type ConfigSnapshot struct {
	Version   int64     `json:"version"`
	JSON      string    `json:"-"`
	Hash      string    `json:"hash"`
	Valid     bool      `json:"valid"`
	CreatedAt time.Time `json:"createdAt"`
}
