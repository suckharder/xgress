// Package config holds the process-level configuration for xgress: where data
// lives, which database backend to use, network ports, and how xgress talks to the
// Traefik process it supervises. Everything here is set once at boot from
// environment variables (with sane defaults) and is independent of the dynamic,
// user-managed proxy configuration that lives in the database.
package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// StreamEntryPoint is a TCP/UDP entrypoint for L4 (stream) proxying. Defined in
// process config to match a port the container publishes.
type StreamEntryPoint struct {
	Name  string `json:"name"`
	Proto string `json:"proto"` // tcp | udp
	Port  int    `json:"port"`
}

// DBDriver enumerates the supported database backends.
type DBDriver string

const (
	// DriverSQLite is the default embedded, zero-configuration backend.
	DriverSQLite DBDriver = "sqlite"
	// DriverPostgres targets an external Postgres container/server.
	DriverPostgres DBDriver = "postgres"
)

// ProviderTokenHeader is the request header carrying the provider auth token.
// xgress requires it on GET /api/provider and Traefik sends it (set in static config).
const ProviderTokenHeader = "X-xgress-Provider-Token"

// EdgeTokenHeader is the request header carrying the cache-edge auth token. The
// renderer injects it (a generated middleware) on cache-routed hosts so only Traefik
// can reach the edge; the edge rejects requests without it. This makes the edge safe
// to expose on the Docker network (external/HA mode) instead of loopback-only.
const EdgeTokenHeader = "X-xgress-Cache-Token"

// Config is the fully-resolved runtime configuration.
type Config struct {
	// DataDir is the single persisted volume. Holds the SQLite DB (if used),
	// acme certificate material, uploaded certs, the generated static
	// traefik.yml, and the secrets key.
	DataDir string

	// DB selects and locates the database backend.
	DBDriver DBDriver
	// DBDSN is the connection string for Postgres. Ignored for SQLite, which
	// always lives at <DataDir>/xgress.db.
	DBDSN string

	// AdminListen is the address the xgress admin UI + REST API listens on.
	AdminListen string

	// ProviderListen is the address Traefik polls for dynamic config over the
	// HTTP provider. In single-container mode it is loopback (never
	// world-reachable). In external-Traefik mode set it to :9000 and set
	// ProviderAdvertise so the external Traefik can reach it by service name.
	ProviderListen string

	// ProviderAdvertise is the base URL the Traefik process uses to reach xgress's
	// provider + ACME-challenge server (e.g. http://xgress:9000 in external-Traefik
	// mode). Defaults to http://<loopback host>:<port> derived from
	// ProviderListen, which is correct for the single-container deployment.
	ProviderAdvertise string

	// ProviderPollInterval is how often Traefik polls the HTTP provider. We
	// default low (1s) for production-grade convergence; the endpoint is
	// ETag-aware so a poll with no change is cheap.
	ProviderPollInterval time.Duration

	// ProviderToken authenticates Traefik's polls of the (otherwise unauthenticated)
	// provider endpoint, which serves decrypted TLS private keys. xgress requires the
	// header ProviderTokenHeader: <token> on GET /api/provider and embeds the same
	// header into the Traefik static config's HTTP provider. Set via
	// XGRESS_PROVIDER_TOKEN, or auto-generated and persisted to <DataDir>/provider.token
	// on first boot. This matters most in external-Traefik mode, where the provider binds
	// the Docker network rather than loopback.
	ProviderToken string

	// Traefik process supervision.
	TraefikBinary    string        // path to the traefik executable
	TraefikManaged   bool          // true: xgress spawns/owns Traefik (single-container). false: external Traefik (2-container).
	TraefikStaticCfg string        // path to the generated static config file
	HTTPEntryPoint   string        // name of the :80 entrypoint
	HTTPSEntryPoint  string        // name of the :443 entrypoint
	HTTPPort         int           // public HTTP port
	HTTPSPort        int           // public HTTPS port
	RestartDrain     time.Duration // grace period for Traefik to drain on restart

	// StreamEntryPoints are additional TCP/UDP entrypoints for L4 stream hosts.
	// They are declared here (and must be published by Docker in compose) rather
	// than created in the UI — a Traefik entrypoint is useless unless the
	// container actually exposes that port. Parsed from XGRESS_STREAM_ENTRYPOINTS,
	// format: "name:port/proto" comma-separated, e.g. "postgres:5432/tcp,dns:53/udp".
	StreamEntryPoints []StreamEntryPoint

	// SecretsKeyFile is where the data-at-rest encryption key is stored
	// (auto-generated on first boot if absent).
	SecretsKeyFile string

	// TraefikAPIListen is a loopback address where xgress exposes Traefik's own
	// read-only API + dashboard (api.insecure on a bound entrypoint) so xgress can
	// read live router/service state for the metrics dashboard and Docker-label
	// import. Loopback-only; never world-reachable. Empty disables it.
	TraefikAPIListen string

	// WAFDefaultEnabled is the default for the global WAF feature when the
	// plugins.waf.enabled setting is unset. The native Coraza engine + OWASP CRS are
	// always compiled into the binary (no plugin, no catalog fetch), so this is just
	// an on/off default; hosts still opt in individually via h.WAF. Defaults true.
	WAFDefaultEnabled bool

	// WAFResponseFailClosed controls the WAF response phase on a Coraza processing
	// error. Default false keeps the request served (fail-open) — a WAF internal error
	// shouldn't 500 a legitimate response. Set true to fail closed (block with 500) for
	// hosts where an uninspected response is unacceptable. The request phase always
	// fails closed. (S4)
	WAFResponseFailClosed bool

	// RedisURL, when set, is the address of a Redis server backing the server-side
	// HTTP cache (shared across instances). Empty = in-memory cache.
	RedisURL string

	// EdgeListen is where xgress's native cache edge listens; EdgeAdvertise is the URL
	// Traefik routes cache-enabled hosts to. Loopback in single-container mode; bind
	// `:9100` + advertise `http://xgress:9100` in external mode so a separate Traefik can
	// reach it (safe because the edge is token-gated — see EdgeToken).
	EdgeListen    string
	EdgeAdvertise string
	// EdgeToken gates the cache edge (so a network-reachable edge isn't an open proxy).
	// Auto-generated to <DataDir>/edge.token on first boot, injected by the renderer on
	// cache-routed hosts, and validated by the edge. Set explicitly (shared value) for
	// multi-instance HA. Empty disables the gate (legacy loopback-only behavior).
	EdgeToken string

	// CacheTTL is the default server-side cache TTL when a response has no max-age.
	CacheTTL time.Duration

	// CacheMaxBytes bounds the total size of the in-memory cache (LRU eviction); a
	// distinct-URL flood can otherwise grow it without bound and OOM-kill PID 1.
	// CacheMaxEntryBytes is the per-entry ceiling: larger responses are streamed
	// (never buffered/cached). Both also cap how much of a response the edge buffers
	// for caching/WAF inspection. Ignored for the Redis backend (externally bounded).
	// Accept a plain byte count or a KB/MB/GB suffix (e.g. "256MB").
	CacheMaxBytes      int64
	CacheMaxEntryBytes int64

	// ExternalCertsDir, when set, is a directory of externally-managed TLS
	// certificates (e.g. written by cert-manager). xgress scans it for *.crt/*.key
	// (or *.pem/*.key) pairs and serves them to Traefik as dynamic certificates,
	// so an external system can own ACME while xgress owns routing ("BYO certs").
	ExternalCertsDir string

	// ACMEEmail is the default contact email for Let's Encrypt registration.
	ACMEEmail string
	// ACMEStaging routes new certificate orders to the LE staging CA. Useful
	// while wiring up DNS providers to avoid burning production rate limits.
	ACMEStaging bool
	// ACMECAURL overrides the ACME directory URL (XGRESS_ACME_CA_URL) to point at a
	// private/internal ACME CA (e.g. step-ca, an internal Boulder) instead of Let's
	// Encrypt. Takes precedence over ACMEStaging; empty = LE staging/production. The
	// CA's TLS certificate must be trusted by the host — for a private root, set
	// LEGO_CA_CERTIFICATES to its PEM (lego reads it natively).
	ACMECAURL string
	// ACMEDNSResolvers overrides the recursive nameservers used for the DNS-01
	// propagation pre-check (comma-separated host:port via XGRESS_ACME_DNS_RESOLVERS).
	// Needed for split-horizon DNS or a private/test resolver; empty = system resolvers.
	ACMEDNSResolvers []string

	// RenewalInterval is how often the background renewal pass runs (XGRESS_RENEWAL_INTERVAL).
	// Default 12h. Lowering it is mainly useful for tests / aggressive HA failover.
	RenewalInterval time.Duration
	// RenewalLeaseTTL is the TTL of the "acme-renewal" leader-election lease
	// (XGRESS_RENEWAL_LEASE_TTL). Across instances sharing one DB, only the lease holder
	// renews; if it dies, another takes over after the lease expires. Default 15m.
	RenewalLeaseTTL time.Duration

	// Dev disables some production guards (e.g. secure-cookie enforcement) for
	// local development over plain HTTP.
	Dev bool

	// AdminInsecureCookie omits the Secure attribute on the admin session cookie so
	// the admin UI can authenticate over plain HTTP (admin exposed without TLS, or a
	// trusted LAN). Unlike Dev it changes NOTHING else. Off by default; only use
	// behind TLS or on a trusted network.
	AdminInsecureCookie bool
}

// Load resolves configuration from environment variables, applying defaults.
func Load() (*Config, error) {
	c := &Config{
		DataDir:               env("XGRESS_DATA_DIR", "/data"),
		DBDriver:              DBDriver(env("XGRESS_DB_DRIVER", string(DriverSQLite))),
		DBDSN:                 env("XGRESS_DB_DSN", ""),
		AdminListen:           env("XGRESS_ADMIN_LISTEN", "127.0.0.1:8088"),
		ProviderListen:        env("XGRESS_PROVIDER_LISTEN", "127.0.0.1:9000"),
		ProviderAdvertise:     env("XGRESS_PROVIDER_ADVERTISE", ""),
		ProviderPollInterval:  envDuration("XGRESS_PROVIDER_POLL_INTERVAL", time.Second),
		ProviderToken:         env("XGRESS_PROVIDER_TOKEN", ""),
		TraefikBinary:         env("XGRESS_TRAEFIK_BINARY", "traefik"),
		TraefikManaged:        envBool("XGRESS_TRAEFIK_MANAGED", true),
		HTTPEntryPoint:        "web",
		HTTPSEntryPoint:       "websecure",
		HTTPPort:              envInt("XGRESS_HTTP_PORT", 80),
		HTTPSPort:             envInt("XGRESS_HTTPS_PORT", 443),
		RestartDrain:          envDuration("XGRESS_RESTART_DRAIN", 10*time.Second),
		TraefikAPIListen:      env("XGRESS_TRAEFIK_API_LISTEN", "127.0.0.1:8099"),
		WAFDefaultEnabled:     envBool("XGRESS_WAF_DEFAULT", true),
		WAFResponseFailClosed: envBool("XGRESS_WAF_RESPONSE_FAIL_CLOSED", false),
		RedisURL:              env("XGRESS_REDIS_URL", ""),
		EdgeListen:            env("XGRESS_EDGE_LISTEN", "127.0.0.1:9100"),
		EdgeAdvertise:         env("XGRESS_EDGE_ADVERTISE", ""),
		EdgeToken:             env("XGRESS_EDGE_TOKEN", ""),
		CacheTTL:              envDuration("XGRESS_CACHE_TTL", 2*time.Minute),
		CacheMaxBytes:         envBytes("XGRESS_CACHE_MAX_BYTES", 128<<20),
		CacheMaxEntryBytes:    envBytes("XGRESS_CACHE_MAX_ENTRY_BYTES", 8<<20),
		ExternalCertsDir:      env("XGRESS_EXTERNAL_CERTS_DIR", ""),
		ACMEEmail:             env("XGRESS_ACME_EMAIL", ""),
		ACMEStaging:           envBool("XGRESS_ACME_STAGING", false),
		ACMECAURL:             env("XGRESS_ACME_CA_URL", ""),
		ACMEDNSResolvers:      splitCSV(env("XGRESS_ACME_DNS_RESOLVERS", "")),
		RenewalInterval:       envDuration("XGRESS_RENEWAL_INTERVAL", 12*time.Hour),
		RenewalLeaseTTL:       envDuration("XGRESS_RENEWAL_LEASE_TTL", 15*time.Minute),
		Dev:                   envBool("XGRESS_DEV", false),
		AdminInsecureCookie:   envBool("XGRESS_ADMIN_INSECURE_COOKIE", false),
	}

	eps, err := parseStreamEntryPoints(env("XGRESS_STREAM_ENTRYPOINTS", ""))
	if err != nil {
		return nil, err
	}
	c.StreamEntryPoints = eps

	c.TraefikStaticCfg = filepath.Join(c.DataDir, "traefik", "traefik.yml")
	c.SecretsKeyFile = filepath.Join(c.DataDir, "secret.key")

	if c.ProviderAdvertise == "" {
		host, port, err := net.SplitHostPort(c.ProviderListen)
		if err != nil {
			return nil, fmt.Errorf("invalid XGRESS_PROVIDER_LISTEN %q: %w", c.ProviderListen, err)
		}
		if host == "" || host == "0.0.0.0" || host == "::" {
			host = "127.0.0.1"
		}
		c.ProviderAdvertise = "http://" + net.JoinHostPort(host, port)
	}
	c.ProviderAdvertise = strings.TrimRight(c.ProviderAdvertise, "/")

	if c.EdgeAdvertise == "" {
		host, port, err := net.SplitHostPort(c.EdgeListen)
		if err != nil {
			return nil, fmt.Errorf("invalid XGRESS_EDGE_LISTEN %q: %w", c.EdgeListen, err)
		}
		if host == "" || host == "0.0.0.0" || host == "::" {
			host = "127.0.0.1"
		}
		c.EdgeAdvertise = "http://" + net.JoinHostPort(host, port)
	}
	c.EdgeAdvertise = strings.TrimRight(c.EdgeAdvertise, "/")

	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Config) validate() error {
	switch c.DBDriver {
	case DriverSQLite:
		// ok, no DSN required
	case DriverPostgres:
		if c.DBDSN == "" {
			return fmt.Errorf("XGRESS_DB_DSN is required when XGRESS_DB_DRIVER=postgres")
		}
	default:
		return fmt.Errorf("unsupported XGRESS_DB_DRIVER %q (want sqlite or postgres)", c.DBDriver)
	}
	if c.ProviderPollInterval <= 0 {
		return fmt.Errorf("XGRESS_PROVIDER_POLL_INTERVAL must be positive")
	}
	return nil
}

// SQLitePath returns the on-disk path for the SQLite database.
func (c *Config) SQLitePath() string { return filepath.Join(c.DataDir, "xgress.db") }

// ProviderTokenFile returns the on-disk path of the auto-generated provider token.
func (c *Config) ProviderTokenFile() string { return filepath.Join(c.DataDir, "provider.token") }

// EdgeTokenFile returns the on-disk path of the auto-generated cache-edge token.
func (c *Config) EdgeTokenFile() string { return filepath.Join(c.DataDir, "edge.token") }

// ACMEDir returns the directory holding ACME account + certificate material.
func (c *Config) ACMEDir() string { return filepath.Join(c.DataDir, "acme") }

// CertsDir returns the directory where rendered/uploaded certs are written for
// Traefik to read via the dynamic file fallback (and for inspection).
func (c *Config) CertsDir() string { return filepath.Join(c.DataDir, "certs") }

// parseStreamEntryPoints parses "name:port/proto,name2:port2/proto2".
func parseStreamEntryPoints(s string) ([]StreamEntryPoint, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	var out []StreamEntryPoint
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		proto := "tcp"
		if i := strings.Index(part, "/"); i >= 0 {
			proto = strings.ToLower(strings.TrimSpace(part[i+1:]))
			part = part[:i]
		}
		colon := strings.LastIndex(part, ":")
		if colon < 0 {
			return nil, fmt.Errorf("invalid XGRESS_STREAM_ENTRYPOINTS entry %q (want name:port/proto)", part)
		}
		name := strings.TrimSpace(part[:colon])
		port, err := strconv.Atoi(strings.TrimSpace(part[colon+1:]))
		if err != nil || name == "" || port <= 0 {
			return nil, fmt.Errorf("invalid XGRESS_STREAM_ENTRYPOINTS entry %q", part)
		}
		if proto != "tcp" && proto != "udp" {
			return nil, fmt.Errorf("invalid protocol %q in XGRESS_STREAM_ENTRYPOINTS (want tcp or udp)", proto)
		}
		out = append(out, StreamEntryPoint{Name: name, Proto: proto, Port: port})
	}
	return out, nil
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && strings.TrimSpace(v) != "" {
		return v
	}
	return def
}

// splitCSV splits a comma-separated value into trimmed, non-empty entries (nil if empty).
func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func envBool(key string, def bool) bool {
	if v, ok := os.LookupEnv(key); ok {
		b, err := strconv.ParseBool(strings.TrimSpace(v))
		if err == nil {
			return b
		}
	}
	return def
}

func envInt(key string, def int) int {
	if v, ok := os.LookupEnv(key); ok {
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err == nil {
			return n
		}
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	if v, ok := os.LookupEnv(key); ok {
		d, err := time.ParseDuration(strings.TrimSpace(v))
		if err == nil {
			return d
		}
	}
	return def
}

// envBytes reads a byte size from the environment. It accepts a plain integer
// (bytes) or a value with a KB/MB/GB/KiB/MiB/GiB suffix (case-insensitive,
// base-1024), e.g. "256MB". A non-positive or unparseable value falls back to def.
func envBytes(key string, def int64) int64 {
	v, ok := os.LookupEnv(key)
	if !ok {
		return def
	}
	s := strings.TrimSpace(v)
	if s == "" {
		return def
	}
	mult := int64(1)
	up := strings.ToUpper(s)
	for _, suf := range []struct {
		s string
		m int64
	}{{"GIB", 1 << 30}, {"GB", 1 << 30}, {"MIB", 1 << 20}, {"MB", 1 << 20}, {"KIB", 1 << 10}, {"KB", 1 << 10}, {"B", 1}} {
		if strings.HasSuffix(up, suf.s) {
			mult = suf.m
			s = strings.TrimSpace(s[:len(s)-len(suf.s)])
			break
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
		return def
	}
	return n * mult
}
