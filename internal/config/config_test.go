package config

import (
	"testing"
	"time"
)

// clearEnv unsets every XGRESS_* variable Load reads so each test starts from a
// known baseline regardless of the host environment.
func clearEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"XGRESS_DATA_DIR", "XGRESS_DB_DRIVER", "XGRESS_DB_DSN", "XGRESS_ADMIN_LISTEN",
		"XGRESS_PROVIDER_LISTEN", "XGRESS_PROVIDER_ADVERTISE", "XGRESS_PROVIDER_POLL_INTERVAL", "XGRESS_PROVIDER_TOKEN",
		"XGRESS_TRAEFIK_BINARY", "XGRESS_TRAEFIK_MANAGED", "XGRESS_HTTP_PORT", "XGRESS_HTTPS_PORT",
		"XGRESS_RESTART_DRAIN", "XGRESS_TRAEFIK_API_LISTEN", "XGRESS_WAF_DEFAULT", "XGRESS_ADMIN_INSECURE_COOKIE",
		"XGRESS_REDIS_URL", "XGRESS_EDGE_LISTEN", "XGRESS_EDGE_ADVERTISE", "XGRESS_CACHE_TTL",
		"XGRESS_EXTERNAL_CERTS_DIR", "XGRESS_ACME_EMAIL", "XGRESS_ACME_STAGING", "XGRESS_ACME_CA_URL", "XGRESS_ACME_DNS_RESOLVERS",
		"XGRESS_RENEWAL_INTERVAL", "XGRESS_RENEWAL_LEASE_TTL",
		"XGRESS_EDGE_TOKEN", "XGRESS_DEV",
		"XGRESS_STREAM_ENTRYPOINTS",
	} {
		t.Setenv(k, "") // Setenv registers cleanup; empty string is treated as unset by env()
	}
}

func TestLoadDefaults(t *testing.T) {
	clearEnv(t)
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.DataDir != "/data" {
		t.Errorf("DataDir = %q, want /data", c.DataDir)
	}
	if c.DBDriver != DriverSQLite {
		t.Errorf("DBDriver = %q, want sqlite", c.DBDriver)
	}
	if c.AdminListen != "127.0.0.1:8088" {
		t.Errorf("AdminListen = %q, want loopback default", c.AdminListen)
	}
	if c.ProviderPollInterval != time.Second {
		t.Errorf("poll = %v, want 1s", c.ProviderPollInterval)
	}
	if !c.TraefikManaged {
		t.Error("TraefikManaged should default true")
	}
	if !c.WAFDefaultEnabled {
		t.Error("WAFDefaultEnabled should default true")
	}
	if c.AdminInsecureCookie {
		t.Error("AdminInsecureCookie should default false")
	}
	if c.HTTPPort != 80 || c.HTTPSPort != 443 {
		t.Errorf("ports = %d/%d, want 80/443", c.HTTPPort, c.HTTPSPort)
	}
	if c.RenewalInterval != 12*time.Hour {
		t.Errorf("RenewalInterval = %v, want 12h", c.RenewalInterval)
	}
	if c.RenewalLeaseTTL != 15*time.Minute {
		t.Errorf("RenewalLeaseTTL = %v, want 15m", c.RenewalLeaseTTL)
	}
	// Derived paths.
	if c.SQLitePath() != "/data/xgress.db" {
		t.Errorf("SQLitePath = %q", c.SQLitePath())
	}
	if c.SecretsKeyFile != "/data/secret.key" {
		t.Errorf("SecretsKeyFile = %q", c.SecretsKeyFile)
	}
	if c.TraefikStaticCfg != "/data/traefik/traefik.yml" {
		t.Errorf("TraefikStaticCfg = %q", c.TraefikStaticCfg)
	}
	// Advertise derived from loopback provider listen.
	if c.ProviderAdvertise != "http://127.0.0.1:9000" {
		t.Errorf("ProviderAdvertise = %q", c.ProviderAdvertise)
	}
	if c.EdgeAdvertise != "http://127.0.0.1:9100" {
		t.Errorf("EdgeAdvertise = %q", c.EdgeAdvertise)
	}
}

func TestLoadEnvOverrides(t *testing.T) {
	clearEnv(t)
	t.Setenv("XGRESS_DATA_DIR", "/srv/xgress")
	t.Setenv("XGRESS_ADMIN_LISTEN", "127.0.0.1:9999")
	t.Setenv("XGRESS_TRAEFIK_MANAGED", "false")
	t.Setenv("XGRESS_WAF_DEFAULT", "false")
	t.Setenv("XGRESS_ADMIN_INSECURE_COOKIE", "true")
	t.Setenv("XGRESS_HTTP_PORT", "8080")
	t.Setenv("XGRESS_PROVIDER_POLL_INTERVAL", "5s")
	t.Setenv("XGRESS_CACHE_TTL", "30s")
	t.Setenv("XGRESS_ACME_STAGING", "true")
	t.Setenv("XGRESS_ACME_CA_URL", "https://ca.internal:9000/acme/acme/directory")
	t.Setenv("XGRESS_ACME_DNS_RESOLVERS", "127.0.0.1:8053, 1.1.1.1:53 ,")
	t.Setenv("XGRESS_RENEWAL_INTERVAL", "3s")
	t.Setenv("XGRESS_RENEWAL_LEASE_TTL", "5s")
	t.Setenv("XGRESS_EDGE_TOKEN", "shared-edge-secret")
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.DataDir != "/srv/xgress" || c.SQLitePath() != "/srv/xgress/xgress.db" {
		t.Errorf("DataDir override not applied: %q / %q", c.DataDir, c.SQLitePath())
	}
	if c.AdminListen != "127.0.0.1:9999" {
		t.Errorf("AdminListen = %q", c.AdminListen)
	}
	if c.TraefikManaged {
		t.Error("TraefikManaged should be false")
	}
	if c.WAFDefaultEnabled {
		t.Error("WAFDefaultEnabled should be false")
	}
	if !c.AdminInsecureCookie {
		t.Error("AdminInsecureCookie should be true when XGRESS_ADMIN_INSECURE_COOKIE=true")
	}
	if c.HTTPPort != 8080 {
		t.Errorf("HTTPPort = %d", c.HTTPPort)
	}
	if c.ProviderPollInterval != 5*time.Second {
		t.Errorf("poll = %v", c.ProviderPollInterval)
	}
	if c.CacheTTL != 30*time.Second {
		t.Errorf("CacheTTL = %v", c.CacheTTL)
	}
	if !c.ACMEStaging {
		t.Error("ACMEStaging should be true")
	}
	if c.ACMECAURL != "https://ca.internal:9000/acme/acme/directory" {
		t.Errorf("ACMECAURL = %q", c.ACMECAURL)
	}
	if c.RenewalInterval != 3*time.Second {
		t.Errorf("RenewalInterval = %v, want 3s", c.RenewalInterval)
	}
	if c.RenewalLeaseTTL != 5*time.Second {
		t.Errorf("RenewalLeaseTTL = %v, want 5s", c.RenewalLeaseTTL)
	}
	if c.EdgeToken != "shared-edge-secret" {
		t.Errorf("EdgeToken = %q", c.EdgeToken)
	}
	// Comma-separated, trimmed, empties dropped.
	if len(c.ACMEDNSResolvers) != 2 || c.ACMEDNSResolvers[0] != "127.0.0.1:8053" || c.ACMEDNSResolvers[1] != "1.1.1.1:53" {
		t.Errorf("ACMEDNSResolvers = %#v", c.ACMEDNSResolvers)
	}
}

func TestProviderAdvertiseFromWildcardListen(t *testing.T) {
	clearEnv(t)
	t.Setenv("XGRESS_PROVIDER_LISTEN", ":9000") // host empty → loopback
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.ProviderAdvertise != "http://127.0.0.1:9000" {
		t.Errorf("ProviderAdvertise = %q, want loopback-derived", c.ProviderAdvertise)
	}
}

func TestProviderAdvertiseExplicitTrimsSlash(t *testing.T) {
	clearEnv(t)
	t.Setenv("XGRESS_PROVIDER_ADVERTISE", "http://xgress:9000/")
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.ProviderAdvertise != "http://xgress:9000" {
		t.Errorf("ProviderAdvertise = %q, want trailing slash trimmed", c.ProviderAdvertise)
	}
}

func TestPostgresRequiresDSN(t *testing.T) {
	clearEnv(t)
	t.Setenv("XGRESS_DB_DRIVER", "postgres")
	if _, err := Load(); err == nil {
		t.Fatal("expected error: postgres driver without DSN")
	}
	t.Setenv("XGRESS_DB_DSN", "postgres://u:p@db:5432/xgress")
	if _, err := Load(); err != nil {
		t.Fatalf("postgres with DSN should load: %v", err)
	}
}

func TestUnsupportedDriverRejected(t *testing.T) {
	clearEnv(t)
	t.Setenv("XGRESS_DB_DRIVER", "mysql")
	if _, err := Load(); err == nil {
		t.Fatal("expected error for unsupported driver")
	}
}

func TestInvalidPollIntervalRejected(t *testing.T) {
	clearEnv(t)
	// A zero/negative duration must be rejected by validate().
	t.Setenv("XGRESS_PROVIDER_POLL_INTERVAL", "0s")
	if _, err := Load(); err == nil {
		t.Fatal("expected error for non-positive poll interval")
	}
}

func TestInvalidProviderListenRejected(t *testing.T) {
	clearEnv(t)
	t.Setenv("XGRESS_PROVIDER_LISTEN", "not-a-host-port")
	if _, err := Load(); err == nil {
		t.Fatal("expected error for malformed provider listen")
	}
}

func TestBadEnvValuesFallBackToDefaults(t *testing.T) {
	clearEnv(t)
	// Unparseable numeric/bool/duration values should fall back, not error.
	t.Setenv("XGRESS_HTTP_PORT", "not-a-number")
	t.Setenv("XGRESS_TRAEFIK_MANAGED", "maybe")
	t.Setenv("XGRESS_CACHE_TTL", "forever")
	c, err := Load()
	if err != nil {
		t.Fatalf("Load should tolerate bad scalar env: %v", err)
	}
	if c.HTTPPort != 80 {
		t.Errorf("HTTPPort = %d, want default 80", c.HTTPPort)
	}
	if !c.TraefikManaged {
		t.Error("TraefikManaged should fall back to default true")
	}
	if c.CacheTTL != 2*time.Minute {
		t.Errorf("CacheTTL = %v, want default 2m", c.CacheTTL)
	}
}

func TestParseStreamEntryPoints(t *testing.T) {
	clearEnv(t)
	t.Setenv("XGRESS_STREAM_ENTRYPOINTS", "postgres:5432/tcp, dns:53/udp ,plain:9999")
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := []StreamEntryPoint{
		{Name: "postgres", Proto: "tcp", Port: 5432},
		{Name: "dns", Proto: "udp", Port: 53},
		{Name: "plain", Proto: "tcp", Port: 9999}, // default proto tcp
	}
	if len(c.StreamEntryPoints) != len(want) {
		t.Fatalf("got %d entrypoints, want %d: %+v", len(c.StreamEntryPoints), len(want), c.StreamEntryPoints)
	}
	for i, w := range want {
		if c.StreamEntryPoints[i] != w {
			t.Errorf("entrypoint[%d] = %+v, want %+v", i, c.StreamEntryPoints[i], w)
		}
	}
}

func TestParseStreamEntryPointsErrors(t *testing.T) {
	for _, bad := range []string{
		"noport",       // missing :port
		"name:abc/tcp", // non-numeric port
		"name:0/tcp",   // non-positive port
		"name:53/sctp", // bad proto
		":53/tcp",      // empty name
	} {
		if _, err := parseStreamEntryPoints(bad); err == nil {
			t.Errorf("parseStreamEntryPoints(%q) = nil error, want error", bad)
		}
	}
	// Empty input is valid (no entrypoints).
	if eps, err := parseStreamEntryPoints("  "); err != nil || eps != nil {
		t.Errorf("empty input: got %v, %v; want nil, nil", eps, err)
	}
}

func TestProviderTokenFromEnvAndPath(t *testing.T) {
	clearEnv(t)
	t.Setenv("XGRESS_DATA_DIR", "/srv/xgress")
	t.Setenv("XGRESS_PROVIDER_TOKEN", "explicit-token")
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.ProviderToken != "explicit-token" {
		t.Errorf("ProviderToken = %q, want explicit-token", c.ProviderToken)
	}
	if c.ProviderTokenFile() != "/srv/xgress/provider.token" {
		t.Errorf("ProviderTokenFile = %q", c.ProviderTokenFile())
	}
	// Unset by default (resolved/generated later in main).
	clearEnv(t)
	c2, _ := Load()
	if c2.ProviderToken != "" {
		t.Errorf("ProviderToken default = %q, want empty", c2.ProviderToken)
	}
}
