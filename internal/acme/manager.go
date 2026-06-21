// Package acme is xgress's own ACME engine. Rather than delegating certificates to
// Traefik (which would force static-config changes and restarts when a new
// resolver/DNS provider is added), xgress obtains and renews certificates itself
// using go-acme/lego — the very library Traefik uses internally — and serves the
// resulting certificates to Traefik as dynamic TLS material. Consequence: adding
// a DNS provider or issuing a new certificate is a pure runtime operation with
// zero Traefik restarts.
package acme

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns"
	"github.com/go-acme/lego/v4/registration"

	"github.com/suckharder/xgress/internal/secrets"
	"github.com/suckharder/xgress/internal/store"
)

const (
	// CADirProduction is Let's Encrypt's production directory.
	CADirProduction = lego.LEDirectoryProduction
	// CADirStaging is Let's Encrypt's staging directory (no rate limits).
	CADirStaging = lego.LEDirectoryStaging
)

// Manager issues and renews certificates.
type Manager struct {
	store     *store.Store
	box       *secrets.Box
	responder *HTTP01Responder
	log       *slog.Logger

	defaultEmail string
	staging      bool
	caDirURL     string   // overrides staging/prod when set (e.g. a private/test CA)
	dnsResolvers []string // custom recursive nameservers for DNS-01 propagation pre-check

	// envMu serialises certificate issuance because lego DNS providers read
	// credentials from process environment variables.
	envMu sync.Mutex
}

// Options configures the Manager.
type Options struct {
	Store        *store.Store
	Box          *secrets.Box
	Responder    *HTTP01Responder
	DefaultEmail string
	Staging      bool
	// CADirURL, when set, overrides the ACME directory URL (taking precedence over
	// Staging). Used to point at a private or test CA — e.g. Pebble in the e2e
	// suite. Empty preserves the default staging/production behavior.
	CADirURL string
	// DNSRecursiveNameservers, when set, are the recursive nameservers lego uses for
	// the DNS-01 propagation pre-check (instead of the system resolvers), and it stops
	// requiring authoritative-NS agreement. Needed to validate against a split-horizon
	// or test DNS server (e.g. pebble-challtestsrv in the e2e suite). Empty = default.
	DNSRecursiveNameservers []string
	Logger                  *slog.Logger
}

// New constructs a Manager.
func New(o Options) *Manager {
	log := o.Logger
	if log == nil {
		log = slog.Default()
	}
	return &Manager{
		store:        o.Store,
		box:          o.Box,
		responder:    o.Responder,
		log:          log,
		defaultEmail: o.DefaultEmail,
		staging:      o.Staging,
		caDirURL:     o.CADirURL,
		dnsResolvers: o.DNSRecursiveNameservers,
	}
}

// caURL resolves the ACME directory: an explicit CADirURL override wins, else the
// LE staging or production directory per the Staging flag.
func (m *Manager) caURL() string {
	if m.caDirURL != "" {
		return m.caDirURL
	}
	if m.staging {
		return CADirStaging
	}
	return CADirProduction
}

// getOrCreateAccount returns a lego user for the configured email/CA, creating
// and registering a new account on first use.
func (m *Manager) getOrCreateAccount(ctx context.Context, email string) (*user, error) {
	if email == "" {
		email = m.defaultEmail
	}
	if email == "" {
		return nil, fmt.Errorf("no ACME contact email configured")
	}
	caURL := m.caURL()

	acct, err := m.store.GetACMEAccountByEmail(ctx, email, caURL)
	if err == nil {
		keyPEM, derr := m.box.DecryptString(acct.PrivateKeyEnc)
		if derr != nil {
			return nil, fmt.Errorf("decrypt account key: %w", derr)
		}
		key, kerr := unmarshalKey(keyPEM)
		if kerr != nil {
			return nil, kerr
		}
		reg, rerr := unmarshalRegistration(acct.Registration)
		if rerr != nil {
			return nil, rerr
		}
		return &user{email: email, key: key, registration: reg}, nil
	}

	// Create + register a new account.
	key, err := newAccountKey()
	if err != nil {
		return nil, err
	}
	u := &user{email: email, key: key}
	cfg := lego.NewConfig(u)
	cfg.CADirURL = caURL
	cfg.Certificate.KeyType = certcrypto.EC256
	client, err := lego.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return nil, fmt.Errorf("register ACME account: %w", err)
	}
	u.registration = reg

	keyPEM, err := marshalKey(key)
	if err != nil {
		return nil, err
	}
	keyEnc, err := m.box.EncryptString(keyPEM)
	if err != nil {
		return nil, err
	}
	regJSON, err := marshalRegistration(reg)
	if err != nil {
		return nil, err
	}
	rec := &store.ACMEAccount{Email: email, CADirURL: caURL, Registration: regJSON, PrivateKeyEnc: keyEnc}
	if err := m.store.CreateACMEAccount(ctx, rec); err != nil {
		return nil, err
	}
	m.log.Info("registered new ACME account", "email", email, "ca", caURL)
	return u, nil
}

// Obtain issues (or renews) the certificate described by cert, updating the
// record in place with status, PEM material (key encrypted), and expiry.
func (m *Manager) Obtain(ctx context.Context, cert *store.Certificate) error {
	now := time.Now()
	cert.LastAttemptAt = &now
	cert.Status = store.CertStatusPending
	_ = m.store.UpdateCertificate(ctx, cert)

	res, err := m.obtain(ctx, cert)
	if err != nil {
		cert.Status = store.CertStatusFailed
		cert.LastError = err.Error()
		_ = m.store.UpdateCertificate(ctx, cert)
		m.log.Error("certificate issuance failed", "domains", cert.Domains, "err", err)
		return err
	}

	keyEnc, err := m.box.EncryptString(string(res.PrivateKey))
	if err != nil {
		return err
	}
	cert.CertPEM = string(res.Certificate)
	cert.KeyPEMEnc = keyEnc
	cert.Status = store.CertStatusValid
	cert.LastError = ""
	if exp, perr := leafExpiry(res.Certificate); perr == nil {
		cert.ExpiresAt = &exp
	}
	cert.IssuedAt = &now
	if err := m.store.UpdateCertificate(ctx, cert); err != nil {
		return err
	}
	m.log.Info("certificate issued", "domains", cert.Domains, "expires", cert.ExpiresAt)
	return nil
}

func (m *Manager) obtain(ctx context.Context, cert *store.Certificate) (*certificate.Resource, error) {
	u, err := m.getOrCreateAccount(ctx, "")
	if err != nil {
		return nil, err
	}
	cfg := lego.NewConfig(u)
	cfg.CADirURL = m.caURL()
	cfg.Certificate.KeyType = certcrypto.EC256
	client, err := lego.NewClient(cfg)
	if err != nil {
		return nil, err
	}

	switch cert.ChallengeType {
	case "dns-01":
		if cert.DNSProviderID == "" {
			return nil, fmt.Errorf("dns-01 challenge requires a DNS provider")
		}
		provider, cleanup, err := m.dnsProvider(ctx, cert.DNSProviderID)
		if err != nil {
			return nil, err
		}
		defer cleanup()
		var dnsOpts []dns01.ChallengeOption
		if len(m.dnsResolvers) > 0 {
			// Validate propagation against the configured resolvers (split-horizon or a
			// test DNS server) and don't require authoritative-NS agreement.
			dnsOpts = append(dnsOpts,
				dns01.AddRecursiveNameservers(m.dnsResolvers),
				dns01.DisableAuthoritativeNssPropagationRequirement())
		}
		if err := client.Challenge.SetDNS01Provider(provider, dnsOpts...); err != nil {
			return nil, err
		}
	default: // http-01
		if err := client.Challenge.SetHTTP01Provider(m.responder); err != nil {
			return nil, err
		}
	}

	req := certificate.ObtainRequest{Domains: cert.Domains, Bundle: true}
	res, err := client.Certificate.Obtain(req)
	if err != nil {
		return nil, err
	}
	return res, nil
}

// dnsProvider builds a lego DNS challenge provider from stored, encrypted
// credentials. lego providers read config from process environment variables, so
// we set them under a mutex for the duration of issuance and restore afterwards.
func (m *Manager) dnsProvider(ctx context.Context, id string) (provider interface {
	Present(domain, token, keyAuth string) error
	CleanUp(domain, token, keyAuth string) error
}, cleanup func(), err error) {
	rec, err := m.store.GetDNSProvider(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	cfgJSON, err := m.box.DecryptString(rec.ConfigEnc)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypt dns credentials: %w", err)
	}
	creds := map[string]string{}
	if err := json.Unmarshal([]byte(cfgJSON), &creds); err != nil {
		return nil, nil, err
	}

	m.envMu.Lock()
	restore := setEnv(creds)
	p, perr := dns.NewDNSChallengeProviderByName(rec.Provider)
	if perr != nil {
		restore()
		m.envMu.Unlock()
		return nil, nil, fmt.Errorf("dns provider %q: %w", rec.Provider, perr)
	}
	cleanup = func() {
		restore()
		m.envMu.Unlock()
	}
	return p, cleanup, nil
}

// leafExpiry parses the not-after of the leaf certificate from a PEM bundle.
func leafExpiry(certPEM []byte) (time.Time, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return time.Time{}, fmt.Errorf("no PEM block")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, err
	}
	return c.NotAfter, nil
}
