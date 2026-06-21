//go:build smoke

package smoke

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"
)

const tlsDomain = "tls.test"

// runTLSCheck uploads a self-signed cert, creates a TLS host that references it, and
// proves the EXACT uploaded leaf is presented on the HTTPS entrypoint. This is the
// one combination no other tier covers: through the real image, the provider serves
// the @@KEY placeholder and InjectKeys splices the decrypted key in at serve time,
// the supervised (or external) Traefik loads it, and presents it on :443.
func runTLSCheck(t *testing.T, client *http.Client, adminBase, httpsAddr string, v variant) {
	certPem, keyPem := selfSignedCert(t, tlsDomain)

	createCert, err := json.Marshal(map[string]any{
		"type":    "uploaded",
		"domains": []string{tlsDomain},
		"certPem": certPem,
		"keyPem":  keyPem,
	})
	if err != nil {
		t.Fatalf("marshal cert: %v", err)
	}
	code, b := postJSON(t, client, adminBase+"/api/certificates", string(createCert))
	if code != http.StatusCreated {
		t.Fatalf("upload cert = %d: %s", code, b)
	}
	var cert struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(b, &cert); err != nil || cert.ID == "" {
		t.Fatalf("cert id not returned: %v (%s)", err, b)
	}

	hostBody := `{"kind":"proxy","enabled":true,"domains":["` + tlsDomain +
		`"],"upstreams":[{"scheme":"http","host":"whoami","port":80}],"tls":"custom","certificateId":"` + cert.ID + `"}`
	if code, b := postJSON(t, client, adminBase+"/api/hosts", hostBody); code != http.StatusCreated {
		t.Fatalf("create tls host = %d: %s", code, b)
	}

	// Poll the HTTPS entrypoint until our leaf is served (Traefik first answers with
	// its default self-signed cert, then swaps in ours once the dynamic config lands).
	timeout := 30 * time.Second
	if v.external {
		timeout = 60 * time.Second
	}
	eventually(t, timeout, func() error {
		return dialAndCheckSAN(httpsAddr, tlsDomain)
	})
}

// dialAndCheckSAN TLS-dials addr with the given SNI and asserts the presented leaf
// carries that name as a SAN (i.e. it's our uploaded cert, not Traefik's default).
func dialAndCheckSAN(addr, sni string) error {
	d := &net.Dialer{Timeout: 3 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", addr, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, //nolint:gosec // self-signed test cert; we assert the SAN ourselves
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		return err
	}
	defer conn.Close()
	peer := conn.ConnectionState().PeerCertificates
	if len(peer) == 0 {
		return fmt.Errorf("no peer certificate presented")
	}
	for _, name := range peer[0].DNSNames {
		if name == sni {
			return nil
		}
	}
	return fmt.Errorf("served cert SAN %v does not include %q (default cert still in use?)", peer[0].DNSNames, sni)
}

// selfSignedCert generates a throwaway ECDSA leaf for domain, returning PEM strings.
func selfSignedCert(t *testing.T, domain string) (certPEM, keyPEM string) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{domain},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	return certPEM, keyPEM
}
