//go:build integration

package e2e

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// selfSignedCert generates an ECDSA leaf certificate + PKCS#8 key for the given
// SNI domain, PEM-encoded. Used to seed an "uploaded" certificate so the test can
// prove @@KEY injection end to end: the rendered config carries a @@KEY:<id>
// placeholder, the provider injects the decrypted key at serve time, and Traefik
// must present this exact leaf on the HTTPS entrypoint.
func selfSignedCert(t *testing.T, domain string) (certPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: domain},
		DNSNames:              []string{domain},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return certPEM, keyPEM
}

// assertLeafSAN parses the leaf (first block) of a PEM bundle and fails unless its
// SANs include domain. Used to verify an issued/served certificate is the real one.
func assertLeafSAN(t *testing.T, certPEM, domain string) {
	t.Helper()
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		t.Fatalf("certificate is not valid PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse leaf certificate: %v", err)
	}
	for _, n := range leaf.DNSNames {
		if n == domain {
			return
		}
	}
	t.Errorf("leaf SAN %v does not include %q", leaf.DNSNames, domain)
}

// assertValidKeyPEM fails unless keyPEM decodes to a parseable private key.
func assertValidKeyPEM(t *testing.T, keyPEM string) {
	t.Helper()
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		t.Fatalf("private key is not valid PEM")
	}
	if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
		// lego may emit SEC1 EC keys ("EC PRIVATE KEY"); accept those too.
		if _, ecErr := x509.ParseECPrivateKey(block.Bytes); ecErr != nil {
			t.Fatalf("private key does not parse (pkcs8: %v; ec: %v)", err, ecErr)
		}
	}
}
