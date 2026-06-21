package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"

	"github.com/go-acme/lego/v4/registration"
)

// user implements lego's registration.User. The account private key is generated
// once per (email, CA) pair and stored encrypted; the registration resource is
// stored as JSON.
type user struct {
	email        string
	key          crypto.PrivateKey
	registration *registration.Resource
}

func (u *user) GetEmail() string                        { return u.email }
func (u *user) GetRegistration() *registration.Resource { return u.registration }
func (u *user) GetPrivateKey() crypto.PrivateKey        { return u.key }

// newAccountKey generates a fresh ECDSA P-256 account key.
func newAccountKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// marshalKey encodes an ECDSA private key to PEM for encrypted storage.
func marshalKey(key *ecdsa.PrivateKey) (string, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})), nil
}

// unmarshalKey decodes a PEM-encoded ECDSA private key.
func unmarshalKey(pemStr string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("invalid account key PEM")
	}
	return x509.ParseECPrivateKey(block.Bytes)
}

func marshalRegistration(r *registration.Resource) (string, error) {
	b, err := json.Marshal(r)
	return string(b), err
}

func unmarshalRegistration(s string) (*registration.Resource, error) {
	if s == "" {
		return nil, nil
	}
	var r registration.Resource
	if err := json.Unmarshal([]byte(s), &r); err != nil {
		return nil, err
	}
	return &r, nil
}
