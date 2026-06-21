// Package secrets provides authenticated encryption for sensitive values stored
// in the database (DNS provider credentials, ACME private keys, uploaded
// certificate private keys). It uses AES-256-GCM with a per-installation random
// key persisted under the data directory.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Box performs symmetric encryption with a single installation key.
type Box struct {
	aead cipher.AEAD
}

// Load reads the key at keyFile, generating a new random 32-byte key on first
// use (mode 0600). This makes encryption-at-rest zero-configuration.
func Load(keyFile string) (*Box, error) {
	key, err := os.ReadFile(keyFile)
	if os.IsNotExist(err) {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, fmt.Errorf("generate secrets key: %w", err)
		}
		if err := os.MkdirAll(filepath.Dir(keyFile), 0o700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(keyFile, key, 0o600); err != nil {
			return nil, fmt.Errorf("persist secrets key: %w", err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("read secrets key: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("secrets key must be 32 bytes, got %d", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Box{aead: aead}, nil
}

// Encrypt returns a base64-encoded, self-describing ciphertext (nonce||ct).
func (b *Box) Encrypt(plaintext []byte) (string, error) {
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ct := b.aead.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ct), nil
}

// EncryptString is a convenience wrapper over Encrypt.
func (b *Box) EncryptString(s string) (string, error) { return b.Encrypt([]byte(s)) }

// Decrypt reverses Encrypt.
func (b *Box) Decrypt(token string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}
	ns := b.aead.NonceSize()
	if len(raw) < ns {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ct := raw[:ns], raw[ns:]
	return b.aead.Open(nil, nonce, ct, nil)
}

// DecryptString reverses EncryptString.
func (b *Box) DecryptString(token string) (string, error) {
	pt, err := b.Decrypt(token)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

const canaryPlaintext = "xgress-secret-key-canary-v1"

// VerifyKey guards against a swapped/lost secrets key silently bricking all
// encrypted-at-rest material (DNS credentials, certificate keys). On first use it
// writes a canary ciphertext at canaryFile; on every boot after, it decrypts the
// canary and returns an error if THIS key can't — i.e. the key differs from the one
// that encrypted existing data. Availability/operational only (decryption already
// fails closed): the caller surfaces the error loudly so the operator restores the
// original key instead of discovering broken secrets later, one feature at a time.
func (b *Box) VerifyKey(canaryFile string) error {
	data, err := os.ReadFile(canaryFile)
	if os.IsNotExist(err) {
		enc, err := b.EncryptString(canaryPlaintext)
		if err != nil {
			return err
		}
		return os.WriteFile(canaryFile, []byte(enc), 0o600)
	}
	if err != nil {
		return err
	}
	pt, err := b.DecryptString(strings.TrimSpace(string(data)))
	if err != nil || pt != canaryPlaintext {
		return fmt.Errorf("secrets key does not match the key that encrypted existing data: " +
			"encrypted secrets (DNS credentials, certificate keys) cannot be decrypted — " +
			"restore the original /data/secret.key")
	}
	return nil
}
