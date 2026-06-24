package secrets

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newBox(t *testing.T) *Box {
	t.Helper()
	b, err := Load(filepath.Join(t.TempDir(), "secret.key"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return b
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	b := newBox(t)
	cases := []string{
		"",
		"hello",
		"a longer secret with spaces and symbols !@#$%^&*()",
		strings.Repeat("x", 4096),
		"unicode: café — 日本語 — 🔐",
		"\x00\x01\x02 embedded nulls \x00",
	}
	for _, pt := range cases {
		ct, err := b.EncryptString(pt)
		if err != nil {
			t.Fatalf("encrypt %q: %v", pt, err)
		}
		if ct == pt && pt != "" {
			t.Fatalf("ciphertext equals plaintext for %q", pt)
		}
		got, err := b.DecryptString(ct)
		if err != nil {
			t.Fatalf("decrypt %q: %v", pt, err)
		}
		if got != pt {
			t.Fatalf("round-trip mismatch: got %q want %q", got, pt)
		}
	}
}

func TestEncryptIsNondeterministic(t *testing.T) {
	b := newBox(t)
	c1, _ := b.EncryptString("same-input")
	c2, _ := b.EncryptString("same-input")
	if c1 == c2 {
		t.Fatal("two encryptions of the same plaintext produced identical ciphertext (nonce reuse?)")
	}
	// Both must still decrypt to the same plaintext.
	p1, _ := b.DecryptString(c1)
	p2, _ := b.DecryptString(c2)
	if p1 != "same-input" || p2 != "same-input" {
		t.Fatalf("decrypt mismatch: %q / %q", p1, p2)
	}
}

func TestDecryptTamperedCiphertextFails(t *testing.T) {
	b := newBox(t)
	ct, _ := b.EncryptString("authentic message")
	raw, err := base64.StdEncoding.DecodeString(ct)
	if err != nil {
		t.Fatal(err)
	}
	// Flip a bit in the final (tag/payload) byte.
	raw[len(raw)-1] ^= 0x01
	tampered := base64.StdEncoding.EncodeToString(raw)
	if _, err := b.Decrypt(tampered); err == nil {
		t.Fatal("tampered ciphertext decrypted without error (GCM auth not enforced)")
	}
}

func TestDecryptWithWrongKeyFails(t *testing.T) {
	b1 := newBox(t)
	b2 := newBox(t) // different temp dir → different key
	ct, _ := b1.EncryptString("for b1 only")
	if _, err := b2.Decrypt(ct); err == nil {
		t.Fatal("ciphertext decrypted under a different installation key")
	}
}

func TestDecryptRejectsMalformedInput(t *testing.T) {
	b := newBox(t)
	for _, bad := range []string{"not base64!!!", "", "QQ=="} { // last is valid b64 but too short for a nonce
		if _, err := b.Decrypt(bad); err == nil {
			t.Fatalf("expected error decrypting malformed input %q", bad)
		}
	}
}

func TestKeyIsGeneratedAndPersisted(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "nested", "secret.key")
	b1, err := Load(keyFile)
	if err != nil {
		t.Fatalf("first Load: %v", err)
	}
	info, err := os.Stat(keyFile)
	if err != nil {
		t.Fatalf("key file not created: %v", err)
	}
	if info.Size() != 32 {
		t.Fatalf("key size = %d, want 32", info.Size())
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("key file perms = %o, want 600", perm)
	}
	// Reloading must reuse the same key, so old ciphertext still decrypts.
	ct, _ := b1.EncryptString("persisted")
	b2, err := Load(keyFile)
	if err != nil {
		t.Fatalf("second Load: %v", err)
	}
	got, err := b2.DecryptString(ct)
	if err != nil || got != "persisted" {
		t.Fatalf("reloaded box could not decrypt prior ciphertext: got %q err %v", got, err)
	}
}

func TestLoadRejectsWrongSizedKey(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "secret.key")
	if err := os.WriteFile(keyFile, bytes.Repeat([]byte{0x41}, 16), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(keyFile); err == nil {
		t.Fatal("Load accepted a 16-byte key; want error requiring 32 bytes")
	}
}

func TestRawEncryptDecryptBytes(t *testing.T) {
	b := newBox(t)
	payload := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF}
	ct, err := b.Encrypt(payload)
	if err != nil {
		t.Fatal(err)
	}
	got, err := b.Decrypt(ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("byte round-trip mismatch: %x vs %x", got, payload)
	}
}

func TestVerifyKeyCanary(t *testing.T) {
	dir := t.TempDir()
	canary := dir + "/secret.key.canary"
	b1 := newBox(t)
	if err := b1.VerifyKey(canary); err != nil {
		t.Fatalf("first VerifyKey (creates canary): %v", err)
	}
	if err := b1.VerifyKey(canary); err != nil {
		t.Fatalf("second VerifyKey (same key): %v", err)
	}
	// A different installation key must be detected as a mismatch.
	b2 := newBox(t)
	if err := b2.VerifyKey(canary); err == nil {
		t.Error("VerifyKey with a different key returned nil; key mismatch went undetected")
	}
}
