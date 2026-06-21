package traefikcfg

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// HashBytes returns the hex SHA-256 of b. Used for change detection of generated
// artifacts (e.g. the static config file).
func HashBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// keyPlaceholderPrefix marks where a certificate's private key must be spliced
// into the served JSON. Private keys are NEVER stored in the rendered/snapshotted
// configuration (that would duplicate secret material into rollback history);
// instead the renderer emits this placeholder and the provider endpoint injects
// the decrypted key only at the moment it serves config to Traefik.
const keyPlaceholderPrefix = "@@KEY:"

// KeyResolver returns the decrypted private-key PEM for a certificate id.
type KeyResolver func(certID string) (string, error)

// InjectKeys replaces every @@KEY:<certID> placeholder with the certificate's
// decrypted private key, returning a ready-to-serve document. It walks the JSON
// *structurally* and only ever rewrites `tls.certificates[].keyFile` fields — so
// attacker-controlled certificate PEM content (in certFile, an uploaded cert, a
// raw-config service, etc.) that happens to contain the "@@KEY:" sentinel can NOT
// trigger a spurious key resolution or break the served document.
func InjectKeys(rendered []byte, resolve KeyResolver) ([]byte, error) {
	if !strings.Contains(string(rendered), keyPlaceholderPrefix) {
		return rendered, nil // fast path: nothing to inject
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(rendered, &doc); err != nil {
		return nil, fmt.Errorf("inject keys: parse config: %w", err)
	}
	tlsRaw, ok := doc["tls"]
	if !ok {
		return rendered, nil
	}
	var tlsSection struct {
		Certificates []map[string]any `json:"certificates"`
		Stores       json.RawMessage  `json:"stores,omitempty"`
		Options      json.RawMessage  `json:"options,omitempty"`
	}
	if err := json.Unmarshal(tlsRaw, &tlsSection); err != nil {
		return nil, fmt.Errorf("inject keys: parse tls: %w", err)
	}
	changed := false
	kept := tlsSection.Certificates[:0] // filter in place: drop certs whose key won't resolve
	for _, cert := range tlsSection.Certificates {
		kf, ok := cert["keyFile"].(string)
		if !ok || !strings.HasPrefix(kf, keyPlaceholderPrefix) {
			kept = append(kept, cert) // real key (external cert) or no placeholder — keep
			continue
		}
		certID := strings.TrimPrefix(kf, keyPlaceholderPrefix)
		keyPEM, err := resolve(certID)
		if err != nil {
			// One cert's key failing must not blank the whole provider document
			// (which would block ALL config from reaching Traefik). Omit just this
			// certificate and serve the rest; the resolver logs the cause.
			changed = true
			continue
		}
		cert["keyFile"] = keyPEM
		kept = append(kept, cert)
		changed = true
	}
	if !changed {
		return rendered, nil
	}
	tlsSection.Certificates = kept
	// Re-encode only the tls section and splice it back, leaving the rest of the
	// document intact.
	newTLS := map[string]any{"certificates": tlsSection.Certificates}
	if len(tlsSection.Stores) > 0 {
		newTLS["stores"] = tlsSection.Stores
	}
	if len(tlsSection.Options) > 0 {
		newTLS["options"] = tlsSection.Options
	}
	tlsEnc, err := json.Marshal(newTLS)
	if err != nil {
		return nil, err
	}
	doc["tls"] = tlsEnc
	return json.Marshal(doc)
}
