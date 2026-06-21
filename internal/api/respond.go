package api

import (
	"encoding/json"
	"net/http"
)

// apiError is the JSON error envelope.
type apiError struct {
	Error  string              `json:"error"`
	Fields map[string]string   `json:"fields,omitempty"`
	Issues []map[string]string `json:"issues,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, apiError{Error: msg})
}

func decodeJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	return dec.Decode(v)
}

// decodeJSONStrict is decodeJSON with DisallowUnknownFields. Use it only for
// endpoints whose request struct fully captures the client payload — small,
// fixed-shape forms the SPA sends verbatim — so a renamed/typo'd field fails loudly
// instead of being silently dropped. Do NOT use it where the client echoes back a
// fuller object than the struct (full store.* structs; the notifications form, which
// carries a server-derived hasSmtpPass), for backup restore (cross-version
// portability), or for map[string]… bodies. Those stay on lenient decodeJSON.
func decodeJSONStrict(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}
