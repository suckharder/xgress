package store

import (
	"encoding/json"

	"github.com/google/uuid"
)

// NewID returns a new random identifier for a row.
func NewID() string { return uuid.NewString() }

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		// The values we marshal are plain data structs; a failure here is a bug.
		panic(err)
	}
	return string(b)
}

func jsonInto(s string, v any) {
	if s == "" {
		return
	}
	_ = json.Unmarshal([]byte(s), v)
}
