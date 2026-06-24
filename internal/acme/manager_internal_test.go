package acme

import "testing"

// TestCAURLPrecedence locks the directory-resolution order: an explicit CADirURL
// override beats the Staging flag, which beats production. This is the seam the
// e2e ACME tier relies on to point lego at Pebble.
func TestCAURLPrecedence(t *testing.T) {
	cases := []struct {
		name     string
		caDirURL string
		staging  bool
		want     string
	}{
		{"default is production", "", false, CADirProduction},
		{"staging flag selects staging", "", true, CADirStaging},
		{"override beats production", "https://pebble.test:14000/dir", false, "https://pebble.test:14000/dir"},
		{"override beats staging", "https://pebble.test:14000/dir", true, "https://pebble.test:14000/dir"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := &Manager{caDirURL: tc.caDirURL, staging: tc.staging}
			if got := m.caURL(); got != tc.want {
				t.Errorf("caURL() = %q, want %q", got, tc.want)
			}
		})
	}
}
