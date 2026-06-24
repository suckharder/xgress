// Package version carries build-time metadata about the xgress binary and the
// Traefik release it is pinned to.
package version

// These are overridden at build time via -ldflags "-X ...".
var (
	// Version is the xgress release version (overridden at build time via -ldflags).
	Version = "0.10.0-rc.1"
	// Commit is the git commit the binary was built from.
	Commit = "unknown"
	// Date is the build date in RFC3339.
	Date = "unknown"
)

// TraefikVersion is the Traefik release whose config structs this build is
// compiled against. xgress pins a single Traefik version per release so that the
// generated configuration can never drift from the structs we validate with.
const TraefikVersion = "v3.7.5"
