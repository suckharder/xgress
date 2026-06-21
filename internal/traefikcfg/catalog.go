package traefikcfg

// CatalogField describes one parameter of a middleware so the UI can render a
// guided form field for it instead of raw JSON.
type CatalogField struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	// Type drives the input widget: "text" | "number" | "bool" | "list" |
	// "users" (basic-auth username/password helper).
	Type string `json:"type"`
	Help string `json:"help,omitempty"`
}

// CatalogEntry describes a supported middleware type for the UI: the Traefik
// JSON key, a friendly label, a short description, an example params object, and
// (optionally) a field spec for a guided form.
type CatalogEntry struct {
	Type        string         `json:"type"`
	Label       string         `json:"label"`
	Description string         `json:"description"`
	Example     map[string]any `json:"example"`
	Fields      []CatalogField `json:"fields,omitempty"`
}

// MiddlewareCatalog returns the curated set of middlewares xgress surfaces in the
// UI. Any valid Traefik middleware can still be created via raw params; this is
// the friendly subset with guided forms.
func MiddlewareCatalog() []CatalogEntry {
	return []CatalogEntry{
		{
			Type: "basicAuth", Label: "Basic Auth",
			Description: "HTTP Basic authentication. Enter username + password; xgress hashes it for you.",
			Example:     map[string]any{"users": []string{"admin:$apr1$..."}},
			Fields: []CatalogField{
				{Key: "users", Label: "Users", Type: "users", Help: "Username + password; the password is bcrypt-hashed automatically."},
			},
		},
		{
			Type: "ipAllowList", Label: "IP Allow List",
			Description: "Allow only the given client source ranges (CIDR).",
			Example:     map[string]any{"sourceRange": []string{"10.0.0.0/8", "192.168.0.0/16"}},
			Fields: []CatalogField{
				{Key: "sourceRange", Label: "Allowed ranges (CIDR)", Type: "list", Help: "One CIDR per line, e.g. 10.0.0.0/8"},
			},
		},
		{
			Type: "rateLimit", Label: "Rate Limit",
			Description: "Token-bucket rate limiting (average requests/s with burst).",
			Example:     map[string]any{"average": 100, "burst": 50},
			Fields: []CatalogField{
				{Key: "average", Label: "Average req/s", Type: "number"},
				{Key: "burst", Label: "Burst", Type: "number"},
			},
		},
		{
			Type: "compress", Label: "Compress",
			Description: "gzip/brotli/zstd response compression.",
			Example:     map[string]any{},
		},
		{
			Type: "headers", Label: "Headers / Security",
			Description: "Add or override request/response headers; HSTS, frame deny, etc.",
			Example: map[string]any{
				"stsSeconds": 31536000, "stsIncludeSubdomains": true,
				"frameDeny": true, "contentTypeNosniff": true, "browserXssFilter": true,
			},
		},
		{
			Type: "forwardAuth", Label: "Forward Auth",
			Description: "Delegate authentication to an external service (Authelia, Authentik).",
			Example:     map[string]any{"address": "http://authelia:9091/api/verify?rd=https://auth.example.com", "trustForwardHeader": true, "authResponseHeaders": []string{"Remote-User", "Remote-Groups"}},
			Fields: []CatalogField{
				{Key: "address", Label: "Auth service URL", Type: "text"},
				{Key: "trustForwardHeader", Label: "Trust X-Forwarded-* headers", Type: "bool"},
				{Key: "authResponseHeaders", Label: "Forward response headers", Type: "list"},
			},
		},
		{
			Type: "redirectScheme", Label: "Redirect Scheme",
			Description: "Redirect to another scheme (e.g. http→https).",
			Example:     map[string]any{"scheme": "https", "permanent": true},
			Fields: []CatalogField{
				{Key: "scheme", Label: "Scheme", Type: "text", Help: "e.g. https"},
				{Key: "permanent", Label: "Permanent (308)", Type: "bool"},
			},
		},
		{
			Type: "redirectRegex", Label: "Redirect Regex",
			Description: "Redirect using a regex match/replacement on the URL.",
			Example:     map[string]any{"regex": "^https?://example\\.com/(.*)", "replacement": "https://www.example.com/${1}", "permanent": true},
		},
		{
			Type: "stripPrefix", Label: "Strip Prefix",
			Description: "Remove path prefixes before forwarding to the backend.",
			Example:     map[string]any{"prefixes": []string{"/api"}},
			Fields:      []CatalogField{{Key: "prefixes", Label: "Prefixes to strip", Type: "list"}},
		},
		{
			Type: "addPrefix", Label: "Add Prefix",
			Description: "Prepend a path prefix before forwarding to the backend.",
			Example:     map[string]any{"prefix": "/api"},
			Fields:      []CatalogField{{Key: "prefix", Label: "Prefix", Type: "text"}},
		},
		{
			Type: "buffering", Label: "Buffering",
			Description: "Buffer request/response bodies with size limits.",
			Example:     map[string]any{"maxRequestBodyBytes": 10485760},
			Fields:      []CatalogField{{Key: "maxRequestBodyBytes", Label: "Max request body (bytes)", Type: "number"}},
		},
		{
			Type: "inFlightReq", Label: "In-Flight Requests",
			Description: "Limit the number of simultaneous in-flight requests.",
			Example:     map[string]any{"amount": 100},
			Fields:      []CatalogField{{Key: "amount", Label: "Max concurrent requests", Type: "number"}},
		},
	}
}
