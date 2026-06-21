// Package traefikapi is a tiny read-only client for Traefik's own HTTP API,
// which xgress exposes on a loopback entrypoint (see XGRESS_TRAEFIK_API_LISTEN). It
// powers the live metrics/overview view and Docker-label router discovery —
// neither of which xgress can derive from its own database.
package traefikapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client reads Traefik's read-only API over loopback.
type Client struct {
	base string
	http *http.Client
}

// New returns a client for the given loopback address (host:port). Empty base
// disables it (methods return ErrDisabled).
func New(addr string) *Client {
	base := ""
	if addr != "" {
		base = "http://" + addr
	}
	return &Client{base: base, http: &http.Client{Timeout: 5 * time.Second}}
}

// ErrDisabled is returned when the Traefik API is not configured.
var ErrDisabled = fmt.Errorf("traefik API is not enabled")

// Enabled reports whether the API base is configured.
func (c *Client) Enabled() bool { return c.base != "" }

// Raw fetches an arbitrary API path (e.g. "/api/overview") and returns the body.
func (c *Client) Raw(ctx context.Context, path string) ([]byte, error) {
	if c.base == "" {
		return nil, ErrDisabled
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("traefik API %s -> %s", path, resp.Status)
	}
	return body, nil
}

// Router is the subset of Traefik's router API we use.
type Router struct {
	Name        string   `json:"name"`
	Rule        string   `json:"rule"`
	Service     string   `json:"service"`
	Status      string   `json:"status"`
	Provider    string   `json:"provider"`
	EntryPoints []string `json:"entryPoints"`
	Middlewares []string `json:"middlewares"`
	TLS         any      `json:"tls,omitempty"`
}

// Service is the subset of Traefik's service API we use.
type Service struct {
	Name         string            `json:"name"`
	Provider     string            `json:"provider"`
	Status       string            `json:"status"`
	Type         string            `json:"type"`
	LoadBalancer map[string]any    `json:"loadBalancer,omitempty"`
	ServerStatus map[string]string `json:"serverStatus,omitempty"`
}

// Routers returns all HTTP routers Traefik currently knows about.
func (c *Client) Routers(ctx context.Context) ([]Router, error) {
	b, err := c.Raw(ctx, "/api/http/routers")
	if err != nil {
		return nil, err
	}
	var rs []Router
	return rs, json.Unmarshal(b, &rs)
}

// Services returns all HTTP services (with per-server health) Traefik knows.
func (c *Client) Services(ctx context.Context) ([]Service, error) {
	b, err := c.Raw(ctx, "/api/http/services")
	if err != nil {
		return nil, err
	}
	var ss []Service
	return ss, json.Unmarshal(b, &ss)
}
