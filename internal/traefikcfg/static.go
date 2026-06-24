package traefikcfg

import (
	"bytes"
	"fmt"
	"sort"

	"gopkg.in/yaml.v3"

	"github.com/suckharder/xgress/internal/config"
)

// StaticParams describes everything needed to generate Traefik's static
// configuration. Static config is the only thing that requires a Traefik
// restart, so xgress keeps it minimal and stable: entrypoints, the HTTP provider,
// and the read-only API. Crucially there are NO ACME certificate resolvers here
// — xgress owns ACME itself and serves certs dynamically — so adding a DNS provider
// or a new certificate never touches static config and never needs a restart.
type StaticParams struct {
	HTTPEntryPoint    string
	HTTPSEntryPoint   string
	HTTPPort          int
	HTTPSPort         int
	ProviderEndpoint  string // e.g. http://127.0.0.1:9000/api/provider
	ProviderToken     string // sent as the ProviderTokenHeader on each poll (auth)
	PollInterval      string // e.g. "1s"
	StreamEntryPoints []config.StreamEntryPoint
	APIListen         string // loopback addr for Traefik's read-only API (empty = off)
	LogLevel          string
	AccessLog         bool
	MetricsProm       bool

	// Minimal strips everything non-essential (read-only API, metrics, access log,
	// stream entrypoints) leaving only the HTTP/HTTPS entrypoints and the HTTP
	// provider. The self-heal escalation ladder writes a minimal config as a
	// last resort so Traefik always boots.
	Minimal bool
}

// RenderStatic produces the YAML bytes for traefik.yml.
func RenderStatic(p StaticParams) ([]byte, error) {
	if p.LogLevel == "" {
		p.LogLevel = "INFO"
	}
	entryPoints := map[string]any{
		p.HTTPEntryPoint: map[string]any{
			"address": fmt.Sprintf(":%d", p.HTTPPort),
		},
		p.HTTPSEntryPoint: map[string]any{
			"address": fmt.Sprintf(":%d", p.HTTPSPort),
		},
	}
	// Additional TCP/UDP stream entrypoints, declared in process config to match
	// container-published ports. Skipped in minimal (recovery) mode.
	if !p.Minimal {
		for _, l := range p.StreamEntryPoints {
			entryPoints[l.Name] = map[string]any{"address": fmt.Sprintf(":%d/%s", l.Port, protoOrTCP(l.Proto))}
		}
	}

	// Traefik's own read-only API + dashboard, bound to a loopback entrypoint so
	// xgress can read live state. api.insecure serves it on this entrypoint without
	// auth — safe because the address is loopback-only.
	api := map[string]any{"dashboard": false, "insecure": false}
	if p.APIListen != "" && !p.Minimal {
		entryPoints["traefik"] = map[string]any{"address": p.APIListen}
		api = map[string]any{"dashboard": true, "insecure": true}
	}

	httpProvider := map[string]any{
		"endpoint":     p.ProviderEndpoint,
		"pollInterval": p.PollInterval,
		"pollTimeout":  "5s",
	}
	if p.ProviderToken != "" {
		// Traefik sends these headers on every poll of the endpoint; xgress requires
		// the token to serve the (decrypted-key-bearing) provider document.
		httpProvider["headers"] = map[string]any{config.ProviderTokenHeader: p.ProviderToken}
	}
	root := map[string]any{
		"entryPoints": entryPoints,
		"providers": map[string]any{
			"http": httpProvider,
		},
		"api": api,
		"log": map[string]any{
			"level":  p.LogLevel,
			"format": "json",
		},
		"ping": map[string]any{
			"entryPoint": p.HTTPEntryPoint,
		},
	}
	if p.AccessLog && !p.Minimal {
		root["accessLog"] = map[string]any{"format": "json"}
	}
	if p.MetricsProm && !p.Minimal {
		root["metrics"] = map[string]any{"prometheus": map[string]any{"addEntryPointsLabels": true, "addRoutersLabels": true}}
	}

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(sortedMap(root)); err != nil {
		return nil, err
	}
	_ = enc.Close()
	return buf.Bytes(), nil
}

func protoOrTCP(proto string) string {
	if proto == "udp" {
		return "udp"
	}
	return "tcp"
}

// sortedMap recursively converts map[string]any into yaml.MapSlice-equivalent
// ordering so the generated file is stable (deterministic key order).
func sortedMap(m map[string]any) yaml.Node {
	var node yaml.Node
	node.Kind = yaml.MappingNode
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		keyNode := yaml.Node{Kind: yaml.ScalarNode, Value: k}
		var valNode yaml.Node
		switch v := m[k].(type) {
		case map[string]any:
			valNode = sortedMap(v)
		default:
			_ = valNode.Encode(v)
		}
		node.Content = append(node.Content, &keyNode, &valNode)
	}
	return node
}
