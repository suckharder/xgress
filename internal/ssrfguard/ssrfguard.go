// Package ssrfguard rejects outbound targets that point at the host's own
// loopback or link-local space (including the cloud-metadata endpoint
// 169.254.169.254). It is used to keep operator/admin-controlled outbound sinks —
// notification webhooks, SMTP servers, raw-config service backends — from being
// aimed at xgress's own loopback servers (the key-serving provider, the admin API) or
// the metadata service.
//
// Private ranges (10/8, 172.16/12, 192.168/16, fc00::/7) are intentionally
// ALLOWED: a self-hosted webhook or an internal proxy upstream on a private
// network is a legitimate target. The unambiguous-bad targets are loopback,
// link-local, and unspecified addresses.
package ssrfguard

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// CheckURL parses raw and rejects it when its host is (or resolves to) a blocked
// address. A parse failure or missing host is returned as an error.
func CheckURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if u.Host == "" {
		return fmt.Errorf("URL has no host")
	}
	return CheckHost(u.Hostname())
}

// CheckHost rejects host when it is, or resolves to, a loopback / link-local /
// unspecified address. Hostnames that don't resolve are allowed (fail-open on
// transient DNS — the literal-IP vectors are what matter most and are always
// caught).
func CheckHost(host string) error {
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if host == "" {
		return fmt.Errorf("empty host")
	}
	var ips []net.IP
	if ip := net.ParseIP(host); ip != nil {
		ips = []net.IP{ip}
	} else {
		resolved, err := net.LookupIP(host)
		if err != nil {
			return nil // cannot resolve; don't block legitimate hosts
		}
		ips = resolved
	}
	for _, ip := range ips {
		if blocked(ip) {
			return fmt.Errorf("target %q resolves to a disallowed address (%s): loopback/link-local/metadata are not permitted", host, ip)
		}
	}
	return nil
}

func blocked(ip net.IP) bool {
	return ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() || // 169.254.0.0/16 (incl. 169.254.169.254), fe80::/10
		ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() ||
		ip.IsUnspecified()
}
