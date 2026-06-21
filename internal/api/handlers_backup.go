package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/suckharder/xgress/internal/ssrfguard"
	"github.com/suckharder/xgress/internal/store"
	"github.com/suckharder/xgress/internal/traefikcfg"
)

// restorableSettingPrefixes is the allow-list of setting keys a backup may set.
// Restoring arbitrary keys is rejected, so a forged backup can't inject unknown
// settings (defense in depth alongside the per-sink SSRF guards).
var restorableSettingPrefixes = []string{
	"defaultsite.", "notify.", "plugins.", "ban.", "traefik.", "acme.", "raw.",
}

func restorableSetting(key string) bool {
	for _, p := range restorableSettingPrefixes {
		if strings.HasPrefix(key, p) {
			return true
		}
	}
	return false
}

// backupDoc is a logical export of xgress's configuration (not /data files). It is
// portable between instances that share the same secrets key (/data/secret.key)
// because DNS-provider credentials are encrypted at rest with that key.
// Certificates are intentionally excluded — ACME certs re-issue automatically.
type backupDoc struct {
	Version      int                 `json:"version"`
	ExportedAt   string              `json:"exportedAt"`
	Hosts        []*store.Host       `json:"hosts"`
	Middlewares  []*store.Middleware `json:"middlewares"`
	AccessLists  []*store.AccessList `json:"accessLists"`
	DNSProviders []dnsExport         `json:"dnsProviders"`
	Settings     map[string]string   `json:"settings"`
}

// dnsExport carries the encrypted credential blob so restore preserves it.
type dnsExport struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Provider   string   `json:"provider"`
	ConfigEnc  string   `json:"configEnc"`
	ConfigKeys []string `json:"configKeys"`
}

func (s *Server) handleBackupExport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hosts, _ := s.store.ListHosts(ctx, "")
	mws, _ := s.store.ListMiddlewares(ctx)
	acls, _ := s.store.ListAccessLists(ctx)
	dns, _ := s.store.ListDNSProviders(ctx)
	settings, _ := s.store.ListAllSettings(ctx)

	doc := backupDoc{
		Version: 1, ExportedAt: time.Now().UTC().Format(time.RFC3339),
		Hosts: hosts, Middlewares: mws, AccessLists: acls, Settings: settings,
	}
	for _, d := range dns {
		doc.DNSProviders = append(doc.DNSProviders, dnsExport{
			ID: d.ID, Name: d.Name, Provider: d.Provider, ConfigEnc: d.ConfigEnc, ConfigKeys: d.ConfigKeys,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="xgress-backup.json"`)
	writeJSON(w, http.StatusOK, doc)
	s.audit(r, "backup.export", "", "")
}

func (s *Server) handleBackupRestore(w http.ResponseWriter, r *http.Request) {
	var doc backupDoc
	if err := decodeJSON(r, &doc); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid backup file")
		return
	}
	ctx := r.Context()

	// Validate EVERYTHING before mutating: a forged/corrupt backup must not wipe
	// the live config or inject invalid/abusive hosts (each host is run through the
	// same validateHost as the API, which also rejects raw routers, reserved
	// priorities, and SSRF service targets). Restore is validate-all-then-apply.
	var issues []traefikcfg.ValidationIssue
	for i, h := range doc.Hosts {
		for _, iss := range validateHost(h) {
			iss.Field = "hosts[" + strconv.Itoa(i) + "]." + iss.Field
			issues = append(issues, iss)
		}
	}
	// Reject notify sinks aimed at loopback/link-local/metadata (SSRF) carried in a
	// forged backup, since the dispatcher delivers stored config without re-checking.
	if u := doc.Settings["notify.webhookUrl"]; u != "" {
		if err := ssrfguard.CheckURL(u); err != nil {
			issues = append(issues, traefikcfg.ValidationIssue{Field: "settings.notify.webhookUrl", Message: err.Error()})
		}
	}
	if h := doc.Settings["notify.smtpHost"]; h != "" {
		if err := ssrfguard.CheckHost(h); err != nil {
			issues = append(issues, traefikcfg.ValidationIssue{Field: "settings.notify.smtpHost", Message: err.Error()})
		}
	}
	if len(issues) > 0 {
		writeIssues(w, issues)
		return
	}

	// Wipe the config tables we own, then restore. (Users/certs are untouched.)
	if hosts, err := s.store.ListHosts(ctx, ""); err == nil {
		for _, h := range hosts {
			_ = s.store.DeleteHost(ctx, h.ID)
		}
	}
	if mws, err := s.store.ListMiddlewares(ctx); err == nil {
		for _, m := range mws {
			_ = s.store.DeleteMiddleware(ctx, m.ID)
		}
	}
	if acls, err := s.store.ListAccessLists(ctx); err == nil {
		for _, a := range acls {
			_ = s.store.DeleteAccessList(ctx, a.ID)
		}
	}
	if dns, err := s.store.ListDNSProviders(ctx); err == nil {
		for _, d := range dns {
			_ = s.store.DeleteDNSProvider(ctx, d.ID)
		}
	}

	for _, h := range doc.Hosts {
		_ = s.store.CreateHost(ctx, h)
	}
	for _, m := range doc.Middlewares {
		_ = s.store.CreateMiddleware(ctx, m)
	}
	for _, a := range doc.AccessLists {
		// Drop any malformed IP/CIDR from a restored allow-list so it can't break the
		// ipAllowList middleware build or reach the satisfy-any ClientIP() rule.
		if a != nil {
			a.AllowIPs, _ = traefikcfg.ParseAllowIPs(a.AllowIPs)
		}
		_ = s.store.CreateAccessList(ctx, a)
	}
	for _, d := range doc.DNSProviders {
		_ = s.store.CreateDNSProvider(ctx, &store.DNSProvider{
			ID: d.ID, Name: d.Name, Provider: d.Provider, ConfigEnc: d.ConfigEnc, ConfigKeys: d.ConfigKeys,
		})
	}
	for k, v := range doc.Settings {
		if !restorableSetting(k) {
			continue // ignore unknown/unsafe keys
		}
		_ = s.store.SetSetting(ctx, k, v)
	}

	if err := s.reloadAfterChange(ctx); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "restored but config invalid: "+err.Error())
		return
	}
	s.audit(r, "backup.restore", "", "")
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "restored",
		"hosts":  len(doc.Hosts), "middlewares": len(doc.Middlewares),
		"accessLists": len(doc.AccessLists), "dnsProviders": len(doc.DNSProviders),
	})
}
