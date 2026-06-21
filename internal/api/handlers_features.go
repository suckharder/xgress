package api

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"github.com/suckharder/xgress/internal/notify"
	"github.com/suckharder/xgress/internal/ssrfguard"
	"github.com/suckharder/xgress/internal/store"
	"github.com/suckharder/xgress/internal/traefikapi"
	"github.com/suckharder/xgress/internal/traefikcfg"
)

// ---------------- Access Lists (#3) + Basic Auth helper (#12) ----------------

type aclUserReq struct {
	Username string `json:"username"`
	Password string `json:"password"` // optional; if set, hashed server-side
	Hash     string `json:"hash"`     // optional existing hash (kept if password empty)
}

type aclReq struct {
	Name       string       `json:"name"`
	Users      []aclUserReq `json:"users"`
	AllowIPs   []string     `json:"allowIps"`
	SatisfyAny bool         `json:"satisfyAny"`
}

func (r aclReq) toUsers() ([]store.AccessListUser, error) {
	out := make([]store.AccessListUser, 0, len(r.Users))
	for _, u := range r.Users {
		if u.Username == "" {
			continue
		}
		hash := u.Hash
		if u.Password != "" {
			h, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
			if err != nil {
				return nil, err
			}
			hash = string(h)
		}
		if hash == "" {
			continue
		}
		out = append(out, store.AccessListUser{Username: u.Username, Hash: hash})
	}
	return out, nil
}

func (s *Server) handleListAccessLists(w http.ResponseWriter, r *http.Request) {
	as, err := s.store.ListAccessLists(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if as == nil {
		as = []*store.AccessList{}
	}
	writeJSON(w, http.StatusOK, as)
}

func (s *Server) handleCreateAccessList(w http.ResponseWriter, r *http.Request) {
	var req aclReq
	if err := decodeJSONStrict(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.Name == "" {
		writeErr(w, http.StatusBadRequest, "name is required")
		return
	}
	users, err := req.toUsers()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	allowIPs, invalid := traefikcfg.ParseAllowIPs(req.AllowIPs)
	if len(invalid) > 0 {
		writeErr(w, http.StatusBadRequest, "invalid IP/CIDR in allow list: "+strings.Join(invalid, ", "))
		return
	}
	a := &store.AccessList{Name: req.Name, Users: users, AllowIPs: allowIPs, SatisfyAny: req.SatisfyAny}
	if err := s.store.CreateAccessList(r.Context(), a); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	_ = s.reloadAfterChange(r.Context())
	s.audit(r, "accesslist.create", a.ID, a.Name)
	writeJSON(w, http.StatusCreated, a)
}

func (s *Server) handleUpdateAccessList(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	existing, err := s.store.GetAccessList(r.Context(), id)
	if err != nil {
		writeErr(w, notFoundIf(err), err.Error())
		return
	}
	var req aclReq
	if err := decodeJSONStrict(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	users, err := req.toUsers()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	allowIPs, invalid := traefikcfg.ParseAllowIPs(req.AllowIPs)
	if len(invalid) > 0 {
		writeErr(w, http.StatusBadRequest, "invalid IP/CIDR in allow list: "+strings.Join(invalid, ", "))
		return
	}
	existing.Name = req.Name
	existing.Users = users
	existing.AllowIPs = allowIPs
	existing.SatisfyAny = req.SatisfyAny
	if err := s.store.UpdateAccessList(r.Context(), existing); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.reloadAfterChange(r.Context())
	s.audit(r, "accesslist.update", id, "")
	writeJSON(w, http.StatusOK, existing)
}

func (s *Server) handleDeleteAccessList(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.store.DeleteAccessList(r.Context(), id); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.reloadAfterChange(r.Context())
	s.audit(r, "accesslist.delete", id, "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// handleHtpasswd hashes a username+password into an htpasswd line for the guided
// basicAuth middleware form (so users never run htpasswd themselves).
func (s *Server) handleHtpasswd(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &req); err != nil || req.Username == "" || req.Password == "" {
		writeErr(w, http.StatusBadRequest, "username and password are required")
		return
	}
	h, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"line": req.Username + ":" + string(h)})
}

// ---------------- Default Site (#1) ----------------

func (s *Server) handleGetDefaultSite(w http.ResponseWriter, r *http.Request) {
	g := func(k, d string) string {
		v, err := s.store.GetSetting(r.Context(), k)
		if err != nil || v == "" {
			return d
		}
		return v
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"mode":       g("defaultsite.mode", "404"),
		"redirectTo": g("defaultsite.redirectTo", ""),
		"html":       g("defaultsite.html", ""),
		"statusCode": g("defaultsite.statusCode", ""),
	})
}

func (s *Server) handleSetDefaultSite(w http.ResponseWriter, r *http.Request) {
	var in map[string]string
	if err := decodeJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	for _, k := range []string{"mode", "redirectTo", "html", "statusCode"} {
		if v, ok := in[k]; ok {
			if err := s.store.SetSetting(r.Context(), "defaultsite."+k, v); err != nil {
				writeErr(w, http.StatusInternalServerError, err.Error())
				return
			}
		}
	}
	_ = s.reloadAfterChange(r.Context())
	s.audit(r, "defaultsite.update", "", in["mode"])
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ---------------- Raw passthrough (#5) ----------------

func (s *Server) handleGetRawConfig(w http.ResponseWriter, r *http.Request) {
	v, _ := s.store.GetSetting(r.Context(), "raw.dynamicYaml")
	writeJSON(w, http.StatusOK, map[string]string{"yaml": v})
}

func (s *Server) handleSetRawConfig(w http.ResponseWriter, r *http.Request) {
	var in struct {
		YAML string `json:"yaml"`
	}
	if err := decodeJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	// Validate BEFORE persisting so a bad snippet can't poison the stored setting
	// (which would fail every subsequent reload). This also rejects raw services
	// aimed at loopback/link-local/metadata (SSRF) and routers in the reserved
	// priority band.
	frag, err := traefikcfg.ParseRawConfig(in.YAML)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if err := traefikcfg.CheckRawServiceTargets(frag); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if err := s.store.SetSetting(r.Context(), "raw.dynamicYaml", in.YAML); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.reloadAfterChange(r.Context()); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	s.audit(r, "rawconfig.update", "", "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ---------------- Security metrics (WAF) ----------------

func (s *Server) handleSecurityMetrics(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"wafEnabled": s.engine.WAFEnabled(r.Context()),
		"metrics":    s.engine.SecurityMetrics(),
	})
}

// ---------------- Host schedules (Round 4a) ----------------

func (s *Server) handleListSchedules(w http.ResponseWriter, r *http.Request) {
	scs, err := s.store.ListSchedules(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if scs == nil {
		scs = []*store.Schedule{}
	}
	writeJSON(w, http.StatusOK, scs)
}

func (s *Server) handleCreateSchedule(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Action string `json:"action"`
		Cron   string `json:"cron"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.Action != "enable" && req.Action != "disable" {
		writeErr(w, http.StatusBadRequest, "action must be enable or disable")
		return
	}
	if len(strings.Fields(req.Cron)) != 5 {
		writeErr(w, http.StatusBadRequest, "cron must have 5 fields (min hour dom month dow)")
		return
	}
	sc := &store.Schedule{HostID: r.PathValue("id"), Action: req.Action, Cron: req.Cron}
	if err := s.store.CreateSchedule(r.Context(), sc); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r, "schedule.create", sc.HostID, req.Action+" @ "+req.Cron)
	writeJSON(w, http.StatusCreated, sc)
}

func (s *Server) handleDeleteSchedule(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteSchedule(r.Context(), r.PathValue("id")); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// ---------------- Plugin platform: WAF + cache (Round 2) ----------------

func (s *Server) handleGetPlugins(w http.ResponseWriter, r *http.Request) {
	g := func(k string) string { v, _ := s.store.GetSetting(r.Context(), k); return v }
	directives := traefikcfg.DefaultWAFDirectives()
	if d := g("plugins.waf.directives"); d != "" {
		_ = json.Unmarshal([]byte(d), &directives)
	}
	ruleset := g("plugins.waf.ruleset")
	if ruleset == "" {
		ruleset = "curated"
	}
	// WAF is preloaded (opt-out): enabled unless explicitly turned off.
	wafEnabled := s.cfg.WAFPreload
	if v, err := s.store.GetSetting(r.Context(), "plugins.waf.enabled"); err == nil {
		wafEnabled = v == "true" || v == "1"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"wafEnabled":    wafEnabled,
		"wafRuleset":    ruleset,
		"wafDirectives": directives,
		"wafModule":     traefikcfg.WAFModuleName + " " + traefikcfg.WAFModuleVersion,
		"cacheEnabled":  g("plugins.cache.enabled") == "true",
		"cacheBackend":  s.engine.CacheBackendName(),
	})
}

func (s *Server) handleSetPlugins(w http.ResponseWriter, r *http.Request) {
	var req struct {
		WAFEnabled    bool     `json:"wafEnabled"`
		WAFRuleset    string   `json:"wafRuleset"`
		WAFDirectives []string `json:"wafDirectives"`
		CacheEnabled  bool     `json:"cacheEnabled"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	set := func(k, v string) { _ = s.store.SetSetting(r.Context(), k, v) }
	set("plugins.waf.enabled", boolStr(req.WAFEnabled))
	if req.WAFRuleset != "" {
		set("plugins.waf.ruleset", req.WAFRuleset)
	}
	set("plugins.cache.enabled", boolStr(req.CacheEnabled))
	if req.WAFDirectives != nil {
		b, _ := json.Marshal(req.WAFDirectives)
		set("plugins.waf.directives", string(b))
	}
	// Enabling/disabling the WAF changes static config → write it and restart
	// Traefik (it loads/unloads the plugin at startup). The native cache toggle
	// is a pure dynamic-config change (no restart) but SyncStatic is a no-op when
	// nothing changed.
	if err := s.engine.SyncStatic(r.Context(), false); err != nil {
		writeErr(w, http.StatusInternalServerError, "saved but restart failed: "+err.Error())
		return
	}
	_ = s.reloadAfterChange(r.Context())
	s.audit(r, "plugins.update", "", "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// ---------------- Config snapshots / rollback (#6) ----------------

func (s *Server) handleListSnapshots(w http.ResponseWriter, r *http.Request) {
	snaps, err := s.store.ListSnapshots(r.Context(), 50)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	type row struct {
		Version   int64  `json:"version"`
		Hash      string `json:"hash"`
		CreatedAt string `json:"createdAt"`
		Current   bool   `json:"current"`
	}
	cur := s.engine.Version()
	out := make([]row, 0, len(snaps))
	for _, sn := range snaps {
		out = append(out, row{Version: sn.Version, Hash: sn.Hash, CreatedAt: sn.CreatedAt.Format("2006-01-02 15:04:05"), Current: sn.Version == cur})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleGetSnapshot(w http.ResponseWriter, r *http.Request) {
	v, err := strconv.ParseInt(r.PathValue("version"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid version")
		return
	}
	snap, err := s.store.GetSnapshot(r.Context(), v)
	if err != nil {
		writeErr(w, notFoundIf(err), err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	var pretty any
	_ = json.Unmarshal([]byte(snap.JSON), &pretty)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(map[string]any{"version": snap.Version, "hash": snap.Hash, "config": pretty})
}

func (s *Server) handleRollback(w http.ResponseWriter, r *http.Request) {
	v, err := strconv.ParseInt(r.PathValue("version"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid version")
		return
	}
	if err := s.engine.Rollback(r.Context(), v); err != nil {
		writeErr(w, notFoundIf(err), err.Error())
		return
	}
	s.audit(r, "config.rollback", strconv.FormatInt(v, 10), "")
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "version": s.engine.Version()})
}

// ---------------- Metrics / live state (#7) ----------------

func (s *Server) handleTraefikOverview(w http.ResponseWriter, r *http.Request) {
	s.proxyTraefik(w, r, "/api/overview")
}

func (s *Server) handleTraefikRouters(w http.ResponseWriter, r *http.Request) {
	s.proxyTraefik(w, r, "/api/http/routers")
}

func (s *Server) handleTraefikServices(w http.ResponseWriter, r *http.Request) {
	s.proxyTraefik(w, r, "/api/http/services")
}

func (s *Server) proxyTraefik(w http.ResponseWriter, r *http.Request, path string) {
	body, err := s.engine.TraefikAPI().Raw(r.Context(), path)
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, "Traefik API unavailable: "+err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

// ---------------- Docker-label import (#8) ----------------

func (s *Server) handleDockerDiscover(w http.ResponseWriter, r *http.Request) {
	routers, err := s.engine.TraefikAPI().Routers(r.Context())
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, "Traefik API unavailable: "+err.Error())
		return
	}
	services, _ := s.engine.TraefikAPI().Services(r.Context())
	svcURL := map[string]string{}
	for _, sv := range services {
		svcURL[sv.Name] = firstServerURL(sv)
	}
	type disc struct {
		Name     string   `json:"name"`
		Rule     string   `json:"rule"`
		Domains  []string `json:"domains"`
		Service  string   `json:"service"`
		Upstream string   `json:"upstream"`
		Status   string   `json:"status"`
	}
	out := []disc{}
	for _, rt := range routers {
		if rt.Provider != "docker" {
			continue
		}
		out = append(out, disc{
			Name: rt.Name, Rule: rt.Rule, Domains: domainsFromRule(rt.Rule),
			Service: rt.Service, Upstream: svcURL[rt.Service], Status: rt.Status,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleDockerImport(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Names []string `json:"names"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	routers, err := s.engine.TraefikAPI().Routers(r.Context())
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	services, _ := s.engine.TraefikAPI().Services(r.Context())
	svcURL := map[string]string{}
	for _, sv := range services {
		svcURL[sv.Name] = firstServerURL(sv)
	}
	want := map[string]bool{}
	for _, n := range req.Names {
		want[n] = true
	}
	imported := 0
	for _, rt := range routers {
		if rt.Provider != "docker" || !want[rt.Name] {
			continue
		}
		domains := domainsFromRule(rt.Rule)
		up := parseUpstream(svcURL[rt.Service])
		if len(domains) == 0 || up == nil {
			continue
		}
		h := &store.Host{
			Kind: store.HostKindProxy, Enabled: false, Domains: domains,
			Upstreams: []store.Upstream{*up}, TLS: store.TLSNone,
			Notes: "Imported from Docker router " + rt.Name,
		}
		if err := s.store.CreateHost(r.Context(), h); err == nil {
			imported++
		}
	}
	_ = s.reloadAfterChange(r.Context())
	s.audit(r, "docker.import", "", strconv.Itoa(imported))
	writeJSON(w, http.StatusOK, map[string]int{"imported": imported})
}

func firstServerURL(sv traefikapi.Service) string {
	servers, _ := sv.LoadBalancer["servers"].([]any)
	for _, s := range servers {
		if m, ok := s.(map[string]any); ok {
			if u, ok := m["url"].(string); ok {
				return u
			}
		}
	}
	return ""
}

func parseUpstream(raw string) *store.Upstream {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil
	}
	port := 80
	if u.Scheme == "https" {
		port = 443
	}
	if p := u.Port(); p != "" {
		port, _ = strconv.Atoi(p)
	}
	return &store.Upstream{Scheme: u.Scheme, Host: u.Hostname(), Port: port}
}

func domainsFromRule(rule string) []string {
	var out []string
	for {
		i := strings.Index(rule, "Host(`")
		if i < 0 {
			break
		}
		rule = rule[i+len("Host(`"):]
		j := strings.Index(rule, "`")
		if j < 0 {
			break
		}
		out = append(out, rule[:j])
		rule = rule[j+1:]
	}
	return out
}

// ---------------- Notifications (#10) ----------------

func (s *Server) handleGetNotifications(w http.ResponseWriter, r *http.Request) {
	g := func(k string) string { v, _ := s.store.GetSetting(r.Context(), k); return v }
	hasPass := g("notify.smtpPassEnc") != ""
	writeJSON(w, http.StatusOK, map[string]any{
		"webhookUrl":  g("notify.webhookUrl"),
		"email":       g("notify.email"),
		"smtpHost":    g("notify.smtpHost"),
		"smtpPort":    g("notify.smtpPort"),
		"smtpUser":    g("notify.smtpUser"),
		"smtpFrom":    g("notify.smtpFrom"),
		"hasSmtpPass": hasPass,
	})
}

type notifyReq struct {
	WebhookURL string `json:"webhookUrl"`
	Email      string `json:"email"`
	SMTPHost   string `json:"smtpHost"`
	SMTPPort   string `json:"smtpPort"`
	SMTPUser   string `json:"smtpUser"`
	SMTPFrom   string `json:"smtpFrom"`
	SMTPPass   string `json:"smtpPass"` // optional; only updated if non-empty
}

func (s *Server) saveNotify(r *http.Request, req notifyReq) error {
	pairs := map[string]string{
		"notify.webhookUrl": req.WebhookURL,
		"notify.email":      req.Email,
		"notify.smtpHost":   req.SMTPHost,
		"notify.smtpPort":   req.SMTPPort,
		"notify.smtpUser":   req.SMTPUser,
		"notify.smtpFrom":   req.SMTPFrom,
	}
	for k, v := range pairs {
		if err := s.store.SetSetting(r.Context(), k, v); err != nil {
			return err
		}
	}
	if req.SMTPPass != "" {
		enc, err := s.box.EncryptString(req.SMTPPass)
		if err != nil {
			return err
		}
		if err := s.store.SetSetting(r.Context(), "notify.smtpPassEnc", enc); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) handleSetNotifications(w http.ResponseWriter, r *http.Request) {
	var req notifyReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.WebhookURL != "" {
		if err := ssrfguard.CheckURL(req.WebhookURL); err != nil {
			writeErr(w, http.StatusBadRequest, "webhook: "+err.Error())
			return
		}
	}
	if req.SMTPHost != "" {
		if err := ssrfguard.CheckHost(req.SMTPHost); err != nil {
			writeErr(w, http.StatusBadRequest, "smtp host: "+err.Error())
			return
		}
	}
	if err := s.saveNotify(r, req); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r, "notifications.update", "", "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleTestNotification(w http.ResponseWriter, r *http.Request) {
	// Use saved config (decrypted) for the test.
	g := func(k string) string { v, _ := s.store.GetSetting(r.Context(), k); return v }
	pass := ""
	if enc := g("notify.smtpPassEnc"); enc != "" {
		if p, err := s.box.DecryptString(enc); err != nil {
			s.log.Error("notify test: SMTP password failed to decrypt; sending without auth", "err", err)
		} else {
			pass = p
		}
	}
	cfg := notify.Config{
		WebhookURL: g("notify.webhookUrl"), EmailTo: g("notify.email"),
		SMTPHost: g("notify.smtpHost"), SMTPPort: g("notify.smtpPort"),
		SMTPUser: g("notify.smtpUser"), SMTPPass: pass, SMTPFrom: g("notify.smtpFrom"),
	}
	if cfg.WebhookURL != "" {
		if err := ssrfguard.CheckURL(cfg.WebhookURL); err != nil {
			writeErr(w, http.StatusBadRequest, "webhook: "+err.Error())
			return
		}
	}
	if cfg.SMTPHost != "" {
		if err := ssrfguard.CheckHost(cfg.SMTPHost); err != nil {
			writeErr(w, http.StatusBadRequest, "smtp host: "+err.Error())
			return
		}
	}
	if err := s.engine.Notifier().Test(r.Context(), cfg); err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "sent"})
}
