package api

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/suckharder/xgress/internal/store"
	"github.com/suckharder/xgress/internal/traefikcfg"
)

func (s *Server) handleListHosts(w http.ResponseWriter, r *http.Request) {
	kind := store.HostKind(r.URL.Query().Get("kind"))
	hosts, err := s.store.ListHosts(r.Context(), kind)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if hosts == nil {
		hosts = []*store.Host{}
	}
	writeJSON(w, http.StatusOK, hosts)
}

func (s *Server) handleGetHost(w http.ResponseWriter, r *http.Request) {
	h, err := s.store.GetHost(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, notFoundIf(err), err.Error())
		return
	}
	writeJSON(w, http.StatusOK, h)
}

// upstreamAdapter lets store.Upstream satisfy the validator's interface.
type upstreamAdapter struct{ u store.Upstream }

func (a upstreamAdapter) GetScheme() string { return a.u.Scheme }
func (a upstreamAdapter) GetHost() string   { return a.u.Host }

func validateHost(h *store.Host) []traefikcfg.ValidationIssue {
	var issues []traefikcfg.ValidationIssue

	switch {
	case h.Kind == store.HostKindStream:
		if h.StreamEntryPoint == "" {
			issues = append(issues, traefikcfg.ValidationIssue{Field: "streamEntryPoint", Message: "an entrypoint is required"})
		}
		if len(h.Upstreams) == 0 || h.Upstreams[0].Host == "" || h.Upstreams[0].Port == 0 {
			issues = append(issues, traefikcfg.ValidationIssue{Field: "upstreams", Message: "a backend host and port are required"})
		}
		if h.TLSPassthrough && len(h.Domains) == 0 {
			issues = append(issues, traefikcfg.ValidationIssue{Field: "domains", Message: "TLS passthrough requires at least one SNI hostname"})
		}

	case h.Kind == store.HostKindProxy && h.ServiceMode != "" && h.ServiceMode != "single":
		// Composition modes (weighted/failover/mirroring) use backend groups, not the
		// top-level upstreams.
		if len(h.Domains) == 0 {
			issues = append(issues, traefikcfg.ValidationIssue{Field: "domains", Message: "at least one domain is required"})
		}
		min := 1
		if h.ServiceMode == "failover" || h.ServiceMode == "mirroring" {
			min = 2
		}
		if len(h.BackendGroups) < min {
			issues = append(issues, traefikcfg.ValidationIssue{Field: "backendGroups", Message: "this mode needs at least " + strconv.Itoa(min) + " backend group(s)"})
		}
		for i, g := range h.BackendGroups {
			if len(g.Upstreams) == 0 || g.Upstreams[0].Host == "" {
				issues = append(issues, traefikcfg.ValidationIssue{Field: "backendGroups[" + strconv.Itoa(i) + "]", Message: "each group needs a backend host"})
			}
		}

	default: // single-service proxy, redirection, dead
		adapters := make([]upstreamAdapter, len(h.Upstreams))
		for i, u := range h.Upstreams {
			adapters[i] = upstreamAdapter{u}
		}
		issues = append(issues, traefikcfg.ValidateHostInputs(string(h.Kind), h.Domains, adapters, h.RedirectTo)...)
	}

	// Common to EVERY kind/mode: validate the values that reach Traefik router rule
	// strings (host domains → Host()/HostSNI(); location path prefixes → PathPrefix()).
	// Centralized here so no branch above can skip it. Plus CORS and per-host raw YAML.
	pathPrefixes := make([]string, len(h.Locations))
	for i, loc := range h.Locations {
		pathPrefixes[i] = loc.PathPrefix
	}
	issues = append(issues, traefikcfg.ValidateRuleInputs(h.Domains, pathPrefixes)...)
	issues = append(issues, corsIssues(h)...)
	issues = append(issues, rawYAMLIssues(h)...)
	return issues
}

// corsIssues validates the per-host CORS settings: at least one origin when
// enabled, and no wildcard origin when credentials are allowed (the CORS spec
// forbids "*" with credentials — browsers reject such responses).
func corsIssues(h *store.Host) []traefikcfg.ValidationIssue {
	if !h.CORSEnabled {
		return nil
	}
	var issues []traefikcfg.ValidationIssue
	var nonEmpty int
	for _, o := range h.CORSAllowOrigins {
		if strings.TrimSpace(o) != "" {
			nonEmpty++
		}
		if h.CORSAllowCredentials && strings.TrimSpace(o) == "*" {
			issues = append(issues, traefikcfg.ValidationIssue{Field: "corsAllowOrigins", Message: `a wildcard origin "*" cannot be combined with "allow credentials"`})
		}
	}
	if nonEmpty == 0 {
		issues = append(issues, traefikcfg.ValidationIssue{Field: "corsAllowOrigins", Message: "at least one allowed origin is required when CORS is enabled"})
	}
	return issues
}

// rawYAMLIssues validates a host's per-host raw passthrough: it must parse (which
// also rejects routers whose priority invades xgress's reserved band, see
// ParseRawConfig) and must NOT define routers — per-host raw is middlewares +
// services only; routers belong in the admin-only global raw config.
func rawYAMLIssues(h *store.Host) []traefikcfg.ValidationIssue {
	if strings.TrimSpace(h.RawYAML) == "" {
		return nil
	}
	frag, err := traefikcfg.ParseRawConfig(h.RawYAML)
	if err != nil {
		return []traefikcfg.ValidationIssue{{Field: "rawYaml", Message: err.Error()}}
	}
	if frag != nil && frag.HTTP != nil && len(frag.HTTP.Routers) > 0 {
		return []traefikcfg.ValidationIssue{{Field: "rawYaml", Message: "per-host raw config supports middlewares and services only; define routers in the global raw config (admin)"}}
	}
	if frag != nil && frag.TCP != nil && len(frag.TCP.Routers) > 0 {
		return []traefikcfg.ValidationIssue{{Field: "rawYaml", Message: "per-host raw config does not support TCP routers"}}
	}
	if err := traefikcfg.CheckRawServiceTargets(frag); err != nil {
		return []traefikcfg.ValidationIssue{{Field: "rawYaml", Message: err.Error()}}
	}
	return nil
}

// rawYAMLRequiresAdmin enforces that only admins may set or change a host's
// RawYAML (per-host raw passthrough is as powerful as the admin-only global raw
// config). For non-admins it preserves the existing value rather than erroring on
// an unchanged round-trip, so operators can still edit other fields of a
// raw-bearing host; it returns true only when a non-admin tries to set or change
// raw to a new non-empty value.
func (s *Server) rawYAMLRequiresAdmin(r *http.Request, h *store.Host, existing *store.Host) (forbidden bool) {
	if u := userFrom(r.Context()); u != nil && u.Role == store.RoleAdmin {
		return false
	}
	prev := ""
	if existing != nil {
		prev = existing.RawYAML
	}
	if strings.TrimSpace(h.RawYAML) == "" {
		h.RawYAML = prev // non-admin cannot clear; preserve existing (empty on create)
		return false
	}
	return h.RawYAML != prev
}

func (s *Server) handleCreateHost(w http.ResponseWriter, r *http.Request) {
	var h store.Host
	if err := decodeJSON(r, &h); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	h.ID = ""
	if h.Kind == "" {
		h.Kind = store.HostKindProxy
	}
	if s.rawYAMLRequiresAdmin(r, &h, nil) {
		writeErr(w, http.StatusForbidden, "setting per-host rawYaml requires the admin role")
		return
	}
	if issues := validateHost(&h); len(issues) > 0 {
		writeIssues(w, issues)
		return
	}
	if err := s.store.CreateHost(r.Context(), &h); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.reloadAfterChange(r.Context()); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "saved but config invalid: "+err.Error())
		return
	}
	s.audit(r, "host.create", h.ID, string(h.Kind))
	writeJSON(w, http.StatusCreated, h)
}

func (s *Server) handleUpdateHost(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	existing, err := s.store.GetHost(r.Context(), id)
	if err != nil {
		writeErr(w, notFoundIf(err), err.Error())
		return
	}
	var h store.Host
	if err := decodeJSON(r, &h); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	h.ID = existing.ID
	h.CreatedAt = existing.CreatedAt
	if h.Kind == "" {
		h.Kind = existing.Kind
	}
	if s.rawYAMLRequiresAdmin(r, &h, existing) {
		writeErr(w, http.StatusForbidden, "modifying per-host rawYaml requires the admin role")
		return
	}
	if issues := validateHost(&h); len(issues) > 0 {
		writeIssues(w, issues)
		return
	}
	if err := s.store.UpdateHost(r.Context(), &h); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.reloadAfterChange(r.Context()); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "saved but config invalid: "+err.Error())
		return
	}
	s.audit(r, "host.update", h.ID, "")
	writeJSON(w, http.StatusOK, h)
}

func (s *Server) handleDeleteHost(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.store.DeleteHost(r.Context(), id); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.reloadAfterChange(r.Context())
	s.audit(r, "host.delete", id, "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func writeIssues(w http.ResponseWriter, issues []traefikcfg.ValidationIssue) {
	out := make([]map[string]string, len(issues))
	for i, is := range issues {
		out[i] = map[string]string{"field": is.Field, "message": is.Message}
	}
	writeJSON(w, http.StatusBadRequest, apiError{Error: "validation failed", Issues: out})
}
