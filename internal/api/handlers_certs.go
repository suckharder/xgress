package api

import (
	"context"
	"net/http"
	"runtime/debug"
	"strings"

	"github.com/suckharder/xgress/internal/store"
)

func (s *Server) handleListCerts(w http.ResponseWriter, r *http.Request) {
	cs, err := s.store.ListCertificates(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if cs == nil {
		cs = []*store.Certificate{}
	}
	writeJSON(w, http.StatusOK, cs)
}

type createCertReq struct {
	Type          store.CertType `json:"type"`
	Domains       []string       `json:"domains"`
	ChallengeType string         `json:"challengeType"`
	DNSProviderID string         `json:"dnsProviderId"`
	// For uploaded certs:
	CertPEM string `json:"certPem"`
	KeyPEM  string `json:"keyPem"`
}

func (s *Server) handleCreateCert(w http.ResponseWriter, r *http.Request) {
	var req createCertReq
	if err := decodeJSONStrict(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if len(req.Domains) == 0 {
		writeErr(w, http.StatusBadRequest, "at least one domain is required")
		return
	}
	c := &store.Certificate{
		Type:          req.Type,
		Domains:       req.Domains,
		ChallengeType: req.ChallengeType,
		DNSProviderID: req.DNSProviderID,
		AutoRenew:     true,
		Status:        store.CertStatusPending,
	}
	if c.Type == "" {
		c.Type = store.CertTypeACME
	}

	switch c.Type {
	case store.CertTypeUploaded:
		if req.CertPEM == "" || req.KeyPEM == "" {
			writeErr(w, http.StatusBadRequest, "certPem and keyPem are required")
			return
		}
		keyEnc, err := s.box.EncryptString(req.KeyPEM)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		c.CertPEM = req.CertPEM
		c.KeyPEMEnc = keyEnc
		c.Status = store.CertStatusValid
		c.AutoRenew = false
		if err := s.store.CreateCertificate(r.Context(), c); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		_ = s.reloadAfterChange(r.Context())
	case store.CertTypeACME:
		if c.ChallengeType == "" {
			c.ChallengeType = "http-01"
		}
		if err := s.store.CreateCertificate(r.Context(), c); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		// Issue asynchronously so the request returns promptly; the UI polls status.
		s.issueAsync(c)
	default:
		writeErr(w, http.StatusBadRequest, "unknown certificate type")
		return
	}

	s.audit(r, "certificate.create", c.ID, strings.Join(c.Domains, ","))
	writeJSON(w, http.StatusCreated, c)
}

// issueAsync obtains a certificate in the background and reloads on success.
func (s *Server) issueAsync(c *store.Certificate) {
	go func() {
		// Single-shot goroutine: recover so a panic in lego/ACME issuance (or an
		// unwired ACME manager) is logged instead of crashing PID 1.
		defer func() {
			if r := recover(); r != nil {
				s.log.Error("panic recovered in async issuance", "panic", r, "stack", string(debug.Stack()))
			}
		}()
		ctx := context.Background()
		if err := s.engine.ACME().Obtain(ctx, c); err != nil {
			s.log.Error("async issuance failed", "domains", c.Domains, "err", err)
			return
		}
		if _, err := s.engine.Reload(ctx); err != nil {
			s.log.Error("reload after issuance", "err", err)
		}
	}()
}

func (s *Server) handleRenewCert(w http.ResponseWriter, r *http.Request) {
	c, err := s.store.GetCertificate(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, notFoundIf(err), err.Error())
		return
	}
	if c.Type != store.CertTypeACME {
		writeErr(w, http.StatusBadRequest, "only ACME certificates can be renewed")
		return
	}
	s.issueAsync(c)
	s.audit(r, "certificate.renew", c.ID, "")
	writeJSON(w, http.StatusAccepted, c)
}

func (s *Server) handleDeleteCert(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.store.DeleteCertificate(r.Context(), id); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.reloadAfterChange(r.Context())
	s.audit(r, "certificate.delete", id, "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
