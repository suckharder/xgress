package api

import (
	"net/http"

	"github.com/suckharder/xgress/internal/store"
	"github.com/suckharder/xgress/internal/traefikcfg"
)

func (s *Server) handleListMiddlewares(w http.ResponseWriter, r *http.Request) {
	ms, err := s.store.ListMiddlewares(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if ms == nil {
		ms = []*store.Middleware{}
	}
	writeJSON(w, http.StatusOK, ms)
}

func (s *Server) handleCreateMiddleware(w http.ResponseWriter, r *http.Request) {
	var m store.Middleware
	if err := decodeJSON(r, &m); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	m.ID = ""
	if issues := traefikcfg.ValidateMiddleware(m.Type, m.Params); len(issues) > 0 {
		writeIssues(w, issues)
		return
	}
	if err := s.store.CreateMiddleware(r.Context(), &m); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.reloadAfterChange(r.Context())
	s.audit(r, "middleware.create", m.ID, m.Type)
	writeJSON(w, http.StatusCreated, m)
}

func (s *Server) handleUpdateMiddleware(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	existing, err := s.store.GetMiddleware(r.Context(), id)
	if err != nil {
		writeErr(w, notFoundIf(err), err.Error())
		return
	}
	var m store.Middleware
	if err := decodeJSON(r, &m); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	m.ID = existing.ID
	if issues := traefikcfg.ValidateMiddleware(m.Type, m.Params); len(issues) > 0 {
		writeIssues(w, issues)
		return
	}
	if err := s.store.UpdateMiddleware(r.Context(), &m); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.reloadAfterChange(r.Context())
	s.audit(r, "middleware.update", m.ID, "")
	writeJSON(w, http.StatusOK, m)
}

func (s *Server) handleDeleteMiddleware(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.store.DeleteMiddleware(r.Context(), id); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.reloadAfterChange(r.Context())
	s.audit(r, "middleware.delete", id, "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// handleMiddlewareCatalog returns the supported middleware types and a short
// description so the UI can render a typed form for each.
func (s *Server) handleMiddlewareCatalog(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, traefikcfg.MiddlewareCatalog())
}
