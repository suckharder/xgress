package api

import (
	"net/http"
	"strings"

	"github.com/suckharder/xgress/internal/store"
)

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	us, err := s.store.ListUsers(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if us == nil {
		us = []*store.User{}
	}
	writeJSON(w, http.StatusOK, us)
}

type createUserReq struct {
	Email    string     `json:"email"`
	Name     string     `json:"name"`
	Password string     `json:"password"`
	Role     store.Role `json:"role"`
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req createUserReq
	if err := decodeJSONStrict(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if !strings.Contains(req.Email, "@") || len(req.Password) < 8 {
		writeErr(w, http.StatusBadRequest, "valid email and 8+ char password required")
		return
	}
	if req.Role == "" {
		req.Role = store.RoleViewer
	}
	hash, err := hashPassword(req.Password)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	u := &store.User{Email: strings.ToLower(req.Email), Name: req.Name, PasswordHash: hash, Role: req.Role}
	if err := s.store.CreateUser(r.Context(), u); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	s.audit(r, "user.create", u.ID, string(u.Role))
	writeJSON(w, http.StatusCreated, u)
}

type updateUserReq struct {
	Name     string     `json:"name"`
	Role     store.Role `json:"role"`
	Password string     `json:"password"`
	Disabled *bool      `json:"disabled"`
}

func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	u, err := s.store.GetUser(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, notFoundIf(err), err.Error())
		return
	}
	var req updateUserReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.Name != "" {
		u.Name = req.Name
	}
	if req.Role != "" {
		u.Role = req.Role
	}
	if req.Disabled != nil {
		u.Disabled = *req.Disabled
	}
	if req.Password != "" {
		if len(req.Password) < 8 {
			writeErr(w, http.StatusBadRequest, "password must be at least 8 characters")
			return
		}
		hash, err := hashPassword(req.Password)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		u.PasswordHash = hash
	}
	if err := s.store.UpdateUser(r.Context(), u); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r, "user.update", u.ID, "")
	writeJSON(w, http.StatusOK, u)
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if me := userFrom(r.Context()); me != nil && me.ID == id {
		writeErr(w, http.StatusBadRequest, "cannot delete your own account")
		return
	}
	if err := s.store.DeleteUser(r.Context(), id); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r, "user.delete", id, "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
