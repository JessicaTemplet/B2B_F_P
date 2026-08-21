package scim

import (
	"net/http"

	"b2bfp/internal/store"
)

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request, tenantID string) {
	filterNode, err := ParseFilter(r.URL.Query().Get("filter"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalidFilter", err.Error())
		return
	}
	all, err := s.Store.ListUsers(tenantID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "", err.Error())
		return
	}
	var matched []*store.User
	for _, u := range all {
		if filterNode == nil || filterNode.Eval(u) {
			matched = append(matched, u)
		}
	}
	startIndex, count := parsePaging(r)
	resp := ListResponse{
		Schemas:      []string{SchemaListResp},
		TotalResults: len(matched),
		StartIndex:   startIndex,
		Resources:    []any{},
	}
	lo := startIndex - 1
	if lo < 0 {
		lo = 0
	}
	if lo < len(matched) {
		hi := lo + count
		if hi > len(matched) {
			hi = len(matched)
		}
		for _, u := range matched[lo:hi] {
			resp.Resources = append(resp.Resources, toUserResource(u, s.base(tenantID)))
		}
	}
	resp.ItemsPerPage = len(resp.Resources)
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) getUser(w http.ResponseWriter, r *http.Request, tenantID string) {
	u, err := s.Store.GetUser(tenantID, idFrom(r))
	if err == store.ErrNotFound {
		writeError(w, http.StatusNotFound, "", "user not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, toUserResource(u, s.base(tenantID)))
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request, tenantID string) {
	var in UserResource
	if err := decodeBody(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalidSyntax", "malformed JSON body")
		return
	}
	if in.UserName == "" {
		writeError(w, http.StatusBadRequest, "invalidValue", "userName is required")
		return
	}
	if _, err := s.Store.FindUserByUserName(tenantID, in.UserName); err == nil {
		writeError(w, http.StatusConflict, "uniqueness", "a user with this userName already exists")
		return
	}
	u := &store.User{TenantID: tenantID, Attributes: map[string]any{}}
	applyUserResource(u, &in)
	if err := s.Store.CreateUser(u); err != nil {
		if err == store.ErrConflict {
			writeError(w, http.StatusConflict, "uniqueness", "a user with this userName already exists")
			return
		}
		writeError(w, http.StatusInternalServerError, "", err.Error())
		return
	}
	w.Header().Set("Location", userLocation(s.base(tenantID), u.ID))
	writeJSON(w, http.StatusCreated, toUserResource(u, s.base(tenantID)))
}

func (s *Server) replaceUser(w http.ResponseWriter, r *http.Request, tenantID string) {
	existing, err := s.Store.GetUser(tenantID, idFrom(r))
	if err == store.ErrNotFound {
		writeError(w, http.StatusNotFound, "", "user not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "", err.Error())
		return
	}
	var in UserResource
	if err := decodeBody(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalidSyntax", "malformed JSON body")
		return
	}
	applyUserResource(existing, &in)
	if err := s.Store.ReplaceUser(existing); err != nil {
		writeError(w, http.StatusInternalServerError, "", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, toUserResource(existing, s.base(tenantID)))
}

func (s *Server) patchUser(w http.ResponseWriter, r *http.Request, tenantID string) {
	existing, err := s.Store.GetUser(tenantID, idFrom(r))
	if err == store.ErrNotFound {
		writeError(w, http.StatusNotFound, "", "user not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "", err.Error())
		return
	}
	var req PatchRequest
	if err := decodeBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalidSyntax", "malformed JSON body")
		return
	}
	if err := applyUserPatch(existing, req.Operations); err != nil {
		writeError(w, http.StatusBadRequest, "invalidValue", err.Error())
		return
	}
	if err := s.Store.ReplaceUser(existing); err != nil {
		writeError(w, http.StatusInternalServerError, "", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, toUserResource(existing, s.base(tenantID)))
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request, tenantID string) {
	err := s.Store.DeleteUser(tenantID, idFrom(r))
	if err == store.ErrNotFound {
		writeError(w, http.StatusNotFound, "", "user not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "", err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
