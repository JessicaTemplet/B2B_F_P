package scim

import (
	"net/http"
	"strings"

	"b2bfp/internal/store"
)

func (s *Server) listGroups(w http.ResponseWriter, r *http.Request, tenantID string) {
	all, err := s.Store.ListGroups(tenantID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "", err.Error())
		return
	}
	// Basic displayName filter support; the full grammar targets Users where
	// directory syncs actually rely on filtering (RFC 7644 §3.4.2.2 examples
	// are User-centric). Group filtering here covers the common `displayName
	// eq "..."` case IdPs use to check for existing groups before creating.
	filter := r.URL.Query().Get("filter")
	startIndex, count := parsePaging(r)
	var matched []*store.Group
	for _, g := range all {
		if filter == "" || matchesGroupFilter(g, filter) {
			matched = append(matched, g)
		}
	}
	resp := ListResponse{Schemas: []string{SchemaListResp}, TotalResults: len(matched), StartIndex: startIndex, Resources: []any{}}
	lo := startIndex - 1
	if lo < 0 {
		lo = 0
	}
	if lo < len(matched) {
		hi := lo + count
		if hi > len(matched) {
			hi = len(matched)
		}
		for _, g := range matched[lo:hi] {
			resp.Resources = append(resp.Resources, toGroupResource(g, s.base(tenantID)))
		}
	}
	resp.ItemsPerPage = len(resp.Resources)
	writeJSON(w, http.StatusOK, resp)
}

func matchesGroupFilter(g *store.Group, filter string) bool {
	f := strings.ToLower(strings.TrimSpace(filter))
	if strings.HasPrefix(f, "displayname eq ") {
		want := strings.Trim(strings.TrimPrefix(f, "displayname eq "), `"`)
		return strings.EqualFold(g.DisplayName, want)
	}
	return true
}

func (s *Server) getGroup(w http.ResponseWriter, r *http.Request, tenantID string) {
	g, err := s.Store.GetGroup(tenantID, idFrom(r))
	if err == store.ErrNotFound {
		writeError(w, http.StatusNotFound, "", "group not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, toGroupResource(g, s.base(tenantID)))
}

func (s *Server) createGroup(w http.ResponseWriter, r *http.Request, tenantID string) {
	var in GroupResource
	if err := decodeBody(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalidSyntax", "malformed JSON body")
		return
	}
	if in.DisplayName == "" {
		writeError(w, http.StatusBadRequest, "invalidValue", "displayName is required")
		return
	}
	g := &store.Group{TenantID: tenantID}
	applyGroupResource(g, &in)
	if err := s.Store.CreateGroup(g); err != nil {
		if err == store.ErrConflict {
			writeError(w, http.StatusConflict, "uniqueness", "a group with this displayName already exists")
			return
		}
		writeError(w, http.StatusInternalServerError, "", err.Error())
		return
	}
	w.Header().Set("Location", groupLocation(s.base(tenantID), g.ID))
	writeJSON(w, http.StatusCreated, toGroupResource(g, s.base(tenantID)))
}

func (s *Server) replaceGroup(w http.ResponseWriter, r *http.Request, tenantID string) {
	existing, err := s.Store.GetGroup(tenantID, idFrom(r))
	if err == store.ErrNotFound {
		writeError(w, http.StatusNotFound, "", "group not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "", err.Error())
		return
	}
	var in GroupResource
	if err := decodeBody(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalidSyntax", "malformed JSON body")
		return
	}
	applyGroupResource(existing, &in)
	if err := s.Store.ReplaceGroup(existing); err != nil {
		writeError(w, http.StatusInternalServerError, "", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, toGroupResource(existing, s.base(tenantID)))
}

func (s *Server) patchGroup(w http.ResponseWriter, r *http.Request, tenantID string) {
	existing, err := s.Store.GetGroup(tenantID, idFrom(r))
	if err == store.ErrNotFound {
		writeError(w, http.StatusNotFound, "", "group not found")
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
	if err := applyGroupPatch(existing, req.Operations); err != nil {
		writeError(w, http.StatusBadRequest, "invalidValue", err.Error())
		return
	}
	if err := s.Store.ReplaceGroup(existing); err != nil {
		writeError(w, http.StatusInternalServerError, "", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, toGroupResource(existing, s.base(tenantID)))
}

func (s *Server) deleteGroup(w http.ResponseWriter, r *http.Request, tenantID string) {
	err := s.Store.DeleteGroup(tenantID, idFrom(r))
	if err == store.ErrNotFound {
		writeError(w, http.StatusNotFound, "", "group not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "", err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
