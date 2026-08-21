package scim

import (
	"encoding/json"
	"net/http"
	"strconv"

	"b2bfp/internal/config"
	"b2bfp/internal/store"
)

const contentType = "application/scim+json"

// Server serves the SCIM 2.0 endpoints for every configured tenant, mounted
// under /scim/{tenantID}/v2/... so one gateway instance can front many
// customers' identity syncs (Okta, Entra ID, Ping, ...) simultaneously.
type Server struct {
	Store   *store.Store
	Tenants map[string]config.Tenant
	// PublicBaseURL builds the externally-visible base URL for a tenant's
	// SCIM endpoint, used in Location headers / meta.location.
	PublicBaseURL func(tenantID string) string
}

func (s *Server) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /scim/{tenant}/v2/Users", s.authenticate(s.listUsers))
	mux.HandleFunc("POST /scim/{tenant}/v2/Users", s.authenticate(s.createUser))
	mux.HandleFunc("GET /scim/{tenant}/v2/Users/{id}", s.authenticate(s.getUser))
	mux.HandleFunc("PUT /scim/{tenant}/v2/Users/{id}", s.authenticate(s.replaceUser))
	mux.HandleFunc("PATCH /scim/{tenant}/v2/Users/{id}", s.authenticate(s.patchUser))
	mux.HandleFunc("DELETE /scim/{tenant}/v2/Users/{id}", s.authenticate(s.deleteUser))

	mux.HandleFunc("GET /scim/{tenant}/v2/Groups", s.authenticate(s.listGroups))
	mux.HandleFunc("POST /scim/{tenant}/v2/Groups", s.authenticate(s.createGroup))
	mux.HandleFunc("GET /scim/{tenant}/v2/Groups/{id}", s.authenticate(s.getGroup))
	mux.HandleFunc("PUT /scim/{tenant}/v2/Groups/{id}", s.authenticate(s.replaceGroup))
	mux.HandleFunc("PATCH /scim/{tenant}/v2/Groups/{id}", s.authenticate(s.patchGroup))
	mux.HandleFunc("DELETE /scim/{tenant}/v2/Groups/{id}", s.authenticate(s.deleteGroup))

	mux.HandleFunc("GET /scim/{tenant}/v2/ServiceProviderConfig", s.authenticate(s.serviceProviderConfig))
}

type ctxKey string

const tenantKey ctxKey = "tenant"

// authenticate checks the tenant's static SCIM bearer token (the credential
// the IdP is configured with when you set up "provisioning" in Okta/Entra/
// Ping) and resolves the {tenant} path segment before calling next.
func (s *Server) authenticate(next func(w http.ResponseWriter, r *http.Request, tenantID string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID := r.PathValue("tenant")
		tenant, ok := s.Tenants[tenantID]
		if !ok {
			writeError(w, http.StatusNotFound, "", "unknown tenant")
			return
		}
		authz := r.Header.Get("Authorization")
		want := "Bearer " + tenant.SCIMBearerToken
		if tenant.SCIMBearerToken == "" || !secureEqual(authz, want) {
			writeError(w, http.StatusUnauthorized, "invalidCredentials", "invalid bearer token")
			return
		}
		// A single SCIM User/Group resource is at most a few KB; cap well
		// above that so a legitimate large group roster still fits, but
		// reject anything designed to exhaust memory. decodeBody's
		// json.Decoder otherwise reads the body fully into memory with no
		// limit of its own.
		r.Body = http.MaxBytesReader(w, r.Body, maxSCIMBodyBytes)
		next(w, r, tenantID)
	}
}

const maxSCIMBodyBytes = 5 << 20 // 5 MiB

func secureEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, scimType, detail string) {
	writeJSON(w, status, ErrorResponse{
		Schemas:  []string{SchemaError},
		Status:   strconv.Itoa(status),
		ScimType: scimType,
		Detail:   detail,
	})
}

func (s *Server) base(tenantID string) string {
	if s.PublicBaseURL != nil {
		return s.PublicBaseURL(tenantID)
	}
	return "/scim/" + tenantID
}

func (s *Server) serviceProviderConfig(w http.ResponseWriter, r *http.Request, tenantID string) {
	writeJSON(w, http.StatusOK, map[string]any{
		"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		"patch":   map[string]bool{"supported": true},
		"filter":  map[string]any{"supported": true, "maxResults": 500},
		"bulk":    map[string]bool{"supported": false},
		"sort":    map[string]bool{"supported": false},
		"authenticationSchemes": []map[string]string{
			{"type": "oauthbearertoken", "name": "Bearer Token", "description": "Static bearer token per tenant"},
		},
	})
}

func parsePaging(r *http.Request) (startIndex, count int) {
	startIndex = 1
	count = 100
	if v := r.URL.Query().Get("startIndex"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 {
			startIndex = n
		}
	}
	if v := r.URL.Query().Get("count"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			count = n
		}
	}
	if count > 500 {
		count = 500
	}
	return
}

func decodeBody(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	return dec.Decode(v)
}

func idFrom(r *http.Request) string { return r.PathValue("id") }
