package oidc

import (
	"log"
	"net/http"
	"time"

	"b2bfp/internal/config"
	"b2bfp/internal/store"
)

const SessionCookieName = "b2bfp_session"

var defaultScopes = []string{"openid", "profile", "email"}

// Server wires the OIDC RP primitives into HTTP handlers, mirroring
// internal/saml.Server's shape so the gateway treats SAML and OIDC tenants
// uniformly (both end in a store.Session with mapped directory attributes).
type Server struct {
	Store         *store.Store
	Tenants       map[string]config.Tenant
	Discovery     *DiscoveryCache
	HTTPClient    *http.Client
	PublicBaseURL func(tenantID string) string
	AfterLogin    func(w http.ResponseWriter, r *http.Request, tenantID, relayState string)
}

func NewServer(st *store.Store, tenants map[string]config.Tenant) *Server {
	return &Server{
		Store: st, Tenants: tenants,
		Discovery:  NewDiscoveryCache(10 * time.Minute),
		HTTPClient: &http.Client{Timeout: 10 * time.Second},
	}
}

func (s *Server) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /oidc/{tenant}/login", s.login)
	mux.HandleFunc("GET /oidc/{tenant}/callback", s.callback)
}

func (s *Server) base(tenantID string) string {
	if s.PublicBaseURL != nil {
		return s.PublicBaseURL(tenantID)
	}
	return "http://localhost:8443"
}

func (s *Server) redirectURI(tenantID string) string {
	return s.base(tenantID) + "/oidc/" + tenantID + "/callback"
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	tenantID := r.PathValue("tenant")
	tenant, ok := s.Tenants[tenantID]
	if !ok || tenant.OIDCIssuer == "" {
		http.NotFound(w, r)
		return
	}
	meta, err := s.Discovery.Metadata(r.Context(), tenant.OIDCIssuer)
	if err != nil {
		http.Error(w, "oidc discovery failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	state, err := GenerateState()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	nonce, err := GenerateState()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	verifier, err := GeneratePKCEVerifier()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	relayState := r.URL.Query().Get("returnTo")
	if err := s.Store.PutOIDCRequest(store.OIDCRequest{
		State: state, TenantID: tenantID, Nonce: nonce, PKCEVerifier: verifier, RelayState: relayState,
	}, 10*time.Minute); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	authURL := BuildAuthorizeURL(meta, tenant.OIDCClientID, s.redirectURI(tenantID), state, nonce, PKCEChallengeS256(verifier), defaultScopes)
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (s *Server) callback(w http.ResponseWriter, r *http.Request) {
	tenantID := r.PathValue("tenant")
	tenant, ok := s.Tenants[tenantID]
	if !ok || tenant.OIDCIssuer == "" {
		http.NotFound(w, r)
		return
	}
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		http.Error(w, "oidc error: "+errParam+" "+r.URL.Query().Get("error_description"), http.StatusBadRequest)
		return
	}
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	if code == "" || state == "" {
		http.Error(w, "missing code/state", http.StatusBadRequest)
		return
	}
	pending, ok, err := s.Store.TakeOIDCRequest(state)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok || pending.TenantID != tenantID {
		http.Error(w, "unknown, expired, or already-used state (possible CSRF)", http.StatusForbidden)
		return
	}

	meta, err := s.Discovery.Metadata(r.Context(), tenant.OIDCIssuer)
	if err != nil {
		http.Error(w, "oidc discovery failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	tr, err := ExchangeCode(r.Context(), s.HTTPClient, meta, tenant.OIDCClientID, tenant.OIDCClientSecret, s.redirectURI(tenantID), code, pending.PKCEVerifier)
	if err != nil {
		log.Printf("oidc callback: tenant=%s token exchange failed: %v", tenantID, err)
		http.Error(w, "token exchange failed", http.StatusBadGateway)
		return
	}
	jwks, err := s.Discovery.JWKS(r.Context(), tenant.OIDCIssuer, meta.JWKSURI)
	if err != nil {
		http.Error(w, "jwks fetch failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	claims, err := VerifyIDToken(tr.IDToken, jwks, tenant.OIDCIssuer, tenant.OIDCClientID, pending.Nonce, time.Now(), defaultClockSkew)
	if err != nil {
		log.Printf("oidc callback: tenant=%s id token verification failed: %v", tenantID, err)
		http.Error(w, "ID token verification failed", http.StatusForbidden)
		return
	}

	subject := claims.String("sub")
	if subject == "" {
		http.Error(w, "ID token missing sub claim", http.StatusForbidden)
		return
	}
	attrs := mapClaims(claims)
	user, err := jitProvisionUser(s.Store, tenantID, claims, attrs)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	groups, _ := s.Store.GroupsForUser(tenantID, user.ID)
	attrs["Groups"] = groups

	sess := &store.Session{
		TenantID: tenantID, UserID: user.ID, Subject: subject,
		Attributes: attrs, AuthMethod: "oidc",
	}
	if err := s.Store.CreateSession(sess, 8*time.Hour); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: SessionCookieName, Value: sess.ID, Path: "/", HttpOnly: true,
		Secure: true, SameSite: http.SameSiteLaxMode, Expires: sess.ExpiresAt,
	})

	if s.AfterLogin != nil {
		s.AfterLogin(w, r, tenantID, pending.RelayState)
		return
	}
	w.Write([]byte("login successful"))
}

func mapClaims(claims Claims) map[string]any {
	out := map[string]any{}
	for _, k := range []string{"email", "given_name", "family_name", "name", "department"} {
		if v := claims.String(k); v != "" {
			out[capitalize(k)] = v
		}
	}
	// Some IdPs (Entra ID with an optional claim, Ping with an attribute
	// mapping) emit department under a custom claim name.
	for _, k := range []string{"department", "https://schemas.example.com/department"} {
		if v := claims.String(k); v != "" {
			out["Department"] = v
		}
	}
	return out
}

func capitalize(s string) string {
	switch s {
	case "email":
		return "Email"
	case "given_name":
		return "GivenName"
	case "family_name":
		return "FamilyName"
	case "name":
		return "Name"
	case "department":
		return "Department"
	}
	return s
}

func jitProvisionUser(st *store.Store, tenantID string, claims Claims, attrs map[string]any) (*store.User, error) {
	userName := claims.String("email")
	if userName == "" {
		userName = claims.String("sub")
	}
	u, err := st.FindUserByUserName(tenantID, userName)
	if err == nil {
		return u, nil
	}
	if err != store.ErrNotFound {
		return nil, err
	}
	dept, _ := attrs["Department"].(string)
	u = &store.User{
		TenantID: tenantID, UserName: userName, Email: claims.String("email"),
		GivenName: claims.String("given_name"), FamilyName: claims.String("family_name"),
		Department: dept, Active: true, Attributes: map[string]any{},
	}
	if err := st.CreateUser(u); err != nil {
		return nil, err
	}
	return u, nil
}
