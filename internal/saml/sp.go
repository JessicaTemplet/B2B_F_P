package saml

import (
	"encoding/base64"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"b2bfp/internal/config"
	"b2bfp/internal/store"
)

const SessionCookieName = "b2bfp_session"

// Server wires the raw SAML SP primitives (metadata parsing, AuthnRequest
// generation, response verification) into HTTP handlers for one gateway
// instance serving many tenants.
type Server struct {
	Store         *store.Store
	Tenants       map[string]config.Tenant
	KeyDir        string // where per-tenant SP key/cert PEMs live
	PublicBaseURL func(tenantID string) string
	// AfterLogin lets the caller (main.go) redirect the browser to the
	// tenant's application after a session cookie is set.
	AfterLogin func(w http.ResponseWriter, r *http.Request, tenantID, relayState string)

	mu       sync.Mutex
	sps      map[string]*SP
	idpCache map[string]*IdPMetadata
}

func NewServer(st *store.Store, tenants map[string]config.Tenant, keyDir string) *Server {
	return &Server{
		Store: st, Tenants: tenants, KeyDir: keyDir,
		sps: map[string]*SP{}, idpCache: map[string]*IdPMetadata{},
	}
}

func (s *Server) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /saml/{tenant}/metadata", s.metadata)
	mux.HandleFunc("GET /saml/{tenant}/login", s.login)
	mux.HandleFunc("POST /saml/{tenant}/acs", s.acs)
}

func (s *Server) base(tenantID string) string {
	if s.PublicBaseURL != nil {
		return s.PublicBaseURL(tenantID)
	}
	return "http://localhost:8443"
}

func (s *Server) spFor(tenantID string) (*SP, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sp, ok := s.sps[tenantID]; ok {
		return sp, nil
	}
	if err := os.MkdirAll(s.KeyDir, 0700); err != nil {
		return nil, err
	}
	entityID := s.base(tenantID) + "/saml/" + tenantID + "/metadata"
	priv, cert, der, err := LoadOrCreateSPKeyPair(
		s.KeyDir+"/"+tenantID+".key.pem",
		s.KeyDir+"/"+tenantID+".cert.pem",
		entityID)
	if err != nil {
		return nil, err
	}
	sp := &SP{
		EntityID:   entityID,
		ACSURL:     s.base(tenantID) + "/saml/" + tenantID + "/acs",
		PrivateKey: priv,
		Cert:       cert,
		CertDER:    der,
	}
	s.sps[tenantID] = sp
	return sp, nil
}

func (s *Server) idpFor(tenantID string, tenant config.Tenant) (*IdPMetadata, error) {
	s.mu.Lock()
	if m, ok := s.idpCache[tenantID]; ok {
		s.mu.Unlock()
		return m, nil
	}
	s.mu.Unlock()

	data, err := os.ReadFile(tenant.SAMLIdPMetadataFile)
	if err != nil {
		return nil, err
	}
	m, err := ParseIdPMetadata(data)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.idpCache[tenantID] = m
	s.mu.Unlock()
	return m, nil
}

func (s *Server) metadata(w http.ResponseWriter, r *http.Request) {
	tenantID := r.PathValue("tenant")
	if _, ok := s.Tenants[tenantID]; !ok {
		http.NotFound(w, r)
		return
	}
	sp, err := s.spFor(tenantID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.Write(sp.SPMetadataXML())
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	tenantID := r.PathValue("tenant")
	tenant, ok := s.Tenants[tenantID]
	if !ok || tenant.SAMLIdPMetadataFile == "" {
		http.NotFound(w, r)
		return
	}
	sp, err := s.spFor(tenantID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	idp, err := s.idpFor(tenantID, tenant)
	if err != nil {
		http.Error(w, "idp metadata unavailable: "+err.Error(), http.StatusBadGateway)
		return
	}
	relayState := r.URL.Query().Get("returnTo")
	redirectURL, requestID, err := sp.BuildRedirectURL(idp, relayState)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.Store.PutSAMLRequest(requestID, tenantID, relayState, 10*time.Minute); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (s *Server) acs(w http.ResponseWriter, r *http.Request) {
	tenantID := r.PathValue("tenant")
	tenant, ok := s.Tenants[tenantID]
	if !ok || tenant.SAMLIdPMetadataFile == "" {
		http.NotFound(w, r)
		return
	}
	sp, err := s.spFor(tenantID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	idp, err := s.idpFor(tenantID, tenant)
	if err != nil {
		http.Error(w, "idp metadata unavailable: "+err.Error(), http.StatusBadGateway)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	samlResponseB64 := r.FormValue("SAMLResponse")
	if samlResponseB64 == "" {
		http.Error(w, "missing SAMLResponse", http.StatusBadRequest)
		return
	}
	// POST binding carries the SAMLResponse as plain base64 (unlike the
	// redirect binding, it is not additionally DEFLATE-compressed).
	rawXML, err := decodeBase64Lenient(samlResponseB64)
	if err != nil {
		http.Error(w, "invalid SAMLResponse encoding", http.StatusBadRequest)
		return
	}

	var lastErr error
	var assertion *Assertion
	for _, cert := range idp.SigningCertificates {
		a, err := ParseAndVerifyResponse(rawXML, cert, sp.EntityID, sp.ACSURL, "", time.Now(), 2*time.Minute)
		if err == nil {
			assertion = a
			break
		}
		lastErr = err
	}
	if assertion == nil {
		log.Printf("saml acs: tenant=%s verification failed: %v", tenantID, lastErr)
		http.Error(w, "SAML response verification failed", http.StatusForbidden)
		return
	}

	// Single-use enforcement for every accepted assertion, SP-initiated or
	// IdP-initiated. SP-initiated responses are additionally covered by
	// TakeSAMLRequest's InResponseTo consumption below; IdP-initiated ones
	// (no InResponseTo at all) have no other replay defense, so this check
	// must not be skipped just because InResponseTo is empty.
	if assertion.AssertionID == "" {
		http.Error(w, "SAML assertion missing ID", http.StatusForbidden)
		return
	}
	expiresAt := assertion.NotOnOrAfter
	if expiresAt.IsZero() {
		expiresAt = time.Now().Add(24 * time.Hour)
	}
	usedBefore, err := s.Store.MarkAssertionUsed(tenantID, assertion.AssertionID, expiresAt)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if usedBefore {
		log.Printf("saml acs: tenant=%s rejected replayed assertion id=%s", tenantID, assertion.AssertionID)
		http.Error(w, "this SAML assertion has already been used", http.StatusForbidden)
		return
	}

	relayState, replayOK, err := s.Store.TakeSAMLRequest(assertion.InResponseTo, tenantID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if assertion.InResponseTo != "" && !replayOK {
		http.Error(w, "AuthnRequest not found, expired, or already used", http.StatusForbidden)
		return
	}

	attrs := mapAssertionAttributes(assertion)
	user, err := jitProvisionUser(s.Store, tenantID, assertion, attrs)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	groups, _ := s.Store.GroupsForUser(tenantID, user.ID)
	attrs["Groups"] = groups

	sess := &store.Session{
		TenantID: tenantID, UserID: user.ID, Subject: assertion.NameID,
		Attributes: attrs, AuthMethod: "saml",
	}
	if err := s.Store.CreateSession(sess, 8*time.Hour); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Secure tracks the configured public_base_url's scheme rather than
	// being hardcoded true: a hardcoded Secure cookie set while
	// public_base_url is http:// (e.g. local dev) is accepted by the
	// browser but then never sent back on the following http:// request,
	// silently breaking every session with no visible error.
	http.SetCookie(w, &http.Cookie{
		Name: SessionCookieName, Value: sess.ID, Path: "/", HttpOnly: true,
		Secure: strings.HasPrefix(s.base(tenantID), "https://"), SameSite: http.SameSiteLaxMode, Expires: sess.ExpiresAt,
	})

	if s.AfterLogin != nil {
		s.AfterLogin(w, r, tenantID, relayState)
		return
	}
	w.Write([]byte("login successful"))
}

func mapAssertionAttributes(a *Assertion) map[string]any {
	out := map[string]any{}
	for k, v := range a.Attributes {
		if len(v) == 1 {
			out[k] = v[0]
		} else {
			out[k] = v
		}
	}
	if _, ok := out["Department"]; !ok {
		// Some IdPs send this under the full SAML2 URI-style claim name.
		if v, ok2 := a.Attributes["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/department"]; ok2 && len(v) > 0 {
			out["Department"] = v[0]
		}
	}
	return out
}

// jitProvisionUser finds the SCIM-provisioned user matching this assertion's
// NameID, or just-in-time creates one from the assertion's own attributes if
// SCIM hasn't synced them yet (common for a first login that races an
// eventually-consistent directory sync).
func jitProvisionUser(st *store.Store, tenantID string, a *Assertion, attrs map[string]any) (*store.User, error) {
	u, err := st.FindUserByUserName(tenantID, a.NameID)
	if err == nil {
		return u, nil
	}
	if err != store.ErrNotFound {
		return nil, err
	}
	dept, _ := attrs["Department"].(string)
	u = &store.User{
		TenantID: tenantID, UserName: a.NameID, Email: a.NameID,
		Department: dept, Active: true, Attributes: map[string]any{},
	}
	if err := st.CreateUser(u); err != nil {
		return nil, err
	}
	return u, nil
}

// decodeBase64Lenient strips the whitespace/newlines browsers commonly wrap
// into a POSTed base64 form value before decoding.
func decodeBase64Lenient(s string) ([]byte, error) {
	clean := strings.Join(strings.Fields(s), "")
	return base64.StdEncoding.DecodeString(clean)
}
