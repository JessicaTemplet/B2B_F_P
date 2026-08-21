package authz

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"b2bfp/internal/abac"
	"b2bfp/internal/store"
)

func testMiddleware(t *testing.T) (*Middleware, *store.Store) {
	t.Helper()
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	ps, err := abac.ParsePolicySet([]byte(`{"policies":[
		{"id":"allow-all","effect":"Allow","resource":"*","condition":{"attr":"user.Department","op":"pr"}}
	]}`))
	if err != nil {
		t.Fatalf("parse policy set: %v", err)
	}

	m := &Middleware{
		Store:    s,
		Policies: ps,
		Resources: func(r *http.Request) (string, bool) {
			return "Reports", true
		},
	}
	return m, s
}

// TestEnforce_StripsClientSuppliedIdentityHeaders is the regression test
// for the header-spoofing fix: a client-supplied X-B2BFP-* header must
// never reach the backend unmodified, even for header names the middleware
// doesn't itself set today. Before the fix, Enforce only overwrote the
// specific keys it knew about (Tenant-Id/User-Id/Subject/Auth-Method/
// Department) and left everything else in that namespace untouched.
func TestEnforce_StripsClientSuppliedIdentityHeaders(t *testing.T) {
	m, s := testMiddleware(t)

	sess := &store.Session{
		TenantID: "acme", UserID: "u1", Subject: "alice@acme.example",
		Attributes: map[string]any{"Department": "Engineering"}, AuthMethod: "saml",
	}
	if err := s.CreateSession(sess, time.Hour); err != nil {
		t.Fatalf("create session: %v", err)
	}

	var gotGroups, gotBogus, gotTenant string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotGroups = r.Header.Get("X-B2BFP-Groups")
		gotBogus = r.Header.Get("X-B2BFP-Totally-Made-Up")
		gotTenant = r.Header.Get("X-B2BFP-Tenant-Id")
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/reports/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: "b2bfp_session", Value: sess.ID})
	// Attacker-controlled request tries to smuggle identity claims the
	// middleware never explicitly sets.
	req.Header.Set("X-B2BFP-Groups", "superadmins")
	req.Header.Set("X-B2BFP-Totally-Made-Up", "trust-me")

	rec := httptest.NewRecorder()
	m.Enforce(next).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if gotGroups == "superadmins" {
		t.Error("client-supplied X-B2BFP-Groups header was forwarded to the backend unmodified")
	}
	if gotBogus == "trust-me" {
		t.Error("client-supplied X-B2BFP-Totally-Made-Up header was forwarded to the backend unmodified")
	}
	if gotTenant != "acme" {
		t.Errorf("expected gateway-set X-B2BFP-Tenant-Id=acme, got %q", gotTenant)
	}
}

func TestEnforce_RejectsUnauthenticated(t *testing.T) {
	m, _ := testMiddleware(t)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be reached without a session")
	})
	req := httptest.NewRequest(http.MethodGet, "/api/reports/dashboard", nil)
	rec := httptest.NewRecorder()
	m.Enforce(next).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestEnforce_DeniesWhenNoPolicyMatches(t *testing.T) {
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	ps, _ := abac.ParsePolicySet([]byte(`{"policies":[]}`))
	m := &Middleware{Store: s, Policies: ps, Resources: func(r *http.Request) (string, bool) { return "Reports", true }}

	sess := &store.Session{TenantID: "acme", UserID: "u1", Subject: "alice@acme.example", Attributes: map[string]any{}, AuthMethod: "saml"}
	if err := s.CreateSession(sess, time.Hour); err != nil {
		t.Fatalf("create session: %v", err)
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be reached when no policy allows access")
	})
	req := httptest.NewRequest(http.MethodGet, "/api/reports/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: "b2bfp_session", Value: sess.ID})
	rec := httptest.NewRecorder()
	m.Enforce(next).ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}
