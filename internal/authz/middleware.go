// Package authz bridges an authenticated session (from internal/saml or
// internal/oidc) to the ABAC evaluator, and enforces the resulting decision
// in front of the tenant's backend microservice.
package authz

import (
	"net"
	"net/http"
	"strings"
	"time"

	"b2bfp/internal/abac"
	"b2bfp/internal/store"
)

// ResourceMapper turns an inbound request path into the ABAC "resource"
// name policies are written against (e.g. "/api/production-db/query" ->
// "Production_DB"). Gateway config supplies this per tenant/route; an
// unmapped path is denied by default (fail closed) rather than silently
// let through unevaluated.
type ResourceMapper func(r *http.Request) (resource string, ok bool)

type Middleware struct {
	Store       *store.Store
	Policies    *abac.PolicySet
	Environment abac.Environment
	Resources   ResourceMapper
	// TrustForwardedFor must only be enabled when the gateway sits behind a
	// trusted L7 load balancer that itself sets/overwrites X-Forwarded-For
	// (never when clients can reach this process directly) — otherwise any
	// client can spoof its way into a VPC-range ABAC policy by forging the
	// header.
	TrustForwardedFor bool
	// AuditLog receives every decision (allow and deny) for compliance
	// trails; nil disables audit logging.
	AuditLog func(entry DecisionLog)
}

type DecisionLog struct {
	Time     time.Time
	TenantID string
	Subject  string
	Resource string
	Decision abac.Decision
	SourceIP string
	Path     string
}

// SessionFrom looks up the session referenced by the gateway's session
// cookie, returning (nil, false) if absent/expired.
func (m *Middleware) SessionFrom(r *http.Request) (*store.Session, bool) {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil, false
	}
	sess, err := m.Store.GetSession(c.Value)
	if err != nil {
		return nil, false
	}
	return sess, true
}

const sessionCookieName = "b2bfp_session"

// Enforce wraps next with authentication + ABAC enforcement: no session ->
// 401; session present but no policy grants Allow for the mapped resource
// -> 403; otherwise the request proceeds with tenant/subject context
// injected as headers for the backend.
func (m *Middleware) Enforce(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, ok := m.SessionFrom(r)
		if !ok {
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		resource, ok := m.Resources(r)
		if !ok {
			http.Error(w, "no resource mapping for this route (default deny)", http.StatusForbidden)
			return
		}

		sourceIP := clientIP(r, m.TrustForwardedFor)
		ctx := abac.NewContext(sess.Attributes, map[string]any{
			"Source_IP": sourceIP,
			"Method":    r.Method,
			"Path":      r.URL.Path,
		}, time.Now(), m.Environment)

		decision := abac.Evaluate(m.Policies, resource, ctx)
		if m.AuditLog != nil {
			m.AuditLog(DecisionLog{
				Time: time.Now(), TenantID: sess.TenantID, Subject: sess.Subject,
				Resource: resource, Decision: decision, SourceIP: sourceIP, Path: r.URL.Path,
			})
		}
		if decision.Effect != abac.Allow {
			http.Error(w, "access denied: "+decision.Reason, http.StatusForbidden)
			return
		}

		r.Header.Set("X-B2BFP-Tenant-Id", sess.TenantID)
		r.Header.Set("X-B2BFP-User-Id", sess.UserID)
		r.Header.Set("X-B2BFP-Subject", sess.Subject)
		r.Header.Set("X-B2BFP-Auth-Method", sess.AuthMethod)
		if dept, ok := sess.Attributes["Department"].(string); ok {
			r.Header.Set("X-B2BFP-Department", dept)
		}
		next.ServeHTTP(w, r)
	})
}

// clientIP extracts the caller's address for ABAC's request.Source_IP,
// preferring X-Forwarded-For's first hop only when trustForwardedFor is set
// by the deployment (see Middleware.TrustForwardedFor) — never from
// anything the request itself claims.
func clientIP(r *http.Request, trustForwardedFor bool) string {
	if trustForwardedFor {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			return strings.TrimSpace(parts[0])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
