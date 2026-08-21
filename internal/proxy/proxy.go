// Package proxy is the multi-tenant reverse proxy that fronts each
// tenant's backend microservice, forwarding only requests that have
// already cleared internal/authz's ABAC gate.
package proxy

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"

	"b2bfp/internal/config"
)

type TenantRouter struct {
	Tenants map[string]config.Tenant

	mu      sync.Mutex
	proxies map[string]*httputil.ReverseProxy
}

func NewTenantRouter(tenants map[string]config.Tenant) *TenantRouter {
	return &TenantRouter{Tenants: tenants, proxies: map[string]*httputil.ReverseProxy{}}
}

// Handler returns an http.Handler that proxies to the backend for the
// tenant identified by the X-B2BFP-Tenant-Id header — set upstream by
// internal/authz.Middleware.Enforce only after a request has been
// authenticated and ABAC-authorized, so nothing reaches here otherwise.
func (t *TenantRouter) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenantID := r.Header.Get("X-B2BFP-Tenant-Id")
		tenant, ok := t.Tenants[tenantID]
		if !ok || tenant.BackendURL == "" {
			http.Error(w, "no backend configured for tenant", http.StatusBadGateway)
			return
		}
		rp, err := t.proxyFor(tenantID, tenant.BackendURL)
		if err != nil {
			http.Error(w, "invalid backend configuration", http.StatusInternalServerError)
			return
		}
		rp.ServeHTTP(w, r)
	})
}

func (t *TenantRouter) proxyFor(tenantID, backendURL string) (*httputil.ReverseProxy, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if rp, ok := t.proxies[tenantID]; ok {
		return rp, nil
	}
	target, err := url.Parse(backendURL)
	if err != nil {
		return nil, err
	}
	rp := httputil.NewSingleHostReverseProxy(target)
	origDirector := rp.Director
	rp.Director = func(r *http.Request) {
		origDirector(r)
		// The backend is multi-tenant too; it trusts these headers because
		// only this gateway process can reach it directly (network policy
		// enforced outside this package).
		r.Header.Set("X-Forwarded-Host", r.Host)
	}
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("proxy: tenant=%s backend error: %v", tenantID, err)
		http.Error(w, "backend unavailable", http.StatusBadGateway)
	}
	t.proxies[tenantID] = rp
	return rp, nil
}
