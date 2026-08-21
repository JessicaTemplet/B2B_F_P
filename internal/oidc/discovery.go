package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ProviderMetadata is the subset of an issuer's
// /.well-known/openid-configuration document the RP needs.
type ProviderMetadata struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
}

// DiscoveryCache fetches and caches provider metadata + JWKS per issuer, so
// repeated logins don't re-fetch on every request but a restart always
// picks up rotated signing keys.
type DiscoveryCache struct {
	httpClient *http.Client
	ttl        time.Duration

	mu   sync.Mutex
	meta map[string]cachedMeta
	jwks map[string]cachedJWKS
}

type cachedMeta struct {
	meta      ProviderMetadata
	fetchedAt time.Time
}

type cachedJWKS struct {
	jwks      JWKS
	fetchedAt time.Time
}

func NewDiscoveryCache(ttl time.Duration) *DiscoveryCache {
	return &DiscoveryCache{
		httpClient: &http.Client{Timeout: 10 * time.Second},
		ttl:        ttl,
		meta:       map[string]cachedMeta{},
		jwks:       map[string]cachedJWKS{},
	}
}

func (c *DiscoveryCache) Metadata(ctx context.Context, issuer string) (*ProviderMetadata, error) {
	c.mu.Lock()
	if m, ok := c.meta[issuer]; ok && time.Since(m.fetchedAt) < c.ttl {
		c.mu.Unlock()
		out := m.meta
		return &out, nil
	}
	c.mu.Unlock()

	url := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc discovery: unexpected status %d", resp.StatusCode)
	}
	var m ProviderMetadata
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		return nil, fmt.Errorf("oidc discovery: invalid JSON: %w", err)
	}
	if m.Issuer != issuer {
		return nil, fmt.Errorf("oidc discovery: document issuer %q does not match configured issuer %q", m.Issuer, issuer)
	}
	c.mu.Lock()
	c.meta[issuer] = cachedMeta{m, time.Now()}
	c.mu.Unlock()
	return &m, nil
}

func (c *DiscoveryCache) JWKS(ctx context.Context, issuer, jwksURI string) (*JWKS, error) {
	c.mu.Lock()
	if j, ok := c.jwks[issuer]; ok && time.Since(j.fetchedAt) < c.ttl {
		c.mu.Unlock()
		out := j.jwks
		return &out, nil
	}
	c.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc jwks fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc jwks: unexpected status %d", resp.StatusCode)
	}
	var j JWKS
	if err := json.NewDecoder(resp.Body).Decode(&j); err != nil {
		return nil, fmt.Errorf("oidc jwks: invalid JSON: %w", err)
	}
	c.mu.Lock()
	c.jwks[issuer] = cachedJWKS{j, time.Now()}
	c.mu.Unlock()
	return &j, nil
}
