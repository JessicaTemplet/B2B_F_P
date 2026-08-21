// Package config loads the gateway's static configuration: tenant registry,
// backend services to proxy to, and the ABAC environment (named CIDR ranges,
// business-hours schedule) referenced by policy files.
package config

import (
	"encoding/json"
	"fmt"
	"os"
)

// Tenant describes one corporate customer: its SCIM/SAML/OIDC identity
// wiring and which backend service its API traffic proxies to.
type Tenant struct {
	ID                  string `json:"id"`
	Name                string `json:"name"`
	SCIMBearerToken     string `json:"scim_bearer_token"` // static bearer token the IdP presents on SCIM calls
	SAMLIdPMetadataFile string `json:"saml_idp_metadata_file,omitempty"`
	OIDCIssuer          string `json:"oidc_issuer,omitempty"`
	OIDCClientID        string `json:"oidc_client_id,omitempty"`
	OIDCClientSecret    string `json:"oidc_client_secret,omitempty"`
	BackendURL          string `json:"backend_url"`
}

// Environment holds named values that ABAC policies refer to symbolically
// (e.g. "Vpc_Range", "Business_Hours") instead of hard-coding.
type Environment struct {
	CIDRRanges    map[string]string `json:"cidr_ranges"`
	BusinessHours BusinessHours     `json:"business_hours"`
}

type BusinessHours struct {
	Timezone  string `json:"timezone"`   // IANA tz name, e.g. "America/New_York"
	Days      []int  `json:"days"`       // 0=Sunday..6=Saturday
	StartHour int    `json:"start_hour"` // local hour, inclusive, 0-23
	EndHour   int    `json:"end_hour"`   // local hour, exclusive, 0-23
}

type Config struct {
	ListenAddr   string `json:"listen_addr"`
	DatabasePath string `json:"database_path"`
	// PublicBaseURL is this gateway's externally-reachable origin (e.g.
	// "https://gateway.acme.example"), used to build per-tenant SAML
	// entityIDs/ACS URLs, OIDC redirect URIs, and SCIM meta.location values.
	PublicBaseURL     string `json:"public_base_url"`
	PolicyFile        string `json:"policy_file"`
	EnvironmentFile   string `json:"environment_file"`
	SAMLKeyDir        string `json:"saml_key_dir"`
	TrustForwardedFor bool   `json:"trust_forwarded_for"`
	// ResourceRoutes maps an API path prefix to the ABAC resource name
	// policies are written against, e.g. "/api/production-db/" ->
	// "Production_DB". The longest matching prefix wins; an unmatched path
	// is denied by default.
	ResourceRoutes map[string]string `json:"resource_routes"`
	Tenants        map[string]Tenant `json:"tenants"`
}

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if c.ListenAddr == "" {
		c.ListenAddr = ":8443"
	}
	if c.DatabasePath == "" {
		c.DatabasePath = "data/gateway.db"
	}
	return &c, nil
}

func LoadEnvironment(path string) (*Environment, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read environment: %w", err)
	}
	var e Environment
	if err := json.Unmarshal(b, &e); err != nil {
		return nil, fmt.Errorf("parse environment: %w", err)
	}
	return &e, nil
}
