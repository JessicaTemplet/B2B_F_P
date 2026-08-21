// Command gateway runs the B2B Federation & Provisioning Gateway: a SCIM
// 2.0 directory-sync server, a SAML 2.0 / OIDC Service Provider, and an
// ABAC-enforced reverse proxy in front of tenant backend microservices.
package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"b2bfp/internal/abac"
	"b2bfp/internal/authz"
	"b2bfp/internal/config"
	"b2bfp/internal/oidc"
	"b2bfp/internal/proxy"
	"b2bfp/internal/saml"
	"b2bfp/internal/scim"
	"b2bfp/internal/store"
)

func main() {
	configPath := flag.String("config", "config.json", "path to gateway config JSON")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	env := abac.Environment{}
	if cfg.EnvironmentFile != "" {
		e, err := config.LoadEnvironment(cfg.EnvironmentFile)
		if err != nil {
			log.Fatalf("environment: %v", err)
		}
		env = abac.Environment{
			CIDRRanges: e.CIDRRanges,
			BusinessHours: abac.BusinessHours{
				Timezone: e.BusinessHours.Timezone, Days: e.BusinessHours.Days,
				StartHour: e.BusinessHours.StartHour, EndHour: e.BusinessHours.EndHour,
			},
		}
	}

	policySetBytes, err := os.ReadFile(cfg.PolicyFile)
	if err != nil {
		log.Fatalf("policy file: %v", err)
	}
	policySet, err := abac.ParsePolicySet(policySetBytes)
	if err != nil {
		log.Fatalf("policy file: %v", err)
	}
	log.Printf("loaded %d ABAC policies", len(policySet.Policies))

	st, err := store.Open(cfg.DatabasePath)
	if err != nil {
		log.Fatalf("store: %v", err)
	}
	defer st.Close()

	base := strings.TrimSuffix(cfg.PublicBaseURL, "/")
	if base == "" {
		base = "http://localhost" + cfg.ListenAddr
	}
	publicBase := func(tenantID string) string { return base }

	mux := http.NewServeMux()

	scimSrv := &scim.Server{Store: st, Tenants: cfg.Tenants, PublicBaseURL: func(t string) string {
		return publicBase(t) + "/scim/" + t
	}}
	scimSrv.Register(mux)

	keyDir := cfg.SAMLKeyDir
	if keyDir == "" {
		keyDir = "data/saml-keys"
	}
	samlSrv := saml.NewServer(st, cfg.Tenants, keyDir)
	samlSrv.PublicBaseURL = publicBase
	samlSrv.AfterLogin = redirectAfterLogin
	samlSrv.Register(mux)

	oidcSrv := oidc.NewServer(st, cfg.Tenants)
	oidcSrv.PublicBaseURL = publicBase
	oidcSrv.AfterLogin = redirectAfterLogin
	oidcSrv.Register(mux)

	resourceRoutes := cfg.ResourceRoutes
	mapper := func(r *http.Request) (string, bool) {
		best, bestLen := "", -1
		for prefix, resource := range resourceRoutes {
			if strings.HasPrefix(r.URL.Path, prefix) && len(prefix) > bestLen {
				best, bestLen = resource, len(prefix)
			}
		}
		if bestLen < 0 {
			return "", false
		}
		return best, true
	}

	authzMw := &authz.Middleware{
		Store: st, Policies: policySet, Environment: env, Resources: mapper,
		TrustForwardedFor: cfg.TrustForwardedFor,
		AuditLog: func(entry authz.DecisionLog) {
			log.Printf("authz decision=%s policy=%q tenant=%s subject=%s resource=%s ip=%s path=%s reason=%q",
				entry.Decision.Effect, entry.Decision.Policy, entry.TenantID, entry.Subject,
				entry.Resource, entry.SourceIP, entry.Path, entry.Decision.Reason)
		},
	}
	router := proxy.NewTenantRouter(cfg.Tenants)
	mux.Handle("/api/", authzMw.Enforce(router.Handler()))

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	logTenants(cfg)
	log.Printf("listening on %s", cfg.ListenAddr)
	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           logRequests(mux),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}

func redirectAfterLogin(w http.ResponseWriter, r *http.Request, tenantID, relayState string) {
	target := relayState
	if target == "" {
		target = "/"
	}
	http.Redirect(w, r, target, http.StatusFound)
}

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start))
	})
}

func logTenants(cfg *config.Config) {
	ids := make([]string, 0, len(cfg.Tenants))
	for id := range cfg.Tenants {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	log.Printf("configured tenants: %s", strings.Join(ids, ", "))
}
