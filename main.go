// Command app is the single-process Render demo entrypoint for B2B_F_P: it
// starts the gateway plus the two dev-only mocks (mockoidc, mockbackend) and
// bootstraps the dev fake IdP, all in one binary/one container, so the free
// tier only has to run and expose one service. Nothing here changes the
// behavior of cmd/gateway, cmd/mockoidc, cmd/mockbackend, or cmd/fakeidp —
// each block below is a straight port of that command's main(), just callable
// as a function instead of being its own package main.
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
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
	ensureFakeIDP("https://fake-idp.example.com/entity", "http://localhost:8443/__fakeidp_unused__",
		"policies/fakeidp-metadata.xml", "data/fakeidp.key.pem")

	go runMockBackend(":9090")
	go runMockOIDC(":9091", "http://localhost:9091", "bob@acme-corp.example", "Engineering")

	runGateway("config.json")
}

// ---- gateway (from cmd/gateway/main.go) ----

func runGateway(configPath string) {
	cfg, err := config.Load(configPath)
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

// ---- mockbackend (from cmd/mockbackend/main.go) ----

func runMockBackend(addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		ctx := map[string]string{"path": r.URL.Path, "method": r.Method}
		for k, v := range r.Header {
			if strings.HasPrefix(k, "X-B2bfp-") || strings.HasPrefix(k, "X-B2BFP-") {
				ctx[k] = strings.Join(v, ",")
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ctx)
	})
	log.Printf("mockbackend listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

// ---- mockoidc (from cmd/mockoidc/main.go) ----

type pendingCode struct {
	nonce, redirectURI, clientID, subject, email, department string
	issuedAt                                                 time.Time
}

func runMockOIDC(addr, issuer, subject, department string) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	kid := "mockoidc-key-1"

	var mu sync.Mutex
	codes := map[string]pendingCode{}

	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 issuer,
			"authorization_endpoint": issuer + "/authorize",
			"token_endpoint":         issuer + "/token",
			"jwks_uri":               issuer + "/jwks.json",
			"userinfo_endpoint":      issuer + "/userinfo",
		})
	})

	mux.HandleFunc("/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		pub := &priv.PublicKey
		eBytes := encodeBigEndianUint(pub.E)
		json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{{
				"kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig",
				"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(eBytes),
			}},
		})
	})

	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		code := randString()
		mu.Lock()
		codes[code] = pendingCode{
			nonce: q.Get("nonce"), redirectURI: q.Get("redirect_uri"), clientID: q.Get("client_id"),
			subject: subject, email: subject, department: department, issuedAt: time.Now(),
		}
		mu.Unlock()
		redirect, err := url.Parse(q.Get("redirect_uri"))
		if err != nil {
			http.Error(w, "bad redirect_uri", http.StatusBadRequest)
			return
		}
		rq := redirect.Query()
		rq.Set("code", code)
		rq.Set("state", q.Get("state"))
		redirect.RawQuery = rq.Encode()
		log.Printf("mockoidc: simulated login as %s, redirecting to %s", subject, redirect.String())
		http.Redirect(w, r, redirect.String(), http.StatusFound)
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		code := r.FormValue("code")
		mu.Lock()
		pc, ok := codes[code]
		if ok {
			delete(codes, code)
		}
		mu.Unlock()
		if !ok {
			http.Error(w, "invalid or already-used code", http.StatusBadRequest)
			return
		}
		now := time.Now()
		claims := map[string]any{
			"iss": issuer, "aud": pc.clientID, "sub": pc.subject,
			"email": pc.email, "department": pc.department,
			"iat": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(),
			"nonce": pc.nonce,
		}
		idToken, err := signJWT(priv, kid, claims)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": randString(), "token_type": "Bearer", "expires_in": 600, "id_token": idToken,
		})
	})

	log.Printf("mockoidc listening on %s (issuer=%s, simulated user=%s dept=%s)", addr, issuer, subject, department)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func signJWT(priv *rsa.PrivateKey, kid string, claims map[string]any) (string, error) {
	header := map[string]string{"alg": "RS256", "typ": "JWT", "kid": kid}
	hb, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	cb, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(cb)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func encodeBigEndianUint(n int) []byte {
	if n == 0 {
		return []byte{0}
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte(n & 0xff)}, b...)
		n >>= 8
	}
	return b
}

func randString() string {
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return fmt.Sprintf("%x", b)
}

// ---- fakeidp init (from cmd/fakeidp/main.go's runInit) ----

func ensureFakeIDP(entityID, ssoURL, out, keyOut string) {
	if _, err := os.Stat(out); err == nil {
		log.Printf("fakeidp: %s already present, skipping init", out)
		return
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	must(err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "fake-idp.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(5, 0, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	must(err)

	must(os.MkdirAll(dirOf(keyOut), 0700))
	must(os.WriteFile(keyOut, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}), 0600))

	certB64 := base64.StdEncoding.EncodeToString(der)
	metadata := fmt.Sprintf(`<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="%s">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo><ds:X509Data><ds:X509Certificate>%s</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="%s"></md:SingleSignOnService>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>
`, entityID, certB64, ssoURL)

	must(os.MkdirAll(dirOf(out), 0755))
	must(os.WriteFile(out, []byte(metadata), 0644))
	log.Printf("fakeidp: wrote IdP metadata to %s and signing key to %s", out, keyOut)
}

func dirOf(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' || p[i] == '\\' {
			return p[:i]
		}
	}
	return "."
}

func must(err error) {
	if err != nil {
		log.Fatalf("fakeidp: %v", err)
	}
}
