// Command mockoidc is a throwaway OpenID Provider for exercising the
// gateway's OIDC Relying Party locally (discovery, PKCE-protected
// authorization code flow, RS256 ID token issuance) without needing a real
// Okta/Entra/Auth0 tenant. It skips any actual login UI — /authorize
// immediately "authenticates" as a fixed test user and redirects back with
// a code — so it is only ever appropriate for local development/demos.
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"
)

type pendingCode struct {
	nonce, redirectURI, clientID, subject, email, department string
	issuedAt                                                 time.Time
}

func main() {
	addr := flag.String("addr", ":9091", "listen address")
	issuer := flag.String("issuer", "http://localhost:9091", "issuer URL to advertise (must match what the gateway tenant config expects)")
	subject := flag.String("subject", "bob@acme-corp.example", "sub / userName of the simulated logged-in user")
	department := flag.String("department", "Engineering", "department claim of the simulated logged-in user")
	flag.Parse()

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
			"issuer":                 *issuer,
			"authorization_endpoint": *issuer + "/authorize",
			"token_endpoint":         *issuer + "/token",
			"jwks_uri":               *issuer + "/jwks.json",
			"userinfo_endpoint":      *issuer + "/userinfo",
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
			subject: *subject, email: *subject, department: *department, issuedAt: time.Now(),
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
		log.Printf("mockoidc: simulated login as %s, redirecting to %s", *subject, redirect.String())
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
			"iss": *issuer, "aud": pc.clientID, "sub": pc.subject,
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

	log.Printf("mockoidc listening on %s (issuer=%s, simulated user=%s dept=%s)", *addr, *issuer, *subject, *department)
	log.Fatal(http.ListenAndServe(*addr, mux))
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
