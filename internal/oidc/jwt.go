// Package oidc implements an OpenID Connect Relying Party: discovery,
// PKCE-protected authorization code flow, and manual RS256 ID token
// verification against the issuer's JWKS (no external OIDC/JWT library).
package oidc

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// Claims is the decoded ID token payload, kept as a raw map so callers can
// pull whatever custom claims the tenant's IdP includes (department, group
// memberships, etc.) alongside the standard ones.
type Claims map[string]any

func (c Claims) String(key string) string {
	if v, ok := c[key].(string); ok {
		return v
	}
	return ""
}

func (c Claims) Float64(key string) (float64, bool) {
	v, ok := c[key].(float64)
	return v, ok
}

// JWK is one entry of a JWKS document's "keys" array (RSA keys only — the
// only key type this gateway's RP needs to support, since every major
// enterprise IdP issues RS256 ID tokens).
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

func (j *JWKS) findKey(kid string) (*JWK, bool) {
	for i := range j.Keys {
		if j.Keys[i].Kid == kid {
			return &j.Keys[i], true
		}
	}
	return nil, false
}

func (k *JWK) publicKey() (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("jwk: invalid n: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("jwk: invalid e: %w", err)
	}
	e := 0
	for _, b := range eBytes {
		e = e<<8 | int(b)
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}, nil
}

// VerifyIDToken parses and validates a compact JWS (header.payload.signature)
// ID token: signature against the matching JWKS key (RS256 only), plus the
// standard OIDC validity claims (iss, aud, exp, and nonce when supplied).
func VerifyIDToken(idToken string, jwks *JWKS, issuer, audience, nonce string, now time.Time, clockSkew time.Duration) (Claims, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("oidc: malformed ID token (expected 3 JWS segments)")
	}
	headerB, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("oidc: invalid header encoding: %w", err)
	}
	payloadB, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("oidc: invalid payload encoding: %w", err)
	}
	sigB, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("oidc: invalid signature encoding: %w", err)
	}

	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerB, &header); err != nil {
		return nil, fmt.Errorf("oidc: invalid header JSON: %w", err)
	}
	// Refuse to let the token dictate a non-signing algorithm. This is the
	// classic "alg:none" / algorithm-confusion JWT bug class; only RS256
	// (asymmetric, verified against the issuer's published JWKS) is
	// accepted, so nothing the token holder controls can make verification
	// trivially pass.
	if header.Alg != "RS256" {
		return nil, fmt.Errorf("oidc: unsupported/untrusted alg %q (only RS256 is accepted)", header.Alg)
	}
	jwk, ok := jwks.findKey(header.Kid)
	if !ok {
		return nil, fmt.Errorf("oidc: no JWKS key matches token kid %q", header.Kid)
	}
	pub, err := jwk.publicKey()
	if err != nil {
		return nil, err
	}
	signingInput := parts[0] + "." + parts[1]
	digest := sha256.Sum256([]byte(signingInput))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sigB); err != nil {
		return nil, fmt.Errorf("oidc: ID token signature invalid: %w", err)
	}

	var claims Claims
	if err := json.Unmarshal(payloadB, &claims); err != nil {
		return nil, fmt.Errorf("oidc: invalid claims JSON: %w", err)
	}

	if iss := claims.String("iss"); iss != issuer {
		return nil, fmt.Errorf("oidc: iss %q does not match expected issuer %q", iss, issuer)
	}
	if !audienceContains(claims["aud"], audience) {
		return nil, fmt.Errorf("oidc: aud does not include this client_id (%q)", audience)
	}
	if exp, ok := claims.Float64("exp"); ok {
		if now.After(time.Unix(int64(exp), 0).Add(clockSkew)) {
			return nil, fmt.Errorf("oidc: ID token expired")
		}
	} else {
		return nil, fmt.Errorf("oidc: ID token missing exp claim")
	}
	if iat, ok := claims.Float64("iat"); ok {
		if now.Add(clockSkew).Before(time.Unix(int64(iat), 0)) {
			return nil, fmt.Errorf("oidc: ID token iat is in the future")
		}
	}
	if nonce != "" && claims.String("nonce") != nonce {
		return nil, fmt.Errorf("oidc: nonce mismatch (possible replay)")
	}
	return claims, nil
}

func audienceContains(aud any, want string) bool {
	switch v := aud.(type) {
	case string:
		return v == want
	case []any:
		for _, a := range v {
			if s, ok := a.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}
