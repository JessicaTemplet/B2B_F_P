package oidc

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

func makeToken(t *testing.T, priv *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header := map[string]string{"alg": "RS256", "typ": "JWT", "kid": kid}
	hb, _ := json.Marshal(header)
	cb, _ := json.Marshal(claims)
	signingInput := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(cb)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func testJWKS(t *testing.T, pub *rsa.PublicKey, kid string) *JWKS {
	t.Helper()
	return &JWKS{Keys: []JWK{{
		Kty: "RSA", Kid: kid, Alg: "RS256", Use: "sig",
		N: base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E: base64.RawURLEncoding.EncodeToString(encodeBigEndianUint(pub.E)),
	}}}
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

func TestVerifyIDToken_ValidTokenAccepted(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Now()
	claims := map[string]any{
		"iss": "https://idp.example.com/", "aud": "client-123", "sub": "user-1",
		"exp": float64(now.Add(time.Hour).Unix()), "iat": float64(now.Unix()),
		"nonce": "nonce-abc", "email": "alice@acme.example",
	}
	tok := makeToken(t, priv, "key1", claims)
	jwks := testJWKS(t, &priv.PublicKey, "key1")

	got, err := VerifyIDToken(tok, jwks, "https://idp.example.com/", "client-123", "nonce-abc", now, 2*time.Minute)
	if err != nil {
		t.Fatalf("expected valid token to verify, got: %v", err)
	}
	if got.String("email") != "alice@acme.example" {
		t.Errorf("unexpected email claim: %v", got["email"])
	}
}

func TestVerifyIDToken_RejectsBadSignature(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	otherPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Now()
	claims := map[string]any{
		"iss": "https://idp.example.com/", "aud": "client-123", "sub": "user-1",
		"exp": float64(now.Add(time.Hour).Unix()),
	}
	tok := makeToken(t, otherPriv, "key1", claims) // signed with the wrong key
	jwks := testJWKS(t, &priv.PublicKey, "key1")   // JWKS advertises a different key

	if _, err := VerifyIDToken(tok, jwks, "https://idp.example.com/", "client-123", "", now, 2*time.Minute); err == nil {
		t.Fatal("expected signature mismatch to be rejected")
	}
}

func TestVerifyIDToken_RejectsAlgNone(t *testing.T) {
	header := map[string]string{"alg": "none", "typ": "JWT"}
	hb, _ := json.Marshal(header)
	claims := map[string]any{"iss": "https://idp.example.com/", "aud": "client-123", "sub": "user-1", "exp": float64(time.Now().Add(time.Hour).Unix())}
	cb, _ := json.Marshal(claims)
	tok := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(cb) + "."

	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwks := testJWKS(t, &priv.PublicKey, "key1")
	if _, err := VerifyIDToken(tok, jwks, "https://idp.example.com/", "client-123", "", time.Now(), 2*time.Minute); err == nil {
		t.Fatal("expected alg=none token to be rejected")
	}
}

func TestVerifyIDToken_RejectsExpired(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Now()
	claims := map[string]any{
		"iss": "https://idp.example.com/", "aud": "client-123", "sub": "user-1",
		"exp": float64(now.Add(-time.Hour).Unix()),
	}
	tok := makeToken(t, priv, "key1", claims)
	jwks := testJWKS(t, &priv.PublicKey, "key1")
	if _, err := VerifyIDToken(tok, jwks, "https://idp.example.com/", "client-123", "", now, 2*time.Minute); err == nil {
		t.Fatal("expected expired token to be rejected")
	}
}

func TestVerifyIDToken_RejectsWrongAudience(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Now()
	claims := map[string]any{
		"iss": "https://idp.example.com/", "aud": "someone-elses-client", "sub": "user-1",
		"exp": float64(now.Add(time.Hour).Unix()),
	}
	tok := makeToken(t, priv, "key1", claims)
	jwks := testJWKS(t, &priv.PublicKey, "key1")
	if _, err := VerifyIDToken(tok, jwks, "https://idp.example.com/", "client-123", "", now, 2*time.Minute); err == nil {
		t.Fatal("expected wrong-audience token to be rejected")
	}
}

func TestVerifyIDToken_RejectsNonceMismatch(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Now()
	claims := map[string]any{
		"iss": "https://idp.example.com/", "aud": "client-123", "sub": "user-1",
		"exp": float64(now.Add(time.Hour).Unix()), "nonce": "actual-nonce",
	}
	tok := makeToken(t, priv, "key1", claims)
	jwks := testJWKS(t, &priv.PublicKey, "key1")
	if _, err := VerifyIDToken(tok, jwks, "https://idp.example.com/", "client-123", "expected-nonce", now, 2*time.Minute); err == nil {
		t.Fatal("expected nonce mismatch to be rejected")
	}
}
