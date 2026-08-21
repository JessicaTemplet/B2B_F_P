package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// GeneratePKCEVerifier returns a cryptographically random code_verifier
// (RFC 7636 §4.1: 43-128 chars from the unreserved URL-safe alphabet).
func GeneratePKCEVerifier() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func PKCEChallengeS256(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func GenerateState() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// BuildAuthorizeURL constructs the authorization-code-with-PKCE request URL.
func BuildAuthorizeURL(meta *ProviderMetadata, clientID, redirectURI, state, nonce, codeChallenge string, scopes []string) string {
	v := url.Values{}
	v.Set("response_type", "code")
	v.Set("client_id", clientID)
	v.Set("redirect_uri", redirectURI)
	v.Set("scope", strings.Join(scopes, " "))
	v.Set("state", state)
	v.Set("nonce", nonce)
	v.Set("code_challenge", codeChallenge)
	v.Set("code_challenge_method", "S256")
	sep := "?"
	if strings.Contains(meta.AuthorizationEndpoint, "?") {
		sep = "&"
	}
	return meta.AuthorizationEndpoint + sep + v.Encode()
}

// TokenResponse is the subset of RFC 6749 §5.1's token response this RP
// consumes.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// ExchangeCode performs the token endpoint request for the authorization
// code flow, presenting the PKCE verifier instead of (or alongside) a
// client secret.
func ExchangeCode(ctx context.Context, httpClient *http.Client, meta *ProviderMetadata, clientID, clientSecret, redirectURI, code, verifier string) (*TokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", clientID)
	form.Set("code_verifier", verifier)
	if clientSecret != "" {
		form.Set("client_secret", clientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, meta.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc token exchange: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc token exchange: unexpected status %d", resp.StatusCode)
	}
	var tr TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return nil, fmt.Errorf("oidc token exchange: invalid JSON: %w", err)
	}
	if tr.IDToken == "" {
		return nil, fmt.Errorf("oidc token exchange: response missing id_token")
	}
	return &tr, nil
}

var defaultClockSkew = 2 * time.Minute
