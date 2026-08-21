package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"time"
)

// Session is the authenticated principal created after a successful SAML or
// OIDC login. Attributes carries whatever the ABAC evaluator needs (mapped
// directory attributes such as Department, plus group memberships).
type Session struct {
	ID         string
	TenantID   string
	UserID     string
	Subject    string // NameID / sub
	Attributes map[string]any
	AuthMethod string // "saml" | "oidc"
	CreatedAt  time.Time
	ExpiresAt  time.Time
}

func randomID(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (s *Store) CreateSession(sess *Session, ttl time.Duration) error {
	id, err := randomID(32)
	if err != nil {
		return err
	}
	sess.ID = id
	sess.CreatedAt = time.Now().UTC()
	sess.ExpiresAt = sess.CreatedAt.Add(ttl)
	attrs, err := json.Marshal(sess.Attributes)
	if err != nil {
		return err
	}
	_, err = s.DB.Exec(`INSERT INTO sessions (id, tenant_id, user_id, subject, attributes, auth_method, created_at, expires_at)
		VALUES (?,?,?,?,?,?,?,?)`, sess.ID, sess.TenantID, sess.UserID, sess.Subject, string(attrs), sess.AuthMethod,
		sess.CreatedAt.Format(time.RFC3339Nano), sess.ExpiresAt.Format(time.RFC3339Nano))
	return err
}

func (s *Store) GetSession(id string) (*Session, error) {
	row := s.DB.QueryRow(`SELECT id, tenant_id, user_id, subject, attributes, auth_method, created_at, expires_at
		FROM sessions WHERE id = ?`, id)
	var sess Session
	var attrs, created, expires string
	var userID sql.NullString
	if err := row.Scan(&sess.ID, &sess.TenantID, &userID, &sess.Subject, &attrs, &sess.AuthMethod, &created, &expires); err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, err
	}
	sess.UserID = userID.String
	sess.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	sess.ExpiresAt, _ = time.Parse(time.RFC3339Nano, expires)
	sess.Attributes = map[string]any{}
	_ = json.Unmarshal([]byte(attrs), &sess.Attributes)
	if time.Now().UTC().After(sess.ExpiresAt) {
		_ = s.DeleteSession(id)
		return nil, ErrNotFound
	}
	return &sess, nil
}

func (s *Store) DeleteSession(id string) error {
	_, err := s.DB.Exec(`DELETE FROM sessions WHERE id = ?`, id)
	return err
}

// --- SAML AuthnRequest tracking (replay / InResponseTo defense) ---

func (s *Store) PutSAMLRequest(requestID, tenantID, relayState string, ttl time.Duration) error {
	now := time.Now().UTC()
	_, err := s.DB.Exec(`INSERT INTO saml_requests (request_id, tenant_id, relay_state, created_at, expires_at) VALUES (?,?,?,?,?)`,
		requestID, tenantID, relayState, now.Format(time.RFC3339Nano), now.Add(ttl).Format(time.RFC3339Nano))
	return err
}

// TakeSAMLRequest atomically consumes (deletes) a pending request record so
// each AuthnRequest ID can be used as an InResponseTo target exactly once.
func (s *Store) TakeSAMLRequest(requestID, tenantID string) (relayState string, ok bool, err error) {
	row := s.DB.QueryRow(`SELECT relay_state, expires_at FROM saml_requests WHERE request_id = ? AND tenant_id = ?`, requestID, tenantID)
	var rs sql.NullString
	var expires string
	if err := row.Scan(&rs, &expires); err != nil {
		if err == sql.ErrNoRows {
			return "", false, nil
		}
		return "", false, err
	}
	if _, err := s.DB.Exec(`DELETE FROM saml_requests WHERE request_id = ?`, requestID); err != nil {
		return "", false, err
	}
	exp, _ := time.Parse(time.RFC3339Nano, expires)
	if time.Now().UTC().After(exp) {
		return "", false, nil
	}
	return rs.String, true, nil
}

// --- OIDC authorization-request tracking (state/nonce/PKCE) ---

type OIDCRequest struct {
	State        string
	TenantID     string
	Nonce        string
	PKCEVerifier string
	RelayState   string
}

func (s *Store) PutOIDCRequest(r OIDCRequest, ttl time.Duration) error {
	now := time.Now().UTC()
	_, err := s.DB.Exec(`INSERT INTO oidc_requests (state, tenant_id, nonce, pkce_verifier, relay_state, created_at, expires_at)
		VALUES (?,?,?,?,?,?,?)`, r.State, r.TenantID, r.Nonce, r.PKCEVerifier, r.RelayState,
		now.Format(time.RFC3339Nano), now.Add(ttl).Format(time.RFC3339Nano))
	return err
}

func (s *Store) TakeOIDCRequest(state string) (*OIDCRequest, bool, error) {
	row := s.DB.QueryRow(`SELECT state, tenant_id, nonce, pkce_verifier, relay_state, expires_at FROM oidc_requests WHERE state = ?`, state)
	var r OIDCRequest
	var relayState sql.NullString
	var expires string
	if err := row.Scan(&r.State, &r.TenantID, &r.Nonce, &r.PKCEVerifier, &relayState, &expires); err != nil {
		if err == sql.ErrNoRows {
			return nil, false, nil
		}
		return nil, false, err
	}
	r.RelayState = relayState.String
	if _, err := s.DB.Exec(`DELETE FROM oidc_requests WHERE state = ?`, state); err != nil {
		return nil, false, err
	}
	exp, _ := time.Parse(time.RFC3339Nano, expires)
	if time.Now().UTC().After(exp) {
		return nil, false, nil
	}
	return &r, true, nil
}
