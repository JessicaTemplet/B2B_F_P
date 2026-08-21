// Package store is the local persistence layer: a single SQLite database
// holding provisioned SCIM directory data (users, groups), authenticated
// sessions, and short-lived SAML request tracking (for replay defense).
package store

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

type Store struct {
	DB *sql.DB
}

const schema = `
CREATE TABLE IF NOT EXISTS users (
	id            TEXT PRIMARY KEY,
	tenant_id     TEXT NOT NULL,
	external_id   TEXT,
	user_name     TEXT NOT NULL,
	given_name    TEXT,
	family_name   TEXT,
	display_name  TEXT,
	email         TEXT,
	department    TEXT,
	active        INTEGER NOT NULL DEFAULT 1,
	attributes    TEXT NOT NULL DEFAULT '{}',
	version       INTEGER NOT NULL DEFAULT 1,
	created_at    TEXT NOT NULL,
	updated_at    TEXT NOT NULL,
	UNIQUE(tenant_id, user_name)
);
CREATE INDEX IF NOT EXISTS idx_users_tenant_external ON users(tenant_id, external_id);

CREATE TABLE IF NOT EXISTS groups (
	id            TEXT PRIMARY KEY,
	tenant_id     TEXT NOT NULL,
	external_id   TEXT,
	display_name  TEXT NOT NULL,
	version       INTEGER NOT NULL DEFAULT 1,
	created_at    TEXT NOT NULL,
	updated_at    TEXT NOT NULL,
	UNIQUE(tenant_id, display_name)
);
CREATE INDEX IF NOT EXISTS idx_groups_tenant_external ON groups(tenant_id, external_id);

CREATE TABLE IF NOT EXISTS group_members (
	group_id TEXT NOT NULL,
	user_id  TEXT NOT NULL,
	PRIMARY KEY (group_id, user_id)
);

CREATE TABLE IF NOT EXISTS sessions (
	id          TEXT PRIMARY KEY,
	tenant_id   TEXT NOT NULL,
	user_id     TEXT,
	subject     TEXT NOT NULL,
	attributes  TEXT NOT NULL DEFAULT '{}',
	auth_method TEXT NOT NULL,
	created_at  TEXT NOT NULL,
	expires_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS saml_requests (
	request_id TEXT PRIMARY KEY,
	tenant_id  TEXT NOT NULL,
	relay_state TEXT,
	created_at TEXT NOT NULL,
	expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS oidc_requests (
	state       TEXT PRIMARY KEY,
	tenant_id   TEXT NOT NULL,
	nonce       TEXT NOT NULL,
	pkce_verifier TEXT NOT NULL,
	relay_state TEXT,
	created_at  TEXT NOT NULL,
	expires_at  TEXT NOT NULL
);
`

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1) // modernc.org/sqlite + SQLite: serialize writers to avoid SQLITE_BUSY
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	return &Store{DB: db}, nil
}

func (s *Store) Close() error {
	return s.DB.Close()
}
