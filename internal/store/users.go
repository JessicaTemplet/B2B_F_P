package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

var ErrNotFound = errors.New("not found")
var ErrConflict = errors.New("conflict")

// User is the gateway's internal directory record. Attributes carries the
// full raw SCIM attribute set (including anything the gateway doesn't model
// explicitly) so round-tripping through PATCH/GET never loses data an IdP
// sent us.
type User struct {
	ID          string
	TenantID    string
	ExternalID  string
	UserName    string
	GivenName   string
	FamilyName  string
	DisplayName string
	Email       string
	Department  string
	Active      bool
	Attributes  map[string]any
	Version     int
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

func scanUser(row interface{ Scan(...any) error }) (*User, error) {
	var u User
	var attrs string
	var created, updated string
	var active int
	var externalID, givenName, familyName, displayName, email, department sql.NullString
	err := row.Scan(&u.ID, &u.TenantID, &externalID, &u.UserName, &givenName, &familyName,
		&displayName, &email, &department, &active, &attrs, &u.Version, &created, &updated)
	if err != nil {
		return nil, err
	}
	u.ExternalID, u.GivenName, u.FamilyName = externalID.String, givenName.String, familyName.String
	u.DisplayName, u.Email, u.Department = displayName.String, email.String, department.String
	u.Active = active != 0
	u.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	u.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
	u.Attributes = map[string]any{}
	_ = json.Unmarshal([]byte(attrs), &u.Attributes)
	return &u, nil
}

const userCols = `id, tenant_id, external_id, user_name, given_name, family_name, display_name, email, department, active, attributes, version, created_at, updated_at`

func (s *Store) CreateUser(u *User) error {
	if u.ID == "" {
		u.ID = uuid.NewString()
	}
	now := time.Now().UTC()
	u.CreatedAt, u.UpdatedAt = now, now
	u.Version = 1
	attrs, err := json.Marshal(u.Attributes)
	if err != nil {
		return err
	}
	_, err = s.DB.Exec(`INSERT INTO users (`+userCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		u.ID, u.TenantID, nullable(u.ExternalID), u.UserName, nullable(u.GivenName), nullable(u.FamilyName),
		nullable(u.DisplayName), nullable(u.Email), nullable(u.Department), boolInt(u.Active), string(attrs),
		u.Version, u.CreatedAt.Format(time.RFC3339Nano), u.UpdatedAt.Format(time.RFC3339Nano))
	if err != nil {
		if isUniqueConstraint(err) {
			return ErrConflict
		}
		return fmt.Errorf("insert user: %w", err)
	}
	return nil
}

func (s *Store) GetUser(tenantID, id string) (*User, error) {
	row := s.DB.QueryRow(`SELECT `+userCols+` FROM users WHERE tenant_id = ? AND id = ?`, tenantID, id)
	u, err := scanUser(row)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	return u, err
}

func (s *Store) FindUserByUserName(tenantID, userName string) (*User, error) {
	row := s.DB.QueryRow(`SELECT `+userCols+` FROM users WHERE tenant_id = ? AND user_name = ?`, tenantID, userName)
	u, err := scanUser(row)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	return u, err
}

func (s *Store) FindUserByExternalID(tenantID, externalID string) (*User, error) {
	row := s.DB.QueryRow(`SELECT `+userCols+` FROM users WHERE tenant_id = ? AND external_id = ?`, tenantID, externalID)
	u, err := scanUser(row)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	return u, err
}

// ListUsers returns every user for a tenant. Filtering/pagination on SCIM
// list requests is applied by the caller (internal/scim) over this set —
// directories are small enough per-tenant that pushing the SCIM filter
// grammar down into SQL isn't worth the complexity here.
func (s *Store) ListUsers(tenantID string) ([]*User, error) {
	rows, err := s.DB.Query(`SELECT `+userCols+` FROM users WHERE tenant_id = ? ORDER BY created_at, id`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) ReplaceUser(u *User) error {
	attrs, err := json.Marshal(u.Attributes)
	if err != nil {
		return err
	}
	u.UpdatedAt = time.Now().UTC()
	u.Version++
	res, err := s.DB.Exec(`UPDATE users SET external_id=?, user_name=?, given_name=?, family_name=?, display_name=?,
		email=?, department=?, active=?, attributes=?, version=?, updated_at=? WHERE tenant_id=? AND id=?`,
		nullable(u.ExternalID), u.UserName, nullable(u.GivenName), nullable(u.FamilyName), nullable(u.DisplayName),
		nullable(u.Email), nullable(u.Department), boolInt(u.Active), string(attrs), u.Version,
		u.UpdatedAt.Format(time.RFC3339Nano), u.TenantID, u.ID)
	if err != nil {
		if isUniqueConstraint(err) {
			return ErrConflict
		}
		return fmt.Errorf("update user: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) DeleteUser(tenantID, id string) error {
	res, err := s.DB.Exec(`DELETE FROM users WHERE tenant_id=? AND id=?`, tenantID, id)
	if err != nil {
		return err
	}
	if _, err := s.DB.Exec(`DELETE FROM group_members WHERE user_id=?`, id); err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func isUniqueConstraint(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "UNIQUE constraint failed")
}
