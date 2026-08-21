package store

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type Group struct {
	ID          string
	TenantID    string
	ExternalID  string
	DisplayName string
	Members     []string // user IDs
	Version     int
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

const groupCols = `id, tenant_id, external_id, display_name, version, created_at, updated_at`

func scanGroup(row interface{ Scan(...any) error }) (*Group, error) {
	var g Group
	var externalID sql.NullString
	var created, updated string
	if err := row.Scan(&g.ID, &g.TenantID, &externalID, &g.DisplayName, &g.Version, &created, &updated); err != nil {
		return nil, err
	}
	g.ExternalID = externalID.String
	g.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	g.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
	return &g, nil
}

func (s *Store) loadMembers(groupID string) ([]string, error) {
	rows, err := s.DB.Query(`SELECT user_id FROM group_members WHERE group_id = ? ORDER BY user_id`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var members []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		members = append(members, id)
	}
	return members, rows.Err()
}

func (s *Store) CreateGroup(g *Group) error {
	if g.ID == "" {
		g.ID = uuid.NewString()
	}
	now := time.Now().UTC()
	g.CreatedAt, g.UpdatedAt = now, now
	g.Version = 1
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO groups (`+groupCols+`) VALUES (?,?,?,?,?,?,?)`,
		g.ID, g.TenantID, nullable(g.ExternalID), g.DisplayName, g.Version,
		g.CreatedAt.Format(time.RFC3339Nano), g.UpdatedAt.Format(time.RFC3339Nano))
	if err != nil {
		if isUniqueConstraint(err) {
			return ErrConflict
		}
		return fmt.Errorf("insert group: %w", err)
	}
	if err := replaceMembersTx(tx, g.ID, g.Members); err != nil {
		return err
	}
	return tx.Commit()
}

func replaceMembersTx(tx *sql.Tx, groupID string, members []string) error {
	if _, err := tx.Exec(`DELETE FROM group_members WHERE group_id = ?`, groupID); err != nil {
		return err
	}
	for _, m := range members {
		if _, err := tx.Exec(`INSERT OR IGNORE INTO group_members (group_id, user_id) VALUES (?, ?)`, groupID, m); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) GetGroup(tenantID, id string) (*Group, error) {
	row := s.DB.QueryRow(`SELECT `+groupCols+` FROM groups WHERE tenant_id = ? AND id = ?`, tenantID, id)
	g, err := scanGroup(row)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	g.Members, err = s.loadMembers(g.ID)
	return g, err
}

func (s *Store) FindGroupByExternalID(tenantID, externalID string) (*Group, error) {
	row := s.DB.QueryRow(`SELECT `+groupCols+` FROM groups WHERE tenant_id = ? AND external_id = ?`, tenantID, externalID)
	g, err := scanGroup(row)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	g.Members, err = s.loadMembers(g.ID)
	return g, err
}

func (s *Store) ListGroups(tenantID string) ([]*Group, error) {
	rows, err := s.DB.Query(`SELECT `+groupCols+` FROM groups WHERE tenant_id = ? ORDER BY created_at, id`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Group
	for rows.Next() {
		g, err := scanGroup(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, g := range out {
		g.Members, err = s.loadMembers(g.ID)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (s *Store) ReplaceGroup(g *Group) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	g.UpdatedAt = time.Now().UTC()
	g.Version++
	res, err := tx.Exec(`UPDATE groups SET external_id=?, display_name=?, version=?, updated_at=? WHERE tenant_id=? AND id=?`,
		nullable(g.ExternalID), g.DisplayName, g.Version, g.UpdatedAt.Format(time.RFC3339Nano), g.TenantID, g.ID)
	if err != nil {
		if isUniqueConstraint(err) {
			return ErrConflict
		}
		return fmt.Errorf("update group: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	if err := replaceMembersTx(tx, g.ID, g.Members); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) DeleteGroup(tenantID, id string) error {
	res, err := s.DB.Exec(`DELETE FROM groups WHERE tenant_id=? AND id=?`, tenantID, id)
	if err != nil {
		return err
	}
	if _, err := s.DB.Exec(`DELETE FROM group_members WHERE group_id=?`, id); err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// GroupsForUser returns the IDs of every group the given user belongs to,
// used to fold "groups" into the ABAC subject attributes at auth time.
func (s *Store) GroupsForUser(tenantID, userID string) ([]string, error) {
	rows, err := s.DB.Query(`SELECT g.id FROM groups g JOIN group_members m ON m.group_id = g.id
		WHERE g.tenant_id = ? AND m.user_id = ?`, tenantID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
