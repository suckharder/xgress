package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// hostData is the kind-specific payload persisted in the hosts.data JSON column.
// Core/queryable fields (id, kind, enabled, domains, timestamps) live in their
// own columns; everything else round-trips through here.
func hostData(h *Host) string {
	clone := *h
	// Null out fields stored in dedicated columns to keep the JSON focused.
	clone.ID, clone.Kind, clone.Enabled, clone.Domains = "", "", false, nil
	clone.CreatedAt, clone.UpdatedAt = time.Time{}, time.Time{}
	return mustJSON(&clone)
}

// CreateHost inserts a host.
func (s *Store) CreateHost(ctx context.Context, h *Host) error {
	now := time.Now().Unix()
	if h.ID == "" {
		h.ID = NewID()
	}
	_, err := s.exec(ctx,
		`INSERT INTO hosts (id,kind,enabled,domains,data,created_at,updated_at) VALUES (?,?,?,?,?,?,?)`,
		h.ID, string(h.Kind), boolToInt(h.Enabled), mustJSON(h.Domains), hostData(h), now, now)
	h.CreatedAt = time.Unix(now, 0).UTC()
	h.UpdatedAt = h.CreatedAt
	return err
}

// UpdateHost persists an existing host.
func (s *Store) UpdateHost(ctx context.Context, h *Host) error {
	now := time.Now().Unix()
	_, err := s.exec(ctx,
		`UPDATE hosts SET kind=?,enabled=?,domains=?,data=?,updated_at=? WHERE id=?`,
		string(h.Kind), boolToInt(h.Enabled), mustJSON(h.Domains), hostData(h), now, h.ID)
	h.UpdatedAt = time.Unix(now, 0).UTC()
	return err
}

// DeleteHost removes a host.
func (s *Store) DeleteHost(ctx context.Context, id string) error {
	_, err := s.exec(ctx, `DELETE FROM hosts WHERE id = ?`, id)
	return err
}

func (s *Store) scanHost(row interface{ Scan(...any) error }) (*Host, error) {
	var (
		h                Host
		kind, domains    string
		data             string
		enabled          int
		created, updated int64
	)
	var id string
	if err := row.Scan(&id, &kind, &enabled, &domains, &data, &created, &updated); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	// Unmarshal kind-specific data first, then apply the dedicated columns so
	// they win over the (intentionally zeroed) copies inside the data blob.
	jsonInto(data, &h)
	h.ID = id
	h.Kind = HostKind(kind)
	h.Enabled = enabled != 0
	jsonInto(domains, &h.Domains)
	h.CreatedAt = time.Unix(created, 0).UTC()
	h.UpdatedAt = time.Unix(updated, 0).UTC()
	return &h, nil
}

const hostCols = `id,kind,enabled,domains,data,created_at,updated_at`

// GetHost fetches one host.
func (s *Store) GetHost(ctx context.Context, id string) (*Host, error) {
	return s.scanHost(s.queryRow(ctx, `SELECT `+hostCols+` FROM hosts WHERE id = ?`, id))
}

// ListHosts returns all hosts (optionally a single kind when kind != "").
func (s *Store) ListHosts(ctx context.Context, kind HostKind) ([]*Host, error) {
	q := `SELECT ` + hostCols + ` FROM hosts`
	var args []any
	if kind != "" {
		q += ` WHERE kind = ?`
		args = append(args, string(kind))
	}
	q += ` ORDER BY created_at`
	rows, err := s.query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Host
	for rows.Next() {
		h, err := s.scanHost(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}
