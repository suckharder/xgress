package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

func (s *Store) CreateAccessList(ctx context.Context, a *AccessList) error {
	now := time.Now().Unix()
	if a.ID == "" {
		a.ID = NewID()
	}
	_, err := s.exec(ctx,
		`INSERT INTO access_lists (id,name,users,allow_ips,satisfy_any,created_at,updated_at) VALUES (?,?,?,?,?,?,?)`,
		a.ID, a.Name, mustJSON(a.Users), mustJSON(a.AllowIPs), boolToInt(a.SatisfyAny), now, now)
	a.CreatedAt = time.Unix(now, 0).UTC()
	a.UpdatedAt = a.CreatedAt
	return err
}

func (s *Store) UpdateAccessList(ctx context.Context, a *AccessList) error {
	now := time.Now().Unix()
	_, err := s.exec(ctx,
		`UPDATE access_lists SET name=?,users=?,allow_ips=?,satisfy_any=?,updated_at=? WHERE id=?`,
		a.Name, mustJSON(a.Users), mustJSON(a.AllowIPs), boolToInt(a.SatisfyAny), now, a.ID)
	a.UpdatedAt = time.Unix(now, 0).UTC()
	return err
}

func (s *Store) DeleteAccessList(ctx context.Context, id string) error {
	_, err := s.exec(ctx, `DELETE FROM access_lists WHERE id = ?`, id)
	return err
}

func (s *Store) scanAccessList(row interface{ Scan(...any) error }) (*AccessList, error) {
	var (
		a                AccessList
		users, ips       string
		satisfy          int
		created, updated int64
	)
	if err := row.Scan(&a.ID, &a.Name, &users, &ips, &satisfy, &created, &updated); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	jsonInto(users, &a.Users)
	jsonInto(ips, &a.AllowIPs)
	a.SatisfyAny = satisfy != 0
	a.CreatedAt = time.Unix(created, 0).UTC()
	a.UpdatedAt = time.Unix(updated, 0).UTC()
	return &a, nil
}

func (s *Store) GetAccessList(ctx context.Context, id string) (*AccessList, error) {
	return s.scanAccessList(s.queryRow(ctx,
		`SELECT id,name,users,allow_ips,satisfy_any,created_at,updated_at FROM access_lists WHERE id = ?`, id))
}

func (s *Store) ListAccessLists(ctx context.Context) ([]*AccessList, error) {
	rows, err := s.query(ctx, `SELECT id,name,users,allow_ips,satisfy_any,created_at,updated_at FROM access_lists ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*AccessList
	for rows.Next() {
		a, err := s.scanAccessList(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
