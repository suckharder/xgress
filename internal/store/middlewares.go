package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// CreateMiddleware inserts a reusable middleware.
func (s *Store) CreateMiddleware(ctx context.Context, m *Middleware) error {
	now := time.Now().Unix()
	if m.ID == "" {
		m.ID = NewID()
	}
	_, err := s.exec(ctx,
		`INSERT INTO middlewares (id,name,type,params,created_at,updated_at) VALUES (?,?,?,?,?,?)`,
		m.ID, m.Name, m.Type, mustJSON(m.Params), now, now)
	m.CreatedAt = time.Unix(now, 0).UTC()
	m.UpdatedAt = m.CreatedAt
	return err
}

// UpdateMiddleware persists changes.
func (s *Store) UpdateMiddleware(ctx context.Context, m *Middleware) error {
	now := time.Now().Unix()
	_, err := s.exec(ctx,
		`UPDATE middlewares SET name=?,type=?,params=?,updated_at=? WHERE id=?`,
		m.Name, m.Type, mustJSON(m.Params), now, m.ID)
	m.UpdatedAt = time.Unix(now, 0).UTC()
	return err
}

// DeleteMiddleware removes a middleware.
func (s *Store) DeleteMiddleware(ctx context.Context, id string) error {
	_, err := s.exec(ctx, `DELETE FROM middlewares WHERE id = ?`, id)
	return err
}

func (s *Store) scanMiddleware(row interface{ Scan(...any) error }) (*Middleware, error) {
	var (
		m                Middleware
		params           string
		created, updated int64
	)
	if err := row.Scan(&m.ID, &m.Name, &m.Type, &params, &created, &updated); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	m.Params = map[string]any{}
	jsonInto(params, &m.Params)
	m.CreatedAt = time.Unix(created, 0).UTC()
	m.UpdatedAt = time.Unix(updated, 0).UTC()
	return &m, nil
}

// GetMiddleware fetches one middleware.
func (s *Store) GetMiddleware(ctx context.Context, id string) (*Middleware, error) {
	return s.scanMiddleware(s.queryRow(ctx,
		`SELECT id,name,type,params,created_at,updated_at FROM middlewares WHERE id = ?`, id))
}

// ListMiddlewares returns all middlewares.
func (s *Store) ListMiddlewares(ctx context.Context) ([]*Middleware, error) {
	rows, err := s.query(ctx, `SELECT id,name,type,params,created_at,updated_at FROM middlewares ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Middleware
	for rows.Next() {
		m, err := s.scanMiddleware(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}
