package store

import (
	"context"
	"time"
)

// Ban is a blocked source IP/CIDR. ExpiresAt zero means permanent.
type Ban struct {
	IP        string     `json:"ip"`
	Reason    string     `json:"reason"`
	Manual    bool       `json:"manual"`
	Hits      int        `json:"hits"`
	CreatedAt time.Time  `json:"createdAt"`
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
}

// AddBan inserts or refreshes a ban (upsert on ip).
func (s *Store) AddBan(ctx context.Context, b *Ban) error {
	now := time.Now().Unix()
	var exp int64
	if b.ExpiresAt != nil && !b.ExpiresAt.IsZero() {
		exp = b.ExpiresAt.Unix()
	}
	res, err := s.exec(ctx,
		`UPDATE bans SET reason=?,manual=?,hits=?,expires_at=? WHERE ip=?`,
		b.Reason, boolToInt(b.Manual), b.Hits, exp, b.IP)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		_, err = s.exec(ctx,
			`INSERT INTO bans (ip,reason,manual,hits,created_at,expires_at) VALUES (?,?,?,?,?,?)`,
			b.IP, b.Reason, boolToInt(b.Manual), b.Hits, now, exp)
	}
	return err
}

// DeleteBan removes a ban (unban).
func (s *Store) DeleteBan(ctx context.Context, ip string) error {
	_, err := s.exec(ctx, `DELETE FROM bans WHERE ip = ?`, ip)
	return err
}

// ListActiveBans returns bans that are permanent or not yet expired.
func (s *Store) ListActiveBans(ctx context.Context) ([]*Ban, error) {
	now := time.Now().Unix()
	rows, err := s.query(ctx,
		`SELECT ip,reason,manual,hits,created_at,expires_at FROM bans WHERE expires_at = 0 OR expires_at > ? ORDER BY created_at DESC`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Ban
	for rows.Next() {
		var (
			b               Ban
			manual          int
			created, expire int64
		)
		if err := rows.Scan(&b.IP, &b.Reason, &manual, &b.Hits, &created, &expire); err != nil {
			return nil, err
		}
		b.Manual = manual != 0
		b.CreatedAt = time.Unix(created, 0).UTC()
		if expire != 0 {
			t := time.Unix(expire, 0).UTC()
			b.ExpiresAt = &t
		}
		out = append(out, &b)
	}
	return out, rows.Err()
}

// IsActivelyBanned reports whether an exact IP currently has an active ban.
func (s *Store) IsActivelyBanned(ctx context.Context, ip string) (bool, error) {
	now := time.Now().Unix()
	var n int
	err := s.queryRow(ctx,
		`SELECT COUNT(1) FROM bans WHERE ip = ? AND (expires_at = 0 OR expires_at > ?)`, ip, now).Scan(&n)
	return n > 0, err
}

// PruneExpiredBans deletes expired bans and returns how many were removed.
func (s *Store) PruneExpiredBans(ctx context.Context) (int, error) {
	now := time.Now().Unix()
	res, err := s.exec(ctx, `DELETE FROM bans WHERE expires_at != 0 AND expires_at <= ?`, now)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}
