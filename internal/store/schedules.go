package store

import (
	"context"
	"time"
)

func (s *Store) CreateSchedule(ctx context.Context, sc *Schedule) error {
	now := time.Now().Unix()
	if sc.ID == "" {
		sc.ID = NewID()
	}
	_, err := s.exec(ctx,
		`INSERT INTO schedules (id,host_id,action,cron,created_at) VALUES (?,?,?,?,?)`,
		sc.ID, sc.HostID, sc.Action, sc.Cron, now)
	sc.CreatedAt = time.Unix(now, 0).UTC()
	return err
}

func (s *Store) DeleteSchedule(ctx context.Context, id string) error {
	_, err := s.exec(ctx, `DELETE FROM schedules WHERE id = ?`, id)
	return err
}

func (s *Store) ListSchedules(ctx context.Context, hostID string) ([]*Schedule, error) {
	q := `SELECT id,host_id,action,cron,created_at FROM schedules`
	var args []any
	if hostID != "" {
		q += ` WHERE host_id = ?`
		args = append(args, hostID)
	}
	q += ` ORDER BY created_at`
	rows, err := s.query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Schedule
	for rows.Next() {
		var (
			sc      Schedule
			created int64
		)
		if err := rows.Scan(&sc.ID, &sc.HostID, &sc.Action, &sc.Cron, &created); err != nil {
			return nil, err
		}
		sc.CreatedAt = time.Unix(created, 0).UTC()
		out = append(out, &sc)
	}
	return out, rows.Err()
}

// AcquireLease tries to take/refresh a named lease for holder until now+ttl.
// Returns true if held. Used for ACME renewal leader election across instances
// sharing one database (Round 4c).
func (s *Store) AcquireLease(ctx context.Context, name, holder string, ttl time.Duration) (bool, error) {
	now := time.Now().Unix()
	exp := now + int64(ttl.Seconds())
	// Refresh if we already hold it, or take it if expired/free.
	res, err := s.exec(ctx,
		`UPDATE leases SET holder=?, expires_at=? WHERE name=? AND (holder=? OR expires_at < ?)`,
		holder, exp, name, holder, now)
	if err != nil {
		return false, err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return true, nil
	}
	// No row yet: try to insert. If another instance inserts first, we lose.
	_, err = s.exec(ctx, `INSERT INTO leases (name,holder,expires_at) VALUES (?,?,?)`, name, holder, exp)
	if err != nil {
		// Insert failed (row exists, held by someone else) → not the leader.
		return false, nil
	}
	return true, nil
}
