package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"
)

// ErrNotFound is returned when a lookup matches no row.
var ErrNotFound = errors.New("not found")

// hashSessionToken maps a session token to its at-rest representation. Sessions are
// stored as sha256(token), never the live token, so a database read (backup, file
// access, SQLi elsewhere) cannot hand out usable sessions (S7). The token stays in
// the cookie; the DB only ever holds its hash. sha256 is sufficient here — the token
// is 256 bits of CSPRNG output, not a low-entropy secret needing a slow KDF.
func hashSessionToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// CountUsers returns how many user accounts exist (used to detect first-run).
func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.queryRow(ctx, `SELECT COUNT(1) FROM users`).Scan(&n)
	return n, err
}

// CreateUser inserts a new user.
func (s *Store) CreateUser(ctx context.Context, u *User) error {
	now := time.Now().Unix()
	if u.ID == "" {
		u.ID = NewID()
	}
	_, err := s.exec(ctx,
		`INSERT INTO users (id,email,name,password_hash,role,disabled,created_at,updated_at)
		 VALUES (?,?,?,?,?,?,?,?)`,
		u.ID, u.Email, u.Name, u.PasswordHash, string(u.Role), boolToInt(u.Disabled), now, now)
	u.CreatedAt = time.Unix(now, 0).UTC()
	u.UpdatedAt = u.CreatedAt
	return err
}

// CreateFirstUser atomically creates the first user, but only if the users table
// is empty. The INSERT ... SELECT ... WHERE NOT EXISTS runs as a single statement,
// so two concurrent first-run POST /api/setup requests can't both succeed — and it
// holds across multiple xgress instances on a shared Postgres, where a process mutex
// wouldn't. Returns whether the row was actually inserted.
func (s *Store) CreateFirstUser(ctx context.Context, u *User) (bool, error) {
	now := time.Now().Unix()
	if u.ID == "" {
		u.ID = NewID()
	}
	res, err := s.exec(ctx,
		`INSERT INTO users (id,email,name,password_hash,role,disabled,created_at,updated_at)
		 SELECT ?,?,?,?,?,?,?,? WHERE NOT EXISTS (SELECT 1 FROM users)`,
		u.ID, u.Email, u.Name, u.PasswordHash, string(u.Role), boolToInt(u.Disabled), now, now)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	if n == 1 {
		u.CreatedAt = time.Unix(now, 0).UTC()
		u.UpdatedAt = u.CreatedAt
	}
	return n == 1, nil
}

func (s *Store) scanUser(row interface{ Scan(...any) error }) (*User, error) {
	var (
		u                User
		disabled         int
		created, updated int64
	)
	if err := row.Scan(&u.ID, &u.Email, &u.Name, &u.PasswordHash, &u.Role, &disabled, &created, &updated); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	u.Disabled = disabled != 0
	u.CreatedAt = time.Unix(created, 0).UTC()
	u.UpdatedAt = time.Unix(updated, 0).UTC()
	return &u, nil
}

const userCols = `id,email,name,password_hash,role,disabled,created_at,updated_at`

// GetUserByEmail looks up a user by email.
func (s *Store) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	return s.scanUser(s.queryRow(ctx, `SELECT `+userCols+` FROM users WHERE email = ?`, email))
}

// GetUser looks up a user by id.
func (s *Store) GetUser(ctx context.Context, id string) (*User, error) {
	return s.scanUser(s.queryRow(ctx, `SELECT `+userCols+` FROM users WHERE id = ?`, id))
}

// ListUsers returns all users.
func (s *Store) ListUsers(ctx context.Context) ([]*User, error) {
	rows, err := s.query(ctx, `SELECT `+userCols+` FROM users ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*User
	for rows.Next() {
		u, err := s.scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// UpdateUser persists mutable user fields.
func (s *Store) UpdateUser(ctx context.Context, u *User) error {
	now := time.Now().Unix()
	_, err := s.exec(ctx,
		`UPDATE users SET email=?,name=?,password_hash=?,role=?,disabled=?,updated_at=? WHERE id=?`,
		u.Email, u.Name, u.PasswordHash, string(u.Role), boolToInt(u.Disabled), now, u.ID)
	u.UpdatedAt = time.Unix(now, 0).UTC()
	return err
}

// DeleteUser removes a user and their sessions.
func (s *Store) DeleteUser(ctx context.Context, id string) error {
	if _, err := s.exec(ctx, `DELETE FROM sessions WHERE user_id = ?`, id); err != nil {
		return err
	}
	_, err := s.exec(ctx, `DELETE FROM users WHERE id = ?`, id)
	return err
}

// --- sessions ---

// CreateSession stores a login session. Only the token's hash is persisted (S7);
// sess.Token is left untouched so the caller can still set it as the cookie value.
func (s *Store) CreateSession(ctx context.Context, sess *Session) error {
	_, err := s.exec(ctx,
		`INSERT INTO sessions (token,user_id,user_agent,ip,created_at,expires_at) VALUES (?,?,?,?,?,?)`,
		hashSessionToken(sess.Token), sess.UserID, sess.UserAgent, sess.IP, sess.CreatedAt.Unix(), sess.ExpiresAt.Unix())
	return err
}

// GetSession fetches a non-expired session by its token (looked up by hash).
func (s *Store) GetSession(ctx context.Context, token string) (*Session, error) {
	var (
		sess             Session
		stored           string
		created, expires int64
	)
	err := s.queryRow(ctx,
		`SELECT token,user_id,user_agent,ip,created_at,expires_at FROM sessions WHERE token = ?`, hashSessionToken(token)).
		Scan(&stored, &sess.UserID, &sess.UserAgent, &sess.IP, &created, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	sess.Token = token // return the live token the caller supplied, not its stored hash
	sess.CreatedAt = time.Unix(created, 0).UTC()
	sess.ExpiresAt = time.Unix(expires, 0).UTC()
	if time.Now().After(sess.ExpiresAt) {
		_ = s.DeleteSession(ctx, token)
		return nil, ErrNotFound
	}
	return &sess, nil
}

// DeleteSession revokes a session.
func (s *Store) DeleteSession(ctx context.Context, token string) error {
	_, err := s.exec(ctx, `DELETE FROM sessions WHERE token = ?`, hashSessionToken(token))
	return err
}

// PurgeExpiredSessions removes stale sessions.
func (s *Store) PurgeExpiredSessions(ctx context.Context) error {
	_, err := s.exec(ctx, `DELETE FROM sessions WHERE expires_at < ?`, time.Now().Unix())
	return err
}
