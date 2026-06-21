package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// --- DNS providers ---

func (s *Store) CreateDNSProvider(ctx context.Context, p *DNSProvider) error {
	now := time.Now().Unix()
	if p.ID == "" {
		p.ID = NewID()
	}
	_, err := s.exec(ctx,
		`INSERT INTO dns_providers (id,name,provider,config_enc,config_keys,created_at,updated_at) VALUES (?,?,?,?,?,?,?)`,
		p.ID, p.Name, p.Provider, p.ConfigEnc, mustJSON(p.ConfigKeys), now, now)
	p.CreatedAt = time.Unix(now, 0).UTC()
	p.UpdatedAt = p.CreatedAt
	return err
}

func (s *Store) DeleteDNSProvider(ctx context.Context, id string) error {
	_, err := s.exec(ctx, `DELETE FROM dns_providers WHERE id = ?`, id)
	return err
}

func (s *Store) scanDNS(row interface{ Scan(...any) error }) (*DNSProvider, error) {
	var (
		p                DNSProvider
		keys             string
		created, updated int64
	)
	if err := row.Scan(&p.ID, &p.Name, &p.Provider, &p.ConfigEnc, &keys, &created, &updated); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	jsonInto(keys, &p.ConfigKeys)
	p.CreatedAt = time.Unix(created, 0).UTC()
	p.UpdatedAt = time.Unix(updated, 0).UTC()
	return &p, nil
}

func (s *Store) GetDNSProvider(ctx context.Context, id string) (*DNSProvider, error) {
	return s.scanDNS(s.queryRow(ctx,
		`SELECT id,name,provider,config_enc,config_keys,created_at,updated_at FROM dns_providers WHERE id = ?`, id))
}

func (s *Store) ListDNSProviders(ctx context.Context) ([]*DNSProvider, error) {
	rows, err := s.query(ctx, `SELECT id,name,provider,config_enc,config_keys,created_at,updated_at FROM dns_providers ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*DNSProvider
	for rows.Next() {
		p, err := s.scanDNS(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// --- ACME accounts ---

func (s *Store) CreateACMEAccount(ctx context.Context, a *ACMEAccount) error {
	now := time.Now().Unix()
	if a.ID == "" {
		a.ID = NewID()
	}
	_, err := s.exec(ctx,
		`INSERT INTO acme_accounts (id,email,ca_dir_url,registration,private_key_enc,created_at) VALUES (?,?,?,?,?,?)`,
		a.ID, a.Email, a.CADirURL, a.Registration, a.PrivateKeyEnc, now)
	a.CreatedAt = time.Unix(now, 0).UTC()
	return err
}

func (s *Store) scanACME(row interface{ Scan(...any) error }) (*ACMEAccount, error) {
	var (
		a       ACMEAccount
		created int64
	)
	if err := row.Scan(&a.ID, &a.Email, &a.CADirURL, &a.Registration, &a.PrivateKeyEnc, &created); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	a.CreatedAt = time.Unix(created, 0).UTC()
	return &a, nil
}

// GetACMEAccountByEmail finds an account for an email/CA pair.
func (s *Store) GetACMEAccountByEmail(ctx context.Context, email, caURL string) (*ACMEAccount, error) {
	return s.scanACME(s.queryRow(ctx,
		`SELECT id,email,ca_dir_url,registration,private_key_enc,created_at FROM acme_accounts WHERE email=? AND ca_dir_url=?`,
		email, caURL))
}

// --- settings ---

func (s *Store) GetSetting(ctx context.Context, key string) (string, error) {
	var v string
	err := s.queryRow(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return v, err
}

// ListAllSettings returns every app setting as a key/value map.
func (s *Store) ListAllSettings(ctx context.Context) (map[string]string, error) {
	rows, err := s.query(ctx, `SELECT key,value FROM settings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}

func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	now := time.Now().Unix()
	// Portable upsert: try update, then insert if nothing changed.
	res, err := s.exec(ctx, `UPDATE settings SET value=?,updated_at=? WHERE key=?`, value, now, key)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		_, err = s.exec(ctx, `INSERT INTO settings (key,value,updated_at) VALUES (?,?,?)`, key, value, now)
	}
	return err
}

// --- audit ---

func (s *Store) AddAudit(ctx context.Context, e *AuditEntry) error {
	if e.ID == "" {
		e.ID = NewID()
	}
	if e.At.IsZero() {
		e.At = time.Now()
	}
	_, err := s.exec(ctx,
		`INSERT INTO audit_log (id,at,user_id,user_email,action,target,detail) VALUES (?,?,?,?,?,?,?)`,
		e.ID, e.At.Unix(), e.UserID, e.UserEmail, e.Action, e.Target, e.Detail)
	return err
}

func (s *Store) ListAudit(ctx context.Context, limit int) ([]*AuditEntry, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := s.query(ctx,
		`SELECT id,at,user_id,user_email,action,target,detail FROM audit_log ORDER BY at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*AuditEntry
	for rows.Next() {
		var (
			e  AuditEntry
			at int64
		)
		if err := rows.Scan(&e.ID, &at, &e.UserID, &e.UserEmail, &e.Action, &e.Target, &e.Detail); err != nil {
			return nil, err
		}
		e.At = time.Unix(at, 0).UTC()
		out = append(out, &e)
	}
	return out, rows.Err()
}

// --- config snapshots (last-known-good / rollback) ---

func (s *Store) AddSnapshot(ctx context.Context, snap *ConfigSnapshot) error {
	now := time.Now().Unix()
	_, err := s.exec(ctx,
		`INSERT INTO config_snapshots (version,json,hash,valid,created_at) VALUES (?,?,?,?,?)`,
		snap.Version, snap.JSON, snap.Hash, boolToInt(snap.Valid), now)
	snap.CreatedAt = time.Unix(now, 0).UTC()
	return err
}

func (s *Store) LatestSnapshotVersion(ctx context.Context) (int64, error) {
	var v sql.NullInt64
	err := s.queryRow(ctx, `SELECT MAX(version) FROM config_snapshots`).Scan(&v)
	if err != nil {
		return 0, err
	}
	if !v.Valid {
		return 0, nil
	}
	return v.Int64, nil
}

func (s *Store) GetSnapshot(ctx context.Context, version int64) (*ConfigSnapshot, error) {
	var (
		snap    ConfigSnapshot
		valid   int
		created int64
	)
	err := s.queryRow(ctx,
		`SELECT version,json,hash,valid,created_at FROM config_snapshots WHERE version = ?`, version).
		Scan(&snap.Version, &snap.JSON, &snap.Hash, &valid, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	snap.Valid = valid != 0
	snap.CreatedAt = time.Unix(created, 0).UTC()
	return &snap, nil
}

// ListSnapshots returns snapshot metadata (no JSON body) newest-first.
func (s *Store) ListSnapshots(ctx context.Context, limit int) ([]*ConfigSnapshot, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.query(ctx, `SELECT version,hash,valid,created_at FROM config_snapshots ORDER BY version DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*ConfigSnapshot
	for rows.Next() {
		var (
			snap    ConfigSnapshot
			valid   int
			created int64
		)
		if err := rows.Scan(&snap.Version, &snap.Hash, &valid, &created); err != nil {
			return nil, err
		}
		snap.Valid = valid != 0
		snap.CreatedAt = time.Unix(created, 0).UTC()
		out = append(out, &snap)
	}
	return out, rows.Err()
}

// PruneSnapshots keeps only the newest keep snapshots.
func (s *Store) PruneSnapshots(ctx context.Context, keep int) error {
	_, err := s.exec(ctx,
		`DELETE FROM config_snapshots WHERE version NOT IN (
			SELECT version FROM config_snapshots ORDER BY version DESC LIMIT ?
		)`, keep)
	return err
}
