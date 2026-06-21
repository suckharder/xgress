package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// CreateCertificate inserts a certificate record.
func (s *Store) CreateCertificate(ctx context.Context, c *Certificate) error {
	now := time.Now().Unix()
	if c.ID == "" {
		c.ID = NewID()
	}
	_, err := s.exec(ctx,
		`INSERT INTO certificates
		 (id,type,domains,status,challenge_type,dns_provider_id,acme_account_id,cert_pem,key_pem_enc,
		  issued_at,expires_at,last_error,last_attempt_at,auto_renew,created_at,updated_at)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		c.ID, string(c.Type), mustJSON(c.Domains), string(c.Status), c.ChallengeType, c.DNSProviderID,
		c.ACMEAccountID, c.CertPEM, c.KeyPEMEnc, nullableUnix(c.IssuedAt), nullableUnix(c.ExpiresAt),
		c.LastError, nullableUnix(c.LastAttemptAt), boolToInt(c.AutoRenew), now, now)
	c.CreatedAt = time.Unix(now, 0).UTC()
	c.UpdatedAt = c.CreatedAt
	return err
}

// UpdateCertificate persists changes (status, material, errors, expiry).
func (s *Store) UpdateCertificate(ctx context.Context, c *Certificate) error {
	now := time.Now().Unix()
	_, err := s.exec(ctx,
		`UPDATE certificates SET
		 type=?,domains=?,status=?,challenge_type=?,dns_provider_id=?,acme_account_id=?,cert_pem=?,key_pem_enc=?,
		 issued_at=?,expires_at=?,last_error=?,last_attempt_at=?,auto_renew=?,updated_at=? WHERE id=?`,
		string(c.Type), mustJSON(c.Domains), string(c.Status), c.ChallengeType, c.DNSProviderID, c.ACMEAccountID,
		c.CertPEM, c.KeyPEMEnc, nullableUnix(c.IssuedAt), nullableUnix(c.ExpiresAt), c.LastError,
		nullableUnix(c.LastAttemptAt), boolToInt(c.AutoRenew), now, c.ID)
	c.UpdatedAt = time.Unix(now, 0).UTC()
	return err
}

// DeleteCertificate removes a certificate.
func (s *Store) DeleteCertificate(ctx context.Context, id string) error {
	_, err := s.exec(ctx, `DELETE FROM certificates WHERE id = ?`, id)
	return err
}

const certCols = `id,type,domains,status,challenge_type,dns_provider_id,acme_account_id,cert_pem,key_pem_enc,
	issued_at,expires_at,last_error,last_attempt_at,auto_renew,created_at,updated_at`

func (s *Store) scanCert(row interface{ Scan(...any) error }) (*Certificate, error) {
	var (
		c                        Certificate
		issued, expires, attempt sql.NullInt64
		autoRenew                int
		created, updated         int64
		domains                  string
	)
	if err := row.Scan(&c.ID, &c.Type, &domains, &c.Status, &c.ChallengeType, &c.DNSProviderID, &c.ACMEAccountID,
		&c.CertPEM, &c.KeyPEMEnc, &issued, &expires, &c.LastError, &attempt, &autoRenew, &created, &updated); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	jsonInto(domains, &c.Domains)
	c.IssuedAt = fromUnix(issued)
	c.ExpiresAt = fromUnix(expires)
	c.LastAttemptAt = fromUnix(attempt)
	c.AutoRenew = autoRenew != 0
	c.CreatedAt = time.Unix(created, 0).UTC()
	c.UpdatedAt = time.Unix(updated, 0).UTC()
	return &c, nil
}

// GetCertificate fetches one certificate.
func (s *Store) GetCertificate(ctx context.Context, id string) (*Certificate, error) {
	return s.scanCert(s.queryRow(ctx, `SELECT `+certCols+` FROM certificates WHERE id = ?`, id))
}

// ListCertificates returns all certificates.
func (s *Store) ListCertificates(ctx context.Context) ([]*Certificate, error) {
	rows, err := s.query(ctx, `SELECT `+certCols+` FROM certificates ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Certificate
	for rows.Next() {
		c, err := s.scanCert(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
