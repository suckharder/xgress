// Package store is the persistence layer and the source of truth for all xgress
// configuration. It supports two interchangeable backends — embedded SQLite
// (default, zero-config) and external Postgres — over a single database/sql
// implementation. SQLite is pure-Go (modernc.org/sqlite) so the binary needs no
// cgo and the container stays tiny.
package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/suckharder/xgress/internal/config"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Dialect identifies SQL placeholder/affinity differences between backends.
type Dialect string

const (
	DialectSQLite   Dialect = "sqlite"
	DialectPostgres Dialect = "postgres"
)

// Store wraps the database handle and knows which dialect it speaks.
type Store struct {
	db      *sql.DB
	dialect Dialect
}

// Open connects to the configured backend, applies migrations, and returns a
// ready Store.
func Open(ctx context.Context, cfg *config.Config) (*Store, error) {
	var (
		db  *sql.DB
		err error
		dia Dialect
	)
	switch cfg.DBDriver {
	case config.DriverSQLite:
		dia = DialectSQLite
		// WAL + busy_timeout + foreign_keys for a robust single-writer setup.
		dsn := cfg.SQLitePath() + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
		db, err = sql.Open("sqlite", dsn)
		if err == nil {
			// SQLite is a single-writer; serialise writes to avoid "database is locked".
			db.SetMaxOpenConns(1)
		}
	case config.DriverPostgres:
		dia = DialectPostgres
		db, err = sql.Open("pgx", cfg.DBDSN)
	default:
		return nil, fmt.Errorf("unsupported driver %q", cfg.DBDriver)
	}
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("ping db: %w", err)
	}

	s := &Store{db: db, dialect: dia}
	if err := s.migrate(ctx); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

// Close releases the database handle.
func (s *Store) Close() error { return s.db.Close() }

// rebind converts the canonical `?` placeholder style we write queries in to the
// dialect's native style ($1,$2,… for Postgres).
func (s *Store) rebind(query string) string {
	if s.dialect != DialectPostgres {
		return query
	}
	var b strings.Builder
	n := 0
	for _, r := range query {
		if r == '?' {
			n++
			b.WriteByte('$')
			b.WriteString(fmt.Sprint(n))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func (s *Store) exec(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return s.db.ExecContext(ctx, s.rebind(query), args...)
}

func (s *Store) query(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return s.db.QueryContext(ctx, s.rebind(query), args...)
}

func (s *Store) queryRow(ctx context.Context, query string, args ...any) *sql.Row {
	return s.db.QueryRowContext(ctx, s.rebind(query), args...)
}

// migrate applies embedded SQL migrations in lexical order, tracked in a
// schema_migrations table so each runs exactly once.
func (s *Store) migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx,
		`CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY, applied_at INTEGER NOT NULL)`); err != nil {
		return err
	}

	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	for _, name := range names {
		var exists int
		if err := s.queryRow(ctx, `SELECT COUNT(1) FROM schema_migrations WHERE name = ?`, name).Scan(&exists); err != nil {
			return err
		}
		if exists > 0 {
			continue
		}
		body, err := migrationsFS.ReadFile("migrations/" + name)
		if err != nil {
			return err
		}
		if err := s.execScript(ctx, string(body)); err != nil {
			return fmt.Errorf("migration %s: %w", name, err)
		}
		if _, err := s.exec(ctx, `INSERT INTO schema_migrations (name, applied_at) VALUES (?, ?)`, name, time.Now().Unix()); err != nil {
			return err
		}
	}
	return nil
}

// execScript runs a multi-statement SQL script. Postgres accepts the whole
// script in one Exec; the SQLite driver also accepts multiple statements, so we
// run it directly without splitting (which would mishandle quoted semicolons).
func (s *Store) execScript(ctx context.Context, script string) error {
	_, err := s.db.ExecContext(ctx, script)
	return err
}

// nullableUnix converts a *time.Time to a nullable unix-seconds value.
func nullableUnix(t *time.Time) any {
	if t == nil || t.IsZero() {
		return nil
	}
	return t.Unix()
}

// fromUnix converts a nullable int64 unix value back to *time.Time.
func fromUnix(n sql.NullInt64) *time.Time {
	if !n.Valid {
		return nil
	}
	t := time.Unix(n.Int64, 0).UTC()
	return &t
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
