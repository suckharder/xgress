//go:build integration

package e2e

import (
	"context"
	"database/sql"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // register the "pgx" sql driver for readiness pings

	"github.com/suckharder/xgress/internal/config"
	"github.com/suckharder/xgress/internal/store"
)

// postgresImage is the digest-pinned Postgres used by the HA tier (matches the
// project's image-pinning hygiene). Resolved from postgres:16-alpine.
const postgresImage = "postgres@sha256:e013e867e712fec275706a6c51c966f0bb0c93cfa8f51000f85a15f9865a28cb"

// startPostgres runs an ephemeral Postgres 16 on a random host port and returns a
// ready-to-use DSN. It skips the test if Docker is unavailable and removes the
// container on cleanup. This is the first Postgres-backed test infra in the repo;
// the helper is reusable for any future store-on-Postgres coverage.
func startPostgres(t *testing.T) string {
	t.Helper()
	requireDocker(t)
	out, err := exec.Command("docker", "run", "-d", "--rm",
		"-p", "5432",
		"-e", "POSTGRES_USER=xgress",
		"-e", "POSTGRES_PASSWORD=xgress",
		"-e", "POSTGRES_DB=xgress",
		postgresImage).CombinedOutput()
	if err != nil {
		t.Fatalf("docker run postgres: %v\n%s", err, out)
	}
	id := strings.TrimSpace(string(out))
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", id).Run() })

	dsn := fmt.Sprintf("postgres://xgress:xgress@127.0.0.1:%d/xgress?sslmode=disable", dockerHostPort(t, id, 5432))
	waitPostgres(t, dsn, 40*time.Second)
	return dsn
}

// waitPostgres blocks until the server accepts connections (it takes a moment to
// initialize the data directory on first boot).
func waitPostgres(t *testing.T, dsn string, timeout time.Duration) {
	t.Helper()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("sql.Open pgx: %v", err)
	}
	defer db.Close()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		err = db.PingContext(ctx)
		cancel()
		if err == nil {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("postgres not ready within %s: %v", timeout, err)
}

// openPGStore opens a xgress store against the shared Postgres DSN (runs migrations).
// Each call is an independent connection pool, modeling a separate xgress instance.
func openPGStore(t *testing.T, dsn string) *store.Store {
	t.Helper()
	cfg := &config.Config{DataDir: t.TempDir(), DBDriver: config.DriverPostgres, DBDSN: dsn}
	st, err := store.Open(context.Background(), cfg)
	if err != nil {
		t.Fatalf("open postgres store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}
