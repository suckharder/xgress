package main

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/suckharder/xgress/internal/config"
	"github.com/suckharder/xgress/internal/store"
)

func TestResolveTokenExplicitWins(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tok")
	// Pre-existing file must be ignored when an explicit value is given.
	if err := os.WriteFile(path, []byte("persisted"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := resolveToken("explicit", path)
	if err != nil {
		t.Fatal(err)
	}
	if got != "explicit" {
		t.Errorf("token = %q, want %q", got, "explicit")
	}
}

func TestResolveTokenReusesPersisted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tok")
	if err := os.WriteFile(path, []byte("  persisted\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := resolveToken("", path)
	if err != nil {
		t.Fatal(err)
	}
	if got != "persisted" {
		t.Errorf("token = %q, want trimmed %q", got, "persisted")
	}
}

func TestResolveTokenGeneratesAndPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tok")
	got, err := resolveToken("", path)
	if err != nil {
		t.Fatal(err)
	}
	if got == "" {
		t.Fatal("generated token is empty")
	}
	// It must have been persisted, with 0600 perms, and be stable across calls.
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("token not persisted: %v", err)
	}
	if string(b) != got {
		t.Errorf("persisted %q != returned %q", b, got)
	}
	if runtime.GOOS != "windows" {
		if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
			t.Errorf("token file mode = %v, want 0600", info.Mode().Perm())
		}
	}
	again, err := resolveToken("", path)
	if err != nil {
		t.Fatal(err)
	}
	if again != got {
		t.Errorf("second resolve = %q, want stable %q", again, got)
	}
}

func TestEnsureProviderAndEdgeTokens(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{DataDir: dir}

	if err := ensureProviderToken(cfg); err != nil {
		t.Fatalf("ensureProviderToken: %v", err)
	}
	if cfg.ProviderToken == "" {
		t.Error("provider token not populated")
	}
	if _, err := os.Stat(cfg.ProviderTokenFile()); err != nil {
		t.Errorf("provider token file missing: %v", err)
	}

	if err := ensureEdgeToken(cfg); err != nil {
		t.Fatalf("ensureEdgeToken: %v", err)
	}
	if cfg.EdgeToken == "" {
		t.Error("edge token not populated")
	}
	if _, err := os.Stat(cfg.EdgeTokenFile()); err != nil {
		t.Errorf("edge token file missing: %v", err)
	}
	if cfg.ProviderToken == cfg.EdgeToken {
		t.Error("provider and edge tokens should be independently generated")
	}
}

func TestSettingTrue(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{DataDir: dir, DBDriver: config.DriverSQLite}
	ctx := context.Background()
	st, err := store.Open(ctx, cfg)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	// Missing key → false.
	if settingTrue(ctx, st, "acme.staging") {
		t.Error("missing setting should be false")
	}
	for _, tc := range []struct {
		val  string
		want bool
	}{
		{"true", true},
		{"1", true},
		{"false", false},
		{"0", false},
		{"", false},
		{"yes", false}, // only "true"/"1" count
	} {
		if err := st.SetSetting(ctx, "acme.staging", tc.val); err != nil {
			t.Fatal(err)
		}
		if got := settingTrue(ctx, st, "acme.staging"); got != tc.want {
			t.Errorf("settingTrue(%q) = %v, want %v", tc.val, got, tc.want)
		}
	}
}
