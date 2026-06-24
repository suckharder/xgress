package engine

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/suckharder/xgress/internal/store"
)

func TestReloadRendersHostAndSnapshots(t *testing.T) {
	e := newTestEngine(t)
	ctx := context.Background()

	// First reload (empty config) already happened implicitly? No — call it.
	if _, err := e.Reload(ctx); err != nil {
		t.Fatalf("initial reload: %v", err)
	}
	v0 := e.Version()

	// Add a proxy host and reload.
	h := &store.Host{
		Kind: store.HostKindProxy, Enabled: true,
		Domains:   []string{"app.example.com"},
		Upstreams: []store.Upstream{{Scheme: "http", Host: "10.0.0.5", Port: 8080}},
		TLS:       store.TLSNone,
	}
	if err := e.st.CreateHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	res, err := e.Reload(ctx)
	if err != nil {
		t.Fatalf("reload after host: %v", err)
	}
	if e.Version() <= v0 {
		t.Errorf("version did not advance: %d <= %d", e.Version(), v0)
	}
	doc := string(res.JSON)
	if !strings.Contains(doc, "app.example.com") {
		t.Errorf("rendered config missing host domain: %s", doc)
	}

	// Snapshot persisted at the new version.
	snap, err := e.st.GetSnapshot(ctx, e.Version())
	if err != nil {
		t.Fatalf("snapshot not stored: %v", err)
	}
	if snap.Hash != res.Hash {
		t.Errorf("snapshot hash %q != render hash %q", snap.Hash, res.Hash)
	}
}

// P1-8: a reload that re-renders a byte-identical config must NOT write a new
// snapshot or bump the served version.
func TestReloadSkipsSnapshotWhenUnchanged(t *testing.T) {
	e := newTestEngine(t)
	ctx := context.Background()

	h := &store.Host{
		Kind: store.HostKindProxy, Enabled: true,
		Domains:   []string{"a.example.com"},
		Upstreams: []store.Upstream{{Scheme: "http", Host: "10.0.0.5", Port: 8080}},
		TLS:       store.TLSNone,
	}
	if err := e.st.CreateHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Reload(ctx); err != nil {
		t.Fatalf("reload: %v", err)
	}
	v1 := e.Version()

	// Reload again with no DB change → no version bump, no new snapshot row.
	if _, err := e.Reload(ctx); err != nil {
		t.Fatalf("second reload: %v", err)
	}
	if e.Version() != v1 {
		t.Errorf("version bumped on an unchanged reload: %d -> %d", v1, e.Version())
	}
	latest, err := e.st.LatestSnapshotVersion(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if latest != v1 {
		t.Errorf("a snapshot was written for an unchanged reload: latest=%d, want %d", latest, v1)
	}
}

// P1-5: RenderedHash() (the cheap pre-decrypt 304 check) must equal the etag that
// ProviderDocument returns for the same served config — otherwise the fast-path
// would 304 (or fail to) inconsistently with the real document.
func TestRenderedHashMatchesProviderEtag(t *testing.T) {
	e := newTestEngine(t)
	if h := e.RenderedHash(); h != "empty" {
		t.Errorf("RenderedHash before first render = %q, want \"empty\"", h)
	}
	ctx := context.Background()
	if _, err := e.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	_, etag, err := e.ProviderDocument(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if h := e.RenderedHash(); h != etag {
		t.Errorf("RenderedHash %q != ProviderDocument etag %q", h, etag)
	}
}

func TestProviderDocumentValidJSON(t *testing.T) {
	e := newTestEngine(t)
	ctx := context.Background()
	if _, err := e.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	doc, etag, err := e.ProviderDocument(ctx)
	if err != nil {
		t.Fatalf("ProviderDocument: %v", err)
	}
	if etag == "" {
		t.Error("empty etag")
	}
	var parsed map[string]any
	if err := json.Unmarshal(doc, &parsed); err != nil {
		t.Fatalf("provider document is not valid JSON: %v", err)
	}
	if _, ok := parsed["http"]; !ok {
		t.Errorf("provider document missing http section: %s", doc)
	}
}

func TestRollbackRestoresPriorVersion(t *testing.T) {
	e := newTestEngine(t)
	ctx := context.Background()
	if _, err := e.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	v1 := e.Version()

	// Add a host, reload → v2 contains it.
	h := &store.Host{Kind: store.HostKindProxy, Enabled: true, Domains: []string{"rollback.example.com"},
		Upstreams: []store.Upstream{{Scheme: "http", Host: "10.0.0.9", Port: 80}}, TLS: store.TLSNone}
	_ = e.st.CreateHost(ctx, h)
	if _, err := e.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	v2 := e.Version()
	if v2 <= v1 {
		t.Fatalf("expected v2 > v1, got %d <= %d", v2, v1)
	}

	// Roll back to v1 → served config no longer contains the host, and a new
	// monotonic version is recorded.
	if err := e.Rollback(ctx, v1); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if e.Version() <= v2 {
		t.Errorf("rollback should record a new version > %d, got %d", v2, e.Version())
	}
	doc, _, _ := e.ProviderDocument(ctx)
	if strings.Contains(string(doc), "rollback.example.com") {
		t.Error("rolled-back config still contains the host added in v2")
	}
}

func TestBanPruneReloadsWhenExpired(t *testing.T) {
	e := newTestEngine(t)
	ctx := context.Background()
	// An already-expired ban present in the DB.
	past := time.Now().Add(-time.Hour)
	if err := e.st.AddBan(ctx, &store.Ban{IP: "9.9.9.9", ExpiresAt: &past}); err != nil {
		t.Fatal(err)
	}
	n, err := e.st.PruneExpiredBans(ctx)
	if err != nil || n != 1 {
		t.Fatalf("PruneExpiredBans = %d, %v; want 1, nil", n, err)
	}
	active, _ := e.st.ListActiveBans(ctx)
	if len(active) != 0 {
		t.Errorf("expired ban still active: %+v", active)
	}
}

func TestManualBanAndRemoveReload(t *testing.T) {
	e := newTestEngine(t)
	ctx := context.Background()

	if err := e.AddManualBan(ctx, "203.0.113.0/24", "abuse", 0); err != nil {
		t.Fatalf("AddManualBan: %v", err)
	}
	doc, _, _ := e.ProviderDocument(ctx)
	if !strings.Contains(string(doc), "203.0.113.0/24") {
		t.Errorf("served config missing manual ban CIDR: %s", doc)
	}

	if err := e.RemoveBan(ctx, "203.0.113.0/24"); err != nil {
		t.Fatalf("RemoveBan: %v", err)
	}
	doc, _, _ = e.ProviderDocument(ctx)
	if strings.Contains(string(doc), "203.0.113.0/24") {
		t.Error("served config still contains the removed ban")
	}
}

func TestPreviewIsPure(t *testing.T) {
	e := newTestEngine(t)
	ctx := context.Background()
	if _, err := e.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	v0 := e.Version()
	lv0, _ := e.st.LatestSnapshotVersion(ctx)

	_ = e.st.CreateHost(ctx, &store.Host{Kind: store.HostKindProxy, Enabled: true,
		Domains: []string{"prev.example.com"}, Upstreams: []store.Upstream{{Scheme: "http", Host: "10.0.0.1", Port: 80}}, TLS: store.TLSNone})

	res, err := e.Preview(ctx)
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}
	if !strings.Contains(string(res.JSON), "prev.example.com") {
		t.Error("preview did not render the new host")
	}
	// Pure: no version bump, no snapshot, no serve swap.
	if e.Version() != v0 {
		t.Errorf("preview bumped version %d -> %d", v0, e.Version())
	}
	if lv, _ := e.st.LatestSnapshotVersion(ctx); lv != lv0 {
		t.Errorf("preview wrote a snapshot: %d -> %d", lv0, lv)
	}
	doc, _, _ := e.ProviderDocument(ctx)
	if strings.Contains(string(doc), "prev.example.com") {
		t.Error("preview swapped the served config")
	}
}
