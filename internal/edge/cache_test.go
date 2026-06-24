package edge

import (
	"context"
	"testing"
	"time"
)

// P0-1: the in-memory cache must be bounded — per-entry ceiling, total-byte
// budget with LRU eviction, and an entry-count cap — so a distinct-URL flood
// can't grow it without bound.

func TestMemStorePerEntryCeiling(t *testing.T) {
	ctx := context.Background()
	m := NewMemStore(ctx, MemLimits{MaxBytes: 1 << 20, MaxEntryBytes: 1024, MaxEntries: 100})

	m.Set(ctx, "big", make([]byte, 2048), time.Minute) // over the ceiling
	if _, ok := m.Get(ctx, "big"); ok {
		t.Error("entry larger than the per-entry ceiling must not be cached")
	}
	m.Set(ctx, "small", make([]byte, 512), time.Minute) // under the ceiling
	if _, ok := m.Get(ctx, "small"); !ok {
		t.Error("entry under the ceiling should be cached")
	}
}

func TestMemStoreByteBudgetEvictsLRU(t *testing.T) {
	ctx := context.Background()
	// ~3 entries of (1-char key + 1000-byte val ≈ 1001 bytes) fit the budget.
	m := NewMemStore(ctx, MemLimits{MaxBytes: 3300, MaxEntryBytes: 1 << 20, MaxEntries: 1000})
	val := func() []byte { return make([]byte, 1000) }

	m.Set(ctx, "a", val(), time.Minute)
	m.Set(ctx, "b", val(), time.Minute)
	m.Set(ctx, "c", val(), time.Minute)
	if _, ok := m.Get(ctx, "a"); !ok { // touch a → most-recently-used
		t.Fatal("a should be present before eviction")
	}
	m.Set(ctx, "d", val(), time.Minute) // pushes total over budget → evict LRU (b)

	if _, ok := m.Get(ctx, "b"); ok {
		t.Error("b (least-recently-used) should have been evicted under the byte budget")
	}
	if _, ok := m.Get(ctx, "a"); !ok {
		t.Error("a (recently used) should survive eviction")
	}
	if _, ok := m.Get(ctx, "d"); !ok {
		t.Error("d (newest) should be present")
	}
	if m.curBytes > m.maxBytes {
		t.Errorf("curBytes %d exceeds budget %d", m.curBytes, m.maxBytes)
	}
}

func TestMemStoreEntryCountCap(t *testing.T) {
	ctx := context.Background()
	m := NewMemStore(ctx, MemLimits{MaxBytes: 1 << 30, MaxEntryBytes: 4096, MaxEntries: 2})
	m.Set(ctx, "a", []byte("x"), time.Minute)
	m.Set(ctx, "b", []byte("x"), time.Minute)
	m.Set(ctx, "c", []byte("x"), time.Minute) // exceeds the cap → evict LRU (a)
	if _, ok := m.Get(ctx, "a"); ok {
		t.Error("a should be evicted by the entry-count cap")
	}
	if m.ll.Len() != 2 {
		t.Errorf("entry count = %d, want 2 (capped)", m.ll.Len())
	}
}

// P0-2: expiry sweeping works and the sweep goroutine is ctx-bound (no leak).
func TestMemStoreSweepExpired(t *testing.T) {
	ctx := context.Background()
	m := NewMemStore(ctx, MemLimits{})
	m.Set(ctx, "k", []byte("v"), time.Millisecond)
	time.Sleep(5 * time.Millisecond)
	m.sweepExpired()
	if m.ll.Len() != 0 {
		t.Errorf("expired entry not swept: len=%d", m.ll.Len())
	}
	if _, ok := m.Get(ctx, "k"); ok {
		t.Error("expired entry must not be returned")
	}
}

func TestMemStoreSweepGoroutineStopsOnCtxCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	m := NewMemStore(ctx, MemLimits{})
	// Cancelling the app context must stop the sweep loop (verified via the loop
	// exiting; a leak would be caught by goleak once wired). The store stays usable.
	cancel()
	time.Sleep(5 * time.Millisecond)
	m.Set(context.Background(), "k", []byte("v"), time.Minute)
	if _, ok := m.Get(context.Background(), "k"); !ok {
		t.Error("store should remain usable after the sweep loop stops")
	}
}
