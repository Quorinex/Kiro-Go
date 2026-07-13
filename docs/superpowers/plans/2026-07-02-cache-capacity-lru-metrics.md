# Cache Capacity, O(1) LRU, and Metrics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop prefix-churn under load (bump the prompt-cache LRU from 4096 → 131072, configurable), replace O(n log n) sort-under-lock eviction with O(1) `container/list`-based LRU, and add hit/miss/eviction/expiration counters exposed via `/v1/stats`.

**Architecture:** The prompt-cache tracker (`proxy/cache_tracker.go`) is an *accounting-only* fingerprint store. Its entries map is converted from value-typed to pointer-typed and paired with a doubly-linked list (`container/list`) that records recency; eviction pops the list back in O(1). Capacity becomes configurable via `config.PromptCacheMaxEntries` (default 131072, clamp ≥ 256). Four atomic counters are added to the tracker and surfaced through a new `Stats()` method folded into the existing `/v1/stats` response.

**Tech Stack:** Go 1.x, standard library (`container/list`, `sync`, `sync/atomic`), package `proxy` (tracker + handler), package `config`.

## Global Constraints

- **Module:** `kiro-go`. Tracker + handler live in package `proxy`; config in package `config`.
- **TDD:** every task is RED → GREEN (write the failing test first, run it, implement, run it green, commit).
- **Disk format:** version 1 unchanged — `flush`/`Load` serialize the same `promptCacheEntryOnDisk{Fingerprint,ExpiresAt,TTLSeconds}`. The list is NOT persisted.
- **Invariants preserved (do not regress):**
  - Global cross-account sharing — the `accountID` parameter on `Compute`/`Update` stays ignored (comment `entries is the global map now (C1: cross-account sharing)` stays).
  - `Update` runs only on the request-success path (`handler.go:1270`).
  - `dirty`-on-hit + idempotent `Stop` (commit `c35e792`).
  - `clampCacheBreakdownToCreation` + `splitAgainstTotal` (commits `c01dfb9`, `501443b`) unchanged.
  - Single mutex; ALL list/map mutation under `t.mu`.
- **Capacity:** default 131072, configurable floor 256, min-cacheable threshold 1024 (4096 opus) unchanged.
- **Commits:** frequent, conventional-commit messages, one per task.

## Spec deviation (note for the implementer)

The spec (`docs/superpowers/specs/2026-07-02-cache-capacity-lru-metrics-design.md`) describes a single constructor `newPromptCacheTracker(maxTTL, maxEntries)`. The plan refines this to **two constructors** to avoid churning ~15 call sites: keep `newPromptCacheTracker(maxTTL)` delegating to `config.GetPromptCacheMaxEntries()`, and add `newPromptCacheTrackerWithCapacity(maxTTL, maxEntries)` for tests. Behavior is identical; only the call-site footprint differs.

## File Structure

- `config/config.go` — add `PromptCacheMaxEntries` field + `GetPromptCacheMaxEntries`/`UpdatePromptCacheMaxEntries` + `defaultPromptCacheMaxEntries` const (Task 1).
- `proxy/cache_tracker.go` — pointer entries + `container/list` LRU + `putLocked`/`evictOverflowLocked` + two constructors + drop `LastHit`/`maxPromptCacheEntries`/`evictLRULocked` (Task 2); atomic counters + `PromptCacheStats`/`Stats()` (Task 4).
- `proxy/cache_tracker_test.go` — config test, churn regression tests, metrics test, rewrites of the 3 direct-insert tests.
- `proxy/cache_tracker_hardening_test.go` — rewrite the LRU eviction test + the dirty-on-hit test.
- `proxy/handler.go` — wire `cache` into `/v1/stats` (Task 5).
- `proxy/handler_test.go` — handler-level stats test (Task 5).

---

### Task 1: Config — `PromptCacheMaxEntries` (field + getter + setter + default)

**Files:**
- Modify: `config/config.go` (field after `:226`; const + getter + setter after `:949`)
- Test: `proxy/cache_tracker_test.go` (append a black-box config test, same pattern as `TestPromptCacheCapConfigurable`)

**Interfaces:**
- Produces: `config.GetPromptCacheMaxEntries() int` (default 131072, ≤0 → default), `config.UpdatePromptCacheMaxEntries(n int) error`, `config.defaultPromptCacheMaxEntries` const. Consumed by Task 2's delegating constructor.

- [ ] **Step 1: Write the failing test**

Append to `proxy/cache_tracker_test.go`:

```go
// TestPromptCacheMaxEntriesConfigurable verifies the cache LRU bound is
// configurable via config and defaults to 131072.
func TestPromptCacheMaxEntriesConfigurable(t *testing.T) {
	cfgFile := t.TempDir() + "/config.json"
	if err := config.Init(cfgFile); err != nil {
		t.Fatalf("config.Init: %v", err)
	}

	if got := config.GetPromptCacheMaxEntries(); got != 131072 {
		t.Fatalf("default cap: expected 131072, got %d", got)
	}

	if err := config.UpdatePromptCacheMaxEntries(50000); err != nil {
		t.Fatalf("update: %v", err)
	}
	if got := config.GetPromptCacheMaxEntries(); got != 50000 {
		t.Fatalf("after update: expected 50000, got %d", got)
	}

	// ≤ 0 falls back to the default.
	if err := config.UpdatePromptCacheMaxEntries(0); err != nil {
		t.Fatalf("reset: %v", err)
	}
	if got := config.GetPromptCacheMaxEntries(); got != 131072 {
		t.Fatalf("zero should fall back to default 131072, got %d", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./proxy/ -run TestPromptCacheMaxEntriesConfigurable -v`
Expected: FAIL — `config.GetPromptCacheMaxEntries undefined`.

- [ ] **Step 3: Add the config field**

In `config/config.go`, immediately after the `PromptCacheMaxRatio` field (currently `:226`), add:

```go
	// PromptCacheMaxEntries bounds the in-memory prompt-cache map; once exceeded,
	// the least-recently-used entries are evicted (LRU). Default 131072. Sized so
	// the prefix write-rate × TTL does not evict multi-turn history prefixes
	// before the next turn reuses them (mirrors kiro-rs's 131072 default). The
	// tracker clamps explicit small values up to 256.
	PromptCacheMaxEntries int `json:"promptCacheMaxEntries,omitempty"`
```

- [ ] **Step 4: Add the const + getter + setter**

In `config/config.go`, immediately after `UpdatePromptCacheMaxRatio` (currently ends at `:949`), add:

```go
const defaultPromptCacheMaxEntries = 131072

// GetPromptCacheMaxEntries returns the prompt-cache LRU bound. Defaults to
// 131072 when unset (≤ 0). Explicit small values are clamped up to 256 by the
// tracker constructor.
func GetPromptCacheMaxEntries() int {
	cfgLock.RLock()
	defer cfgLock.RUnlock()
	if cfg == nil || cfg.PromptCacheMaxEntries <= 0 {
		return defaultPromptCacheMaxEntries
	}
	return cfg.PromptCacheMaxEntries
}

// UpdatePromptCacheMaxEntries sets the prompt-cache LRU bound and persists it.
// Applies on the next tracker construction (restart); it does not resize a
// live tracker.
func UpdatePromptCacheMaxEntries(n int) error {
	cfgLock.Lock()
	defer cfgLock.Unlock()
	cfg.PromptCacheMaxEntries = n
	return Save()
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./proxy/ -run TestPromptCacheMaxEntriesConfigurable -v`
Expected: PASS.

- [ ] **Step 6: Build the whole module to confirm no breakage**

Run: `go build ./...`
Expected: succeeds.

- [ ] **Step 7: Commit**

```bash
git add config/config.go proxy/cache_tracker_test.go
git commit -m "feat(config): add PromptCacheMaxEntries (default 131072)"
```

---

### Task 2: O(1) LRU via `container/list` + capacity field + two constructors

This is the structural change. It converts `entries` to pointer-typed, adds a recency list, drops `LastHit` (list position is authoritative), replaces `evictLRULocked` (sort) with `evictOverflowLocked` (O(1) pop-back), adds `putLocked`, and adds `maxEntries` + the two constructors. Five existing tests are rewritten to compile against the new shape.

**Files:**
- Modify: `proxy/cache_tracker.go` (imports, consts, entry type, struct, constructors, `Load`, `Compute`, `Update`, `pruneExpiredLocked`, replace `evictLRULocked`)
- Modify: `proxy/cache_tracker_hardening_test.go` (rewrite `TestPromptCacheEvictsLRUWhenOverCapacity`, rewrite `TestComputeSetsDirtyOnCacheHit`)
- Modify: `proxy/cache_tracker_test.go` (rewrite the 3 direct-insert sites in `TestPromptCacheDiskPersistence` and `TestComputeBreakdownClampedToCreation`)
- Test: `proxy/cache_tracker_hardening_test.go` (new `TestPromptCacheLRUEvictsOldestUnused` + `TestPromptCacheTrackerClampsSmallCapacity`)

**Interfaces:**
- Consumes: `config.GetPromptCacheMaxEntries()` (Task 1).
- Produces: `newPromptCacheTrackerWithCapacity(maxTTL, maxEntries)`, `(*promptCacheTracker).putLocked(fp, expiresAt, ttl)`, `(*promptCacheTracker).evictOverflowLocked()`, `promptCacheTracker.maxEntries`, pointer-typed `promptCacheEntry` (with `lruElem *list.Element`). Consumed by Tasks 3–5.

- [ ] **Step 1: Write the failing tests**

Replace the entire `TestPromptCacheEvictsLRUWhenOverCapacity` function (currently `proxy/cache_tracker_hardening_test.go:8-45`) with:

```go
// TestPromptCacheLRUEvictsOldestUnused verifies the list-based LRU: with cap 3,
// after inserting a,b,c, touching a, then inserting d, the evicted entry is b
// (the least-recently-used), not a.
func TestPromptCacheLRUEvictsOldestUnused(t *testing.T) {
	tr := newPromptCacheTrackerWithCapacity(time.Hour, 3)
	now := time.Now()

	tr.mu.Lock()
	tr.putLocked([32]byte{1}, now.Add(time.Hour), time.Hour) // a
	tr.putLocked([32]byte{2}, now.Add(time.Hour), time.Hour) // b
	tr.putLocked([32]byte{3}, now.Add(time.Hour), time.Hour) // c
	tr.putLocked([32]byte{1}, now.Add(time.Hour), time.Hour) // touch a → front
	tr.putLocked([32]byte{4}, now.Add(time.Hour), time.Hour) // d
	tr.evictOverflowLocked()                                 // cap 3 → evict back (b)
	tr.mu.Unlock()

	if _, ok := tr.entries[[32]byte{2}]; ok {
		t.Fatalf("expected least-recently-used entry (b) to be evicted")
	}
	for _, want := range [][32]byte{{1}, {3}, {4}} {
		if _, ok := tr.entries[want]; !ok {
			t.Fatalf("expected entry %v to survive", want)
		}
	}
	if got := len(tr.entries); got != 3 {
		t.Fatalf("expected cap=3 after eviction, got %d", got)
	}
}

// TestPromptCacheTrackerClampsSmallCapacity verifies maxEntries < 256 is clamped
// up to 256 so a misconfigured (or tiny test) value cannot make the cache useless.
func TestPromptCacheTrackerClampsSmallCapacity(t *testing.T) {
	tr := newPromptCacheTrackerWithCapacity(time.Hour, 1)
	if tr.maxEntries != 256 {
		t.Fatalf("expected capacity clamped to 256, got %d", tr.maxEntries)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./proxy/ -run 'TestPromptCacheLRUEvictsOldestUnused|TestPromptCacheTrackerClampsSmallCapacity' -v`
Expected: FAIL — does not compile (`newPromptCacheTrackerWithCapacity undefined`, `tr.putLocked undefined`, `tr.evictOverflowLocked undefined`, `tr.maxEntries undefined`).

- [ ] **Step 3: Update the import block**

In `proxy/cache_tracker.go`, add `container/list`:

```go
import (
	"bytes"
	"container/list"
	"crypto/sha256"
	"encoding/json"
	"kiro-go/config"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)
```

- [ ] **Step 4: Drop the `maxPromptCacheEntries` const**

In `proxy/cache_tracker.go`, delete these three lines (currently `:25-27`):

```go
// maxPromptCacheEntries bounds the in-memory cache map; once exceeded, the
// least-recently-hit entries are evicted (LRU), mirroring kiro-rs's cap.
const maxPromptCacheEntries = 4096
```

- [ ] **Step 5: Replace the entry type and tracker struct**

Replace the current `promptCacheEntry` struct (currently `:56-60`) and `promptCacheTracker` struct (currently `:62-69`) with:

```go
type promptCacheEntry struct {
	ExpiresAt time.Time
	TTL       time.Duration
	lruElem   *list.Element // back-ref into t.order; Value = fingerprint [32]byte
}

// minPromptCacheEntries is the floor for maxEntries; an explicit smaller value
// (or a test value) is clamped up so the cache is never useless.
const minPromptCacheEntries = 256

type promptCacheTracker struct {
	mu              sync.Mutex
	entries         map[[32]byte]*promptCacheEntry
	order           *list.List // front = most-recently-used; Element.Value = [32]byte fingerprint
	maxEntries      int
	maxSupportedTTL time.Duration
	dirty           bool
	stopChan        chan struct{}
	stopOnce        sync.Once
}
```

- [ ] **Step 6: Replace the constructor**

Replace the current `newPromptCacheTracker` (currently `:71-79`) with the two-constructor form:

```go
func newPromptCacheTracker(maxTTL time.Duration) *promptCacheTracker {
	return newPromptCacheTrackerWithCapacity(maxTTL, config.GetPromptCacheMaxEntries())
}

func newPromptCacheTrackerWithCapacity(maxTTL time.Duration, maxEntries int) *promptCacheTracker {
	if maxTTL <= 0 {
		maxTTL = defaultPromptCacheTTL
	}
	if maxEntries < minPromptCacheEntries {
		maxEntries = minPromptCacheEntries
	}
	return &promptCacheTracker{
		entries:         make(map[[32]byte]*promptCacheEntry),
		order:           list.New(),
		maxEntries:      maxEntries,
		maxSupportedTTL: maxTTL,
	}
}
```

- [ ] **Step 7: Update `Load` to use `putLocked`**

In `proxy/cache_tracker.go`, replace the body of `Load`'s locked loop (currently `:106-116`):

```go
	for _, e := range disk.Entries {
		exp := time.Unix(e.ExpiresAt, 0)
		if !exp.After(now) {
			continue // already expired
		}
		t.putLocked(e.Fingerprint, exp, time.Duration(e.TTLSeconds)*time.Second)
	}
```

- [ ] **Step 8: Update `Compute` hit path**

In `Compute` (currently `:279-291`), replace the matched-entry block — remove the `LastHit` write and re-insert, add `MoveToFront`:

```go
		entry, ok := t.entries[breakpoint.Fingerprint]
		if !ok || entry.ExpiresAt.Before(now) {
			continue
		}
		entry.ExpiresAt = now.Add(entry.TTL)
		t.order.MoveToFront(entry.lruElem)
		t.dirty = true // hit extends TTL — persist so a flush before the next Update doesn't lose it
		matchedTokens = minInt(breakpoint.CumulativeTokens, profile.TotalInputTokens)
		if matchedTokens > lastTokens {
			matchedTokens = lastTokens
		}
		break
```

- [ ] **Step 9: Update `Update` to use `putLocked` + `evictOverflowLocked`**

In `Update` (currently `:317-329`), replace the storage loop and eviction:

```go
	// entries is the global map now (C1: cross-account sharing).
	for _, breakpoint := range profile.Breakpoints {
		// Skip breakpoints below the minimum cacheable token threshold.
		if breakpoint.CumulativeTokens < minTokens {
			continue
		}
		t.putLocked(breakpoint.Fingerprint, now.Add(breakpoint.TTL), breakpoint.TTL)
	}
	t.dirty = true
	t.evictOverflowLocked()
```

- [ ] **Step 10: Update `pruneExpiredLocked` to keep the list consistent**

Replace `pruneExpiredLocked` (currently `:332-338`):

```go
func (t *promptCacheTracker) pruneExpiredLocked(now time.Time) {
	for fingerprint, entry := range t.entries {
		if !entry.ExpiresAt.After(now) {
			t.order.Remove(entry.lruElem)
			delete(t.entries, fingerprint)
		}
	}
}
```

- [ ] **Step 11: Replace `evictLRULocked` with `putLocked` + `evictOverflowLocked`**

Delete the entire `evictLRULocked` function (currently `:340-361`) and its doc comment, and add in its place:

```go
// putLocked inserts a fingerprint or refreshes its existing entry, marking it
// most-recently-used. Caller holds t.mu.
func (t *promptCacheTracker) putLocked(fp [32]byte, expiresAt time.Time, ttl time.Duration) {
	if e, ok := t.entries[fp]; ok {
		e.ExpiresAt = expiresAt
		e.TTL = ttl
		t.order.MoveToFront(e.lruElem)
		return
	}
	elem := t.order.PushFront(fp)
	t.entries[fp] = &promptCacheEntry{ExpiresAt: expiresAt, TTL: ttl, lruElem: elem}
}

// evictOverflowLocked bounds the entries map to maxEntries by evicting the
// least-recently-used entries (the back of the order list). O(1) per eviction.
// Caller holds t.mu.
func (t *promptCacheTracker) evictOverflowLocked() {
	for len(t.entries) > t.maxEntries {
		back := t.order.Back()
		if back == nil {
			return
		}
		fp := back.Value.([32]byte)
		t.order.Remove(back)
		delete(t.entries, fp)
	}
}
```

- [ ] **Step 12: Rewrite the dirty-on-hit test**

In `proxy/cache_tracker_hardening_test.go`, replace the direct-insert line in `TestComputeSetsDirtyOnCacheHit` (currently `:109`):

```go
	tr.entries[[32]byte{1}] = promptCacheEntry{ExpiresAt: now.Add(time.Hour), TTL: time.Hour, LastHit: now}
```

with:

```go
	tr.mu.Lock()
	tr.putLocked([32]byte{1}, now.Add(time.Hour), time.Hour)
	tr.mu.Unlock()
```

- [ ] **Step 13: Rewrite the breakdown-clamp test's direct insert**

In `proxy/cache_tracker_test.go`, replace the direct-insert line in `TestComputeBreakdownClampedToCreation` (currently `:420`):

```go
	tr.entries[[32]byte{1}] = promptCacheEntry{ExpiresAt: now.Add(time.Hour), TTL: time.Hour, LastHit: now}
```

with:

```go
	tr.mu.Lock()
	tr.putLocked([32]byte{1}, now.Add(time.Hour), time.Hour)
	tr.mu.Unlock()
```

- [ ] **Step 14: Rewrite the two disk-persistence direct inserts**

In `proxy/cache_tracker_test.go`, `TestPromptCacheDiskPersistence`:

Replace the t1 insert block (currently `:361-367`):

```go
	t1.mu.Lock()
	t1.entries[fp] = promptCacheEntry{
		ExpiresAt: time.Now().Add(3 * time.Minute),
		TTL:       5 * time.Minute,
	}
	t1.dirty = true
	t1.mu.Unlock()
```

with:

```go
	t1.mu.Lock()
	t1.putLocked(fp, time.Now().Add(3*time.Minute), 5*time.Minute)
	t1.dirty = true
	t1.mu.Unlock()
```

Replace the t1b insert block (currently `:383-390`):

```go
	t1b.mu.Lock()
	fpExpired := sha256.Sum256([]byte("expired"))
	t1b.entries[fpExpired] = promptCacheEntry{
		ExpiresAt: time.Now().Add(-1 * time.Minute), // already expired
		TTL:       5 * time.Minute,
	}
	t1b.dirty = true
	t1b.mu.Unlock()
```

with:

```go
	t1b.mu.Lock()
	fpExpired := sha256.Sum256([]byte("expired"))
	t1b.putLocked(fpExpired, time.Now().Add(-1*time.Minute), 5*time.Minute) // already expired
	t1b.dirty = true
	t1b.mu.Unlock()
```

- [ ] **Step 15: Run the two new tests to verify they pass**

Run: `go test ./proxy/ -run 'TestPromptCacheLRUEvictsOldestUnused|TestPromptCacheTrackerClampsSmallCapacity' -v`
Expected: PASS.

- [ ] **Step 16: Run the full proxy package test suite**

Run: `go test ./proxy/ -v`
Expected: PASS — all existing tests (cross-account sharing, billing-header drift, breakdown clamp, dirty-on-hit, idempotent Stop, implicit breakpoint, disk persistence, configurable cap) still green.

- [ ] **Step 17: Commit**

```bash
git add proxy/cache_tracker.go proxy/cache_tracker_test.go proxy/cache_tracker_hardening_test.go
git commit -m "refactor(cache): O(1) LRU via container/list + 131072 default capacity"
```

---

### Task 3: Churn regression tests

Locks in the capacity fix. Two characterization tests: at cap 131072 a 5000-prefix workload does NOT churn (the oldest prefix survives → `cache_read > 0`); at cap 4096 the same workload DOES churn (the oldest, never-re-touched prefix is evicted → `cache_read == 0`). These pass immediately after Task 2 and guard against a future capacity regression; the cap value (131072) is separately guarded by `TestPromptCacheMaxEntriesConfigurable`.

**Files:**
- Test: `proxy/cache_tracker_test.go` (append two tests)

**Interfaces:**
- Consumes: `newPromptCacheTrackerWithCapacity`, `putLocked`, `evictOverflowLocked` (Task 2).

- [ ] **Step 1: Write the tests**

Append to `proxy/cache_tracker_test.go`:

```go
// TestCacheDoesNotChurnAtHighCapacity is the regression guard for the prefix
// churn bug: at the production default capacity (131072), a 5000-prefix
// workload (far above the old 4096 cap) does not evict the oldest seeded prefix
// before it is replayed, so the replay reads from cache.
func TestCacheDoesNotChurnAtHighCapacity(t *testing.T) {
	tr := newPromptCacheTrackerWithCapacity(time.Hour, 131072)
	now := time.Now()
	tr.mu.Lock()
	for i := 0; i < 5000; i++ {
		var fp [32]byte
		fp[0] = byte(i)
		fp[1] = byte(i >> 8)
		fp[2] = byte(i >> 16)
		tr.putLocked(fp, now.Add(time.Hour), time.Hour)
	}
	tr.evictOverflowLocked()
	tr.mu.Unlock()

	// The oldest seeded prefix (i=0, all-zero bytes) must survive at cap 131072.
	var fp0 [32]byte
	profile := &promptCacheProfile{
		Model:            "claude-sonnet-4-6",
		TotalInputTokens: 2000,
		Breakpoints:      []promptCacheBreakpoint{{Fingerprint: fp0, CumulativeTokens: 2000, TTL: time.Hour}},
	}
	if usage := tr.Compute("acct", profile); usage.CacheReadInputTokens == 0 {
		t.Fatalf("expected old prefix to survive at cap=131072 (no churn); got cache_read=0")
	}
}

// TestCacheChurnsAtLowCapacity proves the churn mechanism: at the old cap 4096
// the same 5000-prefix workload evicts the oldest prefix (i=0), so its replay
// misses. This is the sensitivity companion to TestCacheDoesNotChurnAtHighCapacity.
func TestCacheChurnsAtLowCapacity(t *testing.T) {
	tr := newPromptCacheTrackerWithCapacity(time.Hour, 4096)
	now := time.Now()
	tr.mu.Lock()
	for i := 0; i < 5000; i++ {
		var fp [32]byte
		fp[0] = byte(i)
		fp[1] = byte(i >> 8)
		fp[2] = byte(i >> 16)
		tr.putLocked(fp, now.Add(time.Hour), time.Hour)
	}
	tr.evictOverflowLocked()
	tr.mu.Unlock()

	// 5000 > 4096 → LRU evicts the 904 oldest; i=0 (oldest, never re-touched) is gone.
	var fp0 [32]byte
	profile := &promptCacheProfile{
		Model:            "claude-sonnet-4-6",
		TotalInputTokens: 2000,
		Breakpoints:      []promptCacheBreakpoint{{Fingerprint: fp0, CumulativeTokens: 2000, TTL: time.Hour}},
	}
	if usage := tr.Compute("acct", profile); usage.CacheReadInputTokens != 0 {
		t.Fatalf("expected oldest prefix churned at cap=4096; got cache_read=%d", usage.CacheReadInputTokens)
	}
}
```

- [ ] **Step 2: Run the tests**

Run: `go test ./proxy/ -run 'TestCacheDoesNotChurnAtHighCapacity|TestCacheChurnsAtLowCapacity' -v`
Expected: PASS (characterization tests — the fix from Task 2 is already in).

- [ ] **Step 3: Commit**

```bash
git add proxy/cache_tracker_test.go
git commit -m "test(cache): regression guard for prefix churn at low capacity"
```

---

### Task 4: Metrics — atomic counters + `Stats()`

Adds four atomic counters (`hits`, `misses`, `evictions`, `expirations`) to the tracker, instruments `Compute`/`evictOverflowLocked`/`pruneExpiredLocked`, and exposes them via a new `Stats()` method returning a JSON-tagged `PromptCacheStats`.

**Files:**
- Modify: `proxy/cache_tracker.go` (imports, struct fields, `Compute` signature + defer, `evictOverflowLocked`, `pruneExpiredLocked`, new `PromptCacheStats` type + `Stats()`)
- Test: `proxy/cache_tracker_test.go` (append `TestCacheStats`)

**Interfaces:**
- Consumes: the Task 2 tracker shape.
- Produces: `(*promptCacheTracker).Stats() PromptCacheStats`. Consumed by Task 5.

- [ ] **Step 1: Write the failing test**

Append to `proxy/cache_tracker_test.go`:

```go
// TestCacheStats verifies the atomic counters and Stats() snapshot: one miss,
// one hit, one expiration, and one LRU eviction are all counted, and capacity
// reflects the configured bound.
func TestCacheStats(t *testing.T) {
	tr := newPromptCacheTrackerWithCapacity(time.Hour, 3)
	hit := &promptCacheProfile{
		Model:            "claude-sonnet-4-6",
		TotalInputTokens: 2000,
		Breakpoints:      []promptCacheBreakpoint{{Fingerprint: [32]byte{7}, CumulativeTokens: 2000, TTL: time.Hour}},
	}
	now := time.Now()

	// Seed an already-expired entry, then Compute: pruneExpiredLocked drops it
	// (expirations=1) and the empty cache yields a miss (misses=1).
	tr.mu.Lock()
	tr.putLocked([32]byte{99}, now.Add(-time.Minute), time.Hour)
	tr.mu.Unlock()
	tr.Compute("acct", hit)

	// Store the hit profile, then Compute → hit (hits=1).
	tr.Update("acct", hit)
	tr.Compute("acct", hit)

	// Overflow: entries were {99-evicted, 7}; add 3 more → {7,1,2,3} len=4 →
	// evictOverflowLocked pops the LRU back (7), leaving 3 (evictions=1).
	tr.mu.Lock()
	for i := 1; i <= 3; i++ {
		tr.putLocked([32]byte{byte(i)}, now.Add(time.Hour), time.Hour)
	}
	tr.evictOverflowLocked()
	tr.mu.Unlock()

	stats := tr.Stats()
	if stats.Hits != 1 {
		t.Errorf("hits = %d, want 1", stats.Hits)
	}
	if stats.Misses != 1 {
		t.Errorf("misses = %d, want 1", stats.Misses)
	}
	if stats.Evictions != 1 {
		t.Errorf("evictions = %d, want 1", stats.Evictions)
	}
	if stats.Expirations != 1 {
		t.Errorf("expirations = %d, want 1", stats.Expirations)
	}
	if stats.Capacity != 3 {
		t.Errorf("capacity = %d, want 3", stats.Capacity)
	}
	if stats.Entries != 3 {
		t.Errorf("entries = %d, want 3", stats.Entries)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./proxy/ -run TestCacheStats -v`
Expected: FAIL — `tr.Stats undefined`.

- [ ] **Step 3: Add `sync/atomic` import**

In `proxy/cache_tracker.go`, add `"sync/atomic"` to the import block:

```go
import (
	"bytes"
	"container/list"
	"crypto/sha256"
	"encoding/json"
	"kiro-go/config"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)
```

- [ ] **Step 4: Add the counter fields to the struct**

Replace the `promptCacheTracker` struct (the version from Task 2 Step 5) with:

```go
type promptCacheTracker struct {
	mu              sync.Mutex
	entries         map[[32]byte]*promptCacheEntry
	order           *list.List // front = most-recently-used; Element.Value = [32]byte fingerprint
	maxEntries      int
	maxSupportedTTL time.Duration
	hits            int64 // atomic — Compute calls returning CacheReadInputTokens > 0
	misses          int64 // atomic — Compute calls returning CacheReadInputTokens == 0
	evictions       int64 // atomic — LRU pop-backs in evictOverflowLocked
	expirations     int64 // atomic — TTL removals in pruneExpiredLocked
	dirty           bool
	stopChan        chan struct{}
	stopOnce        sync.Once
}
```

- [ ] **Step 5: Instrument `Compute` (named return + defer)**

Change the `Compute` signature to a named return and add a counting defer immediately after the guard. The function header becomes:

```go
func (t *promptCacheTracker) Compute(accountID string, profile *promptCacheProfile) (u promptCacheUsage) {
	if t == nil || profile == nil || len(profile.Breakpoints) == 0 || accountID == "" {
		return promptCacheUsage{}
	}
	defer func() {
		if u.CacheReadInputTokens > 0 {
			atomic.AddInt64(&t.hits, 1)
		} else {
			atomic.AddInt64(&t.misses, 1)
		}
	}()
```

Leave the rest of `Compute` unchanged — both later `return promptCacheUsage{...}` statements assign to the named return `u`, which the defer reads. The guard return (before the defer) is not counted.

- [ ] **Step 6: Instrument `evictOverflowLocked`**

In `evictOverflowLocked` (from Task 2 Step 11), add the eviction counter inside the loop:

```go
func (t *promptCacheTracker) evictOverflowLocked() {
	for len(t.entries) > t.maxEntries {
		back := t.order.Back()
		if back == nil {
			return
		}
		fp := back.Value.([32]byte)
		t.order.Remove(back)
		delete(t.entries, fp)
		atomic.AddInt64(&t.evictions, 1)
	}
}
```

- [ ] **Step 7: Instrument `pruneExpiredLocked`**

In `pruneExpiredLocked` (from Task 2 Step 10), add the expiration counter per delete:

```go
func (t *promptCacheTracker) pruneExpiredLocked(now time.Time) {
	for fingerprint, entry := range t.entries {
		if !entry.ExpiresAt.After(now) {
			t.order.Remove(entry.lruElem)
			delete(t.entries, fingerprint)
			atomic.AddInt64(&t.expirations, 1)
		}
	}
}
```

- [ ] **Step 8: Add `PromptCacheStats` + `Stats()`**

Add immediately after `evictOverflowLocked`:

```go
// PromptCacheStats is a point-in-time snapshot of cache counters, surfaced via
// /v1/stats. All counters are cumulative since tracker construction.
type PromptCacheStats struct {
	Entries     int   `json:"entries"`
	Capacity    int   `json:"capacity"`
	Hits        int64 `json:"hits"`
	Misses      int64 `json:"misses"`
	Evictions   int64 `json:"evictions"`
	Expirations int64 `json:"expirations"`
}

func (t *promptCacheTracker) Stats() PromptCacheStats {
	if t == nil {
		return PromptCacheStats{}
	}
	t.mu.Lock()
	entries := len(t.entries)
	capacity := t.maxEntries
	t.mu.Unlock()
	return PromptCacheStats{
		Entries:     entries,
		Capacity:    capacity,
		Hits:        atomic.LoadInt64(&t.hits),
		Misses:      atomic.LoadInt64(&t.misses),
		Evictions:   atomic.LoadInt64(&t.evictions),
		Expirations: atomic.LoadInt64(&t.expirations),
	}
}
```

- [ ] **Step 9: Run the test to verify it passes**

Run: `go test ./proxy/ -run TestCacheStats -v`
Expected: PASS.

- [ ] **Step 10: Run the full proxy package test suite**

Run: `go test ./proxy/ -v`
Expected: PASS.

- [ ] **Step 11: Commit**

```bash
git add proxy/cache_tracker.go proxy/cache_tracker_test.go
git commit -m "feat(cache): hit/miss/eviction metrics + Stats()"
```

---

### Task 5: Expose cache stats in `/v1/stats`

Folds `h.promptCache.Stats()` into the existing `/v1/stats` JSON response (reuses `validateApiKey` auth at the route dispatch; zero new routes).

**Files:**
- Modify: `proxy/handler.go` (the stats response map in `handleStats`, currently `:453-464`)
- Test: `proxy/handler_test.go` (append `TestStatsIncludesCacheMetrics`)

**Interfaces:**
- Consumes: `(*promptCacheTracker).Stats()` (Task 4).

- [ ] **Step 1: Write the failing test**

Append to `proxy/handler_test.go`:

```go
// TestStatsIncludesCacheMetrics verifies /v1/stats surfaces a "cache" object
// populated from the prompt-cache tracker's counters.
func TestStatsIncludesCacheMetrics(t *testing.T) {
	cfgFile := t.TempDir() + "/config.json"
	if err := config.Init(cfgFile); err != nil {
		t.Fatalf("config.Init: %v", err)
	}
	p := accountpool.GetPool()
	p.Reload()

	tr := newPromptCacheTracker(defaultPromptCacheTTL)
	profile := &promptCacheProfile{
		Model:            "claude-sonnet-4-6",
		TotalInputTokens: 2000,
		Breakpoints:      []promptCacheBreakpoint{{Fingerprint: [32]byte{9}, CumulativeTokens: 2000, TTL: time.Hour}},
	}
	tr.Compute("acct", profile) // miss
	tr.Update("acct", profile)
	tr.Compute("acct", profile) // hit

	h := &Handler{
		pool:        p,
		promptCache: tr,
		startTime:   time.Now().Unix(),
	}

	rec := httptest.NewRecorder()
	h.handleStats(rec, httptest.NewRequest(http.MethodGet, "/v1/stats", nil))

	var got map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode stats: %v", err)
	}
	cache, ok := got["cache"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected a cache object in stats, got %#v", got)
	}
	if cache["hits"].(float64) != 1 {
		t.Fatalf("expected 1 hit, got %v", cache["hits"])
	}
	if cache["misses"].(float64) != 1 {
		t.Fatalf("expected 1 miss, got %v", cache["misses"])
	}
}
```

> Note: `handleStats` also reads `h.pool.Count()`, `h.pool.AvailableCount()`, `h.getCredits()`, and `h.startTime`. The literal above provides a real pool + startTime; `totalTokens`/`totalRequests` default to 0. If `getCredits()` panics with this minimal `Handler` (it should not — it reads config/h.totalCredits), inspect `getCredits` and add the needed field to the literal.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./proxy/ -run TestStatsIncludesCacheMetrics -v`
Expected: FAIL — `got["cache"]` is nil (no `cache` key in the response).

- [ ] **Step 3: Wire `cache` into the stats response**

In `proxy/handler.go`, in `handleStats` (the `json.NewEncoder(w).Encode(map[string]interface{}{...})` literal, currently `:453-464`), add the `cache` key:

```go
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":          "ok",
		"version":         config.Version,
		"accounts":        h.pool.Count(),
		"available":       h.pool.AvailableCount(),
		"totalRequests":   atomic.LoadInt64(&h.totalRequests),
		"successRequests": atomic.LoadInt64(&h.successRequests),
		"failedRequests":  atomic.LoadInt64(&h.failedRequests),
		"totalTokens":     atomic.LoadInt64(&h.totalTokens),
		"totalCredits":    h.getCredits(),
		"cache":           h.promptCache.Stats(),
		"uptime":          time.Now().Unix() - h.startTime,
	})
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./proxy/ -run TestStatsIncludesCacheMetrics -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add proxy/handler.go proxy/handler_test.go
git commit -m "feat(handler): expose prompt-cache stats in /v1/stats"
```

---

### Task 6: Full verification

**Files:** none (verification only).

- [ ] **Step 1: Build the whole module**

Run: `go build ./...`
Expected: succeeds.

- [ ] **Step 2: Vet the whole module**

Run: `go vet ./...`
Expected: no issues.

- [ ] **Step 3: Run the entire test suite**

Run: `go test ./...`
Expected: PASS. (Pre-existing unrelated failures, if any, should match the known baseline — only the two pre-existing translator image-test failures noted in the branch history are acceptable.)

- [ ] **Step 4: Manual smoke (optional)**

If a running instance is available: `curl -s <endpoint>/v1/stats -H 'x-api-key: <key>' | jq .cache` should show `hits`, `misses`, `evictions`, `expirations`, `entries`, `capacity`. Under multi-turn load, `hits/(hits+misses)` should rise toward 1 and `evictions` should stay near 0 — the visible proof the churn bug is fixed.

---

## Self-Review (completed)

**Spec coverage:** capacity configurable + default 131072 (Task 1 + Task 2) ✓; O(1) LRU via `container/list` (Task 2) ✓; drop `LastHit` (Task 2) ✓; min clamp 256 (Task 2) ✓; atomic counters hits/misses/evictions/expirations (Task 4) ✓; `Stats()` + `/v1/stats` exposure (Tasks 4–5) ✓; churn regression (Task 3) ✓; invariants preserved (Global Constraints; verified by the unchanged existing tests in Task 2 Step 16) ✓.

**Placeholder scan:** none — every code step shows complete code.

**Type/signature consistency:** `putLocked(fp [32]byte, expiresAt time.Time, ttl time.Duration)`, `evictOverflowLocked()`, `newPromptCacheTrackerWithCapacity(maxTTL time.Duration, maxEntries int)`, `Stats() PromptCacheStats` — identical across all tasks that reference them ✓. `entries` is `map[[32]byte]*promptCacheEntry` everywhere after Task 2 ✓.

**Known GREEN-on-arrival tests:** Task 3's churn guards pass immediately after Task 2 (they are regression guards, not new behavior); the cap value 131072 is independently guarded by Task 1's `TestPromptCacheMaxEntriesConfigurable`. This is documented in Task 3's intro.
