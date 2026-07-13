# Cache Improvements (C1/C2/C3) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Improve the prompt-cache accounting layer (`proxy/cache_tracker.go`) — cross-account sharing (C1), configurable cache cap (C2), and disk persistence (C3) — so hit-rate accuracy and restart-survival improve for multi-account pools.

**Architecture:** The cache tracker is an in-memory SHA-256 fingerprint store that mirrors Anthropic's upstream prompt caching to report `cache_creation/cache_read` tokens. C1 removes the per-account isolation (biggest hit-rate win); C2 makes the 85% cap configurable; C3 persists entries to disk so restart doesn't lose them.

**Tech Stack:** Go 1.21 (module `kiro-go`, stdlib), `encoding/json` for disk persistence.

## Global Constraints

- The cache tracker is ACCOUNTING ONLY — it reports cache tokens; it does NOT cache responses. No upstream behavior changes.
- Canonical fingerprint = SHA-256 running hash of canonicalized blocks (system + tools + messages). This is correct; do NOT change fingerprinting.
- TTL: 5min default, 1h max. Min cacheable: 1024 tokens (4096 opus). These match Anthropic spec — do NOT change.
- Module path `kiro-go`. Run `go test ./...` from `C:\Users\Admin\Kiro-Go`.
- Disk file: `data/prompt_cache.json` (already exists, currently unused). Load on startup, write debounced.

---

### Task 1: C1 — Cross-account cache sharing (remove per-account isolation)

**Files:**
- Modify: `proxy/cache_tracker.go` (struct `promptCacheTracker`, `Compute`, `Update`, `pruneExpiredLocked`)
- Modify: `proxy/cache_tracker_test.go` (add cross-account hit test)

**Why:** Currently `entriesByAccount[accountID]` means N accounts in a pool each build their own cache → hit rate drops to ~1/N. Since all accounts are in the same Anthropic org (tenant codezdevbatman), upstream cache IS shared. Making the fingerprint store global (drop accountID from the key) corrects the accounting → hit rate jumps from ~(1/N)×70% to ~70%.

- [ ] **Step 1: Write the failing test**

Append to `proxy/cache_tracker_test.go`:

```go
// TestPromptCacheCrossAccountSharing verifies C1: two different accountIDs with
// the SAME prompt fingerprint share cache entries. Account B's request should
// HIT on the fingerprint Account A stored — no per-account isolation.
func TestPromptCacheCrossAccountSharing(t *testing.T) {
	tracker := newPromptCacheTracker(5 * time.Minute)

	// Build a profile with one explicit cache_control breakpoint above the
	// min-token threshold.
	block := cacheablePromptBlock{
		Value: map[string]interface{}{"kind": "system", "block": map[string]interface{}{
			"type": "text", "text": strings.Repeat("x ", 600), // ~600 tokens > 1024? use more
			"cache_control": map[string]interface{}{"type": "ephemeral"},
		}},
		Tokens: 1200,
		TTL:    5 * time.Minute,
	}
	hasher := sha256.New()
	writeHashChunk(hasher, canonicalizeCacheValue(block.Value))
	var fp [32]byte
	copy(fp[:], hasher.Sum(nil))

	profile := &promptCacheProfile{
		Breakpoints:      []promptCacheBreakpoint{{Fingerprint: fp, CumulativeTokens: 1200, TTL: 5 * time.Minute}},
		TotalInputTokens: 1200,
		Model:            "claude-sonnet-4-5",
	}

	// Account A: first request → cache_creation.
	usageA := tracker.Compute("account-A", profile)
	if usageA.CacheCreationInputTokens == 0 {
		t.Fatalf("account A: expected cache_creation > 0, got %d", usageA.CacheCreationInputTokens)
	}
	tracker.Update("account-A", profile)

	// Account B: SAME prompt, DIFFERENT account → should be cache_read (C1 fix).
	// Before C1: account B had its own empty store → cache_creation.
	// After C1:  account B shares the global store → cache_read.
	usageB := tracker.Compute("account-B", profile)
	if usageB.CacheReadInputTokens == 0 {
		t.Fatalf("account B: expected cache_read > 0 (cross-account sharing), got 0. usage=%+v", usageB)
	}
}
```

Ensure `crypto/sha256`, `strings`, `time` are imported in the test file.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./proxy/ -run TestPromptCacheCrossAccountSharing -v`
Expected: FAIL — `account B: expected cache_read > 0` (current per-account isolation means account B's store is empty → cache_creation, not cache_read).

- [ ] **Step 3: Change the struct to use a global entries map**

In `proxy/cache_tracker.go`, replace the struct definition:

```go
type promptCacheTracker struct {
	mu               sync.Mutex
	entries          map[[32]byte]promptCacheEntry
	maxSupportedTTL  time.Duration
}
```

And update `newPromptCacheTracker`:

```go
func newPromptCacheTracker(maxTTL time.Duration) *promptCacheTracker {
	if maxTTL <= 0 {
		maxTTL = defaultPromptCacheTTL
	}
	return &promptCacheTracker{
		entries:         make(map[[32]byte]promptCacheEntry),
		maxSupportedTTL: maxTTL,
	}
}
```

- [ ] **Step 4: Update `Compute` to use the global map**

Replace the body of `Compute` — change `entries := t.entriesByAccount[accountID]` and all `entries[...]` references to use `t.entries` directly. The `accountID` parameter stays in the signature (backward compat for callers) but is now IGNORED (the store is global).

In `Compute`, replace:
```go
	entries := t.entriesByAccount[accountID]
	if len(entries) == 0 {
```
With:
```go
	if len(t.entries) == 0 {
```
And replace all `entries[breakpoint.Fingerprint]` with `t.entries[breakpoint.Fingerprint]`, and `entry, ok := entries[...]` with `entry, ok := t.entries[...]`.

- [ ] **Step 5: Update `Update` to use the global map**

In `Update`, replace:
```go
	entries := t.entriesByAccount[accountID]
	if entries == nil {
		entries = make(map[[32]byte]promptCacheEntry)
		t.entriesByAccount[accountID] = entries
	}
```
With:
```go
	// entries is the global map now (C1: cross-account sharing).
```
And replace `entries[breakpoint.Fingerprint] = ...` with `t.entries[breakpoint.Fingerprint] = ...`.

- [ ] **Step 6: Update `pruneExpiredLocked` to iterate the single map**

Replace:
```go
func (t *promptCacheTracker) pruneExpiredLocked(now time.Time) {
	for accountID, entries := range t.entriesByAccount {
		for fingerprint, entry := range entries {
			if !entry.ExpiresAt.After(now) {
				delete(entries, fingerprint)
			}
		}
		if len(entries) == 0 {
			delete(t.entriesByAccount, accountID)
		}
	}
}
```
With:
```go
func (t *promptCacheTracker) pruneExpiredLocked(now time.Time) {
	for fingerprint, entry := range t.entries {
		if !entry.ExpiresAt.After(now) {
			delete(t.entries, fingerprint)
		}
	}
}
```

- [ ] **Step 7: Run the test to verify it passes**

Run: `go test ./proxy/ -run TestPromptCacheCrossAccountSharing -v`
Expected: PASS — account B now hits the global store → cache_read > 0.
Then run the full cache test suite: `go test ./proxy/ -run TestPromptCache -v`
Expected: all PASS (existing tests use accountID but it's now ignored — they still pass because the store works regardless).

- [ ] **Step 8: Commit**

```bash
git add proxy/cache_tracker.go proxy/cache_tracker_test.go
git commit -m "fix(cache): cross-account prompt-cache sharing (C1)

Remove per-account isolation from the fingerprint store so N accounts in a
pool share cache entries (they're in the same Anthropic org). Hit rate jumps
from ~(1/N)*70% to ~70%."
```

---

### Task 2: C2 — Configurable cache cap (replace hardcoded 0.85)

**Files:**
- Modify: `proxy/cache_tracker.go` (`promptCacheTracker` struct, `Compute`)
- Modify: `proxy/cache_tracker_test.go` (cap test)
- Modify: `config/config.go` (`Config` struct + getter)

**Why:** The 85% cap (`maxCacheable = total * 0.85`) is a heuristic that under-reports cache hits on "continue" requests (tiny new turn, 90%+ from cache). Making it configurable lets operators raise it to 0.95 for workloads where the newest content is minimal.

- [ ] **Step 1: Add the config field**

In `config/config.go`, add to the `Config` struct (after `LogLevel` or near the cache-related fields):

```go
	// PromptCacheMaxRatio caps the fraction of input tokens reported as cache_read
	// in a single turn. Default 0.85. Raise to 0.95 for "continue"-heavy workloads
	// where the newest content is minimal and >85% of input is genuinely from cache.
	PromptCacheMaxRatio float64 `json:"promptCacheMaxRatio,omitempty"`
```

Add a getter after `GetLogLevel`:

```go
// GetPromptCacheMaxRatio returns the cache-read cap ratio (0.0-1.0). Defaults to 0.85.
func GetPromptCacheMaxRatio() float64 {
	cfgLock.RLock()
	defer cfgLock.RUnlock()
	if cfg == nil || cfg.PromptCacheMaxRatio <= 0 || cfg.PromptCacheMaxRatio > 1 {
		return 0.85
	}
	return cfg.PromptCacheMaxRatio
}
```

- [ ] **Step 2: Use the config value in Compute**

In `proxy/cache_tracker.go` `Compute`, replace:
```go
		maxCacheable := int(float64(profile.TotalInputTokens) * 0.85)
```
With:
```go
		maxCacheable := int(float64(profile.TotalInputTokens) * config.GetPromptCacheMaxRatio())
```

Ensure `"kiro-go/config"` is imported in `cache_tracker.go`.

- [ ] **Step 3: Write the test**

Append to `proxy/cache_tracker_test.go`:

```go
// TestPromptCacheCapConfigurable verifies C2: the cache-read cap can be set
// above the default 0.85 via config, so a request where 90% of input is from
// cache reports the full 90% (not clamped to 85%).
func TestPromptCacheCapConfigurable(t *testing.T) {
	cfgFile := t.TempDir() + "/config.json"
	if err := config.Init(cfgFile); err != nil {
		t.Fatalf("config.Init: %v", err)
	}

	// Build a profile: 1000 tokens cached, 100 new (total 1100). Default cap
	// would clamp to 0.85*1100=935. With cap=0.95, allows up to 1045.
	hasher := sha256.New()
	writeHashChunk(hasher, canonicalizeCacheValue(map[string]interface{}{"k": strings.Repeat("v ", 500)}))
	var fp [32]byte
	copy(fp[:], hasher.Sum(nil))
	profile := &promptCacheProfile{
		Breakpoints:      []promptCacheBreakpoint{{Fingerprint: fp, CumulativeTokens: 1000, TTL: 5 * time.Minute}},
		TotalInputTokens: 1100,
		Model:            "claude-sonnet-4-5",
	}
	tracker := newPromptCacheTracker(5 * time.Minute)
	tracker.Update("acc", profile) // store it

	// Default cap 0.85: cache_read clamped to min(1000, 0.85*1100=935) = 935.
	usage85 := tracker.Compute("acc", profile)
	if usage85.CacheReadInputTokens > 940 {
		t.Fatalf("default cap: expected cache_read ~935, got %d", usage85.CacheReadInputTokens)
	}

	// Raise cap to 0.95: cache_read should be min(1000, 0.95*1100=1045) = 1000.
	config.UpdatePromptCacheMaxRatio(0.95)
	defer config.UpdatePromptCacheMaxRatio(0.85)
	usage95 := tracker.Compute("acc", profile)
	if usage95.CacheReadInputTokens < 990 {
		t.Fatalf("cap 0.95: expected cache_read ~1000, got %d", usage95.CacheReadInputTokens)
	}
}
```

Add `UpdatePromptCacheMaxRatio` to `config/config.go`:
```go
func UpdatePromptCacheMaxRatio(ratio float64) error {
	cfgLock.Lock()
	defer cfgLock.Unlock()
	cfg.PromptCacheMaxRatio = ratio
	return Save()
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./proxy/ -run 'TestPromptCacheCap|TestPromptCacheCrossAccount' -v`
Expected: PASS.
Then: `go test ./proxy/ ./config/ -v`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add proxy/cache_tracker.go proxy/cache_tracker_test.go config/config.go
git commit -m "feat(cache): configurable cache-read cap (C2)

Replace the hardcoded 0.85 cache-read cap with a config value
(promptCacheMaxRatio, default 0.85). Operators can raise it to 0.95 for
continue-heavy workloads where >85% of input is genuinely from cache."
```

---

### Task 3: C3 — Disk persistence (load on startup, debounce-write)

**Files:**
- Modify: `proxy/cache_tracker.go` (`promptCacheTracker`, add `Load`, `saveLoop`, `dirty` flag)
- Modify: `proxy/cache_tracker_test.go` (disk round-trip test)
- Modify: `proxy/handler.go` (call `Load` on tracker init + start `saveLoop`)

**Why:** Currently the cache is purely in-memory → restart loses all entries → every request after restart is `cache_creation` until fingerprints rebuild. Persisting to `data/prompt_cache.json` (which already exists but is unused) lets entries survive restart.

- [ ] **Step 1: Add persistence fields to the struct**

In `proxy/cache_tracker.go`, update the struct:

```go
type promptCacheTracker struct {
	mu               sync.Mutex
	entries          map[[32]byte]promptCacheEntry
	maxSupportedTTL  time.Duration
	dirty            bool
	stopChan         chan struct{}
}
```

- [ ] **Step 2: Add Load (called on startup)**

Add after `newPromptCacheTracker`:

```go
// on-disk format for prompt-cache persistence (C3).
type promptCacheEntryOnDisk struct {
	Fingerprint [32]byte
	ExpiresAt   int64 // unix seconds
	TTLSeconds  int64
}

// Load reads persisted cache entries from path. Entries already expired (by the
// time load finishes) are dropped. Best-effort: a corrupt/missing file is not
// fatal — the tracker starts empty, same as the pre-C3 behavior.
func (t *promptCacheTracker) Load(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return // missing file = fresh start (normal on first run)
	}
	var disk struct {
		Version int                    `json:"version"`
		Entries []promptCacheEntryOnDisk `json:"entries"`
	}
	if json.Unmarshal(data, &disk) != nil {
		return // corrupt = fresh start
	}
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, e := range disk.Entries {
		exp := time.Unix(e.ExpiresAt, 0)
		if !exp.After(now) {
			continue // already expired
		}
		t.entries[e.Fingerprint] = promptCacheEntry{
			ExpiresAt: exp,
			TTL:       time.Duration(e.TTLSeconds) * time.Second,
		}
	}
}
```

Ensure `"os"` and `"encoding/json"` are imported in `cache_tracker.go`.

- [ ] **Step 3: Add saveLoop (debounced background writer)**

```go
// startSaveLoop launches a background goroutine that flushes the cache to path
// every flushInterval (if dirty). Call once after Load. The goroutine exits when
// stopChan is closed.
func (t *promptCacheTracker) startSaveLoop(path string, flushInterval time.Duration) {
	t.stopChan = make(chan struct{})
	go func() {
		ticker := time.NewTicker(flushInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				t.flush(path)
			case <-t.stopChan:
				t.flush(path) // final flush
				return
			}
		}
	}()
}

func (t *promptCacheTracker) Stop() {
	if t.stopChan != nil {
		close(t.stopChan)
	}
}

func (t *promptCacheTracker) flush(path string) {
	t.mu.Lock()
	if !t.dirty {
		t.mu.Unlock()
		return
	}
	now := time.Now()
	entries := make([]promptCacheEntryOnDisk, 0, len(t.entries))
	for fp, e := range t.entries {
		if !e.ExpiresAt.After(now) {
			continue
		}
		entries = append(entries, promptCacheEntryOnDisk{
			Fingerprint: fp,
			ExpiresAt:   e.ExpiresAt.Unix(),
			TTLSeconds:  int64(e.TTL.Seconds()),
		})
	}
	t.dirty = false
	t.mu.Unlock()

	data, _ := json.MarshalIndent(map[string]interface{}{
		"version": 1,
		"entries": entries,
	}, "", "  ")
	_ = os.WriteFile(path, data, 0600)
}
```

- [ ] **Step 4: Mark dirty on Update**

In `Update`, after storing entries, add:
```go
	t.dirty = true
```
(right before `t.mu.Unlock()` — or after the loop that writes entries, inside the lock).

- [ ] **Step 5: Wire Load + startSaveLoop in the handler**

Find where `newPromptCacheTracker` is called (in `proxy/handler.go` `NewHandler` or similar). After creating the tracker, add:

```go
	cachePath := filepath.Join(config.GetConfigDir(), "prompt_cache.json")
	promptCache.Load(cachePath)
	promptCache.startSaveLoop(cachePath, 30*time.Second)
```

(Adjust the variable name to match the actual tracker variable in handler.go. Ensure `"path/filepath"` and `"time"` are imported.)

- [ ] **Step 6: Write the disk round-trip test**

Append to `proxy/cache_tracker_test.go`:

```go
// TestPromptCacheDiskPersistence verifies C3: entries saved to disk are
// reloaded on startup, surviving a "restart" (new tracker instance).
func TestPromptCacheDiskPersistence(t *testing.T) {
	path := t.TempDir() + "/prompt_cache.json"

	// Tracker 1: store an entry, flush to disk.
	t1 := newPromptCacheTracker(5 * time.Minute)
	hasher := sha256.New()
	writeHashChunk(hasher, "test-cache-value-disk")
	var fp [32]byte
	copy(fp[:], hasher.Sum(nil))
	t1.mu.Lock()
	t1.entries[fp] = promptCacheEntry{
		ExpiresAt: time.Now().Add(3 * time.Minute),
		TTL:       5 * time.Minute,
	}
	t1.dirty = true
	t1.mu.Unlock()
	t1.flush(path)

	// Tracker 2: load from disk → should have the entry.
	t2 := newPromptCacheTracker(5 * time.Minute)
	t2.Load(path)
	t2.mu.Lock()
	_, ok := t2.entries[fp]
	t2.mu.Unlock()
	if !ok {
		t.Fatalf("C3: entry not reloaded from disk after 'restart'")
	}

	// Expired entry should NOT reload.
	path2 := t.TempDir() + "/expired.json"
	t1b := newPromptCacheTracker(5 * time.Minute)
	t1b.mu.Lock()
	var fpExpired [32]byte
	copy(fpExpired[:], sha256.Sum256([]byte("expired")))
	t1b.entries[fpExpired] = promptCacheEntry{
		ExpiresAt: time.Now().Add(-1 * time.Minute), // already expired
		TTL:       5 * time.Minute,
	}
	t1b.dirty = true
	t1b.mu.Unlock()
	t1b.flush(path2)

	t3 := newPromptCacheTracker(5 * time.Minute)
	t3.Load(path2)
	t3.mu.Lock()
	_, okExpired := t3.entries[fpExpired]
	t3.mu.Unlock()
	if okExpired {
		t.Fatalf("C3: expired entry should not be reloaded")
	}
}
```

Ensure `"crypto/sha256"` is imported.

- [ ] **Step 7: Run tests**

Run: `go test ./proxy/ -run 'TestPromptCacheDisk|TestPromptCacheCrossAccount|TestPromptCacheCap' -v`
Expected: all PASS.
Then: `go test ./... `
Expected: all PASS.

- [ ] **Step 8: Commit**

```bash
git add proxy/cache_tracker.go proxy/cache_tracker_test.go proxy/handler.go
git commit -m "feat(cache): persist prompt-cache entries to disk (C3)

Load data/prompt_cache.json on startup and debounce-write every 30s so
cache entries survive restart. Expired entries are dropped on load. The
file already existed but was unused — now it's read and written."
```

---

## Final Verification

- [ ] `go test ./...` passes
- [ ] `go vet ./...` clean
- [ ] `go build -o kiro-go.exe .` succeeds

## Out of scope (deferred to dispatch plan)

- Part A (dispatch): health-aware scoring, circuit breaker, session affinity, auto-recovery, weight-as-probability. See `docs/superpowers/specs/2026-06-27-dispatch-cache-improvements-design.md` Part A. Separate plan TBD.
