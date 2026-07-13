package proxy

import (
	"crypto/sha256"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

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

// TestSplitAgainstTotalAnchorsToRealTotal verifies the cache split is rescaled
// onto the real upstream input total while preserving the accounting identity
// input + creation + read == realTotal.
func TestSplitAgainstTotalAnchorsToRealTotal(t *testing.T) {
	// Estimate domain: covered = 800 (creation 500 + read 300), estTotal = 1000.
	u := promptCacheUsage{
		CacheCreationInputTokens:   500,
		CacheReadInputTokens:       300,
		CacheCreation5mInputTokens: 500,
	}
	got := u.splitAgainstTotal(1000, 2000)

	// ratio = 800/1000 = 0.8 → cacheTotal = 1600; read = 1600*300/800 = 600; creation = 1000.
	if got.CacheReadInputTokens != 600 {
		t.Fatalf("cache_read = %d, want 600", got.CacheReadInputTokens)
	}
	if got.CacheCreationInputTokens != 1000 {
		t.Fatalf("cache_creation = %d, want 1000", got.CacheCreationInputTokens)
	}
	billed := billedClaudeInputTokens(2000, got)
	if billed != 400 {
		t.Fatalf("billed input = %d, want 400", billed)
	}
	if sum := billed + got.CacheCreationInputTokens + got.CacheReadInputTokens; sum != 2000 {
		t.Fatalf("identity broken: input+creation+read = %d, want 2000", sum)
	}
}

// TestSplitAgainstTotalNoCoverageIsAllInput verifies that with no cache
// coverage the whole real total is billed as fresh input.
func TestSplitAgainstTotalNoCoverageIsAllInput(t *testing.T) {
	got := promptCacheUsage{}.splitAgainstTotal(1000, 2000)
	if got.CacheReadInputTokens != 0 || got.CacheCreationInputTokens != 0 {
		t.Fatalf("expected no cache tokens, got read=%d creation=%d", got.CacheReadInputTokens, got.CacheCreationInputTokens)
	}
	if billed := billedClaudeInputTokens(2000, got); billed != 2000 {
		t.Fatalf("expected all 2000 billed as input, got %d", billed)
	}
}

// TestStopIsIdempotent verifies Stop() can be called twice (e.g. test cleanup
// + main shutdown) without panicking on a double close of stopChan.
func TestStopIsIdempotent(t *testing.T) {
	tr := newPromptCacheTracker(time.Hour)
	tr.stopChan = make(chan struct{})
	tr.Stop()
	tr.Stop() // before fix: close of closed channel → panic
}

// TestComputeSetsDirtyOnCacheHit verifies a cache hit marks the tracker dirty
// so the extended TTL/LastHit is persisted even if the save loop flushes
// between Compute and the following Update.
func TestComputeSetsDirtyOnCacheHit(t *testing.T) {
	tr := newPromptCacheTracker(time.Hour)
	profile := &promptCacheProfile{
		Model:            "claude-sonnet-4-6",
		TotalInputTokens: 10000,
		Breakpoints: []promptCacheBreakpoint{
			{Fingerprint: [32]byte{1}, CumulativeTokens: 2000, TTL: time.Hour},
		},
	}
	now := time.Now()
	tr.mu.Lock()
	tr.putLocked([32]byte{1}, now.Add(time.Hour), time.Hour)
	tr.mu.Unlock()
	tr.dirty = false

	tr.Compute("acct", profile)

	if !tr.dirty {
		t.Fatal("Compute must set dirty on a cache hit so the refreshed TTL/LastHit is persisted")
	}
}

// TestWriteFileAtomicPersistsAndLeavesNoTemp verifies the atomic-flush path:
// flush writes a complete, reloadable file via tmp+rename, with no stray
// .prompt-cache-*.tmp left in the directory (which would indicate a torn write).
func TestWriteFileAtomicPersistsAndLeavesNoTemp(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/prompt_cache.json"

	tr := newPromptCacheTracker(5 * time.Minute)
	hasher := sha256.New()
	writeHashChunk(hasher, "atomic-flush-marker")
	var fp [32]byte
	copy(fp[:], hasher.Sum(nil))
	tr.mu.Lock()
	tr.putLocked(fp, time.Now().Add(10*time.Minute), 5*time.Minute)
	tr.dirty = true
	tr.mu.Unlock()
	tr.flush(path)

	// File must be present and valid JSON (reloadable by Load).
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("expected flushed state file, got error: %v", err)
	}
	var disk struct {
		Version int                      `json:"version"`
		Entries []promptCacheEntryOnDisk `json:"entries"`
	}
	if json.Unmarshal(raw, &disk) != nil {
		t.Fatalf("flushed file is not valid JSON: %s", string(raw))
	}
	if len(disk.Entries) != 1 {
		t.Fatalf("expected 1 persisted entry, got %d", len(disk.Entries))
	}

	// No torn-write temp files should remain after a successful flush.
	entries, _ := os.ReadDir(dir)
	for _, f := range entries {
		if strings.HasSuffix(f.Name(), ".tmp") {
			t.Fatalf("leftover temp file after flush: %s", f.Name())
		}
	}

	// Reload via Load confirms the round-trip.
	t2 := newPromptCacheTracker(5 * time.Minute)
	t2.Load(path)
	t2.mu.Lock()
	_, ok := t2.entries[fp]
	t2.mu.Unlock()
	if !ok {
		t.Fatal("entry not reloaded after atomic flush")
	}
}

// TestBuildClaudeProfileAutoPrefixWithoutCacheControl locks the auto-prefix
// behavior (mirrors Rust prefix_chain_works_without_any_cache_control): a
// request with NO cache_control marker still builds a profile and — across two
// turns sharing a stable history prefix — the second turn reads cache
// (cache_read > 0). This reproduces Anthropic's automatic prompt caching, where
// stable prefixes are reused across turns without the client marking
// cache_control. A request carrying cache_control still builds a profile.
func TestBuildClaudeProfileAutoPrefixWithoutCacheControl(t *testing.T) {
	tr := newPromptCacheTracker(time.Hour)
	body := strings.Repeat("lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor incididunt ut labore ", 80)

	mk := func(final string) *ClaudeRequest {
		return &ClaudeRequest{
			Model:    "claude-sonnet-4.5",
			System:   strings.Repeat("system prompt without any cache marker ", 200),
			Messages: []ClaudeMessage{
				{Role: "user", Content: body},
				{Role: "assistant", Content: body},
				{Role: "user", Content: final},
			},
		}
	}

	// No cache_control anywhere — predicate confirms it, yet a profile is built.
	plain := mk("question one")
	if claudeRequestHasCacheControl(plain) {
		t.Fatal("claudeRequestHasCacheControl should be false for a request with no cache_control")
	}
	p1 := tr.BuildClaudeProfile(plain, 5000)
	if p1 == nil {
		t.Fatal("auto-prefix: expected a profile even when no cache_control is present")
	}
	first := tr.Compute("acct-1", p1)
	if first.CacheReadInputTokens != 0 {
		t.Fatalf("first turn has no prior cache to read, got %+v", first)
	}
	tr.Update("acct-1", p1)

	// Turn 2: identical history prefix, new final message, still no cache_control.
	// The shared prefix must hit — auto-prefix cache, no explicit marker needed.
	p2 := tr.BuildClaudeProfile(mk("question two"), 5000)
	if p2 == nil {
		t.Fatal("auto-prefix: turn-2 profile should be built")
	}
	second := tr.Compute("acct-1", p2)
	if second.CacheReadInputTokens == 0 {
		t.Fatalf("auto-prefix: expected cross-turn cache_read without cache_control, got %+v", second)
	}

	// A request WITH cache_control still builds a profile (unchanged path).
	withCache := &ClaudeRequest{
		Model: "claude-sonnet-4.5",
		System: []interface{}{
			map[string]interface{}{
				"type":          "text",
				"text":          strings.Repeat("cached system prompt ", 200),
				"cache_control": map[string]interface{}{"type": "ephemeral"},
			},
		},
		Messages: []ClaudeMessage{{Role: "user", Content: "follow up"}},
	}
	if !claudeRequestHasCacheControl(withCache) {
		t.Fatal("claudeRequestHasCacheControl should be true when cache_control is present")
	}
	if prof := tr.BuildClaudeProfile(withCache, 2048); prof == nil {
		t.Fatal("expected a profile when cache_control is present above threshold")
	}
}
