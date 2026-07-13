package proxy

import (
	"bytes"
	"container/list"
	"crypto/sha256"
	"encoding/json"
	"kiro-go/config"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const defaultPromptCacheTTL = 5 * time.Minute

// Anthropic requires cached prefixes to reach a minimum token count before
// caching takes effect. Breakpoints below this threshold are excluded from
// matching and storage to avoid reporting unrealistic 100% cache hits on
// short requests.
const defaultMinCacheableTokens = 1024

// opusMinCacheableTokens is the minimum cacheable prefix size for Opus models.
// Anthropic's real prompt-cache threshold is ~1024 tokens (Claude 4 family);
// the previous 4096 excluded many valid Opus breakpoints, so an Opus
// conversation would report far fewer cache hits than it actually earned.
// Ported from kiro-tutu (opusMinCacheableTokens = 1024).
const opusMinCacheableTokens = 1024

type promptCacheUsage struct {
	CacheCreationInputTokens   int
	CacheReadInputTokens       int
	CacheCreation5mInputTokens int
	CacheCreation1hInputTokens int
}

type promptCacheBreakpoint struct {
	Fingerprint      [32]byte
	CumulativeTokens int
	TTL              time.Duration
}

type promptCacheProfile struct {
	Breakpoints      []promptCacheBreakpoint
	TotalInputTokens int
	Model            string
}

func minCacheableTokensForModel(model string) int {
	lower := strings.ToLower(model)
	if strings.Contains(lower, "opus") {
		return opusMinCacheableTokens
	}
	return defaultMinCacheableTokens
}

type promptCacheEntry struct {
	ExpiresAt time.Time
	TTL       time.Duration
	lruElem   *list.Element // back-ref into t.order; Value = fingerprint [32]byte
}

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

func newPromptCacheTracker(maxTTL time.Duration) *promptCacheTracker {
	return newPromptCacheTrackerWithCapacity(maxTTL, config.GetPromptCacheMaxEntries())
}

func newPromptCacheTrackerWithCapacity(maxTTL time.Duration, maxEntries int) *promptCacheTracker {
	if maxTTL <= 0 {
		maxTTL = defaultPromptCacheTTL
	}
	return &promptCacheTracker{
		entries:         make(map[[32]byte]*promptCacheEntry),
		order:           list.New(),
		maxEntries:      maxEntries,
		maxSupportedTTL: maxTTL,
	}
}

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
		Version int                      `json:"version"`
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
		t.putLocked(e.Fingerprint, exp, time.Duration(e.TTLSeconds)*time.Second)
	}
}

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
	// Idempotent: a second Stop (e.g. test cleanup + main shutdown) would
	// otherwise close an already-closed channel and panic.
	t.stopOnce.Do(func() {
		if t.stopChan != nil {
			close(t.stopChan)
		}
	})
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
	_ = writeFileAtomic(path, data)
}

// writeFileAtomic writes data to path via a temp file in the same directory
// then renames it into place, so a crash mid-flush cannot leave a truncated
// state file (which would silently reset the cache on the next Load). Mirrors
// the Python shim's tmp+os.replace path. os.Rename is atomic on the same
// filesystem; the same-dir temp guarantees same-fs. Best-effort: a rename
// failure falls back to a direct write (matching pre-existing behavior).
func writeFileAtomic(path string, data []byte) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0o700)
	}
	tmp, err := os.CreateTemp(dirOf(path), ".prompt-cache-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	closed := false
	defer func() {
		if !closed {
			tmp.Close()
		}
		_ = os.Remove(tmpName)
	}()
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	closed = true
	_ = os.Chmod(tmpName, 0o600)
	if err := os.Rename(tmpName, path); err != nil {
		return os.WriteFile(path, data, 0o600)
	}
	return nil
}

func dirOf(path string) string {
	if dir := filepath.Dir(path); dir != "" {
		return dir
	}
	return "."
}

// interfaceHasCacheControl reports whether the value tree contains any
// "cache_control" key on a dict node. Mirrors the Python shim's has_cache_control:
// cache_control can nest inside system blocks or message content blocks.
func interfaceHasCacheControl(v interface{}) bool {
	switch val := v.(type) {
	case map[string]interface{}:
		if _, ok := val["cache_control"]; ok {
			return true
		}
		for _, x := range val {
			if interfaceHasCacheControl(x) {
				return true
			}
		}
	case []interface{}:
		for _, x := range val {
			if interfaceHasCacheControl(x) {
				return true
			}
		}
	}
	return false
}

// claudeRequestHasCacheControl reports whether any cache_control marker appears
// in the request's system or message content. ClaudeTool is a typed struct with
// no cache_control field, so only system/messages can carry one. Used as the
// BuildClaudeProfile fast-path guard: no marker → no breakpoints possible → nil.
func claudeRequestHasCacheControl(req *ClaudeRequest) bool {
	if req == nil {
		return false
	}
	if interfaceHasCacheControl(req.System) {
		return true
	}
	for _, m := range req.Messages {
		if interfaceHasCacheControl(m.Content) {
			return true
		}
	}
	return false
}

// detectMaxTTL returns the largest cache_control TTL present anywhere in the
// request (1h wins over 5m), defaulting to defaultPromptCacheTTL when no
// cache_control marker exists. Mirrors Rust detect_max_ttl: it seeds the
// auto-prefix activeTTL so a request WITHOUT explicit cache_control still
// produces message-end breakpoints at the default TTL — reproducing Anthropic's
// automatic prompt caching (a stable history prefix hits across turns even
// though the client never set cache_control). ClaudeTool is a typed struct with
// no cache_control field, so only system/message blocks can contribute.
func detectMaxTTL(req *ClaudeRequest) time.Duration {
	max := defaultPromptCacheTTL
	bump := func(value interface{}) {
		if normalized := normalizePromptCacheTTL(extractPromptCacheTTL(value)); normalized > max {
			max = normalized
		}
	}
	if arr, ok := req.System.([]interface{}); ok {
		for _, block := range arr {
			bump(block)
		}
	}
	for _, msg := range req.Messages {
		if arr, ok := msg.Content.([]interface{}); ok {
			for _, block := range arr {
				bump(block)
			}
		}
	}
	return max
}

func (t *promptCacheTracker) BuildClaudeProfile(req *ClaudeRequest, totalInputTokens int) *promptCacheProfile {
	blocks := flattenClaudeCacheBlocks(req)
	if len(blocks) == 0 {
		return nil
	}

	hasher := sha256.New()
	breakpoints := make([]promptCacheBreakpoint, 0)
	cumulativeTokens := 0
	// Auto-prefix: seed activeTTL with detectMaxTTL(req) so message-end
	// breakpoints fire even with no explicit cache_control (see detectMaxTTL).
	activeTTL := detectMaxTTL(req)

	for _, block := range blocks {
		canonical := canonicalizeCacheValue(block.Value)
		writeHashChunk(hasher, canonical)
		cumulativeTokens += block.Tokens

		// Determine whether this block acts as a cache breakpoint:
		//   1) Explicit cache_control on the block itself.
		//   2) Once any explicit breakpoint has been seen, every message-end
		//      boundary becomes an implicit breakpoint so that multi-turn
		//      conversations can hit earlier stored prefixes.
		breakpointTTL := time.Duration(0)
		if block.TTL > 0 {
			breakpointTTL = block.TTL
			activeTTL = block.TTL
		} else if block.IsMessageEnd && activeTTL > 0 {
			breakpointTTL = activeTTL
		}

		if breakpointTTL <= 0 {
			continue
		}

		var fingerprint [32]byte
		copy(fingerprint[:], hasher.Sum(nil))
		breakpoints = append(breakpoints, promptCacheBreakpoint{
			Fingerprint:      fingerprint,
			CumulativeTokens: cumulativeTokens,
			TTL:              breakpointTTL,
		})
	}

	if len(breakpoints) == 0 {
		return nil
	}

	if totalInputTokens < cumulativeTokens {
		totalInputTokens = cumulativeTokens
	}

	return &promptCacheProfile{
		Breakpoints:      breakpoints,
		TotalInputTokens: totalInputTokens,
		Model:            req.Model,
	}
}

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

	minTokens := minCacheableTokensForModel(profile.Model)
	last := profile.Breakpoints[len(profile.Breakpoints)-1]
	lastTokens := minInt(last.CumulativeTokens, profile.TotalInputTokens)
	now := time.Now()

	t.mu.Lock()
	defer t.mu.Unlock()
	t.pruneExpiredLocked(now)

	if len(t.entries) == 0 {
		// First request for this account: report creation only if above threshold.
		effectiveCreation := lastTokens
		if effectiveCreation < minTokens {
			effectiveCreation = 0
		}
		cache5m, cache1h := computePromptCacheTTLBreakdown(profile, 0)
		cache5m, cache1h = clampCacheBreakdownToCreation(cache5m, cache1h, effectiveCreation)
		return promptCacheUsage{
			CacheCreationInputTokens:   effectiveCreation,
			CacheReadInputTokens:       0,
			CacheCreation5mInputTokens: cache5m,
			CacheCreation1hInputTokens: cache1h,
		}
	}

	// Cap cacheable tokens at 85% of total input to ensure a realistic
	// uncached portion. The newest content in a request is never fully
	// served from cache on the current turn.
	maxCacheable := int(float64(profile.TotalInputTokens) * config.GetPromptCacheMaxRatio())
	if lastTokens > maxCacheable {
		lastTokens = maxCacheable
	}

	matchedTokens := 0
	for i := len(profile.Breakpoints) - 1; i >= 0; i-- {
		breakpoint := profile.Breakpoints[i]
		// Skip breakpoints below the minimum cacheable token threshold.
		if breakpoint.CumulativeTokens < minTokens {
			continue
		}
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
	}

	creation := maxInt(lastTokens-matchedTokens, 0)
	cache5m, cache1h := computePromptCacheTTLBreakdown(profile, matchedTokens)
	cache5m, cache1h = clampCacheBreakdownToCreation(cache5m, cache1h, creation)
	return promptCacheUsage{
		CacheCreationInputTokens:   creation,
		CacheReadInputTokens:       matchedTokens,
		CacheCreation5mInputTokens: cache5m,
		CacheCreation1hInputTokens: cache1h,
	}
}

func (t *promptCacheTracker) Update(accountID string, profile *promptCacheProfile) {
	if t == nil || profile == nil || len(profile.Breakpoints) == 0 || accountID == "" {
		return
	}

	minTokens := minCacheableTokensForModel(profile.Model)
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	t.pruneExpiredLocked(now)

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
}

func (t *promptCacheTracker) pruneExpiredLocked(now time.Time) {
	for fingerprint, entry := range t.entries {
		if !entry.ExpiresAt.After(now) {
			t.order.Remove(entry.lruElem)
			delete(t.entries, fingerprint)
			atomic.AddInt64(&t.expirations, 1)
		}
	}
}

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
		atomic.AddInt64(&t.evictions, 1)
	}
}

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

// splitAgainstTotal rescales an estimate-domain cache split onto a real input
// total, preserving input + creation + read == realTotal. The cache-covered
// fraction of the prompt (in estimate units) is applied to realTotal, then
// divided into read vs creation by their estimate-domain ratio; the 5m/1h
// breakdown is scaled to the new creation total.
func (u promptCacheUsage) splitAgainstTotal(estTotal, realTotal int) promptCacheUsage {
	if realTotal <= 0 {
		return u
	}
	coveredEst := u.CacheCreationInputTokens + u.CacheReadInputTokens
	if coveredEst <= 0 || estTotal <= 0 {
		return promptCacheUsage{} // no cache coverage → all fresh input
	}
	ratio := float64(coveredEst) / float64(estTotal)
	if ratio > 1 {
		ratio = 1
	}
	cacheTotal := int(float64(realTotal)*ratio + 0.5)
	if cacheTotal > realTotal {
		cacheTotal = realTotal
	}
	read := int(float64(cacheTotal)*float64(u.CacheReadInputTokens)/float64(coveredEst) + 0.5)
	if read > cacheTotal {
		read = cacheTotal
	}
	if read < 0 {
		read = 0
	}
	creation := cacheTotal - read
	cache5m, cache1h := creation, 0
	if u.CacheCreationInputTokens > 0 {
		cache1h = int(float64(u.CacheCreation1hInputTokens)*float64(creation)/float64(u.CacheCreationInputTokens) + 0.5)
		if cache1h > creation {
			cache1h = creation
		}
		cache5m = creation - cache1h
	}
	return promptCacheUsage{
		CacheCreationInputTokens:   creation,
		CacheReadInputTokens:       read,
		CacheCreation5mInputTokens: cache5m,
		CacheCreation1hInputTokens: cache1h,
	}
}

type cacheablePromptBlock struct {
	Value        interface{}
	Tokens       int
	TTL          time.Duration
	IsMessageEnd bool
}

func flattenClaudeCacheBlocks(req *ClaudeRequest) []cacheablePromptBlock {
	blocks := make([]cacheablePromptBlock, 0)
	blocks = append(blocks, buildCachePreludeBlock(req))

	for toolIndex, tool := range req.Tools {
		toolValue := map[string]interface{}{
			"kind":         "tool",
			"tool_index":   toolIndex,
			"name":         tool.Name,
			"description":  tool.Description,
			"input_schema": tool.InputSchema,
		}
		fingerprintValue := stripCachePositionKeys(toolValue)
		blocks = append(blocks, cacheablePromptBlock{
			Value:  fingerprintValue,
			Tokens: estimateApproxTokens(canonicalizeCacheValue(fingerprintValue)),
			TTL:    normalizePromptCacheTTL(extractPromptCacheTTL(tool)),
		})
	}

	appendSystemCacheBlocks(&blocks, req.System)

	for messageIndex, msg := range req.Messages {
		appendMessageCacheBlocks(&blocks, messageIndex, msg)
	}

	return blocks
}

func buildCachePreludeBlock(req *ClaudeRequest) cacheablePromptBlock {
	prelude := map[string]interface{}{
		"kind":        "request_prelude",
		"model":       req.Model,
		"tool_choice": req.ToolChoice,
	}
	return cacheablePromptBlock{
		Value:  prelude,
		Tokens: estimateApproxTokens(canonicalizeCacheValue(prelude)),
	}
}

func appendSystemCacheBlocks(blocks *[]cacheablePromptBlock, system interface{}) {
	switch v := system.(type) {
	case string:
		appendPromptBlock(blocks, map[string]interface{}{
			"kind":         "system",
			"system_index": 0,
			"block": map[string]interface{}{
				"type": "text",
				"text": v,
			},
		}, false)
	case []interface{}:
		// Structural skip (mirrors Rust extract_segments): Claude Code injects a
		// per-turn DYNAMIC block at system[0] WITHOUT cache_control, followed by
		// the stable cached block(s). Fingerprinting from that volatile head would
		// drift every downstream prefix fingerprint across turns, collapsing
		// cross-turn cache hits to zero. So skip every leading system block that
		// lacks cache_control — accumulate from the first block carrying one. If
		// no block has cache_control, skipUntil stays 0 (include all, matching
		// Rust's unwrap_or(0)). system_index is a stripped position key, so the
		// shift in index values does not affect fingerprints. The
		// isAnthropicBillingHeaderBlock drop inside appendPromptBlock stays as a
		// backstop for a non-leading billing-header block.
		skipUntil := 0
		found := false
		for i, block := range v {
			if interfaceHasCacheControl(block) {
				skipUntil = i
				found = true
				break
			}
		}
		_ = found
		for i := skipUntil; i < len(v); i++ {
			appendPromptBlock(blocks, map[string]interface{}{
				"kind":         "system",
				"system_index": i,
				"block":        v[i],
			}, false)
		}
	case []string:
		for i, block := range v {
			appendPromptBlock(blocks, map[string]interface{}{
				"kind":         "system",
				"system_index": i,
				"block": map[string]interface{}{
					"type": "text",
					"text": block,
				},
			}, false)
		}
	}
}

func appendMessageCacheBlocks(blocks *[]cacheablePromptBlock, messageIndex int, msg ClaudeMessage) {
	role := msg.Role
	switch content := msg.Content.(type) {
	case string:
		appendPromptBlock(blocks, map[string]interface{}{
			"kind":          "message",
			"message_index": messageIndex,
			"role":          role,
			"block_index":   0,
			"block": map[string]interface{}{
				"type": "text",
				"text": content,
			},
		}, true)
	case []interface{}:
		lastIdx := len(content) - 1
		for blockIndex, block := range content {
			appendPromptBlock(blocks, map[string]interface{}{
				"kind":          "message",
				"message_index": messageIndex,
				"role":          role,
				"block_index":   blockIndex,
				"block":         block,
			}, blockIndex == lastIdx)
		}
	default:
		if content != nil {
			appendPromptBlock(blocks, map[string]interface{}{
				"kind":          "message",
				"message_index": messageIndex,
				"role":          role,
				"block_index":   0,
				"block":         content,
			}, true)
		}
	}
}

func appendPromptBlock(blocks *[]cacheablePromptBlock, wrapper map[string]interface{}, isMessageEnd bool) {
	blockValue := wrapper["block"]
	ttl := normalizePromptCacheTTL(extractPromptCacheTTL(blockValue))

	// Drop volatile billing metadata from the cache fingerprint. Claude Code's
	// x-anthropic-billing-header can drift, appear, or disappear across
	// otherwise identical requests, and it does not change model semantics.
	if isAnthropicBillingHeaderBlock(blockValue) {
		return
	}

	fingerprintValue := stripCachePositionKeys(wrapper)
	canonical := canonicalizeCacheValue(fingerprintValue)
	*blocks = append(*blocks, cacheablePromptBlock{
		Value:        fingerprintValue,
		Tokens:       estimateApproxTokens(canonical),
		TTL:          ttl,
		IsMessageEnd: isMessageEnd,
	})
}

func stripCachePositionKeys(value map[string]interface{}) map[string]interface{} {
	cloned := make(map[string]interface{}, len(value))
	for key, item := range value {
		if isCachePositionKey(key) {
			continue
		}
		cloned[key] = item
	}
	return cloned
}

func isAnthropicBillingHeaderBlock(value interface{}) bool {
	blockMap, ok := value.(map[string]interface{})
	if !ok {
		return false
	}

	// Only normalize text blocks (or blocks without an explicit type but containing text).
	if t, ok := blockMap["type"].(string); ok && t != "" && t != "text" {
		return false
	}

	text, ok := blockMap["text"].(string)
	if !ok {
		return false
	}

	trimmed := strings.TrimLeft(text, " \t\r\n")
	return strings.HasPrefix(strings.ToLower(trimmed), "x-anthropic-billing-header:")
}

func extractPromptCacheTTL(value interface{}) time.Duration {
	block, ok := value.(map[string]interface{})
	if !ok {
		if raw, err := json.Marshal(value); err == nil {
			var decoded map[string]interface{}
			if json.Unmarshal(raw, &decoded) == nil {
				block = decoded
				ok = true
			}
		}
	}
	if !ok {
		return 0
	}

	rawCache, ok := block["cache_control"]
	if !ok {
		return 0
	}
	cacheControl, ok := rawCache.(map[string]interface{})
	if !ok {
		return 0
	}
	cacheType, _ := cacheControl["type"].(string)
	if !strings.EqualFold(cacheType, "ephemeral") {
		return 0
	}

	if ttl, ok := parsePromptCacheTTLValue(cacheControl["ttl"]); ok {
		return ttl
	}
	return defaultPromptCacheTTL
}

func parsePromptCacheTTLValue(value interface{}) (time.Duration, bool) {
	switch v := value.(type) {
	case string:
		trimmed := strings.TrimSpace(strings.ToLower(v))
		if trimmed == "" {
			return 0, false
		}
		if d, err := time.ParseDuration(trimmed); err == nil {
			return d, true
		}
		if seconds, err := strconv.Atoi(trimmed); err == nil {
			return time.Duration(seconds) * time.Second, true
		}
	case float64:
		if v > 0 {
			return time.Duration(v) * time.Second, true
		}
	case int:
		if v > 0 {
			return time.Duration(v) * time.Second, true
		}
	case int64:
		if v > 0 {
			return time.Duration(v) * time.Second, true
		}
	}
	return 0, false
}

func normalizePromptCacheTTL(ttl time.Duration) time.Duration {
	if ttl <= 0 {
		return 0
	}
	if ttl > time.Hour {
		return time.Hour
	}
	if ttl > defaultPromptCacheTTL {
		return time.Hour
	}
	return defaultPromptCacheTTL
}

func computePromptCacheTTLBreakdown(profile *promptCacheProfile, matchedTokens int) (int, int) {
	if profile == nil || len(profile.Breakpoints) == 0 {
		return 0, 0
	}

	cache5m := 0
	cache1h := 0
	previous := matchedTokens
	for _, breakpoint := range profile.Breakpoints {
		current := minInt(breakpoint.CumulativeTokens, profile.TotalInputTokens)
		if current <= previous {
			continue
		}
		delta := current - previous
		if breakpoint.TTL >= time.Hour {
			cache1h += delta
		} else {
			cache5m += delta
		}
		previous = current
	}
	return cache5m, cache1h
}

// clampCacheBreakdownToCreation scales the 5m/1h cache-creation split down to
// creation when the raw breakpoint deltas (uncapped by the 0.85 cacheable ratio)
// exceed it, preserving the 1h:5m ratio. Guarantees the Anthropic invariant
// cache_creation_input_tokens == ephemeral_5m + ephemeral_1h.
func clampCacheBreakdownToCreation(cache5m, cache1h, creation int) (int, int) {
	total := cache5m + cache1h
	if total <= creation || total <= 0 {
		return cache5m, cache1h
	}
	scale := float64(creation) / float64(total)
	one := int(float64(cache1h)*scale + 0.5)
	if one > creation {
		one = creation
	}
	if one < 0 {
		one = 0
	}
	return creation - one, one
}

func billedClaudeInputTokens(inputTokens int, usage promptCacheUsage) int {
	return maxInt(inputTokens-usage.CacheCreationInputTokens-usage.CacheReadInputTokens, 0)
}

func buildClaudeUsageMap(inputTokens, outputTokens int, usage promptCacheUsage, includeCache bool) map[string]interface{} {
	result := map[string]interface{}{
		"input_tokens":  billedClaudeInputTokens(inputTokens, usage),
		"output_tokens": outputTokens,
	}
	if !includeCache {
		return result
	}
	result["cache_creation_input_tokens"] = usage.CacheCreationInputTokens
	result["cache_read_input_tokens"] = usage.CacheReadInputTokens
	result["cache_creation"] = map[string]int{
		"ephemeral_5m_input_tokens": usage.CacheCreation5mInputTokens,
		"ephemeral_1h_input_tokens": usage.CacheCreation1hInputTokens,
	}
	return result
}

func canonicalizeCacheValue(value interface{}) string {
	var buf bytes.Buffer
	writeCanonicalJSON(&buf, value)
	return buf.String()
}

func writeCanonicalJSON(buf *bytes.Buffer, value interface{}) {
	switch v := value.(type) {
	case nil:
		buf.WriteString("null")
	case string:
		encoded, _ := json.Marshal(v)
		buf.Write(encoded)
	case bool:
		if v {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case float64, float32, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, json.Number:
		encoded, _ := json.Marshal(v)
		buf.Write(encoded)
	case []interface{}:
		buf.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeCanonicalJSON(buf, item)
		}
		buf.WriteByte(']')
	case map[string]interface{}:
		buf.WriteByte('{')
		keys := make([]string, 0, len(v))
		for key := range v {
			if key == "cache_control" {
				continue
			}
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for i, key := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			encoded, _ := json.Marshal(key)
			buf.Write(encoded)
			buf.WriteByte(':')
			writeCanonicalJSON(buf, v[key])
		}
		buf.WriteByte('}')
	default:
		encoded, _ := json.Marshal(v)
		buf.Write(encoded)
	}
}

func isCachePositionKey(key string) bool {
	switch key {
	case "tool_index", "system_index", "message_index", "block_index":
		return true
	default:
		return false
	}
}

func writeHashChunk(hasher hashWriter, chunk string) {
	length := strconv.Itoa(len(chunk))
	hasher.Write([]byte(length))
	hasher.Write([]byte{0})
	hasher.Write([]byte(chunk))
	hasher.Write([]byte{0})
}

type hashWriter interface {
	Write([]byte) (int, error)
	Sum([]byte) []byte
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
