package proxy

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestCacheHitRateSimulation drives the prompt-cache tracker with realistic
// multi-session / multi-turn Claude Code workloads and reports the observed hit
// rate from the Stats() counters. It does NOT touch the network — it replays the
// same BuildClaudeProfile → Compute → Update flow the real handler runs, which is
// exactly what the cache metrics measure.
//
// Run: go test ./proxy/ -run TestCacheHitRateSimulation -v
func TestCacheHitRateSimulation(t *testing.T) {
	// Shared system prompt, large enough (~1500 tokens) to clear the 1024-token
	// min-cacheable threshold. Represents the common cached system prompt.
	sharedSystem := strings.Repeat(
		"You are a meticulous senior engineer who writes careful, idiomatic Go and reviews diffs critically. ", 95)

	// buildReq assembles a multi-turn request that grows turn-by-turn, the way a
	// real conversation does (turn N's message history is a superset of turn N-1's).
	buildReq := func(userText string, turns int) *ClaudeRequest {
		messages := make([]ClaudeMessage, 0, turns*2)
		for i := 0; i < turns; i++ {
			messages = append(messages, ClaudeMessage{
				Role:    "user",
				Content: fmt.Sprintf("%s (turn %d)", userText, i),
			})
			messages = append(messages, ClaudeMessage{
				Role:    "assistant",
				Content: strings.Repeat("Here is a careful, idiomatic answer with rationale. ", 25),
			})
		}
		return &ClaudeRequest{
			Model: "claude-sonnet-4-6",
			System: []interface{}{
				map[string]interface{}{
					"type":          "text",
					"text":          sharedSystem,
					"cache_control": map[string]interface{}{"type": "ephemeral", "ttl": "5m"},
				},
			},
			Messages: messages,
		}
	}

	run := func(tr *promptCacheTracker, req *ClaudeRequest) {
		prof := tr.BuildClaudeProfile(req, estimateClaudeRequestInputTokens(req))
		if prof == nil {
			return
		}
		tr.Compute("acct", prof) // estimate-domain lookup → counts a hit or miss
		tr.Update("acct", prof)  // success path: store refreshed breakpoints
	}

	report := func(label string, tr *promptCacheTracker) {
		s := tr.Stats()
		total := s.Hits + s.Misses
		rate := 0.0
		if total > 0 {
			rate = float64(s.Hits) / float64(total)
		}
		t.Logf("")
		t.Logf("=== %s ===", label)
		t.Logf("  requests    : %d", total)
		t.Logf("  hits        : %d", s.Hits)
		t.Logf("  misses      : %d", s.Misses)
		t.Logf("  HIT RATE    : %.1f%%", rate*100)
		t.Logf("  evictions   : %d (LRU pop-backs)", s.Evictions)
		t.Logf("  expirations : %d (TTL)", s.Expirations)
		t.Logf("  entries now : %d / %d capacity", s.Entries, s.Capacity)
	}

	// Scenario A — realistic Claude Code load: 30 sessions share one system
	// prompt; each grows 1→6 turns (180 requests total). Cross-session sharing
	// (C1) means even a brand-new session hits on the shared system prefix.
	trA := newPromptCacheTracker(time.Hour)
	for s := 0; s < 30; s++ {
		tag := fmt.Sprintf("session-%d", s)
		for n := 1; n <= 6; n++ {
			run(trA, buildReq(tag, n))
		}
	}
	report("A: realistic (30 sessions x 6 turns, shared system prompt)", trA)

	// Scenario B — cold baseline: every request uses a unique system prompt, so
	// nothing is reusable. Expect ~0% hit rate.
	trB := newPromptCacheTracker(time.Hour)
	for i := 0; i < 60; i++ {
		req := buildReq(fmt.Sprintf("unique-%d", i), 1)
		req.System = []interface{}{
			map[string]interface{}{
				"type":          "text",
				"text":          strings.Repeat(fmt.Sprintf("unique-system-prompt-%d ", i), 95),
				"cache_control": map[string]interface{}{"type": "ephemeral", "ttl": "5m"},
			},
		}
		run(trB, req)
	}
	report("B: cold baseline (60 unique system prompts, no sharing)", trB)

	// Scenario C — single long conversation: one session, 12 turns. Only turn 1
	// is a cold miss; turns 2..12 hit at ever-deeper prefixes. Expect ~92%.
	trC := newPromptCacheTracker(time.Hour)
	for n := 1; n <= 12; n++ {
		run(trC, buildReq("one-session", n))
	}
	report("C: single conversation (1 session x 12 turns)", trC)
}
