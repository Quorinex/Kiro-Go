package proxy

import (
	"strings"
	"sync"
)

// modelInputTokenLimits caches the authoritative input-token window each model
// reports through ListAvailableModels (tokenLimits.maxInputTokens), keyed by
// lowercased model ID.
//
// This exists because the window is not a cosmetic number: getContextWindowSize
// multiplies the upstream contextUsagePercentage by it to produce the
// input_tokens we report to clients, and agent clients divide that by the window
// THEY know for the model to decide when to compact. Guessing the window from
// the model name scales every reported count by (guessed / real), so a guess
// that runs high makes a client compact, see a still-inflated count, and compact
// again — the ratio is unchanged by compaction, so the loop never breaks. The
// upstream hands us the real number on every model refresh; use it.
//
// Observation-only and last-write-wins: entries are populated from model
// refreshes and never invalidated. An absent entry falls back to the name-based
// heuristic, which is the pre-existing behaviour.
var modelInputTokenLimits sync.Map

// recordModelTokenLimits stores the input-token window for every model in the
// list that reports one. Safe to call from any model-refresh path.
func recordModelTokenLimits(models []ModelInfo) {
	for _, m := range models {
		if m.TokenLimits == nil || m.TokenLimits.MaxInputTokens <= 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(m.ModelId))
		if key == "" {
			continue
		}
		modelInputTokenLimits.Store(key, m.TokenLimits.MaxInputTokens)
	}
}

// lookupModelInputTokenLimit returns the upstream-reported input-token window
// for a model, and whether one was known.
func lookupModelInputTokenLimit(model string) (int, bool) {
	key := strings.ToLower(strings.TrimSpace(model))
	if key == "" {
		return 0, false
	}
	if v, ok := modelInputTokenLimits.Load(key); ok {
		if limit, isInt := v.(int); isInt && limit > 0 {
			return limit, true
		}
	}
	return 0, false
}
