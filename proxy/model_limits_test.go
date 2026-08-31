package proxy

import "testing"

// clearModelTokenLimits drops every recorded limit so a test starts from the
// name-based fallback. The store is process-global, so tests that record limits
// must clean up or they decide how later tests classify the same model.
func clearModelTokenLimits(t *testing.T) {
	t.Helper()
	reset := func() {
		modelInputTokenLimits.Range(func(k, _ interface{}) bool {
			modelInputTokenLimits.Delete(k)
			return true
		})
	}
	reset()
	t.Cleanup(reset)
}

func modelInfoWithInputLimit(id string, maxInput int) ModelInfo {
	m := ModelInfo{ModelId: id}
	m.TokenLimits = &struct {
		MaxInputTokens  int `json:"maxInputTokens"`
		MaxOutputTokens int `json:"maxOutputTokens"`
	}{MaxInputTokens: maxInput, MaxOutputTokens: 64000}
	return m
}

// Kiro's GPT models fall back to a measured ~256K, not the ~1M those models
// carry on their vendor's own API. The 1M assumption inflated every reported
// count by about 4x, which is what let a compaction loop run forever.
func TestGPTFallbackWindowIsKirosNotVendors(t *testing.T) {
	clearModelTokenLimits(t)

	for _, model := range []string{"gpt-5.6-sol", "gpt-5.6-terra", "GPT-5.6-Luna", "gpt-6"} {
		if got := getContextWindowSize(model); got != gptFallbackContextWindow {
			t.Errorf("getContextWindowSize(%q) = %d, want %d", model, got, gptFallbackContextWindow)
		}
	}
}

// The upstream window is the number clients divide by to decide when to
// compact, so a recorded limit must win over the name-based guess.
func TestGetContextWindowSizePrefersUpstreamLimit(t *testing.T) {
	clearModelTokenLimits(t)

	if got := getContextWindowSize("gpt-5.6-sol"); got != gptFallbackContextWindow {
		t.Fatalf("precondition: name-based fallback = %d, want %d", got, gptFallbackContextWindow)
	}

	recordModelTokenLimits([]ModelInfo{modelInfoWithInputLimit("gpt-5.6-sol", 272_000)})

	if got := getContextWindowSize("gpt-5.6-sol"); got != 272_000 {
		t.Fatalf("getContextWindowSize = %d, want the upstream-reported 272000", got)
	}
}

// The reported window is what makes the compaction loop possible: at a fixed
// upstream usage percentage, an inflated window inflates the reported token
// count by the same ratio no matter how much the client compacts. 1M against a
// ~256K reality is the inflation that ran overnight.
func TestReportedInputTokensTrackWindow(t *testing.T) {
	clearModelTokenLimits(t)

	const pct = 30.0
	reportedAt := func(window int) int { return int(pct * float64(window) / 100.0) }

	honest := reportedAt(getContextWindowSize("gpt-5.6-sol"))
	if want := reportedAt(gptFallbackContextWindow); honest != want {
		t.Fatalf("reported input tokens at %.0f%% = %d, want %d", pct, honest, want)
	}
	if inflated := reportedAt(1_000_000); inflated <= honest {
		t.Fatalf("expected the old 1M assumption (%d) to over-report vs %d", inflated, honest)
	}
}

func TestGetContextWindowSizeIsCaseInsensitive(t *testing.T) {
	clearModelTokenLimits(t)
	recordModelTokenLimits([]ModelInfo{modelInfoWithInputLimit("GPT-5.6-Sol", 272_000)})

	if got := getContextWindowSize("gpt-5.6-sol"); got != 272_000 {
		t.Fatalf("getContextWindowSize = %d, want 272000 regardless of ID casing", got)
	}
}

// An unusable or absent limit must not shrink the window to zero: dividing by
// it downstream, or reporting 0 tokens, is worse than the imperfect guess.
func TestGetContextWindowSizeFallsBackWhenLimitUnusable(t *testing.T) {
	clearModelTokenLimits(t)

	recordModelTokenLimits([]ModelInfo{
		{ModelId: "claude-sonnet-4.5"},                // nil TokenLimits
		modelInfoWithInputLimit("claude-opus-4.6", 0), // zero limit
		modelInfoWithInputLimit("", 500_000),          // empty ID
	})

	if got := getContextWindowSize("claude-sonnet-4.5"); got != 200_000 {
		t.Fatalf("nil TokenLimits: got %d, want the 200000 fallback", got)
	}
	if got := getContextWindowSize("claude-opus-4.6"); got != 1_000_000 {
		t.Fatalf("zero limit: got %d, want the 1000000 fallback", got)
	}
	if got := getContextWindowSize("never-refreshed-model"); got != 200_000 {
		t.Fatalf("unknown model: got %d, want the 200000 fallback", got)
	}
}

// The payload budget must track the window it is derived from, so a client is
// never told it has room that truncation then takes away.
func TestMaxPayloadBytesForModelTracksUpstreamLimit(t *testing.T) {
	clearModelTokenLimits(t)
	recordModelTokenLimits([]ModelInfo{modelInfoWithInputLimit("gpt-5.6-sol", 272_000)})

	want := int(272_000*payloadTokenHeadroom) * payloadBytesPerToken
	if got := maxPayloadBytesForModel("gpt-5.6-sol"); got != want {
		t.Fatalf("budget = %d, want %d (derived from the reported window)", got, want)
	}
}

// The 1M tier must come out at exactly the 3.6MB it ran on before the budget
// was derived from the window rather than from its own constant.
func TestMaxPayloadBytesForModelPreservesLargeTier(t *testing.T) {
	clearModelTokenLimits(t)

	const want = 900_000 * payloadBytesPerToken
	if got := maxPayloadBytesForModel("claude-opus-4.6"); got != want {
		t.Fatalf("budget = %d, want the unchanged %d for the 1M tier", got, want)
	}
}

// A 200K-tier model keeps its existing budget: the floor is what today's working
// models run on, so deriving from the window cannot tighten them.
func TestMaxPayloadBytesForModelLeavesSmallTierAlone(t *testing.T) {
	clearModelTokenLimits(t)
	recordModelTokenLimits([]ModelInfo{modelInfoWithInputLimit("claude-sonnet-4.5", 200_000)})

	if got := maxPayloadBytesForModel("claude-sonnet-4.5"); got != maxPayloadBytes {
		t.Fatalf("budget = %d, want the unchanged %d for the 200K tier", got, maxPayloadBytes)
	}
}
