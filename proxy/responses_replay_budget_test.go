package proxy

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"kiro-go/config"
)

// bulkText returns filler of roughly the requested token size, used to build
// ancestors large enough to exercise the replay budget.
func bulkText(tag string, approxTokens int) string {
	unit := tag + " lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod. "
	var b strings.Builder
	for estimateApproxTokens(b.String()) < approxTokens {
		b.WriteString(unit)
	}
	return b.String()
}

// storeChain writes a linear previous_response_id chain of n responses, each
// carrying roughly tokensPerTurn tokens of input and the same of output, and
// returns the newest.
func storeChain(t *testing.T, n, tokensPerTurn int) *ResponsesObject {
	t.Helper()
	cfgFile := filepath.Join(t.TempDir(), "config.json")
	if err := config.Init(cfgFile); err != nil {
		t.Fatalf("config.Init: %v", err)
	}

	var newest *ResponsesObject
	prevID := ""
	for i := 0; i < n; i++ {
		in, err := json.Marshal(fmt.Sprintf("turn %d user: %s", i, bulkText(fmt.Sprintf("t%d", i), tokensPerTurn)))
		if err != nil {
			t.Fatalf("marshal input: %v", err)
		}
		obj := &ResponsesObject{
			ID:                 fmt.Sprintf("resp_chain_%d", i),
			Object:             "response",
			Status:             "completed",
			Model:              "gpt-5.6-sol",
			StoredInput:        json.RawMessage(in),
			PreviousResponseID: prevID,
			Output: []ResponseOutputItem{{
				Type: "message", Role: "assistant",
				Content: []ResponseContentPart{{
					Type: "output_text",
					Text: fmt.Sprintf("turn %d assistant: %s", i, bulkText("a", tokensPerTurn)),
				}},
			}},
		}
		if err := saveResponse(obj); err != nil {
			t.Fatalf("save turn %d: %v", i, err)
		}
		prevID = obj.ID
		newest = obj
	}
	return newest
}

func replayTokens(messages []OpenAIMessage) int {
	return estimateReplayGroupTokens(messages)
}

// The regression this whole change exists for. A client that compacts sends a
// short summary as its new input while previous_response_id still points at the
// pre-compaction response. With an unbounded replay, every turn the client just
// discarded is read back off disk and prepended, so the post-compaction request
// is no smaller than the one before it — the client sees a still-full context and
// compacts again, forever. Bounding the replay is what makes compaction reduce
// the request size.
func TestReplayBudgetLetsCompactionShrinkTheRequest(t *testing.T) {
	clearModelTokenLimits(t)
	newest := storeChain(t, 24, 4_000)

	replayed := expandPreviousResponseHistory(newest, "gpt-5.6-sol")

	window := getContextWindowSize("gpt-5.6-sol")
	budget := maxReplayHistoryTokens("gpt-5.6-sol")
	got := replayTokens(replayed)

	if got > budget {
		t.Fatalf("replayed %d tokens, over the %d budget", got, budget)
	}
	// The headroom is the point: what is left must be usable by the client's own
	// input, or compaction has nowhere to land.
	if got >= window {
		t.Fatalf("replay filled the whole %d-token window (%d); compaction cannot shrink this", window, got)
	}
}

// Unbounded replay would exceed the window on this chain. Verify the fixture is
// actually large enough to be a real test of the bound rather than a chain that
// fits anyway.
func TestReplayBudgetFixtureWouldOverflowUnbounded(t *testing.T) {
	clearModelTokenLimits(t)
	newest := storeChain(t, 24, 4_000)

	chain := collectAncestorChain(newest)
	unbounded := 0
	for _, node := range chain {
		group := make([]OpenAIMessage, 0, 4)
		if prior, err := parseResponsesInput(node.StoredInput); err == nil {
			group = append(group, prior...)
		}
		group = append(group, outputToMessages(node.Output)...)
		unbounded += estimateReplayGroupTokens(group)
	}

	budget := maxReplayHistoryTokens("gpt-5.6-sol")
	if unbounded <= budget {
		t.Fatalf("fixture too small to test the bound: unbounded=%d, budget=%d", unbounded, budget)
	}
}

// Trimming keeps the newest turns: they are what the current message responds
// to. Dropping those instead would break the conversation outright.
func TestReplayBudgetKeepsNewestTurnsAndMarksElision(t *testing.T) {
	clearModelTokenLimits(t)
	newest := storeChain(t, 24, 4_000)

	replayed := expandPreviousResponseHistory(newest, "gpt-5.6-sol")

	joined := ""
	for _, m := range replayed {
		if s, ok := m.Content.(string); ok {
			joined += s + "\n"
		}
	}

	if !strings.Contains(joined, "turn 23 user") {
		t.Fatal("newest turn missing from replay")
	}
	if strings.Contains(joined, "turn 0 user") {
		t.Fatal("oldest turn should have been trimmed")
	}
	if !strings.Contains(joined, replayTruncationNote) {
		t.Fatal("elision not marked; the model would read a conversation starting mid-thought")
	}
}

// A short chain must pass through untouched, so this bound cannot disturb the
// ordinary multi-turn sessions that work today.
func TestReplayBudgetLeavesShortChainsIntact(t *testing.T) {
	clearModelTokenLimits(t)
	newest := storeChain(t, 3, 50)

	replayed := expandPreviousResponseHistory(newest, "gpt-5.6-sol")

	for _, m := range replayed {
		if s, ok := m.Content.(string); ok && strings.Contains(s, replayTruncationNote) {
			t.Fatal("short chain should not be trimmed")
		}
	}
	joined := ""
	for _, m := range replayed {
		if s, ok := m.Content.(string); ok {
			joined += s
		}
	}
	for _, want := range []string{"turn 0 user", "turn 1 user", "turn 2 user"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("short chain lost %q", want)
		}
	}
}

// The budget tracks the model window, so a larger window replays more history.
func TestReplayBudgetScalesWithWindow(t *testing.T) {
	clearModelTokenLimits(t)
	newest := storeChain(t, 24, 4_000)

	small := replayTokens(expandPreviousResponseHistory(newest, "gpt-5.6-sol"))
	large := replayTokens(expandPreviousResponseHistory(newest, "claude-opus-4.6"))

	if large <= small {
		t.Fatalf("1M-window model replayed %d tokens, expected more than the 256K model's %d", large, small)
	}
}

// Trimming must not strand a tool result from the assistant call it answers:
// an ancestor's tool_calls live in its output while the results arrive in the
// next ancestor's input, so a cut between them leaves an unpaired result that
// Kiro rejects outright.
func TestReplayTrimDropsOrphanedToolResults(t *testing.T) {
	messages := []OpenAIMessage{
		{Role: "tool", Content: "orphaned result", ToolCallID: "call_gone"},
		{Role: "user", Content: "next question"},
		{Role: "assistant", Content: "", ToolCalls: []ToolCall{{ID: "call_kept", Type: "function"}}},
		{Role: "tool", Content: "paired result", ToolCallID: "call_kept"},
	}

	out := dropOrphanedLeadingToolMessages(messages)

	if len(out) != 3 {
		t.Fatalf("expected the orphan dropped, got %d messages: %+v", len(out), out)
	}
	if out[0].Role == "tool" {
		t.Fatalf("replay still starts with an unpaired tool result: %+v", out[0])
	}
	if out[len(out)-1].ToolCallID != "call_kept" {
		t.Fatalf("paired tool result was dropped: %+v", out)
	}
}

// A single ancestor larger than the whole budget is still replayed rather than
// dropped to nothing: dropping it would discard the turn the current message is
// answering, and the byte-level truncation downstream still enforces the real
// limit.
func TestReplayBudgetKeepsNewestGroupEvenIfOversized(t *testing.T) {
	groups := [][]OpenAIMessage{
		{{Role: "user", Content: bulkText("old", 5_000)}},
		{{Role: "user", Content: bulkText("newest", 50_000)}},
	}

	out := flattenReplayGroups(groups, 1_000)

	joined := ""
	for _, m := range out {
		if s, ok := m.Content.(string); ok {
			joined += s
		}
	}
	if !strings.Contains(joined, "newest") {
		t.Fatal("newest group must survive even when it alone exceeds the budget")
	}
	if strings.Contains(joined, "old ") {
		t.Fatal("older group should still have been dropped")
	}
}
