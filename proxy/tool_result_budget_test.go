package proxy

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// buildToolResultOfSize returns one tool result whose text is approximately
// sizeKB kilobytes, shaped like real tool output (a file read or test log).
func buildToolResultOfSize(id string, sizeKB int) KiroToolResult {
	line := "some source code line that a Read tool would return\n"
	body := strings.Repeat(line, sizeKB*1024/len(line)+1)
	return KiroToolResult{
		ToolUseID: id,
		Content:   []KiroResultContent{{Text: body}},
		Status:    "success",
	}
}

// A 32KB tool result used to arrive at the model cut to its first 4000 bytes by
// a hardcoded cap. That cap is the reported bug: when the structured toolResults
// are not attached (the normal case whenever a client answers only part of a
// parallel tool batch) this text is the only carrier of tool output, so the model
// saw an eighth of a test log and had no way to know more existed.
func TestBuildToolResultsContinuationKeepsLargeOutputWithinModelBudget(t *testing.T) {
	result := buildToolResultOfSize("toolu_1", 32)
	rendered := buildToolResultsContinuation([]KiroToolResult{result}, "claude-sonnet-4.5")

	if len(rendered) <= 4000 {
		t.Fatalf("32KB of tool output was cut to %d bytes; the old hardcoded 4000-byte cap is still in force", len(rendered))
	}
	if !strings.Contains(rendered, toolResultsContinuationPrefix) {
		t.Fatalf("rendered output lost its %q prefix", toolResultsContinuationPrefix)
	}
	// Well within a 200K model's share, so nothing should have been cut at all.
	if strings.Contains(rendered, "[Tool output truncated") {
		t.Fatalf("32KB fits the budget and must not be truncated")
	}
	if want := len(result.Content[0].Text); !strings.Contains(rendered, result.Content[0].Text[:want-1]) {
		t.Fatalf("tool output body was altered")
	}
}

// The cap must still be a cap. Past the model's share the text is trimmed, and
// the trim has to be visible: output that simply stops looks complete to the
// model, which then acts on a partial view of a file or test run.
func TestBuildToolResultsContinuationTruncatesPastBudgetWithMarker(t *testing.T) {
	model := "claude-sonnet-4.5"
	limit := maxToolResultsContinuationBytes(model)

	oversized := buildToolResultOfSize("toolu_1", limit/1024+64)
	rendered := buildToolResultsContinuation([]KiroToolResult{oversized}, model)

	if len(rendered) > limit {
		t.Fatalf("rendered %d bytes exceeds the model's tool-result budget %d", len(rendered), limit)
	}
	if !strings.Contains(rendered, "[Tool output truncated") {
		t.Fatalf("a truncated tool result must say so; the model cannot otherwise tell output was cut")
	}
}

// A large-context model gets a larger share, because its payload budget is
// larger. The two must not be pinned to the same constant, which is what made
// the old cap wrong for every model at once.
func TestToolResultBudgetTracksModelContextWindow(t *testing.T) {
	small := maxToolResultsContinuationBytes("claude-sonnet-4.5")
	large := maxToolResultsContinuationBytes("claude-opus-4.8")

	if large <= small {
		t.Fatalf("large-context model budget %d must exceed the 200K model budget %d", large, small)
	}
	if small <= 4000 {
		t.Fatalf("even the smallest budget %d should beat the old hardcoded 4000 bytes", small)
	}
}

// Cutting on a raw byte index splits multi-byte characters, and the partial
// sequence JSON-encodes as U+FFFD. Chinese tool output hits this on almost every
// cut, so the tail of a truncated result would arrive corrupted.
func TestBuildToolResultsContinuationCutsOnRuneBoundary(t *testing.T) {
	model := "claude-sonnet-4.5"
	limit := maxToolResultsContinuationBytes(model)

	// Every rune here is 3 bytes, so a byte-index cut lands mid-rune with
	// probability 2/3.
	chinese := strings.Repeat("这是工具返回的一行中文输出内容\n", limit/10)
	rendered := buildToolResultsContinuation([]KiroToolResult{{
		ToolUseID: "toolu_1",
		Content:   []KiroResultContent{{Text: chinese}},
		Status:    "success",
	}}, model)

	if !utf8.ValidString(rendered) {
		t.Fatalf("truncated Chinese tool output is not valid UTF-8; a rune was split")
	}
	if !strings.ContainsRune(rendered, '这') {
		t.Fatalf("Chinese tool output did not survive rendering")
	}
}

// truncateStringAtRuneBoundary is the primitive the above relies on; check its
// edges directly since a mid-rune budget is exactly the interesting case.
func TestTruncateStringAtRuneBoundary(t *testing.T) {
	s := "中文abc" // 3+3+1+1+1 = 9 bytes

	for _, tc := range []struct {
		budget int
		want   string
	}{
		{0, ""},
		{-1, ""},
		{1, ""},      // mid first rune
		{2, ""},      // still mid first rune
		{3, "中"},     // exactly one rune
		{4, "中"},     // mid second rune
		{6, "中文"},    // exactly two runes
		{7, "中文a"},   // plus ASCII
		{9, "中文abc"}, // whole string
		{99, "中文abc"},
	} {
		if got := truncateStringAtRuneBoundary(s, tc.budget); got != tc.want {
			t.Fatalf("truncateStringAtRuneBoundary(%q, %d) = %q, want %q", s, tc.budget, got, tc.want)
		}
		if got := truncateStringAtRuneBoundary(s, tc.budget); !utf8.ValidString(got) {
			t.Fatalf("budget %d produced invalid UTF-8 %q", tc.budget, got)
		}
	}
}

// End-to-end: a Claude Code style turn carrying a large tool result must reach
// the payload with its output substantially intact, not clipped to 4KB.
func TestClaudeToKiroCarriesLargeToolResultText(t *testing.T) {
	req := &ClaudeRequest{
		Model:  "claude-sonnet-4.5",
		System: "You are Claude Code.",
		Messages: []ClaudeMessage{
			{Role: "user", Content: "run the tests"},
			{Role: "assistant", Content: []interface{}{
				map[string]interface{}{"type": "tool_use", "id": "toolu_1", "name": "Bash", "input": map[string]interface{}{"command": "go test ./..."}},
			}},
			{Role: "user", Content: []interface{}{
				// tool_use_id deliberately does not answer toolu_1, so the
				// structured toolResults are dropped and this text is the only
				// carrier of the output — the case the old cap silently gutted.
				map[string]interface{}{"type": "tool_result", "tool_use_id": "toolu_other", "content": buildToolResultOfSize("x", 32).Content[0].Text},
			}},
		},
	}

	payload := ClaudeToKiro(req, false)
	content := payload.ConversationState.CurrentMessage.UserInputMessage.Content

	if len(content) <= 4000 {
		t.Fatalf("current message carries only %d bytes of a 32KB tool result", len(content))
	}
	if !utf8.ValidString(content) {
		t.Fatalf("current message is not valid UTF-8")
	}
}
