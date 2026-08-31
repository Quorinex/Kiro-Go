package proxy

import (
	"encoding/json"
	"strings"
	"testing"
)

// buildOversizedConversation returns a conversation whose serialized history is
// far larger than the 200K-model budget. turns controls the total size: each
// turn contributes roughly 4KB across its assistant/user pair.
func buildOversizedConversation(turns int) []ClaudeMessage {
	big := strings.Repeat("lorem ipsum dolor sit amet ", 80) // ~2.1KB

	msgs := []ClaudeMessage{
		{Role: "user", Content: "start the long task"},
	}
	for i := 0; i < turns; i++ {
		msgs = append(msgs,
			ClaudeMessage{Role: "assistant", Content: "step result: " + big},
			ClaudeMessage{Role: "user", Content: "next: " + big},
		)
	}
	return append(msgs, ClaudeMessage{Role: "user", Content: "FINAL: summarize everything above"})
}

// TestClaudeToKiroTruncatesOversizedHistory verifies that a conversation past
// the model's payload budget is trimmed below that budget, that a placeholder
// records the elision, and that the current message and system priming survive.
//
// The model here has a 200K context window, so the budget is the smaller one;
// see TestClaudeToKiroLargeContextModelKeepsHistoryUnderBudget for the 1M case.
func TestClaudeToKiroTruncatesOversizedHistory(t *testing.T) {
	req := &ClaudeRequest{
		Model:    "claude-sonnet-4.5",
		System:   "You are a helpful assistant.",
		Messages: buildOversizedConversation(800),
	}

	payload := ClaudeToKiro(req, false)

	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	limit := maxPayloadBytesForModel(currentMessageModelID(payload))
	if len(raw) > limit {
		t.Fatalf("payload size %d exceeds limit %d after truncation", len(raw), limit)
	}

	// The current message must be preserved.
	cur := payload.ConversationState.CurrentMessage.UserInputMessage
	if !strings.Contains(cur.Content, "FINAL: summarize everything above") {
		t.Fatalf("current message lost after truncation, got %q", cur.Content[:min(80, len(cur.Content))])
	}

	// A truncation placeholder must be present in history.
	foundPlaceholder := false
	for _, h := range payload.ConversationState.History {
		if h.UserInputMessage != nil && strings.Contains(h.UserInputMessage.Content, "truncated to fit") {
			foundPlaceholder = true
			break
		}
	}
	if !foundPlaceholder {
		t.Fatalf("expected a truncation placeholder in history")
	}

	// System priming should still be at the front.
	if len(payload.ConversationState.History) < 2 {
		t.Fatalf("expected priming retained, history too short")
	}
	primingUser := payload.ConversationState.History[0].UserInputMessage
	if primingUser == nil || !strings.Contains(primingUser.Content, "helpful assistant") {
		t.Fatalf("expected system priming retained at front")
	}
}

// TestClaudeToKiroLargeContextModelKeepsHistoryUnderBudget covers the reported
// bug: the byte budget used to be a single constant sized for 200K models, so a
// conversation well within a 1M-token window was truncated at roughly a quarter
// of the context the upstream would have accepted. The same history that the
// 200K model above has to truncate must survive intact here.
func TestClaudeToKiroLargeContextModelKeepsHistoryUnderBudget(t *testing.T) {
	messages := buildOversizedConversation(800)

	small := ClaudeToKiro(&ClaudeRequest{
		Model:    "claude-sonnet-4.5",
		System:   "You are a helpful assistant.",
		Messages: messages,
	}, false)
	large := ClaudeToKiro(&ClaudeRequest{
		Model:    "claude-opus-4.6",
		System:   "You are a helpful assistant.",
		Messages: messages,
	}, false)

	for _, h := range large.ConversationState.History {
		if h.UserInputMessage != nil && strings.Contains(h.UserInputMessage.Content, "truncated to fit") {
			t.Fatalf("large-context model should not truncate a history this size")
		}
	}

	if len(large.ConversationState.History) <= len(small.ConversationState.History) {
		t.Fatalf("large-context model kept %d history turns, expected more than the %d kept for a 200K model",
			len(large.ConversationState.History), len(small.ConversationState.History))
	}

	cur := large.ConversationState.CurrentMessage.UserInputMessage
	if !strings.Contains(cur.Content, "FINAL: summarize everything above") {
		t.Fatalf("current message lost, got %q", cur.Content[:min(80, len(cur.Content))])
	}
}

// TestClaudeToKiroLargeContextModelStillTruncatesPastItsOwnBudget ensures the
// raised budget is still a budget: a conversation past the large-context limit
// must be trimmed rather than forwarded for the upstream to reject.
func TestClaudeToKiroLargeContextModelStillTruncatesPastItsOwnBudget(t *testing.T) {
	req := &ClaudeRequest{
		Model:    "claude-opus-4.6",
		System:   "You are a helpful assistant.",
		Messages: buildOversizedConversation(1400),
	}

	payload := ClaudeToKiro(req, false)

	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	limit := maxPayloadBytesForModel(currentMessageModelID(payload))
	if len(raw) > limit {
		t.Fatalf("payload size %d exceeds large-context limit %d after truncation", len(raw), limit)
	}
	if limit <= maxPayloadBytes {
		t.Fatalf("expected a larger budget for a 1M model, got %d", limit)
	}
}

// TestClaudeToKiroSmallPayloadNotTruncated ensures normal-sized conversations
// are left untouched (no placeholder inserted).
func TestClaudeToKiroSmallPayloadNotTruncated(t *testing.T) {
	req := &ClaudeRequest{
		Model:  "claude-opus-4.8",
		System: "You are helpful.",
		Messages: []ClaudeMessage{
			{Role: "user", Content: "hello"},
			{Role: "assistant", Content: "hi"},
			{Role: "user", Content: "how are you?"},
		},
	}
	payload := ClaudeToKiro(req, false)
	for _, h := range payload.ConversationState.History {
		if h.UserInputMessage != nil && strings.Contains(h.UserInputMessage.Content, "truncated to fit") {
			t.Fatalf("small payload should not be truncated")
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
