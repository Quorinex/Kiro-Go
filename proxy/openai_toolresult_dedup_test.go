package proxy

import (
	"strings"
	"testing"
)

// TestOpenAIToKiroDoesNotDuplicateToolResultText reproduces the bug where a
// non-final tool-result history entry was pre-filled with the
// "Tool results:" continuation text AND kept the structured ToolResults, which
// sanitizeKiroHistory then narrated again, producing the same output twice.
// Each tool result's output must appear exactly once in history.
func TestOpenAIToKiroDoesNotDuplicateToolResultText(t *testing.T) {
	req := &OpenAIRequest{
		Model: "claude-opus-4.8",
		Messages: []OpenAIMessage{
			{Role: "user", Content: "run it"},
			{Role: "assistant", Content: "", ToolCalls: []ToolCall{newToolCall("call_1", "exec_command", `{"cmd":"ls"}`)}},
			{Role: "tool", ToolCallID: "call_1", Content: "UNIQUE_OUTPUT_MARKER_12345"},
			{Role: "user", Content: "now summarize"},
		},
	}

	payload := OpenAIToKiro(req, false)

	count := 0
	for _, h := range payload.ConversationState.History {
		if h.UserInputMessage != nil {
			count += strings.Count(h.UserInputMessage.Content, "UNIQUE_OUTPUT_MARKER_12345")
		}
		if h.AssistantResponseMessage != nil {
			count += strings.Count(h.AssistantResponseMessage.Content, "UNIQUE_OUTPUT_MARKER_12345")
		}
	}
	if count != 1 {
		t.Fatalf("expected tool result output to appear exactly once in history, got %d", count)
	}
}

func newToolCall(id, name, args string) ToolCall {
	tc := ToolCall{ID: id, Type: "function"}
	tc.Function.Name = name
	tc.Function.Arguments = args
	return tc
}
