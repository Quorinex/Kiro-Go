package proxy

import (
	"fmt"
	"strings"
	"testing"
)

// TestNoToolInvocationTextInAssistantHistory is a regression guard for the
// few-shot pollution bug: when historical tool calls were narrated as
// "[Called tool X with input ...]" inside assistant turns, the model learned to
// emit that literal text instead of issuing real structured tool calls.
//
// After the fix, assistant history turns must never contain tool-invocation
// syntax. Tool identity is attributed only on the user "Tool results" side.
func TestNoToolInvocationTextInAssistantHistory(t *testing.T) {
	// Build a long OpenAI conversation with many completed tool cycles.
	msgs := []OpenAIMessage{{Role: "user", Content: "start a multi-step task"}}
	for i := 0; i < 8; i++ {
		msgs = append(msgs,
			OpenAIMessage{Role: "assistant", Content: "", ToolCalls: []ToolCall{
				newPollToolCall(fmt.Sprintf("call_%d", i), "exec_command", fmt.Sprintf(`{"cmd":"step %d"}`, i)),
			}},
			OpenAIMessage{Role: "tool", ToolCallID: fmt.Sprintf("call_%d", i), Content: fmt.Sprintf("OUTPUT_%d", i)},
			OpenAIMessage{Role: "user", Content: fmt.Sprintf("continue %d", i)},
		)
	}
	msgs = append(msgs, OpenAIMessage{Role: "user", Content: "summarize"})

	payload := OpenAIToKiro(&OpenAIRequest{Model: "claude-opus-4.8", Messages: msgs}, false)

	for i, h := range payload.ConversationState.History {
		a := h.AssistantResponseMessage
		if a == nil {
			continue
		}
		// No assistant turn may contain tool-invocation-looking text.
		for _, bad := range []string{"[Called tool", "Called tool ", "with input {"} {
			if strings.Contains(a.Content, bad) {
				t.Fatalf("history[%d] assistant content contains mimicable tool text %q: %q", i, bad, a.Content)
			}
		}
		// No assistant turn may carry structured tool calls (rejected upstream).
		if len(a.ToolUses) > 0 {
			t.Fatalf("history[%d] assistant retains %d structured toolUses", i, len(a.ToolUses))
		}
	}

	// Tool outputs must still be preserved (on the user side) for context.
	var allText strings.Builder
	for _, h := range payload.ConversationState.History {
		if h.UserInputMessage != nil {
			allText.WriteString(h.UserInputMessage.Content)
			allText.WriteString("\n")
		}
	}
	combined := allText.String()
	for i := 0; i < 8; i++ {
		marker := fmt.Sprintf("OUTPUT_%d", i)
		if !strings.Contains(combined, marker) {
			t.Fatalf("tool output %q lost from history", marker)
		}
	}
	// Tool identity should be attributed on the user side.
	if !strings.Contains(combined, "[exec_command]") {
		t.Fatalf("expected tool results attributed to exec_command on the user side")
	}
}

func newPollToolCall(id, name, args string) ToolCall {
	tc := ToolCall{ID: id, Type: "function"}
	tc.Function.Name = name
	tc.Function.Arguments = args
	return tc
}
