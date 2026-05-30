package proxy

import (
	"encoding/json"
	"testing"
)

// TestResponsesParallelToolCallsMerge verifies that consecutive function_call
// items in the Responses API input are merged into a single assistant message
// so parallel tool calls stay grouped. Previously each parallel call became its
// own assistant turn, which split the tool_use/tool_result pairing and caused
// Kiro to reject the request with HTTP 400 "Improperly formed request".
func TestResponsesParallelToolCallsMerge(t *testing.T) {
	items := []json.RawMessage{
		mustRaw(`{"type":"message","role":"user","content":[{"type":"input_text","text":"run two commands"}]}`),
		mustRaw(`{"type":"function_call","call_id":"call_a","name":"exec_command","arguments":"{\"cmd\":\"ls\"}"}`),
		mustRaw(`{"type":"function_call","call_id":"call_b","name":"exec_command","arguments":"{\"cmd\":\"pwd\"}"}`),
		mustRaw(`{"type":"function_call_output","call_id":"call_a","output":"file1"}`),
		mustRaw(`{"type":"function_call_output","call_id":"call_b","output":"/home"}`),
	}

	msgs, err := convertResponsesInputItems(items)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}

	// Find the assistant message; it must contain BOTH tool calls.
	var asstToolCalls int
	for _, m := range msgs {
		if m.Role == "assistant" && len(m.ToolCalls) > 0 {
			asstToolCalls = len(m.ToolCalls)
		}
	}
	if asstToolCalls != 2 {
		t.Fatalf("expected 2 merged tool calls in one assistant message, got %d", asstToolCalls)
	}

	// Count assistant messages carrying tool calls; must be exactly 1 (merged).
	asstWithCalls := 0
	for _, m := range msgs {
		if m.Role == "assistant" && len(m.ToolCalls) > 0 {
			asstWithCalls++
		}
	}
	if asstWithCalls != 1 {
		t.Fatalf("expected parallel calls merged into 1 assistant message, got %d", asstWithCalls)
	}
}

func mustRaw(s string) json.RawMessage {
	return json.RawMessage(s)
}
