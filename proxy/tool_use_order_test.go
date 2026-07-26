package proxy

import (
	"bytes"
	"testing"
)

// A fragment without toolUseId opens a synthetic entry; when the real id arrives
// it must adopt that entry in place rather than appending a second one at the
// end of the arrival order.
func TestParseEventStreamRekeyKeepsArrivalPosition(t *testing.T) {
	var stream bytes.Buffer
	frame := func(payload map[string]interface{}) {
		stream.Write(awsEventStreamFrame(t, "toolUseEvent", payload))
	}
	frame(map[string]interface{}{"name": "first_tool", "input": `{"k":`})
	frame(map[string]interface{}{"toolUseId": "real_first", "name": "first_tool", "input": `1}`})
	frame(map[string]interface{}{"toolUseId": "second", "name": "second_tool", "input": `{"k":2}`})

	var order []string
	if err := parseEventStream(bytes.NewReader(stream.Bytes()), &KiroStreamCallback{
		OnToolUse: func(tu KiroToolUse) { order = append(order, tu.ToolUseID) },
	}); err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	if len(order) != 2 {
		t.Fatalf("expected 2 tool calls, got %d: %v", len(order), order)
	}
	if order[0] != "real_first" || order[1] != "second" {
		t.Fatalf("rekey lost arrival position: got %v, want [real_first second]", order)
	}
}
