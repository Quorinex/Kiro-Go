package proxy

// Regression coverage for the three stream-drop failure modes.
// Each case asserts the user-facing symptom so the suite goes red on a
// regression and green once the stream parser is correct.

import (
	"bytes"
	"errors"
	"testing"
)

// Truncation is undetectable when metadataEvent.stopReason is ignored:
// content arrives, the body ends, parseEventStream returns nil and fires
// OnComplete. Callers cannot tell this from a complete response.
// Kiro IDE retries on "content>0 && stopReason === undefined".
func TestParseEventStreamReportsStopReasonFromMetadata(t *testing.T) {
	var stream bytes.Buffer
	stream.Write(awsEventStreamFrame(t, "assistantResponseEvent",
		map[string]interface{}{"content": "Let me check that file"}))
	stream.Write(awsEventStreamFrame(t, "metadataEvent",
		map[string]interface{}{"stopReason": "end_turn"}))

	var text, reason string
	completed := false
	err := parseEventStream(bytes.NewReader(stream.Bytes()), &KiroStreamCallback{
		OnText:       func(s string, _ bool) { text += s },
		OnStopReason: func(r string) { reason = r },
		OnComplete:   func(_, _ int) { completed = true },
	})
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if text != "Let me check that file" {
		t.Fatalf("text = %q", text)
	}
	if reason != "end_turn" {
		t.Fatalf("stopReason = %q, want end_turn", reason)
	}
	if !completed {
		t.Fatal("expected OnComplete")
	}
}

// A truncated stream (content, no stopReason) must leave OnStopReason unset so
// callers can detect truncation. parseEventStream itself still returns nil —
// the signal is the missing callback, not an error.
func TestParseEventStreamTruncationLeavesStopReasonEmpty(t *testing.T) {
	var stream bytes.Buffer
	stream.Write(awsEventStreamFrame(t, "assistantResponseEvent",
		map[string]interface{}{"content": "Let me check that file"}))

	var reason string
	sawStop := false
	err := parseEventStream(bytes.NewReader(stream.Bytes()), &KiroStreamCallback{
		OnText: func(s string, _ bool) {},
		OnStopReason: func(r string) {
			sawStop = true
			reason = r
		},
	})
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if sawStop {
		t.Fatalf("truncated stream must not fire OnStopReason, got %q", reason)
	}
}

// Interleaved parallel tool-call frames must each emit exactly once with
// correct args. The previous single-slot state machine force-finished the
// previous tool on every id change, so the client executed the same tool
// multiple times.
func TestParseEventStreamInterleavedParallelToolCallsEmitOnce(t *testing.T) {
	var stream bytes.Buffer
	frame := func(payload map[string]interface{}) {
		stream.Write(awsEventStreamFrame(t, "toolUseEvent", payload))
	}
	frame(map[string]interface{}{"toolUseId": "call_A", "name": "read_file"})
	frame(map[string]interface{}{"toolUseId": "call_B", "name": "list_dir"})
	frame(map[string]interface{}{"toolUseId": "call_A", "name": "read_file", "input": `{"path":"a.go"}`})
	frame(map[string]interface{}{"toolUseId": "call_B", "name": "list_dir", "input": `{"path":"/tmp"}`})
	frame(map[string]interface{}{"toolUseId": "call_B", "name": "list_dir", "stop": true})

	got := map[string]map[string]interface{}{}
	var order []string
	if err := parseEventStream(bytes.NewReader(stream.Bytes()), &KiroStreamCallback{
		OnToolUse: func(tu KiroToolUse) {
			got[tu.ToolUseID] = tu.Input
			order = append(order, tu.ToolUseID)
		},
	}); err != nil {
		t.Fatalf("parse: %v", err)
	}

	if len(order) != 2 {
		t.Fatalf("expected each tool emitted once (2 total), got %d: %v", len(order), order)
	}
	if p, _ := got["call_A"]["path"].(string); p != "a.go" {
		t.Fatalf("call_A input=%v, want path=a.go", got["call_A"])
	}
	if p, _ := got["call_B"]["path"].(string); p != "/tmp" {
		t.Fatalf("call_B input=%v, want path=/tmp", got["call_B"])
	}
}

// Incomplete tool argument JSON must not be emitted as empty input.
// finishToolUse used to discard the Unmarshal error and substitute {}, so the
// client executed a parameterless tool call.
func TestParseEventStreamDropsIncompleteToolArgs(t *testing.T) {
	var stream bytes.Buffer
	frame := func(payload map[string]interface{}) {
		stream.Write(awsEventStreamFrame(t, "toolUseEvent", payload))
	}
	frame(map[string]interface{}{"toolUseId": "call_X", "name": "write_file"})
	frame(map[string]interface{}{"toolUseId": "call_X", "name": "write_file", "input": `{"path":"main.go",`})
	frame(map[string]interface{}{"toolUseId": "call_X", "name": "write_file", "input": `"content":"pack`})
	// EOF: no stop frame, incomplete JSON.

	var emitted []KiroToolUse
	err := parseEventStream(bytes.NewReader(stream.Bytes()), &KiroStreamCallback{
		OnToolUse: func(tu KiroToolUse) { emitted = append(emitted, tu) },
	})
	if !errors.Is(err, errIncompleteToolUse) {
		t.Fatalf("parse error = %v, want incomplete tool error", err)
	}
	if len(emitted) != 0 {
		t.Fatalf("expected incomplete tool args to be dropped, got %d: %+v", len(emitted), emitted)
	}
}

func TestParseEventStreamRejectsToolWithoutInput(t *testing.T) {
	frame := awsEventStreamFrame(t, "toolUseEvent", map[string]interface{}{
		"toolUseId": "call_missing", "name": "write_file", "stop": true,
	})
	var emitted []KiroToolUse
	err := parseEventStream(bytes.NewReader(frame), &KiroStreamCallback{
		OnToolUse: func(tu KiroToolUse) { emitted = append(emitted, tu) },
	})
	if !errors.Is(err, errIncompleteToolUse) {
		t.Fatalf("parse error = %v, want missing-input tool error", err)
	}
	if len(emitted) != 0 {
		t.Fatalf("tool without input must not be emitted: %+v", emitted)
	}
}

func TestParseEventStreamAcceptsExplicitEmptyToolInput(t *testing.T) {
	frame := awsEventStreamFrame(t, "toolUseEvent", map[string]interface{}{
		"toolUseId": "call_empty", "name": "list_items", "input": `{}`, "stop": true,
	})
	var emitted []KiroToolUse
	if err := parseEventStream(bytes.NewReader(frame), &KiroStreamCallback{
		OnToolUse: func(tu KiroToolUse) { emitted = append(emitted, tu) },
	}); err != nil {
		t.Fatalf("parse explicit empty input: %v", err)
	}
	if len(emitted) != 1 || len(emitted[0].Input) != 0 {
		t.Fatalf("explicit empty input = %+v", emitted)
	}
}

func TestClassifyStreamIntegrity(t *testing.T) {
	for _, tc := range []struct {
		name         string
		content      int
		tools        int
		stopReason   string
		sawReasoning bool
		wantErr      error
	}{
		{"complete with stop", 12, 0, "end_turn", false, nil},
		{"complete with tools", 0, 1, "", false, nil},
		{"empty", 0, 0, "", false, errUpstreamEmptyResponse},
		{"truncated content", 8, 0, "", false, errUpstreamTruncatedResponse},
		{"reasoning only truncated", 0, 0, "", true, errUpstreamTruncatedResponse},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyStreamIntegrity(tc.content, tc.tools, tc.stopReason, tc.sawReasoning)
			if tc.wantErr == nil {
				if got != nil {
					t.Fatalf("got %v, want nil", got)
				}
				return
			}
			if got == nil || got.Error() != tc.wantErr.Error() {
				t.Fatalf("got %v, want %v", got, tc.wantErr)
			}
		})
	}
}

// Two tools left pending at EOF must be emitted in arrival order. The earlier
// map-based flush relied on Go's randomized map iteration, so a parallel tool
// turn cut short by EOF delivered the calls in a nondeterministic order.
func TestParseEventStreamFlushesPendingToolsInArrivalOrder(t *testing.T) {
	var stream bytes.Buffer
	frame := func(payload map[string]interface{}) {
		stream.Write(awsEventStreamFrame(t, "toolUseEvent", payload))
	}
	frame(map[string]interface{}{"toolUseId": "call_1", "name": "read_file", "input": `{"path":"a.go"}`})
	frame(map[string]interface{}{"toolUseId": "call_2", "name": "list_dir", "input": `{"path":"/tmp"}`})
	frame(map[string]interface{}{"toolUseId": "call_3", "name": "grep", "input": `{"q":"x"}`})
	body := stream.Bytes()

	// Repeat: a single pass can match by luck under map iteration.
	for i := 0; i < 20; i++ {
		var order []string
		if err := parseEventStream(bytes.NewReader(body), &KiroStreamCallback{
			OnToolUse: func(tu KiroToolUse) { order = append(order, tu.ToolUseID) },
		}); err != nil {
			t.Fatalf("parse: %v", err)
		}
		want := []string{"call_1", "call_2", "call_3"}
		if len(order) != len(want) {
			t.Fatalf("expected %d tool calls, got %v", len(want), order)
		}
		for j := range want {
			if order[j] != want[j] {
				t.Fatalf("tool flush order = %v, want %v (run %d)", order, want, i)
			}
		}
	}
}

func TestParseEventStreamReportsMixedCompleteAndIncompleteTools(t *testing.T) {
	var stream bytes.Buffer
	frame := func(payload map[string]interface{}) {
		stream.Write(awsEventStreamFrame(t, "toolUseEvent", payload))
	}
	frame(map[string]interface{}{"toolUseId": "call_ok", "name": "read_file", "input": `{"path":"a.go"}`, "stop": true})
	frame(map[string]interface{}{"toolUseId": "call_cut", "name": "write_file", "input": `{"path":"b.go",`})
	stream.Write(awsEventStreamFrame(t, "metadataEvent", map[string]interface{}{"stopReason": "END_TURN"}))

	var emitted []KiroToolUse
	err := parseEventStream(bytes.NewReader(stream.Bytes()), &KiroStreamCallback{
		OnToolUse: func(tu KiroToolUse) { emitted = append(emitted, tu) },
	})
	if !errors.Is(err, errIncompleteToolUse) {
		t.Fatalf("mixed tool set error = %v, want incomplete tool error", err)
	}
	if len(emitted) != 0 {
		t.Fatalf("invalid parallel tool set leaked tools before validation: %+v", emitted)
	}
}

func TestParseEventStreamKeepsPendingTargetAfterSiblingStops(t *testing.T) {
	var stream bytes.Buffer
	frame := func(payload map[string]interface{}) {
		stream.Write(awsEventStreamFrame(t, "toolUseEvent", payload))
	}
	frame(map[string]interface{}{"toolUseId": "call_a", "name": "read_file"})
	frame(map[string]interface{}{"toolUseId": "call_b", "name": "list_dir", "input": `{"path":"/tmp"}`, "stop": true})
	frame(map[string]interface{}{"input": `{"path":"a.go"}`, "stop": true})

	var tools []KiroToolUse
	if err := parseEventStream(bytes.NewReader(stream.Bytes()), &KiroStreamCallback{
		OnToolUse: func(tool KiroToolUse) { tools = append(tools, tool) },
	}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(tools) != 2 {
		t.Fatalf("tools = %+v, want two", tools)
	}
	if tools[0].ToolUseID != "call_a" || tools[0].Input["path"] != "a.go" {
		t.Fatalf("ID-less continuation did not attach to call_a: %+v", tools[0])
	}
	if tools[1].ToolUseID != "call_b" || tools[1].Input["path"] != "/tmp" {
		t.Fatalf("call_b changed: %+v", tools[1])
	}
}
