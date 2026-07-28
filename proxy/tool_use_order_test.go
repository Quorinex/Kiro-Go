package proxy

// Regression coverage for the tool-use state machine in parseEventStream.
// Tool call identity and order are semantic for clients: a duplicated emit
// makes the client run a write or shell tool twice, and a reordered emit
// changes which result is matched to which call.

import (
	"bytes"
	"fmt"
	"testing"
)

// A tool that opens with both id and name, then continues with fragments that
// carry only input and no id, must accumulate into the same entry. This is the
// shape the upstream actually sends for a long argument list, and it used to be
// lost: an id-keyed frame and an id-less frame were dispatched to two separate
// state machines, so the continuation fragments landed nowhere and the call
// failed with an incomplete-input error mid-turn.
func TestParseEventStreamIDFirstThenIDLessContinuationAccumulates(t *testing.T) {
	var stream bytes.Buffer
	for _, event := range []map[string]interface{}{
		{"toolUseId": "toolu_1", "name": "lookup", "input": `{"query":"a`},
		{"input": `b`},
		{"input": `c"}`, "stop": true},
	} {
		stream.Write(awsEventStreamFrame(t, "toolUseEvent", event))
	}

	var toolUses []KiroToolUse
	err := parseEventStream(bytes.NewReader(stream.Bytes()), &KiroStreamCallback{
		OnToolUse: func(toolUse KiroToolUse) { toolUses = append(toolUses, toolUse) },
	})
	if err != nil {
		t.Fatalf("id-less continuation fragments must not be dropped: %v", err)
	}
	if len(toolUses) != 1 {
		t.Fatalf("tool uses=%d, want exactly 1: %#v", len(toolUses), toolUses)
	}
	if toolUses[0].ToolUseID != "toolu_1" || toolUses[0].Name != "lookup" {
		t.Fatalf("id=%q name=%q, want toolu_1/lookup", toolUses[0].ToolUseID, toolUses[0].Name)
	}
	if got := toolUses[0].Input["query"]; got != "abc" {
		t.Fatalf("input=%#v, want the three fragments joined into \"abc\"", toolUses[0].Input)
	}
}

// A fragment that arrives without toolUseId opens a synthetic entry. When the
// real id shows up on a later fragment of the same tool, it must adopt that
// entry instead of opening a second one, otherwise the same logical tool call
// is emitted twice: once under the generated id and once under the real id.
func TestParseEventStreamRekeysGeneratedToolIDInsteadOfSplitting(t *testing.T) {
	var stream bytes.Buffer
	for _, event := range []map[string]interface{}{
		{"name": "lookup", "input": `{"query":`},
		{"toolUseId": "toolu_real", "name": "lookup", "input": `"kiro"}`, "stop": true},
	} {
		stream.Write(awsEventStreamFrame(t, "toolUseEvent", event))
	}

	var toolUses []KiroToolUse
	err := parseEventStream(bytes.NewReader(stream.Bytes()), &KiroStreamCallback{
		OnToolUse: func(toolUse KiroToolUse) { toolUses = append(toolUses, toolUse) },
	})
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if len(toolUses) != 1 {
		t.Fatalf("tool uses=%d, want exactly 1: %#v", len(toolUses), toolUses)
	}
	if toolUses[0].ToolUseID != "toolu_real" {
		t.Fatalf("tool use id=%q, want the real upstream id", toolUses[0].ToolUseID)
	}
	if got := toolUses[0].Input["query"]; got != "kiro" {
		t.Fatalf("input=%#v, want the joined fragments", toolUses[0].Input)
	}
}

// Rekeying must keep the entry's position in arrival order: a tool that opened
// first still has to be emitted first once its real id replaces the generated
// one.
func TestParseEventStreamRekeyKeepsArrivalPosition(t *testing.T) {
	var stream bytes.Buffer
	for _, event := range []map[string]interface{}{
		{"name": "first_tool", "input": `{"k":`},
		{"toolUseId": "toolu_first", "name": "first_tool", "input": `1}`},
		{"toolUseId": "toolu_second", "name": "second_tool", "input": `{"k":2}`},
	} {
		stream.Write(awsEventStreamFrame(t, "toolUseEvent", event))
	}

	var order []string
	err := parseEventStream(bytes.NewReader(stream.Bytes()), &KiroStreamCallback{
		OnToolUse: func(toolUse KiroToolUse) { order = append(order, toolUse.ToolUseID) },
	})
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if len(order) != 2 || order[0] != "toolu_first" || order[1] != "toolu_second" {
		t.Fatalf("emit order=%v, want [toolu_first toolu_second]", order)
	}
}

// Tools left open at EOF must be flushed in arrival order, including one that
// started life without an id. The id-less opener is the part that regressed:
// pre-fix it lived in a separate single-slot path that was always flushed
// before the id-keyed map, so it could not stay behind a tool that arrived
// later. Run repeatedly because a map-iteration flush can match by luck.
func TestParseEventStreamFlushesPendingToolsInArrivalOrder(t *testing.T) {
	for iteration := 0; iteration < 20; iteration++ {
		var stream bytes.Buffer
		// First tool opens without an id and only later learns it, so it must
		// hold position 0 against three tools that arrive with ids up front.
		stream.Write(awsEventStreamFrame(t, "toolUseEvent", map[string]interface{}{
			"name": "lookup_0", "input": `{"query":`,
		}))
		stream.Write(awsEventStreamFrame(t, "toolUseEvent", map[string]interface{}{
			"toolUseId": "toolu_0", "name": "lookup_0", "input": `0}`,
		}))
		want := []string{"toolu_0"}
		for i := 1; i < 4; i++ {
			id := fmt.Sprintf("toolu_%d", i)
			want = append(want, id)
			stream.Write(awsEventStreamFrame(t, "toolUseEvent", map[string]interface{}{
				"toolUseId": id,
				"name":      fmt.Sprintf("lookup_%d", i),
				"input":     fmt.Sprintf(`{"query":%d}`, i),
			}))
		}

		var order []string
		err := parseEventStream(bytes.NewReader(stream.Bytes()), &KiroStreamCallback{
			OnToolUse: func(toolUse KiroToolUse) { order = append(order, toolUse.ToolUseID) },
		})
		if err != nil {
			t.Fatalf("iteration %d: unexpected parse error: %v", iteration, err)
		}
		if len(order) != len(want) {
			t.Fatalf("iteration %d: emitted %d tools (%v), want %d", iteration, len(order), order, len(want))
		}
		for i := range want {
			if order[i] != want[i] {
				t.Fatalf("iteration %d: emit order=%v, want %v", iteration, order, want)
			}
		}
	}
}

// An id-less fragment that switches tool name closes the tool in flight rather
// than appending foreign arguments to it. The interleaved case is what
// regressed: once a tool has been opened by an id-bearing frame, a following
// id-less fragment for a different name must not be folded into it.
func TestParseEventStreamIDLessNameChangeOpensNewTool(t *testing.T) {
	var stream bytes.Buffer
	for _, event := range []map[string]interface{}{
		{"toolUseId": "toolu_first", "name": "first_tool", "input": `{"a":1}`},
		{"name": "second_tool", "input": `{"b":2}`},
	} {
		stream.Write(awsEventStreamFrame(t, "toolUseEvent", event))
	}

	var toolUses []KiroToolUse
	err := parseEventStream(bytes.NewReader(stream.Bytes()), &KiroStreamCallback{
		OnToolUse: func(toolUse KiroToolUse) { toolUses = append(toolUses, toolUse) },
	})
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if len(toolUses) != 2 {
		t.Fatalf("tool uses=%d, want 2: %#v", len(toolUses), toolUses)
	}
	if toolUses[0].Name != "first_tool" || toolUses[1].Name != "second_tool" {
		t.Fatalf("names=[%q %q], want [first_tool second_tool]", toolUses[0].Name, toolUses[1].Name)
	}
	if toolUses[0].ToolUseID != "toolu_first" {
		t.Fatalf("first tool id=%q, want toolu_first", toolUses[0].ToolUseID)
	}
	if got := toolUses[0].Input["a"]; got != float64(1) {
		t.Fatalf("first tool input=%#v, want {\"a\":1}", toolUses[0].Input)
	}
	if got := toolUses[1].Input["b"]; got != float64(2) {
		t.Fatalf("second tool input=%#v, want {\"b\":2}", toolUses[1].Input)
	}
	if _, leaked := toolUses[0].Input["b"]; leaked {
		t.Fatalf("second tool args leaked into the first: %#v", toolUses[0].Input)
	}
}

// stopReason rides inside metadataEvent. Upstream has been seen using both the
// camelCase and snake_case spellings, and missing it means a truncated stream
// is reported to the client as a normal end_turn.
func TestParseEventStreamReadsStopReasonKeyVariants(t *testing.T) {
	for _, key := range []string{"stopReason", "stop_reason"} {
		t.Run(key, func(t *testing.T) {
			var stream bytes.Buffer
			stream.Write(awsEventStreamFrame(t, "assistantResponseEvent",
				map[string]interface{}{"content": "done"}))
			stream.Write(awsEventStreamFrame(t, "metadataEvent",
				map[string]interface{}{key: "end_turn"}))

			var reason string
			err := parseEventStream(bytes.NewReader(stream.Bytes()), &KiroStreamCallback{
				OnText:       func(string, bool) {},
				OnStopReason: func(r string) { reason = r },
			})
			if err != nil {
				t.Fatalf("unexpected parse error: %v", err)
			}
			if reason != "end_turn" {
				t.Fatalf("stop reason=%q, want end_turn", reason)
			}
		})
	}
}
