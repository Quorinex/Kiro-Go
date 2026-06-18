package proxy

import (
	"strings"
	"testing"
)

// runFilter feeds chunks through the filter (process per chunk like the stream
// loop), then flushes, and returns the emitted text plus the rescued tools.
func runFilter(t *testing.T, chunks []string, seenBefore []leakedTool) (string, []leakedTool) {
	t.Helper()
	f := &toolLeakFilter{enabled: true, seen: make(map[string]bool)}
	for _, s := range seenBefore {
		f.markSeen(s.name, s.input)
	}
	var sb strings.Builder
	emit := func(s string) { sb.WriteString(s) }
	for _, c := range chunks {
		f.carry += c
		f.process(false, emit)
	}
	f.process(true, emit)
	return sb.String(), f.leaked
}

func TestToolLeakFilterPassesNormalText(t *testing.T) {
	text, leaked := runFilter(t, []string{"Hello, ", "this is ", "normal text."}, nil)
	if text != "Hello, this is normal text." {
		t.Fatalf("normal text altered: %q", text)
	}
	if len(leaked) != 0 {
		t.Fatalf("expected no leaked tools, got %d", len(leaked))
	}
}

func TestToolLeakFilterExtractsSingleInvoke(t *testing.T) {
	in := `before <function_calls><invoke name="Read"><parameter name="path">/tmp/a.txt</parameter></invoke></function_calls> after`
	text, leaked := runFilter(t, []string{in}, nil)
	if strings.Contains(text, "<invoke") || strings.Contains(text, "<function_calls>") {
		t.Fatalf("leaked XML not stripped from text: %q", text)
	}
	if !strings.Contains(text, "before") || !strings.Contains(text, "after") {
		t.Fatalf("normal text around tool dropped: %q", text)
	}
	if len(leaked) != 1 {
		t.Fatalf("expected 1 leaked tool, got %d", len(leaked))
	}
	if leaked[0].name != "Read" || leaked[0].input["path"] != "/tmp/a.txt" {
		t.Fatalf("unexpected parsed tool: %#v", leaked[0])
	}
}

func TestToolLeakFilterCrossFrameSplit(t *testing.T) {
	// Split the tool XML across many frames to exercise cross-frame buffering.
	full := `<function_calls><invoke name="Bash"><parameter name="command">ls -la</parameter></invoke></function_calls>`
	var chunks []string
	for i := 0; i < len(full); i += 5 {
		end := i + 5
		if end > len(full) {
			end = len(full)
		}
		chunks = append(chunks, full[i:end])
	}
	text, leaked := runFilter(t, chunks, nil)
	if strings.Contains(text, "<invoke") || strings.Contains(text, "parameter") {
		t.Fatalf("cross-frame leaked XML emitted as text: %q", text)
	}
	if len(leaked) != 1 {
		t.Fatalf("expected 1 leaked tool across frames, got %d", len(leaked))
	}
	if leaked[0].input["command"] != "ls -la" {
		t.Fatalf("expected preserved command, got %#v", leaked[0].input)
	}
}

func TestToolLeakFilterTypeRestoration(t *testing.T) {
	in := `<invoke name="X">` +
		`<parameter name="flag">true</parameter>` +
		`<parameter name="off">false</parameter>` +
		`<parameter name="n">42</parameter>` +
		`<parameter name="f">3.14</parameter>` +
		`<parameter name="z">null</parameter>` +
		`<parameter name="s">hello world</parameter>` +
		`</invoke>`
	_, leaked := runFilter(t, []string{in}, nil)
	if len(leaked) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(leaked))
	}
	got := leaked[0].input
	if got["flag"] != true || got["off"] != false {
		t.Fatalf("bool restore failed: %#v", got)
	}
	if got["n"] != 42 {
		t.Fatalf("int restore failed: %#v", got["n"])
	}
	if got["f"] != 3.14 {
		t.Fatalf("float restore failed: %#v", got["f"])
	}
	if got["z"] != nil {
		t.Fatalf("null restore failed: %#v", got["z"])
	}
	if got["s"] != "hello world" {
		t.Fatalf("string preserve failed: %#v", got["s"])
	}
}

func TestToolLeakFilterCorruptedCountPrefix(t *testing.T) {
	// <function_calls> sometimes arrives corrupted as the literal "count".
	in := `text count<invoke name="Read"><parameter name="path">/a</parameter></invoke>`
	text, leaked := runFilter(t, []string{in}, nil)
	if strings.Contains(text, "count") {
		t.Fatalf("corrupted count prefix not stripped: %q", text)
	}
	if len(leaked) != 1 || leaked[0].name != "Read" {
		t.Fatalf("expected Read tool, got %#v", leaked)
	}
}

func TestToolLeakFilterUnclosedInvokeEmittedAsText(t *testing.T) {
	// An invoke that never closes by stream end is corrupted; emit as text, no drop.
	in := `start <invoke name="Read"><parameter name="path">/a`
	text, leaked := runFilter(t, []string{in}, nil)
	if !strings.Contains(text, "<invoke name=") {
		t.Fatalf("unclosed invoke should be emitted as text, got %q", text)
	}
	if len(leaked) != 0 {
		t.Fatalf("expected no parsed tool for unclosed invoke, got %d", len(leaked))
	}
}

func TestToolLeakInjectDedupAgainstSeen(t *testing.T) {
	in := `<invoke name="Read"><parameter name="path">/a</parameter></invoke>`
	// Mark the same name+input as already seen via a structured toolUseEvent.
	seen := []leakedTool{{name: "Read", input: map[string]interface{}{"path": "/a"}}}
	_, leaked := runFilter(t, []string{in}, seen)
	if len(leaked) != 1 {
		t.Fatalf("filter should still parse the leaked copy, got %d", len(leaked))
	}

	f := &toolLeakFilter{enabled: true, seen: make(map[string]bool)}
	for _, s := range seen {
		f.markSeen(s.name, s.input)
	}
	f.leaked = leaked
	var injected []KiroToolUse
	cb := &KiroStreamCallback{OnToolUse: func(tu KiroToolUse) { injected = append(injected, tu) }}
	f.injectLeaked(cb)
	if len(injected) != 0 {
		t.Fatalf("expected dedup to drop already-seen tool, injected %d", len(injected))
	}
}

func TestToolLeakInjectRescuesUnseen(t *testing.T) {
	f := &toolLeakFilter{enabled: true, seen: make(map[string]bool)}
	f.leaked = []leakedTool{{name: "Bash", input: map[string]interface{}{"command": "ls"}}}
	var injected []KiroToolUse
	cb := &KiroStreamCallback{OnToolUse: func(tu KiroToolUse) { injected = append(injected, tu) }}
	f.injectLeaked(cb)
	if len(injected) != 1 {
		t.Fatalf("expected 1 rescued tool, got %d", len(injected))
	}
	if injected[0].Name != "Bash" || injected[0].Input["command"] != "ls" {
		t.Fatalf("unexpected rescued tool: %#v", injected[0])
	}
	if !strings.HasPrefix(injected[0].ToolUseID, "toolleakfix_") {
		t.Fatalf("expected rescued id prefix, got %q", injected[0].ToolUseID)
	}
}

func TestToolLeakFilterMultipleInvokes(t *testing.T) {
	in := `<function_calls>` +
		`<invoke name="A"><parameter name="x">1</parameter></invoke>` +
		`<invoke name="B"><parameter name="y">2</parameter></invoke>` +
		`</function_calls>`
	text, leaked := runFilter(t, []string{in}, nil)
	if strings.TrimSpace(text) != "" {
		t.Fatalf("expected no visible text, got %q", text)
	}
	if len(leaked) != 2 {
		t.Fatalf("expected 2 tools, got %d", len(leaked))
	}
	if leaked[0].name != "A" || leaked[1].name != "B" {
		t.Fatalf("unexpected tool order: %#v", leaked)
	}
}
