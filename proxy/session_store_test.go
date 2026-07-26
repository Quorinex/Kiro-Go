package proxy

import (
	"testing"
)

func TestResolveSessionIDsMintsFreshOnFirstTurn(t *testing.T) {
	msgs := []ClaudeMessage{
		{Role: "user", Content: "hello first turn only"},
	}
	c1, k1, reused := resolveSessionIDs("ak", "claude-sonnet-4.5", msgs)
	if reused {
		t.Fatal("first turn must not reuse")
	}
	if c1 == "" || k1 == "" {
		t.Fatal("must mint both ids")
	}
	c2, k2, reused2 := resolveSessionIDs("ak", "claude-sonnet-4.5", msgs)
	if reused2 {
		t.Fatal("unsealed first turn must not reuse")
	}
	if c1 == c2 || k1 == k2 {
		t.Fatalf("unsealed first turns must mint distinct ids: %s/%s vs %s/%s", c1, k1, c2, k2)
	}
}

func TestSessionSealThenResolveReusesExactChain(t *testing.T) {
	model := "claude-sonnet-4.5"
	api := "ak-session-1"
	user1 := "session-continuity-opener-unique-111"
	asst1 := "session-continuity-answer-unique-111"

	// After turn 1 success, client holds user1+asst1; we seal that chain.
	chain1 := []ClaudeMessage{
		{Role: "user", Content: user1},
		{Role: "assistant", Content: asst1},
	}
	conv, cont := "conv-fixed-aaa", "cont-fixed-bbb"
	sealSessionAfterSuccess(api, model, conv, cont, chain1)

	// Turn 2: client sends user1+asst1+user2. Prefix before current user = chain1.
	turn2 := []ClaudeMessage{
		{Role: "user", Content: user1},
		{Role: "assistant", Content: asst1},
		{Role: "user", Content: "follow up please"},
	}
	gotConv, gotCont, reused := resolveSessionIDs(api, model, turn2)
	if !reused {
		t.Fatal("expected reuse on exact continuation chain")
	}
	if gotConv != conv || gotCont != cont {
		t.Fatalf("reused ids = %s/%s, want %s/%s", gotConv, gotCont, conv, cont)
	}
}

func TestSessionDoesNotReuseAcrossAPIKeysOrModels(t *testing.T) {
	model := "claude-sonnet-4.5"
	chain := []ClaudeMessage{
		{Role: "user", Content: "iso-user"},
		{Role: "assistant", Content: "iso-asst"},
	}
	sealSessionAfterSuccess("key-A", model, "c-A", "k-A", chain)

	turn := []ClaudeMessage{
		{Role: "user", Content: "iso-user"},
		{Role: "assistant", Content: "iso-asst"},
		{Role: "user", Content: "next"},
	}
	_, _, reused := resolveSessionIDs("key-B", model, turn)
	if reused {
		t.Fatal("must not reuse across API keys")
	}
	_, _, reused = resolveSessionIDs("key-A", "other-model", turn)
	if reused {
		t.Fatal("must not reuse across models")
	}
}

func TestSessionDoesNotReuseWhenAssistantTextDiverges(t *testing.T) {
	model := "m"
	api := "ak"
	sealSessionAfterSuccess(api, model, "c1", "k1", []ClaudeMessage{
		{Role: "user", Content: "q"},
		{Role: "assistant", Content: "answer-A"},
	})
	// Client rewrote history assistant text — chain fingerprint changes.
	_, _, reused := resolveSessionIDs(api, model, []ClaudeMessage{
		{Role: "user", Content: "q"},
		{Role: "assistant", Content: "answer-TAMPERED"},
		{Role: "user", Content: "next"},
	})
	if reused {
		t.Fatal("tampered assistant history must not reuse session ids")
	}
}

func TestSessionDoesNotReuseWhenWhitespaceDiverges(t *testing.T) {
	globalSessionStore = newSessionStore()
	sealSessionAfterSuccess("key-space", "model", "conv-space", "cont-space", []ClaudeMessage{
		{Role: "user", Content: "a  b"},
		{Role: "assistant", Content: "answer"},
	})
	_, _, reused := resolveSessionIDs("key-space", "model", []ClaudeMessage{
		{Role: "user", Content: "a b"},
		{Role: "assistant", Content: "answer"},
		{Role: "user", Content: "next"},
	})
	if reused {
		t.Fatal("different whitespace is different client history and must not reuse")
	}
}

func TestClaudeToKiroReusesSessionIDsOnContinuation(t *testing.T) {
	model := "claude-sonnet-4.5"
	api := ""
	user1 := "ctk-session-opener-zzz"
	asst1 := "ctk-session-answer-zzz"

	// Seal as handler would after turn 1.
	sealSessionAfterSuccess(api, MapModel(model), "conv-ctk-1", "cont-ctk-1", []ClaudeMessage{
		{Role: "user", Content: user1},
		{Role: "assistant", Content: asst1},
	})

	req := &ClaudeRequest{
		Model: model,
		Messages: []ClaudeMessage{
			{Role: "user", Content: user1},
			{Role: "assistant", Content: asst1},
			{Role: "user", Content: "second question"},
		},
	}
	// Handler-side resolve (ClaudeToKiro stays pure).
	gotConv, gotCont, reused := resolveSessionIDs(api, MapModel(model), req.Messages)
	if !reused || gotConv != "conv-ctk-1" || gotCont != "cont-ctk-1" {
		t.Fatalf("resolve = %s/%s reused=%v", gotConv, gotCont, reused)
	}
	// Brand-new chat must not reuse.
	_, _, reusedNew := resolveSessionIDs(api, MapModel(model), []ClaudeMessage{{Role: "user", Content: "totally new chat opener"}})
	if reusedNew {
		t.Fatal("new chat must not reuse")
	}
}

// Regression: the seal must fingerprint the CLIENT transcript, not the wire
// payload. ClaudeToKiro prepends a system-priming user/assistant pair whenever
// a system prompt exists (always true for Claude Code / Pi), so a
// payload-derived chain could never match the next request's lookup key and
// continuity silently never happened in production.
func TestSealClaudeSessionMatchesLookupWithSystemPrompt(t *testing.T) {
	globalSessionStore = newSessionStore()

	const api = "key-sys"
	const model = "claude-sonnet-4.5"
	system := "you are a coding agent with a long system prompt"

	turn1 := []ClaudeMessage{{Role: "user", Content: "first question"}}
	req1 := &ClaudeRequest{Model: model, System: system, Messages: turn1}
	payload1 := ClaudeToKiro(req1, false)

	conv1, cont1, reused := resolveSessionIDs(api, MapModel(model), turn1)
	if reused {
		t.Fatalf("first turn must not reuse")
	}
	// Sanity: the payload really does carry the priming pair that used to break this.
	if len(payload1.ConversationState.History) == 0 {
		t.Fatalf("expected system priming history in payload")
	}

	// Seal exactly as the handler does, from the inbound transcript.
	sealClaudeSession(api, model, conv1, cont1, turn1, "first answer", "", nil, "thinking", false)

	turn2 := []ClaudeMessage{
		{Role: "user", Content: "first question"},
		{Role: "assistant", Content: "first answer"},
		{Role: "user", Content: "second question"},
	}
	conv2, cont2, reused2 := resolveSessionIDs(api, MapModel(model), turn2)
	if !reused2 {
		t.Fatalf("continuation must reuse after a real seal (system prompt present)")
	}
	if conv2 != conv1 || cont2 != cont1 {
		t.Fatalf("ids not reused: conv %q vs %q, cont %q vs %q", conv2, conv1, cont2, cont1)
	}
}

// Regression: a tool loop must keep the chain alive. The seal renders this
// turn's tool_use blocks the same way the client replays them.
func TestSealClaudeSessionSurvivesToolLoop(t *testing.T) {
	globalSessionStore = newSessionStore()

	const api = "key-tool"
	const model = "claude-sonnet-4.5"

	turn1 := []ClaudeMessage{{Role: "user", Content: "read the file"}}
	conv, cont, _ := resolveSessionIDs(api, MapModel(model), turn1)
	sealClaudeSession(api, model, conv, cont, turn1, "let me look", "",
		[]KiroToolUse{{ToolUseID: "tu_1", Name: "read_file", Input: map[string]interface{}{"path": "a.go"}}}, "thinking", false)

	// Client replays assistant text + tool_use, then sends the tool_result.
	turn2 := []ClaudeMessage{
		{Role: "user", Content: "read the file"},
		{Role: "assistant", Content: []interface{}{
			map[string]interface{}{"type": "text", "text": "let me look"},
			map[string]interface{}{"type": "tool_use", "id": "tu_1", "name": "read_file", "input": map[string]interface{}{"path": "a.go"}},
		}},
		{Role: "user", Content: []interface{}{
			map[string]interface{}{"type": "tool_result", "tool_use_id": "tu_1", "content": "file body"},
		}},
	}
	got, gotCont, reused := resolveSessionIDs(api, MapModel(model), turn2)
	if !reused {
		t.Fatalf("tool-result turn must continue the chain")
	}
	if got != conv || gotCont != cont {
		t.Fatalf("tool loop lost ids: %q/%q want %q/%q", got, gotCont, conv, cont)
	}
}

// Regression: with default "thinking" format the client stores a thinking
// content block. Seal must include that block or the next-turn lookup misses.
func TestSealClaudeSessionMatchesLookupWithThinkingBlock(t *testing.T) {
	globalSessionStore = newSessionStore()
	const api = "key-think"
	const model = "claude-sonnet-4.5"

	turn1 := []ClaudeMessage{{Role: "user", Content: "first question"}}
	conv, cont, _ := resolveSessionIDs(api, MapModel(model), turn1)
	sealClaudeSession(api, model, conv, cont, turn1, "first answer", "let me reason", nil, "thinking", false)

	turn2 := []ClaudeMessage{
		{Role: "user", Content: "first question"},
		{Role: "assistant", Content: []interface{}{
			map[string]interface{}{"type": "thinking", "thinking": "let me reason"},
			map[string]interface{}{"type": "text", "text": "first answer"},
		}},
		{Role: "user", Content: "second question"},
	}
	got, gotCont, reused := resolveSessionIDs(api, MapModel(model), turn2)
	if !reused {
		t.Fatal("thinking-format continuation must reuse")
	}
	if got != conv || gotCont != cont {
		t.Fatalf("ids lost under thinking format: %q/%q want %q/%q", got, gotCont, conv, cont)
	}
}

// Regression: "think" format folds reasoning into the text the client stores.
// Seal must fingerprint the folded text, not the bare answer.
func TestSealClaudeSessionMatchesLookupWithThinkTags(t *testing.T) {
	globalSessionStore = newSessionStore()
	const api = "key-think-tags"
	const model = "claude-sonnet-4.5"

	turn1 := []ClaudeMessage{{Role: "user", Content: "first question"}}
	conv, cont, _ := resolveSessionIDs(api, MapModel(model), turn1)
	sealClaudeSession(api, model, conv, cont, turn1, "first answer", "let me reason", nil, "think", false)

	turn2 := []ClaudeMessage{
		{Role: "user", Content: "first question"},
		{Role: "assistant", Content: "<think>let me reason</think>first answer"},
		{Role: "user", Content: "second question"},
	}
	got, gotCont, reused := resolveSessionIDs(api, MapModel(model), turn2)
	if !reused {
		t.Fatal("think-tag format continuation must reuse")
	}
	if got != conv || gotCont != cont {
		t.Fatalf("ids lost under think tags: %q/%q want %q/%q", got, gotCont, conv, cont)
	}
}

func TestSealClaudeSessionMatchesOmittedThinkingBlock(t *testing.T) {
	globalSessionStore = newSessionStore()
	inbound := []ClaudeMessage{{Role: "user", Content: "question"}}
	sealClaudeSession("key-omit", "model", "conv-omit", "cont-omit", inbound, "answer", "hidden", nil, "thinking", true)
	_, _, reused := resolveSessionIDs("key-omit", MapModel("model"), []ClaudeMessage{
		{Role: "user", Content: "question"},
		{Role: "assistant", Content: []interface{}{
			map[string]interface{}{"type": "thinking", "thinking": ""},
			map[string]interface{}{"type": "text", "text": "answer"},
		}},
		{Role: "user", Content: "next"},
	})
	if !reused {
		t.Fatal("empty client-visible thinking shell must remain in sealed shape")
	}
}

// Regression: seal text must be the VISIBLE answer, never the integrity-check
// padding that used to glue tool name+input onto rawContentBuilder.
func TestSealClaudeSessionDoesNotFingerprintToolPadding(t *testing.T) {
	globalSessionStore = newSessionStore()
	const api = "key-pad"
	const model = "claude-sonnet-4.5"

	turn1 := []ClaudeMessage{{Role: "user", Content: "read the file"}}
	conv, cont, _ := resolveSessionIDs(api, MapModel(model), turn1)

	// What the client actually stores.
	clean := "let me look"
	// What rawContentBuilder used to contain after OnToolUse padding.
	polluted := clean + `read_file{"path":"a.go"}`

	// Seal the clean shape (as the fixed handler now does).
	sealClaudeSession(api, model, conv, cont, turn1, clean, "",
		[]KiroToolUse{{ToolUseID: "tu_1", Name: "read_file"}}, "thinking", false)

	// Next request replays clean text + tool_use — must hit.
	turn2 := []ClaudeMessage{
		{Role: "user", Content: "read the file"},
		{Role: "assistant", Content: []interface{}{
			map[string]interface{}{"type": "text", "text": clean},
			map[string]interface{}{"type": "tool_use", "id": "tu_1", "name": "read_file"},
		}},
		{Role: "user", Content: []interface{}{
			map[string]interface{}{"type": "tool_result", "tool_use_id": "tu_1", "content": "body"},
		}},
	}
	if _, _, reused := resolveSessionIDs(api, MapModel(model), turn2); !reused {
		t.Fatal("clean seal must match clean client replay")
	}

	// A polluted seal must NOT match the clean client replay (proves the bug
	// class: if we still sealed polluted text, continuity would die here).
	globalSessionStore = newSessionStore()
	conv2, cont2, _ := resolveSessionIDs(api, MapModel(model), turn1)
	sealClaudeSession(api, model, conv2, cont2, turn1, polluted, "",
		[]KiroToolUse{{ToolUseID: "tu_1", Name: "read_file"}}, "thinking", false)
	if _, _, reused := resolveSessionIDs(api, MapModel(model), turn2); reused {
		t.Fatal("polluted seal must NOT match clean client replay — that was the production bug")
	}
}

func TestSessionStoreCollisionFailsClosed(t *testing.T) {
	s := newSessionStore()
	s.put("key", "model", "same-chain", "conv-a", "cont-a")
	s.put("key", "model", "same-chain", "conv-b", "cont-b")
	if got := s.lookup("key", "model", "same-chain"); got != nil {
		t.Fatalf("ambiguous transcript must not reuse either session: %+v", got)
	}
}

func TestSessionFingerprintIncludesToolInput(t *testing.T) {
	chain := func(path string) []ClaudeMessage {
		return []ClaudeMessage{
			{Role: "user", Content: "read a file"},
			{Role: "assistant", Content: []interface{}{
				map[string]interface{}{
					"type": "tool_use", "id": "tool-1", "name": "read_file",
					"input": map[string]interface{}{"path": path},
				},
			}},
		}
	}
	if chainFingerprintClaude(chain("a.go")) == chainFingerprintClaude(chain("b.go")) {
		t.Fatal("different tool inputs must produce different chain fingerprints")
	}
}

func TestSessionFingerprintIncludesStructuredToolResult(t *testing.T) {
	chain := func(result string) []ClaudeMessage {
		return []ClaudeMessage{
			{Role: "assistant", Content: []interface{}{
				map[string]interface{}{
					"type": "tool_result", "tool_use_id": "tool-1",
					"content": []interface{}{map[string]interface{}{"type": "text", "text": result}},
				},
			}},
		}
	}
	if chainFingerprintClaude(chain("first")) == chainFingerprintClaude(chain("second")) {
		t.Fatal("different structured tool results must produce different chain fingerprints")
	}
}
