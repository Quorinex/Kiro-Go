package proxy

import (
	"bytes"
	"encoding/json"
	"testing"
)

// Seam: turnKey — same turn content must hash equal; different assistant text must not.
func TestTurnKeyStableAndIsolatesAssistantText(t *testing.T) {
	a := debugTurnKey("k1", "claude-sonnet-4.5", "conv-a", "hello", "answer one", nil)
	b := debugTurnKey("k1", "claude-sonnet-4.5", "conv-a", "hello", "answer one", nil)
	if a != b {
		t.Fatalf("same turn must produce same key")
	}
	c := debugTurnKey("k1", "claude-sonnet-4.5", "conv-a", "hello", "answer two", nil)
	if a == c {
		t.Fatalf("different assistant text must not share a key")
	}
}

// Seam: store — two parallel chats with the same opener must not share stamps.
func TestReasoningStoreDoesNotCrossConversations(t *testing.T) {
	s := newReasoningStore()
	tools := []KiroToolUse{}
	s.put("keyA", "m1", "conv1", "hi", "reply-A", tools, "think-A", "sig-A", "")
	s.put("keyA", "m1", "conv1", "hi", "reply-B", tools, "think-B", "sig-B", "")

	// Lookup for reply-A must not return B's stamp.
	got := s.lookup("keyA", "m1", "conv1", "hi", "reply-A", tools)
	if got == nil || got.Signature != "sig-A" {
		t.Fatalf("expected sig-A for reply-A, got %+v", got)
	}
	// Different conversation bucket, same text — miss.
	if s.lookup("keyA", "m1", "conv-OTHER", "hi", "reply-A", tools) != nil {
		t.Fatal("must not hit across conversation buckets")
	}
	// Different API key — miss.
	if s.lookup("keyB", "m1", "conv1", "hi", "reply-A", tools) != nil {
		t.Fatal("must not hit across API keys")
	}
	// Different model — miss.
	if s.lookup("keyA", "other-model", "conv1", "hi", "reply-A", tools) != nil {
		t.Fatal("must not hit across models")
	}
}

// Seam: store — unsigned reasoning is never stored (official drops it).
func TestReasoningStoreDropsUnsigned(t *testing.T) {
	s := newReasoningStore()
	s.put("k", "m", "c", "u", "a", nil, "thinking text", "", "")
	if s.lookup("k", "m", "c", "u", "a", nil) != nil {
		t.Fatal("unsigned reasoning must not be stored")
	}
}

// Seam: parseEventStream — signature on reasoningContentEvent must reach OnReasoningMeta.
func TestParseEventStreamFiresReasoningMetaWithSignature(t *testing.T) {
	var stream bytes.Buffer
	stream.Write(awsEventStreamFrame(t, "reasoningContentEvent", map[string]interface{}{
		"text":      "I should check the file",
		"signature": "sig_abc123",
	}))
	stream.Write(awsEventStreamFrame(t, "assistantResponseEvent", map[string]interface{}{
		"content": "done",
	}))
	stream.Write(awsEventStreamFrame(t, "metadataEvent", map[string]interface{}{
		"stopReason": "end_turn",
	}))

	var thinking, sig string
	err := parseEventStream(bytes.NewReader(stream.Bytes()), &KiroStreamCallback{
		OnText: func(text string, isThinking bool) {
			if isThinking {
				thinking += text
			}
		},
		OnReasoningMeta: func(signature, _ string) { sig = signature },
	})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if thinking != "I should check the file" {
		t.Fatalf("thinking text = %q", thinking)
	}
	if sig != "sig_abc123" {
		t.Fatalf("signature = %q, want sig_abc123", sig)
	}
}

// Seam: attachStoredReasoning — only exact-matching assistant turns get stamps.
func TestAttachStoredReasoningExactMatchOnly(t *testing.T) {
	// Reset global store by sealing via public API then attaching.
	// Use unique conversation id to avoid pollution from other tests.
	conv := "conv-attach-test"
	apiKey := "ak-attach"
	model := "claude-sonnet-4.5"
	parent := "what is 1+1?"
	assistant := "2"
	sealSuccessfulTurn(apiKey, model, conv, parent, assistant, nil, "add the numbers", "sig-42", "")

	history := []KiroHistoryMessage{
		{UserInputMessage: &KiroUserInputMessage{Content: parent, Origin: "AI_EDITOR"}},
		{AssistantResponseMessage: &KiroAssistantResponseMessage{Content: assistant}},
		{UserInputMessage: &KiroUserInputMessage{Content: "and 2+2?", Origin: "AI_EDITOR"}},
		// Different assistant text — must stay unstamped.
		{AssistantResponseMessage: &KiroAssistantResponseMessage{Content: "4"}},
	}
	attachStoredReasoning(history, apiKey, model, conv)

	if history[1].AssistantResponseMessage.ReasoningContent == nil {
		t.Fatal("matching turn must receive reasoningContent")
	}
	rt := history[1].AssistantResponseMessage.ReasoningContent.ReasoningText
	if rt == nil || rt.Signature != "sig-42" || rt.Text != "add the numbers" {
		t.Fatalf("bad stamp on matching turn: %+v", history[1].AssistantResponseMessage.ReasoningContent)
	}
	if history[3].AssistantResponseMessage.ReasoningContent != nil {
		t.Fatal("non-matching turn must not receive a stamp")
	}
}

// Seam: ClaudeToKiro — after sealing turn N, the next request's history for that
// assistant message must carry reasoningContent for upstream.
func TestClaudeToKiroAttachesSealedReasoningOnNextTurn(t *testing.T) {
	convSeedUser := "unique-opener-for-reasoning-tdd-xyz"
	model := "claude-sonnet-4.5"
	modelID := MapModel(model)

	// Turn 1: mint session ids the same way the handler/translator will.
	turn1 := []ClaudeMessage{{Role: "user", Content: convSeedUser}}
	p1 := ClaudeToKiro(&ClaudeRequest{Model: model, Messages: turn1}, true)
	convID := p1.ConversationState.ConversationID
	contID := p1.ConversationState.AgentContinuationId

	// After successful stream: seal reasoning + session chain (handler job).
	sealSuccessfulTurn("", modelID, convID, convSeedUser, "first answer", nil, "think first", "sig-turn1", "")
	sealSessionAfterSuccess("", modelID, convID, contID, []ClaudeMessage{
		{Role: "user", Content: convSeedUser},
		{Role: "assistant", Content: "first answer"},
	})

	// Turn 2: continuation must reuse ids; attach must stamp first answer.
	req := &ClaudeRequest{
		Model: model,
		Messages: []ClaudeMessage{
			{Role: "user", Content: convSeedUser},
			{Role: "assistant", Content: []interface{}{
				map[string]interface{}{"type": "text", "text": "first answer"},
			}},
			{Role: "user", Content: "follow up"},
		},
	}
	payload := ClaudeToKiro(req, true)
	// Handler binds session ids with apiKey (empty here).
	c, k, _ := resolveSessionIDs("", modelID, req.Messages)
	payload.ConversationState.ConversationID = c
	payload.ConversationState.AgentContinuationId = k
	if payload.ConversationState.ConversationID != convID {
		t.Fatalf("conversationId = %q, want reused %q", payload.ConversationState.ConversationID, convID)
	}
	attachStoredReasoning(payload.ConversationState.History, "", modelID, payload.ConversationState.ConversationID)
	var found bool
	for _, h := range payload.ConversationState.History {
		if h.AssistantResponseMessage == nil || h.AssistantResponseMessage.Content != "first answer" {
			continue
		}
		found = true
		rc := h.AssistantResponseMessage.ReasoningContent
		if rc == nil || rc.ReasoningText == nil || rc.ReasoningText.Signature != "sig-turn1" {
			t.Fatalf("assistant history missing reasoningContent: %+v", rc)
		}
	}
	if !found {
		t.Fatalf("assistant turn not in history: %s", mustJSON(payload.ConversationState.History))
	}
}

func mustJSON(v interface{}) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// Handler must seal with CurrentMessage as parent (the user just answered),
// not the last user already sitting in History (previous turn).
func TestSealUsesCurrentMessageParentNotHistory(t *testing.T) {
	model := "claude-sonnet-4.5"
	opener := "seal-parent-opener-unique-aaa"
	follow := "seal-parent-follow-up-bbb"
	modelID := MapModel(model)

	p1 := ClaudeToKiro(&ClaudeRequest{Model: model, Messages: []ClaudeMessage{{Role: "user", Content: opener}}}, true)
	convID := p1.ConversationState.ConversationID
	contID := p1.ConversationState.AgentContinuationId

	// Seal as handler: parent = CurrentMessage (opener), then session chain.
	sealSuccessfulTurn("", modelID, convID, opener, "answer-1", nil, "think-1", "sig-1", "")
	sealSessionAfterSuccess("", modelID, convID, contID, []ClaudeMessage{
		{Role: "user", Content: opener},
		{Role: "assistant", Content: "answer-1"},
	})

	req := &ClaudeRequest{
		Model: model,
		Messages: []ClaudeMessage{
			{Role: "user", Content: opener},
			{Role: "assistant", Content: []interface{}{map[string]interface{}{"type": "text", "text": "answer-1"}}},
			{Role: "user", Content: follow},
		},
	}
	payload := ClaudeToKiro(req, true)
	// Handler binds session ids with apiKey (empty here).
	c, k, _ := resolveSessionIDs("", modelID, req.Messages)
	payload.ConversationState.ConversationID = c
	payload.ConversationState.AgentContinuationId = k
	if payload.ConversationState.ConversationID != convID {
		t.Fatalf("want reused conv %q, got %q", convID, payload.ConversationState.ConversationID)
	}
	attachStoredReasoning(payload.ConversationState.History, "", modelID, payload.ConversationState.ConversationID)
	var stamped bool
	for _, h := range payload.ConversationState.History {
		if h.AssistantResponseMessage != nil && h.AssistantResponseMessage.Content == "answer-1" {
			rc := h.AssistantResponseMessage.ReasoningContent
			if rc == nil || rc.ReasoningText == nil || rc.ReasoningText.Signature != "sig-1" {
				t.Fatalf("expected sig-1 on answer-1, got %+v", rc)
			}
			stamped = true
		}
	}
	if !stamped {
		t.Fatal("answer-1 not found/stamped in history")
	}
	if globalReasoningStore.lookup("", modelID, convID, follow, "answer-1", nil) != nil {
		t.Fatal("lookup with wrong parent must miss")
	}
}

func TestRedactedReasoningRoundTripsBase64Once(t *testing.T) {
	rc := toKiroReasoning(&sealedReasoning{RedactedContent: "AQID"})
	if rc == nil {
		t.Fatal("expected redacted reasoning content")
	}
	wire, err := json.Marshal(rc)
	if err != nil {
		t.Fatalf("marshal redacted reasoning: %v", err)
	}
	if got, want := string(wire), `{"redactedContent":"AQID"}`; got != want {
		t.Fatalf("wire reasoning = %s, want %s", got, want)
	}
}

func TestInvalidRedactedReasoningFailsClosed(t *testing.T) {
	if rc := toKiroReasoning(&sealedReasoning{RedactedContent: "not base64"}); rc != nil {
		t.Fatalf("invalid redacted content must not reach upstream: %+v", rc)
	}
}

func TestReasoningTurnKeyUsesExactTextAndToolIdentity(t *testing.T) {
	if debugTurnKey("k", "m", "c", "a  b", "answer", nil) == debugTurnKey("k", "m", "c", "a b", "answer", nil) {
		t.Fatal("reasoning key must preserve exact parent whitespace")
	}
	toolsA := []KiroToolUse{
		{ToolUseID: "a", Name: "read", Input: map[string]interface{}{"path": "a.go"}},
		{ToolUseID: "b", Name: "list", Input: map[string]interface{}{"path": "/tmp"}},
	}
	toolsB := []KiroToolUse{
		{ToolUseID: "a", Name: "read", Input: map[string]interface{}{"path": "b.go"}},
		{ToolUseID: "b", Name: "list", Input: map[string]interface{}{"path": "elsewhere"}},
	}
	if debugTurnKey("k", "m", "c", "u", "a", toolsA) != debugTurnKey("k", "m", "c", "u", "a", toolsB) {
		t.Fatal("reasoning key contract binds tool IDs/names, not arguments")
	}
	reversed := []KiroToolUse{toolsA[1], toolsA[0]}
	if debugTurnKey("k", "m", "c", "u", "a", toolsA) == debugTurnKey("k", "m", "c", "u", "a", reversed) {
		t.Fatal("reasoning key must preserve tool order")
	}
}

func TestReasoningReattachesAcrossRawToolResultParent(t *testing.T) {
	globalReasoningStore = newReasoningStore()
	globalSessionStore = newSessionStore()
	const api = "key-tool-parent"
	const model = "claude-sonnet-4.5"
	const conv = "conv-tool-parent"
	const cont = "cont-tool-parent"

	inbound := []ClaudeMessage{
		{Role: "user", Content: "read it"},
		{Role: "assistant", Content: []interface{}{
			map[string]interface{}{"type": "tool_use", "id": "tu_1", "name": "read_file", "input": map[string]interface{}{"path": "a.go"}},
		}},
		{Role: "user", Content: []interface{}{
			map[string]interface{}{"type": "tool_result", "tool_use_id": "tu_1", "content": "file body"},
		}},
	}
	// Production seals against the translated current-message parent, then
	// reattaches via attachStoredReasoning on the next request.
	// For pure tool_result turns, ClaudeToKiro folds the parent into:
	// "Tool results:\n\n[read_file] file body".
	stamp := &reasoningCapture{sig: "sig-after-tool"}
	parent := "Tool results:\n\n[read_file] file body"
	stamp.sealIfPresent(api, MapModel(model), conv, parent, "final answer", nil, "reason after tool")
	sealClaudeSession(api, model, conv, cont, inbound, "final answer", "", nil, "thinking", false)

	req := &ClaudeRequest{Model: model, Messages: append(append([]ClaudeMessage(nil), inbound...),
		ClaudeMessage{Role: "assistant", Content: "final answer"},
		ClaudeMessage{Role: "user", Content: "next"},
	)}
	payload := ClaudeToKiro(req, true)
	payload.ConversationState.ConversationID = conv
	payload.ConversationState.AgentContinuationId = cont
	attachStoredReasoning(payload.ConversationState.History, api, MapModel(model), conv)
	for _, message := range payload.ConversationState.History {
		asst := message.AssistantResponseMessage
		if asst == nil || asst.Content != "final answer" {
			continue
		}
		if asst.ReasoningContent == nil || asst.ReasoningContent.ReasoningText == nil || asst.ReasoningContent.ReasoningText.Signature != "sig-after-tool" {
			t.Fatalf("post-tool assistant missing exact reasoning stamp: %+v", asst.ReasoningContent)
		}
		return
	}
	t.Fatal("post-tool assistant not found in translated history")
}

func TestReasoningSealUsesClientVisibleThinkFormat(t *testing.T) {
	globalReasoningStore = newReasoningStore()
	const api = "key-think-key"
	const model = "claude-sonnet-4.5"
	const conv = "conv-think-key"
	inbound := []ClaudeMessage{{Role: "user", Content: "question"}}
	stamp := &reasoningCapture{sig: "sig-think-key"}
	// Production seals with the client-visible assistant text, which for
	// "think" format is already folded by claudeAssistantTurn.
	visible := "<think>hidden thought</think>answer"
	stamp.sealIfPresent(api, MapModel(model), conv, "question", visible, nil, "hidden thought")
	sealClaudeSession(api, model, conv, "cont-think-key", inbound, "answer", "hidden thought", nil, "think", false)
	req := &ClaudeRequest{Model: model, Messages: []ClaudeMessage{
		{Role: "user", Content: "question"},
		{Role: "assistant", Content: visible},
		{Role: "user", Content: "next"},
	}}
	payload := ClaudeToKiro(req, true)
	payload.ConversationState.ConversationID = conv
	attachStoredReasoning(payload.ConversationState.History, api, MapModel(model), conv)
	for _, message := range payload.ConversationState.History {
		asst := message.AssistantResponseMessage
		if asst != nil && asst.Content == visible {
			if asst.ReasoningContent == nil || asst.ReasoningContent.ReasoningText == nil || asst.ReasoningContent.ReasoningText.Signature != "sig-think-key" {
				t.Fatalf("think-format key did not reattach: %+v", asst.ReasoningContent)
			}
			return
		}
	}
	t.Fatal("think-format assistant not found")
}

func TestHiddenReasoningStillSealsAndIncompleteTurnDoesNot(t *testing.T) {
	globalReasoningStore = newReasoningStore()
	globalSessionStore = newSessionStore()
	const api = "key-hidden-reasoning"
	const model = "claude-sonnet-4.5"
	const conv = "conv-hidden-reasoning"
	inbound := []ClaudeMessage{{Role: "user", Content: "question"}}
	stamp := &reasoningCapture{sig: "sig-hidden"}
	if !isSuccessfulKiroTurn("END_TURN", 0) {
		t.Fatal("END_TURN must qualify for sealing")
	}
	stamp.sealIfPresent(api, MapModel(model), conv, "question", "answer", nil, "upstream hidden thought")
	sealClaudeSession(api, model, conv, "cont-hidden", inbound, "answer", "upstream hidden thought", nil, "thinking", true)
	if got := globalReasoningStore.lookup(api, MapModel(model), conv, "question", "answer", nil); got == nil || got.Signature != "sig-hidden" {
		t.Fatalf("hidden reasoning was not stored: %+v", got)
	}

	globalReasoningStore = newReasoningStore()
	globalSessionStore = newSessionStore()
	if isSuccessfulKiroTurn("MAX_TOKENS", 0) {
		t.Fatal("MAX_TOKENS must not qualify for sealing")
	}
	// Production only seals after isSuccessfulKiroTurn; incomplete turns skip both stores.
	if got := globalReasoningStore.lookup(api, MapModel(model), conv, "question", "answer", nil); got != nil {
		t.Fatalf("incomplete reasoning leaked into store: %+v", got)
	}
	_, _, reused := resolveSessionIDs(api, MapModel(model), []ClaudeMessage{
		{Role: "user", Content: "question"},
		{Role: "assistant", Content: "answer"},
		{Role: "user", Content: "next"},
	})
	if reused {
		t.Fatal("MAX_TOKENS turn must not seal session IDs")
	}
}
