package proxy

import (
	"context"
	"encoding/json"
	"io"
	"kiro-go/config"
	accountpool "kiro-go/pool"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestResponsesParseStringInput(t *testing.T) {
	raw := json.RawMessage(`"hello world"`)
	msgs, err := parseResponsesInput(raw)
	if err != nil {
		t.Fatalf("parse string input: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	if msgs[0].Role != "user" {
		t.Fatalf("expected user role, got %q", msgs[0].Role)
	}
	if got, _ := msgs[0].Content.(string); got != "hello world" {
		t.Fatalf("expected hello world, got %v", msgs[0].Content)
	}
}

func TestResponsesParseArrayInput(t *testing.T) {
	raw := json.RawMessage(`[
		{"type":"message","role":"user","content":[{"type":"input_text","text":"first"}]},
		{"type":"input_text","text":"loose part"},
		{"type":"function_call_output","call_id":"call_1","output":"42"}
	]`)
	msgs, err := parseResponsesInput(raw)
	if err != nil {
		t.Fatalf("parse array input: %v", err)
	}
	if len(msgs) != 3 {
		t.Fatalf("expected 3 messages, got %d (msgs=%+v)", len(msgs), msgs)
	}
	if msgs[0].Role != "user" {
		t.Fatalf("expected first message user, got %q", msgs[0].Role)
	}
	if got, _ := msgs[0].Content.(string); got != "first" {
		t.Fatalf("expected first text, got %v", msgs[0].Content)
	}
	if msgs[2].Role != "tool" || msgs[2].ToolCallID != "call_1" {
		t.Fatalf("expected tool result with call_id call_1, got %+v", msgs[2])
	}
	if got, _ := msgs[2].Content.(string); got != "42" {
		t.Fatalf("expected tool output 42, got %v", msgs[2].Content)
	}
}

func TestResponsesStoreAndLoad(t *testing.T) {
	cfgFile := filepath.Join(t.TempDir(), "config.json")
	if err := config.Init(cfgFile); err != nil {
		t.Fatalf("config.Init: %v", err)
	}

	resp := &ResponsesObject{
		ID:        "resp_unit_test_001",
		Object:    "response",
		CreatedAt: time.Now().Unix(),
		Status:    "completed",
		Model:     "claude-sonnet-4.5",
		Output: []ResponseOutputItem{{
			ID:   "msg_x",
			Type: "message",
			Role: "assistant",
			Content: []ResponseContentPart{{
				Type: "output_text",
				Text: "stored hello",
			}},
		}},
		StoredInput: json.RawMessage(`"hi"`),
	}

	if err := saveResponse(resp); err != nil {
		t.Fatalf("save: %v", err)
	}

	loaded, err := loadResponse(resp.ID)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.ID != resp.ID || loaded.Model != resp.Model {
		t.Fatalf("loaded mismatch: %+v", loaded)
	}
	if len(loaded.Output) != 1 || loaded.Output[0].Content[0].Text != "stored hello" {
		t.Fatalf("loaded output mismatch: %+v", loaded.Output)
	}
	if string(loaded.StoredInput) != `"hi"` {
		t.Fatalf("stored input mismatch: %s", string(loaded.StoredInput))
	}

	if _, err := loadResponse("does_not_exist"); err == nil {
		t.Fatalf("expected load error for missing id")
	}
}

func TestResponsesPreviousResponseIDExpands(t *testing.T) {
	prev := &ResponsesObject{
		ID:          "resp_prev",
		StoredInput: json.RawMessage(`"earlier user"`),
		Output: []ResponseOutputItem{
			{
				Type: "message",
				Role: "assistant",
				Content: []ResponseContentPart{{
					Type: "output_text",
					Text: "earlier assistant reply",
				}},
			},
			{
				Type:      "function_call",
				CallID:    "call_prev",
				Name:      "lookup",
				Arguments: `{"q":"x"}`,
			},
		},
	}

	expanded := expandPreviousResponseHistory(prev)
	if len(expanded) != 3 {
		t.Fatalf("expected 3 messages from history, got %d (%+v)", len(expanded), expanded)
	}
	if expanded[0].Role != "user" {
		t.Fatalf("expected first message to be user, got %+v", expanded[0])
	}
	if expanded[1].Role != "assistant" {
		t.Fatalf("expected second message to be assistant, got %+v", expanded[1])
	}
	if expanded[2].Role != "assistant" || len(expanded[2].ToolCalls) != 1 {
		t.Fatalf("expected third to be assistant with tool_calls, got %+v", expanded[2])
	}
	if expanded[2].ToolCalls[0].ID != "call_prev" {
		t.Fatalf("expected tool call id call_prev, got %+v", expanded[2].ToolCalls[0])
	}
}

// A → B → C: when expanding history starting from C, all of A's and B's
// inputs/outputs must appear before C's. Previously only C's direct parent
// (B) was emitted, dropping A entirely.
func TestResponsesPreviousResponseIDExpandsFullChain(t *testing.T) {
	cfgFile := filepath.Join(t.TempDir(), "config.json")
	if err := config.Init(cfgFile); err != nil {
		t.Fatalf("config.Init: %v", err)
	}

	a := &ResponsesObject{
		ID:           "resp_a",
		Object:       "response",
		Status:       "completed",
		Model:        "claude-sonnet-4.5",
		StoredInput:  json.RawMessage(`"turn A user"`),
		StoredAt:     time.Now().Unix(),
		Instructions: "be terse",
		Output: []ResponseOutputItem{{
			Type: "message", Role: "assistant",
			Content: []ResponseContentPart{{Type: "output_text", Text: "turn A assistant"}},
		}},
	}
	b := &ResponsesObject{
		ID:                 "resp_b",
		Object:             "response",
		Status:             "completed",
		Model:              "claude-sonnet-4.5",
		StoredInput:        json.RawMessage(`"turn B user"`),
		StoredAt:           time.Now().Unix(),
		PreviousResponseID: a.ID,
		Output: []ResponseOutputItem{{
			Type: "message", Role: "assistant",
			Content: []ResponseContentPart{{Type: "output_text", Text: "turn B assistant"}},
		}},
	}
	if err := saveResponse(a); err != nil {
		t.Fatalf("save a: %v", err)
	}
	if err := saveResponse(b); err != nil {
		t.Fatalf("save b: %v", err)
	}

	expanded := expandPreviousResponseHistory(b)

	var transcript []string
	for _, m := range expanded {
		role := m.Role
		text, _ := m.Content.(string)
		transcript = append(transcript, role+":"+text)
	}
	got := strings.Join(transcript, "|")
	want := "system:be terse|user:turn A user|assistant:turn A assistant|user:turn B user|assistant:turn B assistant"
	if got != want {
		t.Fatalf("chain order mismatch:\n got=%s\nwant=%s", got, want)
	}
}

// New instructions sent on a continuation request must take effect, even when
// previous_response_id is set. The bug: the old code only attached
// req.Instructions when previous_response_id was empty, silently dropping
// updated system prompts on follow-up turns.
func TestResponsesContinuationKeepsNewInstructions(t *testing.T) {
	h, cleanup := setupResponsesTestHandler(t)
	defer cleanup()

	prev := &ResponsesObject{
		ID:          "resp_for_continuation",
		Object:      "response",
		Status:      "completed",
		Model:       "claude-sonnet-4.5",
		StoredInput: json.RawMessage(`"first user message"`),
		StoredAt:    time.Now().Unix(),
		Output: []ResponseOutputItem{{
			Type: "message", Role: "assistant",
			Content: []ResponseContentPart{{Type: "output_text", Text: "first reply"}},
		}},
	}
	if err := saveResponse(prev); err != nil {
		t.Fatalf("save prev: %v", err)
	}

	var capturedSystem string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		capturedSystem = string(body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(awsEventStreamFrame(t, "assistantResponseEvent", map[string]interface{}{
			"content": "second reply",
		}))
		_, _ = w.Write(awsEventStreamFrame(t, "metadataEvent", map[string]interface{}{
			"stopReason": "end_turn",
		}))
	}))
	defer server.Close()
	defer swapKiroEndpointsForTest(t, server)()

	body := strings.NewReader(`{
		"model":"claude-sonnet-4.5",
		"input":"second user turn",
		"previous_response_id":"resp_for_continuation",
		"instructions":"speak only French",
		"store":false
	}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/responses", body)
	rec := httptest.NewRecorder()
	h.handleOpenAIResponses(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(capturedSystem, "speak only French") {
		t.Fatalf("expected new instructions to reach upstream, payload=%s", capturedSystem)
	}
}

func setupResponsesTestHandler(t *testing.T) (*Handler, func()) {
	t.Helper()
	cfgFile := filepath.Join(t.TempDir(), "config.json")
	if err := config.Init(cfgFile); err != nil {
		t.Fatalf("config.Init: %v", err)
	}
	if err := config.AddAccount(config.Account{
		ID:          "test-account",
		Enabled:     true,
		AccessToken: "token-test",
		ProfileArn:  "arn:aws:codewhisperer:profile/test",
	}); err != nil {
		t.Fatalf("add account: %v", err)
	}
	if err := config.UpdatePreferredEndpoint("kiro"); err != nil {
		t.Fatalf("set endpoint: %v", err)
	}
	if err := config.UpdateEndpointFallback(false); err != nil {
		t.Fatalf("disable fallback: %v", err)
	}
	p := accountpool.GetPool()
	p.Reload()
	h := &Handler{
		pool:        p,
		promptCache: newPromptCacheTracker(defaultPromptCacheTTL),
	}
	cleanup := func() {}
	return h, cleanup
}

func swapKiroEndpointsForTest(t *testing.T, server *httptest.Server) func() {
	t.Helper()
	oldEndpoints := kiroEndpoints
	kiroEndpoints = []kiroEndpoint{{
		URL:    server.URL,
		Origin: "AI_EDITOR",
		Name:   "test",
	}}
	oldClient := kiroHttpStore.Load()
	kiroHttpStore.Store(&http.Client{Timeout: time.Second, Transport: &http.Transport{}})
	return func() {
		kiroEndpoints = oldEndpoints
		kiroHttpStore.Store(oldClient)
	}
}

func TestResponsesNonStreamRoundTrip(t *testing.T) {
	h, cleanup := setupResponsesTestHandler(t)
	defer cleanup()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(awsEventStreamFrame(t, "assistantResponseEvent", map[string]interface{}{
			"content": "responses non-stream OK",
		}))
		_, _ = w.Write(awsEventStreamFrame(t, "metadataEvent", map[string]interface{}{
			"stopReason": "end_turn",
		}))
	}))
	defer server.Close()
	defer swapKiroEndpointsForTest(t, server)()

	body := strings.NewReader(`{"model":"claude-sonnet-4.5","input":"hi from test"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/responses", body)
	req = req.WithContext(context.Background())
	rec := httptest.NewRecorder()

	h.handleOpenAIResponses(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	var resp ResponsesObject
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v body=%s", err, rec.Body.String())
	}
	if resp.Object != "response" {
		t.Fatalf("expected object=response, got %q", resp.Object)
	}
	if resp.Status != "completed" {
		t.Fatalf("expected status=completed, got %q", resp.Status)
	}
	if len(resp.Output) == 0 {
		t.Fatalf("expected output items, got none")
	}
	if resp.Output[0].Type != "message" || len(resp.Output[0].Content) == 0 {
		t.Fatalf("expected message with content, got %+v", resp.Output[0])
	}
	if resp.Output[0].Content[0].Text != "responses non-stream OK" {
		t.Fatalf("unexpected text: %q", resp.Output[0].Content[0].Text)
	}

	loaded, err := loadResponse(resp.ID)
	if err != nil {
		t.Fatalf("loadResponse: %v", err)
	}
	if loaded.ID != resp.ID {
		t.Fatalf("stored response id mismatch")
	}
}

func TestResponsesStreamSSE(t *testing.T) {
	h, cleanup := setupResponsesTestHandler(t)
	defer cleanup()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(awsEventStreamFrame(t, "assistantResponseEvent", map[string]interface{}{
			"content": "stream chunk",
		}))
		_, _ = w.Write(awsEventStreamFrame(t, "metadataEvent", map[string]interface{}{
			"stopReason": "end_turn",
		}))
	}))
	defer server.Close()
	defer swapKiroEndpointsForTest(t, server)()

	body := strings.NewReader(`{"model":"claude-sonnet-4.5","input":"stream please","stream":true,"store":false}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/responses", body)
	rec := httptest.NewRecorder()

	h.handleOpenAIResponses(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	bodyBytes, _ := io.ReadAll(rec.Body)
	bodyStr := string(bodyBytes)

	for _, evt := range []string{"event: response.created", "event: response.output_text.delta", "event: response.completed"} {
		if !strings.Contains(bodyStr, evt) {
			t.Fatalf("missing event %q in stream body:\n%s", evt, bodyStr)
		}
	}
	if !strings.Contains(bodyStr, "stream chunk") {
		t.Fatalf("expected stream content delta, got:\n%s", bodyStr)
	}
}

func TestResponsesStreamMaxTokensIsIncomplete(t *testing.T) {
	h, cleanup := setupResponsesTestHandler(t)
	defer cleanup()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(awsEventStreamFrame(t, "assistantResponseEvent", map[string]interface{}{"content": "partial output"}))
		_, _ = w.Write(awsEventStreamFrame(t, "metadataEvent", map[string]interface{}{"stopReason": "MAX_TOKENS"}))
	}))
	defer server.Close()
	defer swapKiroEndpointsForTest(t, server)()

	req := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(
		`{"model":"claude-sonnet-4.5","input":"write a lot","stream":true,"store":false}`,
	))
	rec := httptest.NewRecorder()
	h.handleOpenAIResponses(rec, req)
	body := rec.Body.String()

	if !strings.Contains(body, "event: response.incomplete") {
		t.Fatalf("missing response.incomplete event:\n%s", body)
	}
	if !strings.Contains(body, `"status":"incomplete"`) ||
		!strings.Contains(body, `"incomplete_details":{"reason":"max_output_tokens"}`) {
		t.Fatalf("missing incomplete status details:\n%s", body)
	}
}

func TestResponsesStreamMaxTokensMarksPreToolMessageIncomplete(t *testing.T) {
	h, cleanup := setupResponsesTestHandler(t)
	defer cleanup()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(awsEventStreamFrame(t, "assistantResponseEvent", map[string]interface{}{"content": "partial text"}))
		_, _ = w.Write(awsEventStreamFrame(t, "toolUseEvent", map[string]interface{}{
			"toolUseId": "call_1", "name": "read_file", "input": `{"path":"a.go"}`, "stop": true,
		}))
		_, _ = w.Write(awsEventStreamFrame(t, "metadataEvent", map[string]interface{}{"stopReason": "MAX_TOKENS"}))
	}))
	defer server.Close()
	defer swapKiroEndpointsForTest(t, server)()

	req := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(
		`{"model":"claude-sonnet-4.5","input":"write a lot","stream":true,"store":false}`,
	))
	rec := httptest.NewRecorder()
	h.handleOpenAIResponses(rec, req)

	foundMessage := false
	for _, line := range strings.Split(rec.Body.String(), "\n") {
		if !strings.HasPrefix(line, "data: {") {
			continue
		}
		var event map[string]interface{}
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &event); err != nil {
			continue
		}
		if event["type"] != "response.output_item.done" {
			continue
		}
		item, _ := event["item"].(map[string]interface{})
		if item["type"] != "message" {
			continue
		}
		foundMessage = true
		if item["status"] != "incomplete" {
			t.Fatalf("pre-tool message status = %v, body:\n%s", item["status"], rec.Body.String())
		}
	}
	if !foundMessage {
		t.Fatalf("missing pre-tool message completion event:\n%s", rec.Body.String())
	}
}

func TestResponsesIntegrityExhaustionRotatesOnce(t *testing.T) {
	h, cleanup := setupResponsesTestHandler(t)
	defer cleanup()

	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	defer swapKiroEndpointsForTest(t, server)()

	req := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(
		`{"model":"claude-sonnet-4.5","input":"hello","stream":true,"store":false}`,
	))
	rec := httptest.NewRecorder()
	h.handleOpenAIResponses(rec, req)

	want := int32(maxSameAccountStreamRetries + 1)
	if hits.Load() != want {
		t.Fatalf("empty account called %d times, want one same-account retry budget (%d)", hits.Load(), want)
	}
	if count := strings.Count(rec.Body.String(), "event: response.in_progress"); count != 1 {
		t.Fatalf("response.in_progress emitted %d times:\n%s", count, rec.Body.String())
	}
}
