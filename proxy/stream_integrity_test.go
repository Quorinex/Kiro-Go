package proxy

import (
	"kiro-go/config"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// First upstream response is empty (no content, no stopReason). The helper must
// retry on the same account and succeed once a complete frame pair arrives.
func TestRunKiroWithIntegrityRetryRecoversEmptyThenComplete(t *testing.T) {
	if err := config.Init(filepath.Join(t.TempDir(), "config.json")); err != nil {
		t.Fatalf("config.Init: %v", err)
	}
	if err := config.UpdatePreferredEndpoint("kiro"); err != nil {
		t.Fatalf("set endpoint: %v", err)
	}
	if err := config.UpdateEndpointFallback(false); err != nil {
		t.Fatalf("disable fallback: %v", err)
	}
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		w.WriteHeader(http.StatusOK)
		if n == 1 {
			// Transport OK but empty body => empty-response integrity failure.
			return
		}
		_, _ = w.Write(awsEventStreamFrame(t, "assistantResponseEvent", map[string]interface{}{
			"content": "recovered",
		}))
		_, _ = w.Write(awsEventStreamFrame(t, "metadataEvent", map[string]interface{}{
			"stopReason": "end_turn",
		}))
	}))
	defer server.Close()

	oldEndpoints := kiroEndpoints
	kiroEndpoints = []kiroEndpoint{{URL: server.URL, Origin: "AI_EDITOR", Name: "test"}}
	defer func() { kiroEndpoints = oldEndpoints }()

	oldClient := kiroHttpStore.Load()
	kiroHttpStore.Store(&http.Client{Timeout: time.Second, Transport: &http.Transport{}})
	defer kiroHttpStore.Store(oldClient)

	account := &config.Account{
		ID:          "acc",
		Email:       "acc@test",
		AccessToken: "token",
		ProfileArn:  "arn:aws:codewhisperer:profile/test",
	}
	payload := &KiroPayload{}
	payload.ConversationState.CurrentMessage.UserInputMessage = KiroUserInputMessage{
		Content: "hi",
		Origin:  "AI_EDITOR",
	}

	var content string
	var resets int
	state := streamIntegrityState{}
	err := runKiroWithIntegrityRetry(account, payload,
		&state,
		func() *KiroStreamCallback {
			return &KiroStreamCallback{
				OnText:       func(s string, reasoning bool) { state.observeText(s, reasoning); content += s },
				OnStopReason: state.observeStopReason,
			}
		},
		func() {
			resets++
			content = ""
		},
		nil,
	)
	if err != nil {
		t.Fatalf("expected recovery, got %v", err)
	}
	if hits.Load() != 2 {
		t.Fatalf("upstream hits = %d, want exactly one retry", hits.Load())
	}
	if resets != 1 {
		t.Fatalf("resets = %d, want exactly one reset", resets)
	}
	if content != "recovered" || state.StopReason != "end_turn" {
		t.Fatalf("content=%q stopReason=%q", content, state.StopReason)
	}
}

func TestRunKiroWithIntegrityRetryRecoversTruncatedFrame(t *testing.T) {
	if err := config.Init(filepath.Join(t.TempDir(), "config.json")); err != nil {
		t.Fatalf("config.Init: %v", err)
	}
	if err := config.UpdatePreferredEndpoint("kiro"); err != nil {
		t.Fatalf("set endpoint: %v", err)
	}
	if err := config.UpdateEndpointFallback(false); err != nil {
		t.Fatalf("disable fallback: %v", err)
	}

	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) == 1 {
			frame := awsEventStreamFrame(t, "assistantResponseEvent", map[string]interface{}{"content": "cut"})
			_, _ = w.Write(frame[:len(frame)-3])
			return
		}
		_, _ = w.Write(awsEventStreamFrame(t, "assistantResponseEvent", map[string]interface{}{"content": "recovered"}))
		_, _ = w.Write(awsEventStreamFrame(t, "metadataEvent", map[string]interface{}{"stopReason": "END_TURN"}))
	}))
	defer server.Close()
	defer swapKiroEndpointsForTest(t, server)()

	account := &config.Account{ID: "acc", AccessToken: "token", ProfileArn: "arn:aws:codewhisperer:profile/test"}
	payload := &KiroPayload{}
	payload.ConversationState.CurrentMessage.UserInputMessage = KiroUserInputMessage{Content: "hi", Origin: "AI_EDITOR"}
	state := streamIntegrityState{}
	var content string
	err := runKiroWithIntegrityRetry(account, payload, &state,
		func() *KiroStreamCallback {
			return &KiroStreamCallback{
				OnText:       func(s string, reasoning bool) { state.observeText(s, reasoning); content += s },
				OnStopReason: state.observeStopReason,
			}
		},
		func() { content = "" },
		nil,
	)
	if err != nil {
		t.Fatalf("expected partial-frame recovery, got %v", err)
	}
	if hits.Load() != 2 || content != "recovered" || state.StopReason != "END_TURN" {
		t.Fatalf("hits=%d content=%q stopReason=%q", hits.Load(), content, state.StopReason)
	}
}

// Once the client has already been flushed, an incomplete stream must not be
// retried (would duplicate output). Helper returns the integrity error so the
// caller can emit an error event instead of forging a normal completion.
func TestRunKiroWithIntegrityRetrySkipsRetryAfterClientFlush(t *testing.T) {
	if err := config.Init(filepath.Join(t.TempDir(), "config.json")); err != nil {
		t.Fatalf("config.Init: %v", err)
	}
	if err := config.UpdatePreferredEndpoint("kiro"); err != nil {
		t.Fatalf("set endpoint: %v", err)
	}
	if err := config.UpdateEndpointFallback(false); err != nil {
		t.Fatalf("disable fallback: %v", err)
	}
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(awsEventStreamFrame(t, "assistantResponseEvent", map[string]interface{}{
			"content": "partial",
		}))
		// no metadataEvent/stopReason => truncated
	}))
	defer server.Close()

	oldEndpoints := kiroEndpoints
	kiroEndpoints = []kiroEndpoint{{URL: server.URL, Origin: "AI_EDITOR", Name: "test"}}
	defer func() { kiroEndpoints = oldEndpoints }()

	oldClient := kiroHttpStore.Load()
	kiroHttpStore.Store(&http.Client{Timeout: time.Second, Transport: &http.Transport{}})
	defer kiroHttpStore.Store(oldClient)

	account := &config.Account{ID: "acc", AccessToken: "token", ProfileArn: "arn:aws:codewhisperer:profile/test"}
	payload := &KiroPayload{}
	payload.ConversationState.CurrentMessage.UserInputMessage = KiroUserInputMessage{Content: "hi", Origin: "AI_EDITOR"}

	var content string
	flushed := false
	state := streamIntegrityState{}
	err := runKiroWithIntegrityRetry(account, payload,
		&state,
		func() *KiroStreamCallback {
			return &KiroStreamCallback{
				OnText: func(s string, reasoning bool) {
					state.observeText(s, reasoning)
					flushed = true
					content += s
				},
			}
		},
		func() { content = "" },
		func() bool { return !flushed },
	)
	if !isStreamIntegrityError(err) {
		t.Fatalf("expected integrity error after flush, got %v", err)
	}

	if hits.Load() != 1 {
		t.Fatalf("must not retry after flush, hits=%d", hits.Load())
	}
	if content != "partial" {
		t.Fatalf("content=%q", content)
	}
}

func TestSuccessfulKiroTurnSealGate(t *testing.T) {
	for _, reason := range []string{"MAX_TOKENS", "MAX_OUTPUT_TOKENS", "LENGTH", "MODEL_CONTEXT_WINDOW_EXCEEDED", "CONTENT_FILTERED", "REFUSAL"} {
		if isSuccessfulKiroTurn(reason, 0) {
			t.Fatalf("%s must not qualify for successful sealing", reason)
		}
	}
	if !isSuccessfulKiroTurn("END_TURN", 0) {
		t.Fatal("END_TURN must qualify for sealing")
	}
	if !isSuccessfulKiroTurn("", 1) {
		t.Fatal("tool turn without metadata stop must qualify for sealing")
	}
	if isSuccessfulKiroTurn("", 0) {
		t.Fatal("empty terminal signal must not qualify for sealing")
	}
}

func TestProtocolStopReasonMappings(t *testing.T) {
	if got := mapClaudeStopReason("END_TURN", 0); got != "end_turn" {
		t.Fatalf("Claude END_TURN = %q", got)
	}
	if got := mapClaudeStopReason("MAX_TOKENS", 0); got != "max_tokens" {
		t.Fatalf("Claude MAX_TOKENS = %q", got)
	}
	if got := mapClaudeStopReason("END_TURN", 1); got != "tool_use" {
		t.Fatalf("Claude tool turn = %q", got)
	}
	if got := mapOpenAIFinishReason("MAX_TOKENS", 0); got != "length" {
		t.Fatalf("OpenAI MAX_TOKENS = %q", got)
	}
	if got := mapOpenAIFinishReason("CONTENT_FILTER", 0); got != "content_filter" {
		t.Fatalf("OpenAI CONTENT_FILTER = %q", got)
	}
	if got := mapClaudeStopReason("CONTENT_FILTERED", 0); got != "refusal" {
		t.Fatalf("Claude CONTENT_FILTERED = %q", got)
	}
	if got := mapOpenAIFinishReason("CONTENT_FILTERED", 0); got != "content_filter" {
		t.Fatalf("OpenAI CONTENT_FILTERED = %q", got)
	}
	if got := mapOpenAIFinishReason("END_TURN", 1); got != "tool_calls" {
		t.Fatalf("OpenAI tool turn = %q", got)
	}
	status, reason := mapResponsesCompletion("MAX_TOKENS")
	if status != "incomplete" || reason != "max_output_tokens" {
		t.Fatalf("Responses MAX_TOKENS = status %q reason %q", status, reason)
	}
	status, reason = mapResponsesCompletion("CONTENT_FILTERED")
	if status != "incomplete" || reason != "content_filter" {
		t.Fatalf("Responses CONTENT_FILTERED = status %q reason %q", status, reason)
	}
	status, reason = mapResponsesCompletion("END_TURN")
	if status != "completed" || reason != "" {
		t.Fatalf("Responses END_TURN = status %q reason %q", status, reason)
	}
}

func TestRunKiroWithIntegrityRetryRetriesMixedToolSet(t *testing.T) {
	if err := config.Init(filepath.Join(t.TempDir(), "config.json")); err != nil {
		t.Fatalf("config.Init: %v", err)
	}
	if err := config.UpdatePreferredEndpoint("kiro"); err != nil {
		t.Fatalf("set endpoint: %v", err)
	}
	if err := config.UpdateEndpointFallback(false); err != nil {
		t.Fatalf("disable fallback: %v", err)
	}

	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) == 1 {
			_, _ = w.Write(awsEventStreamFrame(t, "toolUseEvent", map[string]interface{}{
				"toolUseId": "call_ok", "name": "read_file", "input": `{"path":"a.go"}`, "stop": true,
			}))
			_, _ = w.Write(awsEventStreamFrame(t, "toolUseEvent", map[string]interface{}{
				"toolUseId": "call_cut", "name": "write_file", "input": `{"path":"b.go",`, "stop": true,
			}))
			_, _ = w.Write(awsEventStreamFrame(t, "metadataEvent", map[string]interface{}{"stopReason": "END_TURN"}))
			return
		}
		_, _ = w.Write(awsEventStreamFrame(t, "toolUseEvent", map[string]interface{}{
			"toolUseId": "call_fresh", "name": "read_file", "input": `{"path":"fresh.go"}`, "stop": true,
		}))
		_, _ = w.Write(awsEventStreamFrame(t, "metadataEvent", map[string]interface{}{"stopReason": "TOOL_USE"}))
	}))
	defer server.Close()
	defer swapKiroEndpointsForTest(t, server)()

	account := &config.Account{ID: "acc", AccessToken: "token", ProfileArn: "arn:aws:codewhisperer:profile/test"}
	payload := &KiroPayload{}
	payload.ConversationState.CurrentMessage.UserInputMessage = KiroUserInputMessage{Content: "hi", Origin: "AI_EDITOR"}
	var tools []KiroToolUse
	state := streamIntegrityState{}
	err := runKiroWithIntegrityRetry(account, payload, &state,
		func() *KiroStreamCallback {
			return &KiroStreamCallback{
				OnToolUse:    func(tu KiroToolUse) { state.observeToolUse(); tools = append(tools, tu) },
				OnStopReason: state.observeStopReason,
			}
		},
		func() { tools = nil },
		nil,
	)
	if err != nil {
		t.Fatalf("expected retry recovery, got %v", err)
	}
	if hits.Load() != 2 {
		t.Fatalf("upstream hits = %d, want retry after mixed tool set", hits.Load())
	}
	if len(tools) != 1 || tools[0].ToolUseID != "call_fresh" {
		t.Fatalf("partial first attempt leaked into recovered tool set: %+v", tools)
	}
}
