package proxy

import (
	"encoding/json"
	"kiro-go/config"
	accountpool "kiro-go/pool"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestHandlersAcceptTextOnlyCleanEOF(t *testing.T) {
	for _, tc := range []struct {
		name, path, body, terminal string
	}{
		{"Claude stream", "/v1/messages", `{"model":"claude-sonnet-4.5","max_tokens":100,"messages":[{"role":"user","content":"hi"}],"stream":true}`, `"stop_reason":"end_turn"`},
		{"Claude buffered", "/v1/messages", `{"model":"claude-sonnet-4.5","max_tokens":100,"messages":[{"role":"user","content":"hi"}]}`, `"stop_reason":"end_turn"`},
		{"Chat stream", "/v1/chat/completions", `{"model":"claude-sonnet-4.5","messages":[{"role":"user","content":"hi"}],"stream":true}`, `"finish_reason":"stop"`},
		{"Chat buffered", "/v1/chat/completions", `{"model":"claude-sonnet-4.5","messages":[{"role":"user","content":"hi"}]}`, `"finish_reason":"stop"`},
		{"Responses stream", "/v1/responses", `{"model":"claude-sonnet-4.5","input":"hi","stream":true,"store":false}`, "response.completed"},
		{"Responses buffered", "/v1/responses", `{"model":"claude-sonnet-4.5","input":"hi","store":false}`, `"status":"completed"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var hits atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				for _, chunk := range []string{"complete ", "answer"} {
					_, _ = w.Write(awsEventStreamFrame(t, "assistantResponseEvent", map[string]interface{}{"content": chunk}))
				}
				_, _ = w.Write(awsEventStreamFrame(t, "contextUsageEvent", map[string]interface{}{"contextUsagePercentage": 1}))
				_, _ = w.Write(awsEventStreamFrame(t, "meteringEvent", map[string]interface{}{"usage": 1}))
			}))
			defer server.Close()
			h := setupIntegrityPathTest(t, server)
			req := httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(tc.body))
			rec := httptest.NewRecorder()
			switch tc.path {
			case "/v1/messages":
				h.handleClaudeMessages(rec, req)
			case "/v1/chat/completions":
				h.handleOpenAIChat(rec, req)
			case "/v1/responses":
				h.handleOpenAIResponses(rec, req)
			}
			body := rec.Body.String()
			if rec.Code != http.StatusOK || !strings.Contains(body, "answer") || !strings.Contains(body, tc.terminal) {
				t.Fatalf("status=%d body=%s", rec.Code, body)
			}
			if strings.Contains(body, `"type":"error"`) || strings.Contains(body, "response.failed") || strings.Contains(body, "upstream truncated") {
				t.Fatalf("unexpected error: %s", body)
			}
			if tc.name == "Chat stream" && !strings.Contains(body, "[DONE]") {
				t.Fatalf("missing DONE: %s", body)
			}
			if hits.Load() != 1 {
				t.Fatalf("successful EOF must not retry: hits=%d", hits.Load())
			}
		})
	}
}

// setupIntegrityPathTest installs a single-account config plus a fake upstream
// and returns a handler wired to the reloaded pool.
func setupIntegrityPathTest(t *testing.T, server *httptest.Server) *Handler {
	t.Helper()
	if err := config.Init(t.TempDir() + "/config.json"); err != nil {
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
		t.Fatalf("set preferred endpoint: %v", err)
	}
	if err := config.UpdateEndpointFallback(false); err != nil {
		t.Fatalf("disable endpoint fallback: %v", err)
	}
	t.Cleanup(swapKiroEndpointsForTest(t, server))

	p := accountpool.GetPool()
	p.Reload()
	return &Handler{
		pool:        p,
		promptCache: newPromptCacheTracker(defaultPromptCacheTTL),
	}
}

// truncatedUpstream serves reasoning long enough to be flushed to the client but
// never sends a metadataEvent, i.e. a transport-successful truncated stream.
func truncatedUpstream(t *testing.T, hits *atomic.Int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits != nil {
			hits.Add(1)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(awsEventStreamFrame(t, "reasoningContentEvent", map[string]interface{}{
			"text": strings.Repeat("partial answer ", 8),
		}))
	}))
}

// A truncated stream whose content already reached the client must end with an
// SSE error, never with a forged end_turn that tells the client it is done.
func TestClaudeStreamEmitsErrorOnTruncatedStream(t *testing.T) {
	var hits atomic.Int32
	server := truncatedUpstream(t, &hits)
	defer server.Close()
	h := setupIntegrityPathTest(t, server)

	req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(`{
		"model":"claude-sonnet-4.5-thinking",
		"max_tokens":100,
		"messages":[{"role":"user","content":"hello"}],
		"stream":true
	}`))
	rec := httptest.NewRecorder()
	h.handleClaudeMessages(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, "partial answer") {
		t.Fatalf("expected flushed content, got %s", body)
	}
	if strings.Contains(body, `"stop_reason":"end_turn"`) {
		t.Fatalf("truncated stream must not be reported as end_turn, got %s", body)
	}
	if !strings.Contains(body, `"type":"error"`) {
		t.Fatalf("expected SSE error event, got %s", body)
	}
	// Content was already flushed, so reissuing would duplicate output.
	if hits.Load() != 1 {
		t.Fatalf("must not retry after client flush, hits=%d", hits.Load())
	}
}

// Non-stream buffers everything, so a truncated first attempt is safe to retry
// on the same account. The client must receive the recovered answer only.
func TestClaudeNonStreamRetriesTruncatedStream(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		w.WriteHeader(http.StatusOK)
		if n == 1 {
			_, _ = w.Write(awsEventStreamFrame(t, "reasoningContentEvent", map[string]interface{}{
				"text": "truncated attempt",
			}))
			return
		}
		_, _ = w.Write(awsEventStreamFrame(t, "assistantResponseEvent", map[string]interface{}{
			"content": "recovered answer",
		}))
		_, _ = w.Write(awsEventStreamFrame(t, "metadataEvent", map[string]interface{}{
			"stopReason": "end_turn",
		}))
	}))
	defer server.Close()
	h := setupIntegrityPathTest(t, server)

	req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(`{
		"model":"claude-sonnet-4.5-thinking",
		"max_tokens":100,
		"messages":[{"role":"user","content":"hello"}]
	}`))
	rec := httptest.NewRecorder()
	h.handleClaudeMessages(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 after recovery, got %d body=%s", rec.Code, rec.Body.String())
	}
	var resp ClaudeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v body=%s", err, rec.Body.String())
	}
	if len(resp.Content) == 0 {
		t.Fatalf("expected content, got %+v", resp)
	}
	text := resp.Content[0].Text
	if strings.Contains(text, "truncated attempt") {
		t.Fatalf("first attempt must be discarded on retry, got %q", text)
	}
	if !strings.Contains(text, "recovered answer") {
		t.Fatalf("expected recovered answer, got %q", text)
	}
	if hits.Load() < 2 {
		t.Fatalf("expected same-account retry, hits=%d", hits.Load())
	}
}

// A soft integrity failure means the upstream blipped, not that the credential
// is bad. The account must stay enabled and unbanned.
func TestIntegrityFailureDoesNotBanAccount(t *testing.T) {
	server := truncatedUpstream(t, nil)
	defer server.Close()
	h := setupIntegrityPathTest(t, server)

	req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(`{
		"model":"claude-sonnet-4.5-thinking",
		"max_tokens":100,
		"messages":[{"role":"user","content":"hello"}],
		"stream":true
	}`))
	h.handleClaudeMessages(httptest.NewRecorder(), req)

	var account *config.Account
	for _, acc := range config.GetAccounts() {
		if acc.ID == "test-account" {
			found := acc
			account = &found
			break
		}
	}
	if account == nil {
		t.Fatal("account disappeared")
	}
	if !account.Enabled {
		t.Fatal("integrity failure must not disable the account")
	}
	if account.BanStatus == "BANNED" || account.BanStatus == "DISABLED" {
		t.Fatalf("integrity failure must not ban the account, status=%q reason=%q",
			account.BanStatus, account.BanReason)
	}
}

// Responses streaming must surface response.failed instead of closing the turn
// with response.completed when the upstream truncated.
func TestResponsesStreamEmitsFailedOnTruncatedStream(t *testing.T) {
	server := truncatedUpstream(t, nil)
	defer server.Close()
	h := setupIntegrityPathTest(t, server)

	req := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(`{
		"model":"claude-sonnet-4.5-thinking",
		"input":"hello",
		"stream":true,
		"store":false
	}`))
	rec := httptest.NewRecorder()
	h.handleOpenAIResponses(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, "response.failed") {
		t.Fatalf("expected response.failed, got %s", body)
	}
	if strings.Contains(body, "response.completed") {
		t.Fatalf("truncated stream must not report response.completed, got %s", body)
	}
}

// OpenAI streaming must not close a truncated turn with a normal finish_reason.
func TestOpenAIStreamEmitsErrorOnTruncatedStream(t *testing.T) {
	server := truncatedUpstream(t, nil)
	defer server.Close()
	h := setupIntegrityPathTest(t, server)

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{
		"model":"claude-sonnet-4.5-thinking",
		"messages":[{"role":"user","content":"hello"}],
		"stream":true
	}`))
	rec := httptest.NewRecorder()
	h.handleOpenAIChat(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, "partial answer") {
		t.Fatalf("expected flushed content, got %s", body)
	}
	if strings.Contains(body, `"finish_reason":"stop"`) {
		t.Fatalf("truncated stream must not finish with stop, got %s", body)
	}
	if strings.Contains(body, "[DONE]") {
		t.Fatalf("truncated stream must not report completion, got %s", body)
	}
	if !strings.Contains(body, `"error"`) {
		t.Fatalf("expected an SSE error, got %s", body)
	}
}

// Reasoning hidden in non-thinking mode must not leak into the recovered answer.
func TestClaudeStreamRetryDoesNotLeakPreviousAttemptText(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		w.WriteHeader(http.StatusOK)
		if n == 1 {
			// Reasoning is hidden in non-thinking mode, so retry remains safe.
			_, _ = w.Write(awsEventStreamFrame(t, "reasoningContentEvent", map[string]interface{}{
				"text": "LEAK",
			}))
			return
		}
		_, _ = w.Write(awsEventStreamFrame(t, "assistantResponseEvent", map[string]interface{}{
			"content": "clean answer",
		}))
		_, _ = w.Write(awsEventStreamFrame(t, "metadataEvent", map[string]interface{}{
			"stopReason": "end_turn",
		}))
	}))
	defer server.Close()
	h := setupIntegrityPathTest(t, server)

	req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(`{
		"model":"claude-sonnet-4.5",
		"max_tokens":100,
		"messages":[{"role":"user","content":"hello"}],
		"stream":true
	}`))
	rec := httptest.NewRecorder()
	h.handleClaudeMessages(rec, req)

	body := rec.Body.String()
	if hits.Load() < 2 {
		t.Fatalf("expected retry for unflushed truncated stream, hits=%d", hits.Load())
	}
	if strings.Contains(body, "LEAK") {
		t.Fatalf("discarded attempt leaked into the retry output: %s", body)
	}
	if !strings.Contains(body, "clean answer") {
		t.Fatalf("expected recovered answer, got %s", body)
	}
}
