package proxy

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"kiro-go/config"
)

func TestRetryableExternalOpenAIAttemptDoesNotRecordCompletedRequest(t *testing.T) {
	resetExternalCircuits()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	h := &Handler{}
	req := &OpenAIRequest{Model: "gpt-test", Messages: []OpenAIMessage{{Role: "user", Content: "hello"}}}
	body := []byte(`{"model":"gpt-test","messages":[{"role":"user","content":"hello"}]}`)
	if h.proxyExternalOpenAI(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body)), body, req, config.ExternalAPIConfig{BaseURL: server.URL}) {
		t.Fatal("retryable external status should fall back")
	}
	if got := len(h.getRequestLogs()); got != 0 {
		t.Fatalf("attempt-level failure created %d completed request logs", got)
	}
}

func TestRetryableClaudeToOpenAIAttemptDoesNotRecordCompletedRequest(t *testing.T) {
	resetExternalCircuits()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	h := &Handler{}
	req := &ClaudeRequest{Model: "gpt-test", Messages: []ClaudeMessage{{Role: "user", Content: "hello"}}}
	if h.proxyExternalClaudeToOpenAI(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/v1/messages", nil), req, config.ExternalAPIConfig{BaseURL: server.URL}) {
		t.Fatal("retryable external status should fall back")
	}
	if got := len(h.getRequestLogs()); got != 0 {
		t.Fatalf("attempt-level failure created %d completed request logs", got)
	}
}
