package proxy

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"kiro-go/config"
)

type errorAfterReader struct {
	data []byte
	done bool
}

func (r *errorAfterReader) Read(p []byte) (int, error) {
	if !r.done {
		r.done = true
		return copy(p, r.data), nil
	}
	return 0, errors.New("truncated external response")
}

func (r *errorAfterReader) Close() error { return nil }

func TestExternalClaudeNonStreamReadErrorFallsBackBeforeCommit(t *testing.T) {
	resetExternalCircuits()
	oldTransport := http.DefaultTransport
	http.DefaultTransport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       &errorAfterReader{data: []byte(`{"type":"message"}`)},
		}, nil
	})
	t.Cleanup(func() { http.DefaultTransport = oldTransport })

	reqBody := `{"model":"claude-opus-5","messages":[{"role":"user","content":"hello"}],"stream":false}`
	var req ClaudeRequest
	if err := json.Unmarshal([]byte(reqBody), &req); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	h := &Handler{promptCache: newPromptCacheTracker(defaultPromptCacheTTL)}
	handled := h.proxyExternalClaude(
		recorder,
		httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(reqBody)),
		[]byte(reqBody),
		&req,
		config.ExternalAPIConfig{Enabled: true, BaseURL: "https://external.example/v1", TimeoutMS: 1000},
		false,
	)
	if handled {
		t.Fatal("read error must return false so Kiro fallback can run")
	}
	if recorder.Code != http.StatusOK || recorder.Body.Len() != 0 {
		t.Fatalf("response committed before fallback: status=%d body=%q", recorder.Code, recorder.Body.String())
	}
}

func TestExternalOpenAINonStreamReadErrorFallsBackBeforeCommit(t *testing.T) {
	resetExternalCircuits()
	oldTransport := http.DefaultTransport
	http.DefaultTransport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       &errorAfterReader{data: []byte(`{"choices":[]}`)},
		}, nil
	})
	t.Cleanup(func() { http.DefaultTransport = oldTransport })

	reqBody := `{"model":"gpt-test","messages":[{"role":"user","content":"hello"}],"stream":false}`
	var req OpenAIRequest
	if err := json.Unmarshal([]byte(reqBody), &req); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	h := &Handler{promptCache: newPromptCacheTracker(defaultPromptCacheTTL)}
	handled := h.proxyExternalOpenAI(
		recorder,
		httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(reqBody)),
		[]byte(reqBody),
		&req,
		config.ExternalAPIConfig{Enabled: true, BaseURL: "https://external-openai.example/v1", TimeoutMS: 1000},
	)
	if handled {
		t.Fatal("read error must return false so Kiro fallback can run")
	}
	if recorder.Code != http.StatusOK || recorder.Body.Len() != 0 {
		t.Fatalf("response committed before fallback: status=%d body=%q", recorder.Code, recorder.Body.String())
	}
}

func TestExternalClaudeStopHookReadErrorFallsBackBeforeCommit(t *testing.T) {
	resetExternalCircuits()
	oldTransport := http.DefaultTransport
	http.DefaultTransport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       &errorAfterReader{data: []byte(`{"type":"message"}`)},
		}, nil
	})
	t.Cleanup(func() { http.DefaultTransport = oldTransport })

	reqBody := `{"model":"claude-opus-5","messages":[{"role":"user","content":"hello"}],"stream":true}`
	var req ClaudeRequest
	if err := json.Unmarshal([]byte(reqBody), &req); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	h := &Handler{promptCache: newPromptCacheTracker(defaultPromptCacheTTL)}
	handled := h.proxyExternalClaude(
		recorder,
		httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(reqBody)),
		[]byte(reqBody),
		&req,
		config.ExternalAPIConfig{Enabled: true, BaseURL: "https://external-stop-hook.example/v1", TimeoutMS: 1000},
		true,
	)
	if handled {
		t.Fatal("stop-hook read error must return false so Kiro fallback can run")
	}
	if recorder.Code != http.StatusOK || recorder.Body.Len() != 0 {
		t.Fatalf("response committed before fallback: status=%d body=%q", recorder.Code, recorder.Body.String())
	}
}

func TestClaudeToOpenAINonStreamReadErrorFallsBackBeforeCommit(t *testing.T) {
	resetExternalCircuits()
	oldTransport := http.DefaultTransport
	http.DefaultTransport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       &errorAfterReader{data: []byte(`{"choices":[]}`)},
		}, nil
	})
	t.Cleanup(func() { http.DefaultTransport = oldTransport })

	recorder := httptest.NewRecorder()
	h := &Handler{promptCache: newPromptCacheTracker(defaultPromptCacheTTL)}
	handled := h.proxyExternalClaudeToOpenAI(
		recorder,
		httptest.NewRequest(http.MethodPost, "/v1/messages", nil),
		&ClaudeRequest{Model: "gpt-test", Messages: []ClaudeMessage{{Role: "user", Content: "hello"}}},
		config.ExternalAPIConfig{Enabled: true, BaseURL: "https://external-bridge.example/v1", TimeoutMS: 1000},
	)
	if handled {
		t.Fatal("Claude-to-OpenAI read error must return false so Kiro fallback can run")
	}
	if recorder.Code != http.StatusOK || recorder.Body.Len() != 0 {
		t.Fatalf("response committed before fallback: status=%d body=%q", recorder.Code, recorder.Body.String())
	}
}

func TestExternalClaudeStreamReadErrorMarksCommittedRequestFailed(t *testing.T) {
	resetExternalCircuits()
	oldTransport := http.DefaultTransport
	http.DefaultTransport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
			Body:       &errorAfterReader{data: []byte("data: {\"type\":\"content_block_delta\"}\n")},
		}, nil
	})
	t.Cleanup(func() { http.DefaultTransport = oldTransport })

	baseURL := "https://external-stream.example/v1"
	reqBody := `{"model":"claude-opus-5","messages":[{"role":"user","content":"hello"}],"stream":true}`
	var req ClaudeRequest
	if err := json.Unmarshal([]byte(reqBody), &req); err != nil {
		t.Fatal(err)
	}
	h := &Handler{promptCache: newPromptCacheTracker(defaultPromptCacheTTL)}
	if !h.proxyExternalClaude(
		httptest.NewRecorder(),
		httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(reqBody)),
		[]byte(reqBody), &req,
		config.ExternalAPIConfig{Enabled: true, BaseURL: baseURL, TimeoutMS: 1000}, false,
	) {
		t.Fatal("committed stream error cannot fall back and must return handled")
	}
	if failures, _ := externalCircuitStateSnapshot(baseURL); failures != 1 {
		t.Fatalf("circuit failures=%d, want 1", failures)
	}
	logs := h.getRequestLogs()
	if len(logs) != 1 || logs[0].Status != "error" {
		t.Fatalf("logs=%+v, want one failed completed request", logs)
	}
}

func TestExternalOpenAIStreamReadErrorMarksCommittedRequestFailed(t *testing.T) {
	resetExternalCircuits()
	oldTransport := http.DefaultTransport
	http.DefaultTransport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
			Body:       &errorAfterReader{data: []byte("data: {\"choices\":[]}\n")},
		}, nil
	})
	t.Cleanup(func() { http.DefaultTransport = oldTransport })

	baseURL := "https://external-openai-stream.example/v1"
	reqBody := `{"model":"gpt-test","messages":[{"role":"user","content":"hello"}],"stream":true}`
	var req OpenAIRequest
	if err := json.Unmarshal([]byte(reqBody), &req); err != nil {
		t.Fatal(err)
	}
	h := &Handler{promptCache: newPromptCacheTracker(defaultPromptCacheTTL)}
	if !h.proxyExternalOpenAI(
		httptest.NewRecorder(),
		httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(reqBody)),
		[]byte(reqBody), &req,
		config.ExternalAPIConfig{Enabled: true, BaseURL: baseURL, TimeoutMS: 1000},
	) {
		t.Fatal("committed stream error cannot fall back and must return handled")
	}
	if failures, _ := externalCircuitStateSnapshot(baseURL); failures != 1 {
		t.Fatalf("circuit failures=%d, want 1", failures)
	}
	logs := h.getRequestLogs()
	if len(logs) != 1 || logs[0].Status != "error" {
		t.Fatalf("logs=%+v, want one failed completed request", logs)
	}
}

var _ io.ReadCloser = (*errorAfterReader)(nil)
