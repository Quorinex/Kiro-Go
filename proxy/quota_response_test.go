package proxy

import (
	"io"
	"kiro-go/config"
	accountpool "kiro-go/pool"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

type quotaRoundTripperFunc func(*http.Request) (*http.Response, error)

func (f quotaRoundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestClaudeQuotaFailureReturns429AndRetryAfter(t *testing.T) {
	if err := config.Init(filepath.Join(t.TempDir(), "config.json")); err != nil {
		t.Fatalf("config.Init: %v", err)
	}

	account := config.Account{
		ID: "quota", Enabled: true, AuthMethod: "api_key",
		KiroApiKey: "ksk_quota", Region: "us-east-1",
	}
	p := accountpool.NewTestPool(account)
	p.SetModelList("quota", []string{"claude-opus-5"})

	oldClient := kiroHttpStore.Load()
	kiroHttpStore.Store(&http.Client{Transport: quotaRoundTripperFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusTooManyRequests,
			Header:     http.Header{"Retry-After": []string{"45"}},
			Body:       io.NopCloser(strings.NewReader("quota")),
			Request:    req,
		}, nil
	})})
	t.Cleanup(func() { kiroHttpStore.Store(oldClient) })

	h := &Handler{pool: p, promptCache: newPromptCacheTracker(defaultPromptCacheTTL)}
	payload := &KiroPayload{}
	payload.ConversationState.CurrentMessage.UserInputMessage = KiroUserInputMessage{
		Content: "hi", ModelID: "claude-opus-5", Origin: "AI_EDITOR",
	}
	rec := httptest.NewRecorder()
	h.handleClaudeNonStream(rec, nil, nil, nil, payload, "claude-opus-5", false, claudeThinkingResponseOptions{}, 1, nil, "", false)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status=%d body=%s, want 429", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Retry-After"); got != "45" {
		t.Fatalf("Retry-After=%q, want 45", got)
	}
}
