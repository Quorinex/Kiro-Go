package proxy

import (
	"errors"
	"kiro-go/config"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestCallKiroAPIPreservesLongestRetryAfterAcrossEndpoints(t *testing.T) {
	if err := config.Init(filepath.Join(t.TempDir(), "config.json")); err != nil {
		t.Fatalf("config.Init: %v", err)
	}
	serverLong := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "3600")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer serverLong.Close()
	serverShort := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "10")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer serverShort.Close()

	oldResolver := resolveKiroEndpoints
	resolveKiroEndpoints = func(*config.Account) []kiroEndpoint {
		return []kiroEndpoint{
			{URL: serverLong.URL, Origin: "AI_EDITOR", Name: "long"},
			{URL: serverShort.URL, Origin: "AI_EDITOR", Name: "short"},
		}
	}
	t.Cleanup(func() { resolveKiroEndpoints = oldResolver })
	oldClient := kiroHttpStore.Load()
	kiroHttpStore.Store(&http.Client{Timeout: time.Second})
	t.Cleanup(func() { kiroHttpStore.Store(oldClient) })

	payload := &KiroPayload{}
	payload.ConversationState.CurrentMessage.UserInputMessage = KiroUserInputMessage{
		Content: "hello", ModelID: "claude-opus-5", Origin: "AI_EDITOR",
	}
	err := CallKiroAPI(&config.Account{ID: "quota", Enabled: true, AccessToken: "token", ProfileArn: "arn:aws:codewhisperer:profile/test"}, payload, &KiroStreamCallback{})
	var quotaErr *upstreamQuotaError
	if !errors.As(err, &quotaErr) {
		t.Fatalf("error=%v, want upstreamQuotaError", err)
	}
	if quotaErr.retryFor != time.Hour {
		t.Fatalf("retryFor=%s, want 1h", quotaErr.retryFor)
	}
}
