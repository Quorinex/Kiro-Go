package proxy

import (
	"context"
	"errors"
	"kiro-go/config"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// classifyStreamIntegrity is the completeness rule: a stream that returned no
// transport error is still incomplete when it carries no terminal signal.
// A stopReason of any value, or a delivered tool call, means complete. So does
// answer content plus a meteringEvent, which is the only terminal signal
// accounts that never emit metadataEvent do send.
//
// The reasoning-only case deliberately differs from Kiro IDE, which treats it
// as complete. See classifyStreamIntegrity's doc comment for why this proxy is
// stricter, and why metering does not clear it.
func TestClassifyStreamIntegrity(t *testing.T) {
	for _, tc := range []struct {
		name         string
		content      int
		tools        int
		stopReason   string
		sawReasoning bool
		sawMetering  bool
		wantErr      error
	}{
		{"complete with stop", 12, 0, "end_turn", false, false, nil},
		{"complete with tools", 0, 1, "", false, false, nil},
		{"complete with tools despite content", 12, 1, "", false, false, nil},
		{"complete with content and metering", 8, 0, "", false, true, nil},
		{"complete with content after reasoning when metered", 8, 0, "", true, true, nil},
		{"truncated content without metering", 8, 0, "", false, false, errUpstreamTruncatedResponse},
		{"reasoning only stricter than ide", 0, 0, "", true, false, errUpstreamTruncatedResponse},
		{"reasoning only stays truncated when metered", 0, 0, "", true, true, errUpstreamTruncatedResponse},
		{"no signal at all", 0, 0, "", false, false, errUpstreamTruncatedResponse},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyStreamIntegrity(tc.content, tc.tools, tc.stopReason, tc.sawReasoning, tc.sawMetering)
			if tc.wantErr == nil {
				if got != nil {
					t.Fatalf("got %v, want nil", got)
				}
				return
			}
			if got == nil || got.Error() != tc.wantErr.Error() {
				t.Fatalf("got %v, want %v", got, tc.wantErr)
			}
			if !isStreamIntegrityError(got) {
				t.Fatalf("%v must be recognized as a stream integrity error", got)
			}
		})
	}
}

// setupIntegrityTestUpstream points the Kiro endpoint list at a fake upstream
// and returns a restore func. Mirrors the fixture used by handler tests.
func setupIntegrityTestUpstream(t *testing.T, server *httptest.Server) func() {
	t.Helper()
	if err := config.Init(filepath.Join(t.TempDir(), "config.json")); err != nil {
		t.Fatalf("config.Init: %v", err)
	}
	if err := config.UpdatePreferredEndpoint("kiro"); err != nil {
		t.Fatalf("set endpoint: %v", err)
	}
	if err := config.UpdateEndpointFallback(false); err != nil {
		t.Fatalf("disable fallback: %v", err)
	}

	oldEndpoints := kiroEndpoints
	kiroEndpoints = []kiroEndpoint{{URL: server.URL, Origin: "AI_EDITOR", Name: "test"}}
	oldClient := kiroHttpStore.Load()
	kiroHttpStore.Store(&http.Client{Timeout: time.Second, Transport: &http.Transport{}})
	return func() {
		kiroEndpoints = oldEndpoints
		kiroHttpStore.Store(oldClient)
	}
}

func integrityTestAccount() *config.Account {
	return &config.Account{
		ID:          "acc",
		Email:       "acc@test",
		AccessToken: "token",
		ProfileArn:  "arn:aws:codewhisperer:profile/test",
	}
}

func integrityTestPayload() *KiroPayload {
	payload := &KiroPayload{}
	payload.ConversationState.CurrentMessage.UserInputMessage = KiroUserInputMessage{
		Content: "hi",
		Origin:  "AI_EDITOR",
	}
	return payload
}

// A stream that delivered content but no stopReason is truncated, not failed:
// the transport layer sees success and returns nil. The helper must catch that,
// reset the caller's accumulators, and retry on the same account.
//
// Note the fully-empty case is deliberately NOT used here: parseEventStreamTracked
// already returns errEmptyKiroStream when nothing was output, and
// CallKiroAPIContext retries it internally, so it never surfaces as a
// transport-successful call.
func TestRunKiroWithIntegrityRetryRecoversTruncatedThenComplete(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		w.WriteHeader(http.StatusOK)
		if n == 1 {
			// Content but no metadataEvent => transport-successful truncation.
			_, _ = w.Write(awsEventStreamFrame(t, "assistantResponseEvent", map[string]interface{}{
				"content": "partial",
			}))
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
	defer setupIntegrityTestUpstream(t, server)()

	var content string
	var stopReason string
	var resets int
	err := runKiroWithIntegrityRetry(context.Background(), integrityTestAccount(), integrityTestPayload(),
		&KiroStreamCallback{
			OnText:       func(s string, _ bool) { content += s },
			OnStopReason: func(r string) { stopReason = r },
		},
		func() (int, int, string, bool) {
			return len(content), 0, stopReason, false
		},
		func() {
			resets++
			content = ""
			stopReason = ""
		},
		nil,
	)
	if err != nil {
		t.Fatalf("expected recovery, got %v", err)
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("expected exactly one retry (2 upstream hits), got %d", got)
	}
	if resets < 1 {
		t.Fatalf("expected reset before retry, got %d", resets)
	}
	// "partial" from the first attempt must not survive into the final result.
	if content != "recovered" || stopReason != "end_turn" {
		t.Fatalf("content=%q stopReason=%q", content, stopReason)
	}
}

// An account that never sends metadataEvent still closes every turn with
// contextUsageEvent + meteringEvent. That metering is the terminal signal, so a
// complete answer must be accepted on the first attempt instead of burning the
// whole retry budget and failing.
func TestRunKiroWithIntegrityRetryAcceptsMeteredContentWithoutMetadataEvent(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(awsEventStreamFrame(t, "assistantResponseEvent", map[string]interface{}{
			"content": "complete answer",
		}))
		_, _ = w.Write(awsEventStreamFrame(t, "contextUsageEvent", map[string]interface{}{
			"contextUsagePercentage": 13.29,
		}))
		_, _ = w.Write(awsEventStreamFrame(t, "meteringEvent", map[string]interface{}{
			"usage": 0.0196,
		}))
	}))
	defer server.Close()
	defer setupIntegrityTestUpstream(t, server)()

	var content string
	var metered int
	err := runKiroWithIntegrityRetry(context.Background(), integrityTestAccount(), integrityTestPayload(),
		&KiroStreamCallback{
			OnText:     func(s string, _ bool) { content += s },
			OnMetering: func() { metered++ },
		},
		func() (int, int, string, bool) { return len(content), 0, "", false },
		func() { content = "" },
		nil,
	)
	if err != nil {
		t.Fatalf("metered content must count as complete, got %v", err)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("expected no retry, got %d upstream hits", got)
	}
	if content != "complete answer" {
		t.Fatalf("content=%q", content)
	}
	// Wrapping OnMetering for integrity must not swallow a caller's own handler.
	if metered != 1 {
		t.Fatalf("caller OnMetering must still fire, got %d", metered)
	}
}

// sawMetering must be cleared before each attempt. A metered but still
// truncated attempt (reasoning with no answer) followed by an unmetered attempt
// that did produce content must not be accepted on the strength of the earlier
// attempt's billing: that would resurrect the exact silent-success this check
// exists to prevent, one attempt removed.
func TestRunKiroWithIntegrityRetryDoesNotReuseStaleMetering(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		w.WriteHeader(http.StatusOK)
		if n == 1 {
			// Metered, but reasoning only: truncated, and sets the flag.
			_, _ = w.Write(awsEventStreamFrame(t, "reasoningContentEvent", map[string]interface{}{
				"text": "thinking",
			}))
			_, _ = w.Write(awsEventStreamFrame(t, "meteringEvent", map[string]interface{}{
				"usage": 0.01,
			}))
			return
		}
		// Content, no metering: truncated unless the stale flag leaks through.
		_, _ = w.Write(awsEventStreamFrame(t, "assistantResponseEvent", map[string]interface{}{
			"content": "answer",
		}))
	}))
	defer server.Close()
	defer setupIntegrityTestUpstream(t, server)()

	var content, reasoning string
	err := runKiroWithIntegrityRetry(context.Background(), integrityTestAccount(), integrityTestPayload(),
		&KiroStreamCallback{
			OnText: func(s string, isThinking bool) {
				if isThinking {
					reasoning += s
					return
				}
				content += s
			},
		},
		func() (int, int, string, bool) { return len(content), 0, "", reasoning != "" },
		func() { content = ""; reasoning = "" },
		nil,
	)
	if !isStreamIntegrityError(err) {
		t.Fatalf("stale metering must not clear a later unmetered attempt, got %v", err)
	}
	if got := hits.Load(); got != maxSameAccountStreamRetries+1 {
		t.Fatalf("expected the full retry budget (%d hits), got %d", maxSameAccountStreamRetries+1, got)
	}
}

// Once the client has already been flushed, an incomplete stream must not be
// retried (would duplicate output). Helper returns the integrity error so the
// caller can emit an error event instead of forging a normal completion.
func TestRunKiroWithIntegrityRetrySkipsRetryAfterClientFlush(t *testing.T) {
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
	defer setupIntegrityTestUpstream(t, server)()

	var content string
	flushed := true
	err := runKiroWithIntegrityRetry(context.Background(), integrityTestAccount(), integrityTestPayload(),
		&KiroStreamCallback{
			OnText: func(s string, _ bool) { content += s },
		},
		func() (int, int, string, bool) { return len(content), 0, "", false },
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

// A canceled client context must not drive an integrity retry. The turn is over,
// so reissuing it would only burn upstream quota.
//
// The upstream here returns content with no stopReason, which classifies as
// truncated and would otherwise be retried; cancellation must suppress that.
func TestRunKiroWithIntegrityRetryStopsOnCanceledContext(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(awsEventStreamFrame(t, "assistantResponseEvent", map[string]interface{}{
			"content": "partial",
		}))
	}))
	defer server.Close()
	defer setupIntegrityTestUpstream(t, server)()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var content string
	var resets int
	err := runKiroWithIntegrityRetry(ctx, integrityTestAccount(), integrityTestPayload(),
		&KiroStreamCallback{OnText: func(s string, _ bool) { content += s }},
		func() (int, int, string, bool) { return len(content), 0, "", false },
		func() { resets++ },
		nil,
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if isStreamIntegrityError(err) {
		t.Fatalf("cancellation must not be reported as an integrity failure: %v", err)
	}
	if resets != 0 {
		t.Fatalf("cancellation must not trigger a retry reset, got %d", resets)
	}
	if got := hits.Load(); got > 1 {
		t.Fatalf("canceled context must not drive retries, hits=%d", got)
	}
}

// The truncation retry budget must stay bounded and must be spent, not silently
// widened. Truncation never reaches the endpoint fallback (CallKiroAPIContext
// returns nil for it), so the only multiplier is account rotation; see
// maxSameAccountStreamRetries for the cost arithmetic.
func TestRunKiroWithIntegrityRetryStopsAfterBudgetExhausted(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
		// Always truncated: content with no terminal signal.
		_, _ = w.Write(awsEventStreamFrame(t, "assistantResponseEvent", map[string]interface{}{
			"content": "partial",
		}))
	}))
	defer server.Close()
	defer setupIntegrityTestUpstream(t, server)()

	var content string
	err := runKiroWithIntegrityRetry(context.Background(), integrityTestAccount(), integrityTestPayload(),
		&KiroStreamCallback{OnText: func(s string, _ bool) { content += s }},
		func() (int, int, string, bool) { return len(content), 0, "", false },
		func() { content = "" },
		nil,
	)
	if !isStreamIntegrityError(err) {
		t.Fatalf("expected integrity error once the budget is spent, got %v", err)
	}
	if got := hits.Load(); got != int32(maxSameAccountStreamRetries+1) {
		t.Fatalf("upstream hits=%d, want %d (initial attempt plus %d retry)",
			got, maxSameAccountStreamRetries+1, maxSameAccountStreamRetries)
	}
}
