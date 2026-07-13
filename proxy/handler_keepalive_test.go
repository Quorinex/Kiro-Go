package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	accountpool "kiro-go/pool"
	"kiro-go/config"
)

// lockedFlushRecorder 是一个并发安全的 ResponseWriter+Flusher。流式 handler 的保活
// goroutine 与主 goroutine 会并发写 w（上游中途静默时，保活补发 ': keepalive' 而主
// goroutine 仍可能在静默结束后立刻写数据）。生产代码以 hbMu 串行化这两条写路径；本
// recorder 自带锁，仅为让单测在并发写下不因 recorder 自身非线程安全而误报——真正要由
// -race 验证的是 handler 内部 emit/emitRaw 与 ping 是否正确互斥。若 hbMu 失效，race
// detector 会先抓到 handler 内部对 lastWriteNano / w 的竞争。
type lockedFlushRecorder struct {
	mu  sync.Mutex
	buf strings.Builder
}

func newLockedFlushRecorder() *lockedFlushRecorder { return &lockedFlushRecorder{} }

func (r *lockedFlushRecorder) Header() http.Header { return make(http.Header) }

func (r *lockedFlushRecorder) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.buf.Write(p)
}

func (r *lockedFlushRecorder) WriteHeader(int) {}

func (r *lockedFlushRecorder) Flush() {}

func (r *lockedFlushRecorder) body() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.buf.String()
}

// newStalledEventStreamServer 返回一个上游 server：先写一帧 assistant 文本，flush 后
// 静默 stallFor（模拟 opus 两个数据块之间的长 thinking 静默），再写第二帧。用于触发
// 流式 handler 在“数据流中途”发出保活 ping 的路径。
func newStalledEventStreamServer(t *testing.T, stallFor time.Duration) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Errorf("upstream test server ResponseWriter is not a Flusher")
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(awsEventStreamFrame(t, "assistantResponseEvent", map[string]interface{}{
			"content": "first ",
		}))
		flusher.Flush()
		time.Sleep(stallFor)
		_, _ = w.Write(awsEventStreamFrame(t, "assistantResponseEvent", map[string]interface{}{
			"content": "second",
		}))
		flusher.Flush()
	}))
}

// withFastKeepalive 临时把保活间隔调小，并返回恢复函数。
func withFastKeepalive(t *testing.T, d time.Duration) func() {
	t.Helper()
	old := streamKeepaliveInterval
	streamKeepaliveInterval = d
	return func() { streamKeepaliveInterval = old }
}

// withNoTotalTimeoutStreamClient 临时把流式 client 换成无总超时的，避免我们故意制造的
// 静默期间 client 把流砍断、掩盖保活路径。
func withNoTotalTimeoutStreamClient(t *testing.T) func() {
	t.Helper()
	old := kiroHttpStore.Load()
	kiroHttpStore.Store(&http.Client{Timeout: 0, Transport: &http.Transport{}})
	return func() { kiroHttpStore.Store(old) }
}

func setupKeepaliveTestAccount(t *testing.T, id string) {
	t.Helper()
	cfgFile := t.TempDir() + "/config.json"
	if err := config.Init(cfgFile); err != nil {
		t.Fatalf("config.Init: %v", err)
	}
	if err := config.AddAccount(config.Account{
		ID:          id,
		Enabled:     true,
		AccessToken: "token-" + id,
		ProfileArn:  "arn:aws:codewhisperer:profile/" + id,
	}); err != nil {
		t.Fatalf("add account: %v", err)
	}
	if err := config.UpdatePreferredEndpoint("kiro"); err != nil {
		t.Fatalf("set preferred endpoint: %v", err)
	}
	if err := config.UpdateEndpointFallback(false); err != nil {
		t.Fatalf("disable endpoint fallback: %v", err)
	}
}

func keepaliveTestPayload(model string) *KiroPayload {
	payload := &KiroPayload{}
	payload.ConversationState.CurrentMessage.UserInputMessage = KiroUserInputMessage{
		Content: "hello",
		ModelID: model,
		Origin:  "AI_EDITOR",
	}
	return payload
}

// TestClaudeStreamEmitsKeepaliveDuringUpstreamStall 验证：上游在两帧数据之间长静默时，
// handleClaudeStream 会在数据流中途向客户端发出 ': keepalive'，且两帧真实文本仍完整下发、
// 协议收尾正确。保活 goroutine 与主 goroutine 经 hbMu 串行化、无并发写冲突。
func TestClaudeStreamEmitsKeepaliveDuringUpstreamStall(t *testing.T) {
	setupKeepaliveTestAccount(t, "claude-keepalive")

	// 间隔 20ms，静默 200ms（≥ 多个保活周期），确保至少补发一次 ping。
	defer withFastKeepalive(t, 20*time.Millisecond)()

	server := newStalledEventStreamServer(t, 200*time.Millisecond)
	defer server.Close()

	oldEndpoints := kiroEndpoints
	kiroEndpoints = []kiroEndpoint{{URL: server.URL, Origin: "AI_EDITOR", Name: "test"}}
	defer func() { kiroEndpoints = oldEndpoints }()
	defer withNoTotalTimeoutStreamClient(t)()

	p := accountpool.GetPool()
	p.Reload()
	h := &Handler{
		pool:        p,
		promptCache: newPromptCacheTracker(defaultPromptCacheTTL),
	}

	model := "claude-opus-4-8"
	rec := newLockedFlushRecorder()
	h.handleClaudeStream(rec, keepaliveTestPayload(model), model, false, claudeThinkingResponseOptions{}, 1000, nil, "")

	body := rec.body()
	if !strings.Contains(body, ": keepalive") {
		t.Fatalf("expected a keepalive comment emitted during upstream stall, got body=%s", body)
	}
	// 两帧真实文本必须都送达，保活不能吞掉或打断数据。
	if !strings.Contains(body, "first ") || !strings.Contains(body, "second") {
		t.Fatalf("expected both upstream text frames in output, got body=%s", body)
	}
	// 协议收尾必须存在（message_start 在前、message_stop 在后）。
	if !strings.Contains(body, "message_start") {
		t.Fatalf("expected message_start, got body=%s", body)
	}
	if !strings.Contains(body, "message_stop") {
		t.Fatalf("expected message_stop, got body=%s", body)
	}
}

// TestOpenAIStreamEmitsKeepaliveDuringUpstreamStall 与上等价，覆盖 handleOpenAIStream
// 的 emitRaw/ping 并发路径。
func TestOpenAIStreamEmitsKeepaliveDuringUpstreamStall(t *testing.T) {
	setupKeepaliveTestAccount(t, "openai-keepalive")

	defer withFastKeepalive(t, 20*time.Millisecond)()

	server := newStalledEventStreamServer(t, 200*time.Millisecond)
	defer server.Close()

	oldEndpoints := kiroEndpoints
	kiroEndpoints = []kiroEndpoint{{URL: server.URL, Origin: "AI_EDITOR", Name: "test"}}
	defer func() { kiroEndpoints = oldEndpoints }()
	defer withNoTotalTimeoutStreamClient(t)()

	p := accountpool.GetPool()
	p.Reload()
	h := &Handler{
		pool:        p,
		promptCache: newPromptCacheTracker(defaultPromptCacheTTL),
	}

	model := "claude-opus-4-8"
	rec := newLockedFlushRecorder()
	h.handleOpenAIStream(rec, keepaliveTestPayload(model), model, false, 1000, "")

	body := rec.body()
	if !strings.Contains(body, ": keepalive") {
		t.Fatalf("expected a keepalive comment emitted during upstream stall, got body=%s", body)
	}
	if !strings.Contains(body, "first ") || !strings.Contains(body, "second") {
		t.Fatalf("expected both upstream text frames in output, got body=%s", body)
	}
	if !strings.Contains(body, "[DONE]") {
		t.Fatalf("expected [DONE] terminator, got body=%s", body)
	}
}
