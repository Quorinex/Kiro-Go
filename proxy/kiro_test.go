package proxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"hash/crc32"
	"io"
	"kiro-go/config"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Regression: an assistant stream whose chunks legitimately repeat must be reassembled
// verbatim. The previous content-based de-duplication turned these exact inputs into
// "666" and "abab" respectively, silently corrupting model output.
func TestParseEventStreamAssistantRepeatedContentIsNotDropped(t *testing.T) {
	for _, tc := range []struct {
		name   string
		chunks []string
		want   string
	}{
		{"repeated equal chunks", []string{"666", "666", "666", "6"}, "6666666666"},
		{"repeated period", []string{"abab", "abab"}, "abababab"},
		{"chunk equal to previous", []string{"ha", "ha", "ha"}, "hahaha"},
		{"prefix shaped chunks", []string{"6", "66"}, "666"},
		{"non repeating control", []string{"123", "4567890"}, "1234567890"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stream bytes.Buffer
			for _, c := range tc.chunks {
				stream.Write(awsEventStreamFrame(t, "assistantResponseEvent",
					map[string]interface{}{"content": c}))
			}

			var got string
			err := parseEventStream(bytes.NewReader(stream.Bytes()), &KiroStreamCallback{
				OnText: func(text string, reasoning bool) {
					if !reasoning {
						got += text
					}
				},
			})
			if err != nil {
				t.Fatalf("unexpected parse error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("assistant text corrupted: got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestParseEventStreamTrackedRejectsInvalidOrUpstreamErrorFrames(t *testing.T) {
	validText := awsEventStreamFrame(t, "assistantResponseEvent", map[string]interface{}{
		"content": "partial answer",
	})
	corruptFrame := append([]byte(nil), awsEventStreamFrame(t, "assistantResponseEvent", map[string]interface{}{
		"content": "corrupt",
	})...)
	corruptFrame[len(corruptFrame)-5] ^= 1

	upstreamError := awsEventStreamFrameWithHeaders(t, map[string]string{
		":message-type": "exception",
		":event-type":   "error",
	}, map[string]interface{}{
		"message": "upstream denied request",
	})

	for _, tc := range []struct {
		name   string
		stream []byte
	}{
		{name: "message CRC mismatch", stream: append(validText, corruptFrame...)},
		{name: "upstream exception", stream: append(validText, upstreamError...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var text string
			var completed int
			emitted, err := parseEventStreamTracked(bytes.NewReader(tc.stream), &KiroStreamCallback{
				OnText:     func(chunk string, _ bool) { text += chunk },
				OnComplete: func(int, int) { completed++ },
			})
			if err == nil {
				t.Fatal("expected invalid upstream frame to fail parsing")
			}
			if !emitted || text != "partial answer" {
				t.Fatalf("expected the first text frame to have been emitted, emitted=%v text=%q", emitted, text)
			}
			if completed != 0 {
				t.Fatalf("failed stream must not complete, got %d completion callbacks", completed)
			}
		})
	}
}

// The reasoning stream is passed through verbatim too: it carries the same pure
// incremental deltas as the assistant stream, and de-duplicating it dropped
// legitimate repeated text in exactly the same way.
func TestParseEventStreamReasoningRepeatedContentIsNotDropped(t *testing.T) {
	var stream bytes.Buffer
	for _, c := range []string{"666", "666", "666", "6"} {
		stream.Write(awsEventStreamFrame(t, "reasoningContentEvent",
			map[string]interface{}{"text": c}))
	}

	var got string
	err := parseEventStream(bytes.NewReader(stream.Bytes()), &KiroStreamCallback{
		OnText: func(text string, reasoning bool) {
			if reasoning {
				got += text
			}
		},
	})
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if got != "6666666666" {
		t.Fatalf("reasoning text corrupted: got %q, want %q", got, "6666666666")
	}
}

func TestParseEventStreamFinishesPendingToolUseOnEOF(t *testing.T) {
	stream := bytes.NewReader(awsEventStreamFrame(t, "toolUseEvent", map[string]interface{}{
		"toolUseId": "toolu_1",
		"name":      "mcpIdaProMcpStatus",
		"input":     `{"server":"ida-pro-mcp"}`,
	}))

	var toolUses []KiroToolUse
	var completed bool
	err := parseEventStream(stream, &KiroStreamCallback{
		OnToolUse: func(toolUse KiroToolUse) {
			toolUses = append(toolUses, toolUse)
		},
		OnComplete: func(_, _ int) {
			completed = true
		},
	})
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if !completed {
		t.Fatalf("expected stream completion callback")
	}
	if len(toolUses) != 1 {
		t.Fatalf("expected pending tool use to be emitted on EOF, got %d", len(toolUses))
	}
	if toolUses[0].ToolUseID != "toolu_1" || toolUses[0].Name != "mcpIdaProMcpStatus" {
		t.Fatalf("unexpected tool use: %#v", toolUses[0])
	}
	if got := toolUses[0].Input["server"]; got != "ida-pro-mcp" {
		t.Fatalf("expected parsed tool input, got %#v", toolUses[0].Input)
	}
}

func TestParseEventStreamNilCallbackIsNoOp(t *testing.T) {
	stream := bytes.NewReader(bytes.Join([][]byte{
		awsEventStreamFrame(t, "assistantResponseEvent", map[string]interface{}{"content": "hello"}),
		awsEventStreamFrame(t, "reasoningContentEvent", map[string]interface{}{"text": "thinking"}),
		awsEventStreamFrame(t, "contextUsageEvent", map[string]interface{}{"contextUsagePercentage": 12.5}),
		awsEventStreamFrame(t, "meteringEvent", map[string]interface{}{"usage": 1.25}),
		awsEventStreamFrame(t, "toolUseEvent", map[string]interface{}{
			"name":  "mcpIdaProMcpStatus",
			"input": `{"server":"ida-pro-mcp"}`,
			"stop":  true,
		}),
	}, nil))

	if err := parseEventStream(stream, nil); err != nil {
		t.Fatalf("expected nil callback to be a no-op, got %v", err)
	}
}

func TestParseEventStreamNilCallbackFieldsAreNoOp(t *testing.T) {
	stream := bytes.NewReader(awsEventStreamFrame(t, "assistantResponseEvent", map[string]interface{}{
		"content": "hello",
	}))

	if err := parseEventStream(stream, &KiroStreamCallback{}); err != nil {
		t.Fatalf("expected empty callback to be a no-op, got %v", err)
	}
}

func TestParseEventStreamPreservesInterleavedToolInputs(t *testing.T) {
	var stream bytes.Buffer
	for _, event := range []map[string]interface{}{
		{"toolUseId": "toolu_a", "name": "lookup", "input": `{"query":"a`},
		{"toolUseId": "toolu_b", "name": "lookup", "input": `{"query":"b`},
		{"toolUseId": "toolu_a", "name": "lookup", "input": `1"}`, "stop": true},
		{"toolUseId": "toolu_b", "name": "lookup", "input": `2"}`, "stop": true},
	} {
		stream.Write(awsEventStreamFrame(t, "toolUseEvent", event))
	}

	var toolUses []KiroToolUse
	err := parseEventStream(bytes.NewReader(stream.Bytes()), &KiroStreamCallback{
		OnToolUse: func(toolUse KiroToolUse) {
			toolUses = append(toolUses, toolUse)
		},
	})
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if len(toolUses) != 2 {
		t.Fatalf("tool uses=%d, want 2 (%#v)", len(toolUses), toolUses)
	}
	got := map[string]string{}
	for _, toolUse := range toolUses {
		got[toolUse.ToolUseID], _ = toolUse.Input["query"].(string)
	}
	if got["toolu_a"] != "a1" || got["toolu_b"] != "b2" {
		t.Fatalf("interleaved inputs=%#v, want toolu_a=a1 and toolu_b=b2", got)
	}
}

func TestHandleToolUseEventGeneratesMissingToolUseID(t *testing.T) {
	var toolUses []KiroToolUse
	pending := &pendingToolUses{}
	err := handleToolUseEvent(map[string]interface{}{
		"name":  "mcpIdaProMcpStatus",
		"input": `{"server":"ida-pro-mcp"}`,
		"stop":  true,
	}, pending, &KiroStreamCallback{
		OnToolUse: func(toolUse KiroToolUse) {
			toolUses = append(toolUses, toolUse)
		},
	})
	if err != nil {
		t.Fatalf("unexpected tool use error: %v", err)
	}

	if len(pending.order) != 0 {
		t.Fatalf("expected stopped tool use to clear pending state, got %d", len(pending.order))
	}
	if len(toolUses) != 1 {
		t.Fatalf("expected one tool use, got %d", len(toolUses))
	}
	if toolUses[0].ToolUseID == "" {
		t.Fatalf("expected generated tool use id")
	}
	if toolUses[0].Name != "mcpIdaProMcpStatus" {
		t.Fatalf("unexpected tool name: %q", toolUses[0].Name)
	}
}

func TestHandleToolUseEventReplacesGeneratedIDWhenRealIDArrives(t *testing.T) {
	var toolUses []KiroToolUse
	callback := &KiroStreamCallback{
		OnToolUse: func(toolUse KiroToolUse) {
			toolUses = append(toolUses, toolUse)
		},
	}
	pending := &pendingToolUses{}

	if err := handleToolUseEvent(map[string]interface{}{
		"name":  "mcpIdaProMcpStatus",
		"input": `{"server":`,
	}, pending, callback); err != nil {
		t.Fatalf("unexpected first tool fragment error: %v", err)
	}
	if err := handleToolUseEvent(map[string]interface{}{
		"toolUseId": "toolu_real",
		"name":      "mcpIdaProMcpStatus",
		"input":     `"ida-pro-mcp"}`,
		"stop":      true,
	}, pending, callback); err != nil {
		t.Fatalf("unexpected completed tool error: %v", err)
	}

	if len(pending.order) != 0 {
		t.Fatalf("expected stopped tool use to clear pending state, got %d", len(pending.order))
	}
	if len(toolUses) != 1 {
		t.Fatalf("expected one completed tool use, got %d", len(toolUses))
	}
	if toolUses[0].ToolUseID != "toolu_real" {
		t.Fatalf("expected real tool id to replace generated id, got %q", toolUses[0].ToolUseID)
	}
	if got := toolUses[0].Input["server"]; got != "ida-pro-mcp" {
		t.Fatalf("expected joined tool input, got %#v", toolUses[0].Input)
	}
}

func TestBuildKiroTransportUsesExplicitProxyURL(t *testing.T) {
	transport := buildKiroTransport("http://proxy.local:8080")
	req := &http.Request{URL: mustParseURL(t, "https://q.us-east-1.amazonaws.com")}

	got, err := transport.Proxy(req)
	if err != nil {
		t.Fatalf("unexpected proxy error: %v", err)
	}
	assertProxyURL(t, got, "http://proxy.local:8080")
}

func TestBuildKiroTransportFallsBackToEnvironmentProxy(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://env-proxy.local:2323")
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")

	transport := buildKiroTransport("")
	req := &http.Request{URL: mustParseURL(t, "https://q.us-east-1.amazonaws.com")}

	got, err := transport.Proxy(req)
	if err != nil {
		t.Fatalf("unexpected proxy error: %v", err)
	}
	assertProxyURL(t, got, "http://env-proxy.local:2323")
}

func TestInitKiroHttpClientKeepsShortRestTimeout(t *testing.T) {
	InitKiroHttpClient("")
	t.Cleanup(func() { InitKiroHttpClient("") })

	streamClient := kiroHttpStore.Load()
	restClient := kiroRestHttpStore.Load()

	if streamClient.Timeout != 5*time.Minute {
		t.Fatalf("expected streaming timeout to be 5m, got %s", streamClient.Timeout)
	}
	if restClient.Timeout != 30*time.Second {
		t.Fatalf("expected REST timeout to stay 30s, got %s", restClient.Timeout)
	}
}

func TestSetPayloadProfileArnForAccountUsesAccountArn(t *testing.T) {
	payload := &KiroPayload{ProfileArn: "arn:aws:codewhisperer:profile/stale"}

	setPayloadProfileArnForAccount(payload, &config.Account{ProfileArn: " arn:aws:codewhisperer:profile/current "})
	if payload.ProfileArn != "arn:aws:codewhisperer:profile/current" {
		t.Fatalf("expected current account profile ARN, got %q", payload.ProfileArn)
	}
}

func TestSetPayloadProfileArnForAccountPreservesExplicitPayloadArn(t *testing.T) {
	payload := &KiroPayload{ProfileArn: " arn:aws:codewhisperer:profile/explicit "}

	setPayloadProfileArnForAccount(payload, &config.Account{})
	if payload.ProfileArn != "arn:aws:codewhisperer:profile/explicit" {
		t.Fatalf("expected explicit payload profile ARN to be preserved, got %q", payload.ProfileArn)
	}
}

func TestSetPayloadProfileArnForAccountClearsAPIKeyProfile(t *testing.T) {
	payload := &KiroPayload{ProfileArn: "arn:aws:codewhisperer:us-east-1:123:profile/STALE"}
	setPayloadProfileArnForAccount(payload, &config.Account{
		AuthMethod: "api_key",
		KiroApiKey: "ksk_test",
		ProfileArn: "arn:aws:codewhisperer:us-east-1:123:profile/STALE",
	})
	if payload.ProfileArn != "" {
		t.Fatalf("expected empty profileArn for API key account, got %q", payload.ProfileArn)
	}
}

func TestEndpointsForAccountUsesCLIForAPIKey(t *testing.T) {
	eps := endpointsForAccount(&config.Account{AuthMethod: "api_key", KiroApiKey: "ksk_x"})
	if len(eps) != 1 || eps[0].Name != "Kiro CLI" {
		t.Fatalf("expected single CLI endpoint, got %+v", eps)
	}
	if eps[0].Origin != "KIRO_CLI" {
		t.Fatalf("origin = %q", eps[0].Origin)
	}
	if got := cliRuntimeURL(&config.Account{Region: "eu-central-1"}); got != "https://runtime.eu-central-1.kiro.dev/" {
		t.Fatalf("cli url = %q", got)
	}
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("invalid test URL: %v", err)
	}
	return parsed
}

func assertProxyURL(t *testing.T, got *url.URL, want string) {
	t.Helper()
	if got == nil {
		t.Fatalf("expected proxy URL %q, got nil", want)
	}
	if got.String() != want {
		t.Fatalf("expected proxy URL %q, got %q", want, got.String())
	}
}

func awsEventStreamFrame(t *testing.T, eventType string, payload map[string]interface{}) []byte {
	t.Helper()
	return awsEventStreamFrameWithHeaders(t, map[string]string{
		":event-type": eventType,
	}, payload)
}

func awsEventStreamFrameWithHeaders(t *testing.T, headers map[string]string, payload map[string]interface{}) []byte {
	t.Helper()

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	headerBytes := make([]byte, 0)
	for name, value := range headers {
		headerBytes = append(headerBytes, byte(len(name)))
		headerBytes = append(headerBytes, name...)
		headerBytes = append(headerBytes, byte(7))
		headerBytes = append(headerBytes, byte(len(value)>>8), byte(len(value)))
		headerBytes = append(headerBytes, value...)
	}

	totalLength := 12 + len(headerBytes) + len(payloadBytes) + 4
	frame := make([]byte, 12, totalLength)
	binary.BigEndian.PutUint32(frame[0:4], uint32(totalLength))
	binary.BigEndian.PutUint32(frame[4:8], uint32(len(headerBytes)))
	binary.BigEndian.PutUint32(frame[8:12], crc32.ChecksumIEEE(frame[:8]))
	frame = append(frame, headerBytes...)
	frame = append(frame, payloadBytes...)
	frame = append(frame, 0, 0, 0, 0)
	binary.BigEndian.PutUint32(frame[len(frame)-4:], crc32.ChecksumIEEE(frame[:len(frame)-4]))
	return frame
}

// --- stream EOF retry safety -------------------------------------------------

// truncatedReader yields the given bytes then fails, simulating an upstream
// connection that dies mid-stream.
type truncatedReader struct {
	data []byte
	pos  int
	err  error
}

func (r *truncatedReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, r.err
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

func TestParseEventStreamTrackedReportsNoEmissionOnEarlyFailure(t *testing.T) {
	// Stream dies before any frame completes: nothing reached the client.
	stream := &truncatedReader{data: []byte{0, 0, 1}, err: io.ErrUnexpectedEOF}

	var emittedText int
	emitted, err := parseEventStreamTracked(stream, &KiroStreamCallback{
		OnText:    func(string, bool) { emittedText++ },
		OnToolUse: func(KiroToolUse) { emittedText++ },
	})
	if err == nil {
		t.Fatalf("expected a truncation error")
	}
	if emitted {
		t.Fatalf("expected emitted=false when the stream died before any output")
	}
	if emittedText != 0 {
		t.Fatalf("expected no callbacks, got %d", emittedText)
	}
}

func TestParseEventStreamTrackedReportsEmissionAfterText(t *testing.T) {
	// One complete text frame, then the connection dies.
	frame := awsEventStreamFrame(t, "assistantResponseEvent", map[string]interface{}{
		"content": "partial answer",
	})
	stream := &truncatedReader{
		data: append(frame, 0, 0, 1),
		err:  io.ErrUnexpectedEOF,
	}

	var got string
	emitted, err := parseEventStreamTracked(stream, &KiroStreamCallback{
		OnText: func(text string, _ bool) { got += text },
	})
	if err == nil {
		t.Fatalf("expected a truncation error")
	}
	if !emitted {
		t.Fatalf("expected emitted=true once text reached the client")
	}
	if got != "partial answer" {
		t.Fatalf("expected the partial text to have been delivered, got %q", got)
	}
}

func TestParseEventStreamTrackedReportsEmissionOnCleanStream(t *testing.T) {
	stream := bytes.NewReader(awsEventStreamFrame(t, "assistantResponseEvent", map[string]interface{}{
		"content": "done",
	}))

	emitted, err := parseEventStreamTracked(stream, &KiroStreamCallback{
		OnText: func(string, bool) {},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !emitted {
		t.Fatalf("expected emitted=true for a clean stream")
	}
}

func TestParseEventStreamTrackedThinkingCountsAsEmission(t *testing.T) {
	frame := awsEventStreamFrame(t, "reasoningContentEvent", map[string]interface{}{
		"text": "let me think",
	})
	stream := &truncatedReader{data: append(frame, 0, 0, 1), err: io.ErrUnexpectedEOF}

	emitted, err := parseEventStreamTracked(stream, &KiroStreamCallback{
		OnText: func(string, bool) {},
	})
	if err == nil {
		t.Fatalf("expected a truncation error")
	}
	if !emitted {
		t.Fatalf("thinking text is client-visible, so it must count as emitted")
	}
}

func TestParseEventStreamTrackedRejectsIncompleteToolOnCleanEOF(t *testing.T) {
	frame := awsEventStreamFrame(t, "toolUseEvent", map[string]interface{}{
		"toolUseId": "toolu_partial",
		"name":      "lookup",
		"input":     `{"query":`,
	})

	var toolUses, completed int
	emitted, err := parseEventStreamTracked(bytes.NewReader(frame), &KiroStreamCallback{
		OnToolUse:  func(KiroToolUse) { toolUses++ },
		OnComplete: func(int, int) { completed++ },
	})
	if !errors.Is(err, errIncompleteKiroToolInput) {
		t.Fatalf("expected incomplete tool error, got %v", err)
	}
	if emitted {
		t.Fatal("an incomplete tool use that was not delivered must not count as emitted")
	}
	if toolUses != 0 || completed != 0 {
		t.Fatalf("toolUses=%d completed=%d, want no callbacks", toolUses, completed)
	}
}

func TestCallKiroAPIRetriesAPIKeyEndpointAfterEmptyStream(t *testing.T) {
	var calls, completed int
	var text string
	var attempts, invocationIDs, hosts []string
	installKiroStreamTestClient(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		attempts = append(attempts, req.Header.Get("Amz-Sdk-Request"))
		invocationIDs = append(invocationIDs, req.Header.Get("Amz-Sdk-Invocation-Id"))
		hosts = append(hosts, req.URL.Host)
		if calls == 1 {
			return kiroStreamTestResponse(bytes.NewReader(nil)), nil
		}
		return kiroStreamTestResponse(bytes.NewReader(awsEventStreamFrame(t,
			"assistantResponseEvent", map[string]interface{}{"content": "recovered"}))), nil
	}))

	var waits int
	installKiroRetryWait(t, func(delay time.Duration) {
		waits++
		if delay != streamRetryBackoff {
			t.Errorf("retry delay = %s, want %s", delay, streamRetryBackoff)
		}
	})

	err := CallKiroAPI(
		newKiroRetryTestAPIKeyAccount("eu-west-1"),
		newKiroRetryTestPayload(),
		&KiroStreamCallback{
			OnText:     func(chunk string, _ bool) { text += chunk },
			OnComplete: func(int, int) { completed++ },
		},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 2 || waits != 1 {
		t.Fatalf("calls=%d waits=%d, want calls=2 waits=1", calls, waits)
	}
	if text != "recovered" || completed != 1 {
		t.Fatalf("text=%q completed=%d, want recovered and one completion", text, completed)
	}
	if got := strings.Join(attempts, ","); got != "attempt=1; max=2,attempt=2; max=2" {
		t.Fatalf("attempt headers = %q", got)
	}
	if len(invocationIDs) != 2 || invocationIDs[0] == "" || invocationIDs[0] != invocationIDs[1] {
		t.Fatalf("same endpoint retries must share an invocation ID: %q", invocationIDs)
	}
	if got := strings.Join(hosts, ","); got != "runtime.eu-west-1.kiro.dev,runtime.eu-west-1.kiro.dev" {
		t.Fatalf("API key retry hosts = %q", got)
	}
}

func TestCallKiroAPIRetriesCurrentEndpointBeforeFallback(t *testing.T) {
	installKiroRetryTestEndpoints(t)

	var trace, attempts, invocationIDs []string
	var text string
	var completed int
	installKiroStreamTestClient(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		trace = append(trace, req.URL.Host)
		attempts = append(attempts, req.Header.Get("Amz-Sdk-Request"))
		invocationIDs = append(invocationIDs, req.Header.Get("Amz-Sdk-Invocation-Id"))
		if req.URL.Host == "first.example" {
			return kiroStreamTestResponse(&truncatedReader{
				data: []byte{0, 0, 1},
				err:  io.ErrUnexpectedEOF,
			}), nil
		}
		return kiroStreamTestResponse(bytes.NewReader(awsEventStreamFrame(t,
			"assistantResponseEvent", map[string]interface{}{"content": "fallback"}))), nil
	}))
	installKiroRetryWait(t, func(delay time.Duration) {
		if delay != streamRetryBackoff {
			t.Errorf("retry delay = %s, want %s", delay, streamRetryBackoff)
		}
		trace = append(trace, "wait")
	})

	err := CallKiroAPI(
		newKiroRetryTestOAuthAccount(),
		newKiroRetryTestPayload(),
		&KiroStreamCallback{
			OnText:     func(chunk string, _ bool) { text += chunk },
			OnComplete: func(int, int) { completed++ },
		},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	wantTrace := "first.example,wait,first.example,wait,second.example"
	if got := strings.Join(trace, ","); got != wantTrace {
		t.Fatalf("request trace = %q, want %q", got, wantTrace)
	}
	wantAttempts := "attempt=1; max=2,attempt=2; max=2,attempt=1; max=2"
	if got := strings.Join(attempts, ","); got != wantAttempts {
		t.Fatalf("attempt headers = %q, want %q", got, wantAttempts)
	}
	if len(invocationIDs) != 3 ||
		invocationIDs[0] == "" ||
		invocationIDs[0] != invocationIDs[1] ||
		invocationIDs[1] == invocationIDs[2] {
		t.Fatalf("unexpected invocation IDs: %q", invocationIDs)
	}
	if text != "fallback" || completed != 1 {
		t.Fatalf("text=%q completed=%d, want fallback and one completion", text, completed)
	}
}

func TestCallKiroAPISingleEndpointStopsAfterFinalAttempt(t *testing.T) {
	var calls, waits, completed int
	var attempts []string
	installKiroStreamTestClient(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		attempts = append(attempts, req.Header.Get("Amz-Sdk-Request"))
		return kiroStreamTestResponse(&truncatedReader{
			data: []byte{0, 0, 1},
			err:  io.ErrUnexpectedEOF,
		}), nil
	}))
	installKiroRetryWait(t, func(time.Duration) { waits++ })

	err := CallKiroAPI(
		newKiroRetryTestAPIKeyAccount(""),
		newKiroRetryTestPayload(),
		&KiroStreamCallback{OnComplete: func(int, int) { completed++ }},
	)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("expected final truncation error, got %v", err)
	}
	if calls != maxStreamAttemptsPerEndpoint || waits != maxStreamAttemptsPerEndpoint-1 {
		t.Fatalf("calls=%d waits=%d, want calls=%d waits=%d",
			calls, waits, maxStreamAttemptsPerEndpoint, maxStreamAttemptsPerEndpoint-1)
	}
	if completed != 0 {
		t.Fatalf("failed attempts must not complete, got %d callbacks", completed)
	}
	wantAttempts := "attempt=1; max=2,attempt=2; max=2"
	if got := strings.Join(attempts, ","); got != wantAttempts {
		t.Fatalf("attempt headers = %q, want %q", got, wantAttempts)
	}
}

func TestCallKiroAPIRetriesIncompleteToolUse(t *testing.T) {
	var calls, waits, completed int
	var toolUses []KiroToolUse
	installKiroStreamTestClient(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			frame := awsEventStreamFrame(t, "toolUseEvent", map[string]interface{}{
				"toolUseId": "toolu_partial",
				"name":      "lookup",
				"input":     `{"query":`,
				"stop":      true,
			})
			return kiroStreamTestResponse(bytes.NewReader(frame)), nil
		}
		frame := awsEventStreamFrame(t, "toolUseEvent", map[string]interface{}{
			"toolUseId": "toolu_complete",
			"name":      "lookup",
			"input":     `{"query":"kiro"}`,
			"stop":      true,
		})
		return kiroStreamTestResponse(bytes.NewReader(frame)), nil
	}))
	installKiroRetryWait(t, func(time.Duration) { waits++ })

	err := CallKiroAPI(
		newKiroRetryTestAPIKeyAccount(""),
		newKiroRetryTestPayload(),
		&KiroStreamCallback{
			OnToolUse:  func(toolUse KiroToolUse) { toolUses = append(toolUses, toolUse) },
			OnComplete: func(int, int) { completed++ },
		},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 2 || waits != 1 {
		t.Fatalf("calls=%d waits=%d, want calls=2 waits=1", calls, waits)
	}
	if len(toolUses) != 1 || toolUses[0].ToolUseID != "toolu_complete" {
		t.Fatalf("expected only the completed retry tool use, got %#v", toolUses)
	}
	if got := toolUses[0].Input["query"]; got != "kiro" {
		t.Fatalf("tool input = %#v, want kiro", got)
	}
	if completed != 1 {
		t.Fatalf("completion callbacks = %d, want 1", completed)
	}
}

func TestCallKiroAPIDoesNotRetryAfterCompletedToolCallback(t *testing.T) {
	var calls, waits, completed int
	var toolUses []KiroToolUse
	installKiroStreamTestClient(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		frame := awsEventStreamFrame(t, "toolUseEvent", map[string]interface{}{
			"toolUseId": "toolu_complete",
			"name":      "lookup",
			"input":     `{"query":"kiro"}`,
			"stop":      true,
		})
		return kiroStreamTestResponse(&truncatedReader{
			data: append(frame, 0, 0, 1),
			err:  io.ErrUnexpectedEOF,
		}), nil
	}))
	installKiroRetryWait(t, func(time.Duration) { waits++ })

	err := CallKiroAPI(
		newKiroRetryTestAPIKeyAccount(""),
		newKiroRetryTestPayload(),
		&KiroStreamCallback{
			OnToolUse:  func(toolUse KiroToolUse) { toolUses = append(toolUses, toolUse) },
			OnComplete: func(int, int) { completed++ },
		},
	)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("expected truncation error, got %v", err)
	}
	if calls != 1 || waits != 0 {
		t.Fatalf("calls=%d waits=%d, want no retry or wait after tool callback", calls, waits)
	}
	if len(toolUses) != 1 || toolUses[0].ToolUseID != "toolu_complete" {
		t.Fatalf("expected one completed tool callback, got %#v", toolUses)
	}
	if completed != 0 {
		t.Fatalf("completion callbacks = %d, want 0", completed)
	}
}

func TestCallKiroAPIDoesNotRetryTimedOutStream(t *testing.T) {
	var calls, waits int
	installKiroStreamTestClient(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return kiroStreamTestResponse(&truncatedReader{err: context.DeadlineExceeded}), nil
	}))
	installKiroRetryWait(t, func(time.Duration) { waits++ })

	err := CallKiroAPI(
		newKiroRetryTestAPIKeyAccount(""),
		newKiroRetryTestPayload(),
		&KiroStreamCallback{},
	)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline error, got %v", err)
	}
	if calls != 1 || waits != 0 {
		t.Fatalf("calls=%d waits=%d, want no retry or wait after deadline", calls, waits)
	}
}

func TestCallKiroAPIDoesNotFallbackAfterTimedOutTransport(t *testing.T) {
	installKiroRetryTestEndpoints(t)

	var calls, waits int
	installKiroStreamTestClient(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, context.DeadlineExceeded
	}))
	installKiroRetryWait(t, func(time.Duration) { waits++ })

	err := CallKiroAPI(
		newKiroRetryTestOAuthAccount(),
		newKiroRetryTestPayload(),
		&KiroStreamCallback{},
	)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline error, got %v", err)
	}
	if calls != 1 || waits != 0 {
		t.Fatalf("calls=%d waits=%d, want no fallback or wait after deadline", calls, waits)
	}
}

func TestCallKiroAPIContextStopsRetryWhenClientCancels(t *testing.T) {
	type requestContextKey struct{}
	baseContext := context.WithValue(context.Background(), requestContextKey{}, "client-request")
	ctx, cancel := context.WithCancel(baseContext)
	defer cancel()

	var calls, waits int
	installKiroStreamTestClient(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		if got := req.Context().Value(requestContextKey{}); got != "client-request" {
			t.Fatalf("upstream request context value = %v, want client-request", got)
		}
		cancel()
		return kiroStreamTestResponse(bytes.NewReader(nil)), nil
	}))
	installKiroRetryWait(t, func(time.Duration) { waits++ })

	err := CallKiroAPIContext(ctx, newKiroRetryTestAPIKeyAccount(""), newKiroRetryTestPayload(), &KiroStreamCallback{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}
	if calls != 1 || waits != 0 {
		t.Fatalf("calls=%d waits=%d, want no retry or wait after client cancellation", calls, waits)
	}
}

func installKiroRetryTestEndpoints(t *testing.T) {
	t.Helper()
	oldResolver := resolveKiroEndpoints
	resolveKiroEndpoints = func(*config.Account) []kiroEndpoint {
		return []kiroEndpoint{
			{URL: "https://first.example/generate", Origin: "AI_EDITOR", Name: "first"},
			{URL: "https://second.example/generate", Origin: "AI_EDITOR", Name: "second"},
		}
	}
	t.Cleanup(func() { resolveKiroEndpoints = oldResolver })
}

func installKiroStreamTestClient(t *testing.T, transport http.RoundTripper) {
	t.Helper()
	oldClient, hadOldClient := proxyClientCache.Load(kiroRetryTestProxyURL)
	proxyClientCache.Store(kiroRetryTestProxyURL, &http.Client{Transport: transport})
	t.Cleanup(func() {
		if hadOldClient {
			proxyClientCache.Store(kiroRetryTestProxyURL, oldClient)
		} else {
			proxyClientCache.Delete(kiroRetryTestProxyURL)
		}
	})
}

func installKiroRetryWait(t *testing.T, wait func(time.Duration)) {
	t.Helper()
	oldWait := streamRetryWait
	streamRetryWait = func(_ context.Context, delay time.Duration) error {
		wait(delay)
		return nil
	}
	t.Cleanup(func() { streamRetryWait = oldWait })
}

func newKiroRetryTestPayload() *KiroPayload {
	payload := &KiroPayload{}
	payload.ConversationState.CurrentMessage.UserInputMessage.Content = "test"
	return payload
}

const kiroRetryTestProxyURL = "test://kiro-retry-proxy"

func newKiroRetryTestAPIKeyAccount(region string) *config.Account {
	return &config.Account{
		AuthMethod: "api_key",
		KiroApiKey: "ksk_test",
		Region:     region,
		ProxyURL:   kiroRetryTestProxyURL,
	}
}

func newKiroRetryTestOAuthAccount() *config.Account {
	return &config.Account{
		AccessToken: "access-token",
		ProfileArn:  "arn:aws:codewhisperer:us-east-1:123456789012:profile/test",
		ProxyURL:    kiroRetryTestProxyURL,
	}
}

func kiroStreamTestResponse(body io.Reader) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(body),
		Header:     make(http.Header),
	}
}
