package proxy

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"hash/crc32"
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

func TestParseEventStreamRejectsPreludeCRCMismatch(t *testing.T) {
	frame := awsEventStreamFrame(t, "assistantResponseEvent", map[string]interface{}{"content": "hello"})
	frame[8] ^= 0xff

	err := parseEventStream(bytes.NewReader(frame), &KiroStreamCallback{})
	if err == nil || !strings.Contains(err.Error(), "prelude CRC") {
		t.Fatalf("parse error = %v, want prelude CRC mismatch", err)
	}
}

func TestParseEventStreamRejectsMessageCRCMismatchBeforeCallbacks(t *testing.T) {
	frame := awsEventStreamFrame(t, "assistantResponseEvent", map[string]interface{}{"content": "hello"})
	frame[len(frame)-1] ^= 0xff

	called := false
	err := parseEventStream(bytes.NewReader(frame), &KiroStreamCallback{
		OnText: func(string, bool) { called = true },
	})
	if err == nil || !strings.Contains(err.Error(), "message CRC") {
		t.Fatalf("parse error = %v, want message CRC mismatch", err)
	}
	if called {
		t.Fatal("corrupt frame reached callback")
	}
}

func TestParseEventStreamReturnsModeledException(t *testing.T) {
	frame := awsEventStreamMessage(t, map[string]string{
		":message-type":   "exception",
		":exception-type": "throttlingError",
	}, map[string]interface{}{
		"message":                "rate limited",
		"reason":                 "INSUFFICIENT_MODEL_CAPACITY",
		"retryAfterMilliseconds": 1250,
	})

	err := parseEventStream(bytes.NewReader(frame), &KiroStreamCallback{})
	if err == nil {
		t.Fatal("expected modeled stream exception")
	}
	for _, want := range []string{"throttlingError", "rate limited", "INSUFFICIENT_MODEL_CAPACITY", "1250"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("stream exception %q missing %q", err, want)
		}
	}
}

func TestParseEventStreamReturnsUnmodeledError(t *testing.T) {
	frame := awsEventStreamMessage(t, map[string]string{
		":message-type":  "error",
		":error-code":    "UpstreamUnavailable",
		":error-message": "try later",
	}, nil)

	err := parseEventStream(bytes.NewReader(frame), &KiroStreamCallback{})
	if err == nil || !strings.Contains(err.Error(), "UpstreamUnavailable") || !strings.Contains(err.Error(), "try later") {
		t.Fatalf("parse error = %v, want upstream error details", err)
	}
}

func TestParseEventStreamRejectsUnknownEvent(t *testing.T) {
	frame := awsEventStreamFrame(t, "futureEvent", map[string]interface{}{"value": true})

	err := parseEventStream(bytes.NewReader(frame), &KiroStreamCallback{})
	if err == nil || !strings.Contains(err.Error(), "futureEvent") {
		t.Fatalf("parse error = %v, want unsupported event", err)
	}
}

func TestParseEventStreamIgnoresKnownOptionalEvents(t *testing.T) {
	stream := bytes.NewReader(bytes.Join([][]byte{
		awsEventStreamFrame(t, "codeReferenceEvent", map[string]interface{}{"references": []interface{}{}}),
		awsEventStreamFrame(t, "documentCitationEvent", map[string]interface{}{"title": "source"}),
		awsEventStreamFrame(t, "toolResultEvent", map[string]interface{}{}),
		awsEventStreamFrame(t, "supplementaryWebLinksEvent", map[string]interface{}{"links": []interface{}{}}),
		awsEventStreamFrame(t, "messageMetadataEvent", map[string]interface{}{}),
		awsEventStreamFrame(t, "interactionComponentsEvent", map[string]interface{}{}),
		awsEventStreamFrame(t, "intentsEvent", map[string]interface{}{}),
		awsEventStreamFrame(t, "followupPromptEvent", map[string]interface{}{}),
		awsEventStreamFrame(t, "citationEvent", map[string]interface{}{}),
		awsEventStreamFrame(t, "codeEvent", map[string]interface{}{}),
		awsEventStreamFrame(t, "dryRunSucceedEvent", map[string]interface{}{}),
	}, nil))

	if err := parseEventStream(stream, &KiroStreamCallback{}); err != nil {
		t.Fatalf("known optional events must remain compatible: %v", err)
	}
}

func TestHandleToolUseEventGeneratesMissingToolUseID(t *testing.T) {
	var toolUses []KiroToolUse
	pending := &pendingToolUses{}
	if err := handleToolUseEvent(map[string]interface{}{
		"name":  "mcpIdaProMcpStatus",
		"input": `{"server":"ida-pro-mcp"}`,
		"stop":  true,
	}, pending); err != nil {
		t.Fatalf("handle tool event: %v", err)
	}
	if len(toolUses) != 0 {
		t.Fatalf("tool must remain buffered until full-set validation: %+v", toolUses)
	}
	if err := pending.flushAll(&KiroStreamCallback{OnToolUse: func(toolUse KiroToolUse) {
		toolUses = append(toolUses, toolUse)
	}}); err != nil {
		t.Fatalf("flush tools: %v", err)
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
	}, pending); err != nil {
		t.Fatalf("first tool fragment: %v", err)
	}
	if err := handleToolUseEvent(map[string]interface{}{
		"toolUseId": "toolu_real",
		"name":      "mcpIdaProMcpStatus",
		"input":     `"ida-pro-mcp"}`,
		"stop":      true,
	}, pending); err != nil {
		t.Fatalf("final tool fragment: %v", err)
	}
	if len(toolUses) != 0 {
		t.Fatalf("tool must remain buffered until full-set validation: %+v", toolUses)
	}
	if err := pending.flushAll(callback); err != nil {
		t.Fatalf("flush tools: %v", err)
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

func TestEndpointsForAccountPrefersKiroRuntimeForOAuth(t *testing.T) {
	if err := config.Init(t.TempDir() + "/config.json"); err != nil {
		t.Fatalf("init config: %v", err)
	}
	account := &config.Account{AccessToken: "token", Region: "eu-central-1"}
	eps := endpointsForAccount(account)
	if len(eps) == 0 {
		t.Fatal("expected at least one endpoint")
	}
	if eps[0].Name != "Kiro Runtime" || eps[0].Origin != "AI_EDITOR" {
		t.Fatalf("unexpected primary endpoint: %+v", eps[0])
	}
	if resolved, err := resolveKiroEndpoint(eps[0], account, ""); err != nil || resolved.URL != "https://runtime.eu-central-1.kiro.dev/generateAssistantResponse" {
		t.Fatalf("OAuth Kiro endpoint = %+v, err=%v", resolved, err)
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
	resolved, err := resolveKiroEndpoint(eps[0], &config.Account{Region: "eu-central-1", AuthMethod: "api_key", KiroApiKey: "ksk_x"}, "")
	if err != nil || resolved.URL != "https://runtime.eu-central-1.kiro.dev/" {
		t.Fatalf("cli endpoint = %+v, err=%v", resolved, err)
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

func awsEventStreamMessage(t *testing.T, fields map[string]string, payload interface{}) []byte {
	t.Helper()

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	var headers []byte
	for _, name := range []string{":message-type", ":event-type", ":exception-type", ":error-code", ":error-message"} {
		value, ok := fields[name]
		if !ok {
			continue
		}
		headers = append(headers, byte(len(name)))
		headers = append(headers, name...)
		headers = append(headers, byte(7))
		headers = append(headers, byte(len(value)>>8), byte(len(value)))
		headers = append(headers, value...)
	}

	totalLength := 12 + len(headers) + len(payloadBytes) + 4
	frame := make([]byte, totalLength)
	binary.BigEndian.PutUint32(frame[0:4], uint32(totalLength))
	binary.BigEndian.PutUint32(frame[4:8], uint32(len(headers)))
	binary.BigEndian.PutUint32(frame[8:12], crc32.ChecksumIEEE(frame[:8]))
	copy(frame[12:], headers)
	copy(frame[12+len(headers):], payloadBytes)
	binary.BigEndian.PutUint32(frame[totalLength-4:], crc32.ChecksumIEEE(frame[:totalLength-4]))
	return frame
}

func awsEventStreamFrame(t *testing.T, eventType string, payload map[string]interface{}) []byte {
	t.Helper()
	return awsEventStreamMessage(t, map[string]string{
		":message-type": "event",
		":event-type":   eventType,
	}, payload)
}
