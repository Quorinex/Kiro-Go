package proxy

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRTKCompressesClaudeToolResultBeforeUpstreamKiroRequest(t *testing.T) {
	t.Setenv("KIRO_GO_RTK_MIN_BYTES", "1")

	h, cleanup := setupResponsesTestHandler(t)
	defer cleanup()

	rawToolOutput := rtkIntegrationGrepOutput(40)
	requestBody := `{
		"model":"claude-sonnet-4.5",
		"max_tokens":256,
		"messages":[
			{"role":"user","content":"run the search"},
			{"role":"assistant","content":[{"type":"tool_use","id":"toolu_1","name":"exec_command","input":{"cmd":"rg needle"}}]},
			{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1","content":` + quoteJSONString(rawToolOutput) + `}]}
		]
	}`

	baselineKiroRequest := captureClaudeMessagesKiroRequest(t, h, requestBody, false)
	baselineText := capturedKiroToolResultText(t, baselineKiroRequest)
	if baselineText != rawToolOutput {
		t.Fatalf("expected disabled RTK to preserve raw tool result, got %q", baselineText)
	}

	compressedKiroRequest := captureClaudeMessagesKiroRequest(t, h, requestBody, true)
	compressedText := capturedKiroToolResultText(t, compressedKiroRequest)
	if !strings.Contains(compressedText, "40 matches in 1 files") {
		t.Fatalf("expected compressed grep summary in upstream Kiro request, got %q", compressedText)
	}
	if strings.Contains(compressedText, "needle occurrence 39") {
		t.Fatalf("expected raw grep tail to be removed from upstream Kiro request, got %q", compressedText)
	}

	if dir := os.Getenv("KIRO_GO_RTK_ARTIFACT_DIR"); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir artifact dir: %v", err)
		}
		writeTestArtifact(t, filepath.Join(dir, "claude-request-before.json"), []byte(requestBody))
		writeTestArtifact(t, filepath.Join(dir, "kiro-upstream-before.json"), baselineKiroRequest)
		writeTestArtifact(t, filepath.Join(dir, "kiro-upstream-after.json"), compressedKiroRequest)
		writeTestArtifact(t, filepath.Join(dir, "kiro-upstream-before.normalized.json"), normalizedKiroRequestArtifact(t, baselineKiroRequest))
		writeTestArtifact(t, filepath.Join(dir, "kiro-upstream-after.normalized.json"), normalizedKiroRequestArtifact(t, compressedKiroRequest))
		writeTestArtifact(t, filepath.Join(dir, "tool-result-before.txt"), []byte(baselineText))
		writeTestArtifact(t, filepath.Join(dir, "tool-result-after.txt"), []byte(compressedText))
	}
}

func TestRTKCompressesMultiTurnClaudeCodeSessionBeforeUpstreamKiroRequest(t *testing.T) {
	t.Setenv("KIRO_GO_RTK_MIN_BYTES", "1")

	h, cleanup := setupResponsesTestHandler(t)
	defer cleanup()

	searchOutput := rtkIntegrationGrepOutputFrom("proxy/handler.go", 200, 32, "search-history")
	buildOutput := rtkIntegrationBuildOutput(36)
	currentOutput := rtkIntegrationGrepOutputFrom("rtk/rtk.go", 500, 38, "current-search")
	requestBody := string(multiTurnClaudeCodeRequest(t, searchOutput, buildOutput, currentOutput))

	baselineKiroRequest := captureClaudeMessagesKiroRequest(t, h, requestBody, false)
	baselinePayload := decodeCapturedKiroPayload(t, baselineKiroRequest)
	baselineCurrentText := capturedKiroToolResultText(t, baselineKiroRequest)
	if baselineCurrentText != currentOutput {
		t.Fatalf("expected disabled RTK to preserve current raw tool result, got %q", baselineCurrentText)
	}
	assertActiveToolTurnPreserved(t, baselinePayload, "toolu_current_search")

	compressedKiroRequest := captureClaudeMessagesKiroRequest(t, h, requestBody, true)
	compressedPayload := decodeCapturedKiroPayload(t, compressedKiroRequest)
	compressedCurrentText := capturedKiroToolResultText(t, compressedKiroRequest)
	if !strings.Contains(compressedCurrentText, "38 matches in 1 files") {
		t.Fatalf("expected compressed current grep summary, got %q", compressedCurrentText)
	}
	if strings.Contains(compressedCurrentText, "current-search occurrence 37") {
		t.Fatalf("expected current grep tail removed, got %q", compressedCurrentText)
	}
	assertActiveToolTurnPreserved(t, compressedPayload, "toolu_current_search")

	baselineHistory := kiroHistoryText(t, baselinePayload)
	if !strings.Contains(baselineHistory, "search-history occurrence 31") {
		t.Fatalf("expected disabled RTK history to retain raw earlier search tail, got %q", baselineHistory)
	}
	if !strings.Contains(baselineHistory, "package_35") {
		t.Fatalf("expected disabled RTK history to retain raw build tail, got %q", baselineHistory)
	}

	compressedHistory := kiroHistoryText(t, compressedPayload)
	if !strings.Contains(compressedHistory, "32 matches in 1 files") {
		t.Fatalf("expected earlier search summary in history, got %q", compressedHistory)
	}
	if strings.Contains(compressedHistory, "search-history occurrence 31") {
		t.Fatalf("expected earlier search tail removed from history, got %q", compressedHistory)
	}
	if !strings.Contains(compressedHistory, "Compiled 36 packages") {
		t.Fatalf("expected build summary in history, got %q", compressedHistory)
	}
	if strings.Contains(compressedHistory, "package_35") {
		t.Fatalf("expected raw build tail removed from history, got %q", compressedHistory)
	}

	if dir := os.Getenv("KIRO_GO_RTK_ARTIFACT_DIR"); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir artifact dir: %v", err)
		}
		writeTestArtifact(t, filepath.Join(dir, "multi-turn-claude-request-before.json"), []byte(requestBody))
		writeTestArtifact(t, filepath.Join(dir, "multi-turn-kiro-upstream-before.json"), baselineKiroRequest)
		writeTestArtifact(t, filepath.Join(dir, "multi-turn-kiro-upstream-after.json"), compressedKiroRequest)
		writeTestArtifact(t, filepath.Join(dir, "multi-turn-kiro-upstream-before.normalized.json"), normalizedKiroRequestArtifact(t, baselineKiroRequest))
		writeTestArtifact(t, filepath.Join(dir, "multi-turn-kiro-upstream-after.normalized.json"), normalizedKiroRequestArtifact(t, compressedKiroRequest))
		writeTestArtifact(t, filepath.Join(dir, "multi-turn-current-tool-result-before.txt"), []byte(baselineCurrentText))
		writeTestArtifact(t, filepath.Join(dir, "multi-turn-current-tool-result-after.txt"), []byte(compressedCurrentText))
		writeTestArtifact(t, filepath.Join(dir, "multi-turn-history-before.txt"), []byte(baselineHistory))
		writeTestArtifact(t, filepath.Join(dir, "multi-turn-history-after.txt"), []byte(compressedHistory))
	}
}

func TestRTKCompressesMultiTurnOpenAIChatSessionBeforeUpstreamKiroRequest(t *testing.T) {
	t.Setenv("KIRO_GO_RTK_MIN_BYTES", "1")

	h, cleanup := setupResponsesTestHandler(t)
	defer cleanup()

	searchOutput := rtkIntegrationGrepOutputFrom("proxy/responses_handler.go", 300, 30, "codex-history")
	buildOutput := rtkIntegrationBuildOutput(34)
	currentOutput := rtkIntegrationGrepOutputFrom("rtk/rtk.go", 700, 36, "codex-current")
	requestBody := string(multiTurnOpenAIChatRequest(t, searchOutput, buildOutput, currentOutput))

	baselineKiroRequest := captureOpenAIChatKiroRequest(t, h, requestBody, false)
	baselinePayload := decodeCapturedKiroPayload(t, baselineKiroRequest)
	baselineCurrentText := capturedKiroToolResultText(t, baselineKiroRequest)
	if baselineCurrentText != currentOutput {
		t.Fatalf("expected disabled RTK to preserve current raw tool result, got %q", baselineCurrentText)
	}
	assertActiveToolTurnPreserved(t, baselinePayload, "call_current_search")

	compressedKiroRequest := captureOpenAIChatKiroRequest(t, h, requestBody, true)
	compressedPayload := decodeCapturedKiroPayload(t, compressedKiroRequest)
	compressedCurrentText := capturedKiroToolResultText(t, compressedKiroRequest)
	if !strings.Contains(compressedCurrentText, "36 matches in 1 files") {
		t.Fatalf("expected compressed current grep summary, got %q", compressedCurrentText)
	}
	if strings.Contains(compressedCurrentText, "codex-current occurrence 35") {
		t.Fatalf("expected current grep tail removed, got %q", compressedCurrentText)
	}
	assertActiveToolTurnPreserved(t, compressedPayload, "call_current_search")

	baselineHistory := kiroHistoryText(t, baselinePayload)
	if !strings.Contains(baselineHistory, "codex-history occurrence 29") {
		t.Fatalf("expected disabled RTK history to retain raw earlier search tail, got %q", baselineHistory)
	}
	if !strings.Contains(baselineHistory, "package_33") {
		t.Fatalf("expected disabled RTK history to retain raw build tail, got %q", baselineHistory)
	}

	compressedHistory := kiroHistoryText(t, compressedPayload)
	if !strings.Contains(compressedHistory, "30 matches in 1 files") {
		t.Fatalf("expected earlier search summary in history, got %q", compressedHistory)
	}
	if strings.Contains(compressedHistory, "codex-history occurrence 29") {
		t.Fatalf("expected earlier search tail removed from history, got %q", compressedHistory)
	}
	if !strings.Contains(compressedHistory, "Compiled 34 packages") {
		t.Fatalf("expected build summary in history, got %q", compressedHistory)
	}
	if strings.Contains(compressedHistory, "package_33") {
		t.Fatalf("expected raw build tail removed from history, got %q", compressedHistory)
	}

	if dir := os.Getenv("KIRO_GO_RTK_ARTIFACT_DIR"); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir artifact dir: %v", err)
		}
		writeTestArtifact(t, filepath.Join(dir, "codex-multi-turn-openai-request-before.json"), []byte(requestBody))
		writeTestArtifact(t, filepath.Join(dir, "codex-multi-turn-kiro-upstream-before.json"), baselineKiroRequest)
		writeTestArtifact(t, filepath.Join(dir, "codex-multi-turn-kiro-upstream-after.json"), compressedKiroRequest)
		writeTestArtifact(t, filepath.Join(dir, "codex-multi-turn-kiro-upstream-before.normalized.json"), normalizedKiroRequestArtifact(t, baselineKiroRequest))
		writeTestArtifact(t, filepath.Join(dir, "codex-multi-turn-kiro-upstream-after.normalized.json"), normalizedKiroRequestArtifact(t, compressedKiroRequest))
		writeTestArtifact(t, filepath.Join(dir, "codex-multi-turn-current-tool-result-before.txt"), []byte(baselineCurrentText))
		writeTestArtifact(t, filepath.Join(dir, "codex-multi-turn-current-tool-result-after.txt"), []byte(compressedCurrentText))
		writeTestArtifact(t, filepath.Join(dir, "codex-multi-turn-history-before.txt"), []byte(baselineHistory))
		writeTestArtifact(t, filepath.Join(dir, "codex-multi-turn-history-after.txt"), []byte(compressedHistory))
	}
}

func captureClaudeMessagesKiroRequest(t *testing.T, h *Handler, requestBody string, rtkEnabled bool) []byte {
	t.Helper()
	if rtkEnabled {
		t.Setenv("KIRO_GO_RTK", "true")
	} else {
		t.Setenv("KIRO_GO_RTK", "false")
	}

	var captured []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read upstream request: %v", err)
		}
		captured = append([]byte(nil), body...)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(awsEventStreamFrame(t, "assistantResponseEvent", map[string]interface{}{
			"content": "request accepted",
		}))
	}))
	defer server.Close()
	defer swapKiroEndpointsForTest(t, server)()

	req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(requestBody))
	rec := httptest.NewRecorder()
	h.handleClaudeMessages(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if len(captured) == 0 {
		t.Fatalf("expected upstream Kiro request to be captured")
	}
	return captured
}

func captureOpenAIChatKiroRequest(t *testing.T, h *Handler, requestBody string, rtkEnabled bool) []byte {
	t.Helper()
	if rtkEnabled {
		t.Setenv("KIRO_GO_RTK", "true")
	} else {
		t.Setenv("KIRO_GO_RTK", "false")
	}

	var captured []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read upstream request: %v", err)
		}
		captured = append([]byte(nil), body...)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(awsEventStreamFrame(t, "assistantResponseEvent", map[string]interface{}{
			"content": "request accepted",
		}))
	}))
	defer server.Close()
	defer swapKiroEndpointsForTest(t, server)()

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(requestBody))
	rec := httptest.NewRecorder()
	h.handleOpenAIChat(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if len(captured) == 0 {
		t.Fatalf("expected upstream Kiro request to be captured")
	}
	return captured
}

func decodeCapturedKiroPayload(t *testing.T, raw []byte) *KiroPayload {
	t.Helper()
	var payload KiroPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("decode upstream Kiro payload: %v\n%s", err, string(raw))
	}
	return &payload
}

func capturedKiroToolResultText(t *testing.T, raw []byte) string {
	t.Helper()
	var payload struct {
		ConversationState struct {
			CurrentMessage struct {
				UserInputMessage struct {
					UserInputMessageContext *struct {
						ToolResults []struct {
							Content []struct {
								Text string `json:"text"`
							} `json:"content"`
						} `json:"toolResults"`
					} `json:"userInputMessageContext"`
				} `json:"userInputMessage"`
			} `json:"currentMessage"`
		} `json:"conversationState"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("decode upstream request: %v\n%s", err, string(raw))
	}
	ctx := payload.ConversationState.CurrentMessage.UserInputMessage.UserInputMessageContext
	if ctx == nil || len(ctx.ToolResults) == 0 || len(ctx.ToolResults[0].Content) == 0 {
		t.Fatalf("upstream request missing current tool result: %s", string(raw))
	}
	return ctx.ToolResults[0].Content[0].Text
}

func normalizedKiroRequestArtifact(t *testing.T, raw []byte) []byte {
	t.Helper()
	var payload map[string]interface{}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("decode upstream request for normalized artifact: %v", err)
	}
	if conversationState, ok := payload["conversationState"].(map[string]interface{}); ok {
		conversationState["agentContinuationId"] = "<generated>"
	}
	out, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		t.Fatalf("encode normalized upstream request artifact: %v", err)
	}
	return append(out, '\n')
}

func rtkIntegrationGrepOutput(n int) string {
	return rtkIntegrationGrepOutputFrom("proxy/handler.go", 200, n, "needle")
}

func rtkIntegrationGrepOutputFrom(file string, startLine, n int, label string) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteString(file)
		b.WriteString(":")
		b.WriteString(strconvItoa(startLine + i))
		b.WriteString(": ")
		b.WriteString(label)
		b.WriteString(" occurrence ")
		b.WriteString(strconvItoa(i))
		b.WriteString(" with verbose context that should be summarized before Kiro receives it\n")
	}
	return b.String()
}

func rtkIntegrationBuildOutput(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteString("   Compiling package_")
		b.WriteString(strconvItoa(i))
		b.WriteString(" v0.1.0 (/tmp/kiro-go/package)\n")
	}
	b.WriteString("warning: generated fixture includes a representative warning\n")
	b.WriteString("    Finished test [unoptimized + debuginfo] target(s) in 12.34s\n")
	return b.String()
}

func multiTurnClaudeCodeRequest(t *testing.T, searchOutput, buildOutput, currentOutput string) []byte {
	t.Helper()
	payload := map[string]interface{}{
		"model":      "claude-sonnet-4.5",
		"max_tokens": 512,
		"system":     "You are Claude Code running in a local repository. Use tools to inspect files and test changes.",
		"messages": []interface{}{
			map[string]interface{}{"role": "user", "content": "Please inspect RTK and verify the branch."},
			map[string]interface{}{
				"role": "assistant",
				"content": []interface{}{
					map[string]interface{}{"type": "text", "text": "I will inspect the integration points."},
					map[string]interface{}{
						"type":  "tool_use",
						"id":    "toolu_search_history",
						"name":  "exec_command",
						"input": map[string]interface{}{"cmd": "rg RTK proxy rtk"},
					},
				},
			},
			map[string]interface{}{
				"role": "user",
				"content": []interface{}{
					map[string]interface{}{"type": "tool_result", "tool_use_id": "toolu_search_history", "content": searchOutput},
				},
			},
			map[string]interface{}{
				"role": "assistant",
				"content": []interface{}{
					map[string]interface{}{"type": "text", "text": "I found the integration and will run focused tests."},
					map[string]interface{}{
						"type":  "tool_use",
						"id":    "toolu_build_history",
						"name":  "exec_command",
						"input": map[string]interface{}{"cmd": "go test ./rtk ./proxy"},
					},
				},
			},
			map[string]interface{}{
				"role": "user",
				"content": []interface{}{
					map[string]interface{}{"type": "tool_result", "tool_use_id": "toolu_build_history", "content": buildOutput},
				},
			},
			map[string]interface{}{
				"role": "assistant",
				"content": []interface{}{
					map[string]interface{}{"type": "text", "text": "The focused test output is available. I will inspect one final current search result."},
					map[string]interface{}{
						"type":  "tool_use",
						"id":    "toolu_current_search",
						"name":  "exec_command",
						"input": map[string]interface{}{"cmd": "rg current-search rtk"},
					},
				},
			},
			map[string]interface{}{
				"role": "user",
				"content": []interface{}{
					map[string]interface{}{"type": "tool_result", "tool_use_id": "toolu_current_search", "content": currentOutput},
				},
			},
		},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("encode multi-turn Claude request: %v", err)
	}
	return raw
}

func multiTurnOpenAIChatRequest(t *testing.T, searchOutput, buildOutput, currentOutput string) []byte {
	t.Helper()
	payload := map[string]interface{}{
		"model":      "gpt-5-codex",
		"max_tokens": 512,
		"messages": []interface{}{
			map[string]interface{}{"role": "system", "content": "You are Codex running in a local repository. Use tools to inspect files and test changes."},
			map[string]interface{}{"role": "user", "content": "Please inspect RTK and verify the branch."},
			openAIToolCallMessage("call_search_history", "I will inspect the integration points.", "rg RTK proxy rtk"),
			map[string]interface{}{"role": "tool", "tool_call_id": "call_search_history", "content": searchOutput},
			openAIToolCallMessage("call_build_history", "I found the integration and will run focused tests.", "go test ./rtk ./proxy"),
			map[string]interface{}{"role": "tool", "tool_call_id": "call_build_history", "content": buildOutput},
			openAIToolCallMessage("call_current_search", "The focused test output is available. I will inspect one final current search result.", "rg codex-current rtk"),
			map[string]interface{}{"role": "tool", "tool_call_id": "call_current_search", "content": currentOutput},
		},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("encode multi-turn OpenAI chat request: %v", err)
	}
	return raw
}

func openAIToolCallMessage(id, text, cmd string) map[string]interface{} {
	args, _ := json.Marshal(map[string]string{"cmd": cmd})
	return map[string]interface{}{
		"role":    "assistant",
		"content": text,
		"tool_calls": []interface{}{
			map[string]interface{}{
				"id":   id,
				"type": "function",
				"function": map[string]interface{}{
					"name":      "exec_command",
					"arguments": string(args),
				},
			},
		},
	}
}

func assertActiveToolTurnPreserved(t *testing.T, payload *KiroPayload, wantToolID string) {
	t.Helper()
	history := payload.ConversationState.History
	if len(history) == 0 {
		t.Fatalf("expected Kiro history to contain prior turns")
	}
	last := history[len(history)-1].AssistantResponseMessage
	if last == nil || len(last.ToolUses) != 1 {
		t.Fatalf("expected final assistant tool use to stay structured, got %+v", history[len(history)-1])
	}
	if last.ToolUses[0].ToolUseID != wantToolID {
		t.Fatalf("expected active tool use %s, got %+v", wantToolID, last.ToolUses[0])
	}
	ctx := payload.ConversationState.CurrentMessage.UserInputMessage.UserInputMessageContext
	if ctx == nil || len(ctx.ToolResults) != 1 {
		t.Fatalf("expected current message to carry one structured tool result, got %+v", ctx)
	}
	if ctx.ToolResults[0].ToolUseID != wantToolID {
		t.Fatalf("expected current tool result to match active tool use %s, got %+v", wantToolID, ctx.ToolResults[0])
	}
}

func kiroHistoryText(t *testing.T, payload *KiroPayload) string {
	t.Helper()
	var parts []string
	for _, msg := range payload.ConversationState.History {
		if msg.UserInputMessage != nil {
			parts = append(parts, msg.UserInputMessage.Content)
		}
		if msg.AssistantResponseMessage != nil {
			parts = append(parts, msg.AssistantResponseMessage.Content)
			for _, toolUse := range msg.AssistantResponseMessage.ToolUses {
				parts = append(parts, toolUse.ToolUseID)
				parts = append(parts, toolUse.Name)
			}
		}
	}
	return strings.Join(parts, "\n")
}

func quoteJSONString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func writeTestArtifact(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write artifact %s: %v", path, err)
	}
}

func strconvItoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
