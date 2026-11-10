package proxy

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"kiro-go/config"
)

func testPayload() *KiroPayload {
	p := &KiroPayload{}
	p.ConversationState.ChatTriggerType = "MANUAL"
	p.ConversationState.ConversationID = "conv-1"
	p.ConversationState.AgentTaskType = "SPEC_TASK"

	hist := KiroHistoryMessage{}
	hist.UserInputMessage = &KiroUserInputMessage{Content: "北京天气如何？", Origin: "AI_EDITOR"}
	p.ConversationState.History = append(p.ConversationState.History, hist)

	assistant := KiroAssistantResponseMessage{
		Content: "我查一下。</ok>",
		ToolUses: []KiroToolUse{{
			ToolUseID: "toolu_1",
			Name:      "get_weather",
			Input:     map[string]interface{}{"city": "北京"},
		}},
	}
	h2 := KiroHistoryMessage{AssistantResponseMessage: &assistant}
	p.ConversationState.History = append(p.ConversationState.History, h2)

	cur := &p.ConversationState.CurrentMessage.UserInputMessage
	cur.Content = ""
	cur.ModelID = "claude-opus-5.5"
	cur.Origin = "AI_EDITOR"
	cur.UserInputMessageContext = &UserInputMessageContext{
		ToolResults: []KiroToolResult{{
			ToolUseID: "toolu_1",
			Status:    "success",
			Content:   []KiroResultContent{{Text: `{"tempC":12}`}},
		}},
		Tools: []KiroToolWrapper{{
			ToolSpecification: struct {
				Name        string      `json:"name"`
				Description string      `json:"description"`
				InputSchema InputSchema `json:"inputSchema"`
			}{
				Name:        "get_weather",
				Description: "weather",
				InputSchema: InputSchema{JSON: map[string]interface{}{"type": "object"}},
			},
		}},
	}
	p.ProfileArn = "arn:profile/test"
	p.AdditionalModelRequestFields = map[string]interface{}{
		"thinking":      map[string]interface{}{"type": "adaptive"},
		"output_config": map[string]interface{}{"effort": "medium"},
	}
	return p
}

func TestBuildResponsesRequestMapping(t *testing.T) {
	req := buildResponsesRequest(testPayload())
	if req == nil {
		t.Fatal("nil request")
	}
	if req.Model != "claude-opus-5.5" || req.Origin != "AI_EDITOR" || !req.Stream {
		t.Fatalf("bad top level fields: %+v", req)
	}
	if req.ProfileArn != "arn:profile/test" {
		t.Fatalf("profileArn lost: %q", req.ProfileArn)
	}
	if req.Metadata["kiro:agent_mode"] != "vibe" ||
		req.Metadata["kiro:conversation_id"] != "conv-1" ||
		req.Metadata["kiro:agent_task_type"] != "SPEC_TASK" {
		t.Fatalf("metadata wrong: %+v", req.Metadata)
	}
	if req.Reasoning["type"] != "adaptive" || req.Reasoning["effort"] != "medium" {
		t.Fatalf("reasoning wrong: %+v", req.Reasoning)
	}
	if len(req.Tools) != 1 || req.Tools[0].Type != "function" || req.Tools[0].Name != "get_weather" {
		t.Fatalf("tools wrong: %+v", req.Tools)
	}
	if len(req.Input) != 4 {
		t.Fatalf("expected 4 input items, got %d: %+v", len(req.Input), req.Input)
	}
	if req.Input[0]["role"] != "user" || req.Input[0]["content"] != "北京天气如何？" {
		t.Fatalf("history user item wrong: %+v", req.Input[0])
	}
	if req.Input[1]["role"] != "assistant" || req.Input[1]["content"] != "我查一下。</ok>" {
		t.Fatalf("history assistant item wrong: %+v", req.Input[1])
	}
	if req.Input[2]["type"] != "function_call" || req.Input[2]["call_id"] != "toolu_1" ||
		req.Input[2]["name"] != "get_weather" || !strings.Contains(req.Input[2]["arguments"].(string), "北京") {
		t.Fatalf("function_call item wrong: %+v", req.Input[2])
	}
	if req.Input[3]["type"] != "function_call_output" || req.Input[3]["call_id"] != "toolu_1" ||
		req.Input[3]["output"] != `{"tempC":12}` {
		t.Fatalf("function_call_output item wrong: %+v", req.Input[3])
	}

	if _, err := json.Marshal(req); err != nil {
		t.Fatalf("request does not marshal: %v", err)
	}
}

func TestBuildResponsesRequestMultimodal(t *testing.T) {
	p := &KiroPayload{}
	cur := &p.ConversationState.CurrentMessage.UserInputMessage
	cur.ModelID = "claude-opus-5.5"
	cur.Content = "看图"
	cur.Images = []KiroImage{{Format: "PNG"}}
	cur.Images[0].Source.Bytes = "AAA"

	req := buildResponsesRequest(p)
	if len(req.Input) != 1 {
		t.Fatalf("expected 1 item, got %+v", req.Input)
	}
	parts, ok := req.Input[0]["content"].([]map[string]interface{})
	if !ok || len(parts) != 2 {
		t.Fatalf("expected text+image parts, got %+v", req.Input[0]["content"])
	}
	if parts[0]["type"] != "input_text" || parts[0]["text"] != "看图" {
		t.Fatalf("text part wrong: %+v", parts[0])
	}
	if parts[1]["type"] != "input_image" || !strings.HasPrefix(parts[1]["image_url"].(string), "data:image/png;base64,") {
		t.Fatalf("image part wrong: %+v", parts[1])
	}
}

func TestUseResponsesUpstreamGate(t *testing.T) {
	oauth := &config.Account{AuthMethod: "idc"}
	apiKey := &config.Account{AuthMethod: "api_key", KiroApiKey: "ksk_x"}

	oldEnv, hadEnv := os.LookupEnv("KIRO_UPSTREAM_PROTOCOL")
	t.Cleanup(func() {
		if hadEnv {
			_ = os.Setenv("KIRO_UPSTREAM_PROTOCOL", oldEnv)
		} else {
			_ = os.Unsetenv("KIRO_UPSTREAM_PROTOCOL")
		}
	})

	if err := os.Setenv("KIRO_UPSTREAM_PROTOCOL", responsesProtocolLegacy); err != nil {
		t.Fatal(err)
	}
	if useResponsesUpstream(oauth) {
		t.Fatal("legacy protocol should not use the responses transport")
	}

	if err := os.Unsetenv("KIRO_UPSTREAM_PROTOCOL"); err != nil {
		t.Fatal(err)
	}
	if !useResponsesUpstream(oauth) {
		t.Fatal("default protocol should use the responses transport")
	}
	if useResponsesUpstream(apiKey) {
		t.Fatal("api-key account must stay on the CLI runtime path")
	}
}

func TestParseResponsesSSETextStream(t *testing.T) {
	stream := strings.Join([]string{
		`event: response.created`,
		`data: {"type":"response.created","response":{"id":"resp_1","status":"in_progress"}}`,
		``,
		`data: {"type":"response.output_text.delta","delta":"你"}`,
		``,
		`data: {"type":"response.output_text.delta","delta":"好"}`,
		``,
		`data: {"type":"response.completed","response":{"id":"resp_1","status":"completed","usage":{"kiro:credits":{"value":0.02},"kiro:context_usage_percentage":1.5}}}`,
		``,
	}, "\n")

	var text strings.Builder
	var thinking strings.Builder
	var credits float64
	var contextPct float64
	var stop string
	var inTok, outTok int
	cb := &KiroStreamCallback{
		OnText: func(s string, isThinking bool) {
			if isThinking {
				thinking.WriteString(s)
				return
			}
			text.WriteString(s)
		},
		OnCredits:      func(c float64) { credits = c },
		OnContextUsage: func(p float64) { contextPct = p },
		OnStopReason:   func(r string) { stop = r },
		OnComplete:     func(i, o int) { inTok, outTok = i, o },
	}

	if _, err := parseResponsesSSE(strings.NewReader(stream), testPayload(), cb); err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if text.String() != "你好" {
		t.Fatalf("text = %q", text.String())
	}
	if thinking.Len() != 0 {
		t.Fatalf("unexpected thinking %q", thinking.String())
	}
	if credits != 0.02 || contextPct != 1.5 {
		t.Fatalf("credits=%v pct=%v", credits, contextPct)
	}
	if stop != "END_TURN" {
		t.Fatalf("stop reason = %q", stop)
	}
	if inTok <= 0 || outTok <= 0 {
		t.Fatalf("token estimates missing: in=%d out=%d", inTok, outTok)
	}
}

func TestParseResponsesSSEToolCall(t *testing.T) {
	stream := strings.Join([]string{
		`data: {"type":"response.output_item.added","item":{"type":"function_call","id":"fc_1","call_id":"toolu_9","name":"get_weather"}}`,
		``,
		`data: {"type":"response.function_call_arguments.delta","item_id":"fc_1","delta":"{\"city\":"}`,
		``,
		`data: {"type":"response.function_call_arguments.delta","item_id":"fc_1","delta":"\"北京\"}"}`,
		``,
		`data: {"type":"response.function_call_arguments.done","item_id":"fc_1","arguments":"{\"city\":\"北京\"}"}`,
		``,
		`data: {"type":"response.output_item.done","item":{"type":"function_call","id":"fc_1","call_id":"toolu_9","name":"get_weather","arguments":"{\"city\":\"北京\"}"}}`,
		``,
		`data: {"type":"response.completed","response":{"id":"resp_2","status":"requires_action","usage":{"kiro:credits":{"value":0.01}}}}`,
		``,
	}, "\n")

	var tools []KiroToolUse
	cb := &KiroStreamCallback{OnToolUse: func(tu KiroToolUse) { tools = append(tools, tu) }}

	if _, err := parseResponsesSSE(strings.NewReader(stream), testPayload(), cb); err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(tools) != 1 {
		t.Fatalf("expected 1 tool use, got %d", len(tools))
	}
	if tools[0].ToolUseID != "toolu_9" || tools[0].Name != "get_weather" {
		t.Fatalf("tool identity wrong: %+v", tools[0])
	}
	if city, ok := tools[0].Input["city"].(string); !ok || city != "北京" {
		t.Fatalf("arguments not parsed: %+v", tools[0].Input)
	}
}

func TestParseResponsesSSEReasoningChannel(t *testing.T) {
	stream := strings.Join([]string{
		`data: {"type":"response.output_item.added","item":{"type":"reasoning","id":"rs_1","status":"in_progress"}}`,
		``,
		`data: {"type":"response.reasoning_text.delta","delta":"先算一下"}`,
		``,
		`data: {"type":"response.output_text.delta","delta":"答案是8"}`,
		``,
		`data: {"type":"response.completed","response":{"id":"resp_3","status":"completed"}}`,
		``,
	}, "\n")

	var text, thinking strings.Builder
	cb := &KiroStreamCallback{OnText: func(s string, isThinking bool) {
		if isThinking {
			thinking.WriteString(s)
		} else {
			text.WriteString(s)
		}
	}}
	if _, err := parseResponsesSSE(strings.NewReader(stream), testPayload(), cb); err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if thinking.String() != "先算一下" {
		t.Fatalf("thinking = %q", thinking.String())
	}
	if text.String() != "答案是8" {
		t.Fatalf("text = %q", text.String())
	}
}

func TestParseResponsesSSETruncated(t *testing.T) {
	stream := strings.Join([]string{
		`data: {"type":"response.output_text.delta","delta":"半截"}`,
		``,
	}, "\n")
	// Text already reached the client: emitted must be true so the caller does
	// not retry and duplicate the answer.
	emitted, err := parseResponsesSSE(strings.NewReader(stream), testPayload(), &KiroStreamCallback{})
	if err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("expected truncation error, got %v", err)
	}
	if !emitted {
		t.Fatal("emitted should be true once a delta was delivered")
	}
}

func TestParseResponsesSSEEmpty(t *testing.T) {
	_, err := parseResponsesSSE(strings.NewReader(""), testPayload(), &KiroStreamCallback{})
	if err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("expected truncation error, got %v", err)
	}
}

func TestParseResponsesSSEFailedStatus(t *testing.T) {
	stream := strings.Join([]string{
		`data: {"type":"response.failed","response":{"id":"resp_4","status":"failed","incomplete_details":{"reason":"content_filter"}}}`,
		``,
	}, "\n")
	_, err := parseResponsesSSE(strings.NewReader(stream), testPayload(), &KiroStreamCallback{})
	if err == nil || !strings.Contains(err.Error(), "content_filter") {
		t.Fatalf("expected failure surfaced, got %v", err)
	}
}

func TestCallKiroResponsesAPIContextRejectsNil(t *testing.T) {
	if err := callKiroResponsesAPIContext(context.Background(), nil, nil, nil); err == nil {
		t.Fatal("expected error for nil payload")
	}
}

func TestResponsesStopReason(t *testing.T) {
	cases := []struct {
		status   string
		reason   string
		expected string
	}{
		{"completed", "", "END_TURN"},
		{"requires_action", "", "END_TURN"},
		{"incomplete", "max_output_tokens", "MAX_TOKENS"},
		{"incomplete", "content_filter", "REFUSAL"},
	}
	for _, c := range cases {
		resp := &responsesPayload{Status: c.status}
		if c.reason != "" {
			resp.IncompleteDetails = &struct {
				Reason string `json:"reason"`
			}{Reason: c.reason}
		}
		if got := responsesStopReason(resp); got != c.expected {
			t.Fatalf("status=%s reason=%s got=%s want=%s", c.status, c.reason, got, c.expected)
		}
	}
}
