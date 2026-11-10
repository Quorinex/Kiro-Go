package proxy

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"kiro-go/config"
)

// TestLiveResponsesTransport exercises the real /v1/responses upstream with the
// configured account. It is skipped unless KIRO_LIVE=1, so `go test ./...`
// stays hermetic.
//
// Run it after refreshing the account so the access token is valid:
//
//	curl -s -X POST -H "X-Admin-Password: $PW" \
//	  http://127.0.0.1:8080/admin/api/accounts/$ID/refresh
//	KIRO_LIVE=1 KIRO_LIVE_CONFIG=/home/vvv/Kiro-Go/data/config.json \
//	  go test ./proxy -run TestLiveResponsesTransport -v
func TestLiveResponsesTransport(t *testing.T) {
	if os.Getenv("KIRO_LIVE") != "1" {
		t.Skip("set KIRO_LIVE=1 to run against the real upstream")
	}
	cfgPath := os.Getenv("KIRO_LIVE_CONFIG")
	if cfgPath == "" {
		cfgPath = os.ExpandEnv("$HOME/Kiro-Go/data/config.json")
	}
	if err := config.Init(cfgPath); err != nil {
		t.Fatalf("config.Init(%s): %v", cfgPath, err)
	}
	accounts := config.GetAccounts()
	if len(accounts) == 0 {
		t.Fatal("no accounts in config")
	}
	account := accounts[0]
	accountPtr := &account
	if account.ExpiresAt > 0 && account.ExpiresAt < time.Now().Unix()+120 {
		t.Fatalf("access token expires in %ds; refresh the account first", account.ExpiresAt-time.Now().Unix())
	}

	// The transport must not be shadowed by a legacy pin.
	t.Setenv("KIRO_UPSTREAM_PROTOCOL", responsesProtocolResponses)

	newPayload := func(prompt string) *KiroPayload {
		p := &KiroPayload{}
		p.ConversationState.ChatTriggerType = "MANUAL"
		p.ConversationState.ConversationID = "live-test-" + time.Now().Format("150405")
		cur := &p.ConversationState.CurrentMessage.UserInputMessage
		cur.Content = prompt
		cur.ModelID = "claude-opus-5.5"
		cur.Origin = "AI_EDITOR"
		return p
	}

	t.Run("text stream", func(t *testing.T) {
		var text strings.Builder
		var stop string
		var credits float64
		var contextPct float64
		var sawComplete bool
		cb := &KiroStreamCallback{
			OnText:         func(s string, isThinking bool) { text.WriteString(s) },
			OnStopReason:   func(r string) { stop = r },
			OnCredits:      func(c float64) { credits = c },
			OnContextUsage: func(p float64) { contextPct = p },
			OnComplete:     func(i, o int) { sawComplete = true },
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if err := callKiroResponsesAPIContext(ctx, accountPtr, newPayload("只回复三个字：真实好"), cb); err != nil {
			t.Fatalf("transport error: %v", err)
		}
		t.Logf("text=%q stop=%q credits=%.6f contextPct=%.3f completed=%v",
			text.String(), stop, credits, contextPct, sawComplete)
		if strings.TrimSpace(text.String()) == "" {
			t.Fatal("no text emitted")
		}
		if stop != "END_TURN" {
			t.Fatalf("stop reason = %q", stop)
		}
		if credits <= 0 {
			t.Fatalf("no credits reported: %v", credits)
		}
		if !sawComplete {
			t.Fatal("OnComplete never fired")
		}
	})

	t.Run("tool call", func(t *testing.T) {
		p := newPayload("查一下北京的天气，必须调用 get_weather 工具。")
		p.ConversationState.CurrentMessage.UserInputMessage.ModelID = "claude-opus-5.5"
		wrapper := KiroToolWrapper{}
		wrapper.ToolSpecification.Name = "get_weather"
		wrapper.ToolSpecification.Description = "Get current weather for a city"
		wrapper.ToolSpecification.InputSchema.JSON = map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{"city": map[string]interface{}{"type": "string"}},
			"required":   []string{"city"},
		}
		p.ConversationState.CurrentMessage.UserInputMessage.UserInputMessageContext = &UserInputMessageContext{
			Tools: []KiroToolWrapper{wrapper},
		}

		var tools []KiroToolUse
		cb := &KiroStreamCallback{OnToolUse: func(tu KiroToolUse) { tools = append(tools, tu) }}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if err := callKiroResponsesAPIContext(ctx, accountPtr, p, cb); err != nil {
			t.Fatalf("transport error: %v", err)
		}
		if len(tools) != 1 {
			t.Fatalf("expected 1 tool use, got %d (%+v)", len(tools), tools)
		}
		if tools[0].Name != "get_weather" {
			t.Fatalf("tool name = %q", tools[0].Name)
		}
		if _, ok := tools[0].Input["city"]; !ok {
			t.Fatalf("tool args missing city: %+v", tools[0].Input)
		}
		raw, _ := json.Marshal(tools[0])
		t.Logf("tool=%s", raw)
	})
}
