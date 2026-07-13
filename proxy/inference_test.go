package proxy

import (
	"encoding/json"
	"strings"
	"testing"
)

// Guards the temperature:0 fix: an explicitly-provided temperature of 0 must be
// transmitted to Kiro (not dropped by omitempty), while an unset temperature is
// still omitted. Ported from kiro-tutu.
func TestInferenceConfigTransmitsExplicitZeroTemperature(t *testing.T) {
	zero := 0.0
	withZero, _ := json.Marshal(&InferenceConfig{Temperature: &zero})
	if !strings.Contains(string(withZero), `"temperature":0`) {
		t.Fatalf("explicit temperature 0 must be transmitted, got %s", withZero)
	}

	unset, _ := json.Marshal(&InferenceConfig{})
	if strings.Contains(string(unset), "temperature") {
		t.Fatalf("unset temperature must be omitted, got %s", unset)
	}
}

// TestClaudeRequestTransmitsExplicitZeroTemperature locks the full user-facing
// fix: a Claude request with temperature:0 (deterministic decoding — a real,
// deliberate setting) must survive JSON marshalling and reach the translator
// path, instead of being silently dropped by float64+omitempty (which treated
// 0 == "unset" and stripped the field, silently switching the client to the
// default temperature).
func TestClaudeRequestTransmitsExplicitZeroTemperature(t *testing.T) {
	zero := 0.0
	raw, _ := json.Marshal(&ClaudeRequest{Model: "claude-sonnet-4.5", Temperature: &zero})
	if !strings.Contains(string(raw), `"temperature":0`) {
		t.Fatalf("ClaudeRequest must transmit explicit temperature 0, got %s", raw)
	}
}

// TestOpenAIRequestTransmitsExplicitZeroTemperature is the OpenAI-side guard
// for the same temperature:0 drop bug.
func TestOpenAIRequestTransmitsExplicitZeroTemperature(t *testing.T) {
	zero := 0.0
	raw, _ := json.Marshal(&OpenAIRequest{Model: "gpt-4o", Temperature: &zero})
	if !strings.Contains(string(raw), `"temperature":0`) {
		t.Fatalf("OpenAIRequest must transmit explicit temperature 0, got %s", raw)
	}
}

// TestClaudeToKiroPropagatesExplicitZeroTemperature verifies the end-to-end
// translation path: temperature:0 on an inbound Claude request must land on the
// Kiro InferenceConfig (also as a non-nil 0), not be dropped — so deterministic
// decoding reaches the upstream model rather than silently reverting to default.
func TestClaudeToKiroPropagatesExplicitZeroTemperature(t *testing.T) {
	zero := 0.0
	req := &ClaudeRequest{
		Model:       "claude-sonnet-4.5",
		MaxTokens:   1024,
		Messages:    []ClaudeMessage{{Role: "user", Content: "hi"}},
		Temperature: &zero,
	}
	payload := ClaudeToKiro(req, false)
	if payload.InferenceConfig == nil {
		t.Fatal("InferenceConfig must be set when temperature is explicitly 0")
	}
	if payload.InferenceConfig.Temperature == nil {
		t.Fatal("temperature must be propagated as a non-nil pointer when explicitly 0")
	}
	if *payload.InferenceConfig.Temperature != 0 {
		t.Fatalf("temperature must be 0, got %v", *payload.InferenceConfig.Temperature)
	}
	kiroRaw, _ := json.Marshal(payload.InferenceConfig)
	if !strings.Contains(string(kiroRaw), `"temperature":0`) {
		t.Fatalf("Kiro InferenceConfig must transmit temperature:0, got %s", kiroRaw)
	}
}
