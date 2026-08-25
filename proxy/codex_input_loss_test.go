package proxy

import (
	"encoding/json"
	"strings"
	"testing"
)

func mustMarshalPayload(t *testing.T, payload *KiroPayload) string {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return string(raw)
}

// TestOpenAIToKiroKeepsDeveloperRoleContent guards the single largest input-loss
// bug on the Codex path. "developer" is the Responses API name for what Chat
// Completions calls "system", and on the Responses Lite path (gpt-5.6+) Codex
// sends instructions as an empty string and ships its entire base prompt as a
// developer-role message instead. OpenAIToKiro folded only role=="system" into
// the system prompt, so developer messages matched no case in the role switch
// and were dropped outright — the bulk of every Codex request never reached
// Kiro, which is why reported input tokens collapsed versus other proxies.
func TestOpenAIToKiroKeepsDeveloperRoleContent(t *testing.T) {
	req := &OpenAIRequest{
		Model: "claude-sonnet-4.5",
		Messages: []OpenAIMessage{
			{Role: "developer", Content: "DEVELOPER_PROMPT_MARKER you are a coding agent"},
			{Role: "user", Content: "USER_MARKER check the repo"},
		},
	}

	payload := OpenAIToKiro(req, false)
	encoded := mustMarshalPayload(t, payload)

	if !strings.Contains(encoded, "DEVELOPER_PROMPT_MARKER") {
		t.Fatalf("developer-role content dropped from payload: %s", encoded)
	}
	if !strings.Contains(encoded, "USER_MARKER") {
		t.Fatalf("user content missing from payload: %s", encoded)
	}
}

// TestOpenAIToKiroDeveloperAndSystemBothPrime verifies developer content is
// treated as a system instruction rather than a conversational turn, so it is
// primed the same way system prompts are and both sources survive together.
func TestOpenAIToKiroDeveloperAndSystemBothPrime(t *testing.T) {
	req := &OpenAIRequest{
		Model: "claude-sonnet-4.5",
		Messages: []OpenAIMessage{
			{Role: "system", Content: "SYSTEM_MARKER"},
			{Role: "developer", Content: "DEVELOPER_MARKER"},
			{Role: "user", Content: "USER_MARKER"},
		},
	}

	payload := OpenAIToKiro(req, false)
	encoded := mustMarshalPayload(t, payload)

	for _, marker := range []string{"SYSTEM_MARKER", "DEVELOPER_MARKER", "USER_MARKER"} {
		if !strings.Contains(encoded, marker) {
			t.Fatalf("%s missing from payload: %s", marker, encoded)
		}
	}

	// The developer text must arrive as priming, not as the final user turn.
	current := payload.ConversationState.CurrentMessage.UserInputMessage.Content
	if strings.Contains(current, "DEVELOPER_MARKER") {
		t.Fatalf("developer content leaked into the current user turn: %q", current)
	}
	if !strings.Contains(current, "USER_MARKER") {
		t.Fatalf("expected user text as the current turn, got %q", current)
	}
}

// TestEstimatorAndPayloadAgreeOnDeveloperContent pins down why the reported
// input token count diverged so far from reality. The estimator walks every
// message regardless of role, so it always counted developer content, while the
// payload sent upstream did not carry it. Kiro then reported context usage for a
// far smaller prompt than the client actually sent, and the two numbers have to
// stay consistent for usage reporting to mean anything.
func TestEstimatorAndPayloadAgreeOnDeveloperContent(t *testing.T) {
	bulk := strings.Repeat("developer instruction body. ", 400)

	withDeveloper := &OpenAIRequest{
		Model: "claude-sonnet-4.5",
		Messages: []OpenAIMessage{
			{Role: "developer", Content: bulk},
			{Role: "user", Content: "hi"},
		},
	}
	withoutDeveloper := &OpenAIRequest{
		Model:    "claude-sonnet-4.5",
		Messages: []OpenAIMessage{{Role: "user", Content: "hi"}},
	}

	estimatedDelta := estimateOpenAIRequestInputTokens(withDeveloper) -
		estimateOpenAIRequestInputTokens(withoutDeveloper)
	if estimatedDelta <= 0 {
		t.Fatalf("expected the estimator to count developer content, delta=%d", estimatedDelta)
	}

	payloadDelta := len(mustMarshalPayload(t, OpenAIToKiro(withDeveloper, false))) -
		len(mustMarshalPayload(t, OpenAIToKiro(withoutDeveloper, false)))
	if payloadDelta <= 0 {
		t.Fatalf("developer content counted by the estimator never reached the payload (delta=%d bytes)", payloadDelta)
	}
}
