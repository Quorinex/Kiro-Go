package proxy

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestClaudeCodeStopHookEvaluatorDetection(t *testing.T) {
	req := &ClaudeRequest{
		Model: "claude-opus-5",
		Messages: []ClaudeMessage{{
			Role: "user",
			Content: `Based on the conversation transcript above, has the following stopping condition been satisfied? Answer based on transcript evidence only.

Condition: reply exactly DONE and stop

ARGUMENTS: {"session_id":"s","transcript_path":"/tmp/t.jsonl","cwd":"/tmp","prompt_id":"p","permission_mode":"bypassPermissions","effort":{"level":"low"},"hook_event_name":"Stop","stop_hook_active":false,"last_assistant_message":"DONE","background_tasks":[],"session_crons":[]}`,
		}},
	}

	if !isClaudeCodeStopHookEvaluatorRequest(req) {
		t.Fatalf("expected Stop hook evaluator request to be detected")
	}
}

func TestNormalizeClaudeStopHookEvaluatorTextExtractsFencedJSON(t *testing.T) {
	got := normalizeClaudeStopHookEvaluatorText("```json\n{\"ok\": true, \"reason\": \"done\"}\n```")
	assertStopHookVerdict(t, got, true, "done")
}

func TestNormalizeClaudeStopHookEvaluatorTextCoercesProse(t *testing.T) {
	got := normalizeClaudeStopHookEvaluatorText("Yes, the stopping condition has been satisfied because the last assistant message is DONE.")
	assertStopHookVerdict(t, got, true, "Yes,")
}

func TestNormalizeClaudeStopHookEvaluatorTextAmbiguousProseContinuesGoal(t *testing.T) {
	got := normalizeClaudeStopHookEvaluatorText("The transcript is unclear and needs more work.")
	assertStopHookVerdict(t, got, false, "non-JSON output")
}

func assertStopHookVerdict(t *testing.T, raw string, wantOK bool, reasonContains string) {
	t.Helper()

	var verdict claudeStopHookVerdict
	if err := json.Unmarshal([]byte(raw), &verdict); err != nil {
		t.Fatalf("normalized verdict is not JSON: %v raw=%q", err, raw)
	}
	if verdict.OK != wantOK {
		t.Fatalf("ok = %v, want %v in %s", verdict.OK, wantOK, raw)
	}
	if reasonContains != "" && !strings.Contains(verdict.Reason, reasonContains) {
		t.Fatalf("reason %q does not contain %q", verdict.Reason, reasonContains)
	}
}
