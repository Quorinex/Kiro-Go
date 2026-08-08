package proxy

import (
	"encoding/json"
	"fmt"
	"strings"
)

type claudeStopHookVerdict struct {
	OK     bool   `json:"ok"`
	Reason string `json:"reason"`
}

func isClaudeCodeStopHookEvaluatorRequest(req *ClaudeRequest) bool {
	if req == nil {
		return false
	}

	text := strings.ToLower(claudeRequestTextForDetection(req))
	if text == "" {
		return false
	}

	required := []string{
		"has the following stopping condition been satisfied",
		"answer based on transcript evidence only",
		"condition:",
		"arguments:",
	}
	for _, marker := range required {
		if !strings.Contains(text, marker) {
			return false
		}
	}

	return strings.Contains(text, "hook_event_name") &&
		strings.Contains(text, "stop") &&
		strings.Contains(text, "last_assistant_message")
}

func claudeRequestTextForDetection(req *ClaudeRequest) string {
	var b strings.Builder
	if system := extractSystemPrompt(req.System); system != "" {
		b.WriteString(system)
		b.WriteByte('\n')
	}

	for _, msg := range req.Messages {
		switch strings.TrimSpace(strings.ToLower(msg.Role)) {
		case "assistant":
			text, _ := extractClaudeAssistantContent(msg.Content)
			b.WriteString(text)
		default:
			text, _, _ := extractClaudeUserContent(msg.Content)
			if text == "" {
				text, _ = extractClaudeAssistantContent(msg.Content)
			}
			b.WriteString(text)
		}
		b.WriteByte('\n')
	}

	return b.String()
}

func normalizeClaudeStopHookEvaluatorText(raw string) string {
	raw = strings.TrimSpace(raw)
	if normalized, ok := normalizeStopHookJSONFromString(raw); ok {
		return normalized
	}

	ok, reason := inferStopHookVerdictFromProse(raw)
	return marshalStopHookVerdict(ok, reason)
}

func normalizeStopHookJSONFromString(raw string) (string, bool) {
	if normalized, ok := normalizeStopHookJSONCandidate(raw); ok {
		return normalized, true
	}

	unwrapped := unwrapMarkdownFence(raw)
	if unwrapped != raw {
		if normalized, ok := normalizeStopHookJSONCandidate(unwrapped); ok {
			return normalized, true
		}
	}

	for _, candidate := range jsonObjectCandidates(raw) {
		if normalized, ok := normalizeStopHookJSONCandidate(candidate); ok {
			return normalized, true
		}
	}

	return "", false
}

func normalizeStopHookJSONCandidate(candidate string) (string, bool) {
	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		return "", false
	}

	var obj map[string]interface{}
	if err := json.Unmarshal([]byte(candidate), &obj); err == nil {
		ok, hasOK := flexibleHookBool(obj["ok"])
		if !hasOK {
			ok, hasOK = flexibleHookBool(obj["satisfied"])
		}
		if !hasOK {
			ok, hasOK = flexibleHookBool(obj["condition_satisfied"])
		}
		if !hasOK {
			return "", false
		}

		reason := hookReason(obj["reason"])
		if reason == "" {
			reason = hookReason(obj["explanation"])
		}
		if reason == "" {
			reason = "Model returned a valid hook verdict."
		}
		return marshalStopHookVerdict(ok, reason), true
	}

	var ok bool
	if err := json.Unmarshal([]byte(candidate), &ok); err == nil {
		return marshalStopHookVerdict(ok, "Model returned a boolean hook verdict."), true
	}

	return "", false
}

func flexibleHookBool(v interface{}) (bool, bool) {
	switch value := v.(type) {
	case bool:
		return value, true
	case string:
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "true", "yes", "satisfied", "met":
			return true, true
		case "false", "no", "unsatisfied", "not satisfied", "not met":
			return false, true
		}
	}
	return false, false
}

func hookReason(v interface{}) string {
	switch value := v.(type) {
	case nil:
		return ""
	case string:
		return value
	default:
		return fmt.Sprint(value)
	}
}

func jsonObjectCandidates(raw string) []string {
	var candidates []string
	for start := 0; start < len(raw); start++ {
		if raw[start] != '{' {
			continue
		}
		if candidate, ok := jsonObjectCandidateAt(raw, start); ok {
			candidates = append(candidates, candidate)
		}
	}
	return candidates
}

func jsonObjectCandidateAt(raw string, start int) (string, bool) {
	depth := 0
	inString := false
	escaped := false

	for i := start; i < len(raw); i++ {
		ch := raw[i]
		if inString {
			if escaped {
				escaped = false
				continue
			}
			switch ch {
			case '\\':
				escaped = true
			case '"':
				inString = false
			}
			continue
		}

		switch ch {
		case '"':
			inString = true
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return raw[start : i+1], true
			}
		}
	}

	return "", false
}

func unwrapMarkdownFence(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if !strings.HasPrefix(trimmed, "```") {
		return raw
	}

	trimmed = strings.TrimPrefix(trimmed, "```")
	if idx := strings.IndexByte(trimmed, '\n'); idx >= 0 {
		trimmed = trimmed[idx+1:]
	}
	if idx := strings.LastIndex(trimmed, "```"); idx >= 0 {
		trimmed = trimmed[:idx]
	}
	return strings.TrimSpace(trimmed)
}

func inferStopHookVerdictFromProse(raw string) (bool, string) {
	reason := compactHookReason(unwrapMarkdownFence(raw))
	if reason == "" {
		return false, "Hook evaluator returned an empty response; continuing goal to avoid premature stop."
	}

	lower := strings.ToLower(reason)
	falseMarkers := []string{
		"ok: false",
		"\"ok\": false",
		"\"ok\":false",
		"has not been satisfied",
		"not been satisfied",
		"is not satisfied",
		"not satisfied",
		"has not been met",
		"is not met",
		"not met",
	}
	for _, marker := range falseMarkers {
		if strings.Contains(lower, marker) {
			return false, reason
		}
	}
	if strings.HasPrefix(lower, "no") || strings.HasPrefix(lower, "false") {
		return false, reason
	}

	trueMarkers := []string{
		"ok: true",
		"\"ok\": true",
		"\"ok\":true",
		"has been satisfied",
		"is satisfied",
		"condition satisfied",
		"has been met",
		"is met",
		"condition was met",
		"condition is met",
	}
	for _, marker := range trueMarkers {
		if strings.Contains(lower, marker) {
			return true, reason
		}
	}
	if strings.HasPrefix(lower, "yes") || strings.HasPrefix(lower, "true") {
		return true, reason
	}

	return false, "Hook evaluator returned non-JSON output; continuing goal to avoid premature stop. Raw: " + reason
}

func marshalStopHookVerdict(ok bool, reason string) string {
	reason = compactHookReason(reason)
	if reason == "" {
		reason = "Hook evaluator did not provide a reason."
	}

	out, err := json.Marshal(claudeStopHookVerdict{
		OK:     ok,
		Reason: reason,
	})
	if err != nil {
		return `{"ok":false,"reason":"Hook evaluator normalization failed."}`
	}
	return string(out)
}

func compactHookReason(reason string) string {
	reason = strings.Join(strings.Fields(strings.TrimSpace(reason)), " ")
	const maxRunes = 800
	runes := []rune(reason)
	if len(runes) > maxRunes {
		reason = string(runes[:maxRunes]) + "..."
	}
	return reason
}
