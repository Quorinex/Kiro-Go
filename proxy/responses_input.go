package proxy

import (
	"encoding/json"
	"fmt"
	"strings"
)

// responsesAdditionalToolsType is the input item Codex Responses Lite (gpt-5.6
// and newer) uses to carry tool definitions instead of the top-level tools
// array. On that path the request arrives with tools omitted entirely.
const responsesAdditionalToolsType = "additional_tools"

// responsesInputItems splits an input payload into its individual items,
// tolerating both the array form and a single bare object. Malformed input
// yields no items rather than an error; parseResponsesInput reports shape
// problems to the caller.
func responsesInputItems(raw json.RawMessage) []json.RawMessage {
	if len(raw) == 0 {
		return nil
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return nil
	}
	switch trimmed[0] {
	case '[':
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil {
			return nil
		}
		return items
	case '{':
		return []json.RawMessage{raw}
	}
	return nil
}

// extractResponsesAdditionalTools pulls tool definitions out of the
// additional_tools input item:
//
//	{"type":"additional_tools","role":"developer","tools":[...]}
//
// The item carries no content field, so handling it as an ordinary developer
// message discards every tool it holds and the model then reports having no
// tools available at all.
func extractResponsesAdditionalTools(raw json.RawMessage) []OpenAITool {
	var tools []OpenAITool
	for _, item := range responsesInputItems(raw) {
		var probe struct {
			Type  string       `json:"type"`
			Tools []OpenAITool `json:"tools"`
		}
		if err := json.Unmarshal(item, &probe); err != nil {
			continue
		}
		if probe.Type != responsesAdditionalToolsType {
			continue
		}
		tools = append(tools, probe.Tools...)
	}
	return tools
}

func parseResponsesInput(raw json.RawMessage) ([]OpenAIMessage, error) {
	if len(raw) == 0 {
		return nil, nil
	}

	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return nil, nil
	}

	if trimmed[0] == '"' {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, fmt.Errorf("invalid input string: %w", err)
		}
		if strings.TrimSpace(s) == "" {
			return nil, nil
		}
		return []OpenAIMessage{{Role: "user", Content: s}}, nil
	}

	if trimmed[0] == '[' {
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil {
			return nil, fmt.Errorf("invalid input array: %w", err)
		}
		return convertResponsesInputItems(items)
	}

	if trimmed[0] == '{' {
		return convertResponsesInputItems([]json.RawMessage{raw})
	}

	return nil, fmt.Errorf("unsupported input shape")
}

func convertResponsesInputItems(items []json.RawMessage) ([]OpenAIMessage, error) {
	messages := make([]OpenAIMessage, 0, len(items))
	pendingUserParts := []interface{}{}

	flushPendingUser := func() {
		if len(pendingUserParts) == 0 {
			return
		}
		messages = append(messages, OpenAIMessage{
			Role:    "user",
			Content: pendingUserParts,
		})
		pendingUserParts = nil
	}

	for _, item := range items {
		var obj map[string]interface{}
		if err := json.Unmarshal(item, &obj); err != nil {
			continue
		}

		typ, _ := obj["type"].(string)
		role, _ := obj["role"].(string)

		switch {
		case typ == responsesAdditionalToolsType:
			// Tool definitions rather than conversational content; the caller
			// reads them via extractResponsesAdditionalTools. Emitting nothing
			// keeps the developer-role wrapper out of the prompt.

		case typ == "message" || (typ == "" && role != ""):
			flushPendingUser()
			msg := buildMessageFromInputItem(obj, role)
			if msg != nil {
				messages = append(messages, *msg)
			}

		case typ == "function_call_output" || typ == "tool_result" || typ == "custom_tool_call_output":
			flushPendingUser()
			callID, _ := obj["call_id"].(string)
			if callID == "" {
				callID, _ = obj["tool_call_id"].(string)
			}
			out := stringifyArbitrary(obj["output"])
			if out == "" {
				out = stringifyArbitrary(obj["content"])
			}
			messages = append(messages, OpenAIMessage{
				Role:       "tool",
				Content:    out,
				ToolCallID: callID,
			})

		case typ == "function_call" || typ == responsesCustomToolCallType:
			flushPendingUser()
			tc := ToolCall{
				ID:   stringField(obj, "call_id", "id"),
				Type: "function",
			}
			tc.Function.Name, _ = obj["name"].(string)
			if typ == responsesCustomToolCallType {
				// Freeform calls replay their payload under "input". Re-wrap it
				// in the single-argument schema convertOpenAITools advertises so
				// the replayed call still matches its tool definition.
				tc.Function.Arguments = wrapCustomToolArguments(stringifyArbitrary(obj["input"]))
			} else {
				tc.Function.Arguments = stringifyArbitrary(obj["arguments"])
			}
			// Merge consecutive function_call items into a single assistant
			// message so parallel tool calls stay grouped in one turn. The
			// Responses API emits each parallel call as a separate input item;
			// keeping them in one assistant message preserves the tool_use /
			// tool_result pairing that Kiro requires.
			if n := len(messages); n > 0 &&
				messages[n-1].Role == "assistant" &&
				len(messages[n-1].ToolCalls) > 0 &&
				strings.TrimSpace(extractOpenAIMessageText(messages[n-1].Content)) == "" {
				messages[n-1].ToolCalls = append(messages[n-1].ToolCalls, tc)
			} else {
				messages = append(messages, OpenAIMessage{
					Role:      "assistant",
					Content:   "",
					ToolCalls: []ToolCall{tc},
				})
			}

		case typ == "input_text" || typ == "text":
			text, _ := obj["text"].(string)
			if text != "" {
				pendingUserParts = append(pendingUserParts, map[string]interface{}{
					"type": "input_text",
					"text": text,
				})
			}

		case typ == "input_image", typ == "image", typ == "image_url":
			pendingUserParts = append(pendingUserParts, map[string]interface{}(obj))

		case typ == "output_text":
			flushPendingUser()
			text, _ := obj["text"].(string)
			if text != "" {
				messages = append(messages, OpenAIMessage{Role: "assistant", Content: text})
			}

		default:
			if role != "" {
				flushPendingUser()
				msg := buildMessageFromInputItem(obj, role)
				if msg != nil {
					messages = append(messages, *msg)
				}
			}
		}
	}

	flushPendingUser()
	return messages, nil
}

func buildMessageFromInputItem(obj map[string]interface{}, role string) *OpenAIMessage {
	if role == "" {
		role = "user"
	}

	if content, ok := obj["content"]; ok {
		switch v := content.(type) {
		case string:
			return &OpenAIMessage{Role: role, Content: v}
		case []interface{}:
			parts := make([]interface{}, 0, len(v))
			textOnly := strings.Builder{}
			anyNonText := false
			for _, p := range v {
				part, ok := p.(map[string]interface{})
				if !ok {
					continue
				}
				ptype, _ := part["type"].(string)
				switch ptype {
				case "input_text", "text":
					if t, ok := part["text"].(string); ok {
						textOnly.WriteString(t)
						parts = append(parts, map[string]interface{}{"type": "input_text", "text": t})
					}
				case "output_text":
					if t, ok := part["text"].(string); ok {
						textOnly.WriteString(t)
						parts = append(parts, map[string]interface{}{"type": "input_text", "text": t})
					}
				case "input_image", "image", "image_url":
					anyNonText = true
					parts = append(parts, part)
				default:
					if t, ok := part["text"].(string); ok && t != "" {
						textOnly.WriteString(t)
						parts = append(parts, map[string]interface{}{"type": "input_text", "text": t})
					}
				}
			}
			if !anyNonText {
				return &OpenAIMessage{Role: role, Content: textOnly.String()}
			}
			return &OpenAIMessage{Role: role, Content: parts}
		case map[string]interface{}:
			return buildMessageFromInputItem(v, role)
		}
	}

	if text, ok := obj["text"].(string); ok && text != "" {
		return &OpenAIMessage{Role: role, Content: text}
	}

	return nil
}

func stringifyArbitrary(v interface{}) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return ""
		}
		return string(b)
	}
}

func stringField(obj map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		if v, ok := obj[k].(string); ok && v != "" {
			return v
		}
	}
	return ""
}
