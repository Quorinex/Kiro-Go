package proxy

import (
	"encoding/json"
	"strings"
	"testing"
)

// Codex wraps tools in a namespace envelope for every provider that leaves
// namespace_tools enabled, which is the default for custom providers. Dropping
// the envelope discarded every tool inside it, leaving the model with no tools
// at all and making it report that it has no shell available.
func TestConvertOpenAIToolsUnwrapsCodexNamespace(t *testing.T) {
	tools := []OpenAITool{
		mustTool(t, `{"type":"namespace","name":"functions","description":"Codex tools","tools":[
			{"type":"function","name":"exec_command","description":"Run a command","parameters":{"type":"object","properties":{"cmd":{"type":"string"}}}},
			{"type":"function","name":"write_stdin","description":"Write to stdin","parameters":{"type":"object"}}
		]}`),
	}

	wrappers := convertOpenAITools(tools)
	if len(wrappers) != 2 {
		t.Fatalf("expected 2 tools unwrapped from namespace, got %d", len(wrappers))
	}
	got := map[string]bool{}
	for _, w := range wrappers {
		got[w.ToolSpecification.Name] = true
	}
	if !got["exec_command"] || !got["write_stdin"] {
		t.Fatalf("expected namespace children preserved, got %v", got)
	}
}

// Server-side tool types are executed by the model host, not by Kiro. They must
// be dropped rather than forwarded (Kiro rejects them) and rather than failing
// the whole request, while the real function tools beside them survive.
func TestConvertOpenAIToolsDropsServerSideTypes(t *testing.T) {
	tools := []OpenAITool{
		mustTool(t, `{"type":"web_search"}`),
		mustTool(t, `{"type":"tool_search","execution":"auto","description":"search"}`),
		mustTool(t, `{"type":"local_shell"}`),
		mustTool(t, `{"type":"function","name":"exec_command","parameters":{"type":"object"}}`),
	}

	wrappers := convertOpenAITools(tools)
	if len(wrappers) != 1 {
		t.Fatalf("expected only the function tool to survive, got %d", len(wrappers))
	}
	if wrappers[0].ToolSpecification.Name != "exec_command" {
		t.Fatalf("expected exec_command, got %q", wrappers[0].ToolSpecification.Name)
	}
}

// Codex sends apply_patch as a freeform grammar tool. Kiro only accepts
// JSON-schema tool specs, so the grammar has to travel in the description while
// the schema degrades to a single string argument.
func TestConvertOpenAIToolsExposesFreeformToolAsStringArgument(t *testing.T) {
	tools := []OpenAITool{
		mustTool(t, `{"type":"custom","name":"apply_patch","description":"Edit files.",
			"format":{"type":"grammar","syntax":"lark","definition":"start: patch"}}`),
	}

	wrappers := convertOpenAITools(tools)
	if len(wrappers) != 1 {
		t.Fatalf("expected freeform tool to be forwarded, got %d", len(wrappers))
	}
	spec := wrappers[0].ToolSpecification
	if spec.Name != "apply_patch" {
		t.Fatalf("expected apply_patch, got %q", spec.Name)
	}
	if !strings.Contains(spec.Description, "start: patch") {
		t.Fatalf("expected grammar carried in description, got %q", spec.Description)
	}
	if !strings.Contains(spec.Description, "lark") {
		t.Fatalf("expected grammar syntax named in description, got %q", spec.Description)
	}

	schema, ok := spec.InputSchema.JSON.(map[string]interface{})
	if !ok {
		t.Fatalf("expected object schema, got %T", spec.InputSchema.JSON)
	}
	props, ok := schema["properties"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected schema properties, got %#v", schema)
	}
	if _, ok := props[customToolInputKey]; !ok {
		t.Fatalf("expected single %q argument, got %#v", customToolInputKey, props)
	}
}

// Responses Lite (gpt-5.6 and newer) omits the top-level tools array entirely
// and ships tool definitions in an additional_tools input item. The item has no
// content field, so treating it as an ordinary developer message dropped every
// tool it carried — the confirmed root cause of "no terminal tool available".
func TestExtractResponsesAdditionalToolsRecoversLiteTools(t *testing.T) {
	input := json.RawMessage(`[
		{"type":"additional_tools","role":"developer","tools":[
			{"type":"function","name":"exec_command","description":"Run","parameters":{"type":"object"}},
			{"type":"custom","name":"apply_patch","description":"Edit","format":{"type":"grammar","syntax":"lark","definition":"start: x"}}
		]},
		{"type":"message","role":"user","content":[{"type":"input_text","text":"list files"}]}
	]`)

	tools := extractResponsesAdditionalTools(input)
	if len(tools) != 2 {
		t.Fatalf("expected 2 tools recovered from additional_tools, got %d", len(tools))
	}
	if tools[0].Function.Name != "exec_command" || tools[1].Function.Name != "apply_patch" {
		t.Fatalf("unexpected recovered tools: %q, %q", tools[0].Function.Name, tools[1].Function.Name)
	}

	// The wrapper itself must not leak into the prompt as conversation content.
	messages, err := parseResponsesInput(input)
	if err != nil {
		t.Fatalf("parseResponsesInput: %v", err)
	}
	if len(messages) != 1 {
		t.Fatalf("expected only the user message, got %d: %#v", len(messages), messages)
	}
	if messages[0].Role != "user" {
		t.Fatalf("expected user message, got role %q", messages[0].Role)
	}
}

// A freeform call returned as a plain function_call is abandoned by Codex, so
// the response has to restore the custom_tool_call shape with a raw input
// string instead of JSON arguments.
func TestShapeResponsesToolCallRestoresCustomToolCall(t *testing.T) {
	customTools := map[string]bool{"apply_patch": true}
	patch := "*** Begin Patch\n*** End Patch"

	custom := shapeResponsesToolCall(KiroToolUse{
		ToolUseID: "call_1",
		Name:      "apply_patch",
		Input:     map[string]interface{}{customToolInputKey: patch},
	}, customTools)
	if custom.Type != responsesCustomToolCallType {
		t.Fatalf("expected %s, got %s", responsesCustomToolCallType, custom.Type)
	}
	if custom.Input != patch {
		t.Fatalf("expected raw patch preserved, got %q", custom.Input)
	}

	fn := shapeResponsesToolCall(KiroToolUse{
		ToolUseID: "call_2",
		Name:      "exec_command",
		Input:     map[string]interface{}{"cmd": "ls"},
	}, customTools)
	if fn.Type != "function_call" {
		t.Fatalf("expected function_call, got %s", fn.Type)
	}
	if fn.Arguments != `{"cmd":"ls"}` {
		t.Fatalf("unexpected arguments: %q", fn.Arguments)
	}
}

// Codex reads tool calls only from response.output_item.done, so that item must
// carry the complete call. An empty-argument tool use must still serialize as
// "{}" rather than null, which Codex silently discards.
func TestResponsesToolCallOutputItemCarriesCompletePayload(t *testing.T) {
	shape := shapeResponsesToolCall(KiroToolUse{
		ToolUseID: "call_1",
		Name:      "exec_command",
		Input:     nil,
	}, nil)
	if shape.Arguments != "{}" {
		t.Fatalf("expected empty input to serialize as {}, got %q", shape.Arguments)
	}

	done := shape.outputItem("fc_1", KiroToolUse{ToolUseID: "call_1", Name: "exec_command"}, "completed", true)
	if done["arguments"] != "{}" {
		t.Fatalf("expected done item to carry arguments, got %#v", done["arguments"])
	}
	if done["call_id"] != "call_1" || done["name"] != "exec_command" {
		t.Fatalf("expected call_id and name on done item, got %#v", done)
	}

	added := shape.outputItem("fc_1", KiroToolUse{ToolUseID: "call_1", Name: "exec_command"}, "in_progress", false)
	if added["arguments"] != "" {
		t.Fatalf("expected added item to announce empty payload, got %#v", added["arguments"])
	}
}

// A custom_tool_call replayed as conversation history must map back onto the
// single-argument schema convertOpenAITools advertises, so the tool call and its
// definition stay consistent across turns.
func TestParseResponsesInputReplaysCustomToolCall(t *testing.T) {
	input := json.RawMessage(`[
		{"type":"custom_tool_call","call_id":"call_1","name":"apply_patch","input":"*** Begin Patch"},
		{"type":"custom_tool_call_output","call_id":"call_1","output":"done"}
	]`)

	messages, err := parseResponsesInput(input)
	if err != nil {
		t.Fatalf("parseResponsesInput: %v", err)
	}
	if len(messages) != 2 {
		t.Fatalf("expected assistant call + tool result, got %d: %#v", len(messages), messages)
	}
	if messages[0].Role != "assistant" || len(messages[0].ToolCalls) != 1 {
		t.Fatalf("expected assistant tool call, got %#v", messages[0])
	}
	call := messages[0].ToolCalls[0]
	if call.Function.Name != "apply_patch" {
		t.Fatalf("expected apply_patch, got %q", call.Function.Name)
	}
	var args map[string]string
	if err := json.Unmarshal([]byte(call.Function.Arguments), &args); err != nil {
		t.Fatalf("expected JSON arguments, got %q: %v", call.Function.Arguments, err)
	}
	if args[customToolInputKey] != "*** Begin Patch" {
		t.Fatalf("expected payload rewrapped under %q, got %#v", customToolInputKey, args)
	}
	if messages[1].Role != "tool" || messages[1].ToolCallID != "call_1" {
		t.Fatalf("expected paired tool result, got %#v", messages[1])
	}
}
