package proxy

import "testing"

// Codex CLI 0.165+ sends its "collaboration" sub-agent group as a top-level
// namespace tool instead of inside an "additional_tools" input item.
func TestDecodeTopLevelResponsesToolsFlattensNamespace(t *testing.T) {
	body := []byte(`{"model":"m","input":"hi","tools":[
		{"type":"namespace","name":"collaboration","description":"agents","tools":[
			{"type":"function","name":"spawn_agent","parameters":{"type":"object","properties":{"message":{"type":"string","encrypted":true}},"required":["message"]}},
			{"type":"function","name":"wait_agent","parameters":{"type":"object"}}
		]},
		{"type":"function","name":"exec_command","parameters":{"type":"object"}}
	]}`)

	tools := decodeTopLevelResponsesTools(body)
	if len(tools) != 3 {
		t.Fatalf("expected 3 flattened tools, got %d: %+v", len(tools), tools)
	}
	byName := map[string]OpenAITool{}
	for _, tool := range tools {
		byName[tool.Function.Name] = tool
	}
	if byName["spawn_agent"].Namespace != "collaboration" || byName["wait_agent"].Namespace != "collaboration" {
		t.Fatalf("namespace not recorded: %+v", tools)
	}
	if byName["exec_command"].Namespace != "" {
		t.Fatalf("plain tool should have no namespace: %+v", byName["exec_command"])
	}

	kiro := convertOpenAITools(tools)
	if len(kiro) != 3 {
		t.Fatalf("expected 3 kiro tools, got %d", len(kiro))
	}
	if ns := toolNamespaceMap(tools); ns["spawn_agent"] != "collaboration" {
		t.Fatalf("toolNamespaceMap missing spawn_agent: %v", ns)
	}

	if decodeTopLevelResponsesTools([]byte(`{"model":"m","input":"hi"}`)) != nil {
		t.Fatal("expected nil when no top-level tools")
	}
}
