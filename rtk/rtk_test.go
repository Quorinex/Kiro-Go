package rtk

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestTransformJSONCompressesClaudeToolResult(t *testing.T) {
	toolOutput := repeatedGrepOutput(35)
	raw := `{
		"model":"claude-sonnet-4.5",
		"messages":[
			{"role":"assistant","content":[{"type":"tool_use","id":"toolu_1","name":"exec_command","input":{"cmd":"rg needle"}}]},
			{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1","content":` + quoteJSON(toolOutput) + `}]}
		]
	}`

	updated, stats, changed, err := TransformJSON([]byte(raw), Config{Enabled: true, MinBytes: 1, MaxBytes: DefaultMaxBytes})
	if err != nil {
		t.Fatalf("TransformJSON error: %v", err)
	}
	if !changed {
		t.Fatalf("expected request to be compressed")
	}
	if len(stats.Hits) != 1 || stats.Hits[0].Filter != "grep" || stats.Hits[0].Shape != "tool-result" {
		t.Fatalf("unexpected stats: %+v", stats)
	}

	var payload map[string]any
	if err := json.Unmarshal(updated, &payload); err != nil {
		t.Fatalf("decode updated: %v", err)
	}
	content := payload["messages"].([]any)[1].(map[string]any)["content"].([]any)[0].(map[string]any)["content"].(string)
	if !strings.Contains(content, "35 matches in 1 files") {
		t.Fatalf("expected grep summary, got %q", content)
	}
	if strings.Contains(content, "needle occurrence 34") {
		t.Fatalf("expected long raw tail to be removed, got %q", content)
	}
}

func TestTransformJSONCompressesOpenAIResponsesBuildOutput(t *testing.T) {
	raw := `{
		"model":"claude-sonnet-4.5",
		"input":[
			{"type":"function_call","call_id":"call_1","name":"exec_command","input":{"cmd":"cargo build"}},
			{"type":"function_call_output","call_id":"call_1","output":` + quoteJSON(repeatedBuildOutput(40)) + `}
		]
	}`

	updated, stats, changed, err := TransformJSON([]byte(raw), Config{Enabled: true, MinBytes: 1, MaxBytes: DefaultMaxBytes})
	if err != nil {
		t.Fatalf("TransformJSON error: %v", err)
	}
	if !changed {
		t.Fatalf("expected request to be compressed")
	}
	if len(stats.Hits) != 1 || stats.Hits[0].Filter != "build-output" || stats.Hits[0].Shape != "openai-responses" {
		t.Fatalf("unexpected stats: %+v", stats)
	}
	if !strings.Contains(string(updated), "Compiled 40 packages") {
		t.Fatalf("expected build summary, got %s", string(updated))
	}
}

func TestTransformJSONCompressesNativeKiroToolResult(t *testing.T) {
	raw := `{
		"conversationState":{
			"currentMessage":{
				"userInputMessage":{
					"userInputMessageContext":{
						"toolResults":[{"toolUseId":"toolu_1","status":"success","content":[{"text":` + quoteJSON(repeatedGrepOutput(30)) + `}]}]
					}
				}
			},
			"history":[]
		}
	}`

	updated, stats, changed, err := TransformJSON([]byte(raw), Config{Enabled: true, MinBytes: 1, MaxBytes: DefaultMaxBytes})
	if err != nil {
		t.Fatalf("TransformJSON error: %v", err)
	}
	if !changed {
		t.Fatalf("expected native Kiro payload to be compressed")
	}
	if len(stats.Hits) != 1 || stats.Hits[0].Shape != "kiro-tool-result" {
		t.Fatalf("unexpected stats: %+v", stats)
	}
	if !strings.Contains(string(updated), "30 matches in 1 files") {
		t.Fatalf("expected native Kiro grep summary, got %s", string(updated))
	}
}

func TestTransformJSONSkipsErroredNativeKiroToolResult(t *testing.T) {
	output := repeatedGrepOutput(30)
	raw := `{
		"conversationState":{
			"currentMessage":{
				"userInputMessage":{
					"userInputMessageContext":{
						"toolResults":[{"toolUseId":"toolu_1","status":"error","content":[{"text":` + quoteJSON(output) + `}]}]
					}
				}
			}
		}
	}`

	updated, stats, changed, err := TransformJSON([]byte(raw), Config{Enabled: true, MinBytes: 1, MaxBytes: DefaultMaxBytes})
	if err != nil {
		t.Fatalf("TransformJSON error: %v", err)
	}
	if changed {
		t.Fatalf("expected errored tool result to remain unchanged")
	}
	if len(stats.Hits) != 0 {
		t.Fatalf("unexpected hits: %+v", stats.Hits)
	}
	if !strings.Contains(string(updated), "needle occurrence 29") {
		t.Fatalf("expected raw error output to remain, got %s", string(updated))
	}
}

func repeatedGrepOutput(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteString("proxy/handler.go:")
		b.WriteString(stringInt(100 + i))
		b.WriteString(": needle occurrence ")
		b.WriteString(stringInt(i))
		b.WriteString(" with a verbose line that should not be repeated in full after compression\n")
	}
	return b.String()
}

func repeatedBuildOutput(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteString("   Compiling crate_")
		b.WriteString(stringInt(i))
		b.WriteString(" v0.1.0 (/tmp/crate)\n")
	}
	b.WriteString("warning: unused import: fmt\n")
	b.WriteString("    Finished dev [unoptimized + debuginfo] target(s) in 12.34s\n")
	return b.String()
}

func quoteJSON(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
