package proxy

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestHasWebSearchTool_SingleNativeTool(t *testing.T) {
	req := &ClaudeRequest{
		Model: "claude-sonnet-4",
		Tools: []ClaudeTool{
			{Type: "web_search_20250305", Name: "web_search"},
		},
	}
	if !hasWebSearchTool(req) {
		t.Fatal("expected single native web_search tool to be detected")
	}
}

func TestHasWebSearchTool_MultipleTools(t *testing.T) {
	req := &ClaudeRequest{
		Model: "claude-sonnet-4",
		Tools: []ClaudeTool{
			{Type: "web_search_20250305", Name: "web_search"},
			{Name: "other_tool", Description: "Other"},
		},
	}
	if hasWebSearchTool(req) {
		t.Fatal("multiple tools must not be treated as pure web_search request")
	}
}

func TestHasWebSearchTool_RegularToolNamedWebSearch(t *testing.T) {
	// クライアント定義の通常ツールが web_search という名前でも、
	// type が web_search_* でなければネイティブ扱いしない。
	req := &ClaudeRequest{
		Model: "claude-sonnet-4",
		Tools: []ClaudeTool{
			{Name: "web_search", Description: "Regular client-side search tool"},
		},
	}
	if hasWebSearchTool(req) {
		t.Fatal("regular tool named web_search must not trigger native websearch")
	}
}

func TestHasWebSearchTool_NoTools(t *testing.T) {
	req := &ClaudeRequest{Model: "claude-sonnet-4"}
	if hasWebSearchTool(req) {
		t.Fatal("request without tools must not be treated as web_search request")
	}
}

func TestExtractSearchQuery_StringContentWithPrefix(t *testing.T) {
	req := &ClaudeRequest{
		Messages: []ClaudeMessage{
			{Role: "user", Content: "Perform a web search for the query: rust latest version 2026"},
		},
	}
	got := extractSearchQuery(req)
	want := "rust latest version 2026"
	if got != want {
		t.Fatalf("query = %q, want %q", got, want)
	}
}

func TestExtractSearchQuery_StringContentWithoutPrefix(t *testing.T) {
	req := &ClaudeRequest{
		Messages: []ClaudeMessage{
			{Role: "user", Content: "typescript 5.7 features"},
		},
	}
	if got := extractSearchQuery(req); got != "typescript 5.7 features" {
		t.Fatalf("query = %q", got)
	}
}

func TestExtractSearchQuery_ArrayContent(t *testing.T) {
	// JSON 経由でデコードした場合 Content は []interface{} になる。
	raw := `{
		"model": "claude-sonnet-4",
		"messages": [
			{"role": "user", "content": [
				{"type": "text", "text": "Perform a web search for the query: golang generics"}
			]}
		]
	}`
	var req ClaudeRequest
	if err := json.Unmarshal([]byte(raw), &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got := extractSearchQuery(&req); got != "golang generics" {
		t.Fatalf("query = %q", got)
	}
}

func TestExtractSearchQuery_Empty(t *testing.T) {
	req := &ClaudeRequest{}
	if got := extractSearchQuery(req); got != "" {
		t.Fatalf("expected empty query, got %q", got)
	}
}

func TestCreateMcpRequest_Format(t *testing.T) {
	toolUseID, mcpReq := createMcpRequest("hello")

	if !strings.HasPrefix(toolUseID, "srvtoolu_") {
		t.Errorf("toolUseID prefix wrong: %q", toolUseID)
	}
	if len(toolUseID) != len("srvtoolu_")+32 {
		t.Errorf("toolUseID length = %d", len(toolUseID))
	}
	if !strings.HasPrefix(mcpReq.ID, "web_search_tooluse_") {
		t.Errorf("mcp request ID prefix wrong: %q", mcpReq.ID)
	}
	if mcpReq.JSONRPC != "2.0" {
		t.Errorf("jsonrpc = %q", mcpReq.JSONRPC)
	}
	if mcpReq.Method != "tools/call" {
		t.Errorf("method = %q", mcpReq.Method)
	}
	if mcpReq.Params.Name != "web_search" {
		t.Errorf("params.name = %q", mcpReq.Params.Name)
	}
	if mcpReq.Params.Arguments.Query != "hello" {
		t.Errorf("query = %q", mcpReq.Params.Arguments.Query)
	}
}

func TestParseSearchResults(t *testing.T) {
	inner := `{"results":[{"title":"T1","url":"https://e.com","snippet":"s1","publishedDate":1732299319000,"id":"1","domain":"e.com"}],"totalResults":1,"query":"q"}`
	mcpResp := &McpResponse{
		Result: &McpResult{
			Content: []McpContent{{Type: "text", Text: inner}},
		},
	}
	results := parseSearchResults(mcpResp)
	if results == nil {
		t.Fatal("expected results")
	}
	if len(results.Results) != 1 {
		t.Fatalf("results len = %d", len(results.Results))
	}
	r := results.Results[0]
	if r.Title != "T1" || r.URL != "https://e.com" {
		t.Errorf("unexpected result: %+v", r)
	}
	if r.Snippet == nil || *r.Snippet != "s1" {
		t.Errorf("snippet mismatch: %+v", r.Snippet)
	}
}

func TestParseSearchResults_NonTextContent(t *testing.T) {
	mcpResp := &McpResponse{
		Result: &McpResult{Content: []McpContent{{Type: "image", Text: ""}}},
	}
	if parseSearchResults(mcpResp) != nil {
		t.Fatal("non-text content must yield nil")
	}
}

func TestParseSearchResults_NilResult(t *testing.T) {
	if parseSearchResults(&McpResponse{}) != nil {
		t.Fatal("nil result must yield nil")
	}
}

func TestGenerateSearchSummary_WithResults(t *testing.T) {
	s1 := "a snippet"
	results := &WebSearchResults{
		Results: []WebSearchResult{
			{Title: "Title One", URL: "https://one.com", Snippet: &s1},
		},
	}
	summary := generateSearchSummary("myquery", results)
	for _, want := range []string{"myquery", "Title One", "https://one.com", "a snippet"} {
		if !strings.Contains(summary, want) {
			t.Errorf("summary missing %q:\n%s", want, summary)
		}
	}
}

func TestGenerateSearchSummary_NoResults(t *testing.T) {
	summary := generateSearchSummary("q", nil)
	if !strings.Contains(summary, "No results found") {
		t.Errorf("expected 'No results found':\n%s", summary)
	}
}

func TestGenerateSearchSummary_LongSnippetTruncated(t *testing.T) {
	long := strings.Repeat("x", 300)
	results := &WebSearchResults{
		Results: []WebSearchResult{{Title: "T", URL: "https://e.com", Snippet: &long}},
	}
	summary := generateSearchSummary("q", results)
	if !strings.Contains(summary, "...") {
		t.Error("expected long snippet to be truncated with ellipsis")
	}
}

func TestChunkByRunes(t *testing.T) {
	chunks := chunkByRunes("abcdef", 2)
	if len(chunks) != 3 {
		t.Fatalf("chunks = %v", chunks)
	}
	if strings.Join(chunks, "") != "abcdef" {
		t.Errorf("rejoined = %q", strings.Join(chunks, ""))
	}
}

func TestChunkByRunes_Multibyte(t *testing.T) {
	// マルチバイト文字が壊れないことを確認。
	in := "あいうえおかきくけこ"
	chunks := chunkByRunes(in, 3)
	if strings.Join(chunks, "") != in {
		t.Errorf("multibyte rejoin failed: %q", strings.Join(chunks, ""))
	}
	for _, c := range chunks {
		if !json.Valid([]byte(`"` + c + `"`)) {
			t.Errorf("chunk not valid utf-8: %q", c)
		}
	}
}
