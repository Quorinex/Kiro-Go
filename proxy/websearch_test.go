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
	if hasWebSearchAmongTools(req) {
		t.Fatal("single native tool must not be treated as mixed")
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
	if !hasWebSearchAmongTools(req) {
		t.Fatal("expected mixed tools with native web_search")
	}
}

func TestHasWebSearchTool_RegularToolNamedWebSearch(t *testing.T) {
	// Client-defined tools named web_search without type web_search_* must not
	// take the native path.
	req := &ClaudeRequest{
		Model: "claude-sonnet-4",
		Tools: []ClaudeTool{
			{Name: "web_search", Description: "Regular client-side search tool"},
		},
	}
	if hasWebSearchTool(req) {
		t.Fatal("regular tool named web_search must not trigger native websearch")
	}
	if isNativeWebSearchTool(req.Tools[0]) {
		t.Fatal("regular tool must not be native")
	}
}

func TestHasWebSearchTool_NoTools(t *testing.T) {
	req := &ClaudeRequest{Model: "claude-sonnet-4"}
	if hasWebSearchTool(req) {
		t.Fatal("request without tools must not be treated as web_search request")
	}
	if hasWebSearchAmongTools(req) {
		t.Fatal("request without tools must not be mixed web_search")
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

func TestExtractSearchQuery_LastUserTurn(t *testing.T) {
	req := &ClaudeRequest{
		Messages: []ClaudeMessage{
			{Role: "user", Content: "Perform a web search for the query: first"},
			{Role: "assistant", Content: "ok"},
			{Role: "user", Content: "Perform a web search for the query: second"},
		},
	}
	if got := extractSearchQuery(req); got != "second" {
		t.Fatalf("query = %q, want second", got)
	}
}

func TestExtractSearchQuery_ArrayContent(t *testing.T) {
	// JSON decode yields []interface{} for content arrays.
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

func TestParseSearchResults_EmbeddedError(t *testing.T) {
	inner := `{"results":[],"error":"upstream failed"}`
	mcpResp := &McpResponse{
		Result: &McpResult{
			Content: []McpContent{{Type: "text", Text: inner}},
		},
	}
	if parseSearchResults(mcpResp) != nil {
		t.Fatal("embedded error must yield nil")
	}
}

func TestParseSearchResults_IsErrorFlag(t *testing.T) {
	mcpResp := &McpResponse{
		Result: &McpResult{
			IsError: true,
			Content: []McpContent{{Type: "text", Text: `{"results":[]}`}},
		},
	}
	if parseSearchResults(mcpResp) != nil {
		t.Fatal("isError must yield nil")
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

func TestShouldSearchRound(t *testing.T) {
	web := []KiroToolUse{{Name: "web_search"}, {Name: "web_search"}}
	if !shouldSearchRound(0, web, maxWebSearchRounds) {
		t.Fatal("pure web_search should continue")
	}
	if shouldSearchRound(maxWebSearchRounds, web, maxWebSearchRounds) {
		t.Fatal("at limit should stop")
	}
	if shouldSearchRound(1, web, 1) {
		t.Fatal("max_uses=1 must stop after first search round index")
	}
	mixed := []KiroToolUse{{Name: "web_search"}, {Name: "Bash"}}
	if shouldSearchRound(0, mixed, maxWebSearchRounds) {
		t.Fatal("mixed tools should not continue loop")
	}
	if shouldSearchRound(0, nil, maxWebSearchRounds) {
		t.Fatal("empty tool uses should not continue")
	}
}

func TestResolveWebSearchMaxUses(t *testing.T) {
	if got := resolveWebSearchMaxUses(nil); got != maxWebSearchRounds {
		t.Fatalf("nil tools: got %d", got)
	}
	if got := resolveWebSearchMaxUses([]ClaudeTool{
		{Type: "web_search_20250305", Name: "web_search", MaxUses: 2},
		{Name: "Bash"},
	}); got != 2 {
		t.Fatalf("max_uses=2: got %d", got)
	}
	if got := resolveWebSearchMaxUses([]ClaudeTool{
		{Type: "web_search_20250305", Name: "web_search", MaxUses: 99},
	}); got != maxWebSearchRounds {
		t.Fatalf("max_uses must be capped at %d, got %d", maxWebSearchRounds, got)
	}
	if got := resolveWebSearchMaxUses([]ClaudeTool{
		{Type: "web_search_20250305", Name: "web_search"},
	}); got != maxWebSearchRounds {
		t.Fatalf("omitted max_uses: got %d", got)
	}
}

func TestResolveFlushStopReason(t *testing.T) {
	if got := resolveFlushStopReason("max_tokens", nil, nil); got != "max_tokens" {
		t.Fatalf("override: %q", got)
	}
	client := []KiroToolUse{{Name: "Bash"}}
	if got := resolveFlushStopReason("", client, nil); got != "tool_use" {
		t.Fatalf("client tool: %q", got)
	}
	webOnly := []KiroToolUse{{Name: "web_search"}}
	if got := resolveFlushStopReason("", webOnly, nil); got != "end_turn" {
		t.Fatalf("web only: %q", got)
	}
	contentWithClient := []map[string]interface{}{
		{"type": "tool_use", "name": "Bash"},
	}
	if got := resolveFlushStopReason("", nil, contentWithClient); got != "tool_use" {
		t.Fatalf("content client tool: %q", got)
	}
}

func TestBuildFlushContent_WebSearchAsServerTool(t *testing.T) {
	snippet := "hello"
	results := &WebSearchResults{
		Results: []WebSearchResult{{Title: "T", URL: "https://e.com", Snippet: &snippet}},
	}
	content := buildFlushContent(nil, "done", []KiroToolUse{
		{ToolUseID: "toolu_1", Name: "web_search", Input: map[string]interface{}{"query": "q"}},
		{ToolUseID: "toolu_2", Name: "Bash", Input: map[string]interface{}{"command": "ls"}},
	}, []*WebSearchResults{results, nil})

	var sawServer, sawClient, sawRawWeb bool
	for _, b := range content {
		switch b["type"] {
		case "server_tool_use":
			sawServer = true
			if b["name"] != "web_search" {
				t.Errorf("server tool name = %v", b["name"])
			}
		case "web_search_tool_result":
			// ok
		case "tool_use":
			if b["name"] == "web_search" {
				sawRawWeb = true
			}
			if b["name"] == "Bash" {
				sawClient = true
			}
		}
	}
	if !sawServer {
		t.Error("expected server_tool_use for web_search")
	}
	if !sawClient {
		t.Error("expected raw tool_use for Bash")
	}
	if sawRawWeb {
		t.Error("web_search must not be flushed as raw tool_use")
	}
}

func TestConvertClaudeTools_SkipsNativeWebSearchAndInjectsSchema(t *testing.T) {
	tools := []ClaudeTool{
		{Type: "web_search_20250305", Name: "web_search"},
		{Name: "Bash", Description: "run", InputSchema: map[string]interface{}{"type": "object"}},
	}
	kiroTools, nameMap := convertClaudeTools(tools)
	var sawWeb, sawClient bool
	for _, tspec := range kiroTools {
		name := tspec.ToolSpecification.Name
		switch {
		case name == "web_search":
			sawWeb = true
			schema, ok := tspec.ToolSpecification.InputSchema.JSON.(map[string]interface{})
			if !ok {
				t.Fatal("web_search schema must be object map")
			}
			props, _ := schema["properties"].(map[string]interface{})
			if props == nil || props["query"] == nil {
				t.Fatalf("web_search schema missing query: %+v", schema)
			}
		case name == "Bash" || name == "bash" || nameMap[name] == "Bash":
			sawClient = true
		}
	}
	if !sawWeb {
		t.Error("expected injected web_search schema for mixed tools")
	}
	if !sawClient {
		t.Errorf("expected client Bash tool in %+v (nameMap=%v)", kiroTools, nameMap)
	}
}

func TestConvertClaudeTools_PureNativeWebSearchSkipped(t *testing.T) {
	// Pure path never calls convertClaudeTools. If it did, native-only must not
	// inject a Kiro web_search (no client tools remain after filtering).
	tools := []ClaudeTool{
		{Type: "web_search_20250305", Name: "web_search"},
	}
	kiroTools, _ := convertClaudeTools(tools)
	if len(kiroTools) != 0 {
		t.Fatalf("pure native web_search must not produce Kiro tools, got %+v", kiroTools)
	}
}

func TestClaudeToolTypeJSONRoundTrip(t *testing.T) {
	raw := `{"type":"web_search_20250305","name":"web_search","max_uses":8}`
	var tool ClaudeTool
	if err := json.Unmarshal([]byte(raw), &tool); err != nil {
		t.Fatal(err)
	}
	if tool.Type != "web_search_20250305" || tool.Name != "web_search" || tool.MaxUses != 8 {
		t.Fatalf("tool = %+v", tool)
	}
	if !isNativeWebSearchTool(tool) {
		t.Fatal("expected native")
	}
}

func TestBuildWebSearchContentBlocks(t *testing.T) {
	s := "snip"
	results := &WebSearchResults{
		Results: []WebSearchResult{{Title: "T", URL: "https://e.com", Snippet: &s}},
	}
	blocks := buildWebSearchContentBlocks("q", "srvtoolu_abc", results)
	if len(blocks) != 4 {
		t.Fatalf("blocks len = %d", len(blocks))
	}
	if blocks[1]["type"] != "server_tool_use" {
		t.Errorf("block1 type = %v", blocks[1]["type"])
	}
	if blocks[2]["type"] != "web_search_tool_result" {
		t.Errorf("block2 type = %v", blocks[2]["type"])
	}
}

// Regression: appendSearchRound must store content in a shape ClaudeToKiro can
// extract (tool_use + tool_result pairing). Previously []map was dropped.
func TestAppendSearchRound_ContentSurvivesClaudeToKiro(t *testing.T) {
	req := &ClaudeRequest{
		Model: "claude-sonnet-4",
		Messages: []ClaudeMessage{
			{Role: "user", Content: "search something"},
		},
		Tools: []ClaudeTool{
			{Type: "web_search_20250305", Name: "web_search", MaxUses: 3},
			{Name: "Bash", Description: "run", InputSchema: map[string]interface{}{"type": "object"}},
		},
	}
	round := &webSearchRoundOutcome{
		text: "Looking it up.",
		toolUses: []KiroToolUse{
			{
				ToolUseID: "toolu_ws_1",
				Name:      "web_search",
				Input:     map[string]interface{}{"query": "golang generics"},
			},
		},
	}
	snippet := "Go 1.18 introduced generics"
	searched := []*WebSearchResults{
		{Results: []WebSearchResult{{Title: "Generics", URL: "https://go.dev", Snippet: &snippet}}},
	}
	presentation := make([]map[string]interface{}, 0)
	appendSearchRound(req, round, searched, &presentation)

	if len(req.Messages) != 3 {
		t.Fatalf("messages len = %d, want 3 (user + assistant + tool_result user)", len(req.Messages))
	}
	if len(presentation) != 2 {
		t.Fatalf("presentation len = %d, want server_tool_use + web_search_tool_result", len(presentation))
	}

	// Direct extract on the in-memory shapes.
	aText, aUses := extractClaudeAssistantContent(req.Messages[1].Content)
	if aText != "Looking it up." || len(aUses) != 1 || aUses[0].ToolUseID != "toolu_ws_1" {
		t.Fatalf("assistant extract failed: text=%q uses=%+v", aText, aUses)
	}
	_, _, _, uResults, errMsg := extractClaudeUserContent(req.Messages[2].Content)
	if errMsg != "" {
		t.Fatalf("unexpected document error: %s", errMsg)
	}
	if len(uResults) != 1 || uResults[0].ToolUseID != "toolu_ws_1" {
		t.Fatalf("user tool_result extract failed: %+v", uResults)
	}
	if len(uResults[0].Content) == 0 || !strings.Contains(uResults[0].Content[0].Text, "golang generics") {
		t.Fatalf("tool_result summary missing query: %+v", uResults[0].Content)
	}

	// Full ClaudeToKiro must keep the active tool turn (history tool_use ↔ current toolResults).
	payload := ClaudeToKiro(req, false)
	if payload == nil {
		t.Fatal("nil payload")
	}
	ctx := payload.ConversationState.CurrentMessage.UserInputMessage.UserInputMessageContext
	if ctx == nil || len(ctx.ToolResults) == 0 {
		t.Fatal("ClaudeToKiro dropped tool_results after appendSearchRound")
	}
	if ctx.ToolResults[0].ToolUseID != "toolu_ws_1" {
		t.Fatalf("tool result id = %q", ctx.ToolResults[0].ToolUseID)
	}
	// History last assistant must carry matching tool_use.
	hist := payload.ConversationState.History
	if len(hist) == 0 {
		t.Fatal("expected history")
	}
	last := hist[len(hist)-1]
	if last.AssistantResponseMessage == nil || len(last.AssistantResponseMessage.ToolUses) == 0 {
		t.Fatalf("last history assistant missing tool_use: %+v", last.AssistantResponseMessage)
	}
	if last.AssistantResponseMessage.ToolUses[0].ToolUseID != "toolu_ws_1" {
		t.Fatalf("history tool_use id = %q", last.AssistantResponseMessage.ToolUses[0].ToolUseID)
	}
}

func TestExtractClaudeContent_MapSliceShape(t *testing.T) {
	// Defense in depth: []map[string]interface{} must work even without []interface{}.
	user := []map[string]interface{}{
		{"type": "tool_result", "tool_use_id": "id1", "content": "ok"},
	}
	_, _, _, results, errMsg := extractClaudeUserContent(user)
	if errMsg != "" {
		t.Fatalf("unexpected document error: %s", errMsg)
	}
	if len(results) != 1 || results[0].ToolUseID != "id1" {
		t.Fatalf("map-slice user content: %+v", results)
	}
	asst := []map[string]interface{}{
		{"type": "text", "text": "hi"},
		{"type": "tool_use", "id": "id1", "name": "web_search", "input": map[string]interface{}{"query": "q"}},
	}
	text, uses := extractClaudeAssistantContent(asst)
	if text != "hi" || len(uses) != 1 || uses[0].Name != "web_search" {
		t.Fatalf("map-slice assistant content: text=%q uses=%+v", text, uses)
	}
}

func TestParseSearchResults_EmptyResultsArrayIsValid(t *testing.T) {
	// Empty results is a legitimate MCP success; only unparseable/error payloads are nil.
	inner := `{"results":[],"totalResults":0,"query":"q"}`
	mcpResp := &McpResponse{
		Result: &McpResult{
			Content: []McpContent{{Type: "text", Text: inner}},
		},
	}
	results := parseSearchResults(mcpResp)
	if results == nil {
		t.Fatal("empty results array must parse as non-nil success")
	}
	if len(results.Results) != 0 {
		t.Fatalf("results len = %d", len(results.Results))
	}
}

func TestClaudeToKiroFoldsServerWebSearchResultsIntoHistory(t *testing.T) {
	snippet := "Go 1.18 introduced generics"
	req := &ClaudeRequest{
		Model: "claude-sonnet-4.5",
		Messages: []ClaudeMessage{
			{Role: "user", Content: "search and then run bash"},
			{Role: "assistant", Content: []interface{}{
				map[string]interface{}{"type": "text", "text": "I searched first."},
				map[string]interface{}{
					"type":  "server_tool_use",
					"id":    "srvtoolu_1",
					"name":  "web_search",
					"input": map[string]interface{}{"query": "golang generics"},
				},
				map[string]interface{}{
					"type": "web_search_tool_result",
					"content": []interface{}{
						map[string]interface{}{
							"type":              "web_search_result",
							"title":             "Generics",
							"url":               "https://go.dev",
							"encrypted_content": snippet,
						},
					},
				},
				map[string]interface{}{
					"type":  "tool_use",
					"id":    "toolu_bash",
					"name":  "Bash",
					"input": map[string]interface{}{"command": "ls"},
				},
			}},
			{Role: "user", Content: []interface{}{
				map[string]interface{}{"type": "tool_result", "tool_use_id": "toolu_bash", "content": "a.go"},
			}},
		},
	}

	payload := ClaudeToKiro(req, false)
	if payload == nil {
		t.Fatal("nil payload")
	}
	history := payload.ConversationState.History
	if len(history) == 0 {
		t.Fatal("expected history")
	}
	last := history[len(history)-1]
	if last.AssistantResponseMessage == nil {
		t.Fatal("expected assistant history entry")
	}
	if !strings.Contains(last.AssistantResponseMessage.Content, "golang generics") {
		t.Fatalf("assistant history missing folded search summary: %q", last.AssistantResponseMessage.Content)
	}
	if !strings.Contains(last.AssistantResponseMessage.Content, "https://go.dev") {
		t.Fatalf("assistant history missing search source: %q", last.AssistantResponseMessage.Content)
	}
	if len(last.AssistantResponseMessage.ToolUses) != 1 || last.AssistantResponseMessage.ToolUses[0].ToolUseID != "toolu_bash" {
		t.Fatalf("client tool uses = %+v, want only Bash", last.AssistantResponseMessage.ToolUses)
	}
}

func TestClaudeToKiroFoldsEmptyServerWebSearchResults(t *testing.T) {
	req := &ClaudeRequest{
		Model: "claude-sonnet-4.5",
		Messages: []ClaudeMessage{
			{Role: "user", Content: "search and then run bash"},
			{Role: "assistant", Content: []interface{}{
				map[string]interface{}{"type": "text", "text": "I searched first."},
				map[string]interface{}{
					"type":  "server_tool_use",
					"id":    "srvtoolu_empty",
					"name":  "web_search",
					"input": map[string]interface{}{"query": "unlikely query"},
				},
				map[string]interface{}{
					"type":    "web_search_tool_result",
					"content": []interface{}{},
				},
				map[string]interface{}{
					"type":  "tool_use",
					"id":    "toolu_bash",
					"name":  "Bash",
					"input": map[string]interface{}{"command": "ls"},
				},
			}},
			{Role: "user", Content: []interface{}{
				map[string]interface{}{"type": "tool_result", "tool_use_id": "toolu_bash", "content": "a.go"},
			}},
		},
	}

	payload := ClaudeToKiro(req, false)
	last := payload.ConversationState.History[len(payload.ConversationState.History)-1]
	if last.AssistantResponseMessage == nil {
		t.Fatal("expected assistant history entry")
	}
	if !strings.Contains(last.AssistantResponseMessage.Content, "unlikely query") {
		t.Fatalf("empty search missing query in folded summary: %q", last.AssistantResponseMessage.Content)
	}
	if !strings.Contains(last.AssistantResponseMessage.Content, "No results found.") {
		t.Fatalf("empty search missing No results found text: %q", last.AssistantResponseMessage.Content)
	}
	if len(last.AssistantResponseMessage.ToolUses) != 1 || last.AssistantResponseMessage.ToolUses[0].ToolUseID != "toolu_bash" {
		t.Fatalf("client tool uses = %+v, want only Bash", last.AssistantResponseMessage.ToolUses)
	}
}

func TestSealClientVisibleWebSearchContentMatchesContinuation(t *testing.T) {
	globalSessionStore = newSessionStore()
	const api = "key-ws-mixed"
	const model = "claude-sonnet-4.5"
	inbound := []ClaudeMessage{{Role: "user", Content: "search and then run bash"}}
	conv, cont, _ := resolveSessionIDs(api, MapModel(model), inbound)

	content := []map[string]interface{}{
		{"type": "text", "text": "I searched first."},
		{
			"type":  "server_tool_use",
			"id":    "srvtoolu_1",
			"name":  "web_search",
			"input": map[string]interface{}{"query": "golang generics"},
		},
		{
			"type": "web_search_tool_result",
			"content": []interface{}{
				map[string]interface{}{
					"type":              "web_search_result",
					"title":             "Generics",
					"url":               "https://go.dev",
					"encrypted_content": "Go 1.18 introduced generics",
				},
			},
		},
		{
			"type":  "tool_use",
			"id":    "toolu_bash",
			"name":  "Bash",
			"input": map[string]interface{}{"command": "ls"},
		},
	}
	// Old path: seal the raw upstream tool_use shape. That must not match the
	// client-visible continuation that stores server_tool_use blocks.
	sealClaudeSession(api, model, conv, cont, inbound, "I searched first.", "",
		[]KiroToolUse{
			{ToolUseID: "toolu_ws", Name: "web_search", Input: map[string]interface{}{"query": "golang generics"}},
			{ToolUseID: "toolu_bash", Name: "Bash", Input: map[string]interface{}{"command": "ls"}},
		}, "", true)
	turn2 := []ClaudeMessage{
		inbound[0],
		{Role: "assistant", Content: content},
		{Role: "user", Content: []interface{}{
			map[string]interface{}{"type": "tool_result", "tool_use_id": "toolu_bash", "content": "a.go"},
		}},
	}
	if _, _, reused := resolveSessionIDs(api, MapModel(model), turn2); reused {
		t.Fatal("raw upstream tool shape must not match client-visible server_tool_use continuation")
	}

	// Target path: seal the exact client-visible content. Continuation must reuse.
	globalSessionStore = newSessionStore()
	conv, cont, _ = resolveSessionIDs(api, MapModel(model), inbound)
	sealClaudeSessionFromContent(api, model, conv, cont, inbound, content)
	gotConv, gotCont, reused := resolveSessionIDs(api, MapModel(model), turn2)
	if !reused {
		t.Fatal("client-visible flush content must seal the continuation chain")
	}
	if gotConv != conv || gotCont != cont {
		t.Fatalf("ids = %s/%s, want %s/%s", gotConv, gotCont, conv, cont)
	}
}

// Intermediate search-only rounds seal the raw upstream tool shape so the next
// loop iteration can reuse the same conversation / continuation IDs. The final
// client-facing flush still seals server_tool_use content separately.
func TestIntermediateWebSearchRoundSealReusesNextLoopIDs(t *testing.T) {
	globalSessionStore = newSessionStore()
	globalReasoningStore = newReasoningStore()

	const api = "key-ws-intermediate"
	const model = "claude-sonnet-4.5"
	inbound := []ClaudeMessage{{Role: "user", Content: "search golang generics"}}
	conv, cont, reused := resolveSessionIDs(api, MapModel(model), inbound)
	if reused {
		t.Fatal("first web-search round must mint fresh ids")
	}

	round := &webSearchRoundOutcome{
		text: "Looking it up.",
		toolUses: []KiroToolUse{{
			ToolUseID: "toolu_ws_1",
			Name:      webSearchToolName,
			Input:     map[string]interface{}{"query": "golang generics"},
		}},
		convID: conv,
		contID: cont,
	}
	// Same seal the production intermediate path performs after a successful
	// upstream round, before appendSearchRound mutates the working transcript.
	stamp := &reasoningCapture{sig: "sig-ws-1"}
	stamp.sealIfPresent(api, MapModel(model), conv, "search golang generics", round.text, round.toolUses, "hidden search plan")
	sealClaudeSession(api, model, conv, cont, inbound, round.text, "", round.toolUses, "", true)

	working := &ClaudeRequest{Model: model, Messages: append([]ClaudeMessage(nil), inbound...)}
	presentation := make([]map[string]interface{}, 0)
	snippet := "Go 1.18 introduced generics"
	searched := []*WebSearchResults{{
		Results: []WebSearchResult{{Title: "Generics", URL: "https://go.dev", Snippet: &snippet}},
	}}
	appendSearchRound(working, round, searched, &presentation)

	gotConv, gotCont, reusedNext := resolveSessionIDs(api, MapModel(model), working.Messages)
	if !reusedNext {
		t.Fatal("next loop iteration must reuse ids after intermediate raw-tool seal")
	}
	if gotConv != conv || gotCont != cont {
		t.Fatalf("next-loop ids = %s/%s, want %s/%s", gotConv, gotCont, conv, cont)
	}

	// Final client-visible flush still needs its own seal; raw intermediate seal
	// must not accidentally match a server_tool_use continuation from the client.
	content := buildFlushContent(presentation, "done", nil, nil)
	clientTurn := []ClaudeMessage{
		inbound[0],
		{Role: "assistant", Content: content},
		{Role: "user", Content: "thanks"},
	}
	if _, _, reusedClient := resolveSessionIDs(api, MapModel(model), clientTurn); reusedClient {
		t.Fatal("intermediate raw-tool seal must not match client-visible server_tool_use chain")
	}
}
