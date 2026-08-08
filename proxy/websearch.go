// WebSearch tool handling.
//
// Anthropic native web_search tools are relayed through Kiro's MCP endpoint
// (https://q.{region}.amazonaws.com/mcp) and synthesized into Anthropic-compatible
// SSE / JSON responses. generateAssistantResponse does not execute web_search;
// it only surfaces tool_use, so pure web_search needs this dedicated path and
// mixed tools need the agentic loop in websearch_loop.go.
//
// References: kiro.rs (ZyphrZero / 2ue) src/anthropic/websearch.rs
package proxy

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"kiro-go/config"
	"kiro-go/logger"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	// Claude Code / Desktop prefixes the user message when invoking native web_search.
	webSearchQueryPrefix = "Perform a web search for the query:"
	webSearchToolName    = "web_search"
	// Chunk size for summary text_delta events (UTF-8 safe via runes).
	webSearchSummaryChunkSize = 100
)

// ==================== MCP types ====================

// McpRequest is the JSON-RPC body sent to Kiro's MCP endpoint.
type McpRequest struct {
	ID      string       `json:"id"`
	JSONRPC string       `json:"jsonrpc"`
	Method  string       `json:"method"`
	Params  McpReqParams `json:"params"`
}

type McpReqParams struct {
	Name      string       `json:"name"`
	Arguments McpArguments `json:"arguments"`
}

type McpArguments struct {
	Query string `json:"query"`
}

// McpResponse is the JSON-RPC response from the MCP endpoint.
type McpResponse struct {
	Error   *McpError  `json:"error"`
	ID      string     `json:"id"`
	JSONRPC string     `json:"jsonrpc"`
	Result  *McpResult `json:"result"`
}

type McpError struct {
	Code    *int    `json:"code"`
	Message *string `json:"message"`
}

type McpResult struct {
	Content []McpContent `json:"content"`
	IsError bool         `json:"isError"`
}

type McpContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// WebSearchResults is the JSON payload embedded in MCP content[0].text.
type WebSearchResults struct {
	Results      []WebSearchResult `json:"results"`
	TotalResults *int              `json:"totalResults"`
	Query        *string           `json:"query"`
	Error        *string           `json:"error"`
}

type WebSearchResult struct {
	Title         string  `json:"title"`
	URL           string  `json:"url"`
	Snippet       *string `json:"snippet"`
	PublishedDate *int64  `json:"publishedDate"`
	ID            *string `json:"id"`
	Domain        *string `json:"domain"`
}

// ==================== Detection & query extraction ====================

// isNativeWebSearchTool reports whether t is Anthropic's server-side web_search tool.
// Native tools use type "web_search_20250305" (or a later web_search_* revision)
// with name "web_search". Client-defined tools that happen to share the name
// but lack the type prefix must not take this path.
func isNativeWebSearchTool(t ClaudeTool) bool {
	return t.Name == webSearchToolName && strings.HasPrefix(strings.TrimSpace(t.Type), "web_search_")
}

// hasWebSearchTool is true when the request carries exactly one native web_search tool.
// That is the pure / fast path that skips generateAssistantResponse entirely.
func hasWebSearchTool(req *ClaudeRequest) bool {
	if req == nil || len(req.Tools) != 1 {
		return false
	}
	return isNativeWebSearchTool(req.Tools[0])
}

// hasWebSearchAmongTools is true when native web_search coexists with other tools.
// Mutually exclusive with hasWebSearchTool: the mixed case falls onto the normal
// chat path and needs the internal agentic loop when upstream returns tool_use
// name=web_search.
func hasWebSearchAmongTools(req *ClaudeRequest) bool {
	if req == nil || len(req.Tools) <= 1 {
		return false
	}
	for _, t := range req.Tools {
		if isNativeWebSearchTool(t) {
			return true
		}
	}
	return false
}

// extractSearchQuery reads the last user turn and strips Claude's fixed search prefix.
// Prefer the last user message so multi-turn pure web_search requests still work
// (2ue refinement over first-message-only).
func extractSearchQuery(req *ClaudeRequest) string {
	if req == nil || len(req.Messages) == 0 {
		return ""
	}

	var text string
	for i := len(req.Messages) - 1; i >= 0; i-- {
		msg := req.Messages[i]
		if strings.TrimSpace(msg.Role) != "user" {
			continue
		}
		text = extractTextFromClaudeContent(msg.Content)
		if strings.TrimSpace(text) != "" {
			break
		}
	}
	if text == "" {
		return ""
	}

	// Prefix may be followed by a space; strip both "prefix" and "prefix ".
	trimmed := strings.TrimSpace(text)
	if strings.HasPrefix(trimmed, webSearchQueryPrefix) {
		trimmed = strings.TrimSpace(trimmed[len(webSearchQueryPrefix):])
	}
	return trimmed
}

// extractTextFromClaudeContent returns the first non-empty text block from Claude content.
func extractTextFromClaudeContent(content interface{}) string {
	switch c := content.(type) {
	case string:
		return c
	case []interface{}:
		// Prefer the last text block (matches 2ue reverse scan within the turn).
		for i := len(c) - 1; i >= 0; i-- {
			block, ok := c[i].(map[string]interface{})
			if !ok {
				continue
			}
			if bt, _ := block["type"].(string); bt != "text" {
				continue
			}
			if t, _ := block["text"].(string); strings.TrimSpace(t) != "" {
				return t
			}
		}
	case []ClaudeContentBlock:
		for i := len(c) - 1; i >= 0; i-- {
			if c[i].Type == "text" && strings.TrimSpace(c[i].Text) != "" {
				return c[i].Text
			}
		}
	}
	return ""
}

// ==================== MCP call ====================

// createMcpRequest builds a tools/call JSON-RPC request and a server_tool_use id
// in the same shape Kiro IDE / Claude expect.
func createMcpRequest(query string) (string, *McpRequest) {
	requestID := fmt.Sprintf(
		"web_search_tooluse_%s_%d_%s",
		randomAlnum(22),
		time.Now().UnixMilli(),
		randomLowerAlnum(8),
	)
	toolUseID := "srvtoolu_" + strings.ReplaceAll(uuid.New().String(), "-", "")
	if len(toolUseID) > len("srvtoolu_")+32 {
		toolUseID = toolUseID[:len("srvtoolu_")+32]
	}

	return toolUseID, &McpRequest{
		ID:      requestID,
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params: McpReqParams{
			Name:      webSearchToolName,
			Arguments: McpArguments{Query: query},
		},
	}
}

func randomAlnum(n int) string {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	return randomFromCharset(n, charset)
}

func randomLowerAlnum(n int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	return randomFromCharset(n, charset)
}

func randomFromCharset(n int, charset string) string {
	if n <= 0 {
		return ""
	}
	b := make([]byte, n)
	// crypto/rand avoids math/rand seed pitfalls in long-running servers.
	if _, err := rand.Read(b); err != nil {
		// Extremely unlikely; fall back to time-based entropy.
		now := time.Now().UnixNano()
		for i := range b {
			b[i] = charset[int(now+int64(i))%len(charset)]
		}
		return string(b)
	}
	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}
	return string(b)
}

// callMcpAPI posts the JSON-RPC request to Kiro MCP and returns the parsed response.
func callMcpAPI(account *config.Account, mcpReq *McpRequest) (*McpResponse, error) {
	if mcpReq == nil {
		return nil, fmt.Errorf("nil MCP request")
	}

	// Ensure profile ARN is available for non-API-key accounts (header required by MCP).
	profileArn := ""
	if account != nil {
		profileArn = strings.TrimSpace(account.ProfileArn)
	}
	if profileArn == "" && account != nil && !config.IsAPIKeyAccount(account) {
		if arn, err := ResolveProfileArn(account); err == nil {
			profileArn = strings.TrimSpace(arn)
		} else if !isProfileArnResolutionSoftError(err) {
			logger.Debugf("[MCP] ProfileArn resolve for %s: %v", accountEmailForLog(account), err)
		}
	}

	region := kiroRegionForProfile(account, profileArn)
	endpoint := fmt.Sprintf("https://q.%s.amazonaws.com/mcp", region)

	reqBody, err := json.Marshal(mcpReq)
	if err != nil {
		return nil, err
	}
	logger.Debugf("[MCP] Request: %s", string(reqBody))

	req, err := http.NewRequest("POST", endpoint, bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}

	host := ""
	if parsed, perr := url.Parse(endpoint); perr == nil {
		host = parsed.Host
	}
	headerValues := buildStreamingHeaderValues(account, host)

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "*/*")
	applyKiroBaseHeaders(req, account, headerValues)
	req.Header.Set("Amz-Sdk-Request", "attempt=1; max=3")
	req.Header.Set("Amz-Sdk-Invocation-Id", uuid.New().String())
	if profileArn != "" {
		req.Header.Set("x-amzn-kiro-profile-arn", profileArn)
	}

	resp, err := GetClientForProxy(ResolveAccountProxyURL(account)).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	logger.Debugf("[MCP] Response (%d): %s", resp.StatusCode, string(body))

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("MCP request failed: HTTP %d: %s", resp.StatusCode, string(body))
	}

	var mcpResp McpResponse
	if err := json.Unmarshal(body, &mcpResp); err != nil {
		return nil, fmt.Errorf("MCP response JSON: %w", err)
	}
	if mcpResp.Error != nil {
		code := -1
		if mcpResp.Error.Code != nil {
			code = *mcpResp.Error.Code
		}
		msg := "Unknown error"
		if mcpResp.Error.Message != nil {
			msg = *mcpResp.Error.Message
		}
		return nil, fmt.Errorf("MCP error: %d - %s", code, msg)
	}
	if mcpResp.Result != nil && mcpResp.Result.IsError {
		return nil, fmt.Errorf("MCP tool error for web_search")
	}

	return &mcpResp, nil
}

// parseSearchResults expands MCP content[0].text into WebSearchResults.
// Returns nil when the payload is missing, malformed, or carries an embedded error.
func parseSearchResults(mcpResp *McpResponse) *WebSearchResults {
	if mcpResp == nil || mcpResp.Result == nil || len(mcpResp.Result.Content) == 0 {
		return nil
	}
	if mcpResp.Result.IsError {
		return nil
	}
	content := mcpResp.Result.Content[0]
	if content.Type != "text" {
		return nil
	}
	var results WebSearchResults
	if err := json.Unmarshal([]byte(content.Text), &results); err != nil {
		logger.Warnf("[MCP] Failed to parse search results: %v", err)
		return nil
	}
	if results.Error != nil && strings.TrimSpace(*results.Error) != "" {
		logger.Warnf("[MCP] Search result payload error: %s", *results.Error)
		return nil
	}
	return &results
}

// performWebSearch runs MCP web_search across the account pool for the given model.
// On total failure it returns (nil, lastErr) so callers can choose to error out
// instead of silently fabricating empty results (the issue #120 symptom).
// A 200 JSON-RPC envelope whose search payload cannot be parsed is also treated
// as failure (retry next account) — only a well-formed results object (including
// an empty results array) counts as success.
func (h *Handler) performWebSearch(model, query string) (*WebSearchResults, string, *config.Account, error) {
	excluded := make(map[string]bool)
	var lastErr error
	for attempt := 0; attempt < maxAccountRetryAttempts; attempt++ {
		account := h.pool.GetNextForModelExcluding(model, excluded)
		if account == nil {
			break
		}
		if err := h.ensureValidToken(account); err != nil {
			lastErr = err
			excluded[account.ID] = true
			h.handleAccountFailure(account, err)
			continue
		}

		toolUseID, mcpReq := createMcpRequest(query)
		mcpResp, err := callMcpAPI(account, mcpReq)
		if err != nil {
			logger.Warnf("[WebSearch] MCP call failed on account %s: %v", account.Email, err)
			lastErr = err
			excluded[account.ID] = true
			h.handleAccountFailure(account, err)
			continue
		}
		results := parseSearchResults(mcpResp)
		if results == nil {
			// HTTP/RPC succeeded but payload is unusable — do not RecordSuccess or
			// return a silent empty summary (issue #120 class of bugs).
			lastErr = fmt.Errorf("MCP web_search returned unparseable or error search payload")
			logger.Warnf("[WebSearch] %v on account %s", lastErr, account.Email)
			excluded[account.ID] = true
			h.handleAccountFailure(account, lastErr)
			continue
		}
		h.pool.RecordSuccess(account.ID)
		return results, toolUseID, account, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no available accounts for web_search")
	}
	return nil, "", nil, lastErr
}

// resolveWebSearchMaxUses returns the effective search budget for a request.
// Native Anthropic tools may set max_uses; when omitted or non-positive, fall
// back to maxWebSearchRounds. The value is also capped by maxWebSearchRounds
// so a large client max_uses cannot open an unbounded agentic loop.
func resolveWebSearchMaxUses(tools []ClaudeTool) int {
	maxUses := 0
	for _, t := range tools {
		if !isNativeWebSearchTool(t) {
			continue
		}
		if t.MaxUses > maxUses {
			maxUses = t.MaxUses
		}
	}
	if maxUses <= 0 {
		return maxWebSearchRounds
	}
	if maxUses > maxWebSearchRounds {
		return maxWebSearchRounds
	}
	return maxUses
}

// ==================== Summary & content blocks ====================

// generateSearchSummary formats results into a human-readable summary for the model / client.
func generateSearchSummary(query string, results *WebSearchResults) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Here are the search results for \"%s\":\n\n", query)

	if results != nil && len(results.Results) > 0 {
		for i, r := range results.Results {
			fmt.Fprintf(&b, "%d. **%s**\n", i+1, r.Title)
			if r.Snippet != nil && *r.Snippet != "" {
				snippet := *r.Snippet
				runes := []rune(snippet)
				if len(runes) > 200 {
					snippet = string(runes[:200]) + "..."
				}
				fmt.Fprintf(&b, "   %s\n", snippet)
			}
			fmt.Fprintf(&b, "   Source: %s\n\n", r.URL)
		}
	} else {
		b.WriteString("No results found.\n")
	}

	b.WriteString("\nPlease note that these are web search results and may not be fully accurate or up-to-date.")
	return b.String()
}

// webSearchResultContent builds Anthropic web_search_result blocks (Contract A fields).
func webSearchResultContent(results *WebSearchResults) []map[string]interface{} {
	out := make([]map[string]interface{}, 0)
	if results == nil {
		return out
	}
	for _, r := range results.Results {
		var pageAge interface{}
		if r.PublishedDate != nil {
			pageAge = time.UnixMilli(*r.PublishedDate).UTC().Format("January 2, 2006")
		}
		encryptedContent := ""
		if r.Snippet != nil {
			encryptedContent = *r.Snippet
		}
		out = append(out, map[string]interface{}{
			"type":              "web_search_result",
			"title":             r.Title,
			"url":               r.URL,
			"encrypted_content": encryptedContent,
			"page_age":          pageAge,
		})
	}
	return out
}

// buildWebSearchContentBlocks returns the pure-path assistant content array.
func buildWebSearchContentBlocks(query, toolUseID string, results *WebSearchResults) []map[string]interface{} {
	return []map[string]interface{}{
		{"type": "text", "text": fmt.Sprintf("I'll search for \"%s\".", query)},
		{
			"id":    toolUseID,
			"type":  "server_tool_use",
			"name":  webSearchToolName,
			"input": map[string]interface{}{"query": query},
		},
		{
			"type":    "web_search_tool_result",
			"content": webSearchResultContent(results),
		},
		{"type": "text", "text": generateSearchSummary(query, results)},
	}
}

// ==================== Pure-path handler ====================

// handleWebSearchRequest serves pure native web_search requests via MCP.
func (h *Handler) handleWebSearchRequest(w http.ResponseWriter, req *ClaudeRequest, estimatedInputTokens int, apiKeyID string) {
	query := extractSearchQuery(req)
	if query == "" {
		h.sendClaudeError(w, 400, "invalid_request_error", "Unable to extract search query from message")
		return
	}

	logger.Infof("[WebSearch] Processing query: %s (stream=%v)", query, req.Stream)
	reqStart := time.Now()

	results, toolUseID, account, err := h.performWebSearch(req.Model, query)
	if err != nil {
		logger.Warnf("[WebSearch] All MCP attempts failed: %v", err)
		accountID := ""
		if account != nil {
			accountID = account.ID
		}
		h.recordFailureWithDetails("claude", req.Model, accountID, err)
		// Prefer a real error over a silent empty body (issue #120 symptom).
		status := 502
		errType := "api_error"
		if isAuthErrorMessage(err.Error()) {
			status = 401
			errType = "authentication_error"
		} else if isQuotaErrorMessage(err.Error()) {
			status = 429
			errType = "rate_limit_error"
		}
		setRetryAfterHeader(w, err)
		h.sendClaudeError(w, status, errType, "Web search failed: "+err.Error())
		return
	}

	summary := generateSearchSummary(query, results)
	outputTokens := (len([]rune(summary)) + 3) / 4
	if outputTokens < 1 {
		outputTokens = 1
	}
	inputTokens := estimatedInputTokens
	if inputTokens < 0 {
		inputTokens = 0
	}

	accountID := ""
	if account != nil {
		accountID = account.ID
		h.pool.UpdateStats(account.ID, inputTokens+outputTokens, 0)
	}
	h.recordSuccessForApiKey(apiKeyID, inputTokens, outputTokens, 0)
	h.recordSuccessLog("claude", req.Model, accountID, inputTokens+outputTokens, 0, time.Since(reqStart).Milliseconds())

	if req.Stream {
		h.streamWebSearchSSE(w, req.Model, query, toolUseID, results, inputTokens, outputTokens)
		return
	}

	// Non-stream JSON (same content blocks as SSE).
	content := buildWebSearchContentBlocks(query, toolUseID, results)
	messageID := "msg_" + strings.ReplaceAll(uuid.New().String(), "-", "")
	if len(messageID) > 4+24 {
		messageID = messageID[:4+24]
	}
	resp := map[string]interface{}{
		"id":            messageID,
		"type":          "message",
		"role":          "assistant",
		"model":         req.Model,
		"content":       content,
		"stop_reason":   "end_turn",
		"stop_sequence": nil,
		"usage": map[string]interface{}{
			"input_tokens":                inputTokens,
			"output_tokens":               outputTokens,
			"cache_creation_input_tokens": 0,
			"cache_read_input_tokens":     0,
			"server_tool_use": map[string]interface{}{
				"web_search_requests": 1,
			},
		},
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(resp)
}

// streamWebSearchSSE emits the Anthropic-compatible pure web_search SSE sequence.
func (h *Handler) streamWebSearchSSE(
	w http.ResponseWriter,
	model, query, toolUseID string,
	results *WebSearchResults,
	inputTokens, outputTokens int,
) {
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		h.sendClaudeError(w, 500, "api_error", "Streaming not supported")
		return
	}

	messageID := "msg_" + strings.ReplaceAll(uuid.New().String(), "-", "")
	if len(messageID) > 4+24 {
		messageID = messageID[:4+24]
	}

	// 1. message_start
	h.sendSSE(w, flusher, "message_start", map[string]interface{}{
		"type": "message_start",
		"message": map[string]interface{}{
			"id":            messageID,
			"type":          "message",
			"role":          "assistant",
			"model":         model,
			"content":       []interface{}{},
			"stop_reason":   nil,
			"stop_sequence": nil,
			"usage": map[string]interface{}{
				"input_tokens":                inputTokens,
				"output_tokens":               0,
				"cache_creation_input_tokens": 0,
				"cache_read_input_tokens":     0,
			},
		},
	})

	// 2. text: decision
	decisionText := fmt.Sprintf("I'll search for \"%s\".", query)
	h.sendSSE(w, flusher, "content_block_start", map[string]interface{}{
		"type":          "content_block_start",
		"index":         0,
		"content_block": map[string]interface{}{"type": "text", "text": ""},
	})
	h.sendSSE(w, flusher, "content_block_delta", map[string]interface{}{
		"type":  "content_block_delta",
		"index": 0,
		"delta": map[string]interface{}{"type": "text_delta", "text": decisionText},
	})
	h.sendSSE(w, flusher, "content_block_stop", map[string]interface{}{
		"type":  "content_block_stop",
		"index": 0,
	})

	// 3. server_tool_use (input is complete in content_block_start; no input_json_delta)
	h.sendSSE(w, flusher, "content_block_start", map[string]interface{}{
		"type":  "content_block_start",
		"index": 1,
		"content_block": map[string]interface{}{
			"id":    toolUseID,
			"type":  "server_tool_use",
			"name":  webSearchToolName,
			"input": map[string]interface{}{"query": query},
		},
	})
	h.sendSSE(w, flusher, "content_block_stop", map[string]interface{}{
		"type":  "content_block_stop",
		"index": 1,
	})

	// 4. web_search_tool_result (no tool_use_id field — matches official API)
	h.sendSSE(w, flusher, "content_block_start", map[string]interface{}{
		"type":  "content_block_start",
		"index": 2,
		"content_block": map[string]interface{}{
			"type":    "web_search_tool_result",
			"content": webSearchResultContent(results),
		},
	})
	h.sendSSE(w, flusher, "content_block_stop", map[string]interface{}{
		"type":  "content_block_stop",
		"index": 2,
	})

	// 5. text: summary
	h.sendSSE(w, flusher, "content_block_start", map[string]interface{}{
		"type":          "content_block_start",
		"index":         3,
		"content_block": map[string]interface{}{"type": "text", "text": ""},
	})
	summary := generateSearchSummary(query, results)
	for _, chunk := range chunkByRunes(summary, webSearchSummaryChunkSize) {
		h.sendSSE(w, flusher, "content_block_delta", map[string]interface{}{
			"type":  "content_block_delta",
			"index": 3,
			"delta": map[string]interface{}{"type": "text_delta", "text": chunk},
		})
	}
	h.sendSSE(w, flusher, "content_block_stop", map[string]interface{}{
		"type":  "content_block_stop",
		"index": 3,
	})

	// 6. message_delta + message_stop
	h.sendSSE(w, flusher, "message_delta", map[string]interface{}{
		"type":  "message_delta",
		"delta": map[string]interface{}{"stop_reason": "end_turn"},
		"usage": map[string]interface{}{
			"output_tokens": outputTokens,
			"server_tool_use": map[string]interface{}{
				"web_search_requests": 1,
			},
		},
	})
	h.sendSSE(w, flusher, "message_stop", map[string]interface{}{
		"type": "message_stop",
	})
}

// chunkByRunes splits s into rune chunks of at most size (UTF-8 safe).
func chunkByRunes(s string, size int) []string {
	if size <= 0 {
		return []string{s}
	}
	runes := []rune(s)
	if len(runes) == 0 {
		return nil
	}
	var chunks []string
	for i := 0; i < len(runes); i += size {
		end := i + size
		if end > len(runes) {
			end = len(runes)
		}
		chunks = append(chunks, string(runes[i:end]))
	}
	return chunks
}

// toolUseQuery extracts the "query" field from a tool_use input map.
func toolUseQuery(input map[string]interface{}) string {
	if input == nil {
		return ""
	}
	if q, ok := input["query"].(string); ok {
		return strings.TrimSpace(q)
	}
	return ""
}
