// WebSearch 工具处理模块
//
// Anthropic ネイティブ web_search ツールのリクエストを Kiro の MCP エンドポイント
// (https://q.{region}.amazonaws.com/mcp) に中継し、Anthropic 互換の SSE レスポンスを
// 合成して返す。Kiro 自身は web_search を MCP ツールとして提供しているが、通常の
// generateAssistantResponse 経由では実行されないため、専用パスとして処理する。
//
// 参考実装: kiro.rs src/anthropic/websearch.rs
package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"kiro-go/config"
	"kiro-go/logger"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	// webSearchQueryPrefix は Claude Code / Desktop がネイティブ web_search を
	// 呼ぶ際にメッセージ本文へ付与するプレフィックス。
	webSearchQueryPrefix = "Perform a web search for the query: "
	// webSearchToolName は Anthropic / Kiro 双方での web_search ツール名。
	webSearchToolName = "web_search"
	// webSearchSummaryChunkSize はテキスト要約を SSE で分割送信する際の文字数。
	webSearchSummaryChunkSize = 100
)

// ==================== MCP 类型 ====================

// McpRequest は Kiro MCP エンドポイントへ送る JSON-RPC リクエスト。
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

// McpResponse は MCP エンドポイントからの JSON-RPC レスポンス。
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

// WebSearchResults は MCP の content[0].text に JSON 文字列として埋め込まれた検索結果。
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

// ==================== 检测与查询提取 ====================

// isNativeWebSearchTool は Anthropic ネイティブ web_search ツール
// (name=web_search かつ type=web_search_*) かを判定する。
func isNativeWebSearchTool(t ClaudeTool) bool {
	return t.Name == webSearchToolName && strings.HasPrefix(t.Type, "web_search_")
}

// hasWebSearchTool はリクエストが「ネイティブ web_search ツール 1 個だけ」を
// 持つ純粋な WebSearch リクエストかを判定する（高速パスの条件）。
func hasWebSearchTool(req *ClaudeRequest) bool {
	if req == nil || len(req.Tools) != 1 {
		return false
	}
	return isNativeWebSearchTool(req.Tools[0])
}

// extractSearchQuery は最初のユーザーメッセージから検索クエリを抽出する。
// "Perform a web search for the query: " プレフィックスがあれば取り除く。
func extractSearchQuery(req *ClaudeRequest) string {
	if req == nil || len(req.Messages) == 0 {
		return ""
	}
	first := req.Messages[0]
	text := ""
	switch c := first.Content.(type) {
	case string:
		text = c
	case []interface{}:
		if len(c) == 0 {
			return ""
		}
		block, ok := c[0].(map[string]interface{})
		if !ok {
			return ""
		}
		if bt, _ := block["type"].(string); bt != "text" {
			return ""
		}
		text, _ = block["text"].(string)
	default:
		return ""
	}

	text = strings.TrimPrefix(text, webSearchQueryPrefix)
	return strings.TrimSpace(text)
}

// ==================== MCP 调用 ====================

// resolveMcpRegion はアカウントのリージョンを返す。未設定なら us-east-1。
func resolveMcpRegion(account *config.Account) string {
	if account != nil {
		if r := strings.TrimSpace(account.Region); r != "" {
			return r
		}
	}
	return "us-east-1"
}

// createMcpRequest は web_search 用の MCP リクエストと、レスポンス用の
// server_tool_use ID を生成する。ID 形式は Kiro IDE の実装に合わせる。
func createMcpRequest(query string) (string, *McpRequest) {
	requestID := fmt.Sprintf(
		"web_search_tooluse_%s_%d_%s",
		randomAlnum(22),
		time.Now().UnixMilli(),
		randomLowerAlnum(8),
	)
	toolUseID := "srvtoolu_" + strings.ReplaceAll(uuid.New().String(), "-", "")[:32]

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
	b := make([]byte, n)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

// callMcpAPI は Kiro MCP エンドポイントへ JSON-RPC リクエストを送り、結果を返す。
func callMcpAPI(account *config.Account, mcpReq *McpRequest) (*McpResponse, error) {
	region := resolveMcpRegion(account)
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
	if account != nil {
		if arn := strings.TrimSpace(account.ProfileArn); arn != "" {
			req.Header.Set("x-amzn-kiro-profile-arn", arn)
		}
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
		return nil, err
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

	return &mcpResp, nil
}

// parseSearchResults は MCP レスポンスの content[0].text を WebSearchResults に展開する。
func parseSearchResults(mcpResp *McpResponse) *WebSearchResults {
	if mcpResp == nil || mcpResp.Result == nil || len(mcpResp.Result.Content) == 0 {
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
	return &results
}

// ==================== 摘要生成 ====================

// generateSearchSummary は検索結果を人間可読なテキスト要約に整形する。
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

// ==================== SSE 生成 ====================

// handleWebSearchRequest は純粋な WebSearch リクエストを処理し、SSE で結果を返す。
func (h *Handler) handleWebSearchRequest(w http.ResponseWriter, req *ClaudeRequest, estimatedInputTokens int) {
	query := extractSearchQuery(req)
	if query == "" {
		h.sendClaudeError(w, 400, "invalid_request_error", "Unable to extract search query from message")
		return
	}

	logger.Infof("[WebSearch] Processing query: %s", query)

	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		h.sendClaudeError(w, 500, "api_error", "Streaming not supported")
		return
	}

	// 利用可能なアカウントで MCP を呼び出す。
	var searchResults *WebSearchResults
	excluded := make(map[string]bool)
	for attempt := 0; attempt < maxAccountRetryAttempts; attempt++ {
		account := h.pool.GetNextForModelExcluding(req.Model, excluded)
		if account == nil {
			break
		}
		if err := h.ensureValidToken(account); err != nil {
			excluded[account.ID] = true
			h.handleAccountFailure(account, err)
			continue
		}

		toolUseID, mcpReq := createMcpRequest(query)
		mcpResp, err := callMcpAPI(account, mcpReq)
		if err != nil {
			logger.Warnf("[WebSearch] MCP call failed on account %s: %v", account.Email, err)
			excluded[account.ID] = true
			h.handleAccountFailure(account, err)
			continue
		}
		searchResults = parseSearchResults(mcpResp)
		h.streamWebSearchSSE(w, flusher, req.Model, query, toolUseID, searchResults, estimatedInputTokens)
		return
	}

	// 全アカウントで失敗した場合も、空結果として正常な SSE を返す
	// (クライアント側がエラーで停止しないよう、Rust 実装と同じ挙動)。
	toolUseID := "srvtoolu_" + strings.ReplaceAll(uuid.New().String(), "-", "")[:32]
	h.streamWebSearchSSE(w, flusher, req.Model, query, toolUseID, nil, estimatedInputTokens)
}

// streamWebSearchSSE は Anthropic 互換の WebSearch SSE イベント列を送信する。
func (h *Handler) streamWebSearchSSE(
	w http.ResponseWriter,
	flusher http.Flusher,
	model, query, toolUseID string,
	results *WebSearchResults,
	inputTokens int,
) {
	messageID := "msg_" + strings.ReplaceAll(uuid.New().String(), "-", "")[:24]

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

	// 2. content_block (text, index 0): 検索決定の説明
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

	// 3. content_block (server_tool_use, index 1): input は一括送信
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

	// 4. content_block (web_search_tool_result, index 2)
	searchContent := make([]map[string]interface{}, 0)
	if results != nil {
		for _, r := range results.Results {
			var pageAge interface{}
			if r.PublishedDate != nil {
				pageAge = time.UnixMilli(*r.PublishedDate).UTC().Format("January 2, 2006")
			}
			encryptedContent := ""
			if r.Snippet != nil {
				encryptedContent = *r.Snippet
			}
			searchContent = append(searchContent, map[string]interface{}{
				"type":              "web_search_result",
				"title":             r.Title,
				"url":               r.URL,
				"encrypted_content": encryptedContent,
				"page_age":          pageAge,
			})
		}
	}
	h.sendSSE(w, flusher, "content_block_start", map[string]interface{}{
		"type":  "content_block_start",
		"index": 2,
		"content_block": map[string]interface{}{
			"type":    "web_search_tool_result",
			"content": searchContent,
		},
	})
	h.sendSSE(w, flusher, "content_block_stop", map[string]interface{}{
		"type":  "content_block_stop",
		"index": 2,
	})

	// 5. content_block (text, index 3): 結果要約
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

	// 6. message_delta
	outputTokens := (len([]rune(summary)) + 3) / 4
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

	// 7. message_stop
	h.sendSSE(w, flusher, "message_stop", map[string]interface{}{
		"type": "message_stop",
	})
}

// chunkByRunes は文字列を rune 単位で size 文字ずつに分割する（UTF-8 安全）。
func chunkByRunes(s string, size int) []string {
	if size <= 0 {
		return []string{s}
	}
	runes := []rune(s)
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
