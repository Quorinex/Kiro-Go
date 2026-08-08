// web_search local agentic loop.
//
// Handles mixed tools (native web_search + client tools such as Bash/exec):
// when generateAssistantResponse returns tool_use name=web_search, we execute
// the search via MCP, feed the summary back as tool_result, and re-call Kiro
// until the model stops asking to search or hits the round limit.
// Client tool_use blocks are returned to the client as usual (never swallowed).
//
// References: kiro.rs src/anthropic/websearch_loop.rs
package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"kiro-go/config"
	"kiro-go/logger"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

const maxWebSearchRounds = 5

// webSearchRoundOutcome is one buffered generateAssistantResponse round.
type webSearchRoundOutcome struct {
	text               string
	toolUses           []KiroToolUse
	inputTokens        int
	credits            float64
	stopReasonOverride string
}

// runWebSearchLoop is the mixed-tools entry point.
func (h *Handler) runWebSearchLoop(ctx context.Context, w http.ResponseWriter, req *ClaudeRequest, thinking bool, estimatedInputTokens int, apiKeyID string) {
	// Working copy of messages we will mutate as we feed search results back.
	working := *req
	working.Messages = append([]ClaudeMessage(nil), req.Messages...)

	presentation := make([]map[string]interface{}, 0)
	var lastAccountID string
	var totalCredits float64
	reqStart := time.Now()
	fallbackInput := estimatedInputTokens
	// Respect native max_uses (capped by maxWebSearchRounds).
	maxUses := resolveWebSearchMaxUses(req.Tools)
	searchCount := 0

	// Allow one extra iteration so a terminal flush can run after the last
	// search-only round (same pattern as 0..=MAX_WEB_SEARCH_ROUNDS in kiro-rs).
	for roundIdx := 0; roundIdx <= maxUses; roundIdx++ {
		if ctx.Err() != nil {
			return
		}
		round, account, err := h.callUpstreamForWebSearch(ctx, &working, thinking, fallbackInput)
		if err != nil {
			logger.Warnf("[WebSearchLoop] upstream round %d failed: %v", roundIdx, err)
			accountID := ""
			if account != nil {
				accountID = account.ID
			}
			h.recordFailureWithDetails("claude", req.Model, accountID, err)
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
			h.sendClaudeError(w, status, errType, err.Error())
			return
		}
		if account != nil {
			lastAccountID = account.ID
		}
		totalCredits += round.credits

		// Continue only when every tool_use is web_search, budget remains, and
		// this round's searches fit under max_uses.
		roundSearchN := countWebSearchToolUses(round.toolUses)
		if shouldSearchRound(roundIdx, round.toolUses, maxUses) && searchCount+roundSearchN <= maxUses {
			searched, searchErr := h.searchAllWebUses(req.Model, round.toolUses)
			if searchErr != nil {
				logger.Warnf("[WebSearchLoop] MCP search failed: %v", searchErr)
				h.recordFailureWithDetails("claude", req.Model, lastAccountID, searchErr)
				setRetryAfterHeader(w, searchErr)
				h.sendClaudeError(w, upstreamErrorHTTPStatus(searchErr), "api_error", "Web search failed: "+searchErr.Error())
				return
			}
			searchCount += roundSearchN
			appendSearchRound(&working, round, searched, &presentation)
			continue
		}

		// Terminal round: execute any remaining web_search (mixed with client tools
		// or round/max_uses limit), present them as server_tool_use, pass client tools through.
		// Honor remaining max_uses budget for final-round web_search executions.
		searched := make([]*WebSearchResults, len(round.toolUses))
		for i, tu := range round.toolUses {
			if tu.Name != webSearchToolName {
				continue
			}
			if searchCount >= maxUses {
				logger.Warnf("[WebSearchLoop] max_uses=%d reached; skipping further web_search", maxUses)
				break
			}
			results, _, _, sErr := h.performWebSearch(req.Model, toolUseQuery(tu.Input))
			if sErr != nil {
				logger.Warnf("[WebSearchLoop] final-round MCP search failed: %v", sErr)
				h.recordFailureWithDetails("claude", req.Model, lastAccountID, sErr)
				setRetryAfterHeader(w, sErr)
				h.sendClaudeError(w, upstreamErrorHTTPStatus(sErr), "api_error", "Web search failed: "+sErr.Error())
				return
			}
			searched[i] = results
			searchCount++
		}

		content := buildFlushContent(presentation, round.text, round.toolUses, searched)
		stopReason := resolveFlushStopReason(round.stopReasonOverride, round.toolUses, content)
		outputTokens := estimateContentBlocksTokens(content)
		inputTokens := round.inputTokens
		if inputTokens <= 0 {
			inputTokens = fallbackInput
		}

		if lastAccountID != "" {
			h.pool.RecordSuccess(lastAccountID)
			h.pool.UpdateStats(lastAccountID, inputTokens+outputTokens, totalCredits)
		}
		h.recordSuccessForApiKey(apiKeyID, inputTokens, outputTokens, totalCredits)
		h.recordSuccessLog("claude", req.Model, lastAccountID, inputTokens+outputTokens, totalCredits, time.Since(reqStart).Milliseconds())

		if req.Stream {
			h.renderWebSearchLoopSSE(w, req.Model, content, stopReason, inputTokens, outputTokens)
			return
		}
		h.renderWebSearchLoopJSON(w, req.Model, content, stopReason, inputTokens, outputTokens)
		return
	}

	h.sendClaudeError(w, 500, "api_error", "web_search loop exited unexpectedly")
}

// callUpstreamForWebSearch converts the Claude request and buffers one Kiro stream.
func (h *Handler) callUpstreamForWebSearch(ctx context.Context, req *ClaudeRequest, thinking bool, estimatedInputTokens int) (*webSearchRoundOutcome, *config.Account, error) {
	payload := ClaudeToKiro(req, thinking)
	excluded := make(map[string]bool)
	var lastErr error

	for attempt := 0; attempt < maxAccountRetryAttempts; attempt++ {
		account := h.pool.GetNextForModelExcluding(req.Model, excluded)
		if account == nil {
			break
		}
		if err := h.ensureValidToken(account); err != nil {
			lastErr = err
			excluded[account.ID] = true
			h.handleAccountFailure(account, err)
			continue
		}

		var text string
		var toolUses []KiroToolUse
		var inputTokens int
		var credits float64
		var realInputTokens int
		var stopOverride string

		callback := &KiroStreamCallback{
			OnText: func(t string, isThinking bool) {
				if isThinking {
					return
				}
				text += t
			},
			OnToolUse: func(tu KiroToolUse) {
				toolUses = append(toolUses, tu)
			},
			OnComplete: func(inTok, outTok int) {
				inputTokens = inTok
				_ = outTok
			},
			OnCredits: func(c float64) {
				credits = c
			},
			OnContextUsage: func(pct float64) {
				realInputTokens = int(pct * float64(getContextWindowSize(req.Model)) / 100.0)
				if pct >= 100.0 {
					stopOverride = "model_context_window_exceeded"
				}
			},
			OnError: func(err error) {
				if err != nil {
					lastErr = err
				}
			},
		}

		err := CallKiroAPIContext(ctx, account, payload, callback)
		if err != nil {
			if ctx.Err() != nil {
				return nil, account, ctx.Err()
			}
			lastErr = err
			excluded[account.ID] = true
			h.handleAccountFailure(account, err)
			continue
		}

		if realInputTokens > 0 {
			inputTokens = realInputTokens
		} else if inputTokens <= 0 {
			inputTokens = estimatedInputTokens
		}

		return &webSearchRoundOutcome{
			text:               text,
			toolUses:           toolUses,
			inputTokens:        inputTokens,
			credits:            credits,
			stopReasonOverride: stopOverride,
		}, account, nil
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("no available accounts")
	}
	return nil, nil, lastErr
}

// shouldSearchRound continues the loop only when every tool_use is web_search
// and the max_uses / round budget has not been reached.
func shouldSearchRound(roundIdx int, toolUses []KiroToolUse, maxUses int) bool {
	if maxUses <= 0 {
		maxUses = maxWebSearchRounds
	}
	if len(toolUses) == 0 || roundIdx >= maxUses {
		return false
	}
	for _, tu := range toolUses {
		if tu.Name != webSearchToolName {
			return false
		}
	}
	return true
}

func countWebSearchToolUses(toolUses []KiroToolUse) int {
	n := 0
	for _, tu := range toolUses {
		if tu.Name == webSearchToolName {
			n++
		}
	}
	return n
}

// searchAllWebUses runs MCP for each tool_use in order (all are web_search).
func (h *Handler) searchAllWebUses(model string, toolUses []KiroToolUse) ([]*WebSearchResults, error) {
	out := make([]*WebSearchResults, 0, len(toolUses))
	for _, tu := range toolUses {
		results, _, _, err := h.performWebSearch(model, toolUseQuery(tu.Input))
		if err != nil {
			return nil, err
		}
		out = append(out, results)
	}
	return out, nil
}

// appendSearchRound feeds assistant(text + web_search tool_use) + user(tool_result)
// into the working messages and appends presentation blocks for the client.
//
// Content is stored as []interface{} (not []map[string]interface{}) so that
// ClaudeToKiro's extractClaude* helpers — which historically only accepted the
// JSON-decoded []interface{} shape — always see tool_use/tool_result blocks.
// extractClaude* also accepts []map now as defense in depth.
func appendSearchRound(
	req *ClaudeRequest,
	round *webSearchRoundOutcome,
	searched []*WebSearchResults,
	presentation *[]map[string]interface{},
) {
	assistantContent := make([]interface{}, 0)
	if strings.TrimSpace(round.text) != "" {
		assistantContent = append(assistantContent, map[string]interface{}{
			"type": "text",
			"text": round.text,
		})
	}
	for _, tu := range round.toolUses {
		input := tu.Input
		if input == nil {
			input = map[string]interface{}{}
		}
		assistantContent = append(assistantContent, map[string]interface{}{
			"type":  "tool_use",
			"id":    tu.ToolUseID,
			"name":  tu.Name,
			"input": input,
		})
	}
	req.Messages = append(req.Messages, ClaudeMessage{
		Role:    "assistant",
		Content: assistantContent,
	})

	userContent := make([]interface{}, 0, len(round.toolUses))
	for i, tu := range round.toolUses {
		var results *WebSearchResults
		if i < len(searched) {
			results = searched[i]
		}
		query := toolUseQuery(tu.Input)
		summary := generateSearchSummary(query, results)
		userContent = append(userContent, map[string]interface{}{
			"type":        "tool_result",
			"tool_use_id": tu.ToolUseID,
			"content":     summary,
		})

		// Client presentation: server_tool_use + web_search_tool_result (Contract A).
		srvID, _ := createMcpRequest(query)
		*presentation = append(*presentation, map[string]interface{}{
			"type":  "server_tool_use",
			"id":    srvID,
			"name":  webSearchToolName,
			"input": map[string]interface{}{"query": query},
		})
		*presentation = append(*presentation, map[string]interface{}{
			"type":    "web_search_tool_result",
			"content": webSearchResultContent(results),
		})
	}
	req.Messages = append(req.Messages, ClaudeMessage{
		Role:    "user",
		Content: userContent,
	})
}

// buildFlushContent merges presentation + final text + tool uses.
// web_search becomes server_tool_use + web_search_tool_result; client tools stay raw.
func buildFlushContent(
	presentation []map[string]interface{},
	text string,
	toolUses []KiroToolUse,
	searched []*WebSearchResults,
) []map[string]interface{} {
	content := make([]map[string]interface{}, 0, len(presentation)+len(toolUses)+1)
	content = append(content, presentation...)
	if strings.TrimSpace(text) != "" {
		content = append(content, map[string]interface{}{
			"type": "text",
			"text": text,
		})
	}
	for i, tu := range toolUses {
		if tu.Name == webSearchToolName {
			query := toolUseQuery(tu.Input)
			srvID, _ := createMcpRequest(query)
			var results *WebSearchResults
			if i < len(searched) {
				results = searched[i]
			}
			content = append(content, map[string]interface{}{
				"type":  "server_tool_use",
				"id":    srvID,
				"name":  webSearchToolName,
				"input": map[string]interface{}{"query": query},
			})
			content = append(content, map[string]interface{}{
				"type":    "web_search_tool_result",
				"content": webSearchResultContent(results),
			})
			continue
		}
		input := tu.Input
		if input == nil {
			input = map[string]interface{}{}
		}
		content = append(content, map[string]interface{}{
			"type":  "tool_use",
			"id":    tu.ToolUseID,
			"name":  tu.Name,
			"input": input,
		})
	}
	return content
}

// resolveFlushStopReason picks stop_reason for the flushed response.
// web_search-only rounds end as end_turn; client tool_use yields tool_use.
func resolveFlushStopReason(override string, toolUses []KiroToolUse, content []map[string]interface{}) string {
	if override != "" {
		return override
	}
	for _, c := range content {
		if c["type"] == "tool_use" {
			if name, _ := c["name"].(string); name != webSearchToolName {
				return "tool_use"
			}
		}
	}
	for _, tu := range toolUses {
		if tu.Name != webSearchToolName {
			return "tool_use"
		}
	}
	return "end_turn"
}

func estimateContentBlocksTokens(content []map[string]interface{}) int {
	total := 0
	for _, block := range content {
		switch block["type"] {
		case "text":
			if t, ok := block["text"].(string); ok {
				total += estimateApproxTokens(t)
			}
		case "tool_use", "server_tool_use":
			if n, ok := block["name"].(string); ok {
				total += estimateApproxTokens(n)
			}
			total += estimateJSONTokens(block["input"])
		case "web_search_tool_result":
			total += estimateJSONTokens(block["content"])
		}
	}
	if total < 1 {
		return 1
	}
	return total
}

func (h *Handler) renderWebSearchLoopJSON(
	w http.ResponseWriter,
	model string,
	content []map[string]interface{},
	stopReason string,
	inputTokens, outputTokens int,
) {
	messageID := "msg_" + strings.ReplaceAll(uuid.New().String(), "-", "")
	if len(messageID) > 4+24 {
		messageID = messageID[:4+24]
	}
	resp := map[string]interface{}{
		"id":            messageID,
		"type":          "message",
		"role":          "assistant",
		"model":         model,
		"content":       content,
		"stop_reason":   stopReason,
		"stop_sequence": nil,
		"usage": map[string]interface{}{
			"input_tokens":                inputTokens,
			"output_tokens":               outputTokens,
			"cache_creation_input_tokens": 0,
			"cache_read_input_tokens":     0,
		},
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(resp)
}

func (h *Handler) renderWebSearchLoopSSE(
	w http.ResponseWriter,
	model string,
	content []map[string]interface{},
	stopReason string,
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

	for index, block := range content {
		btype, _ := block["type"].(string)
		switch btype {
		case "text":
			text, _ := block["text"].(string)
			h.sendSSE(w, flusher, "content_block_start", map[string]interface{}{
				"type":          "content_block_start",
				"index":         index,
				"content_block": map[string]interface{}{"type": "text", "text": ""},
			})
			if text != "" {
				h.sendSSE(w, flusher, "content_block_delta", map[string]interface{}{
					"type":  "content_block_delta",
					"index": index,
					"delta": map[string]interface{}{"type": "text_delta", "text": text},
				})
			}
			h.sendSSE(w, flusher, "content_block_stop", map[string]interface{}{
				"type":  "content_block_stop",
				"index": index,
			})
		case "tool_use":
			id, _ := block["id"].(string)
			name, _ := block["name"].(string)
			input := block["input"]
			if input == nil {
				input = map[string]interface{}{}
			}
			partial, _ := json.Marshal(input)
			h.sendSSE(w, flusher, "content_block_start", map[string]interface{}{
				"type":  "content_block_start",
				"index": index,
				"content_block": map[string]interface{}{
					"type":  "tool_use",
					"id":    id,
					"name":  name,
					"input": map[string]interface{}{},
				},
			})
			h.sendSSE(w, flusher, "content_block_delta", map[string]interface{}{
				"type":  "content_block_delta",
				"index": index,
				"delta": map[string]interface{}{
					"type":         "input_json_delta",
					"partial_json": string(partial),
				},
			})
			h.sendSSE(w, flusher, "content_block_stop", map[string]interface{}{
				"type":  "content_block_stop",
				"index": index,
			})
		case "server_tool_use", "web_search_tool_result":
			h.sendSSE(w, flusher, "content_block_start", map[string]interface{}{
				"type":          "content_block_start",
				"index":         index,
				"content_block": block,
			})
			h.sendSSE(w, flusher, "content_block_stop", map[string]interface{}{
				"type":  "content_block_stop",
				"index": index,
			})
		}
	}

	h.sendSSE(w, flusher, "message_delta", map[string]interface{}{
		"type":  "message_delta",
		"delta": map[string]interface{}{"stop_reason": stopReason},
		"usage": map[string]interface{}{"output_tokens": outputTokens},
	})
	h.sendSSE(w, flusher, "message_stop", map[string]interface{}{
		"type": "message_stop",
	})
}
