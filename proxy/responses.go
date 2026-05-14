package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"kiro-go/config"
)

// OpenAI Responses API types

type ResponsesRequest struct {
	Model              string          `json:"model"`
	Input              interface{}     `json:"input"` // string or []InputItem
	MaxTokens          int             `json:"max_output_tokens,omitempty"`
	Temperature        float64         `json:"temperature,omitempty"`
	TopP               float64         `json:"top_p,omitempty"`
	Stream             bool            `json:"stream,omitempty"`
	Tools              json.RawMessage `json:"tools,omitempty"`
	Instructions       string          `json:"instructions,omitempty"`
	PreviousResponseID string          `json:"previous_response_id,omitempty"`
}

// responsesSessionStore stores response outputs for previous_response_id lookups
// This enables multi-turn tool calling: model returns function_call → client executes →
// client sends new request with previous_response_id + function_call_output in input
var responsesSessionStore = struct {
	sync.RWMutex
	sessions map[string][]interface{} // response_id → output items
}{
	sessions: make(map[string][]interface{}),
}

type InputItem struct {
	Type    string      `json:"type"`
	Role    string      `json:"role,omitempty"`
	Content interface{} `json:"content,omitempty"`
}

type ResponsesResponse struct {
	ID        string           `json:"id"`
	Object    string           `json:"object"`
	CreatedAt int64            `json:"created_at"`
	Model     string           `json:"model"`
	Output    []ResponseOutput `json:"output"`
	Usage     ResponsesUsage   `json:"usage"`
	Status    string           `json:"status"`
}

type ResponseOutput struct {
	Type    string             `json:"type"`
	ID      string             `json:"id"`
	Role    string             `json:"role,omitempty"`
	Content []ResponseContent  `json:"content,omitempty"`
	Status  string             `json:"status,omitempty"`
}

type ResponseContent struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

type ResponsesUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
	TotalTokens  int `json:"total_tokens"`
}

// handleOpenAIResponses handles /v1/responses endpoint
func (h *Handler) handleOpenAIResponses(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method Not Allowed", 405)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.sendOpenAIError(w, 400, "invalid_request_error", "Failed to read request body")
		return
	}

	var req ResponsesRequest
	if err := json.Unmarshal(body, &req); err != nil {
		h.sendOpenAIError(w, 400, "invalid_request_error", "Invalid JSON")
		return
	}

	// Debug: dump raw request
	os.WriteFile("/app/data/last_raw_request.json", body, 0644)

	if req.Model == "" {
		h.sendOpenAIError(w, 400, "invalid_request_error", "model is required")
		return
	}

	// Convert Responses API request to OpenAI chat format
	openaiReq := responsesToOpenAI(&req)

	account := h.pool.GetNext()
	if account == nil {
		h.sendOpenAIError(w, 503, "server_error", "No available accounts")
		return
	}

	if err := h.ensureValidToken(account); err != nil {
		h.sendOpenAIError(w, 503, "server_error", "Token refresh failed")
		return
	}

	// Parse model and thinking mode
	thinkingCfg := config.GetThinkingConfig()
	actualModel, thinking := ParseModelAndThinking(openaiReq.Model, thinkingCfg.Suffix)
	openaiReq.Model = actualModel
	estimatedInputTokens := estimateOpenAIRequestInputTokens(openaiReq)

	kiroPayload := OpenAIToKiro(openaiReq, thinking)

	// Truncate payload content if too large for Kiro API (max ~100KB content)
	truncateKiroPayloadContent(kiroPayload)

	if req.Stream {
		h.handleResponsesStream(w, account, kiroPayload, openaiReq.Model, thinking, estimatedInputTokens)
	} else {
		h.handleResponsesNonStream(w, account, kiroPayload, openaiReq.Model, thinking, estimatedInputTokens)
	}
}

// handleResponsesNonStream handles non-streaming responses API
func (h *Handler) handleResponsesNonStream(w http.ResponseWriter, account *config.Account, payload *KiroPayload, model string, thinking bool, estimatedInputTokens int) {
	var content string
	var reasoningContent string
	var inputTokens, outputTokens int
	var credits float64
	var realInputTokens int

	callback := &KiroStreamCallback{
		OnText: func(text string, isThinking bool) {
			if isThinking {
				reasoningContent += text
			} else {
				content += text
			}
		},
		OnToolUse:  func(tu KiroToolUse) {},
		OnComplete: func(inTok, outTok int) { inputTokens = inTok; outputTokens = outTok },
		OnError:    func(err error) { h.pool.RecordError(account.ID, strings.Contains(err.Error(), "429")) },
		OnCredits:  func(c float64) { credits = c },
		OnContextUsage: func(pct float64) {
			realInputTokens = int(pct * float64(getContextWindowSize(model)) / 100.0)
		},
	}

	err := CallKiroAPI(account, payload, callback)
	if err != nil {
		h.recordFailure()
		h.pool.RecordError(account.ID, strings.Contains(err.Error(), "429"))
		h.sendOpenAIError(w, 500, "server_error", err.Error())
		return
	}

	finalContent, extractedReasoning := extractThinkingFromContent(content)
	if thinking && reasoningContent == "" && extractedReasoning != "" {
		reasoningContent = extractedReasoning
	} else if !thinking {
		reasoningContent = ""
	}

	if realInputTokens > 0 {
		inputTokens = realInputTokens
	} else if inputTokens <= 0 {
		inputTokens = estimatedInputTokens
	}
	outputTokens = estimateOpenAIOutputTokens(finalContent, reasoningContent, nil)

	h.recordSuccess(inputTokens, outputTokens, credits)
	h.pool.RecordSuccess(account.ID)
	h.pool.UpdateStats(account.ID, inputTokens+outputTokens, credits)

	resp := buildResponsesResponse(finalContent, model, inputTokens, outputTokens)

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(resp)
}

// responsesSSEWriter manages SSE writing with sequence numbers for OpenAI Responses API
type responsesSSEWriter struct {
	w       http.ResponseWriter
	flusher http.Flusher
	seq     int
	mu      sync.Mutex
}

func newResponsesSSEWriter(w http.ResponseWriter, flusher http.Flusher) *responsesSSEWriter {
	return &responsesSSEWriter{w: w, flusher: flusher, seq: 0}
}

func (s *responsesSSEWriter) send(event string, data map[string]interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data["type"] = event
	data["sequence_number"] = s.seq
	s.seq++
	jsonData, _ := json.Marshal(data)
	fmt.Fprintf(s.w, "event: %s\ndata: %s\n\n", event, string(jsonData))
	s.flusher.Flush()
}

// handleResponsesStream handles streaming responses API with full OpenAI-compatible SSE format
func (h *Handler) handleResponsesStream(w http.ResponseWriter, account *config.Account, payload *KiroPayload, model string, thinking bool, estimatedInputTokens int) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		h.sendOpenAIError(w, 500, "server_error", "Streaming not supported")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(200)

	sse := newResponsesSSEWriter(w, flusher)

	respID := fmt.Sprintf("resp_%s", generateShortID())
	msgItemID := fmt.Sprintf("msg_%s", generateShortID())
	reasoningItemID := fmt.Sprintf("rs_%s", generateShortID())
	createdAt := time.Now().Unix()

	// Build base response object for lifecycle events
	buildResponseObj := func(status string, output []interface{}, usage interface{}) map[string]interface{} {
		resp := map[string]interface{}{
			"id":         respID,
			"object":     "response",
			"created_at": createdAt,
			"status":     status,
			"model":      model,
			"output":     output,
		}
		if usage != nil {
			resp["usage"] = usage
		} else {
			resp["usage"] = nil
		}
		return resp
	}

	// === response.created ===
	sse.send("response.created", map[string]interface{}{
		"response": buildResponseObj("in_progress", []interface{}{}, nil),
	})

	// === response.in_progress ===
	sse.send("response.in_progress", map[string]interface{}{
		"response": buildResponseObj("in_progress", []interface{}{}, nil),
	})

	// Track state for output items
	var outputIndex int
	var reasoningSent bool
	var textStarted bool
	var fullText strings.Builder
	var fullReasoning strings.Builder
	var toolCalls []map[string]interface{}

	// Helper: start reasoning output item
	startReasoning := func() {
		if reasoningSent {
			return
		}
		reasoningSent = true
		// response.output_item.added for reasoning
		sse.send("response.output_item.added", map[string]interface{}{
			"output_index": outputIndex,
			"item": map[string]interface{}{
				"id":      reasoningItemID,
				"type":    "reasoning",
				"status":  "in_progress",
				"summary": []interface{}{},
			},
		})
		// response.reasoning_summary_part.added
		sse.send("response.reasoning_summary_part.added", map[string]interface{}{
			"item_id":       reasoningItemID,
			"output_index":  outputIndex,
			"summary_index": 0,
			"part":          map[string]interface{}{"type": "summary_text", "text": ""},
		})
	}

	// Helper: finish reasoning output item
	finishReasoning := func() {
		if !reasoningSent {
			return
		}
		reasoningText := fullReasoning.String()
		// response.reasoning_summary_text.done
		sse.send("response.reasoning_summary_text.done", map[string]interface{}{
			"item_id":       reasoningItemID,
			"output_index":  outputIndex,
			"summary_index": 0,
			"text":          reasoningText,
		})
		// response.reasoning_summary_part.done
		sse.send("response.reasoning_summary_part.done", map[string]interface{}{
			"item_id":       reasoningItemID,
			"output_index":  outputIndex,
			"summary_index": 0,
			"part":          map[string]interface{}{"type": "summary_text", "text": reasoningText},
		})
		// response.output_item.done for reasoning
		sse.send("response.output_item.done", map[string]interface{}{
			"output_index": outputIndex,
			"item": map[string]interface{}{
				"id":     reasoningItemID,
				"type":   "reasoning",
				"status": "completed",
				"summary": []interface{}{
					map[string]interface{}{"type": "summary_text", "text": reasoningText},
				},
			},
		})
		outputIndex++
	}

	// Helper: start text message output item
	startTextMessage := func() {
		if textStarted {
			return
		}
		textStarted = true
		// If reasoning was active, finish it first
		finishReasoning()

		// response.output_item.added for message
		sse.send("response.output_item.added", map[string]interface{}{
			"output_index": outputIndex,
			"item": map[string]interface{}{
				"id":      msgItemID,
				"type":    "message",
				"role":    "assistant",
				"status":  "in_progress",
				"content": []interface{}{},
			},
		})
		// response.content_part.added
		sse.send("response.content_part.added", map[string]interface{}{
			"item_id":       msgItemID,
			"output_index":  outputIndex,
			"content_index": 0,
			"part":          map[string]interface{}{"type": "output_text", "text": ""},
		})
	}

	var inputTokens, outputTokens int
	var credits float64
	var realInputTokens int

	callback := &KiroStreamCallback{
		OnText: func(text string, isThinking bool) {
			if isThinking && thinking {
				startReasoning()
				fullReasoning.WriteString(text)
				// response.reasoning_summary_text.delta
				sse.send("response.reasoning_summary_text.delta", map[string]interface{}{
					"item_id":       reasoningItemID,
					"output_index":  0,
					"summary_index": 0,
					"delta":         text,
				})
			} else {
				startTextMessage()
				fullText.WriteString(text)
				// response.output_text.delta
				sse.send("response.output_text.delta", map[string]interface{}{
					"item_id":       msgItemID,
					"output_index":  outputIndex,
					"content_index": 0,
					"delta":         text,
				})
			}
		},
		OnToolUse: func(tu KiroToolUse) {
			// Finish reasoning if active
			if reasoningSent && !textStarted {
				finishReasoning()
			}
			toolCallItemID := fmt.Sprintf("fc_%s", generateShortID())
			toolOutputIndex := outputIndex
			outputIndex++

			// response.output_item.added for function_call
			sse.send("response.output_item.added", map[string]interface{}{
				"output_index": toolOutputIndex,
				"item": map[string]interface{}{
					"id":        toolCallItemID,
					"type":      "function_call",
					"status":    "in_progress",
					"call_id":   tu.ToolUseID,
					"name":      tu.Name,
					"arguments": "",
				},
			})

			// Marshal arguments
			argsJSON, _ := json.Marshal(tu.Input)
			argsStr := string(argsJSON)

			// response.function_call_arguments.delta (send full args as one delta)
			sse.send("response.function_call_arguments.delta", map[string]interface{}{
				"item_id":      toolCallItemID,
				"output_index": toolOutputIndex,
				"delta":        argsStr,
			})

			// response.function_call_arguments.done
			sse.send("response.function_call_arguments.done", map[string]interface{}{
				"item_id":      toolCallItemID,
				"output_index": toolOutputIndex,
				"name":         tu.Name,
				"arguments":    argsStr,
			})

			// response.output_item.done for function_call
			sse.send("response.output_item.done", map[string]interface{}{
				"output_index": toolOutputIndex,
				"item": map[string]interface{}{
					"id":        toolCallItemID,
					"type":      "function_call",
					"status":    "completed",
					"call_id":   tu.ToolUseID,
					"name":      tu.Name,
					"arguments": argsStr,
				},
			})

			toolCalls = append(toolCalls, map[string]interface{}{
				"id":        toolCallItemID,
				"type":      "function_call",
				"call_id":   tu.ToolUseID,
				"name":      tu.Name,
				"arguments": argsStr,
			})
		},
		OnComplete: func(inTok, outTok int) { inputTokens = inTok; outputTokens = outTok },
		OnError:    func(err error) { h.pool.RecordError(account.ID, strings.Contains(err.Error(), "429")) },
		OnCredits:  func(c float64) { credits = c },
		OnContextUsage: func(pct float64) {
			realInputTokens = int(pct * float64(getContextWindowSize(model)) / 100.0)
		},
	}

	err := CallKiroAPI(account, payload, callback)
	if err != nil {
		h.recordFailure()
		h.pool.RecordError(account.ID, strings.Contains(err.Error(), "429"))
		sse.send("error", map[string]interface{}{
			"code":    "server_error",
			"message": err.Error(),
		})
		return
	}

	// Finish text message if started
	if textStarted {
		finalText := fullText.String()
		// response.output_text.done
		sse.send("response.output_text.done", map[string]interface{}{
			"item_id":       msgItemID,
			"output_index":  outputIndex,
			"content_index": 0,
			"text":          finalText,
		})
		// response.content_part.done
		sse.send("response.content_part.done", map[string]interface{}{
			"item_id":       msgItemID,
			"output_index":  outputIndex,
			"content_index": 0,
			"part":          map[string]interface{}{"type": "output_text", "text": finalText},
		})
		// response.output_item.done for message
		sse.send("response.output_item.done", map[string]interface{}{
			"output_index": outputIndex,
			"item": map[string]interface{}{
				"id":     msgItemID,
				"type":   "message",
				"role":   "assistant",
				"status": "completed",
				"content": []interface{}{
					map[string]interface{}{"type": "output_text", "text": finalText},
				},
			},
		})
	} else if reasoningSent {
		// Only reasoning, no text - still finish reasoning
		finishReasoning()
	} else {
		// No content at all - send empty message
		startTextMessage()
		finalText := fullText.String()
		sse.send("response.output_text.done", map[string]interface{}{
			"item_id":       msgItemID,
			"output_index":  outputIndex,
			"content_index": 0,
			"text":          finalText,
		})
		sse.send("response.content_part.done", map[string]interface{}{
			"item_id":       msgItemID,
			"output_index":  outputIndex,
			"content_index": 0,
			"part":          map[string]interface{}{"type": "output_text", "text": finalText},
		})
		sse.send("response.output_item.done", map[string]interface{}{
			"output_index": outputIndex,
			"item": map[string]interface{}{
				"id":     msgItemID,
				"type":   "message",
				"role":   "assistant",
				"status": "completed",
				"content": []interface{}{
					map[string]interface{}{"type": "output_text", "text": finalText},
				},
			},
		})
	}

	// Calculate final tokens
	if realInputTokens > 0 {
		inputTokens = realInputTokens
	} else if inputTokens <= 0 {
		inputTokens = estimatedInputTokens
	}
	// Estimate output tokens from actual generated content
	// Chinese: ~1.5 chars/token, English: ~4 chars/token, Code: ~3 chars/token
	if outputTokens <= 0 {
		outputText := fullText.String() + fullReasoning.String()
		for _, tc := range toolCalls {
			if args, ok := tc["arguments"].(string); ok {
				outputText += args
			}
		}
		outputTokens = estimateTokensByCharType(outputText)
		if outputTokens < 1 {
			outputTokens = 1
		}
	}

	h.recordSuccess(inputTokens, outputTokens, credits)
	h.pool.RecordSuccess(account.ID)
	h.pool.UpdateStats(account.ID, inputTokens+outputTokens, credits)

	// Build final output array for response.completed
	var finalOutput []interface{}
	if reasoningSent {
		finalOutput = append(finalOutput, map[string]interface{}{
			"id":     reasoningItemID,
			"type":   "reasoning",
			"status": "completed",
			"summary": []interface{}{
				map[string]interface{}{"type": "summary_text", "text": fullReasoning.String()},
			},
		})
	}
	for _, tc := range toolCalls {
		finalOutput = append(finalOutput, tc)
	}
	if textStarted {
		finalOutput = append(finalOutput, map[string]interface{}{
			"id":     msgItemID,
			"type":   "message",
			"role":   "assistant",
			"status": "completed",
			"content": []interface{}{
				map[string]interface{}{"type": "output_text", "text": fullText.String()},
			},
		})
	}

	// === response.completed ===
	sse.send("response.completed", map[string]interface{}{
		"response": map[string]interface{}{
			"id":         respID,
			"object":     "response",
			"created_at": createdAt,
			"status":     "completed",
			"model":      model,
			"output":     finalOutput,
			"usage": map[string]interface{}{
				"input_tokens":  inputTokens,
				"output_tokens": outputTokens,
				"total_tokens":  inputTokens + outputTokens,
			},
		},
	})

	// Save session for previous_response_id support (enables multi-turn tool calling)
	if len(finalOutput) > 0 {
		responsesSessionStore.Lock()
		responsesSessionStore.sessions[respID] = finalOutput
		// Limit store size to prevent memory leak (keep last 100 sessions)
		if len(responsesSessionStore.sessions) > 100 {
			for k := range responsesSessionStore.sessions {
				delete(responsesSessionStore.sessions, k)
				break
			}
		}
		responsesSessionStore.Unlock()
	}
}

// generateShortID generates a short unique ID
func generateShortID() string {
	return fmt.Sprintf("%x", time.Now().UnixNano()&0xFFFFFFFFFF)
}

// responsesToOpenAI converts Responses API request to OpenAI chat format
func responsesToOpenAI(req *ResponsesRequest) *OpenAIRequest {
	var messages []OpenAIMessage

	// Add instructions as system message
	if req.Instructions != "" {
		messages = append(messages, OpenAIMessage{
			Role:    "system",
			Content: req.Instructions,
		})
	}

	// Handle previous_response_id: inject previous response output into conversation
	// This enables multi-turn tool calling (model calls tool → client executes → sends result back)
	if req.PreviousResponseID != "" {
		responsesSessionStore.RLock()
		prevOutput, exists := responsesSessionStore.sessions[req.PreviousResponseID]
		responsesSessionStore.RUnlock()

		if exists {
			// Convert previous output items to assistant/tool messages
			for _, rawItem := range prevOutput {
				item, ok := rawItem.(map[string]interface{})
				if !ok {
					continue
				}
				itemType, _ := item["type"].(string)
				switch itemType {
				case "message":
					// Previous assistant text response
					if content, ok := item["content"].([]interface{}); ok {
						var textParts []string
						for _, c := range content {
							if cm, ok := c.(map[string]interface{}); ok {
								if text, ok := cm["text"].(string); ok {
									textParts = append(textParts, text)
								}
							}
						}
						if len(textParts) > 0 {
							messages = append(messages, OpenAIMessage{
								Role:    "assistant",
								Content: strings.Join(textParts, "\n"),
							})
						}
					}
				case "function_call":
					// Previous tool call by assistant
					name, _ := item["name"].(string)
					callID, _ := item["call_id"].(string)
					args, _ := item["arguments"].(string)
					if callID == "" {
						callID, _ = item["id"].(string)
					}
					messages = append(messages, OpenAIMessage{
						Role:    "assistant",
						Content: nil,
						ToolCalls: []ToolCall{{
							ID:   callID,
							Type: "function",
							Function: struct {
								Name      string `json:"name"`
								Arguments string `json:"arguments"`
							}{Name: name, Arguments: args},
						}},
					})
				}
			}
		}
	}

	// Parse input
	switch input := req.Input.(type) {
	case string:
		// Simple string input
		messages = append(messages, OpenAIMessage{
			Role:    "user",
			Content: input,
		})
	case []interface{}:
		// Array of input items
		for _, item := range input {
			itemMap, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			itemType, _ := itemMap["type"].(string)
			switch itemType {
			case "message":
				role, _ := itemMap["role"].(string)
				content := itemMap["content"]
				// Map "developer" role to "system" (OpenAI Responses API uses developer for system instructions)
				if role == "developer" {
					role = "system"
				}
				// Validate role - only allow standard OpenAI Chat roles
				if role != "system" && role != "user" && role != "assistant" && role != "tool" {
					role = "user"
				}
				// content can be string or array
				switch c := content.(type) {
				case string:
					if c != "" {
						messages = append(messages, OpenAIMessage{Role: role, Content: c})
					}
				case []interface{}:
					// Array of content parts (input_text, text, output_text)
					var textParts []string
					for _, part := range c {
						partMap, ok := part.(map[string]interface{})
						if !ok {
							continue
						}
						pt, _ := partMap["type"].(string)
						if pt == "input_text" || pt == "text" || pt == "output_text" {
							if text, ok := partMap["text"].(string); ok && text != "" {
								textParts = append(textParts, text)
							}
						}
					}
					if len(textParts) > 0 {
						messages = append(messages, OpenAIMessage{Role: role, Content: strings.Join(textParts, "\n")})
					}
				}
			case "function_call":
				// Convert function_call to assistant message with tool_calls
				name, _ := itemMap["name"].(string)
				callID, _ := itemMap["call_id"].(string)
				argsRaw := itemMap["arguments"]
				var argsStr string
				switch a := argsRaw.(type) {
				case string:
					argsStr = a
				default:
					if a != nil {
						argsBytes, _ := json.Marshal(a)
						argsStr = string(argsBytes)
					}
				}
				if callID != "" && name != "" {
					messages = append(messages, OpenAIMessage{
						Role:    "assistant",
						Content: nil,
						ToolCalls: []ToolCall{{
							ID:   callID,
							Type: "function",
							Function: struct {
								Name      string `json:"name"`
								Arguments string `json:"arguments"`
							}{Name: name, Arguments: argsStr},
						}},
					})
				}
			case "function_call_output":
				// Tool result - convert to tool role message
				callID, _ := itemMap["call_id"].(string)
				output, _ := itemMap["output"].(string)
				if callID != "" {
					messages = append(messages, OpenAIMessage{Role: "tool", Content: output, ToolCallID: callID})
				}
			default:
				// Treat as user message if has content
				if content, ok := itemMap["content"].(string); ok {
					messages = append(messages, OpenAIMessage{Role: "user", Content: content})
				}
			}
		}
	}

	// Deduplicate consecutive identical messages with the same role
	// (Codex CLI sends repeated developer/system instructions and AGENTS.md)
	if len(messages) > 1 {
		var deduped []OpenAIMessage
		for i, m := range messages {
			contentStr, _ := m.Content.(string)
			if i > 0 {
				prev := deduped[len(deduped)-1]
				prevContentStr, _ := prev.Content.(string)
				if prev.Role == m.Role && prevContentStr == contentStr {
					continue
				}
			}
			deduped = append(deduped, m)
		}
		messages = deduped
	}

	// Merge consecutive system messages into one (Kiro API expects single system prompt)
	if len(messages) > 1 {
		var merged []OpenAIMessage
		for _, m := range messages {
			if m.Role == "system" && len(merged) > 0 && merged[len(merged)-1].Role == "system" {
				prevContent, _ := merged[len(merged)-1].Content.(string)
				currContent, _ := m.Content.(string)
				merged[len(merged)-1].Content = prevContent + "\n\n" + currContent
			} else {
				merged = append(merged, m)
			}
		}
		messages = merged
	}

	// Fallback if no messages parsed
	if len(messages) == 0 {
		messages = append(messages, OpenAIMessage{Role: "user", Content: "hi"})
	}

	maxTokens := req.MaxTokens
	if maxTokens == 0 {
		maxTokens = 4096
	}

	// Convert Responses API tools to OpenAI Chat Completions tools format
	// Responses API: {"type":"function","name":"x","description":"y","parameters":{...}}
	// Chat Completions: {"type":"function","function":{"name":"x","description":"y","parameters":{...}}}
	var tools []OpenAITool
	if len(req.Tools) > 0 {
		var rawTools []map[string]interface{}
		if err := json.Unmarshal(req.Tools, &rawTools); err == nil {
			for _, rt := range rawTools {
				toolType, _ := rt["type"].(string)
				if toolType != "function" {
					continue
				}
				var tool OpenAITool
				tool.Type = "function"
				// Responses API format: name/description/parameters at top level
				if name, ok := rt["name"].(string); ok {
					tool.Function.Name = name
				}
				if desc, ok := rt["description"].(string); ok {
					tool.Function.Description = desc
				}
				if params, ok := rt["parameters"]; ok {
					tool.Function.Parameters = params
				}
				// Also support nested "function" field (Chat Completions format)
				if fn, ok := rt["function"].(map[string]interface{}); ok {
					if name, ok := fn["name"].(string); ok {
						tool.Function.Name = name
					}
					if desc, ok := fn["description"].(string); ok {
						tool.Function.Description = desc
					}
					if params, ok := fn["parameters"]; ok {
						tool.Function.Parameters = params
					}
				}
				// Skip tools with empty name
				if tool.Function.Name == "" {
					continue
				}
				tools = append(tools, tool)
			}
		}
	}

	return &OpenAIRequest{
		Model:       req.Model,
		Messages:    messages,
		MaxTokens:   maxTokens,
		Temperature: req.Temperature,
		TopP:        req.TopP,
		Stream:      req.Stream,
		Tools:       tools,
	}
}

func buildResponsesResponse(content, model string, inputTokens, outputTokens int) *ResponsesResponse {
	return &ResponsesResponse{
		ID:        fmt.Sprintf("resp_%s", generateShortID()),
		Object:    "response",
		CreatedAt: time.Now().Unix(),
		Model:     model,
		Status:    "completed",
		Output: []ResponseOutput{
			{
				Type: "message",
				ID:   fmt.Sprintf("msg_%s", generateShortID()),
				Role: "assistant",
				Content: []ResponseContent{
					{Type: "output_text", Text: content},
				},
				Status: "completed",
			},
		},
		Usage: ResponsesUsage{
			InputTokens:  inputTokens,
			OutputTokens: outputTokens,
			TotalTokens:  inputTokens + outputTokens,
		},
	}
}

// truncateKiroPayloadContent cleans up the KiroPayload before sending to Kiro API.
// Fixes: invalid tools, unpaired tool_use/tool_result in history, and oversized payloads.
func truncateKiroPayloadContent(payload *KiroPayload) {
	// 0. Fix history: ensure user/assistant alternation and deduplicate
	// Kiro API requires history to alternate between user and assistant messages.
	payload.ConversationState.History = fixHistoryAlternation(payload.ConversationState.History)

	// 0b. If history's last entry is user, merge it into currentMessage
	// (Kiro API: currentMessage is the new user input, history must end with assistant)
	if len(payload.ConversationState.History) > 0 {
		last := payload.ConversationState.History[len(payload.ConversationState.History)-1]
		if last.UserInputMessage != nil {
			// Last history entry is user - merge into current message
			currentContent := payload.ConversationState.CurrentMessage.UserInputMessage.Content
			lastContent := last.UserInputMessage.Content
			if currentContent != "" && currentContent != "." {
				payload.ConversationState.CurrentMessage.UserInputMessage.Content = lastContent + "\n\n" + currentContent
			} else {
				payload.ConversationState.CurrentMessage.UserInputMessage.Content = lastContent
			}
			// Remove the last user entry from history
			payload.ConversationState.History = payload.ConversationState.History[:len(payload.ConversationState.History)-1]
		}
	}

	// 1. Remove invalid tools (empty name or null schema) - Kiro API rejects these
	// Also limit to max 30 tools and sanitize tool names (Kiro API requires camelCase)
	if ctx := payload.ConversationState.CurrentMessage.UserInputMessage.UserInputMessageContext; ctx != nil {
		var validTools []KiroToolWrapper
		for _, t := range ctx.Tools {
			if t.ToolSpecification.Name != "" && t.ToolSpecification.InputSchema.JSON != nil {
				// Sanitize name: convert snake_case/kebab-case to camelCase
				t.ToolSpecification.Name = sanitizeKiroToolName(t.ToolSpecification.Name)
				// Ensure description is non-empty (Kiro API may require it)
				if t.ToolSpecification.Description == "" {
					t.ToolSpecification.Description = "Tool function"
				}
				// Limit description length to avoid Kiro API rejection
				if len(t.ToolSpecification.Description) > 1024 {
					t.ToolSpecification.Description = t.ToolSpecification.Description[:1024]
				}
				validTools = append(validTools, t)
			}
		}
		// Kiro API has a tool count limit - keep only first 20
		if len(validTools) > 20 {
			validTools = validTools[:20]
		}
		ctx.Tools = validTools
		// Remove orphan toolResults (no matching toolUse in history = Kiro API 400)
		if len(ctx.ToolResults) > 0 {
			validToolUseIDs := make(map[string]bool)
			for i := len(payload.ConversationState.History) - 1; i >= 0; i-- {
				entry := payload.ConversationState.History[i]
				if entry.AssistantResponseMessage != nil {
					for _, tu := range entry.AssistantResponseMessage.ToolUses {
						validToolUseIDs[tu.ToolUseID] = true
					}
					break
				}
			}
			var validResults []KiroToolResult
			for _, tr := range ctx.ToolResults {
				if validToolUseIDs[tr.ToolUseID] {
					validResults = append(validResults, tr)
				}
			}
			ctx.ToolResults = validResults
		}
		if len(ctx.Tools) == 0 && len(ctx.ToolResults) == 0 {
			payload.ConversationState.CurrentMessage.UserInputMessage.UserInputMessageContext = nil
		}
	}

	// 1b. If history has only user messages (no assistant), clear it
	// Kiro API requires alternating user/assistant in history
	hasAssistant := false
	for _, h := range payload.ConversationState.History {
		if h.AssistantResponseMessage != nil {
			hasAssistant = true
			break
		}
	}
	if !hasAssistant {
		payload.ConversationState.History = nil
	}

	// 2. Fix tool_use/tool_result pairing in history
	// Kiro API requires: every tool_result must have a matching tool_use in the preceding assistant message.
	// Strategy: collect all tool_use IDs from assistant messages, then verify tool_results reference valid IDs.
	// Also ensure: if an assistant message has tool_uses, the next user message must have matching tool_results.
	payload.ConversationState.History = fixToolPairingInHistory(payload.ConversationState.History)

	// 3. Ensure currentMessage tool_results have matching tool_uses in the last assistant history entry
	if ctx := payload.ConversationState.CurrentMessage.UserInputMessage.UserInputMessageContext; ctx != nil && len(ctx.ToolResults) > 0 {
		// Find the last assistant message in history to get valid tool_use IDs
		validToolUseIDs := make(map[string]bool)
		for i := len(payload.ConversationState.History) - 1; i >= 0; i-- {
			h := payload.ConversationState.History[i]
			if h.AssistantResponseMessage != nil {
				for _, tu := range h.AssistantResponseMessage.ToolUses {
					validToolUseIDs[tu.ToolUseID] = true
				}
				break
			}
		}

		// Filter tool_results to only those with matching tool_use IDs
		// If no valid IDs found, clear all tool_results (orphaned tool_results break the request)
		var validResults []KiroToolResult
		for _, tr := range ctx.ToolResults {
			if validToolUseIDs[tr.ToolUseID] {
				validResults = append(validResults, tr)
			}
		}
		ctx.ToolResults = validResults

		// If no valid tool results remain and no tools, clear context
		if len(ctx.ToolResults) == 0 && len(ctx.Tools) == 0 {
			payload.ConversationState.CurrentMessage.UserInputMessage.UserInputMessageContext = nil
		}
	}

	// 4. Trim history if total payload exceeds Kiro API size limit (~450KB)
	const maxPayloadBytes = 450 * 1024
	for len(payload.ConversationState.History) > 0 {
		data, _ := json.Marshal(payload)
		if len(data) <= maxPayloadBytes {
			break
		}
		// Remove oldest 2 entries (to maintain user/assistant pairing)
		if len(payload.ConversationState.History) >= 2 {
			payload.ConversationState.History = payload.ConversationState.History[2:]
		} else {
			payload.ConversationState.History = payload.ConversationState.History[1:]
		}
	}

	// After trimming, re-validate tool pairing (trimming might break pairs)
	payload.ConversationState.History = fixToolPairingInHistory(payload.ConversationState.History)
}

// fixToolPairingInHistory ensures tool_use and tool_result are properly paired in history.
// Kiro API rejects requests where tool_result references a non-existent tool_use.
func fixToolPairingInHistory(history []KiroHistoryMessage) []KiroHistoryMessage {
	if len(history) == 0 {
		return history
	}

	// Pass 1: Collect all tool_use IDs from assistant messages
	toolUseIDs := make(map[string]bool)
	for _, h := range history {
		if h.AssistantResponseMessage != nil {
			for _, tu := range h.AssistantResponseMessage.ToolUses {
				if tu.ToolUseID != "" {
					toolUseIDs[tu.ToolUseID] = true
				}
			}
		}
	}

	// Pass 2: For each user message with tool_results, verify they reference valid tool_use IDs
	for i := range history {
		h := &history[i]
		if h.UserInputMessage == nil || h.UserInputMessage.UserInputMessageContext == nil {
			continue
		}
		ctx := h.UserInputMessage.UserInputMessageContext
		if len(ctx.ToolResults) == 0 {
			continue
		}

		var validResults []KiroToolResult
		for _, tr := range ctx.ToolResults {
			if tr.ToolUseID != "" && toolUseIDs[tr.ToolUseID] {
				validResults = append(validResults, tr)
			}
		}
		ctx.ToolResults = validResults

		// If tool_results were removed and content is empty, add minimal content
		if len(ctx.ToolResults) == 0 && len(ctx.Tools) == 0 {
			h.UserInputMessage.UserInputMessageContext = nil
			if strings.TrimSpace(h.UserInputMessage.Content) == "" {
				h.UserInputMessage.Content = "."
			}
		}
	}

	// Pass 3: For each assistant message with tool_uses, verify the next user message has matching tool_results
	for i := 0; i < len(history)-1; i++ {
		h := history[i]
		if h.AssistantResponseMessage == nil || len(h.AssistantResponseMessage.ToolUses) == 0 {
			continue
		}

		// Check if next message is a user message with tool_results
		next := &history[i+1]
		if next.UserInputMessage == nil {
			// Next is not a user message - remove tool_uses from this assistant message
			history[i].AssistantResponseMessage.ToolUses = nil
			continue
		}

		ctx := next.UserInputMessage.UserInputMessageContext
		if ctx == nil || len(ctx.ToolResults) == 0 {
			// Next user message has no tool_results - remove tool_uses from assistant
			history[i].AssistantResponseMessage.ToolUses = nil
			continue
		}

		// Verify each tool_use has a matching tool_result
		resultIDs := make(map[string]bool)
		for _, tr := range ctx.ToolResults {
			resultIDs[tr.ToolUseID] = true
		}

		var pairedToolUses []KiroToolUse
		for _, tu := range h.AssistantResponseMessage.ToolUses {
			if resultIDs[tu.ToolUseID] {
				pairedToolUses = append(pairedToolUses, tu)
			}
		}
		history[i].AssistantResponseMessage.ToolUses = pairedToolUses
	}

	// Pass 4: Remove empty history entries that might have been created
	var cleaned []KiroHistoryMessage
	for _, h := range history {
		if h.UserInputMessage != nil && strings.TrimSpace(h.UserInputMessage.Content) == "" &&
			(h.UserInputMessage.UserInputMessageContext == nil ||
				(len(h.UserInputMessage.UserInputMessageContext.ToolResults) == 0 &&
					len(h.UserInputMessage.UserInputMessageContext.Tools) == 0)) {
			continue
		}
		cleaned = append(cleaned, h)
	}

	return cleaned
}



// fixHistoryAlternation ensures history alternates between user and assistant messages.
// Kiro API rejects history with consecutive messages of the same role.
// This function:
// 1. Removes duplicate consecutive user messages (keeps only the last one in a run)
// 2. Ensures the pattern is user -> assistant -> user -> assistant
// 3. Removes leading assistant messages (history must start with user)
func fixHistoryAlternation(history []KiroHistoryMessage) []KiroHistoryMessage {
	if len(history) == 0 {
		return history
	}

	// Step 1: Collapse consecutive user messages - keep only the last one in each run
	// (Codex CLI sends repeated AGENTS.md as separate user messages)
	var collapsed []KiroHistoryMessage
	for i := 0; i < len(history); i++ {
		isUser := history[i].UserInputMessage != nil
		if !isUser {
			// Assistant message - keep as-is
			collapsed = append(collapsed, history[i])
			continue
		}

		// User message - check if next is also user
		lastUserInRun := i
		for j := i + 1; j < len(history); j++ {
			if history[j].UserInputMessage != nil {
				lastUserInRun = j
			} else {
				break
			}
		}

		// Only keep the last user message in the consecutive run
		collapsed = append(collapsed, history[lastUserInRun])
		i = lastUserInRun
	}

	// Step 2: Remove leading assistant messages (history must start with user)
	for len(collapsed) > 0 && collapsed[0].AssistantResponseMessage != nil {
		collapsed = collapsed[1:]
	}

	// Step 3: Ensure strict alternation - if two of the same type are adjacent, remove the first
	var alternated []KiroHistoryMessage
	for i, h := range collapsed {
		if i == 0 {
			alternated = append(alternated, h)
			continue
		}
		prevIsUser := alternated[len(alternated)-1].UserInputMessage != nil
		currIsUser := h.UserInputMessage != nil

		if prevIsUser == currIsUser {
			// Same type consecutive - replace previous with current (keep the later one)
			alternated[len(alternated)-1] = h
		} else {
			alternated = append(alternated, h)
		}
	}

	return alternated
}

// sanitizeKiroToolName converts a tool name to camelCase format that Kiro API accepts.
// Kiro tool names must be camelCase (no underscores or dashes).
// Examples:
//   list_mcp_resources -> listMcpResources
//   mcp__playwright__browser_click -> mcpPlaywrightBrowserClick
//   mcp__aris-claude-review__review -> mcpArisClaudeReviewReview
func sanitizeKiroToolName(name string) string {
	// Split on underscores and dashes
	parts := strings.FieldsFunc(name, func(r rune) bool {
		return r == '_' || r == '-'
	})
	if len(parts) == 0 {
		return "tool"
	}
	var b strings.Builder
	for i, part := range parts {
		if part == "" {
			continue
		}
		if i == 0 {
			b.WriteString(strings.ToLower(part[:1]) + part[1:])
		} else {
			b.WriteString(strings.ToUpper(part[:1]) + part[1:])
		}
	}
	result := b.String()
	if result == "" {
		return "tool"
	}
	// Limit length to 64 characters
	if len(result) > 64 {
		result = result[:64]
	}
	return result
}

// estimateTokensByCharType estimates token count by classifying characters into
// Chinese (~1.5 chars/token), English (~4 chars/token), and Code (~3 chars/token).
func estimateTokensByCharType(text string) int {
	var chineseChars, englishChars, codeChars int

	for _, r := range text {
		if r >= 0x4E00 && r <= 0x9FFF || r >= 0x3400 && r <= 0x4DBF || r >= 0xF900 && r <= 0xFAFF {
			// CJK Unified Ideographs (Chinese/Japanese/Korean)
			chineseChars++
		} else if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == ' ' {
			// English letters and spaces
			englishChars++
		} else if r == '{' || r == '}' || r == '(' || r == ')' || r == '[' || r == ']' ||
			r == ';' || r == ':' || r == '.' || r == ',' || r == '=' || r == '+' || r == '-' ||
			r == '*' || r == '/' || r == '<' || r == '>' || r == '_' || r == '"' || r == '\'' ||
			r == '!' || r == '&' || r == '|' || r == '\t' || r == '\n' {
			// Code-like punctuation and whitespace
			codeChars++
		} else if r >= '0' && r <= '9' {
			codeChars++
		} else {
			// Other (treat as English)
			englishChars++
		}
	}

	// Calculate tokens for each type
	chineseTokens := float64(chineseChars) / 1.2
	englishTokens := float64(englishChars) / 3.0
	codeTokens := float64(codeChars) / 2.0

	return int(chineseTokens + englishTokens + codeTokens)
}
