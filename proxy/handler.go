package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"kiro-api-proxy/auth"
	"kiro-api-proxy/config"
	"kiro-api-proxy/pool"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Handler HTTP 处理器
type Handler struct {
	pool *pool.AccountPool
	// 运行时统计
	totalRequests   int
	successRequests int
	failedRequests  int
	totalTokens     int
	totalCredits    float64
	startTime       int64
	stopRefresh     chan struct{}
}

func NewHandler() *Handler {
	totalReq, successReq, failedReq, totalTokens, totalCredits := config.GetStats()
	h := &Handler{
		pool:            pool.GetPool(),
		totalRequests:   totalReq,
		successRequests: successReq,
		failedRequests:  failedReq,
		totalTokens:     totalTokens,
		totalCredits:    totalCredits,
		startTime:       time.Now().Unix(),
		stopRefresh:     make(chan struct{}),
	}
	// 启动后台刷新
	go h.backgroundRefresh()
	return h
}

// backgroundRefresh 后台定时刷新账户信息
func (h *Handler) backgroundRefresh() {
	ticker := time.NewTicker(30 * time.Minute) // 每 30 分钟刷新一次
	defer ticker.Stop()

	// 启动时延迟 10 秒后执行一次
	time.Sleep(10 * time.Second)
	h.refreshAllAccounts()

	for {
		select {
		case <-ticker.C:
			h.refreshAllAccounts()
		case <-h.stopRefresh:
			return
		}
	}
}

// refreshAllAccounts 刷新所有账户信息
func (h *Handler) refreshAllAccounts() {
	accounts := config.GetAccounts()
	for i := range accounts {
		account := &accounts[i]
		if !account.Enabled || account.AccessToken == "" {
			continue
		}

		// 检查 token 是否需要刷新
		if account.ExpiresAt > 0 && time.Now().Unix() > account.ExpiresAt-300 {
			newAccessToken, newRefreshToken, newExpiresAt, err := auth.RefreshToken(account)
			if err != nil {
				fmt.Printf("[BackgroundRefresh] Token refresh failed for %s: %v\n", account.Email, err)
				continue
			}
			account.AccessToken = newAccessToken
			if newRefreshToken != "" {
				account.RefreshToken = newRefreshToken
			}
			account.ExpiresAt = newExpiresAt
			config.UpdateAccountToken(account.ID, newAccessToken, newRefreshToken, newExpiresAt)
			h.pool.UpdateToken(account.ID, newAccessToken, newRefreshToken, newExpiresAt)
		}

		// 刷新账户信息
		info, err := RefreshAccountInfo(account)
		if err != nil {
			fmt.Printf("[BackgroundRefresh] Failed to refresh %s: %v\n", account.Email, err)
			continue
		}

		config.UpdateAccountInfo(account.ID, *info)
		fmt.Printf("[BackgroundRefresh] Refreshed %s: %s %.1f/%.1f\n", account.Email, info.SubscriptionType, info.UsageCurrent, info.UsageLimit)
	}
	h.pool.Reload()
}

// validateApiKey 验证 API Key
func (h *Handler) validateApiKey(r *http.Request) bool {
	if !config.IsApiKeyRequired() {
		return true
	}
	
	expectedKey := config.GetApiKey()
	if expectedKey == "" {
		return true
	}

	// 从 Authorization 头或 X-Api-Key 头获取
	authHeader := r.Header.Get("Authorization")
	apiKeyHeader := r.Header.Get("X-Api-Key")

	var providedKey string
	if strings.HasPrefix(authHeader, "Bearer ") {
		providedKey = strings.TrimPrefix(authHeader, "Bearer ")
	} else if apiKeyHeader != "" {
		providedKey = apiKeyHeader
	}

	return providedKey == expectedKey
}

// ServeHTTP 路由分发
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	// CORS - 完整的头部支持
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Api-Key, anthropic-version, anthropic-beta, x-api-key, x-stainless-os, x-stainless-lang, x-stainless-package-version, x-stainless-runtime, x-stainless-runtime-version, x-stainless-arch")
	w.Header().Set("Access-Control-Expose-Headers", "x-request-id, x-ratelimit-limit-requests, x-ratelimit-limit-tokens, x-ratelimit-remaining-requests, x-ratelimit-remaining-tokens, x-ratelimit-reset-requests, x-ratelimit-reset-tokens")

	if r.Method == "OPTIONS" {
		w.WriteHeader(204)
		return
	}

	// 路由
	switch {
	// API 端点（需要验证 API Key）
	case path == "/v1/messages" || path == "/messages" || path == "/anthropic/v1/messages":
		if !h.validateApiKey(r) {
			h.sendClaudeError(w, 401, "authentication_error", "Invalid or missing API key")
			return
		}
		h.handleClaudeMessages(w, r)
	case path == "/v1/messages/count_tokens" || path == "/messages/count_tokens":
		if !h.validateApiKey(r) {
			h.sendClaudeError(w, 401, "authentication_error", "Invalid or missing API key")
			return
		}
		h.handleCountTokens(w, r)
	case path == "/v1/chat/completions" || path == "/chat/completions":
		if !h.validateApiKey(r) {
			h.sendOpenAIError(w, 401, "authentication_error", "Invalid or missing API key")
			return
		}
		h.handleOpenAIChat(w, r)
	case path == "/v1/models" || path == "/models":
		h.handleModels(w, r)
	case path == "/api/event_logging/batch":
		// Claude Code 遥测端点 - 直接返回 200 OK
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Write([]byte(`{"status":"ok"}`))

	// 管理端点
	case path == "/admin" || path == "/admin/":
		h.serveAdminPage(w, r)
	case strings.HasPrefix(path, "/admin/api/"):
		h.handleAdminAPI(w, r)
	case strings.HasPrefix(path, "/admin/"):
		h.serveStaticFile(w, r)

	// 健康检查
	case path == "/health" || path == "/":
		h.handleHealth(w, r)

	default:
		http.Error(w, "Not Found", 404)
	}
}

// handleHealth 健康检查
func (h *Handler) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":          "ok",
		"accounts":        h.pool.Count(),
		"available":       h.pool.AvailableCount(),
		"totalRequests":   h.totalRequests,
		"successRequests": h.successRequests,
		"failedRequests":  h.failedRequests,
		"totalTokens":     h.totalTokens,
		"totalCredits":    h.totalCredits,
		"uptime":          time.Now().Unix() - h.startTime,
	})
}

// handleModels 模型列表
func (h *Handler) handleModels(w http.ResponseWriter, r *http.Request) {
	models := []map[string]interface{}{
		{"id": "claude-sonnet-4.5", "object": "model", "owned_by": "anthropic"},
		{"id": "claude-sonnet-4.5-thinking", "object": "model", "owned_by": "anthropic"},
		{"id": "claude-sonnet-4", "object": "model", "owned_by": "anthropic"},
		{"id": "claude-sonnet-4-thinking", "object": "model", "owned_by": "anthropic"},
		{"id": "claude-haiku-4.5", "object": "model", "owned_by": "anthropic"},
		{"id": "claude-haiku-4.5-thinking", "object": "model", "owned_by": "anthropic"},
		{"id": "claude-opus-4.5", "object": "model", "owned_by": "anthropic"},
		{"id": "claude-opus-4.5-thinking", "object": "model", "owned_by": "anthropic"},
		{"id": "auto", "object": "model", "owned_by": "kiro-api"},
		{"id": "gpt-4o", "object": "model", "owned_by": "kiro-proxy"},
		{"id": "gpt-4", "object": "model", "owned_by": "kiro-proxy"},
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"object": "list",
		"data":   models,
	})
}

// handleCountTokens Token 计数（Claude Code 会调用）
func (h *Handler) handleCountTokens(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method Not Allowed", 405)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.sendClaudeError(w, 400, "invalid_request_error", "Failed to read request body")
		return
	}

	var req struct {
		Messages []struct {
			Role    string      `json:"role"`
			Content interface{} `json:"content"`
		} `json:"messages"`
		System interface{} `json:"system"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		h.sendClaudeError(w, 400, "invalid_request_error", "Invalid JSON")
		return
	}

	// 简单估算 token 数量（每 4 个字符约 1 个 token）
	var totalChars int
	for _, msg := range req.Messages {
		switch content := msg.Content.(type) {
		case string:
			totalChars += len(content)
		case []interface{}:
			for _, part := range content {
				if p, ok := part.(map[string]interface{}); ok {
					if text, ok := p["text"].(string); ok {
						totalChars += len(text)
					}
				}
			}
		}
	}

	// 系统提示
	switch system := req.System.(type) {
	case string:
		totalChars += len(system)
	case []interface{}:
		for _, part := range system {
			if p, ok := part.(map[string]interface{}); ok {
				if text, ok := p["text"].(string); ok {
					totalChars += len(text)
				}
			}
		}
	}

	estimatedTokens := (totalChars + 3) / 4 // 向上取整
	if estimatedTokens < 1 {
		estimatedTokens = 1
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(map[string]int{"input_tokens": estimatedTokens})
}

// handleClaudeMessages Claude API 处理
func (h *Handler) handleClaudeMessages(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method Not Allowed", 405)
		return
	}

	// 读取请求
	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.sendClaudeError(w, 400, "invalid_request_error", "Failed to read request body")
		return
	}

	var req ClaudeRequest
	if err := json.Unmarshal(body, &req); err != nil {
		h.sendClaudeError(w, 400, "invalid_request_error", "Invalid JSON: "+err.Error())
		return
	}

	// 获取账号
	account := h.pool.GetNext()
	if account == nil {
		h.sendClaudeError(w, 503, "api_error", "No available accounts")
		return
	}

	// 检查并刷新 token
	if err := h.ensureValidToken(account); err != nil {
		h.sendClaudeError(w, 503, "api_error", "Token refresh failed: "+err.Error())
		return
	}

	// 解析模型和 thinking 模式
	thinkingCfg := config.GetThinkingConfig()
	actualModel, thinking := ParseModelAndThinking(req.Model, thinkingCfg.Suffix)
	req.Model = actualModel

	// 转换请求
	kiroPayload := ClaudeToKiro(&req, thinking)

	// 流式或非流式
	if req.Stream {
		h.handleClaudeStream(w, account, kiroPayload, req.Model)
	} else {
		h.handleClaudeNonStream(w, account, kiroPayload, req.Model)
	}
}

// handleClaudeStream Claude 流式响应
func (h *Handler) handleClaudeStream(w http.ResponseWriter, account *config.Account, payload *KiroPayload, model string) {
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		h.sendClaudeError(w, 500, "api_error", "Streaming not supported")
		return
	}

	// 获取 thinking 输出格式配置
	thinkingFormat := config.GetThinkingConfig().ClaudeFormat

	msgID := "msg_" + uuid.New().String()
	var contentStarted bool
	var toolUseIndex int
	var inputTokens, outputTokens int
	var credits float64
	var toolUses []KiroToolUse

	// Thinking 标签解析状态
	var textBuffer string
	var inThinkingBlock bool

	// 发送文本的辅助函数
	// thinkingState: 0=普通内容, 1=thinking开始, 2=thinking中间, 3=thinking结束
	sendText := func(text string, thinkingState int) {
		// 确保 content_block 已开始
		if !contentStarted {
			h.sendSSE(w, flusher, "content_block_start", map[string]interface{}{
				"type":          "content_block_start",
				"index":         0,
				"content_block": map[string]string{"type": "text", "text": ""},
			})
			contentStarted = true
		}
		
		if thinkingState == 0 {
			// 普通内容
			if text == "" {
				return
			}
			h.sendSSE(w, flusher, "content_block_delta", map[string]interface{}{
				"type":  "content_block_delta",
				"index": 0,
				"delta": map[string]string{"type": "text_delta", "text": text},
			})
		} else {
			// thinking 内容
			var outputText string
			switch thinkingFormat {
			case "think":
				switch thinkingState {
				case 1:
					outputText = "<think>" + text
				case 2:
					outputText = text
				case 3:
					outputText = text + "</think>"
				}
			case "reasoning_content":
				// Claude 格式不支持 reasoning_content，直接输出内容
				outputText = text
			default: // "thinking"
				switch thinkingState {
				case 1:
					outputText = "<thinking>" + text
				case 2:
					outputText = text
				case 3:
					outputText = text + "</thinking>"
				}
			}
			if outputText == "" {
				return
			}
			h.sendSSE(w, flusher, "content_block_delta", map[string]interface{}{
				"type":  "content_block_delta",
				"index": 0,
				"delta": map[string]string{"type": "text_delta", "text": outputText},
			})
		}
	}

	// 处理文本，解析 <thinking> 标签
	var thinkingStarted bool
	
	processClaudeText := func(text string, isThinking bool, forceFlush bool) {
		// 如果是 reasoningContentEvent，直接输出
		if isThinking {
			if !thinkingStarted {
				sendText(text, 1)
				thinkingStarted = true
			} else {
				sendText(text, 2)
			}
			return
		}

		textBuffer += text

		for {
			if !inThinkingBlock {
				thinkingStart := strings.Index(textBuffer, "<thinking>")
				if thinkingStart != -1 {
					if thinkingStart > 0 {
						sendText(textBuffer[:thinkingStart], 0)
					}
					textBuffer = textBuffer[thinkingStart+10:]
					inThinkingBlock = true
					thinkingStarted = false
				} else if forceFlush || len([]rune(textBuffer)) > 50 {
					// 使用 rune 切片来正确处理 Unicode 字符
					runes := []rune(textBuffer)
					safeLen := len(runes)
					if !forceFlush {
						safeLen = max(0, len(runes)-15)
					}
					if safeLen > 0 {
						sendText(string(runes[:safeLen]), 0)
						textBuffer = string(runes[safeLen:])
					}
					break
				} else {
					break
				}
			} else {
				thinkingEnd := strings.Index(textBuffer, "</thinking>")
				if thinkingEnd != -1 {
					content := textBuffer[:thinkingEnd]
					if !thinkingStarted {
						sendText(content, 1)
						sendText("", 3)
					} else {
						sendText(content, 3)
					}
					textBuffer = textBuffer[thinkingEnd+11:]
					inThinkingBlock = false
					thinkingStarted = false
				} else if forceFlush {
					if textBuffer != "" {
						if !thinkingStarted {
							sendText(textBuffer, 1)
							sendText("", 3)
						} else {
							sendText(textBuffer, 3)
						}
						textBuffer = ""
					}
					break
				} else {
					// 流式输出 thinking 块内的内容
					runes := []rune(textBuffer)
					if len(runes) > 20 {
						safeLen := len(runes) - 15
						if safeLen > 0 {
							if !thinkingStarted {
								sendText(string(runes[:safeLen]), 1)
								thinkingStarted = true
							} else {
								sendText(string(runes[:safeLen]), 2)
							}
							textBuffer = string(runes[safeLen:])
						}
					}
					break
				}
			}
		}
	}

	// 发送 message_start
	h.sendSSE(w, flusher, "message_start", map[string]interface{}{
		"type": "message_start",
		"message": map[string]interface{}{
			"id":      msgID,
			"type":    "message",
			"role":    "assistant",
			"content": []interface{}{},
			"model":   model,
		},
	})

	callback := &KiroStreamCallback{
		OnText: func(text string, isThinking bool) {
			if text == "" {
				return
			}
			processClaudeText(text, isThinking, false)
		},
		OnToolUse: func(tu KiroToolUse) {
			// 先刷新缓冲区
			processClaudeText("", false, true)

			toolUses = append(toolUses, tu)

			// 关闭文本块
			if contentStarted && toolUseIndex == 0 {
				h.sendSSE(w, flusher, "content_block_stop", map[string]interface{}{
					"type":  "content_block_stop",
					"index": 0,
				})
			}

			idx := toolUseIndex
			if contentStarted {
				idx = toolUseIndex + 1
			}
			toolUseIndex++

			h.sendSSE(w, flusher, "content_block_start", map[string]interface{}{
				"type":  "content_block_start",
				"index": idx,
				"content_block": map[string]interface{}{
					"type":  "tool_use",
					"id":    tu.ToolUseID,
					"name":  tu.Name,
					"input": map[string]interface{}{},
				},
			})

			inputJSON, _ := json.Marshal(tu.Input)
			h.sendSSE(w, flusher, "content_block_delta", map[string]interface{}{
				"type":  "content_block_delta",
				"index": idx,
				"delta": map[string]interface{}{
					"type":         "input_json_delta",
					"partial_json": string(inputJSON),
				},
			})

			h.sendSSE(w, flusher, "content_block_stop", map[string]interface{}{
				"type":  "content_block_stop",
				"index": idx,
			})
		},
		OnComplete: func(inTok, outTok int) {
			inputTokens = inTok
			outputTokens = outTok
		},
		OnError: func(err error) {
			h.pool.RecordError(account.ID, strings.Contains(err.Error(), "429") || strings.Contains(err.Error(), "quota"))
		},
		OnCredits: func(c float64) {
			credits = c
		},
	}

	err := CallKiroAPI(account, payload, callback)
	if err != nil {
		h.recordFailure()
		h.pool.RecordError(account.ID, strings.Contains(err.Error(), "429") || strings.Contains(err.Error(), "quota"))
		h.sendSSE(w, flusher, "error", map[string]interface{}{
			"type":  "error",
			"error": map[string]string{"type": "api_error", "message": err.Error()},
		})
		return
	}

	// 刷新剩余缓冲区
	processClaudeText("", false, true)

	h.recordSuccess(inputTokens, outputTokens, credits)
	h.pool.RecordSuccess(account.ID)
	h.pool.UpdateStats(account.ID, inputTokens+outputTokens, credits)

	// 关闭最后的内容块
	if contentStarted && toolUseIndex == 0 {
		h.sendSSE(w, flusher, "content_block_stop", map[string]interface{}{
			"type":  "content_block_stop",
			"index": 0,
		})
	}

	// 发送 message_delta
	stopReason := "end_turn"
	if len(toolUses) > 0 {
		stopReason = "tool_use"
	}

	h.sendSSE(w, flusher, "message_delta", map[string]interface{}{
		"type": "message_delta",
		"delta": map[string]interface{}{
			"stop_reason": stopReason,
		},
		"usage": map[string]int{
			"input_tokens":  inputTokens,
			"output_tokens": outputTokens,
		},
	})

	h.sendSSE(w, flusher, "message_stop", map[string]interface{}{
		"type": "message_stop",
	})
}

func (h *Handler) sendSSE(w http.ResponseWriter, flusher http.Flusher, event string, data interface{}) {
	jsonData, _ := json.Marshal(data)
	fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, string(jsonData))
	flusher.Flush()
}

// 统计记录
func (h *Handler) recordSuccess(inputTokens, outputTokens int, credits float64) {
	h.totalRequests++
	h.successRequests++
	h.totalTokens += inputTokens + outputTokens
	h.totalCredits += credits
	// 异步保存
	go config.UpdateStats(h.totalRequests, h.successRequests, h.failedRequests, h.totalTokens, h.totalCredits)
}

func (h *Handler) recordFailure() {
	h.totalRequests++
	h.failedRequests++
	go config.UpdateStats(h.totalRequests, h.successRequests, h.failedRequests, h.totalTokens, h.totalCredits)
}

// handleClaudeNonStream Claude 非流式响应
func (h *Handler) handleClaudeNonStream(w http.ResponseWriter, account *config.Account, payload *KiroPayload, model string) {
	var content string
	var thinkingContent string
	var toolUses []KiroToolUse
	var inputTokens, outputTokens int
	var credits float64

	callback := &KiroStreamCallback{
		OnText: func(text string, isThinking bool) {
			if isThinking {
				thinkingContent += text
			} else {
				content += text
			}
		},
		OnToolUse: func(tu KiroToolUse) {
			toolUses = append(toolUses, tu)
		},
		OnComplete: func(inTok, outTok int) {
			inputTokens = inTok
			outputTokens = outTok
		},
		OnError: func(err error) {
			h.pool.RecordError(account.ID, strings.Contains(err.Error(), "429"))
		},
		OnCredits: func(c float64) {
			credits = c
		},
	}

	err := CallKiroAPI(account, payload, callback)
	if err != nil {
		h.recordFailure()
		h.pool.RecordError(account.ID, strings.Contains(err.Error(), "429"))
		h.sendClaudeError(w, 500, "api_error", err.Error())
		return
	}

	h.recordSuccess(inputTokens, outputTokens, credits)
	h.pool.RecordSuccess(account.ID)
	h.pool.UpdateStats(account.ID, inputTokens+outputTokens, credits)

	// 合并 thinking 内容（如果有 reasoningContentEvent 的内容）
	thinkingFormat := config.GetThinkingConfig().ClaudeFormat
	finalContent := content
	if thinkingContent != "" {
		switch thinkingFormat {
		case "think":
			finalContent = "<think>" + thinkingContent + "</think>" + content
		case "reasoning_content":
			finalContent = thinkingContent + content // Claude 格式不支持 reasoning_content，直接拼接
		default: // "thinking"
			finalContent = "<thinking>" + thinkingContent + "</thinking>" + content
		}
	}

	resp := KiroToClaudeResponse(finalContent, toolUses, inputTokens, outputTokens, model)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(resp)
}

func (h *Handler) sendClaudeError(w http.ResponseWriter, status int, errType, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"type": "error",
		"error": map[string]string{
			"type":    errType,
			"message": message,
		},
	})
}

// handleOpenAIChat OpenAI API 处理
func (h *Handler) handleOpenAIChat(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method Not Allowed", 405)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.sendOpenAIError(w, 400, "invalid_request_error", "Failed to read request body")
		return
	}

	var req OpenAIRequest
	if err := json.Unmarshal(body, &req); err != nil {
		h.sendOpenAIError(w, 400, "invalid_request_error", "Invalid JSON")
		return
	}

	account := h.pool.GetNext()
	if account == nil {
		h.sendOpenAIError(w, 503, "server_error", "No available accounts")
		return
	}

	if err := h.ensureValidToken(account); err != nil {
		h.sendOpenAIError(w, 503, "server_error", "Token refresh failed")
		return
	}

	// 解析模型和 thinking 模式
	thinkingCfg := config.GetThinkingConfig()
	actualModel, thinking := ParseModelAndThinking(req.Model, thinkingCfg.Suffix)
	req.Model = actualModel

	kiroPayload := OpenAIToKiro(&req, thinking)

	if req.Stream {
		h.handleOpenAIStream(w, account, kiroPayload, req.Model)
	} else {
		h.handleOpenAINonStream(w, account, kiroPayload, req.Model)
	}
}

// handleOpenAIStream OpenAI 流式响应
func (h *Handler) handleOpenAIStream(w http.ResponseWriter, account *config.Account, payload *KiroPayload, model string) {
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		h.sendOpenAIError(w, 500, "server_error", "Streaming not supported")
		return
	}

	// 获取 thinking 输出格式配置
	thinkingFormat := config.GetThinkingConfig().OpenAIFormat

	chatID := "chatcmpl-" + uuid.New().String()
	var toolCalls []ToolCall
	var toolCallIndex int
	var inputTokens, outputTokens int
	var credits float64

	// Thinking 标签解析状态
	var textBuffer string
	var inThinkingBlock bool

	// 发送 chunk 的辅助函数
	// thinkingState: 0=普通内容, 1=thinking开始, 2=thinking中间, 3=thinking结束
	sendChunk := func(content string, thinkingState int) {
		if content == "" && thinkingState == 2 {
			return
		}
		
		var chunk map[string]interface{}
		
		if thinkingState > 0 {
			// thinking 内容
			switch thinkingFormat {
			case "thinking":
				// 流式输出标签
				var text string
				switch thinkingState {
				case 1: // 开始
					text = "<thinking>" + content
				case 2: // 中间
					text = content
				case 3: // 结束
					text = content + "</thinking>"
				}
				if text == "" {
					return
				}
				chunk = map[string]interface{}{
					"id":      chatID,
					"object":  "chat.completion.chunk",
					"created": time.Now().Unix(),
					"model":   model,
					"choices": []map[string]interface{}{{
						"index":         0,
						"delta":         map[string]string{"content": text},
						"finish_reason": nil,
					}},
				}
			case "think":
				var text string
				switch thinkingState {
				case 1:
					text = "<think>" + content
				case 2:
					text = content
				case 3:
					text = content + "</think>"
				}
				if text == "" {
					return
				}
				chunk = map[string]interface{}{
					"id":      chatID,
					"object":  "chat.completion.chunk",
					"created": time.Now().Unix(),
					"model":   model,
					"choices": []map[string]interface{}{{
						"index":         0,
						"delta":         map[string]string{"content": text},
						"finish_reason": nil,
					}},
				}
			default: // "reasoning_content"
				if content == "" {
					return
				}
				chunk = map[string]interface{}{
					"id":      chatID,
					"object":  "chat.completion.chunk",
					"created": time.Now().Unix(),
					"model":   model,
					"choices": []map[string]interface{}{{
						"index":         0,
						"delta":         map[string]string{"reasoning_content": content},
						"finish_reason": nil,
					}},
				}
			}
		} else {
			// 普通内容
			if content == "" {
				return
			}
			chunk = map[string]interface{}{
				"id":      chatID,
				"object":  "chat.completion.chunk",
				"created": time.Now().Unix(),
				"model":   model,
				"choices": []map[string]interface{}{{
					"index":         0,
					"delta":         map[string]string{"content": content},
					"finish_reason": nil,
				}},
			}
		}
		data, _ := json.Marshal(chunk)
		fmt.Fprintf(w, "data: %s\n\n", string(data))
		flusher.Flush()
	}

	// 处理文本，解析 <thinking> 标签
	// thinkingStarted 用于跟踪是否已发送开始标签
	var thinkingStarted bool
	
	processText := func(text string, isThinking bool, forceFlush bool) {
		// 如果是 reasoningContentEvent，直接输出
		if isThinking {
			if !thinkingStarted {
				sendChunk(text, 1) // 开始
				thinkingStarted = true
			} else {
				sendChunk(text, 2) // 中间
			}
			return
		}

		textBuffer += text

		for {
			if !inThinkingBlock {
				// 查找 <thinking> 开始标签
				thinkingStart := strings.Index(textBuffer, "<thinking>")
				if thinkingStart != -1 {
					// 输出 thinking 标签之前的内容
					if thinkingStart > 0 {
						sendChunk(textBuffer[:thinkingStart], 0)
					}
					textBuffer = textBuffer[thinkingStart+10:] // 移除 <thinking>
					inThinkingBlock = true
					thinkingStarted = false // 重置，准备发送新的开始标签
				} else if forceFlush || len([]rune(textBuffer)) > 50 {
					// 没有找到标签，安全输出（保留可能的部分标签）
					runes := []rune(textBuffer)
					safeLen := len(runes)
					if !forceFlush {
						safeLen = max(0, len(runes)-15)
					}
					if safeLen > 0 {
						sendChunk(string(runes[:safeLen]), 0)
						textBuffer = string(runes[safeLen:])
					}
					break
				} else {
					break
				}
			} else {
				// 在 thinking 块内，查找 </thinking> 结束标签
				thinkingEnd := strings.Index(textBuffer, "</thinking>")
				if thinkingEnd != -1 {
					// 输出 thinking 内容
					content := textBuffer[:thinkingEnd]
					if !thinkingStarted {
						// 一次性输出完整内容（开始+内容+结束）
						sendChunk(content, 1) // 开始
						sendChunk("", 3)      // 结束（空内容，只发结束标签）
					} else {
						// 已经开始了，发送剩余内容和结束
						sendChunk(content, 3) // 结束
					}
					textBuffer = textBuffer[thinkingEnd+11:] // 移除 </thinking>
					inThinkingBlock = false
					thinkingStarted = false
				} else if forceFlush {
					// 强制刷新：输出剩余内容
					if textBuffer != "" {
						if !thinkingStarted {
							sendChunk(textBuffer, 1) // 开始
							sendChunk("", 3)         // 结束
						} else {
							sendChunk(textBuffer, 3) // 结束
						}
						textBuffer = ""
					}
					break
				} else {
					// 流式输出 thinking 块内的内容
					runes := []rune(textBuffer)
					if len(runes) > 20 {
						safeLen := len(runes) - 15 // 保留可能的 </thinking> 部分
						if safeLen > 0 {
							if !thinkingStarted {
								sendChunk(string(runes[:safeLen]), 1) // 开始
								thinkingStarted = true
							} else {
								sendChunk(string(runes[:safeLen]), 2) // 中间
							}
							textBuffer = string(runes[safeLen:])
						}
					}
					break
				}
			}
		}
	}

	callback := &KiroStreamCallback{
		OnText: func(text string, isThinking bool) {
			if text == "" {
				return
			}
			processText(text, isThinking, false)
		},
		OnToolUse: func(tu KiroToolUse) {
			// 先刷新缓冲区
			processText("", false, true)

			args, _ := json.Marshal(tu.Input)
			tc := ToolCall{ID: tu.ToolUseID, Type: "function"}
			tc.Function.Name = tu.Name
			tc.Function.Arguments = string(args)
			toolCalls = append(toolCalls, tc)

			chunk := map[string]interface{}{
				"id":      chatID,
				"object":  "chat.completion.chunk",
				"created": time.Now().Unix(),
				"model":   model,
				"choices": []map[string]interface{}{{
					"index": 0,
					"delta": map[string]interface{}{
						"tool_calls": []map[string]interface{}{{
							"index": toolCallIndex,
							"id":    tu.ToolUseID,
							"type":  "function",
							"function": map[string]string{
								"name":      tu.Name,
								"arguments": string(args),
							},
						}},
					},
					"finish_reason": nil,
				}},
			}
			toolCallIndex++
			data, _ := json.Marshal(chunk)
			fmt.Fprintf(w, "data: %s\n\n", string(data))
			flusher.Flush()
		},
		OnComplete: func(inTok, outTok int) {
			inputTokens = inTok
			outputTokens = outTok
		},
		OnError: func(err error) {
			h.pool.RecordError(account.ID, strings.Contains(err.Error(), "429"))
		},
		OnCredits: func(c float64) {
			credits = c
		},
	}

	err := CallKiroAPI(account, payload, callback)
	if err != nil {
		h.recordFailure()
		h.pool.RecordError(account.ID, strings.Contains(err.Error(), "429"))
		return
	}

	// 刷新剩余缓冲区
	processText("", false, true)

	h.recordSuccess(inputTokens, outputTokens, credits)
	h.pool.RecordSuccess(account.ID)
	h.pool.UpdateStats(account.ID, inputTokens+outputTokens, credits)

	// 发送结束
	finishReason := "stop"
	if len(toolCalls) > 0 {
		finishReason = "tool_calls"
	}

	chunk := map[string]interface{}{
		"id":      chatID,
		"object":  "chat.completion.chunk",
		"created": time.Now().Unix(),
		"model":   model,
		"choices": []map[string]interface{}{{
			"index":         0,
			"delta":         map[string]interface{}{},
			"finish_reason": finishReason,
		}},
	}
	data, _ := json.Marshal(chunk)
	fmt.Fprintf(w, "data: %s\n\n", string(data))
	fmt.Fprintf(w, "data: [DONE]\n\n")
	flusher.Flush()
}

// handleOpenAINonStream OpenAI 非流式响应
func (h *Handler) handleOpenAINonStream(w http.ResponseWriter, account *config.Account, payload *KiroPayload, model string) {
	var content string
	var reasoningContent string
	var toolUses []KiroToolUse
	var inputTokens, outputTokens int
	var credits float64

	callback := &KiroStreamCallback{
		OnText: func(text string, isThinking bool) {
			if isThinking {
				reasoningContent += text
			} else {
				content += text
			}
		},
		OnToolUse:  func(tu KiroToolUse) { toolUses = append(toolUses, tu) },
		OnComplete: func(inTok, outTok int) { inputTokens = inTok; outputTokens = outTok },
		OnError:    func(err error) { h.pool.RecordError(account.ID, strings.Contains(err.Error(), "429")) },
		OnCredits:  func(c float64) { credits = c },
	}

	err := CallKiroAPI(account, payload, callback)
	if err != nil {
		h.recordFailure()
		h.pool.RecordError(account.ID, strings.Contains(err.Error(), "429"))
		h.sendOpenAIError(w, 500, "server_error", err.Error())
		return
	}

	h.recordSuccess(inputTokens, outputTokens, credits)
	h.pool.RecordSuccess(account.ID)
	h.pool.UpdateStats(account.ID, inputTokens+outputTokens, credits)

	// 解析 content 中的 <thinking> 标签
	finalContent, extractedReasoning := extractThinkingFromContent(content)
	if extractedReasoning != "" {
		reasoningContent = extractedReasoning + reasoningContent
	}

	thinkingFormat := config.GetThinkingConfig().OpenAIFormat
	resp := KiroToOpenAIResponseWithReasoning(finalContent, reasoningContent, toolUses, inputTokens, outputTokens, model, thinkingFormat)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(resp)
}

func (h *Handler) sendOpenAIError(w http.ResponseWriter, status int, errType, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error": map[string]interface{}{
			"type":    errType,
			"message": message,
		},
	})
}

// ensureValidToken 确保 token 有效
func (h *Handler) ensureValidToken(account *config.Account) error {
	if account.ExpiresAt == 0 || time.Now().Unix() < account.ExpiresAt-300 {
		return nil
	}

	accessToken, refreshToken, expiresAt, err := auth.RefreshToken(account)
	if err != nil {
		return err
	}

	// 更新内存
	h.pool.UpdateToken(account.ID, accessToken, refreshToken, expiresAt)
	account.AccessToken = accessToken
	if refreshToken != "" {
		account.RefreshToken = refreshToken
	}
	account.ExpiresAt = expiresAt

	// 持久化
	config.UpdateAccountToken(account.ID, accessToken, refreshToken, expiresAt)

	return nil
}

// ==================== 管理 API ====================

func (h *Handler) handleAdminAPI(w http.ResponseWriter, r *http.Request) {
	// 验证密码
	password := r.Header.Get("X-Admin-Password")
	if password == "" {
		cookie, _ := r.Cookie("admin_password")
		if cookie != nil {
			password = cookie.Value
		}
	}

	if password != config.GetPassword() {
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(map[string]string{"error": "Unauthorized"})
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/admin/api")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	switch {
	case path == "/accounts" && r.Method == "GET":
		h.apiGetAccounts(w, r)
	case path == "/accounts" && r.Method == "POST":
		h.apiAddAccount(w, r)
	case strings.HasPrefix(path, "/accounts/") && strings.HasSuffix(path, "/refresh") && r.Method == "POST":
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/accounts/"), "/refresh")
		h.apiRefreshAccount(w, r, id)
	case strings.HasPrefix(path, "/accounts/") && strings.HasSuffix(path, "/models") && r.Method == "GET":
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/accounts/"), "/models")
		h.apiGetAccountModels(w, r, id)
	case strings.HasPrefix(path, "/accounts/") && r.Method == "DELETE":
		h.apiDeleteAccount(w, r, strings.TrimPrefix(path, "/accounts/"))
	case strings.HasPrefix(path, "/accounts/") && r.Method == "PUT":
		h.apiUpdateAccount(w, r, strings.TrimPrefix(path, "/accounts/"))
	case path == "/auth/iam-sso/start" && r.Method == "POST":
		h.apiStartIamSso(w, r)
	case path == "/auth/iam-sso/complete" && r.Method == "POST":
		h.apiCompleteIamSso(w, r)
	case path == "/auth/builderid/start" && r.Method == "POST":
		h.apiStartBuilderIdLogin(w, r)
	case path == "/auth/builderid/poll" && r.Method == "POST":
		h.apiPollBuilderIdAuth(w, r)
	case path == "/auth/sso-token" && r.Method == "POST":
		h.apiImportSsoToken(w, r)
	case path == "/auth/credentials" && r.Method == "POST":
		h.apiImportCredentials(w, r)
	case path == "/status" && r.Method == "GET":
		h.apiGetStatus(w, r)
	case path == "/settings" && r.Method == "GET":
		h.apiGetSettings(w, r)
	case path == "/settings" && r.Method == "POST":
		h.apiUpdateSettings(w, r)
	case path == "/stats" && r.Method == "GET":
		h.apiGetStats(w, r)
	case path == "/stats/reset" && r.Method == "POST":
		h.apiResetStats(w, r)
	case path == "/generate-machine-id" && r.Method == "GET":
		h.apiGenerateMachineId(w, r)
	case path == "/thinking" && r.Method == "GET":
		h.apiGetThinkingConfig(w, r)
	case path == "/thinking" && r.Method == "POST":
		h.apiUpdateThinkingConfig(w, r)
	default:
		w.WriteHeader(404)
		json.NewEncoder(w).Encode(map[string]string{"error": "Not Found"})
	}
}

func (h *Handler) apiGetAccounts(w http.ResponseWriter, r *http.Request) {
	accounts := config.GetAccounts()
	poolAccounts := h.pool.GetAllAccounts()
	
	// 合并运行时统计
	statsMap := make(map[string]config.Account)
	for _, a := range poolAccounts {
		statsMap[a.ID] = a
	}
	
	// 隐藏敏感信息
	result := make([]map[string]interface{}, len(accounts))
	for i, a := range accounts {
		// 获取运行时统计
		stats := statsMap[a.ID]
		
		result[i] = map[string]interface{}{
			"id":                a.ID,
			"email":             a.Email,
			"userId":            a.UserId,
			"nickname":          a.Nickname,
			"authMethod":        a.AuthMethod,
			"provider":          a.Provider,
			"region":            a.Region,
			"enabled":           a.Enabled,
			"expiresAt":         a.ExpiresAt,
			"hasToken":          a.AccessToken != "",
			"machineId":         a.MachineId,
			"subscriptionType":    a.SubscriptionType,
			"subscriptionTitle":   a.SubscriptionTitle,
			"daysRemaining":       a.DaysRemaining,
			"usageCurrent":        a.UsageCurrent,
			"usageLimit":          a.UsageLimit,
			"usagePercent":        a.UsagePercent,
			"nextResetDate":       a.NextResetDate,
			"lastRefresh":         a.LastRefresh,
			"trialUsageCurrent":   a.TrialUsageCurrent,
			"trialUsageLimit":     a.TrialUsageLimit,
			"trialUsagePercent":   a.TrialUsagePercent,
			"trialStatus":         a.TrialStatus,
			"trialExpiresAt":      a.TrialExpiresAt,
			"requestCount":        stats.RequestCount,
			"errorCount":        stats.ErrorCount,
			"totalTokens":       stats.TotalTokens,
			"totalCredits":      stats.TotalCredits,
			"lastUsed":          stats.LastUsed,
		}
	}
	json.NewEncoder(w).Encode(result)
}

func (h *Handler) apiAddAccount(w http.ResponseWriter, r *http.Request) {
	var account config.Account
	if err := json.NewDecoder(r.Body).Decode(&account); err != nil {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON"})
		return
	}

	if account.ID == "" {
		account.ID = auth.GenerateAccountID()
	}
	if account.Region == "" {
		account.Region = "us-east-1"
	}

	if err := config.AddAccount(account); err != nil {
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	h.pool.Reload()
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "id": account.ID})
}

func (h *Handler) apiDeleteAccount(w http.ResponseWriter, r *http.Request, id string) {
	if err := config.DeleteAccount(id); err != nil {
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	h.pool.Reload()
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func (h *Handler) apiUpdateAccount(w http.ResponseWriter, r *http.Request, id string) {
	var updates map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON"})
		return
	}

	// 获取现有账号
	accounts := config.GetAccounts()
	var existing *config.Account
	for i := range accounts {
		if accounts[i].ID == id {
			existing = &accounts[i]
			break
		}
	}
	if existing == nil {
		w.WriteHeader(404)
		json.NewEncoder(w).Encode(map[string]string{"error": "Account not found"})
		return
	}

	// 只更新传入的字段
	if v, ok := updates["enabled"].(bool); ok {
		existing.Enabled = v
	}
	if v, ok := updates["nickname"].(string); ok {
		existing.Nickname = v
	}
	if v, ok := updates["machineId"].(string); ok {
		existing.MachineId = v
	}

	if err := config.UpdateAccount(id, *existing); err != nil {
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	h.pool.Reload()
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func (h *Handler) apiStartIamSso(w http.ResponseWriter, r *http.Request) {
	var req struct {
		StartUrl string `json:"startUrl"`
		Region   string `json:"region"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON"})
		return
	}

	if req.StartUrl == "" {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]string{"error": "startUrl is required"})
		return
	}

	sessionID, authorizeUrl, expiresIn, err := auth.StartIamSsoLogin(req.StartUrl, req.Region)
	if err != nil {
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"sessionId":    sessionID,
		"authorizeUrl": authorizeUrl,
		"expiresIn":    expiresIn,
	})
}

func (h *Handler) apiCompleteIamSso(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SessionID   string `json:"sessionId"`
		CallbackUrl string `json:"callbackUrl"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON"})
		return
	}

	accessToken, refreshToken, clientID, clientSecret, region, expiresIn, err := auth.CompleteIamSsoLogin(req.SessionID, req.CallbackUrl)
	if err != nil {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	// 获取用户信息
	email, _, _ := auth.GetUserInfo(accessToken)

	// 创建账号
	account := config.Account{
		ID:           auth.GenerateAccountID(),
		Email:        email,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		AuthMethod:   "idc",
		Region:       region,
		ExpiresAt:    time.Now().Unix() + int64(expiresIn),
		Enabled:      true,
		MachineId:    config.GenerateMachineId(),
	}

	if err := config.AddAccount(account); err != nil {
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	h.pool.Reload()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"account": map[string]interface{}{
			"id":    account.ID,
			"email": account.Email,
		},
	})
}

func (h *Handler) apiStartBuilderIdLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Region string `json:"region"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	session, err := auth.StartBuilderIdLogin(req.Region)
	if err != nil {
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"sessionId":       session.ID,
		"userCode":        session.UserCode,
		"verificationUri": session.VerificationUri,
		"interval":        session.Interval,
	})
}

func (h *Handler) apiPollBuilderIdAuth(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SessionID string `json:"sessionId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON"})
		return
	}

	accessToken, refreshToken, clientID, clientSecret, region, expiresIn, status, err := auth.PollBuilderIdAuth(req.SessionID)
	if err != nil {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	if status == "pending" || status == "slow_down" {
		// 获取当前间隔
		interval := 5
		if session := auth.GetBuilderIdSession(req.SessionID); session != nil {
			interval = session.Interval
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":   true,
			"completed": false,
			"status":    status,
			"interval":  interval,
		})
		return
	}

	// 授权完成，获取用户信息
	email, _, _ := auth.GetUserInfo(accessToken)

	// 创建账号
	account := config.Account{
		ID:           auth.GenerateAccountID(),
		Email:        email,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		AuthMethod:   "idc",
		Provider:     "BuilderId",
		Region:       region,
		ExpiresAt:    time.Now().Unix() + int64(expiresIn),
		Enabled:      true,
		MachineId:    config.GenerateMachineId(),
	}

	if err := config.AddAccount(account); err != nil {
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	h.pool.Reload()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":   true,
		"completed": true,
		"account": map[string]interface{}{
			"id":    account.ID,
			"email": account.Email,
		},
	})
}

func (h *Handler) apiImportSsoToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		BearerToken string `json:"bearerToken"`
		Region      string `json:"region"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON"})
		return
	}

	if req.BearerToken == "" {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]string{"error": "bearerToken is required"})
		return
	}

	// 支持批量导入，按行分割
	tokens := strings.Split(strings.TrimSpace(req.BearerToken), "\n")
	var imported []map[string]interface{}
	var errors []string

	for _, token := range tokens {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}

		accessToken, refreshToken, clientID, clientSecret, expiresIn, err := auth.ImportFromSsoToken(token, req.Region)
		if err != nil {
			errors = append(errors, err.Error())
			continue
		}

		// 获取用户信息
		email, _, _ := auth.GetUserInfo(accessToken)

		// 创建账号
		account := config.Account{
			ID:           auth.GenerateAccountID(),
			Email:        email,
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
			ClientID:     clientID,
			ClientSecret: clientSecret,
			AuthMethod:   "idc",
			Region:       req.Region,
			ExpiresAt:    time.Now().Unix() + int64(expiresIn),
			Enabled:      true,
			MachineId:    config.GenerateMachineId(),
		}

		if err := config.AddAccount(account); err != nil {
			errors = append(errors, err.Error())
			continue
		}

		imported = append(imported, map[string]interface{}{
			"id":    account.ID,
			"email": account.Email,
		})
	}

	h.pool.Reload()

	if len(imported) == 0 && len(errors) > 0 {
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   strings.Join(errors, "; "),
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":  true,
		"accounts": imported,
		"errors":   errors,
	})
}

func (h *Handler) apiImportCredentials(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AccessToken  string `json:"accessToken"`
		RefreshToken string `json:"refreshToken"`
		ClientID     string `json:"clientId"`
		ClientSecret string `json:"clientSecret"`
		AuthMethod   string `json:"authMethod"`
		Provider     string `json:"provider"`
		Region       string `json:"region"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON"})
		return
	}

	if req.RefreshToken == "" {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]string{"error": "refreshToken is required"})
		return
	}

	// 设置默认值
	if req.Region == "" {
		req.Region = "us-east-1"
	}
	if req.AuthMethod == "" {
		if req.ClientID != "" {
			req.AuthMethod = "idc"
		} else {
			req.AuthMethod = "social"
		}
	}

	// 如果没有 accessToken，尝试刷新获取
	accessToken := req.AccessToken
	var expiresAt int64
	if accessToken == "" {
		tempAccount := &config.Account{
			RefreshToken: req.RefreshToken,
			ClientID:     req.ClientID,
			ClientSecret: req.ClientSecret,
			AuthMethod:   req.AuthMethod,
			Region:       req.Region,
		}
		newAccessToken, newRefreshToken, newExpiresAt, err := auth.RefreshToken(tempAccount)
		if err != nil {
			w.WriteHeader(400)
			json.NewEncoder(w).Encode(map[string]string{"error": "Token refresh failed: " + err.Error()})
			return
		}
		accessToken = newAccessToken
		if newRefreshToken != "" {
			req.RefreshToken = newRefreshToken
		}
		expiresAt = newExpiresAt
	} else {
		expiresAt = time.Now().Unix() + 3600 // 默认 1 小时
	}

	// 获取用户信息
	email, _, _ := auth.GetUserInfo(accessToken)

	// 创建账号
	account := config.Account{
		ID:           auth.GenerateAccountID(),
		Email:        email,
		AccessToken:  accessToken,
		RefreshToken: req.RefreshToken,
		ClientID:     req.ClientID,
		ClientSecret: req.ClientSecret,
		AuthMethod:   req.AuthMethod,
		Provider:     req.Provider,
		Region:       req.Region,
		ExpiresAt:    expiresAt,
		Enabled:      true,
		MachineId:    config.GenerateMachineId(),
	}

	if err := config.AddAccount(account); err != nil {
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	h.pool.Reload()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"account": map[string]interface{}{
			"id":    account.ID,
			"email": account.Email,
		},
	})
}

func (h *Handler) apiGetStatus(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]interface{}{
		"accounts":        h.pool.Count(),
		"available":       h.pool.AvailableCount(),
		"totalRequests":   h.totalRequests,
		"successRequests": h.successRequests,
		"failedRequests":  h.failedRequests,
		"totalTokens":     h.totalTokens,
		"totalCredits":    h.totalCredits,
		"uptime":          time.Now().Unix() - h.startTime,
	})
}

func (h *Handler) apiGetSettings(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]interface{}{
		"apiKey":        config.GetApiKey(),
		"requireApiKey": config.IsApiKeyRequired(),
		"port":          config.GetPort(),
		"host":          config.GetHost(),
	})
}

func (h *Handler) apiUpdateSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ApiKey        string `json:"apiKey"`
		RequireApiKey bool   `json:"requireApiKey"`
		Password      string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON"})
		return
	}

	if err := config.UpdateSettings(req.ApiKey, req.RequireApiKey, req.Password); err != nil {
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func (h *Handler) apiGetStats(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]interface{}{
		"totalRequests":   h.totalRequests,
		"successRequests": h.successRequests,
		"failedRequests":  h.failedRequests,
		"totalTokens":     h.totalTokens,
		"totalCredits":    h.totalCredits,
		"uptime":          time.Now().Unix() - h.startTime,
	})
}

func (h *Handler) apiResetStats(w http.ResponseWriter, r *http.Request) {
	h.totalRequests = 0
	h.successRequests = 0
	h.failedRequests = 0
	h.totalTokens = 0
	h.totalCredits = 0
	config.UpdateStats(0, 0, 0, 0, 0)
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// apiGenerateMachineId 生成新的机器码
func (h *Handler) apiGenerateMachineId(w http.ResponseWriter, r *http.Request) {
	machineId := config.GenerateMachineId()
	json.NewEncoder(w).Encode(map[string]string{"machineId": machineId})
}

// apiRefreshAccount 刷新账户信息（使用量、订阅等）
func (h *Handler) apiRefreshAccount(w http.ResponseWriter, r *http.Request, id string) {
	accounts := config.GetAccounts()
	var account *config.Account
	for i := range accounts {
		if accounts[i].ID == id {
			account = &accounts[i]
			break
		}
	}

	if account == nil {
		w.WriteHeader(404)
		json.NewEncoder(w).Encode(map[string]string{"error": "Account not found"})
		return
	}

	// 检查 token 是否过期，需要刷新
	if account.ExpiresAt > 0 && time.Now().Unix() > account.ExpiresAt-60 {
		newAccessToken, newRefreshToken, newExpiresAt, err := auth.RefreshToken(account)
		if err != nil {
			w.WriteHeader(500)
			json.NewEncoder(w).Encode(map[string]string{"error": "Token refresh failed: " + err.Error()})
			return
		}
		account.AccessToken = newAccessToken
		if newRefreshToken != "" {
			account.RefreshToken = newRefreshToken
		}
		account.ExpiresAt = newExpiresAt
		config.UpdateAccountToken(id, newAccessToken, newRefreshToken, newExpiresAt)
		h.pool.UpdateToken(id, newAccessToken, newRefreshToken, newExpiresAt)
	}

	// 获取账户信息
	info, err := RefreshAccountInfo(account)
	if err != nil {
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	// 保存到配置
	if err := config.UpdateAccountInfo(id, *info); err != nil {
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"info":    info,
	})
}

// apiGetAccountModels 获取账户可用模型
func (h *Handler) apiGetAccountModels(w http.ResponseWriter, r *http.Request, id string) {
	accounts := config.GetAccounts()
	var account *config.Account
	for i := range accounts {
		if accounts[i].ID == id {
			account = &accounts[i]
			break
		}
	}

	if account == nil {
		w.WriteHeader(404)
		json.NewEncoder(w).Encode(map[string]string{"error": "Account not found"})
		return
	}

	models, err := ListAvailableModels(account)
	if err != nil {
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"models":  models,
	})
}

// ==================== 静态文件服务 ====================

func (h *Handler) serveAdminPage(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "web/index.html")
}

func (h *Handler) serveStaticFile(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/admin/")
	http.ServeFile(w, r, "web/"+path)
}

// apiGetThinkingConfig 获取 thinking 配置
func (h *Handler) apiGetThinkingConfig(w http.ResponseWriter, r *http.Request) {
	cfg := config.GetThinkingConfig()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"suffix":       cfg.Suffix,
		"openaiFormat": cfg.OpenAIFormat,
		"claudeFormat": cfg.ClaudeFormat,
	})
}

// apiUpdateThinkingConfig 更新 thinking 配置
func (h *Handler) apiUpdateThinkingConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Suffix       string `json:"suffix"`
		OpenAIFormat string `json:"openaiFormat"`
		ClaudeFormat string `json:"claudeFormat"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON"})
		return
	}

	// 验证格式
	validFormats := map[string]bool{"reasoning_content": true, "thinking": true, "think": true}
	if req.OpenAIFormat != "" && !validFormats[req.OpenAIFormat] {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid openaiFormat, must be: reasoning_content, thinking, or think"})
		return
	}
	if req.ClaudeFormat != "" && !validFormats[req.ClaudeFormat] {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid claudeFormat, must be: reasoning_content, thinking, or think"})
		return
	}

	if err := config.UpdateThinkingConfig(req.Suffix, req.OpenAIFormat, req.ClaudeFormat); err != nil {
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}
