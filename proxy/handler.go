package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"kiro-go/auth"
	"kiro-go/config"
	"kiro-go/logger"
	"kiro-go/pool"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

const tokenRefreshSkewSeconds int64 = 120

const (
	microsoftProfileSelectionTTL          = 10 * time.Minute
	microsoftMaxPendingProfileSelections  = 64
	microsoftCanceledSessionTTL           = 10 * time.Minute
	microsoftMaxCanceledSessionTombstones = 128
	microsoftProfileDiscoveryTimeout      = 30 * time.Second
)

// looksLikeKiroAPIKey is a lightweight heuristic for plain-text imports.
// Official keys currently use the ksk_ prefix; future formats can still be
// imported via explicit authMethod/kiroApiKey fields.
func looksLikeKiroAPIKey(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	// Convenience form: ksk_xxx|region
	if idx := strings.IndexByte(value, '|'); idx > 0 {
		value = strings.TrimSpace(value[:idx])
	}
	return strings.HasPrefix(value, "ksk_")
}

// RequestLog stores details about a single API request (success or failure).
type RequestLog struct {
	Time      int64   `json:"time"`      // Unix timestamp
	Endpoint  string  `json:"endpoint"`  // claude/openai/responses
	Model     string  `json:"model"`     // Requested model
	AccountID string  `json:"accountId"` // Account used
	Status    string  `json:"status"`    // "success" or "error"
	Error     string  `json:"error"`     // Error message (empty on success)
	ErrorType string  `json:"errorType"` // Error category (empty on success)
	Tokens    int     `json:"tokens"`    // Total tokens (input+output, 0 on failure)
	Credits   float64 `json:"credits"`   // Credits consumed (0 on failure)
	Duration  int64   `json:"duration"`  // Request duration in ms
}

const requestLogsMaxSize = 500

// Handler HTTP 处理器
type Handler struct {
	pool *pool.AccountPool
	// 运行时统计 (使用原子操作)
	totalRequests   int64
	successRequests int64
	failedRequests  int64
	totalTokens     int64
	totalCredits    float64 // float64 需要用锁保护
	creditsMu       sync.RWMutex
	startTime       int64
	stopRefresh     chan struct{}
	stopStatsSaver  chan struct{}
	// 模型缓存
	cachedModels       []ModelInfo
	modelsCacheMu      sync.RWMutex
	modelsCacheTime    int64
	promptCache        *promptCacheTracker
	tokenRefreshMu     sync.Mutex
	credentialImportMu sync.Mutex
	// 请求日志 (环形缓冲区，包含成功和失败)
	requestLogs   []RequestLog
	requestLogsMu sync.RWMutex

	microsoftSelections   map[string]*microsoftProfileSelection
	microsoftSelectionsMu sync.Mutex
	microsoftFlowMu       sync.Mutex
	microsoftCanceled     map[string]time.Time
	microsoftDiscoveries  map[string]*microsoftProfileDiscovery
}

type microsoftProfileSelection struct {
	SessionID string
	Account   config.Account
	Profiles  []KiroProfile
	ExpiresAt time.Time
	timer     *time.Timer
	mu        sync.Mutex
	canceled  atomic.Bool
}

type microsoftProfileDiscovery struct {
	cancel context.CancelFunc
}

type thinkingStreamSource int

const (
	thinkingSourceUnknown thinkingStreamSource = iota
	thinkingSourceReasoningEvent
	thinkingSourceTagBlock
)

func allowReasoningSource(source *thinkingStreamSource) bool {
	if *source == thinkingSourceTagBlock {
		return false
	}
	*source = thinkingSourceReasoningEvent
	return true
}

func allowTagSource(source *thinkingStreamSource) bool {
	if *source == thinkingSourceReasoningEvent {
		return false
	}
	if *source == thinkingSourceUnknown {
		*source = thinkingSourceTagBlock
	}
	return *source == thinkingSourceTagBlock
}

func validateClaudeRequestShape(req *ClaudeRequest) string {
	if len(req.Messages) == 0 {
		return "messages must not be empty"
	}
	if msg := validateClaudeThinkingConfig(req.Thinking, req.MaxTokens); msg != "" {
		return msg
	}

	hasUserContext := false
	lastRole := ""
	for _, msg := range req.Messages {
		role := strings.TrimSpace(msg.Role)
		if role == "" {
			continue
		}
		lastRole = role
		if role != "user" {
			continue
		}

		text, images, toolResults := extractClaudeUserContent(msg.Content)
		if normalizeUserContent(text, len(images) > 0) != "" || len(toolResults) > 0 {
			hasUserContext = true
		}
	}

	if lastRole == "assistant" {
		return "assistant-prefill final message is not supported; last message must be user"
	}
	if !hasUserContext {
		return "at least one non-empty user message is required"
	}
	return ""
}

func validateClaudeThinkingConfig(thinking *ClaudeThinkingConfig, maxTokens int) string {
	if thinking == nil {
		return ""
	}

	kind := strings.ToLower(strings.TrimSpace(thinking.Type))
	switch kind {
	case "enabled":
		if maxTokens == 0 {
			return "thinking.type enabled cannot be used with max_tokens=0"
		}
		if thinking.BudgetTokens <= 0 {
			return "thinking.budget_tokens is required when thinking.type is enabled"
		}
		if thinking.BudgetTokens < 1024 {
			return "thinking.budget_tokens must be at least 1024"
		}
		if maxTokens > 0 && thinking.BudgetTokens >= maxTokens {
			return "thinking.budget_tokens must be less than max_tokens"
		}
	case "adaptive":
		if thinking.BudgetTokens != 0 {
			return "thinking.budget_tokens is not supported when thinking.type is adaptive"
		}
	case "disabled":
		if thinking.BudgetTokens != 0 {
			return "thinking.budget_tokens is not supported when thinking.type is disabled"
		}
	default:
		return "thinking.type must be one of: enabled, adaptive, disabled"
	}

	display := strings.ToLower(strings.TrimSpace(thinking.Display))
	if display != "" && display != "summarized" && display != "omitted" {
		return "thinking.display must be one of: summarized, omitted"
	}
	if kind == "disabled" && display != "" {
		return "thinking.display is not supported when thinking.type is disabled"
	}

	return ""
}

type claudeThinkingResponseOptions struct {
	Format      string
	OmitDisplay bool
}

func resolveClaudeThinkingResponseOptions(thinking *ClaudeThinkingConfig, defaultFormat string) claudeThinkingResponseOptions {
	opts := claudeThinkingResponseOptions{Format: defaultFormat}
	if opts.Format == "" {
		opts.Format = "thinking"
	}
	if thinking == nil {
		return opts
	}

	display := strings.ToLower(strings.TrimSpace(thinking.Display))
	switch display {
	case "summarized":
		opts.Format = "thinking"
	case "omitted":
		opts.Format = "thinking"
		opts.OmitDisplay = true
	}

	return opts
}

func validateOpenAIRequestShape(req *OpenAIRequest) string {
	if len(req.Messages) == 0 {
		return "messages must not be empty"
	}

	hasNonSystem := false
	hasUserContext := false
	lastRole := ""
	for _, msg := range req.Messages {
		role := strings.TrimSpace(msg.Role)
		if role == "" {
			continue
		}
		if role != "system" {
			hasNonSystem = true
			lastRole = role
		}

		if role != "user" {
			continue
		}
		text, images := extractOpenAIUserContent(msg.Content)
		if normalizeUserContent(text, len(images) > 0) != "" {
			hasUserContext = true
		}
	}

	if !hasNonSystem {
		return "at least one non-system message is required"
	}
	if lastRole == "assistant" {
		return "assistant-prefill final message is not supported; last message must be user or tool"
	}
	if !hasUserContext {
		return "at least one non-empty user message is required"
	}
	return ""
}

func NewHandler() *Handler {
	// 启动时应用代理配置
	applyProxyConfig(config.GetProxyURL())

	totalReq, successReq, failedReq, totalTokens, totalCredits := config.GetStats()
	h := &Handler{
		pool:                 pool.GetPool(),
		totalRequests:        int64(totalReq),
		successRequests:      int64(successReq),
		failedRequests:       int64(failedReq),
		totalTokens:          int64(totalTokens),
		totalCredits:         totalCredits,
		startTime:            time.Now().Unix(),
		stopRefresh:          make(chan struct{}),
		stopStatsSaver:       make(chan struct{}),
		promptCache:          newPromptCacheTracker(defaultPromptCacheTTL),
		microsoftSelections:  make(map[string]*microsoftProfileSelection),
		microsoftCanceled:    make(map[string]time.Time),
		microsoftDiscoveries: make(map[string]*microsoftProfileDiscovery),
	}
	// 启动后台刷新
	go h.backgroundRefresh()
	// 启动后台统计保存 (每30秒保存一次)
	go h.backgroundStatsSaver()
	// 清理过期的 stored responses（>30 天）
	go purgeExpiredResponses(responsesDefaultTTL)
	return h
}

// backgroundRefresh 后台定时刷新账户信息
func (h *Handler) backgroundRefresh() {
	ticker := time.NewTicker(30 * time.Minute) // 每 30 分钟刷新一次
	defer ticker.Stop()

	// 启动时延迟 10 秒后执行一次
	time.Sleep(10 * time.Second)
	h.refreshModelsCache()
	h.refreshAllAccounts()

	for {
		select {
		case <-ticker.C:
			h.refreshModelsCache()
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
		if !account.Enabled {
			continue
		}
		if accountBearerToken(account) == "" {
			continue
		}

		// API Key accounts skip OAuth refresh; still sync usage/subscription.
		if !config.IsAPIKeyAccount(account) {
			// 检查 token 是否需要刷新
			if account.ExpiresAt > 0 && time.Now().Unix() > account.ExpiresAt-tokenRefreshSkewSeconds {
				if _, err := h.refreshAccountToken(account, false); err != nil {
					logger.Warnf("[BackgroundRefresh] Token refresh failed for %s: %v", account.Email, err)
					h.handleAccountFailure(account, err)
					continue
				}
			}
		}

		// 刷新账户信息
		info, err := RefreshAccountInfo(account)
		if err != nil {
			logger.Warnf("[BackgroundRefresh] Failed to refresh %s: %v", account.Email, err)
			continue
		}

		config.UpdateAccountInfo(account.ID, *info)
		logger.Infof("[BackgroundRefresh] Refreshed %s: %s %.1f/%.1f", account.Email, info.SubscriptionType, info.UsageCurrent, info.UsageLimit)
	}
	h.pool.Reload()
}

// validateApiKey 验证 API Key（Bool 包装，旧签名仍被部分调用方使用）
func (h *Handler) validateApiKey(r *http.Request) bool {
	_, err := h.authenticate(r)
	return err == nil
}

// authenticateForClaude runs authenticate and writes a Claude-style error on failure.
// Returns the request with the matched API key injected into context, or nil if auth failed.
func (h *Handler) authenticateForClaude(w http.ResponseWriter, r *http.Request) *http.Request {
	entry, err := h.authenticate(r)
	if err != nil {
		ae, _ := err.(*authError)
		if ae == nil {
			ae = newAuthError(http.StatusUnauthorized, "authentication_error", err.Error())
		}
		h.sendClaudeError(w, ae.status, ae.code, ae.message)
		return nil
	}
	return withApiKeyContext(r, entry)
}

// authenticateForOpenAI runs authenticate and writes an OpenAI-style error on failure.
func (h *Handler) authenticateForOpenAI(w http.ResponseWriter, r *http.Request) *http.Request {
	entry, err := h.authenticate(r)
	if err != nil {
		ae, _ := err.(*authError)
		if ae == nil {
			ae = newAuthError(http.StatusUnauthorized, "authentication_error", err.Error())
		}
		h.sendOpenAIError(w, ae.status, ae.code, ae.message)
		return nil
	}
	return withApiKeyContext(r, entry)
}

// ServeHTTP 路由分发
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	// Debug-level request trace for fine-grained visibility
	logger.Debugf("[HTTP] %s %s from %s", r.Method, path, r.RemoteAddr)

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
		ar := h.authenticateForClaude(w, r)
		if ar == nil {
			return
		}
		h.handleClaudeMessages(w, ar)
	case path == "/v1/messages/count_tokens" || path == "/messages/count_tokens":
		ar := h.authenticateForClaude(w, r)
		if ar == nil {
			return
		}
		h.handleCountTokens(w, ar)
	case path == "/v1/chat/completions" || path == "/chat/completions":
		ar := h.authenticateForOpenAI(w, r)
		if ar == nil {
			return
		}
		h.handleOpenAIChat(w, ar)
	case path == "/v1/responses" || path == "/responses":
		ar := h.authenticateForOpenAI(w, r)
		if ar == nil {
			return
		}
		h.handleOpenAIResponses(w, ar)
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

	// 统计端点（需要 API Key 鉴权）
	case path == "/v1/stats":
		if !h.validateApiKey(r) {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(401)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid or missing API key"})
			return
		}
		h.handleStats(w, r)

	default:
		http.Error(w, "Not Found", 404)
	}
}

// handleHealth 健康检查（不暴露统计数据）
func (h *Handler) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "ok",
		"version": config.Version,
		"uptime":  time.Now().Unix() - h.startTime,
	})
}

// handleStats 统计数据（需要 API Key 鉴权）
func (h *Handler) handleStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":          "ok",
		"version":         config.Version,
		"accounts":        h.pool.Count(),
		"available":       h.pool.AvailableCount(),
		"totalRequests":   atomic.LoadInt64(&h.totalRequests),
		"successRequests": atomic.LoadInt64(&h.successRequests),
		"failedRequests":  atomic.LoadInt64(&h.failedRequests),
		"totalTokens":     atomic.LoadInt64(&h.totalTokens),
		"totalCredits":    h.getCredits(),
		"uptime":          time.Now().Unix() - h.startTime,
	})
}

// handleModels 模型列表
func (h *Handler) handleModels(w http.ResponseWriter, r *http.Request) {
	// 尝试用缓存的真实模型列表
	h.modelsCacheMu.RLock()
	cached := h.cachedModels
	h.modelsCacheMu.RUnlock()
	if len(cached) == 0 {
		h.refreshModelsCache()
		h.modelsCacheMu.RLock()
		cached = h.cachedModels
		h.modelsCacheMu.RUnlock()
	}

	thinkingSuffix := config.GetThinkingConfig().Suffix

	models := buildAnthropicModelsResponse(cached, thinkingSuffix)
	if len(models) == 0 {
		models = fallbackAnthropicModels(thinkingSuffix)
	}

	// 添加别名模型
	models = append(models,
		buildModelInfo("auto", "kiro-proxy", true),
		buildModelInfo("gpt-4o", "kiro-proxy", true),
		buildModelInfo("gpt-4", "kiro-proxy", true),
	)

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"object": "list",
		"data":   models,
	})
	return
}

func buildAnthropicModelsResponse(cached []ModelInfo, thinkingSuffix string) []map[string]interface{} {
	if len(cached) == 0 {
		return nil
	}

	models := make([]map[string]interface{}, 0, len(cached)*2)
	if len(cached) > 0 {
		for _, m := range cached {
			supportsImage := modelSupportsImage(m.InputTypes)
			models = append(models, buildModelInfo(m.ModelId, "anthropic", supportsImage))
			// 自动生成 thinking 变体
			models = append(models, buildModelInfo(m.ModelId+thinkingSuffix, "anthropic", supportsImage))
		}
	}
	return models
}

func fallbackAnthropicModels(thinkingSuffix string) []map[string]interface{} {
	return []map[string]interface{}{
		buildModelInfo("claude-sonnet-4.6", "anthropic", true),
		buildModelInfo("claude-sonnet-4.6"+thinkingSuffix, "anthropic", true),
		buildModelInfo("claude-opus-4.6", "anthropic", true),
		buildModelInfo("claude-opus-4.6"+thinkingSuffix, "anthropic", true),
		buildModelInfo("claude-opus-4.7", "anthropic", true),
		buildModelInfo("claude-opus-4.7"+thinkingSuffix, "anthropic", true),
		buildModelInfo("claude-sonnet-4.5", "anthropic", true),
		buildModelInfo("claude-sonnet-4.5"+thinkingSuffix, "anthropic", true),
		buildModelInfo("claude-sonnet-4", "anthropic", true),
		buildModelInfo("claude-sonnet-4"+thinkingSuffix, "anthropic", true),
		buildModelInfo("claude-haiku-4.5", "anthropic", true),
		buildModelInfo("claude-haiku-4.5"+thinkingSuffix, "anthropic", true),
		buildModelInfo("claude-opus-4.5", "anthropic", true),
		buildModelInfo("claude-opus-4.5"+thinkingSuffix, "anthropic", true),
	}
}

func modelSupportsImage(inputTypes []string) bool {
	for _, t := range inputTypes {
		lt := strings.ToLower(t)
		if strings.Contains(lt, "image") || strings.Contains(lt, "vision") {
			return true
		}
	}
	return false
}

func buildModelInfo(id, ownedBy string, supportsImage bool) map[string]interface{} {
	modalities := []string{"text"}
	if supportsImage {
		modalities = append(modalities, "image")
	}
	modalitiesMap := map[string][]string{
		"input":  modalities,
		"output": []string{"text"},
	}

	return map[string]interface{}{
		"id":               id,
		"object":           "model",
		"owned_by":         ownedBy,
		"supports_image":   supportsImage,
		"input_modalities": modalities,
		"modalities":       modalitiesMap,
		"capabilities": map[string]bool{
			"vision":       supportsImage,
			"image":        supportsImage,
			"image_vision": supportsImage,
		},
		"info": map[string]interface{}{
			"meta": map[string]interface{}{
				"capabilities": map[string]bool{
					"vision":       supportsImage,
					"image_vision": supportsImage,
				},
			},
		},
	}
}

// refreshModelsCache 从 Kiro API 拉取模型列表并缓存
func (h *Handler) refreshModelsCache() {
	accounts := config.GetEnabledAccounts()
	if len(accounts) == 0 {
		return
	}

	aggregated := make([]ModelInfo, 0)
	for i := range accounts {
		account := &accounts[i]
		if err := h.ensureValidToken(account); err != nil {
			logger.Warnf("[ModelsCache] Skip %s token refresh failed: %v", account.Email, err)
			h.handleAccountFailure(account, err)
			continue
		}

		models, err := ListAvailableModels(account)
		if err != nil {
			logger.Warnf("[ModelsCache] Failed to refresh for %s: %v", account.Email, err)
			h.handleAccountFailure(account, err)
			continue
		}
		// 缓存每账号可用模型，用于路由时过滤
		modelIDs := make([]string, 0, len(models))
		for _, m := range models {
			modelIDs = append(modelIDs, m.ModelId)
		}
		h.pool.SetModelList(account.ID, modelIDs)
		aggregated = mergeUniqueModels(aggregated, models)
	}

	if len(aggregated) > 0 {
		h.modelsCacheMu.Lock()
		h.cachedModels = aggregated
		h.modelsCacheTime = time.Now().Unix()
		h.modelsCacheMu.Unlock()
		logger.Infof("[ModelsCache] Cached %d models", len(aggregated))
	}
}

// fetchAndCacheAccountModels 为单个账号拉取并写入模型缓存。
// 同时更新 pool 的路由缓存与全局聚合模型列表。
func (h *Handler) fetchAndCacheAccountModels(account *config.Account) error {
	if err := h.ensureValidToken(account); err != nil {
		return fmt.Errorf("token refresh failed: %w", err)
	}
	models, err := ListAvailableModels(account)
	if err != nil {
		return err
	}
	modelIDs := make([]string, 0, len(models))
	for _, m := range models {
		modelIDs = append(modelIDs, m.ModelId)
	}
	h.pool.SetModelList(account.ID, modelIDs)

	// 合并到聚合缓存
	h.modelsCacheMu.Lock()
	h.cachedModels = mergeUniqueModels(h.cachedModels, models)
	h.modelsCacheTime = time.Now().Unix()
	h.modelsCacheMu.Unlock()

	logger.Infof("[ModelsCache] Refreshed %d models for account %s", len(models), account.Email)
	return nil
}

// apiRefreshAccountModels POST /admin/api/accounts/{id}/models/refresh
// 立即为指定账号拉取并更新模型路由缓存。
func (h *Handler) apiRefreshAccountModels(w http.ResponseWriter, r *http.Request, id string) {
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
	// 从 pool 取运行时最新 token（与 refreshModelsCache 逻辑一致）
	if latest := h.pool.GetByID(id); latest != nil {
		account.AccessToken = latest.AccessToken
		account.RefreshToken = latest.RefreshToken
		account.ExpiresAt = latest.ExpiresAt
		account.ProfileArn = latest.ProfileArn
	}
	if err := h.fetchAndCacheAccountModels(account); err != nil {
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"count":   len(h.pool.GetModelList(id)),
	})
}

// apiRefreshAllAccountsModels POST /admin/api/accounts/models/refresh
// 直接复用 refreshModelsCache，为所有已启用账号刷新模型路由缓存。
func (h *Handler) apiRefreshAllAccountsModels(w http.ResponseWriter, r *http.Request) {
	h.refreshModelsCache()
	h.modelsCacheMu.RLock()
	cachedLen := len(h.cachedModels)
	h.modelsCacheMu.RUnlock()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":   true,
		"refreshed": cachedLen,
		"failed":    0,
	})
}

func mergeUniqueModels(existing []ModelInfo, incoming []ModelInfo) []ModelInfo {
	if len(incoming) == 0 {
		return existing
	}

	indexByID := make(map[string]int, len(existing))
	merged := make([]ModelInfo, len(existing))
	copy(merged, existing)
	for i, model := range merged {
		indexByID[strings.ToLower(strings.TrimSpace(model.ModelId))] = i
	}

	for _, model := range incoming {
		key := strings.ToLower(strings.TrimSpace(model.ModelId))
		if key == "" {
			continue
		}
		if idx, ok := indexByID[key]; ok {
			merged[idx] = mergeModelInfo(merged[idx], model)
			continue
		}
		indexByID[key] = len(merged)
		merged = append(merged, model)
	}

	return merged
}

func mergeModelInfo(base ModelInfo, extra ModelInfo) ModelInfo {
	if base.ModelName == "" {
		base.ModelName = extra.ModelName
	}
	if base.Description == "" {
		base.Description = extra.Description
	}
	if base.RateMultiplier == 0 {
		base.RateMultiplier = extra.RateMultiplier
	}
	if base.TokenLimits == nil {
		base.TokenLimits = extra.TokenLimits
	}
	base.InputTypes = mergeStringLists(base.InputTypes, extra.InputTypes)
	return base
}

func mergeStringLists(base []string, extra []string) []string {
	if len(extra) == 0 {
		return base
	}
	seen := make(map[string]bool, len(base)+len(extra))
	merged := make([]string, 0, len(base)+len(extra))
	for _, item := range base {
		key := strings.ToLower(strings.TrimSpace(item))
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		merged = append(merged, item)
	}
	for _, item := range extra {
		key := strings.ToLower(strings.TrimSpace(item))
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		merged = append(merged, item)
	}
	return merged
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

	var req ClaudeRequest
	if err := json.Unmarshal(body, &req); err != nil {
		h.sendClaudeError(w, 400, "invalid_request_error", "Invalid JSON")
		return
	}
	if msg := validateClaudeThinkingConfig(req.Thinking, req.MaxTokens); msg != "" {
		h.sendClaudeError(w, 400, "invalid_request_error", msg)
		return
	}

	thinkingCfg := config.GetThinkingConfig()
	actualModel, thinking := resolveClaudeThinkingMode(req.Model, req.Thinking, thinkingCfg.Suffix)
	req.Model = actualModel
	effectiveReq := cloneClaudeRequestForThinking(&req, thinking)

	estimatedTokens := estimateClaudeRequestInputTokens(effectiveReq)
	if estimatedTokens < 1 {
		estimatedTokens = 1
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(map[string]int{"input_tokens": estimatedTokens})
}

// handleClaudeMessages Claude API 处理
func (h *Handler) handleClaudeMessages(w http.ResponseWriter, r *http.Request) {
	h.handleClaudeMessagesInternal(w, r)
}

func (h *Handler) handleClaudeMessagesInternal(w http.ResponseWriter, r *http.Request) {
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
	if msg := validateClaudeRequestShape(&req); msg != "" {
		h.sendClaudeError(w, 400, "invalid_request_error", msg)
		return
	}
	normalizeStopHookJSON := isClaudeCodeStopHookEvaluatorRequest(&req)

	// Prefer the configured external provider. Keep the original request
	// immutable so a retryable external failure falls back to Kiro with the
	// client's model rather than a provider-specific mapped model.
	ext := config.GetExternalAPIConfig()
	if ext.Enabled && strings.TrimSpace(ext.BaseURL) != "" {
		externalReq := req
		origModel := strings.ToLower(externalReq.Model)
		switch {
		case strings.Contains(origModel, "opus") && ext.DefaultOpusModel != "":
			externalReq.Model = ext.DefaultOpusModel
		case strings.Contains(origModel, "sonnet") && ext.DefaultSonnetModel != "":
			externalReq.Model = ext.DefaultSonnetModel
		case strings.Contains(origModel, "haiku") && ext.DefaultHaikuModel != "":
			externalReq.Model = ext.DefaultHaikuModel
		case strings.Contains(origModel, "fable") && ext.DefaultSonnetModel != "":
			externalReq.Model = ext.DefaultSonnetModel
		case ext.DefaultModel != "":
			externalReq.Model = ext.DefaultModel
		}
		mappedLower := strings.ToLower(externalReq.Model)
		isOpenAICompatible := strings.Contains(ext.BaseURL, "localhost:5100") ||
			strings.Contains(mappedLower, "kimi") || strings.Contains(mappedLower, "gpt") ||
			strings.Contains(mappedLower, "gemini") || strings.Contains(mappedLower, "deepseek")
		if isOpenAICompatible {
			if h.proxyExternalClaudeToOpenAI(w, r, &externalReq, ext) {
				return
			}
		} else if h.proxyExternalClaude(w, r, body, &externalReq, ext, normalizeStopHookJSON) {
			return
		}
	}

	// 解析模型和 thinking 模式
	thinkingCfg := config.GetThinkingConfig()
	actualModel, thinking := resolveClaudeThinkingMode(req.Model, req.Thinking, thinkingCfg.Suffix)
	req.Model = actualModel
	effectiveReq := cloneClaudeRequestForThinking(&req, thinking)
	thinkingResponseOpts := resolveClaudeThinkingResponseOptions(req.Thinking, thinkingCfg.ClaudeFormat)
	estimatedInputTokens := estimateClaudeRequestInputTokens(effectiveReq)
	cacheProfile := h.promptCache.BuildClaudeProfile(effectiveReq, estimatedInputTokens)

	apiKeyID := apiKeyIDFromContext(r.Context())

	// Pure native web_search: relay via Kiro MCP (generateAssistantResponse does not run it).
	if hasWebSearchTool(&req) {
		h.handleWebSearchRequest(w, &req, estimatedInputTokens, apiKeyID)
		return
	}

	// Mixed tools including native web_search: agentic loop digests web_search internally
	// and returns client tool_use blocks as-is.
	if hasWebSearchAmongTools(&req) {
		logger.Infof("[WebSearch] Mixed tools with native web_search, entering agentic loop")
		h.runWebSearchLoop(r.Context(), w, &req, thinking, estimatedInputTokens, apiKeyID)
		return
	}

	// 转换请求
	kiroPayload := ClaudeToKiro(&req, thinking)

	// Stream or non-stream
	if req.Stream {
		h.handleClaudeStream(r.Context(), w, kiroPayload, req.Model, thinking, thinkingResponseOpts, estimatedInputTokens, cacheProfile, apiKeyID)
	} else {
		h.handleClaudeNonStream(r.Context(), w, kiroPayload, req.Model, thinking, thinkingResponseOpts, estimatedInputTokens, cacheProfile, apiKeyID)
	}
}

func (h *Handler) proxyExternalClaude(w http.ResponseWriter, r *http.Request, body []byte, req *ClaudeRequest, ext config.ExternalAPIConfig, normalizeStopHookJSON bool) bool {
	reqStart := time.Now()
	apiKeyID := apiKeyIDFromContext(r.Context())
	estimatedInputTokens := estimateClaudeRequestInputTokens(req)
	baseURL := strings.TrimSuffix(ext.BaseURL, "/")
	targetURL := baseURL
	displayURL := strings.TrimPrefix(strings.TrimPrefix(baseURL, "https://"), "http://")
	allowed, releaseProbe := externalCircuitAcquire(baseURL, time.Now())
	if !allowed {
		logger.Debugf("[ExternalAPI] Circuit open for %s; using Kiro account pool", displayURL)
		return false
	}
	defer releaseProbe()
	if strings.HasSuffix(targetURL, "/v1") {
		targetURL += "/messages"
	} else if !strings.HasSuffix(targetURL, "/v1/messages") && !strings.HasSuffix(targetURL, "/messages") {
		targetURL += "/v1/messages"
	}

	origModel := strings.ToLower(req.Model)
	mappedModel := req.Model
	if strings.Contains(origModel, "opus") && ext.DefaultOpusModel != "" {
		mappedModel = ext.DefaultOpusModel
	} else if strings.Contains(origModel, "sonnet") && ext.DefaultSonnetModel != "" {
		mappedModel = ext.DefaultSonnetModel
	} else if strings.Contains(origModel, "haiku") && ext.DefaultHaikuModel != "" {
		mappedModel = ext.DefaultHaikuModel
	} else if strings.Contains(origModel, "fable") && ext.DefaultSonnetModel != "" {
		mappedModel = ext.DefaultSonnetModel
	} else if ext.DefaultModel != "" {
		if ext.DefaultModel == "opus" && ext.DefaultOpusModel != "" {
			mappedModel = ext.DefaultOpusModel
		} else if ext.DefaultModel == "sonnet" && ext.DefaultSonnetModel != "" {
			mappedModel = ext.DefaultSonnetModel
		} else if ext.DefaultModel == "haiku" && ext.DefaultHaikuModel != "" {
			mappedModel = ext.DefaultHaikuModel
		} else {
			mappedModel = ext.DefaultModel
		}
	}

	originalStream := req.Stream
	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err == nil {
		payload["model"] = mappedModel
		payload["reasoning_effort"] = "xhigh"
		delete(payload, "thinking")
		if normalizeStopHookJSON {
			payload["stream"] = false
		}
		if updated, err := json.Marshal(payload); err == nil {
			body = updated
		}
	}

	clientTimeout := 10 * time.Minute
	if ext.TimeoutMS > 0 {
		clientTimeout = time.Duration(ext.TimeoutMS) * time.Millisecond
	}

	outReq, err := http.NewRequestWithContext(r.Context(), "POST", targetURL, bytes.NewReader(body))
	if err != nil {
		logger.Errorf("[ExternalAPI] Failed to create request: %v", err)
		return false
	}

	copyExternalClaudeHeaders(outReq.Header, r.Header)
	outReq.Header.Set("Content-Type", "application/json")
	apiKey := ext.APIKey
	if apiKey == "" {
		apiKey = ext.AuthToken
	}
	if apiKey != "" {
		outReq.Header.Set("x-api-key", apiKey)
		outReq.Header.Set("Authorization", "Bearer "+apiKey)
	}

	client := &http.Client{Timeout: clientTimeout}
	resp, err := client.Do(outReq)
	if err != nil {
		logger.Warnf("[ExternalAPI] Request to external URL %s failed: %v", targetURL, err)
		if cooldown, opened := externalCircuitFailure(baseURL, "", clientTimeout); opened {
			logger.Warnf("[ExternalAPI] Circuit opened for %s for %s after repeated transport failures", displayURL, cooldown)
		}
		return false
	}
	defer resp.Body.Close()
	if isRetryableExternalStatus(resp.StatusCode) {
		if cooldown, opened := externalCircuitFailure(baseURL, resp.Header.Get("Retry-After"), clientTimeout); opened {
			logger.Warnf("[ExternalAPI] Circuit opened for %s for %s after repeated HTTP %d responses", displayURL, cooldown, resp.StatusCode)
		}
		return false
	}
	if !req.Stream && !normalizeStopHookJSON {
		bodyBytes, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			if cooldown, opened := externalCircuitFailure(baseURL, "", clientTimeout); opened {
				logger.Warnf("[ExternalAPI] Circuit opened for %s for %s after response read failure", displayURL, cooldown)
			}
			return false
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			externalCircuitSuccess(baseURL)
		}
		for k, v := range resp.Header {
			w.Header()[k] = v
		}
		w.WriteHeader(resp.StatusCode)
		externalInputTokens, externalOutputTokens := externalClaudeUsageFromBody(bodyBytes)
		bodyBytes = bytes.ReplaceAll(bodyBytes, []byte(`"model":"`+mappedModel+`"`), []byte(`"model":"`+req.Model+`"`))
		_, _ = w.Write(bodyBytes)
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			if externalInputTokens <= 0 {
				externalInputTokens = estimatedInputTokens
			}
			h.recordSuccessForApiKey(apiKeyID, externalInputTokens, externalOutputTokens, 0)
			h.recordSuccessLog("claude", req.Model, displayURL, externalInputTokens+externalOutputTokens, 0, time.Since(reqStart).Milliseconds())
		} else {
			h.recordFailureWithDuration("claude", req.Model, displayURL, fmt.Errorf("HTTP %d", resp.StatusCode), time.Since(reqStart).Milliseconds())
		}
		return true
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		externalCircuitSuccess(baseURL)
	}

	if normalizeStopHookJSON {
		inputTokens, outputTokens := h.writeNormalizedExternalClaudeResponse(w, resp, mappedModel, originalStream)
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			if inputTokens <= 0 {
				inputTokens = estimatedInputTokens
			}
			h.recordSuccessForApiKey(apiKeyID, inputTokens, outputTokens, 0)
			h.recordSuccessLog("claude", req.Model, displayURL, inputTokens+outputTokens, 0, time.Since(reqStart).Milliseconds())
		} else {
			h.recordFailureWithDuration("claude", req.Model, displayURL, fmt.Errorf("HTTP %d", resp.StatusCode), time.Since(reqStart).Milliseconds())
		}
		return true
	}

	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(resp.StatusCode)

	var externalInputTokens, externalOutputTokens int
	if req.Stream {
		flusher, _ := w.(http.Flusher)
		reader := bufio.NewReader(resp.Body)
		targetPattern := []byte(`"model":"` + mappedModel + `"`)
		replacementPattern := []byte(`"model":"` + req.Model + `"`)
		for {
			line, err := reader.ReadBytes('\n')
			if len(line) > 0 {
				if inTok, outTok := externalClaudeUsageFromSSELine(line); inTok > 0 || outTok > 0 {
					externalInputTokens, externalOutputTokens = mergeExternalUsage(externalInputTokens, externalOutputTokens, inTok, outTok)
				}
				if bytes.Contains(line, targetPattern) {
					line = bytes.ReplaceAll(line, targetPattern, replacementPattern)
				}
				w.Write(line)
				if flusher != nil {
					flusher.Flush()
				}
			}
			if err != nil {
				break
			}
		}
	} else {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err == nil {
			externalInputTokens, externalOutputTokens = externalClaudeUsageFromBody(bodyBytes)
			bodyBytes = bytes.ReplaceAll(bodyBytes, []byte(`"model":"`+mappedModel+`"`), []byte(`"model":"`+req.Model+`"`))
			w.Write(bodyBytes)
		}
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if externalInputTokens <= 0 {
			externalInputTokens = estimatedInputTokens
		}
		h.recordSuccessForApiKey(apiKeyID, externalInputTokens, externalOutputTokens, 0)
		h.recordSuccessLog("claude", req.Model, displayURL, externalInputTokens+externalOutputTokens, 0, time.Since(reqStart).Milliseconds())
	} else {
		h.recordFailureWithDuration("claude", req.Model, displayURL, fmt.Errorf("HTTP %d", resp.StatusCode), time.Since(reqStart).Milliseconds())
	}
	return true
}

func copyExternalClaudeHeaders(dst, src http.Header) {
	for k, v := range src {
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "anthropic-") {
			dst[k] = v
		}
	}
}

func copyExternalOpenAIHeaders(dst, src http.Header) {
	for _, name := range []string{
		"User-Agent",
		"Openai-Organization",
		"Openai-Project",
		"Idempotency-Key",
		"X-Request-Id",
	} {
		if values := src.Values(name); len(values) > 0 {
			dst[name] = append([]string(nil), values...)
		}
	}
}

func (h *Handler) writeNormalizedExternalClaudeResponse(w http.ResponseWriter, resp *http.Response, model string, stream bool) (int, int) {
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		for k, v := range resp.Header {
			w.Header()[k] = v
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
		return 0, 0
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		h.sendClaudeError(w, 502, "api_error", "Failed to read external API response: "+err.Error())
		return 0, 0
	}

	claudeResp := normalizeClaudeStopHookResponseBody(body, model)
	if stream {
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		flusher, ok := w.(http.Flusher)
		if !ok {
			h.sendClaudeError(w, 500, "api_error", "Streaming not supported")
			return claudeResp.Usage.InputTokens, claudeResp.Usage.OutputTokens
		}
		h.sendClaudeBufferedTextStream(
			w,
			flusher,
			claudeResp.ID,
			claudeResp.Model,
			claudeResponseText(claudeResp),
			claudeResp.Usage.InputTokens,
			claudeResp.Usage.OutputTokens,
			promptCacheUsage{},
			false,
		)
		return claudeResp.Usage.InputTokens, claudeResp.Usage.OutputTokens
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(claudeResp)
	return claudeResp.Usage.InputTokens, claudeResp.Usage.OutputTokens
}

func externalClaudeUsageFromBody(body []byte) (int, int) {
	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		return 0, 0
	}
	return externalClaudeUsageFromMap(payload)
}

func externalClaudeUsageFromSSELine(line []byte) (int, int) {
	line = bytes.TrimSpace(line)
	if !bytes.HasPrefix(line, []byte("data:")) {
		return 0, 0
	}
	data := bytes.TrimSpace(bytes.TrimPrefix(line, []byte("data:")))
	if len(data) == 0 || bytes.Equal(data, []byte("[DONE]")) {
		return 0, 0
	}
	return externalClaudeUsageFromBody(data)
}

func externalClaudeUsageFromMap(payload map[string]interface{}) (int, int) {
	if payload == nil {
		return 0, 0
	}
	if message, ok := payload["message"].(map[string]interface{}); ok {
		if inTok, outTok := externalClaudeUsageFromMap(message); inTok > 0 || outTok > 0 {
			return inTok, outTok
		}
	}
	usage, ok := payload["usage"].(map[string]interface{})
	if !ok {
		return 0, 0
	}
	inputTokens := firstExternalUsageInt(usage, "input_tokens", "prompt_tokens", "inputTokens", "promptTokens")
	outputTokens := firstExternalUsageInt(usage, "output_tokens", "completion_tokens", "outputTokens", "completionTokens")
	if inputTokens <= 0 || outputTokens <= 0 {
		totalTokens := firstExternalUsageInt(usage, "total_tokens", "totalTokens")
		if inputTokens <= 0 && totalTokens > outputTokens {
			inputTokens = totalTokens - outputTokens
		}
		if outputTokens <= 0 && totalTokens > inputTokens {
			outputTokens = totalTokens - inputTokens
		}
	}
	return inputTokens, outputTokens
}

func firstExternalUsageInt(m map[string]interface{}, keys ...string) int {
	for _, key := range keys {
		if value, ok := m[key]; ok {
			switch v := value.(type) {
			case float64:
				return int(v)
			case int:
				return v
			case json.Number:
				if n, err := v.Int64(); err == nil {
					return int(n)
				}
			}
		}
	}
	return 0
}

func mergeExternalUsage(currentInput, currentOutput, newInput, newOutput int) (int, int) {
	if newInput > 0 {
		currentInput = newInput
	}
	if newOutput > 0 {
		currentOutput = newOutput
	}
	return currentInput, currentOutput
}

func normalizeClaudeStopHookResponseBody(body []byte, model string) *ClaudeResponse {
	var resp ClaudeResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		text := normalizeClaudeStopHookEvaluatorText(string(body))
		return KiroToClaudeResponse(text, "", false, nil, 1, estimateClaudeOutputTokens(text, "", nil), model, "end_turn")
	}
	normalizeClaudeStopHookResponse(&resp, model)
	return &resp
}

func normalizeClaudeStopHookResponse(resp *ClaudeResponse, model string) {
	text := normalizeClaudeStopHookEvaluatorText(claudeResponseText(resp))
	resp.Content = []ClaudeContentBlock{{
		Type: "text",
		Text: text,
	}}
	resp.StopReason = "end_turn"
	resp.StopSequence = nil
	if resp.ID == "" {
		resp.ID = "msg_" + uuid.New().String()
	}
	if resp.Type == "" {
		resp.Type = "message"
	}
	if resp.Role == "" {
		resp.Role = "assistant"
	}
	if resp.Model == "" {
		resp.Model = model
	}
	if resp.Usage.InputTokens <= 0 {
		resp.Usage.InputTokens = 1
	}
	resp.Usage.OutputTokens = estimateClaudeOutputTokens(text, "", nil)
}

func claudeResponseText(resp *ClaudeResponse) string {
	if resp == nil {
		return ""
	}
	var b strings.Builder
	for _, block := range resp.Content {
		if block.Type == "text" {
			b.WriteString(block.Text)
		}
	}
	return b.String()
}

// handleClaudeStream Claude 流式响应
func (h *Handler) handleClaudeStream(ctx context.Context, w http.ResponseWriter, payload *KiroPayload, model string, thinking bool, thinkingOpts claudeThinkingResponseOptions, estimatedInputTokens int, cacheProfile *promptCacheProfile, apiKeyID string) {
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		h.sendClaudeError(w, 500, "api_error", "Streaming not supported")
		return
	}

	// 获取 thinking 输出格式配置
	thinkingFormat := thinkingOpts.Format

	reqStart := time.Now()
	msgID := "msg_" + uuid.New().String()
	startInputTokens := estimatedInputTokens
	excluded := make(map[string]bool)
	var lastErr error
	messageStarted := false
	var messageStartUsage promptCacheUsage

	ensureMessageStart := func() {
		if messageStarted {
			return
		}
		h.sendSSE(w, flusher, "message_start", map[string]interface{}{
			"type": "message_start",
			"message": map[string]interface{}{
				"id":            msgID,
				"type":          "message",
				"role":          "assistant",
				"content":       []interface{}{},
				"model":         model,
				"stop_reason":   nil,
				"stop_sequence": nil,
				"usage":         buildClaudeUsageMap(startInputTokens, 0, messageStartUsage, cacheProfile != nil),
			},
		})
		messageStarted = true
	}

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
		cacheUsage := h.promptCache.Compute(account.ID, cacheProfile)
		messageStartUsage = cacheUsage

		var inputTokens, outputTokens int
		var credits float64
		var realInputTokens int
		var toolUses []KiroToolUse
		var upstreamStopReason string
		var nextContentIndex int
		var rawContentBuilder strings.Builder
		var rawThinkingBuilder strings.Builder
		activeBlockIndex := -1
		activeBlockType := ""

		closeActiveBlock := func() {
			if activeBlockIndex < 0 {
				return
			}
			h.sendSSE(w, flusher, "content_block_stop", map[string]interface{}{
				"type":  "content_block_stop",
				"index": activeBlockIndex,
			})
			activeBlockIndex = -1
			activeBlockType = ""
		}

		startContentBlock := func(blockType string) {
			if activeBlockType == blockType {
				return
			}
			ensureMessageStart()
			closeActiveBlock()

			idx := nextContentIndex
			nextContentIndex++

			if blockType == "thinking" {
				h.sendSSE(w, flusher, "content_block_start", map[string]interface{}{
					"type":  "content_block_start",
					"index": idx,
					"content_block": map[string]string{
						"type":     "thinking",
						"thinking": "",
					},
				})
			} else {
				h.sendSSE(w, flusher, "content_block_start", map[string]interface{}{
					"type":  "content_block_start",
					"index": idx,
					"content_block": map[string]string{
						"type": "text",
						"text": "",
					},
				})
			}

			activeBlockIndex = idx
			activeBlockType = blockType
		}

		var textBuffer string
		var inThinkingBlock bool
		var dropTagThinking bool
		var thinkingSource thinkingStreamSource
		var thinkingStarted bool
		var eventThinkingOpen bool

		sendText := func(text string, thinkingState int) {
			if thinkingState == 0 {
				if text == "" {
					return
				}
				startContentBlock("text")
				h.sendSSE(w, flusher, "content_block_delta", map[string]interface{}{
					"type":  "content_block_delta",
					"index": activeBlockIndex,
					"delta": map[string]string{"type": "text_delta", "text": text},
				})
				return
			}

			if !thinking {
				return
			}

			switch thinkingFormat {
			case "think":
				var outputText string
				switch thinkingState {
				case 1:
					outputText = "<think>" + text
				case 2:
					outputText = text
				case 3:
					outputText = text + "</think>"
				}
				if outputText == "" {
					return
				}
				startContentBlock("text")
				h.sendSSE(w, flusher, "content_block_delta", map[string]interface{}{
					"type":  "content_block_delta",
					"index": activeBlockIndex,
					"delta": map[string]string{"type": "text_delta", "text": outputText},
				})
			case "reasoning_content":
				if text == "" {
					return
				}
				startContentBlock("text")
				h.sendSSE(w, flusher, "content_block_delta", map[string]interface{}{
					"type":  "content_block_delta",
					"index": activeBlockIndex,
					"delta": map[string]string{"type": "text_delta", "text": text},
				})
			default:
				if thinkingOpts.OmitDisplay {
					if thinkingState == 1 {
						startContentBlock("thinking")
						return
					}
					if thinkingState == 3 {
						if activeBlockType != "thinking" {
							startContentBlock("thinking")
						}
						closeActiveBlock()
					}
					return
				}
				if thinkingState == 3 && text == "" {
					if activeBlockType == "thinking" {
						closeActiveBlock()
					}
					return
				}
				if text != "" {
					startContentBlock("thinking")
					h.sendSSE(w, flusher, "content_block_delta", map[string]interface{}{
						"type":  "content_block_delta",
						"index": activeBlockIndex,
						"delta": map[string]string{"type": "thinking_delta", "thinking": text},
					})
				}
				if thinkingState == 3 && activeBlockType == "thinking" {
					closeActiveBlock()
				}
			}
		}

		processClaudeText := func(text string, isThinking bool, forceFlush bool) {
			if isThinking && !thinking {
				return
			}

			if isThinking {
				if !allowReasoningSource(&thinkingSource) {
					return
				}
				if !thinkingStarted {
					sendText(text, 1)
					thinkingStarted = true
					eventThinkingOpen = true
				} else {
					sendText(text, 2)
				}
				return
			}

			if eventThinkingOpen {
				sendText("", 3)
				eventThinkingOpen = false
				thinkingStarted = false
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
						dropTagThinking = !allowTagSource(&thinkingSource)
						thinkingStarted = false
					} else if forceFlush || len([]rune(textBuffer)) > 50 {
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
						if !dropTagThinking {
							if !thinkingStarted {
								sendText(content, 1)
								sendText("", 3)
							} else {
								sendText(content, 3)
							}
						}
						textBuffer = textBuffer[thinkingEnd+11:]
						inThinkingBlock = false
						dropTagThinking = false
						thinkingStarted = false
					} else if forceFlush {
						if textBuffer != "" {
							if !dropTagThinking {
								if !thinkingStarted {
									sendText(textBuffer, 1)
									sendText("", 3)
								} else {
									sendText(textBuffer, 3)
								}
							}
							textBuffer = ""
						}
						inThinkingBlock = false
						dropTagThinking = false
						thinkingStarted = false
						break
					} else {
						runes := []rune(textBuffer)
						if len(runes) > 20 {
							safeLen := len(runes) - 15
							if safeLen > 0 {
								if !dropTagThinking {
									if !thinkingStarted {
										sendText(string(runes[:safeLen]), 1)
										thinkingStarted = true
									} else {
										sendText(string(runes[:safeLen]), 2)
									}
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
				if isThinking {
					rawThinkingBuilder.WriteString(text)
				} else {
					rawContentBuilder.WriteString(text)
				}
				processClaudeText(text, isThinking, false)
			},
			OnToolUse: func(tu KiroToolUse) {
				processClaudeText("", false, true)
				rawContentBuilder.WriteString(tu.Name)
				if b, err := json.Marshal(tu.Input); err == nil {
					rawContentBuilder.Write(b)
				}

				toolUses = append(toolUses, tu)
				ensureMessageStart()
				closeActiveBlock()

				idx := nextContentIndex
				nextContentIndex++

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
			OnCredits: func(c float64) {
				credits = c
			},
			OnContextUsage: func(pct float64) {
				realInputTokens = int(pct * float64(getContextWindowSize(model)) / 100.0)
			},
			OnStopReason: func(reason string) {
				upstreamStopReason = reason
			},
		}

		measure := func() (int, int, string, bool) {
			return rawContentBuilder.Len(), len(toolUses), upstreamStopReason, rawThinkingBuilder.Len() > 0
		}

		// A same-account retry only happens while nothing has been flushed, so
		// SSE block indices are still at their initial values and need no
		// rollback. What must be cleared is every accumulator plus the thinking
		// tag parser state: processClaudeText buffers up to 50 runes before
		// flushing, so a short truncated attempt can leave a partial tag behind
		// that would otherwise be prefixed onto the retry's first chunk.
		reset := func() {
			rawContentBuilder.Reset()
			rawThinkingBuilder.Reset()
			toolUses = nil
			inputTokens = 0
			outputTokens = 0
			credits = 0
			realInputTokens = 0
			upstreamStopReason = ""
			textBuffer = ""
			inThinkingBlock = false
			dropTagThinking = false
			thinkingSource = thinkingSourceUnknown
			thinkingStarted = false
			eventThinkingOpen = false
		}

		err := runKiroWithIntegrityRetry(ctx, account, payload, callback, measure, reset,
			func() bool { return !messageStarted })
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			lastErr = err
			excluded[account.ID] = true
			if !isStreamIntegrityError(err) {
				h.handleAccountFailure(account, err)
			}
			if !messageStarted {
				continue
			}
			h.recordFailureWithDetails("claude", model, account.ID, err)
			h.sendSSE(w, flusher, "error", map[string]interface{}{
				"type":  "error",
				"error": map[string]string{"type": "api_error", "message": err.Error()},
			})
			return
		}

		processClaudeText("", false, true)
		if eventThinkingOpen {
			sendText("", 3)
		}
		closeActiveBlock()

		if realInputTokens > 0 {
			inputTokens = realInputTokens
		} else if inputTokens <= 0 {
			inputTokens = estimatedInputTokens
		}
		outputContent, extractedReasoning := extractThinkingFromContent(rawContentBuilder.String())
		thinkingOutput := rawThinkingBuilder.String()
		if thinking && thinkingOutput == "" && extractedReasoning != "" {
			thinkingOutput = extractedReasoning
		}
		if !thinking {
			thinkingOutput = ""
		}
		outputTokens = estimateClaudeOutputTokens(outputContent, thinkingOutput, toolUses)

		h.recordSuccessForApiKey(apiKeyID, inputTokens, outputTokens, credits)
		h.pool.RecordSuccess(account.ID)
		h.pool.UpdateStats(account.ID, inputTokens+outputTokens, credits)
		h.promptCache.Update(account.ID, cacheProfile)
		h.recordSuccessLog("claude", model, account.ID, inputTokens+outputTokens, credits, time.Since(reqStart).Milliseconds())

		stopReason := mapClaudeStopReason(upstreamStopReason, len(toolUses))

		ensureMessageStart()
		h.sendSSE(w, flusher, "message_delta", map[string]interface{}{
			"type": "message_delta",
			"delta": map[string]interface{}{
				"stop_reason": stopReason,
			},
			"usage": buildClaudeUsageMap(inputTokens, outputTokens, cacheUsage, cacheProfile != nil),
		})

		h.sendSSE(w, flusher, "message_stop", map[string]interface{}{
			"type": "message_stop",
		})
		return
	}

	if lastErr == nil {
		h.sendClaudeError(w, 503, "api_error", "No available accounts")
		return
	}

	h.recordFailureWithDetails("claude", model, "", lastErr)
	setRetryAfterHeader(w, lastErr)
	h.sendClaudeError(w, upstreamErrorHTTPStatus(lastErr), "api_error", lastErr.Error())
}

func (h *Handler) sendClaudeBufferedTextStream(
	w http.ResponseWriter,
	flusher http.Flusher,
	msgID, model, text string,
	inputTokens, outputTokens int,
	cacheUsage promptCacheUsage,
	includeCache bool,
) {
	if msgID == "" {
		msgID = "msg_" + uuid.New().String()
	}
	if inputTokens <= 0 {
		inputTokens = 1
	}
	if outputTokens <= 0 {
		outputTokens = estimateClaudeOutputTokens(text, "", nil)
	}
	h.sendSSE(w, flusher, "message_start", map[string]interface{}{
		"type": "message_start",
		"message": map[string]interface{}{
			"id": msgID, "type": "message", "role": "assistant",
			"content": []interface{}{}, "model": model,
			"stop_reason": nil, "stop_sequence": nil,
			"usage": buildClaudeUsageMap(inputTokens, 0, cacheUsage, includeCache),
		},
	})
	if text != "" {
		h.sendSSE(w, flusher, "content_block_start", map[string]interface{}{
			"type": "content_block_start", "index": 0,
			"content_block": map[string]string{"type": "text", "text": ""},
		})
		h.sendSSE(w, flusher, "content_block_delta", map[string]interface{}{
			"type": "content_block_delta", "index": 0,
			"delta": map[string]string{"type": "text_delta", "text": text},
		})
		h.sendSSE(w, flusher, "content_block_stop", map[string]interface{}{"type": "content_block_stop", "index": 0})
	}
	h.sendSSE(w, flusher, "message_delta", map[string]interface{}{
		"type": "message_delta", "delta": map[string]interface{}{"stop_reason": "end_turn"},
		"usage": buildClaudeUsageMap(inputTokens, outputTokens, cacheUsage, includeCache),
	})
	h.sendSSE(w, flusher, "message_stop", map[string]interface{}{"type": "message_stop"})
}

func (h *Handler) sendSSE(w http.ResponseWriter, flusher http.Flusher, event string, data interface{}) {
	jsonData, _ := json.Marshal(data)
	fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, string(jsonData))
	flusher.Flush()
}

// backgroundStatsSaver 后台定时保存统计数据
func (h *Handler) backgroundStatsSaver() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			h.saveStats()
		case <-h.stopStatsSaver:
			h.saveStats() // 退出前保存一次
			return
		}
	}
}

// saveStats 保存统计到配置文件
func (h *Handler) saveStats() {
	config.UpdateStats(
		int(atomic.LoadInt64(&h.totalRequests)),
		int(atomic.LoadInt64(&h.successRequests)),
		int(atomic.LoadInt64(&h.failedRequests)),
		int(atomic.LoadInt64(&h.totalTokens)),
		h.getCredits(),
	)
}

// getCredits 线程安全获取 credits
func (h *Handler) getCredits() float64 {
	h.creditsMu.RLock()
	defer h.creditsMu.RUnlock()
	return h.totalCredits
}

// addCredits 线程安全增加 credits
func (h *Handler) addCredits(credits float64) {
	h.creditsMu.Lock()
	h.totalCredits += credits
	h.creditsMu.Unlock()
}

// 统计记录 (使用原子操作)
func (h *Handler) recordSuccess(inputTokens, outputTokens int, credits float64) {
	atomic.AddInt64(&h.totalRequests, 1)
	atomic.AddInt64(&h.successRequests, 1)
	atomic.AddInt64(&h.totalTokens, int64(inputTokens+outputTokens))
	h.addCredits(credits)
}

// recordSuccessForApiKey is recordSuccess + per-API-key usage attribution.
// When apiKeyID is empty (legacy single-key path or unauthenticated path), only the
// global counters are updated. Persistence errors are logged but do not propagate.
func (h *Handler) recordSuccessForApiKey(apiKeyID string, inputTokens, outputTokens int, credits float64) {
	h.recordSuccess(inputTokens, outputTokens, credits)
	if apiKeyID == "" {
		return
	}
	if err := config.RecordApiKeyUsage(apiKeyID, int64(inputTokens+outputTokens), credits); err != nil {
		logger.Warnf("[ApiKey] failed to record usage for key %s: %v", apiKeyID, err)
	}
}

// recordFailureWithDetails records a failure and stores it in the request logs.
func (h *Handler) recordFailureWithDetails(endpoint, model, accountID string, err error) {
	h.recordFailureWithDuration(endpoint, model, accountID, err, 0)
}

func (h *Handler) recordFailureWithDuration(endpoint, model, accountID string, err error, durationMs int64) {
	atomic.AddInt64(&h.totalRequests, 1)
	atomic.AddInt64(&h.failedRequests, 1)

	if err == nil {
		return
	}

	errMsg := err.Error()
	errType := classifyError(errMsg)

	entry := RequestLog{
		Time:      time.Now().Unix(),
		Endpoint:  endpoint,
		Model:     model,
		AccountID: accountID,
		Status:    "error",
		Error:     errMsg,
		ErrorType: errType,
		Duration:  durationMs,
	}

	h.appendRequestLog(entry)
}

// recordSuccessLog records a successful request in the request logs.
func (h *Handler) recordSuccessLog(endpoint, model, accountID string, tokens int, credits float64, durationMs int64) {
	entry := RequestLog{
		Time:      time.Now().Unix(),
		Endpoint:  endpoint,
		Model:     model,
		AccountID: accountID,
		Status:    "success",
		Tokens:    tokens,
		Credits:   credits,
		Duration:  durationMs,
	}

	h.appendRequestLog(entry)
}

func (h *Handler) appendRequestLog(entry RequestLog) {
	h.requestLogsMu.Lock()
	if h.requestLogs == nil {
		h.requestLogs = make([]RequestLog, 0, requestLogsMaxSize)
	}
	if len(h.requestLogs) >= requestLogsMaxSize {
		h.requestLogs = h.requestLogs[1:]
	}
	h.requestLogs = append(h.requestLogs, entry)
	h.requestLogsMu.Unlock()
}

// classifyError categorizes an error message into a type for display.
func classifyError(msg string) string {
	switch {
	case isQuotaErrorMessage(msg):
		return "quota"
	case isOverageErrorMessage(msg):
		return "overage"
	case isSuspensionErrorMessage(msg):
		return "suspended"
	case isAuthErrorMessage(msg):
		return "auth"
	case isProfileUnavailableErrorMessage(msg):
		return "profile"
	default:
		return "unknown"
	}
}

// getRequestLogs returns a copy of request logs (newest first).
func (h *Handler) getRequestLogs() []RequestLog {
	h.requestLogsMu.RLock()
	defer h.requestLogsMu.RUnlock()
	if len(h.requestLogs) == 0 {
		return []RequestLog{}
	}
	result := make([]RequestLog, len(h.requestLogs))
	for i, e := range h.requestLogs {
		result[len(h.requestLogs)-1-i] = e
	}
	return result
}

// handleClaudeNonStream Claude 非流式响应
func (h *Handler) handleClaudeNonStream(ctx context.Context, w http.ResponseWriter, payload *KiroPayload, model string, thinking bool, thinkingOpts claudeThinkingResponseOptions, estimatedInputTokens int, cacheProfile *promptCacheProfile, apiKeyID string) {
	excluded := make(map[string]bool)
	var lastErr error
	reqStart := time.Now()

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
		cacheUsage := h.promptCache.Compute(account.ID, cacheProfile)

		var content string
		var thinkingContent string
		var toolUses []KiroToolUse
		var inputTokens, outputTokens int
		var credits float64
		var realInputTokens int
		var upstreamStopReason string

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
			OnCredits: func(c float64) {
				credits = c
			},
			OnContextUsage: func(pct float64) {
				realInputTokens = int(pct * float64(getContextWindowSize(model)) / 100.0)
			},
			OnStopReason: func(reason string) {
				upstreamStopReason = reason
			},
		}

		measure := func() (int, int, string, bool) {
			return len(content), len(toolUses), upstreamStopReason, thinkingContent != ""
		}

		reset := func() {
			content = ""
			thinkingContent = ""
			toolUses = nil
			inputTokens = 0
			outputTokens = 0
			credits = 0
			realInputTokens = 0
			upstreamStopReason = ""
		}

		// Fully buffered: nothing reaches the client until the response is
		// encoded, so a retry can never duplicate output.
		err := runKiroWithIntegrityRetry(ctx, account, payload, callback, measure, reset, nil)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			lastErr = err
			excluded[account.ID] = true
			if !isStreamIntegrityError(err) {
				h.handleAccountFailure(account, err)
			}
			continue
		}

		thinkingFormat := thinkingOpts.Format
		finalContent, extractedReasoning := extractThinkingFromContent(content)
		rawThinkingContent := thinkingContent
		if thinking && rawThinkingContent == "" && extractedReasoning != "" {
			rawThinkingContent = extractedReasoning
		}
		if !thinking {
			rawThinkingContent = ""
		}

		if realInputTokens > 0 {
			inputTokens = realInputTokens
		} else if inputTokens <= 0 {
			inputTokens = estimatedInputTokens
		}
		outputTokens = estimateClaudeOutputTokens(finalContent, rawThinkingContent, toolUses)

		h.recordSuccessForApiKey(apiKeyID, inputTokens, outputTokens, credits)
		h.pool.RecordSuccess(account.ID)
		h.pool.UpdateStats(account.ID, inputTokens+outputTokens, credits)
		h.promptCache.Update(account.ID, cacheProfile)
		h.recordSuccessLog("claude", model, account.ID, inputTokens+outputTokens, credits, time.Since(reqStart).Milliseconds())

		responseThinkingContent := rawThinkingContent
		includeEmptyThinkingBlock := thinking && thinkingOpts.OmitDisplay && rawThinkingContent != ""
		if includeEmptyThinkingBlock {
			responseThinkingContent = ""
		}

		if thinking && responseThinkingContent != "" {
			switch thinkingFormat {
			case "think":
				finalContent = "<think>" + responseThinkingContent + "</think>" + finalContent
				responseThinkingContent = ""
			case "reasoning_content":
				finalContent = responseThinkingContent + finalContent
				responseThinkingContent = ""
			default:
			}
		}

		resp := KiroToClaudeResponse(finalContent, responseThinkingContent, includeEmptyThinkingBlock, toolUses, inputTokens, outputTokens, model, upstreamStopReason)
		resp.Usage.InputTokens = billedClaudeInputTokens(inputTokens, cacheUsage)
		resp.Usage.CacheCreationInputTokens = cacheUsage.CacheCreationInputTokens
		resp.Usage.CacheReadInputTokens = cacheUsage.CacheReadInputTokens
		if cacheProfile != nil {
			resp.Usage.CacheCreation = &ClaudeCacheCreationUsage{
				Ephemeral5mInputTokens: cacheUsage.CacheCreation5mInputTokens,
				Ephemeral1hInputTokens: cacheUsage.CacheCreation1hInputTokens,
			}
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		json.NewEncoder(w).Encode(resp)
		return
	}

	if lastErr == nil {
		h.sendClaudeError(w, 503, "api_error", "No available accounts")
		return
	}

	h.recordFailureWithDetails("claude", model, "", lastErr)
	setRetryAfterHeader(w, lastErr)
	h.sendClaudeError(w, upstreamErrorHTTPStatus(lastErr), "api_error", lastErr.Error())
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

func (h *Handler) proxyExternalOpenAI(w http.ResponseWriter, r *http.Request, body []byte, req *OpenAIRequest, ext config.ExternalAPIConfig) bool {
	reqStart := time.Now()
	apiKeyID := apiKeyIDFromContext(r.Context())
	estimatedInputTokens := estimateOpenAIRequestInputTokens(req)
	baseURL := strings.TrimSuffix(ext.BaseURL, "/")
	targetURL := baseURL
	displayURL := strings.TrimPrefix(strings.TrimPrefix(baseURL, "https://"), "http://")
	allowed, releaseProbe := externalCircuitAcquire(baseURL, time.Now())
	if !allowed {
		logger.Debugf("[ExternalAPI] Circuit open for %s; using Kiro account pool", displayURL)
		return false
	}
	defer releaseProbe()
	if strings.HasSuffix(targetURL, "/v1") {
		targetURL += "/chat/completions"
	} else if !strings.HasSuffix(targetURL, "/v1/chat/completions") && !strings.HasSuffix(targetURL, "/chat/completions") {
		targetURL += "/v1/chat/completions"
	}

	mappedModel := req.Model
	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err == nil {
		payload["model"] = mappedModel
		if updated, err := json.Marshal(payload); err == nil {
			body = updated
		}
	}

	clientTimeout := 10 * time.Minute
	if ext.TimeoutMS > 0 {
		clientTimeout = time.Duration(ext.TimeoutMS) * time.Millisecond
	}

	outReq, err := http.NewRequestWithContext(r.Context(), "POST", targetURL, bytes.NewReader(body))
	if err != nil {
		logger.Errorf("[ExternalAPI] Failed to create OpenAI request: %v", err)
		return false
	}

	outReq.Header.Set("Content-Type", "application/json")
	if ext.AuthToken != "" {
		outReq.Header.Set("Authorization", "Bearer "+ext.AuthToken)
	} else if ext.APIKey != "" {
		outReq.Header.Set("Authorization", "Bearer "+ext.APIKey)
	}

	copyExternalOpenAIHeaders(outReq.Header, r.Header)

	client := &http.Client{Timeout: clientTimeout}
	resp, err := client.Do(outReq)
	if err != nil {
		if cooldown, opened := externalCircuitFailure(baseURL, "", clientTimeout); opened {
			logger.Warnf("[ExternalAPI] Circuit opened for %s for %s after repeated transport failures", displayURL, cooldown)
		}
		h.recordFailureWithDuration("openai", req.Model, displayURL, err, time.Since(reqStart).Milliseconds())
		return false
	}
	defer resp.Body.Close()
	if isRetryableExternalStatus(resp.StatusCode) {
		if cooldown, opened := externalCircuitFailure(baseURL, resp.Header.Get("Retry-After"), clientTimeout); opened {
			logger.Warnf("[ExternalAPI] Circuit opened for %s for %s after repeated HTTP %d responses", displayURL, cooldown, resp.StatusCode)
		}
		h.recordFailureWithDuration("openai", req.Model, displayURL, fmt.Errorf("HTTP %d", resp.StatusCode), time.Since(reqStart).Milliseconds())
		return false
	}
	if !req.Stream {
		bodyBytes, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			if cooldown, opened := externalCircuitFailure(baseURL, "", clientTimeout); opened {
				logger.Warnf("[ExternalAPI] Circuit opened for %s for %s after response read failure", displayURL, cooldown)
			}
			return false
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			externalCircuitSuccess(baseURL)
		}
		if resp.StatusCode >= 400 {
			h.recordFailureWithDuration("openai", req.Model, displayURL, fmt.Errorf("HTTP %d", resp.StatusCode), time.Since(reqStart).Milliseconds())
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(resp.StatusCode)
			_, _ = w.Write(bodyBytes)
			return true
		}
		var externalInputTokens, externalOutputTokens int
		var respObj map[string]interface{}
		if err := json.Unmarshal(bodyBytes, &respObj); err == nil {
			if usage, ok := respObj["usage"].(map[string]interface{}); ok {
				if pTok, ok := usage["prompt_tokens"].(float64); ok {
					externalInputTokens = int(pTok)
				}
				if cTok, ok := usage["completion_tokens"].(float64); ok {
					externalOutputTokens = int(cTok)
				}
			}
		}
		bodyBytes = bytes.ReplaceAll(bodyBytes, []byte(`"model":"`+mappedModel+`"`), []byte(`"model":"`+req.Model+`"`))
		for k, v := range resp.Header {
			w.Header()[k] = v
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(bodyBytes)
		if externalInputTokens <= 0 {
			externalInputTokens = estimatedInputTokens
		}
		h.recordSuccessForApiKey(apiKeyID, externalInputTokens, externalOutputTokens, 0)
		h.recordSuccessLog("openai", req.Model, displayURL, externalInputTokens+externalOutputTokens, 0, time.Since(reqStart).Milliseconds())
		return true
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		externalCircuitSuccess(baseURL)
	}

	if resp.StatusCode >= 400 {
		h.recordFailureWithDuration("openai", req.Model, displayURL, fmt.Errorf("HTTP %d", resp.StatusCode), time.Since(reqStart).Milliseconds())
		bodyBytes, _ := io.ReadAll(resp.Body)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(resp.StatusCode)
		w.Write(bodyBytes)
		return true
	}

	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(resp.StatusCode)

	var externalInputTokens, externalOutputTokens int
	if req.Stream {
		flusher, _ := w.(http.Flusher)
		reader := bufio.NewReader(resp.Body)
		for {
			line, err := reader.ReadBytes('\n')
			if len(line) > 0 {
				w.Write(line)
				if flusher != nil {
					flusher.Flush()
				}
			}
			if err != nil {
				break
			}
		}
	} else {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err == nil {
			var respObj map[string]interface{}
			if err := json.Unmarshal(bodyBytes, &respObj); err == nil {
				if usage, ok := respObj["usage"].(map[string]interface{}); ok {
					if pTok, ok := usage["prompt_tokens"].(float64); ok {
						externalInputTokens = int(pTok)
					}
					if cTok, ok := usage["completion_tokens"].(float64); ok {
						externalOutputTokens = int(cTok)
					}
				}
			}
			bodyBytes = bytes.ReplaceAll(bodyBytes, []byte(`"model":"`+mappedModel+`"`), []byte(`"model":"`+req.Model+`"`))
			w.Write(bodyBytes)
		}
	}

	if externalInputTokens <= 0 {
		externalInputTokens = estimatedInputTokens
	}
	h.recordSuccessForApiKey(apiKeyID, externalInputTokens, externalOutputTokens, 0)
	h.recordSuccessLog("openai", req.Model, displayURL, externalInputTokens+externalOutputTokens, 0, time.Since(reqStart).Milliseconds())
	return true
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
	if msg := validateOpenAIRequestShape(&req); msg != "" {
		h.sendOpenAIError(w, 400, "invalid_request_error", msg)
		return
	}

	// 解析模型和 thinking 模式
	thinkingCfg := config.GetThinkingConfig()
	actualModel, thinking := ParseModelAndThinking(req.Model, thinkingCfg.Suffix)
	req.Model = actualModel
	estimatedInputTokens := estimateOpenAIRequestInputTokens(&req)

	kiroPayload := OpenAIToKiro(&req, thinking)

	apiKeyID := apiKeyIDFromContext(r.Context())
	if req.Stream {
		h.handleOpenAIStream(r.Context(), w, kiroPayload, req.Model, thinking, estimatedInputTokens, apiKeyID)
	} else {
		h.handleOpenAINonStream(r.Context(), w, kiroPayload, req.Model, thinking, estimatedInputTokens, apiKeyID)
	}
}

// handleOpenAIStream OpenAI 流式响应
func (h *Handler) handleOpenAIStream(ctx context.Context, w http.ResponseWriter, payload *KiroPayload, model string, thinking bool, estimatedInputTokens int, apiKeyID string) {
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
	excluded := make(map[string]bool)
	var lastErr error
	reqStart := time.Now()

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

		var upstreamStopReason string
		var toolCalls []ToolCall
		var toolCallIndex int
		var inputTokens, outputTokens int
		var credits float64
		var realInputTokens int
		var rawContentBuilder strings.Builder
		var rawReasoningBuilder strings.Builder
		var textBuffer string
		var inThinkingBlock bool
		var dropTagThinking bool
		var thinkingSource thinkingStreamSource
		var thinkingStarted bool
		var eventThinkingOpen bool
		responseStarted := false

		sendStreamError := func(err error) {
			data, _ := json.Marshal(map[string]interface{}{
				"error": map[string]string{
					"message": err.Error(),
					"type":    "server_error",
				},
			})
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}

		sendChunk := func(content string, thinkingState int) {
			if content == "" && thinkingState == 2 {
				return
			}

			var chunk map[string]interface{}

			if thinkingState > 0 {
				if !thinking {
					return
				}
				switch thinkingFormat {
				case "thinking":
					var text string
					switch thinkingState {
					case 1:
						text = "<thinking>" + content
					case 2:
						text = content
					case 3:
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
				default:
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
			responseStarted = true
		}

		processText := func(text string, isThinking bool, forceFlush bool) {
			if isThinking && !thinking {
				return
			}

			if isThinking {
				if !allowReasoningSource(&thinkingSource) {
					return
				}
				if !thinkingStarted {
					sendChunk(text, 1)
					thinkingStarted = true
					eventThinkingOpen = true
				} else {
					sendChunk(text, 2)
				}
				return
			}

			if eventThinkingOpen {
				sendChunk("", 3)
				eventThinkingOpen = false
				thinkingStarted = false
			}

			textBuffer += text

			for {
				if !inThinkingBlock {
					thinkingStart := strings.Index(textBuffer, "<thinking>")
					if thinkingStart != -1 {
						if thinkingStart > 0 {
							sendChunk(textBuffer[:thinkingStart], 0)
						}
						textBuffer = textBuffer[thinkingStart+10:]
						inThinkingBlock = true
						dropTagThinking = !allowTagSource(&thinkingSource)
						thinkingStarted = false
					} else if forceFlush || len([]rune(textBuffer)) > 50 {
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
					thinkingEnd := strings.Index(textBuffer, "</thinking>")
					if thinkingEnd != -1 {
						content := textBuffer[:thinkingEnd]
						if !dropTagThinking {
							if !thinkingStarted {
								sendChunk(content, 1)
								sendChunk("", 3)
							} else {
								sendChunk(content, 3)
							}
						}
						textBuffer = textBuffer[thinkingEnd+11:]
						inThinkingBlock = false
						dropTagThinking = false
						thinkingStarted = false
					} else if forceFlush {
						if textBuffer != "" {
							if !dropTagThinking {
								if !thinkingStarted {
									sendChunk(textBuffer, 1)
									sendChunk("", 3)
								} else {
									sendChunk(textBuffer, 3)
								}
							}
							textBuffer = ""
						}
						inThinkingBlock = false
						dropTagThinking = false
						thinkingStarted = false
						break
					} else {
						runes := []rune(textBuffer)
						if len(runes) > 20 {
							safeLen := len(runes) - 15
							if safeLen > 0 {
								if !dropTagThinking {
									if !thinkingStarted {
										sendChunk(string(runes[:safeLen]), 1)
										thinkingStarted = true
									} else {
										sendChunk(string(runes[:safeLen]), 2)
									}
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
				if isThinking {
					rawReasoningBuilder.WriteString(text)
				} else {
					rawContentBuilder.WriteString(text)
				}
				processText(text, isThinking, false)
			},
			OnToolUse: func(tu KiroToolUse) {
				processText("", false, true)

				args, _ := json.Marshal(tu.Input)
				rawContentBuilder.WriteString(tu.Name)
				rawContentBuilder.Write(args)
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
				responseStarted = true
			},
			OnStopReason: func(reason string) {
				upstreamStopReason = reason
			},
			OnComplete: func(inTok, outTok int) {
				inputTokens = inTok
				outputTokens = outTok
			},
			OnCredits: func(c float64) {
				credits = c
			},
			OnContextUsage: func(pct float64) {
				realInputTokens = int(pct * float64(getContextWindowSize(model)) / 100.0)
			},
		}

		measure := func() (int, int, string, bool) {
			return rawContentBuilder.Len(), len(toolCalls), upstreamStopReason, rawReasoningBuilder.Len() > 0
		}

		// Retries only happen before anything is flushed, so chunk indices stay
		// valid. The thinking tag parser state must be cleared too: processText
		// holds back up to 50 runes, so a short truncated attempt would
		// otherwise prepend its leftovers to the retry's first chunk.
		reset := func() {
			rawContentBuilder.Reset()
			rawReasoningBuilder.Reset()
			toolCalls = nil
			toolCallIndex = 0
			inputTokens = 0
			outputTokens = 0
			credits = 0
			realInputTokens = 0
			upstreamStopReason = ""
			textBuffer = ""
			inThinkingBlock = false
			dropTagThinking = false
			thinkingSource = thinkingSourceUnknown
			thinkingStarted = false
			eventThinkingOpen = false
		}

		err := runKiroWithIntegrityRetry(ctx, account, payload, callback, measure, reset,
			func() bool { return !responseStarted })
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			lastErr = err
			excluded[account.ID] = true
			// Integrity failures are upstream hiccups, not account faults.
			if !isStreamIntegrityError(err) {
				h.handleAccountFailure(account, err)
			}
			if !responseStarted {
				continue
			}
			h.recordFailureWithDetails("openai", model, account.ID, err)
			sendStreamError(err)
			return
		}

		processText("", false, true)
		if eventThinkingOpen {
			sendChunk("", 3)
		}

		if realInputTokens > 0 {
			inputTokens = realInputTokens
		} else if inputTokens <= 0 {
			inputTokens = estimatedInputTokens
		}
		outputContent, extractedReasoning := extractThinkingFromContent(rawContentBuilder.String())
		reasoningOutput := rawReasoningBuilder.String()
		if thinking && reasoningOutput == "" && extractedReasoning != "" {
			reasoningOutput = extractedReasoning
		}
		if !thinking {
			reasoningOutput = ""
		}
		outputTokens = estimateApproxTokens(outputContent) + estimateApproxTokens(reasoningOutput)
		for _, tc := range toolCalls {
			outputTokens += estimateApproxTokens(tc.Function.Name)
			outputTokens += estimateApproxTokens(tc.Function.Arguments)
		}

		h.recordSuccessForApiKey(apiKeyID, inputTokens, outputTokens, credits)
		h.pool.RecordSuccess(account.ID)
		h.pool.UpdateStats(account.ID, inputTokens+outputTokens, credits)
		h.recordSuccessLog("openai", model, account.ID, inputTokens+outputTokens, credits, time.Since(reqStart).Milliseconds())
		finishReason := mapOpenAIFinishReason(upstreamStopReason, len(toolCalls))

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
			"usage": map[string]int{
				"prompt_tokens":     inputTokens,
				"completion_tokens": outputTokens,
				"total_tokens":      inputTokens + outputTokens,
			},
		}
		data, _ := json.Marshal(chunk)
		fmt.Fprintf(w, "data: %s\n\n", string(data))
		fmt.Fprintf(w, "data: [DONE]\n\n")
		flusher.Flush()
		return
	}

	if lastErr == nil {
		h.sendOpenAIError(w, 503, "server_error", "No available accounts")
		return
	}

	h.recordFailureWithDetails("openai", model, "", lastErr)
	setRetryAfterHeader(w, lastErr)
	h.sendOpenAIError(w, upstreamErrorHTTPStatus(lastErr), "server_error", lastErr.Error())
}

// handleOpenAINonStream OpenAI 非流式响应
func (h *Handler) handleOpenAINonStream(ctx context.Context, w http.ResponseWriter, payload *KiroPayload, model string, thinking bool, estimatedInputTokens int, apiKeyID string) {
	excluded := make(map[string]bool)
	var lastErr error
	reqStart := time.Now()

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

		var content string
		var reasoningContent string
		var toolUses []KiroToolUse
		var inputTokens, outputTokens int
		var credits float64
		var realInputTokens int
		var upstreamStopReason string

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
			OnCredits:  func(c float64) { credits = c },
			OnContextUsage: func(pct float64) {
				realInputTokens = int(pct * float64(getContextWindowSize(model)) / 100.0)
			},
			OnStopReason: func(reason string) {
				upstreamStopReason = reason
			},
		}

		measure := func() (int, int, string, bool) {
			return len(content), len(toolUses), upstreamStopReason, reasoningContent != ""
		}

		reset := func() {
			content = ""
			reasoningContent = ""
			toolUses = nil
			inputTokens = 0
			outputTokens = 0
			credits = 0
			realInputTokens = 0
			upstreamStopReason = ""
		}

		// Fully buffered: nothing reaches the client until the response is
		// encoded, so a retry can never duplicate output.
		err := runKiroWithIntegrityRetry(ctx, account, payload, callback, measure, reset, nil)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			lastErr = err
			excluded[account.ID] = true
			// Integrity failures are upstream hiccups, not account faults.
			if !isStreamIntegrityError(err) {
				h.handleAccountFailure(account, err)
			}
			continue
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
		outputTokens = estimateOpenAIOutputTokens(finalContent, reasoningContent, toolUses)

		h.recordSuccessForApiKey(apiKeyID, inputTokens, outputTokens, credits)
		h.pool.RecordSuccess(account.ID)
		h.pool.UpdateStats(account.ID, inputTokens+outputTokens, credits)
		h.recordSuccessLog("openai", model, account.ID, inputTokens+outputTokens, credits, time.Since(reqStart).Milliseconds())

		thinkingFormat := config.GetThinkingConfig().OpenAIFormat
		resp := KiroToOpenAIResponseWithReasoning(finalContent, reasoningContent, toolUses, inputTokens, outputTokens, model, thinkingFormat, upstreamStopReason)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		json.NewEncoder(w).Encode(resp)
		return
	}

	if lastErr == nil {
		h.sendOpenAIError(w, 503, "server_error", "No available accounts")
		return
	}

	h.recordFailureWithDetails("openai", model, "", lastErr)
	setRetryAfterHeader(w, lastErr)
	h.sendOpenAIError(w, upstreamErrorHTTPStatus(lastErr), "server_error", lastErr.Error())
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

// refreshAccountToken serializes the complete refresh-token rotation lifecycle:
// load the latest persisted credential, refresh it, persist any rotation, and
// only then publish it to the runtime pool. A single lock is intentionally used
// across accounts because refreshes are rare and this keeps every refresh entry
// point consistent.
func (h *Handler) refreshAccountToken(account *config.Account, force bool) (bool, error) {
	if account == nil || strings.TrimSpace(account.ID) == "" {
		return false, fmt.Errorf("account is required for token refresh")
	}

	h.tokenRefreshMu.Lock()
	defer h.tokenRefreshMu.Unlock()

	var latest *config.Account
	accounts := config.GetAccounts()
	for i := range accounts {
		if accounts[i].ID == account.ID {
			latest = &accounts[i]
			break
		}
	}
	if latest == nil {
		return false, fmt.Errorf("account %s no longer exists", account.ID)
	}
	working := *latest

	// API Key credentials never expire and cannot be OAuth-refreshed.
	if config.IsAPIKeyAccount(&working) {
		token := strings.TrimSpace(working.KiroApiKey)
		if token == "" {
			token = strings.TrimSpace(working.AccessToken)
		}
		if token == "" {
			return false, fmt.Errorf("account %s has no kiroApiKey", working.ID)
		}
		h.pool.UpdateCredentialState(
			account,
			working.ID,
			token,
			"",
			0,
			"",
		)
		return false, nil
	}

	if !force && (working.ExpiresAt == 0 || time.Now().Unix() < working.ExpiresAt-tokenRefreshSkewSeconds) {
		h.pool.UpdateCredentialState(
			account,
			working.ID,
			working.AccessToken,
			working.RefreshToken,
			working.ExpiresAt,
			working.ProfileArn,
		)
		return false, nil
	}
	if strings.TrimSpace(working.RefreshToken) == "" {
		return false, fmt.Errorf("account %s has no refresh token", working.ID)
	}

	accessToken, refreshToken, expiresAt, profileArn, err := auth.RefreshToken(&working)
	if err != nil {
		return false, err
	}
	if refreshToken == "" {
		refreshToken = working.RefreshToken
	}

	if err := config.UpdateAccountCredentialState(
		working.ID,
		accessToken,
		refreshToken,
		expiresAt,
		profileArn,
	); err != nil {
		return false, fmt.Errorf("persist refreshed token for account %s: %w", working.ID, err)
	}

	// Do not expose a rotated credential through the pool until persistence has
	// succeeded. This ordering prevents a later refresh from reading stale state.
	h.pool.UpdateCredentialState(
		account,
		working.ID,
		accessToken,
		refreshToken,
		expiresAt,
		profileArn,
	)
	return true, nil
}

// ensureValidToken 确保 token 有效
func (h *Handler) ensureValidToken(account *config.Account) error {
	if config.IsAPIKeyAccount(account) {
		if accountBearerToken(account) == "" {
			return fmt.Errorf("account %s has no kiroApiKey", account.ID)
		}
		return nil
	}
	if account.ExpiresAt == 0 || time.Now().Unix() < account.ExpiresAt-tokenRefreshSkewSeconds {
		return nil
	}

	_, err := h.refreshAccountToken(account, false)
	return err
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
	case path == "/accounts/batch" && r.Method == "POST":
		h.apiBatchAccounts(w, r)
	// models/refresh 必须在通用 /refresh 前匹配，否则会被误拦截
	case path == "/accounts/models/refresh" && r.Method == "POST":
		h.apiRefreshAllAccountsModels(w, r)
	case strings.HasPrefix(path, "/accounts/") && strings.HasSuffix(path, "/models/refresh") && r.Method == "POST":
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/accounts/"), "/models/refresh")
		h.apiRefreshAccountModels(w, r, id)
	case strings.HasPrefix(path, "/accounts/") && strings.HasSuffix(path, "/refresh") && r.Method == "POST":
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/accounts/"), "/refresh")
		h.apiRefreshAccount(w, r, id)
	case strings.HasPrefix(path, "/accounts/") && strings.HasSuffix(path, "/test") && r.Method == "POST":
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/accounts/"), "/test")
		h.apiTestAccount(w, r, id)
	case strings.HasPrefix(path, "/accounts/") && strings.HasSuffix(path, "/models/cached") && r.Method == "GET":
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/accounts/"), "/models/cached")
		h.apiGetAccountModelsCached(w, r, id)
	case strings.HasPrefix(path, "/accounts/") && strings.HasSuffix(path, "/models") && r.Method == "GET":
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/accounts/"), "/models")
		h.apiGetAccountModels(w, r, id)

	case strings.HasPrefix(path, "/accounts/") && strings.HasSuffix(path, "/overage") && r.Method == "POST":
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/accounts/"), "/overage")
		h.apiSetAccountOverage(w, r, id)
	case strings.HasPrefix(path, "/accounts/") && strings.HasSuffix(path, "/overage") && r.Method == "GET":
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/accounts/"), "/overage")
		h.apiGetAccountOverage(w, r, id)

	case strings.HasPrefix(path, "/accounts/") && strings.HasSuffix(path, "/full") && r.Method == "GET":
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/accounts/"), "/full")
		h.apiGetAccountFull(w, r, id)
	case strings.HasPrefix(path, "/accounts/") && r.Method == "DELETE":
		h.apiDeleteAccount(w, r, strings.TrimPrefix(path, "/accounts/"))
	case strings.HasPrefix(path, "/accounts/") && r.Method == "PUT":
		h.apiUpdateAccount(w, r, strings.TrimPrefix(path, "/accounts/"))
	case path == "/auth/iam-sso/start" && r.Method == "POST":
		h.apiStartIamSso(w, r)
	case path == "/auth/iam-sso/complete" && r.Method == "POST":
		h.apiCompleteIamSso(w, r)
	case path == "/auth/microsoft-sso/start" && r.Method == "POST":
		h.apiStartMicrosoftSSO(w, r)
	case path == "/auth/microsoft-sso/complete" && r.Method == "POST":
		h.apiCompleteMicrosoftSSO(w, r)
	case path == "/auth/microsoft-sso/select-profile" && r.Method == "POST":
		h.apiSelectMicrosoftSSOProfile(w, r)
	case path == "/auth/microsoft-sso/cancel" && r.Method == "POST":
		h.apiCancelMicrosoftSSO(w, r)
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
	case path == "/logs" && r.Method == "GET":
		h.apiGetLogs(w, r)
	case path == "/logs" && r.Method == "DELETE":
		h.apiClearLogs(w, r)
	case path == "/generate-machine-id" && r.Method == "GET":
		h.apiGenerateMachineId(w, r)
	case path == "/thinking" && r.Method == "GET":
		h.apiGetThinkingConfig(w, r)
	case path == "/thinking" && r.Method == "POST":
		h.apiUpdateThinkingConfig(w, r)
	case path == "/endpoint" && r.Method == "GET":
		h.apiGetEndpointConfig(w, r)
	case path == "/endpoint" && r.Method == "POST":
		h.apiUpdateEndpointConfig(w, r)
	case path == "/proxy" && r.Method == "GET":
		h.apiGetProxy(w, r)
	case path == "/proxy" && r.Method == "POST":
		h.apiUpdateProxy(w, r)
	case path == "/prompt-filter" && r.Method == "GET":
		h.apiGetPromptFilter(w, r)
	case path == "/prompt-filter" && r.Method == "POST":
		h.apiUpdatePromptFilter(w, r)
	case path == "/version" && r.Method == "GET":
		h.apiGetVersion(w, r)
	case path == "/export" && r.Method == "POST":
		h.apiExportAccounts(w, r)
	case path == "/api-keys" && r.Method == "GET":
		h.apiListApiKeys(w, r)
	case path == "/api-keys" && r.Method == "POST":
		h.apiCreateApiKey(w, r)
	case strings.HasPrefix(path, "/api-keys/") && strings.HasSuffix(path, "/reset-usage") && r.Method == "POST":
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/api-keys/"), "/reset-usage")
		h.apiResetApiKeyUsage(w, r, id)
	case strings.HasPrefix(path, "/api-keys/") && r.Method == "GET":
		h.apiGetApiKey(w, r, strings.TrimPrefix(path, "/api-keys/"))
	case strings.HasPrefix(path, "/api-keys/") && r.Method == "PUT":
		h.apiUpdateApiKey(w, r, strings.TrimPrefix(path, "/api-keys/"))
	case strings.HasPrefix(path, "/api-keys/") && r.Method == "DELETE":
		h.apiDeleteApiKey(w, r, strings.TrimPrefix(path, "/api-keys/"))
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
			"banStatus":         a.BanStatus,
			"banReason":         a.BanReason,
			"banTime":           a.BanTime,
			"expiresAt":         a.ExpiresAt,
			"hasToken":          accountBearerToken(&a) != "",
			"machineId":         a.MachineId,
			"weight":            a.Weight,
			"overageStatus":     a.OverageStatus,
			"overageCapability": a.OverageCapability,
			"overageCap":        a.OverageCap,
			"overageRate":       a.OverageRate,
			"currentOverages":   a.CurrentOverages,
			"overageCheckedAt":  a.OverageCheckedAt,
			"proxyURL":          a.ProxyURL,
			"subscriptionType":  a.SubscriptionType,
			"subscriptionTitle": a.SubscriptionTitle,
			"daysRemaining":     a.DaysRemaining,
			"usageCurrent":      a.UsageCurrent,
			"usageLimit":        a.UsageLimit,
			"usagePercent":      a.UsagePercent,
			"nextResetDate":     a.NextResetDate,
			"lastRefresh":       a.LastRefresh,
			"trialUsageCurrent": a.TrialUsageCurrent,
			"trialUsageLimit":   a.TrialUsageLimit,
			"trialUsagePercent": a.TrialUsagePercent,
			"trialStatus":       a.TrialStatus,
			"trialExpiresAt":    a.TrialExpiresAt,
			"requestCount":      stats.RequestCount,
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
	// 新账号若已启用且有 token，立即拉取并缓存模型列表
	if account.Enabled && account.AccessToken != "" {
		go func(acc config.Account) {
			if err := h.fetchAndCacheAccountModels(&acc); err != nil {
				logger.Warnf("[ModelsCache] Auto-refresh failed for new account %s: %v", acc.Email, err)
			}
		}(account)
	}
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
	oldEnabled := existing.Enabled
	if v, ok := updates["enabled"].(bool); ok {
		existing.Enabled = v
	}
	if v, ok := updates["nickname"].(string); ok {
		existing.Nickname = v
	}
	if v, ok := updates["machineId"].(string); ok {
		existing.MachineId = v
	}
	if v, ok := updates["weight"].(float64); ok {
		existing.Weight = int(v)
	}
	if v, ok := updates["proxyURL"].(string); ok {
		existing.ProxyURL = v
	}

	if err := config.UpdateAccount(id, *existing); err != nil {
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	h.pool.Reload()
	// 账号从禁用→启用时，自动拉取并缓存模型列表
	if !oldEnabled && existing.Enabled && existing.AccessToken != "" {
		go func(acc config.Account) {
			if err := h.fetchAndCacheAccountModels(&acc); err != nil {
				logger.Warnf("[ModelsCache] Auto-refresh failed for re-enabled account %s: %v", acc.Email, err)
			}
		}(*existing)
	}
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// apiGetAccountOverage 拉取并返回单个账号的上游 Overages 状态。
// 同步把结果写回 config.json 缓存，确保 UI 与持久化一致。
func (h *Handler) apiGetAccountOverage(w http.ResponseWriter, r *http.Request, id string) {
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

	snap, err := FetchOverageStatus(account)
	if err != nil {
		w.WriteHeader(502)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	if persistErr := PersistOverageSnapshot(id, snap); persistErr != nil {
		logger.Warnf("[Overage] persist GET overage failed for %s: %v", account.Email, persistErr)
	}
	h.pool.Reload()

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":           true,
		"overageStatus":     snap.Status,
		"overageCapability": snap.Capability,
		"subscriptionTitle": snap.SubscriptionTitle,
		"overageCap":        snap.OverageCap,
		"overageRate":       snap.OverageRate,
		"currentOverages":   snap.CurrentOverages,
		"overageCheckedAt":  snap.CheckedAt,
	})
}

// apiSetAccountOverage 翻转单个账号的上游 Overages 开关，并刷新缓存。
// Body: {"enabled": true|false}
func (h *Handler) apiSetAccountOverage(w http.ResponseWriter, r *http.Request, id string) {
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON"})
		return
	}

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

	snap, err := SetOverageStatus(account, body.Enabled)
	if err != nil {
		w.WriteHeader(502)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	if persistErr := PersistOverageSnapshot(id, snap); persistErr != nil {
		logger.Warnf("[Overage] persist SET overage failed for %s: %v", account.Email, persistErr)
	}
	h.pool.Reload()

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":           true,
		"overageStatus":     snap.Status,
		"overageCapability": snap.Capability,
		"subscriptionTitle": snap.SubscriptionTitle,
		"overageCap":        snap.OverageCap,
		"overageRate":       snap.OverageRate,
		"currentOverages":   snap.CurrentOverages,
		"overageCheckedAt":  snap.CheckedAt,
	})
}

// apiBatchAccounts 批量操作账号（启用/禁用/刷新）
func (h *Handler) apiBatchAccounts(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IDs    []string `json:"ids"`
		Action string   `json:"action"` // "enable", "disable", "refresh"
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON"})
		return
	}
	if len(req.IDs) == 0 {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]string{"error": "No account IDs provided"})
		return
	}

	switch req.Action {
	case "enable", "disable":
		enabled := req.Action == "enable"
		accounts := config.GetAccounts()
		idSet := make(map[string]bool)
		for _, id := range req.IDs {
			idSet[id] = true
		}
		var toRefreshModels []config.Account
		for _, a := range accounts {
			if idSet[a.ID] {
				// 记录本次从禁用→启用、且有 token 的账号
				if enabled && !a.Enabled && a.AccessToken != "" {
					toRefreshModels = append(toRefreshModels, a)
				}
				a.Enabled = enabled
				if enabled && a.BanStatus != "" && a.BanStatus != "ACTIVE" {
					a.BanStatus = "ACTIVE"
					a.BanReason = ""
					a.BanTime = 0
				}
				config.UpdateAccount(a.ID, a)
			}
		}
		h.pool.Reload()
		// 为本次新启用的账号异步拉取模型缓存
		for _, acc := range toRefreshModels {
			go func(a config.Account) {
				a.Enabled = true
				if err := h.fetchAndCacheAccountModels(&a); err != nil {
					logger.Warnf("[ModelsCache] Auto-refresh failed for batch-enabled account %s: %v", a.Email, err)
				}
			}(acc)
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "count": len(req.IDs)})

	case "refresh":
		successCount := 0
		failCount := 0
		for _, id := range req.IDs {
			accounts := config.GetAccounts()
			var account *config.Account
			for i := range accounts {
				if accounts[i].ID == id {
					account = &accounts[i]
					break
				}
			}
			if account == nil {
				failCount++
				continue
			}
			// 刷新 token
			if account.RefreshToken != "" {
				if _, err := h.refreshAccountToken(account, true); err != nil {
					logger.Warnf("[BatchRefresh] Token refresh failed for %s: %v", account.Email, err)
					failCount++
					continue
				}
			}
			// 刷新账户信息
			info, err := RefreshAccountInfo(account)
			if err != nil {
				failCount++
				continue
			}
			config.UpdateAccountInfo(id, *info)
			successCount++
		}
		h.pool.Reload()
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":   true,
			"refreshed": successCount,
			"failed":    failCount,
		})

	default:
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid action: " + req.Action})
	}
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

func (h *Handler) apiStartMicrosoftSSO(w http.ResponseWriter, r *http.Request) {
	sessionID, authorizeURL, expiresIn, err := auth.StartMicrosoftSSOLogin()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"sessionId":    sessionID,
		"authorizeUrl": authorizeURL,
		"expiresIn":    expiresIn,
		"stage":        "kiro",
	})
}

func (h *Handler) apiCompleteMicrosoftSSO(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SessionID   string `json:"sessionId"`
		CallbackURL string `json:"callbackUrl"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON"})
		return
	}
	if strings.TrimSpace(req.SessionID) == "" || strings.TrimSpace(req.CallbackURL) == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "sessionId and callbackUrl are required"})
		return
	}

	progress, err := auth.ContinueMicrosoftSSOLogin(req.SessionID, req.CallbackURL)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	if h.microsoftSessionCanceled(req.SessionID) {
		auth.CancelMicrosoftSSOLogin(req.SessionID)
		h.writeMicrosoftSSOCanceled(w)
		return
	}
	if progress.AuthorizationURL != "" {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":      true,
			"stage":        "microsoft",
			"authorizeUrl": progress.AuthorizationURL,
		})
		return
	}
	if progress.Result == nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Microsoft SSO returned no credential"})
		return
	}

	result := progress.Result
	account := config.Account{
		ID:            auth.GenerateAccountID(),
		Email:         result.Email,
		UserId:        result.UserID,
		AccessToken:   result.AccessToken,
		RefreshToken:  result.RefreshToken,
		ClientID:      result.ClientID,
		AuthMethod:    auth.MicrosoftSSOAuthMethod,
		Provider:      auth.MicrosoftSSOProvider,
		Region:        "us-east-1",
		ExpiresAt:     result.ExpiresAt,
		Enabled:       true,
		MachineId:     config.GenerateMachineId(),
		TokenEndpoint: result.TokenEndpoint,
		IssuerURL:     result.IssuerURL,
		Scopes:        result.Scopes,
	}

	discoveryContext, discovery, ok := h.beginMicrosoftProfileDiscovery(r.Context(), req.SessionID)
	if !ok {
		clearMicrosoftAccountCredential(&account)
		h.writeMicrosoftSSOCanceled(w)
		return
	}
	profiles, profileErr := DiscoverKiroProfilesContext(discoveryContext, &account)
	discoveryErr := discoveryContext.Err()
	h.endMicrosoftProfileDiscovery(req.SessionID, discovery)

	h.microsoftFlowMu.Lock()
	if h.microsoftSessionCanceledLocked(req.SessionID, time.Now()) {
		h.microsoftFlowMu.Unlock()
		clearMicrosoftAccountCredential(&account)
		h.writeMicrosoftSSOCanceled(w)
		return
	}
	if discoveryErr != nil {
		h.microsoftFlowMu.Unlock()
		clearMicrosoftAccountCredential(&account)
		w.WriteHeader(http.StatusGatewayTimeout)
		json.NewEncoder(w).Encode(map[string]string{"error": "Microsoft profile discovery was canceled or timed out"})
		return
	}
	if len(profiles) > 1 {
		selectionID, expiredSelections, err := h.storeMicrosoftProfileSelection(req.SessionID, account, profiles)
		h.microsoftFlowMu.Unlock()
		discardDetachedMicrosoftProfileSelections(expiredSelections)
		if err != nil {
			clearMicrosoftAccountCredential(&account)
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":                  true,
			"stage":                    "profile",
			"requiresProfileSelection": true,
			"selectionId":              selectionID,
			"profiles":                 profiles,
		})
		return
	}
	if len(profiles) == 1 {
		account.ProfileArn = profiles[0].ARN
	}
	if err := config.AddAccount(account); err != nil {
		h.microsoftFlowMu.Unlock()
		h.writeAddAccountError(w, err)
		return
	}
	delete(h.microsoftCanceled, strings.TrimSpace(req.SessionID))
	h.microsoftFlowMu.Unlock()
	h.pool.Reload()

	response := map[string]interface{}{
		"success": true,
		"stage":   "complete",
		"account": map[string]interface{}{"id": account.ID, "email": account.Email},
	}
	if profileErr != nil {
		response["warning"] = "The account was added, but its Kiro profile could not be resolved yet"
	}
	json.NewEncoder(w).Encode(response)
}

func (h *Handler) apiSelectMicrosoftSSOProfile(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SelectionID string `json:"selectionId"`
		ProfileARN  string `json:"profileArn"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON"})
		return
	}
	selectionID := strings.TrimSpace(req.SelectionID)
	selection := h.getMicrosoftProfileSelection(selectionID)
	if selection == nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Microsoft profile selection not found or expired"})
		return
	}

	selection.mu.Lock()
	if selection.canceled.Load() || !time.Now().Before(selection.ExpiresAt) {
		selection.mu.Unlock()
		h.removeMicrosoftProfileSelection(selectionID, selection)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Microsoft profile selection not found or expired"})
		return
	}

	profileARN := strings.TrimSpace(req.ProfileARN)
	allowed := false
	for _, profile := range selection.Profiles {
		if profile.ARN == profileARN {
			allowed = true
			break
		}
	}
	if !allowed {
		selection.mu.Unlock()
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Selected Kiro profile was not offered for this login"})
		return
	}

	account := selection.Account
	account.ProfileArn = profileARN
	h.microsoftFlowMu.Lock()
	now := time.Now()
	if selection.canceled.Load() ||
		!now.Before(selection.ExpiresAt) ||
		h.microsoftSessionCanceledLocked(selection.SessionID, now) {
		h.microsoftFlowMu.Unlock()
		h.detachMicrosoftProfileSelection(selectionID, selection)
		selection.canceled.Store(true)
		selection.Account = config.Account{}
		selection.Profiles = nil
		selection.mu.Unlock()
		h.writeMicrosoftSSOCanceled(w)
		return
	}
	if err := config.AddAccount(account); err != nil {
		h.microsoftFlowMu.Unlock()
		selection.mu.Unlock()
		h.writeAddAccountError(w, err)
		return
	}
	h.detachMicrosoftProfileSelection(selectionID, selection)
	selection.canceled.Store(true)
	selection.Account = config.Account{}
	selection.Profiles = nil
	delete(h.microsoftCanceled, selection.SessionID)
	h.microsoftFlowMu.Unlock()
	selection.mu.Unlock()
	h.pool.Reload()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"stage":   "complete",
		"account": map[string]interface{}{"id": account.ID, "email": account.Email},
	})
}

func (h *Handler) apiCancelMicrosoftSSO(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SessionID   string `json:"sessionId"`
		SelectionID string `json:"selectionId"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err != io.EOF {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON"})
		return
	}
	sessionID := strings.TrimSpace(req.SessionID)
	selectionID := strings.TrimSpace(req.SelectionID)
	if sessionID == "" && selectionID != "" {
		if selection := h.getMicrosoftProfileSelection(selectionID); selection != nil {
			sessionID = selection.SessionID
		}
	}
	if sessionID != "" {
		h.markMicrosoftSessionCanceled(sessionID)
	}
	auth.CancelMicrosoftSSOLogin(sessionID)
	if selectionID != "" {
		h.removeMicrosoftProfileSelection(selectionID, nil)
	}
	if sessionID != "" {
		h.removeMicrosoftProfileSelectionsForSession(sessionID)
	}
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func (h *Handler) storeMicrosoftProfileSelection(
	sessionID string,
	account config.Account,
	profiles []KiroProfile,
) (string, []*microsoftProfileSelection, error) {
	now := time.Now()
	expiresAt := now.Add(microsoftProfileSelectionTTL)
	tokenExpiry := time.Unix(account.ExpiresAt, 0)
	if account.ExpiresAt > 0 && tokenExpiry.Before(expiresAt) {
		expiresAt = tokenExpiry
	}
	if !expiresAt.After(now) {
		return "", nil, fmt.Errorf("Microsoft credential expired before profile selection")
	}
	selectionID := uuid.NewString()
	selection := &microsoftProfileSelection{
		SessionID: strings.TrimSpace(sessionID),
		Account:   account,
		Profiles:  append([]KiroProfile(nil), profiles...),
		ExpiresAt: expiresAt,
	}
	var expired []*microsoftProfileSelection

	h.microsoftSelectionsMu.Lock()
	if h.microsoftSelections == nil {
		h.microsoftSelections = make(map[string]*microsoftProfileSelection)
	}
	for id, current := range h.microsoftSelections {
		if !now.Before(current.ExpiresAt) {
			delete(h.microsoftSelections, id)
			current.canceled.Store(true)
			if current.timer != nil {
				current.timer.Stop()
				current.timer = nil
			}
			expired = append(expired, current)
		}
	}
	if len(h.microsoftSelections) >= microsoftMaxPendingProfileSelections {
		h.microsoftSelectionsMu.Unlock()
		return "", expired, fmt.Errorf("too many pending Microsoft profile selections; cancel one and try again")
	}
	h.microsoftSelections[selectionID] = selection
	selection.timer = time.AfterFunc(time.Until(expiresAt), func() {
		h.removeMicrosoftProfileSelection(selectionID, selection)
	})
	h.microsoftSelectionsMu.Unlock()
	return selectionID, expired, nil
}

func (h *Handler) getMicrosoftProfileSelection(selectionID string) *microsoftProfileSelection {
	if selectionID == "" {
		return nil
	}
	h.microsoftSelectionsMu.Lock()
	selection := h.microsoftSelections[selectionID]
	if selection != nil && !time.Now().Before(selection.ExpiresAt) {
		delete(h.microsoftSelections, selectionID)
		selection.canceled.Store(true)
		if selection.timer != nil {
			selection.timer.Stop()
			selection.timer = nil
		}
		h.microsoftSelectionsMu.Unlock()
		discardDetachedMicrosoftProfileSelection(selection)
		return nil
	}
	h.microsoftSelectionsMu.Unlock()
	return selection
}

func (h *Handler) detachMicrosoftProfileSelection(
	selectionID string,
	expected *microsoftProfileSelection,
) *microsoftProfileSelection {
	selectionID = strings.TrimSpace(selectionID)
	if selectionID == "" {
		return nil
	}
	h.microsoftSelectionsMu.Lock()
	current := h.microsoftSelections[selectionID]
	if current != nil && (expected == nil || current == expected) {
		delete(h.microsoftSelections, selectionID)
		current.canceled.Store(true)
		if current.timer != nil {
			current.timer.Stop()
			current.timer = nil
		}
	} else {
		current = nil
	}
	h.microsoftSelectionsMu.Unlock()
	return current
}

func (h *Handler) removeMicrosoftProfileSelection(selectionID string, expected *microsoftProfileSelection) {
	if selection := h.detachMicrosoftProfileSelection(selectionID, expected); selection != nil {
		discardDetachedMicrosoftProfileSelection(selection)
	}
}

func (h *Handler) removeMicrosoftProfileSelectionsForSession(sessionID string) {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return
	}
	var removed []*microsoftProfileSelection
	h.microsoftSelectionsMu.Lock()
	for selectionID, selection := range h.microsoftSelections {
		if selection.SessionID == sessionID {
			delete(h.microsoftSelections, selectionID)
			selection.canceled.Store(true)
			if selection.timer != nil {
				selection.timer.Stop()
				selection.timer = nil
			}
			removed = append(removed, selection)
		}
	}
	h.microsoftSelectionsMu.Unlock()
	for _, selection := range removed {
		discardDetachedMicrosoftProfileSelection(selection)
	}
}

func discardDetachedMicrosoftProfileSelection(selection *microsoftProfileSelection) {
	selection.mu.Lock()
	selection.Account = config.Account{}
	selection.Profiles = nil
	selection.mu.Unlock()
}

func discardDetachedMicrosoftProfileSelections(selections []*microsoftProfileSelection) {
	for _, selection := range selections {
		discardDetachedMicrosoftProfileSelection(selection)
	}
}

func clearMicrosoftAccountCredential(account *config.Account) {
	account.AccessToken = ""
	account.RefreshToken = ""
	account.ClientSecret = ""
}

func (h *Handler) markMicrosoftSessionCanceled(sessionID string) {
	now := time.Now()
	h.microsoftFlowMu.Lock()
	if h.microsoftCanceled == nil {
		h.microsoftCanceled = make(map[string]time.Time)
	}
	h.cleanupMicrosoftCanceledLocked(now)
	if len(h.microsoftCanceled) >= microsoftMaxCanceledSessionTombstones {
		var oldestID string
		var oldestExpiry time.Time
		for id, expiry := range h.microsoftCanceled {
			if oldestID == "" || expiry.Before(oldestExpiry) {
				oldestID = id
				oldestExpiry = expiry
			}
		}
		delete(h.microsoftCanceled, oldestID)
	}
	h.microsoftCanceled[sessionID] = now.Add(microsoftCanceledSessionTTL)
	if discovery := h.microsoftDiscoveries[sessionID]; discovery != nil {
		discovery.cancel()
	}
	h.microsoftFlowMu.Unlock()
}

func (h *Handler) beginMicrosoftProfileDiscovery(
	parent context.Context,
	sessionID string,
) (context.Context, *microsoftProfileDiscovery, bool) {
	sessionID = strings.TrimSpace(sessionID)
	h.microsoftFlowMu.Lock()
	defer h.microsoftFlowMu.Unlock()
	if h.microsoftSessionCanceledLocked(sessionID, time.Now()) {
		return nil, nil, false
	}
	if h.microsoftDiscoveries == nil {
		h.microsoftDiscoveries = make(map[string]*microsoftProfileDiscovery)
	}
	if h.microsoftDiscoveries[sessionID] != nil {
		return nil, nil, false
	}
	ctx, cancel := context.WithTimeout(parent, microsoftProfileDiscoveryTimeout)
	discovery := &microsoftProfileDiscovery{cancel: cancel}
	h.microsoftDiscoveries[sessionID] = discovery
	return ctx, discovery, true
}

func (h *Handler) endMicrosoftProfileDiscovery(sessionID string, expected *microsoftProfileDiscovery) {
	expected.cancel()
	h.microsoftFlowMu.Lock()
	if h.microsoftDiscoveries[strings.TrimSpace(sessionID)] == expected {
		delete(h.microsoftDiscoveries, strings.TrimSpace(sessionID))
	}
	h.microsoftFlowMu.Unlock()
}

func (h *Handler) microsoftSessionCanceled(sessionID string) bool {
	h.microsoftFlowMu.Lock()
	defer h.microsoftFlowMu.Unlock()
	return h.microsoftSessionCanceledLocked(sessionID, time.Now())
}

func (h *Handler) microsoftSessionCanceledLocked(sessionID string, now time.Time) bool {
	h.cleanupMicrosoftCanceledLocked(now)
	expiry, exists := h.microsoftCanceled[strings.TrimSpace(sessionID)]
	return exists && now.Before(expiry)
}

func (h *Handler) cleanupMicrosoftCanceledLocked(now time.Time) {
	for sessionID, expiry := range h.microsoftCanceled {
		if !now.Before(expiry) {
			delete(h.microsoftCanceled, sessionID)
		}
	}
}

func (h *Handler) writeMicrosoftSSOCanceled(w http.ResponseWriter) {
	w.WriteHeader(http.StatusConflict)
	json.NewEncoder(w).Encode(map[string]string{"error": "Microsoft SSO login was canceled"})
}

func (h *Handler) writeAddAccountError(w http.ResponseWriter, err error, rotatedRefreshToken ...string) {
	if errors.Is(err, config.ErrDuplicateAccountID) ||
		errors.Is(err, config.ErrDuplicateRefreshToken) ||
		errors.Is(err, config.ErrDuplicateAPIKey) {
		w.WriteHeader(http.StatusConflict)
	} else {
		w.WriteHeader(http.StatusInternalServerError)
	}
	payload := map[string]string{"error": err.Error()}
	if len(rotatedRefreshToken) > 0 {
		if rotated := strings.TrimSpace(rotatedRefreshToken[0]); rotated != "" {
			// Microsoft may have already invalidated the original refresh token.
			// Surface the rotated value so operators can retry import without a
			// full interactive re-login.
			payload["rotatedRefreshToken"] = rotated
			payload["hint"] = "The identity provider rotated the refresh token before persistence failed; retry import with rotatedRefreshToken"
		}
	}
	json.NewEncoder(w).Encode(payload)
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
		ID            string `json:"id"`
		Email         string `json:"email"`
		UserID        string `json:"userId"`
		Nickname      string `json:"nickname"`
		ProfileARN    string `json:"profileArn"`
		AccessToken   string `json:"accessToken"`
		RefreshToken  string `json:"refreshToken"`
		KiroApiKey    string `json:"kiroApiKey"`
		ClientID      string `json:"clientId"`
		ClientSecret  string `json:"clientSecret"`
		AuthMethod    string `json:"authMethod"`
		Provider      string `json:"provider"`
		Region        string `json:"region"`
		TokenEndpoint string `json:"tokenEndpoint"`
		IssuerURL     string `json:"issuerUrl"`
		Scopes        string `json:"scopes"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON"})
		return
	}

	req.RefreshToken = strings.TrimSpace(req.RefreshToken)
	req.KiroApiKey = strings.TrimSpace(req.KiroApiKey)
	req.AccessToken = strings.TrimSpace(req.AccessToken)
	methodHint := strings.ToLower(strings.TrimSpace(req.AuthMethod))
	isAPIKeyImport := req.KiroApiKey != "" ||
		methodHint == "api_key" || methodHint == "apikey" ||
		(req.RefreshToken == "" && looksLikeKiroAPIKey(req.AccessToken))
	if isAPIKeyImport && req.KiroApiKey == "" {
		// Allow plain-text / AccessToken-only API key imports.
		req.KiroApiKey = req.AccessToken
	}
	if !isAPIKeyImport && req.RefreshToken == "" {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]string{"error": "refreshToken or kiroApiKey is required"})
		return
	}
	if len(req.RefreshToken) > 512<<10 || len(req.AccessToken) > 512<<10 || len(req.KiroApiKey) > 512<<10 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "credential token is too long"})
		return
	}
	originalRefreshToken := req.RefreshToken
	h.credentialImportMu.Lock()
	defer h.credentialImportMu.Unlock()
	accountID := strings.TrimSpace(req.ID)
	if accountID != "" {
		if _, err := uuid.Parse(accountID); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "id must be a UUID"})
			return
		}
		if config.AccountIDExists(accountID) {
			h.writeAddAccountError(w, config.ErrDuplicateAccountID)
			return
		}
	}

	// API Key import path: no OAuth refresh, no profileArn.
	if isAPIKeyImport {
		if accountID == "" {
			accountID = auth.GenerateAccountID()
		}
		account := config.Account{
			ID:         accountID,
			Email:      strings.TrimSpace(req.Email),
			UserId:     strings.TrimSpace(req.UserID),
			Nickname:   strings.TrimSpace(req.Nickname),
			KiroApiKey: req.KiroApiKey,
			AuthMethod: "api_key",
			Provider:   strings.TrimSpace(req.Provider),
			Region:     strings.TrimSpace(req.Region),
			Enabled:    true,
		}
		if err := config.NormalizeAPIKeyAccount(&account); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		if config.AccountAPIKeyExists(account.KiroApiKey) {
			h.writeAddAccountError(w, config.ErrDuplicateAPIKey)
			return
		}
		if err := config.AddAccount(account); err != nil {
			h.writeAddAccountError(w, err)
			return
		}
		h.pool.Reload()
		if account.Enabled && account.AccessToken != "" {
			go func(acc config.Account) {
				if err := h.fetchAndCacheAccountModels(&acc); err != nil {
					logger.Warnf("[ModelsCache] Auto-refresh failed for new API key account %s: %v", acc.Email, err)
				}
			}(account)
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"account": map[string]interface{}{
				"id":    account.ID,
				"email": account.Email,
			},
		})
		return
	}

	if config.AccountCredentialExists(originalRefreshToken) {
		h.writeAddAccountError(w, config.ErrDuplicateRefreshToken)
		return
	}

	// 设置默认值
	req.Region = strings.TrimSpace(req.Region)
	if req.Region == "" {
		req.Region = "us-east-1"
	}
	method := strings.ToLower(strings.TrimSpace(req.AuthMethod))
	provider := strings.ToLower(strings.TrimSpace(req.Provider))
	derivedTokenEndpoint, derivedIssuer, derivedScopes := auth.DeriveExternalIdpEndpoints(
		req.UserID, req.ClientID, req.AccessToken,
	)
	// Explicit AWS/social methods win over incidental tokenEndpoint/issuerUrl
	// fields so mixed JSON templates cannot force the external-IdP path.
	explicitMicrosoft := method == "external_idp" || method == "external-idp" ||
		method == "external" || method == "microsoft" || method == "m365" || method == "office365" ||
		method == "azure" || method == "azuread" || method == "azure-ad" || method == "azure_ad" ||
		method == "entra" || method == "entra-id" ||
		provider == "external" || provider == "microsoft" || provider == "m365" || provider == "office365" ||
		provider == "azure" || provider == "azuread" || provider == "azure-ad" || provider == "azure_ad" ||
		provider == "entra" || provider == "entra-id"
	implicitExternal := method == "" && provider == "" &&
		(derivedTokenEndpoint != "" ||
			strings.TrimSpace(req.TokenEndpoint) != "" ||
			strings.TrimSpace(req.IssuerURL) != "")
	switch {
	case method == "api_key" || method == "apikey":
		req.AuthMethod = "api_key"
	case method == "idc" || method == "builderid" || method == "enterprise":
		req.AuthMethod = "idc"
	case method == "social" || method == "google" || method == "github":
		req.AuthMethod = "social"
	case explicitMicrosoft || implicitExternal:
		req.AuthMethod = auth.MicrosoftSSOAuthMethod
	case req.ClientID != "" && req.ClientSecret != "":
		req.AuthMethod = "idc"
	default:
		req.AuthMethod = "social"
	}

	// 用 refreshToken 刷新获取新的 accessToken。导入必须以一次成功的刷新为前提：
	// 本地缓存里的 accessToken 不携带可信的过期时间，盲猜短 TTL 会让账号在选号时
	// 永远被跳过，导致后台/按需刷新都无法触发（详见 ensureValidToken 与 Pick 的过期判定）。
	req.ClientID = strings.TrimSpace(req.ClientID)
	req.TokenEndpoint = strings.TrimSpace(req.TokenEndpoint)
	req.IssuerURL = strings.TrimRight(strings.TrimSpace(req.IssuerURL), "/")
	req.Scopes = strings.TrimSpace(req.Scopes)

	if req.AuthMethod == auth.MicrosoftSSOAuthMethod {
		if req.IssuerURL == "" {
			req.IssuerURL = derivedIssuer
		}
		if req.IssuerURL == "" && req.TokenEndpoint != "" {
			normalizedTokenEndpoint, tokenIssuer, tokenScopes := auth.ExternalIdpConfigurationFromTokenEndpoint(
				req.TokenEndpoint, req.ClientID,
			)
			if normalizedTokenEndpoint != "" {
				req.TokenEndpoint = normalizedTokenEndpoint
				req.IssuerURL = tokenIssuer
				if req.Scopes == "" {
					req.Scopes = tokenScopes
				}
			}
		}
		if req.IssuerURL != "" {
			builtTokenEndpoint, normalizedIssuer, builtScopes := auth.ExternalIdpConfigurationFromIssuer(req.IssuerURL, req.ClientID)
			if req.TokenEndpoint == "" {
				req.TokenEndpoint = builtTokenEndpoint
			}
			if normalizedIssuer != "" {
				req.IssuerURL = normalizedIssuer
			}
			if req.Scopes == "" {
				req.Scopes = builtScopes
			}
		}
		if req.TokenEndpoint == "" {
			req.TokenEndpoint = derivedTokenEndpoint
		}
		if req.Scopes == "" {
			req.Scopes = derivedScopes
		}
		normalizedScopes, err := auth.NormalizeExternalIdpScopes(req.Scopes, req.ClientID)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		req.Scopes = normalizedScopes
		if err := auth.ValidateExternalIdpConfiguration(req.ClientID, req.TokenEndpoint, req.IssuerURL, req.Scopes); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		req.Provider = auth.MicrosoftSSOProvider
		req.ClientSecret = ""
	}

	profileARN := strings.TrimSpace(req.ProfileARN)
	if profileARN != "" {
		canonicalARN, _, ok := parseKiroProfileArn(profileARN)
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "profileArn is invalid"})
			return
		}
		profileARN = canonicalARN
	}

	tempAccount := &config.Account{
		RefreshToken:  req.RefreshToken,
		ClientID:      req.ClientID,
		ClientSecret:  req.ClientSecret,
		AuthMethod:    req.AuthMethod,
		Region:        req.Region,
		TokenEndpoint: req.TokenEndpoint,
		IssuerURL:     req.IssuerURL,
		Scopes:        req.Scopes,
	}
	accessToken, newRefreshToken, expiresAt, newProfileArn, err := auth.RefreshToken(tempAccount)
	if err != nil {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]string{"error": "Token refresh failed: " + err.Error()})
		return
	}
	if newRefreshToken != "" {
		req.RefreshToken = newRefreshToken
	}
	rotatedRefreshToken := ""
	if req.RefreshToken != "" && req.RefreshToken != originalRefreshToken {
		rotatedRefreshToken = req.RefreshToken
	}

	// 获取用户信息
	email := strings.TrimSpace(req.Email)
	userID := strings.TrimSpace(req.UserID)
	if req.AuthMethod == auth.MicrosoftSSOAuthMethod {
		tokenEmail, tokenUserID := auth.ExternalIdpTokenIdentity(accessToken)
		if tokenEmail != "" {
			email = tokenEmail
		}
		if tokenUserID != "" {
			userID = tokenUserID
		}
	} else if tokenEmail, _, _ := auth.GetUserInfo(accessToken); tokenEmail != "" {
		email = tokenEmail
	}

	if accountID == "" {
		accountID = auth.GenerateAccountID()
	}
	if profileARN == "" {
		profileARN = newProfileArn
	}
	// Interactive Microsoft login only accepts profiles discovered for the
	// refreshed token. Import keeps the same trust boundary so a client cannot
	// pin an arbitrary data-plane ARN onto a working credential.
	if req.AuthMethod == auth.MicrosoftSSOAuthMethod && profileARN != "" {
		probeAccount := *tempAccount
		probeAccount.AccessToken = accessToken
		probeAccount.RefreshToken = req.RefreshToken
		probeAccount.ExpiresAt = expiresAt
		offeredProfiles, discoverErr := DiscoverKiroProfiles(&probeAccount)
		if discoverErr != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Unable to verify profileArn against Kiro profiles: " + discoverErr.Error(),
			})
			return
		}
		offered := false
		for _, profile := range offeredProfiles {
			if profile.ARN == profileARN {
				offered = true
				break
			}
		}
		if !offered {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "profileArn was not offered for this credential",
			})
			return
		}
	}

	// 创建账号
	account := config.Account{
		ID:                      accountID,
		Email:                   email,
		UserId:                  userID,
		Nickname:                strings.TrimSpace(req.Nickname),
		AccessToken:             accessToken,
		RefreshToken:            req.RefreshToken,
		RefreshTokenFingerprint: config.RefreshTokenFingerprint(originalRefreshToken),
		ClientID:                req.ClientID,
		ClientSecret:            req.ClientSecret,
		AuthMethod:              req.AuthMethod,
		Provider:                req.Provider,
		Region:                  req.Region,
		ExpiresAt:               expiresAt,
		Enabled:                 true,
		MachineId:               config.GenerateMachineId(),
		ProfileArn:              profileARN,
		TokenEndpoint:           req.TokenEndpoint,
		IssuerURL:               req.IssuerURL,
		Scopes:                  req.Scopes,
	}

	if err := config.AddAccount(account); err != nil {
		h.writeAddAccountError(w, err, rotatedRefreshToken)
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
		"version":         config.Version,
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
		"apiKey":         config.GetApiKey(),
		"requireApiKey":  config.IsApiKeyRequired(),
		"port":           config.GetPort(),
		"host":           config.GetHost(),
		"allowOverUsage": config.GetAllowOverUsage(),
	})
}

func (h *Handler) apiGetPromptFilter(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(config.GetPromptFilterConfig())
}

func (h *Handler) apiUpdatePromptFilter(w http.ResponseWriter, r *http.Request) {
	var req struct {
		FilterClaudeCode      *bool                      `json:"filterClaudeCode,omitempty"`
		FilterEnvNoise        *bool                      `json:"filterEnvNoise,omitempty"`
		FilterStripBoundaries *bool                      `json:"filterStripBoundaries,omitempty"`
		Rules                 *[]config.PromptFilterRule `json:"rules,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON"})
		return
	}

	// Read current config to fill in any fields not provided in the request.
	current := config.GetPromptFilterConfig()
	fcc := current.FilterClaudeCode
	fen := current.FilterEnvNoise
	fsb := current.FilterStripBoundaries
	rules := current.Rules
	if req.FilterClaudeCode != nil {
		fcc = *req.FilterClaudeCode
	}
	if req.FilterEnvNoise != nil {
		fen = *req.FilterEnvNoise
	}
	if req.FilterStripBoundaries != nil {
		fsb = *req.FilterStripBoundaries
	}
	if req.Rules != nil {
		rules = *req.Rules
	}
	if err := config.UpdatePromptFilterConfig(fcc, fen, fsb, rules); err != nil {
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func (h *Handler) apiUpdateSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ApiKey         *string `json:"apiKey,omitempty"`
		RequireApiKey  *bool   `json:"requireApiKey,omitempty"`
		Password       string  `json:"password,omitempty"`
		AllowOverUsage *bool   `json:"allowOverUsage,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON"})
		return
	}

	if err := config.UpdateSettingsPatch(req.ApiKey, req.RequireApiKey, req.Password); err != nil {
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	// 更新超额使用设置
	if req.AllowOverUsage != nil {
		if err := config.UpdateAllowOverUsage(*req.AllowOverUsage); err != nil {
			w.WriteHeader(500)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		// Rebuild the pool so over-quota accounts are re-included or dropped immediately.
		h.pool.Reload()
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func (h *Handler) apiGetStats(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]interface{}{
		"totalRequests":   atomic.LoadInt64(&h.totalRequests),
		"successRequests": atomic.LoadInt64(&h.successRequests),
		"failedRequests":  atomic.LoadInt64(&h.failedRequests),
		"totalTokens":     atomic.LoadInt64(&h.totalTokens),
		"totalCredits":    h.getCredits(),
		"uptime":          time.Now().Unix() - h.startTime,
	})
}

func (h *Handler) apiResetStats(w http.ResponseWriter, r *http.Request) {
	atomic.StoreInt64(&h.totalRequests, 0)
	atomic.StoreInt64(&h.successRequests, 0)
	atomic.StoreInt64(&h.failedRequests, 0)
	atomic.StoreInt64(&h.totalTokens, 0)
	h.creditsMu.Lock()
	h.totalCredits = 0
	h.creditsMu.Unlock()
	config.UpdateStats(0, 0, 0, 0, 0)
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func (h *Handler) apiGetLogs(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]interface{}{
		"logs": h.getRequestLogs(),
	})
}

func (h *Handler) apiClearLogs(w http.ResponseWriter, r *http.Request) {
	h.requestLogsMu.Lock()
	h.requestLogs = h.requestLogs[:0]
	h.requestLogsMu.Unlock()
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// apiGenerateMachineId 生成新的机器码
func (h *Handler) apiGenerateMachineId(w http.ResponseWriter, r *http.Request) {
	machineId := config.GenerateMachineId()
	json.NewEncoder(w).Encode(map[string]string{"machineId": machineId})
}

// apiTestAccount tests a specific account by sending a real model request through its proxy.
func (h *Handler) apiTestAccount(w http.ResponseWriter, r *http.Request, id string) {
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

	if err := h.ensureValidToken(account); err != nil {
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(map[string]string{"error": "Token refresh failed: " + err.Error()})
		return
	}

	// Parse test model from request body (optional)
	var req struct {
		Model string `json:"model"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	if req.Model == "" {
		req.Model = "claude-sonnet-4"
	}

	// Build a minimal chat payload
	thinkingCfg := config.GetThinkingConfig()
	actualModel, thinking := ParseModelAndThinking(req.Model, thinkingCfg.Suffix)

	openaiReq := &OpenAIRequest{
		Model:     actualModel,
		Messages:  []OpenAIMessage{{Role: "user", Content: "say ok"}},
		MaxTokens: 5,
		Stream:    false,
	}
	kiroPayload := OpenAIToKiro(openaiReq, thinking)

	var content string
	callback := &KiroStreamCallback{
		OnText:         func(text string, isThinking bool) { content += text },
		OnToolUse:      func(tu KiroToolUse) {},
		OnComplete:     func(inTok, outTok int) {},
		OnError:        func(err error) {},
		OnCredits:      func(c float64) {},
		OnContextUsage: func(pct float64) {},
	}

	err := CallKiroAPIContext(r.Context(), account, kiroPayload, callback)
	if err != nil {
		if r.Context().Err() != nil {
			return
		}
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"reply":   content,
		"model":   req.Model,
	})
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

	// 先尝试刷新 token（不管是否过期，确保 token 有效）
	refreshTokenIfNeeded := func() error {
		if account.RefreshToken == "" {
			return nil
		}
		_, err := h.refreshAccountToken(account, true)
		return err
	}

	// 检查 token 是否快过期，先刷新
	if account.ExpiresAt > 0 && time.Now().Unix() > account.ExpiresAt-tokenRefreshSkewSeconds {
		if err := refreshTokenIfNeeded(); err != nil {
			w.WriteHeader(500)
			json.NewEncoder(w).Encode(map[string]string{"error": "Token refresh failed: " + err.Error()})
			return
		}
	}

	// 获取账户信息
	info, err := RefreshAccountInfo(account)
	if err != nil {
		// 检查是否为封禁相关错误
		errMsg := err.Error()
		if strings.Contains(errMsg, "TEMPORARILY_SUSPENDED") || strings.Contains(errMsg, "Account suspended") {
			// 封禁状态已在 RefreshAccountInfo 中处理，静默返回成功
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"message": "Account status updated",
			})
			return
		}

		// 如果是 403/401，说明 token 无效，尝试刷新后重试
		if strings.Contains(errMsg, "403") || strings.Contains(errMsg, "401") || strings.Contains(errMsg, "invalid") || strings.Contains(errMsg, "expired") {
			if refreshErr := refreshTokenIfNeeded(); refreshErr == nil {
				// 重试
				info, err = RefreshAccountInfo(account)
				if err != nil {
					// 重试后仍然失败，检查是否为封禁状态
					if strings.Contains(err.Error(), "TEMPORARILY_SUSPENDED") || strings.Contains(err.Error(), "Account suspended") {
						json.NewEncoder(w).Encode(map[string]interface{}{
							"success": true,
							"message": "Account status updated",
						})
						return
					}
				}
			}
		}

		// 其他错误才显示错误信息
		if err != nil {
			w.WriteHeader(500)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
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

// apiGetAccountFull 获取单个账号的完整信息（包含敏感字段）
func (h *Handler) apiGetAccountFull(w http.ResponseWriter, r *http.Request, id string) {
	accounts := config.GetAccounts()
	poolAccounts := h.pool.GetAllAccounts()

	// 查找指定账号
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

	// 获取运行时统计
	var stats config.Account
	for _, a := range poolAccounts {
		if a.ID == id {
			stats = a
			break
		}
	}

	// 返回完整账号信息（包含敏感字段）
	result := map[string]interface{}{
		"id":                account.ID,
		"email":             account.Email,
		"userId":            account.UserId,
		"nickname":          account.Nickname,
		"accessToken":       account.AccessToken,
		"refreshToken":      account.RefreshToken,
		"clientId":          account.ClientID,
		"clientSecret":      account.ClientSecret,
		"authMethod":        account.AuthMethod,
		"provider":          account.Provider,
		"region":            account.Region,
		"profileArn":        account.ProfileArn,
		"tokenEndpoint":     account.TokenEndpoint,
		"issuerUrl":         account.IssuerURL,
		"scopes":            account.Scopes,
		"expiresAt":         account.ExpiresAt,
		"machineId":         account.MachineId,
		"weight":            account.Weight,
		"overageStatus":     account.OverageStatus,
		"overageCapability": account.OverageCapability,
		"overageCap":        account.OverageCap,
		"overageRate":       account.OverageRate,
		"currentOverages":   account.CurrentOverages,
		"overageCheckedAt":  account.OverageCheckedAt,
		"proxyURL":          account.ProxyURL,
		"enabled":           account.Enabled,
		"banStatus":         account.BanStatus,
		"banReason":         account.BanReason,
		"banTime":           account.BanTime,
		"subscriptionType":  account.SubscriptionType,
		"subscriptionTitle": account.SubscriptionTitle,
		"daysRemaining":     account.DaysRemaining,
		"usageCurrent":      account.UsageCurrent,
		"usageLimit":        account.UsageLimit,
		"usagePercent":      account.UsagePercent,
		"nextResetDate":     account.NextResetDate,
		"lastRefresh":       account.LastRefresh,
		"trialUsageCurrent": account.TrialUsageCurrent,
		"trialUsageLimit":   account.TrialUsageLimit,
		"trialUsagePercent": account.TrialUsagePercent,
		"trialStatus":       account.TrialStatus,
		"trialExpiresAt":    account.TrialExpiresAt,
		"requestCount":      stats.RequestCount,
		"errorCount":        stats.ErrorCount,
		"totalTokens":       stats.TotalTokens,
		"totalCredits":      stats.TotalCredits,
		"lastUsed":          stats.LastUsed,
	}

	json.NewEncoder(w).Encode(result)
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

	// 同步更新路由缓存
	modelIDs := make([]string, 0, len(models))
	for _, m := range models {
		modelIDs = append(modelIDs, m.ModelId)
	}
	h.pool.SetModelList(id, modelIDs)
	h.modelsCacheMu.Lock()
	h.cachedModels = mergeUniqueModels(h.cachedModels, models)
	h.modelsCacheTime = time.Now().Unix()
	h.modelsCacheMu.Unlock()

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"models":  models,
	})
}

// apiGetAccountModelsCached 返回账号已缓存的模型列表（不实时拉取）
func (h *Handler) apiGetAccountModelsCached(w http.ResponseWriter, r *http.Request, id string) {
	models := h.pool.GetModelList(id)
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

// apiGetEndpointConfig 获取端点配置
func (h *Handler) apiGetEndpointConfig(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]interface{}{
		"preferredEndpoint": config.GetPreferredEndpoint(),
		"endpointFallback":  config.GetEndpointFallback(),
	})
}

// apiUpdateEndpointConfig 更新端点配置
func (h *Handler) apiUpdateEndpointConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PreferredEndpoint string `json:"preferredEndpoint"`
		EndpointFallback  *bool  `json:"endpointFallback"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON"})
		return
	}

	valid := map[string]bool{"auto": true, "kiro": true, "codewhisperer": true, "amazonq": true}
	if !valid[req.PreferredEndpoint] {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid endpoint, must be: auto, kiro, codewhisperer, or amazonq"})
		return
	}

	if err := config.UpdatePreferredEndpoint(req.PreferredEndpoint); err != nil {
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	if req.EndpointFallback != nil {
		config.UpdateEndpointFallback(*req.EndpointFallback)
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// applyProxyConfig 将代理配置应用到所有出站 HTTP 客户端（Kiro API + auth 模块）
func applyProxyConfig(proxyURL string) {
	InitKiroHttpClient(proxyURL)
	auth.InitHttpClient(proxyURL)
}

// apiGetProxy 获取当前代理配置
func (h *Handler) apiGetProxy(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]string{
		"proxyURL": config.GetProxyURL(),
	})
}

// apiUpdateProxy 更新代理配置并立即生效
func (h *Handler) apiUpdateProxy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProxyURL string `json:"proxyURL"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON"})
		return
	}

	// 验证代理 URL 格式（非空时）
	if req.ProxyURL != "" {
		if !strings.HasPrefix(req.ProxyURL, "http://") &&
			!strings.HasPrefix(req.ProxyURL, "https://") &&
			!strings.HasPrefix(req.ProxyURL, "socks5://") &&
			!strings.HasPrefix(req.ProxyURL, "socks5h://") {
			w.WriteHeader(400)
			json.NewEncoder(w).Encode(map[string]string{"error": "proxyURL must start with http://, https://, socks5://, or socks5h://"})
			return
		}
	}

	if err := config.UpdateProxySettings(req.ProxyURL); err != nil {
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	// 立即应用新的代理配置
	applyProxyConfig(req.ProxyURL)

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// apiGetVersion 获取版本信息
func (h *Handler) apiGetVersion(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]string{
		"version": config.Version,
	})
}

// apiExportAccounts 导出账号凭证
func (h *Handler) apiExportAccounts(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IDs []string `json:"ids"` // 为空则导出全部
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// 如果 body 为空或解析失败，导出全部
		req.IDs = nil
	}

	accounts := config.GetAccounts()

	// 如果指定了 ID，只导出指定的
	if len(req.IDs) > 0 {
		idSet := make(map[string]bool)
		for _, id := range req.IDs {
			idSet[id] = true
		}
		var filtered []config.Account
		for _, a := range accounts {
			if idSet[a.ID] {
				filtered = append(filtered, a)
			}
		}
		accounts = filtered
	}

	// 构建兼容 Kiro Account Manager 的导出格式
	type ExportCredentials struct {
		AccessToken   string `json:"accessToken"`
		CsrfToken     string `json:"csrfToken"`
		RefreshToken  string `json:"refreshToken"`
		ClientID      string `json:"clientId,omitempty"`
		ClientSecret  string `json:"clientSecret,omitempty"`
		Region        string `json:"region,omitempty"`
		ExpiresAt     int64  `json:"expiresAt"`
		AuthMethod    string `json:"authMethod,omitempty"`
		Provider      string `json:"provider,omitempty"`
		TokenEndpoint string `json:"tokenEndpoint,omitempty"`
		IssuerURL     string `json:"issuerUrl,omitempty"`
		Scopes        string `json:"scopes,omitempty"`
	}

	type ExportSubscription struct {
		Type  string `json:"type"`
		Title string `json:"title,omitempty"`
	}

	type ExportUsage struct {
		Current     float64 `json:"current"`
		Limit       float64 `json:"limit"`
		PercentUsed float64 `json:"percentUsed"`
		LastUpdated int64   `json:"lastUpdated"`
	}

	type ExportAccount struct {
		ID           string             `json:"id"`
		Email        string             `json:"email"`
		Nickname     string             `json:"nickname,omitempty"`
		Idp          string             `json:"idp"`
		UserId       string             `json:"userId,omitempty"`
		ProfileArn   string             `json:"profileArn,omitempty"`
		MachineId    string             `json:"machineId,omitempty"`
		Credentials  ExportCredentials  `json:"credentials"`
		Subscription ExportSubscription `json:"subscription"`
		Usage        ExportUsage        `json:"usage"`
		Tags         []string           `json:"tags"`
		Status       string             `json:"status"`
		CreatedAt    int64              `json:"createdAt"`
		LastUsedAt   int64              `json:"lastUsedAt"`
	}

	type ExportData struct {
		Version    string          `json:"version"`
		ExportedAt int64           `json:"exportedAt"`
		Accounts   []ExportAccount `json:"accounts"`
		Groups     []interface{}   `json:"groups"`
		Tags       []interface{}   `json:"tags"`
	}

	exportAccounts := make([]ExportAccount, 0, len(accounts))
	for _, a := range accounts {
		// API Key accounts are not OAuth credentials; export a flat-compatible shape.
		if config.IsAPIKeyAccount(&a) {
			exportAccounts = append(exportAccounts, ExportAccount{
				ID:        a.ID,
				Email:     a.Email,
				Nickname:  a.Nickname,
				Idp:       "APIKey",
				UserId:    a.UserId,
				MachineId: a.MachineId,
				Credentials: ExportCredentials{
					AccessToken:  a.KiroApiKey,
					RefreshToken: "",
					Region:       a.Region,
					AuthMethod:   "api_key",
					Provider:     "APIKey",
				},
				Subscription: ExportSubscription{
					Type:  a.SubscriptionType,
					Title: a.SubscriptionTitle,
				},
				Usage: ExportUsage{
					Current:     a.UsageCurrent,
					Limit:       a.UsageLimit,
					PercentUsed: a.UsagePercent,
					LastUpdated: a.LastRefresh,
				},
				Tags:       []string{"api_key"},
				Status:     "active",
				CreatedAt:  0,
				LastUsedAt: a.LastUsed,
			})
			continue
		}

		// 映射 provider 到 idp
		idp := a.Provider
		if idp == "" {
			if a.AuthMethod == "social" {
				idp = "Google"
			} else if a.AuthMethod == auth.MicrosoftSSOAuthMethod {
				idp = auth.MicrosoftSSOProvider
			} else {
				idp = "BuilderId"
			}
		}

		// 映射 authMethod
		authMethod := a.AuthMethod
		if authMethod == "idc" {
			authMethod = "IdC"
		}

		// 映射订阅类型
		subType := "Free"
		rawType := strings.ToUpper(a.SubscriptionType)
		if strings.Contains(rawType, "PRO_PLUS") || strings.Contains(rawType, "PROPLUS") {
			subType = "Pro_Plus"
		} else if strings.Contains(rawType, "PRO") {
			subType = "Pro"
		} else if strings.Contains(rawType, "POWER") {
			subType = "Pro_Plus"
		}

		exportAccounts = append(exportAccounts, ExportAccount{
			ID:         a.ID,
			Email:      a.Email,
			Nickname:   a.Nickname,
			Idp:        idp,
			UserId:     a.UserId,
			ProfileArn: a.ProfileArn,
			MachineId:  a.MachineId,
			Credentials: ExportCredentials{
				AccessToken:   a.AccessToken,
				CsrfToken:     "",
				RefreshToken:  a.RefreshToken,
				ClientID:      a.ClientID,
				ClientSecret:  a.ClientSecret,
				Region:        a.Region,
				ExpiresAt:     a.ExpiresAt * 1000, // 转为毫秒时间戳
				AuthMethod:    authMethod,
				Provider:      a.Provider,
				TokenEndpoint: a.TokenEndpoint,
				IssuerURL:     a.IssuerURL,
				Scopes:        a.Scopes,
			},
			Subscription: ExportSubscription{
				Type:  subType,
				Title: a.SubscriptionTitle,
			},
			Usage: ExportUsage{
				Current:     a.UsageCurrent,
				Limit:       a.UsageLimit,
				PercentUsed: a.UsagePercent,
				LastUpdated: time.Now().UnixMilli(),
			},
			Tags:       []string{},
			Status:     "active",
			CreatedAt:  time.Now().UnixMilli(),
			LastUsedAt: time.Now().UnixMilli(),
		})
	}

	data := ExportData{
		Version:    config.Version,
		ExportedAt: time.Now().UnixMilli(),
		Accounts:   exportAccounts,
		Groups:     []interface{}{},
		Tags:       []interface{}{},
	}

	json.NewEncoder(w).Encode(data)
}

func clampInt(v, min, max int) int {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

// proxyExternalClaudeToOpenAI intercepts a Claude API request, transforms it into a basic OpenAI request,
// sends it to external URL with stream=false, and mocks a Claude SSE stream response.
func (h *Handler) proxyExternalClaudeToOpenAI(w http.ResponseWriter, r *http.Request, req *ClaudeRequest, ext config.ExternalAPIConfig) bool {
	reqStart := time.Now()
	apiKeyID := apiKeyIDFromContext(r.Context())

	baseURL := strings.TrimSuffix(ext.BaseURL, "/")
	targetURL := baseURL
	displayURL := strings.TrimPrefix(strings.TrimPrefix(baseURL, "https://"), "http://")
	allowed, releaseProbe := externalCircuitAcquire(baseURL, time.Now())
	if !allowed {
		logger.Debugf("[ExternalAPI] Circuit open for %s; using Kiro account pool", displayURL)
		return false
	}
	defer releaseProbe()
	if strings.HasSuffix(targetURL, "/v1") {
		targetURL += "/chat/completions"
	} else if !strings.HasSuffix(targetURL, "/v1/chat/completions") && !strings.HasSuffix(targetURL, "/chat/completions") {
		targetURL += "/v1/chat/completions"
	}

	// 1. Transform ClaudeRequest to simple OpenAI request
	var openaiMessages []map[string]interface{}

	// System prompt
	if req.System != nil {
		sysStr := ""
		switch v := req.System.(type) {
		case string:
			sysStr = v
		case []interface{}:
			for _, b := range v {
				if bm, ok := b.(map[string]interface{}); ok {
					if txt, ok := bm["text"].(string); ok {
						sysStr += txt + "\n"
					}
				}
			}
		}
		if sysStr != "" {
			openaiMessages = append(openaiMessages, map[string]interface{}{
				"role":    "system",
				"content": sysStr,
			})
		}
	}

	// Messages
	for _, m := range req.Messages {
		contentStr := ""
		switch v := m.Content.(type) {
		case string:
			contentStr = v
		case []interface{}:
			for _, b := range v {
				if bm, ok := b.(map[string]interface{}); ok {
					if txt, ok := bm["text"].(string); ok {
						contentStr += txt + "\n"
					} else if bType, ok := bm["type"].(string); ok && bType == "tool_use" {
						contentStr += fmt.Sprintf("[Tool Use: %v]\n", bm["name"])
					} else if bType == "tool_result" {
						contentStr += fmt.Sprintf("[Tool Result: %v]\n", bm["content"])
					}
				}
			}
		}
		openaiMessages = append(openaiMessages, map[string]interface{}{
			"role":    m.Role,
			"content": contentStr,
		})
	}

	mappedModel := req.Model
	openaiReq := map[string]interface{}{
		"model":    mappedModel,
		"messages": openaiMessages,
		"stream":   false, // Force stream=false to avoid tokenrouter freeze
	}

	bodyBytes, _ := json.Marshal(openaiReq)

	outReq, err := http.NewRequestWithContext(r.Context(), "POST", targetURL, bytes.NewReader(bodyBytes))
	if err != nil {
		h.sendClaudeError(w, 500, "api_error", "Failed to create internal request")
		return false
	}

	outReq.Header.Set("Content-Type", "application/json")
	if ext.AuthToken != "" {
		outReq.Header.Set("Authorization", "Bearer "+ext.AuthToken)
	} else if ext.APIKey != "" {
		outReq.Header.Set("Authorization", "Bearer "+ext.APIKey)
	}

	clientTimeout := 10 * time.Minute
	if ext.TimeoutMS > 0 {
		clientTimeout = time.Duration(ext.TimeoutMS) * time.Millisecond
	}
	client := &http.Client{Timeout: clientTimeout}

	resp, err := client.Do(outReq)
	if err != nil {
		if cooldown, opened := externalCircuitFailure(baseURL, "", clientTimeout); opened {
			logger.Warnf("[ExternalAPI] Circuit opened for %s for %s after repeated transport failures", displayURL, cooldown)
		}
		h.recordFailureWithDuration("claude", req.Model, displayURL, err, time.Since(reqStart).Milliseconds())
		return false
	}
	defer resp.Body.Close()
	if isRetryableExternalStatus(resp.StatusCode) {
		if cooldown, opened := externalCircuitFailure(baseURL, resp.Header.Get("Retry-After"), clientTimeout); opened {
			logger.Warnf("[ExternalAPI] Circuit opened for %s for %s after repeated HTTP %d responses", displayURL, cooldown, resp.StatusCode)
		}
		h.recordFailureWithDuration("claude", req.Model, displayURL, fmt.Errorf("HTTP %d", resp.StatusCode), time.Since(reqStart).Milliseconds())
		return false
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		externalCircuitSuccess(baseURL)
	}

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		h.recordFailureWithDuration("claude", req.Model, displayURL, fmt.Errorf("HTTP %d", resp.StatusCode), time.Since(reqStart).Milliseconds())
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		w.Write(respBody)
		return true
	}

	// Parse OpenAI response
	var openaiResp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
		} `json:"usage"`
	}
	json.Unmarshal(respBody, &openaiResp)

	replyText := ""
	if len(openaiResp.Choices) > 0 {
		replyText = openaiResp.Choices[0].Message.Content
	}

	inTokens := openaiResp.Usage.PromptTokens
	outTokens := openaiResp.Usage.CompletionTokens

	// Mock Claude response
	if req.Stream {
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		flusher, _ := w.(http.Flusher)

		msgID := "msg_" + uuid.New().String()

		// message_start
		startEv := map[string]interface{}{
			"type": "message_start",
			"message": map[string]interface{}{
				"id":            msgID,
				"type":          "message",
				"role":          "assistant",
				"model":         mappedModel,
				"content":       []interface{}{},
				"stop_reason":   nil,
				"stop_sequence": nil,
				"usage":         map[string]interface{}{"input_tokens": inTokens, "output_tokens": 0},
			},
		}
		startBytes, _ := json.Marshal(startEv)
		fmt.Fprintf(w, "event: message_start\ndata: %s\n\n", startBytes)

		// content_block_start
		cbStart := map[string]interface{}{
			"type":          "content_block_start",
			"index":         0,
			"content_block": map[string]interface{}{"type": "text", "text": ""},
		}
		cbStartBytes, _ := json.Marshal(cbStart)
		fmt.Fprintf(w, "event: content_block_start\ndata: %s\n\n", cbStartBytes)

		// Stream content in chunks to mimic real stream
		chunkSize := 20
		for i := 0; i < len(replyText); i += chunkSize {
			end := i + chunkSize
			if end > len(replyText) {
				end = len(replyText)
			}
			chunk := replyText[i:end]
			cbDelta := map[string]interface{}{
				"type":  "content_block_delta",
				"index": 0,
				"delta": map[string]interface{}{"type": "text_delta", "text": chunk},
			}
			cbDeltaBytes, _ := json.Marshal(cbDelta)
			fmt.Fprintf(w, "event: content_block_delta\ndata: %s\n\n", cbDeltaBytes)
			if flusher != nil {
				flusher.Flush()
			}
			time.Sleep(10 * time.Millisecond)
		}

		// content_block_stop
		cbStop := map[string]interface{}{"type": "content_block_stop", "index": 0}
		cbStopBytes, _ := json.Marshal(cbStop)
		fmt.Fprintf(w, "event: content_block_stop\ndata: %s\n\n", cbStopBytes)

		// message_delta
		msgDelta := map[string]interface{}{
			"type":  "message_delta",
			"delta": map[string]interface{}{"stop_reason": "end_turn", "stop_sequence": nil},
			"usage": map[string]interface{}{"output_tokens": outTokens},
		}
		msgDeltaBytes, _ := json.Marshal(msgDelta)
		fmt.Fprintf(w, "event: message_delta\ndata: %s\n\n", msgDeltaBytes)

		// message_stop
		msgStop := map[string]interface{}{"type": "message_stop"}
		msgStopBytes, _ := json.Marshal(msgStop)
		fmt.Fprintf(w, "event: message_stop\ndata: %s\n\n", msgStopBytes)

	} else {
		// Non-stream response
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		respData := map[string]interface{}{
			"id":    "msg_" + uuid.New().String(),
			"type":  "message",
			"role":  "assistant",
			"model": mappedModel,
			"content": []map[string]interface{}{
				{"type": "text", "text": replyText},
			},
			"stop_reason":   "end_turn",
			"stop_sequence": nil,
			"usage":         map[string]interface{}{"input_tokens": inTokens, "output_tokens": outTokens},
		}
		json.NewEncoder(w).Encode(respData)
	}

	h.recordSuccessForApiKey(apiKeyID, inTokens, outTokens, 0)
	h.recordSuccessLog("claude", req.Model, displayURL, inTokens+outTokens, 0, time.Since(reqStart).Milliseconds())
	return true
}
