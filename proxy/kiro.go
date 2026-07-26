// Package proxy is the core proxy layer for the Kiro API.
// It handles streaming API calls to the Kiro backend and parses AWS Event Stream responses.
package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"kiro-go/config"
	"kiro-go/logger"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// Endpoint configuration (auto-fallback on quota exhaustion).
type kiroEndpointProtocol uint8

const (
	kiroProtocolLegacyStreaming kiroEndpointProtocol = iota
	kiroProtocolRuntime
	kiroProtocolCLI
)

type kiroEndpoint struct {
	URL       string
	Origin    string
	AmzTarget string
	Name      string
	Protocol  kiroEndpointProtocol
}

type resolvedKiroEndpoint struct {
	URL          string
	HeaderValues kiroHeaderValues
	ContentType  string
	AgentMode    bool
}

var kiroEndpoints = []kiroEndpoint{
	{
		URL:      "https://runtime.us-east-1.kiro.dev/generateAssistantResponse",
		Origin:   "AI_EDITOR",
		Name:     "Kiro Runtime",
		Protocol: kiroProtocolRuntime,
	},
	{
		URL:       "https://codewhisperer.us-east-1.amazonaws.com/generateAssistantResponse",
		Origin:    "AI_EDITOR",
		AmzTarget: "AmazonCodeWhispererStreamingService.GenerateAssistantResponse",
		Name:      "CodeWhisperer",
	},
	{
		URL:       "https://q.us-east-1.amazonaws.com/generateAssistantResponse",
		Origin:    "AI_EDITOR",
		AmzTarget: "AmazonQDeveloperStreamingService.SendMessage",
		Name:      "AmazonQ",
	},
}

// kiroCLIEndpoint is the headless / API Key path used by Kiro CLI:
// POST https://runtime.{region}.kiro.dev/ with AWS JSON 1.0 protocol.
var kiroCLIEndpoint = kiroEndpoint{
	URL:       "https://runtime.us-east-1.kiro.dev/",
	Origin:    "KIRO_CLI",
	AmzTarget: "AmazonCodeWhispererStreamingService.GenerateAssistantResponse",
	Name:      "Kiro CLI",
	Protocol:  kiroProtocolCLI,
}

// Global HTTP clients, swappable at runtime to apply proxy reconfiguration without restart.
var kiroHttpStore atomic.Pointer[http.Client]
var kiroRestHttpStore atomic.Pointer[http.Client]

// proxyClientCache caches http.Client instances keyed by proxy URL for per-account proxy support.
var proxyClientCache sync.Map

func init() {
	InitKiroHttpClient("")
}

// GetClientForProxy returns an http.Client configured for the given proxy URL.
// If proxyURL is empty, returns the global kiro HTTP client.
func GetClientForProxy(proxyURL string) *http.Client {
	if proxyURL == "" {
		return kiroHttpStore.Load()
	}
	if cached, ok := proxyClientCache.Load(proxyURL); ok {
		return cached.(*http.Client)
	}
	client := &http.Client{
		Timeout:   5 * time.Minute,
		Transport: buildKiroTransport(proxyURL),
	}
	proxyClientCache.Store(proxyURL, client)
	return client
}

// GetRestClientForProxy returns a rest http.Client (30s timeout) for the given proxy URL.
// If proxyURL is empty, returns the global kiro REST HTTP client.
func GetRestClientForProxy(proxyURL string) *http.Client {
	if proxyURL == "" {
		return kiroRestHttpStore.Load()
	}
	cacheKey := "rest:" + proxyURL
	if cached, ok := proxyClientCache.Load(cacheKey); ok {
		return cached.(*http.Client)
	}
	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: buildKiroTransport(proxyURL),
	}
	proxyClientCache.Store(cacheKey, client)
	return client
}

// ResolveAccountProxyURL returns the effective proxy URL for an account.
// Falls back to global config.GetProxyURL() if the account has no per-account proxy.
func ResolveAccountProxyURL(account *config.Account) string {
	if account != nil && account.ProxyURL != "" {
		return account.ProxyURL
	}
	return config.GetProxyURL()
}

// buildKiroTransport constructs an HTTP Transport with optional outbound proxy support.
func buildKiroTransport(proxyURL string) *http.Transport {
	t := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  false,
		ForceAttemptHTTP2:   true,
	}
	if proxyURL != "" {
		if u, err := url.Parse(proxyURL); err == nil {
			t.Proxy = http.ProxyURL(u)
			// Proxied connections cannot negotiate HTTP/2.
			t.ForceAttemptHTTP2 = false
		}
	} else {
		t.Proxy = http.ProxyFromEnvironment
	}
	return t
}

// InitKiroHttpClient initializes (or reinitializes) the HTTP clients used for Kiro API requests.
func InitKiroHttpClient(proxyURL string) {
	client := &http.Client{
		Timeout:   5 * time.Minute,
		Transport: buildKiroTransport(proxyURL),
	}
	kiroHttpStore.Store(client)

	restClient := &http.Client{
		Timeout:   30 * time.Second,
		Transport: buildKiroTransport(proxyURL),
	}
	kiroRestHttpStore.Store(restClient)
}

// ==================== Request Structs ====================

// KiroPayload is the top-level request body sent to the Kiro API.
type KiroPayload struct {
	ConversationState struct {
		AgentContinuationId string `json:"agentContinuationId,omitempty"`
		AgentTaskType       string `json:"agentTaskType,omitempty"`
		ChatTriggerType     string `json:"chatTriggerType"`
		ConversationID      string `json:"conversationId"`
		CurrentMessage      struct {
			UserInputMessage KiroUserInputMessage `json:"userInputMessage"`
		} `json:"currentMessage"`
		History []KiroHistoryMessage `json:"history,omitempty"`
	} `json:"conversationState"`
	ProfileArn      string           `json:"profileArn,omitempty"`
	InferenceConfig *InferenceConfig `json:"inferenceConfig,omitempty"`

	// ToolNameMap maps sanitized tool names (sent to Kiro) back to the
	// original names supplied by the client. Used to restore original names
	// in tool_use responses so the client can match them to its tool registry.
	// Not serialized to the Kiro API request body.
	ToolNameMap map[string]string `json:"-"`
}

type KiroUserInputMessage struct {
	Content                 string                   `json:"content"`
	ModelID                 string                   `json:"modelId,omitempty"`
	Origin                  string                   `json:"origin"`
	Images                  []KiroImage              `json:"images,omitempty"`
	Documents               []KiroDocument           `json:"documents,omitempty"`
	UserInputMessageContext *UserInputMessageContext `json:"userInputMessageContext,omitempty"`
}

type UserInputMessageContext struct {
	Tools       []KiroToolWrapper `json:"tools,omitempty"`
	ToolResults []KiroToolResult  `json:"toolResults,omitempty"`
}

type KiroToolWrapper struct {
	ToolSpecification struct {
		Name        string      `json:"name"`
		Description string      `json:"description"`
		InputSchema InputSchema `json:"inputSchema"`
	} `json:"toolSpecification"`
}

type InputSchema struct {
	JSON interface{} `json:"json"`
}

type KiroToolResult struct {
	ToolUseID string              `json:"toolUseId"`
	Content   []KiroResultContent `json:"content"`
	Status    string              `json:"status"`
}

type KiroResultContent struct {
	Text string `json:"text"`
}

type KiroImage struct {
	Format string `json:"format"`
	Source struct {
		Bytes string `json:"bytes"`
	} `json:"source"`
}

// KiroDocument is a non-image attachment (PDF, office, text, ...).
type KiroDocument struct {
	Name   string `json:"name"`
	Format string `json:"format"`
	Source struct {
		Bytes string `json:"bytes"`
	} `json:"source"`
}

// KiroReasoningContent is the signed thinking stamp upstream expects on later
// turns. Either open text+signature or redacted content.
type KiroReasoningContent struct {
	ReasoningText *struct {
		Text      string `json:"text"`
		Signature string `json:"signature"`
	} `json:"reasoningText,omitempty"`
	RedactedContent []byte `json:"redactedContent,omitempty"`
}

type KiroHistoryMessage struct {
	UserInputMessage         *KiroUserInputMessage         `json:"userInputMessage,omitempty"`
	AssistantResponseMessage *KiroAssistantResponseMessage `json:"assistantResponseMessage,omitempty"`
}

type KiroAssistantResponseMessage struct {
	Content          string                `json:"content"`
	ToolUses         []KiroToolUse         `json:"toolUses,omitempty"`
	ReasoningContent *KiroReasoningContent `json:"reasoningContent,omitempty"`
}

type KiroToolUse struct {
	ToolUseID string                 `json:"toolUseId"`
	Name      string                 `json:"name"`
	Input     map[string]interface{} `json:"input"`
}

type InferenceConfig struct {
	MaxTokens   int     `json:"maxTokens,omitempty"`
	Temperature float64 `json:"temperature,omitempty"`
	TopP        float64 `json:"topP,omitempty"`
}

// ==================== Stream Callbacks ====================

// KiroStreamCallback stream response callbacks
type KiroStreamCallback struct {
	OnText         func(text string, isThinking bool)
	OnToolUse      func(toolUse KiroToolUse)
	OnComplete     func(inputTokens, outputTokens int)
	OnError        func(err error)
	OnCredits      func(credits float64)
	OnContextUsage func(percentage float64)
	// OnStopReason is fired when a metadataEvent carries stopReason.
	// Absence after content is how callers detect a truncated stream
	// (Kiro IDE retries those; see _streamResponseChunks).
	OnStopReason func(reason string)
	// OnReasoningMeta carries only the validation stamp for a thinking
	// segment. Visible text still arrives via OnText(..., true).
	OnReasoningMeta func(signature, redactedBase64 string)
}

// ==================== API Call ====================

func setPayloadProfileArnForAccount(payload *KiroPayload, account *config.Account) {
	if payload == nil {
		return
	}

	// API Key credentials must not carry IDE/profile semantics.
	if config.IsAPIKeyAccount(account) {
		payload.ProfileArn = ""
		return
	}

	payload.ProfileArn = strings.TrimSpace(payload.ProfileArn)
	if account != nil {
		if profileArn := strings.TrimSpace(account.ProfileArn); profileArn != "" {
			payload.ProfileArn = profileArn
		}
	}
}

// endpointsForAccount returns the upstream endpoint list for a credential.
// API Key accounts always use the CLI runtime protocol; OAuth accounts keep
// the configured preferred-endpoint fallback chain.
func endpointsForAccount(account *config.Account) []kiroEndpoint {
	if config.IsAPIKeyAccount(account) {
		return []kiroEndpoint{kiroCLIEndpoint}
	}
	return getSortedEndpoints(config.GetPreferredEndpoint())
}

func resolveKiroEndpoint(endpoint kiroEndpoint, account *config.Account, profileArn string) (resolvedKiroEndpoint, error) {
	region := kiroRegionForProfile(account, profileArn)
	resolvedURL := endpoint.URL
	if endpoint.Protocol == kiroProtocolRuntime || endpoint.Protocol == kiroProtocolCLI {
		resolvedURL = strings.Replace(endpoint.URL, "runtime.us-east-1.kiro.dev", "runtime."+region+".kiro.dev", 1)
	} else if endpoint.Protocol == kiroProtocolLegacyStreaming {
		resolvedURL = regionalizeURLForProfile(endpoint.URL, account, profileArn)
	} else {
		return resolvedKiroEndpoint{}, fmt.Errorf("unsupported Kiro endpoint protocol %d", endpoint.Protocol)
	}
	parsed, err := url.Parse(resolvedURL)
	if err != nil || parsed.Host == "" {
		return resolvedKiroEndpoint{}, fmt.Errorf("invalid Kiro endpoint URL %q", resolvedURL)
	}

	resolved := resolvedKiroEndpoint{URL: resolvedURL, ContentType: "application/json", AgentMode: true}
	switch endpoint.Protocol {
	case kiroProtocolRuntime:
		resolved.HeaderValues = buildKiroRuntimeHeaderValues(account, parsed.Host)
	case kiroProtocolCLI:
		resolved.HeaderValues = buildKiroCLIHeaderValues(parsed.Host, "codewhispererstreaming")
		resolved.ContentType = "application/x-amz-json-1.0"
		resolved.AgentMode = false
	case kiroProtocolLegacyStreaming:
		resolved.HeaderValues = buildLegacyStreamingHeaderValues(account, parsed.Host)
	}
	return resolved, nil
}

// getSortedEndpoints returns endpoints ordered by user preference, with optional fallback.
func getSortedEndpoints(preferred string) []kiroEndpoint {
	fallback := config.GetEndpointFallback()

	var primary int
	switch preferred {
	case "kiro":
		primary = 0
	case "codewhisperer":
		primary = 1
	case "amazonq":
		primary = 2
	default:
		// "auto": Kiro first, then fallback to others
		return []kiroEndpoint{kiroEndpoints[0], kiroEndpoints[1], kiroEndpoints[2]}
	}

	if !fallback {
		// No fallback: only use the selected endpoint
		return []kiroEndpoint{kiroEndpoints[primary]}
	}

	// With fallback: selected first, then others in order
	result := []kiroEndpoint{kiroEndpoints[primary]}
	for i, ep := range kiroEndpoints {
		if i != primary {
			result = append(result, ep)
		}
	}
	return result
}

// CallKiroAPI calls the Kiro streaming API, trying each configured endpoint with automatic fallback.
func CallKiroAPI(account *config.Account, payload *KiroPayload, callback *KiroStreamCallback) error {
	originalProfileArn := ""
	if payload != nil {
		originalProfileArn = payload.ProfileArn
		defer func() {
			payload.ProfileArn = originalProfileArn
		}()
	}
	setPayloadProfileArnForAccount(payload, account)

	if _, err := json.Marshal(payload); err != nil {
		return err
	}

	// Debug: dump full payload for troubleshooting upstream rejections
	if payloadJSON, err := json.Marshal(payload); err == nil {
		logger.Debugf("[KiroAPI] Request payload: %s", string(payloadJSON))
	}

	// Wrap OnToolUse to restore original tool names for the client.
	if callback != nil && callback.OnToolUse != nil && len(payload.ToolNameMap) > 0 {
		originalOnToolUse := callback.OnToolUse
		nameMap := payload.ToolNameMap
		wrapped := *callback
		wrapped.OnToolUse = func(tu KiroToolUse) {
			if original, ok := nameMap[tu.Name]; ok {
				tu.Name = original
			}
			originalOnToolUse(tu)
		}
		callback = &wrapped
	}

	if payload != nil && strings.TrimSpace(payload.ProfileArn) == "" && !config.IsAPIKeyAccount(account) {
		if profileArn, err := ResolveProfileArn(account); err == nil {
			payload.ProfileArn = profileArn
		} else if isProfileArnResolutionSoftError(err) {
			logger.Debugf("[ProfileArn] Skipped profile ARN resolution for %s: %v", accountEmailForLog(account), err)
		} else {
			logger.Warnf("[ProfileArn] Failed to resolve profile ARN for %s: %v", accountEmailForLog(account), err)
		}
	}

	// Build endpoint list ordered by configuration / credential type.
	endpoints := endpointsForAccount(account)

	var lastErr error
	for _, ep := range endpoints {
		// Update the origin field for the selected endpoint.
		payload.ConversationState.CurrentMessage.UserInputMessage.Origin = ep.Origin

		resolved, err := resolveKiroEndpoint(ep, account, payload.ProfileArn)
		if err != nil {
			lastErr = err
			continue
		}

		reqBody, _ := json.Marshal(payload)
		req, err := http.NewRequest("POST", resolved.URL, bytes.NewReader(reqBody))
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("Content-Type", resolved.ContentType)
		req.Header.Set("Accept", "*/*")
		if ep.AmzTarget != "" {
			req.Header.Set("X-Amz-Target", ep.AmzTarget)
		}
		applyKiroBaseHeaders(req, account, resolved.HeaderValues)
		if resolved.AgentMode {
			req.Header.Set("x-amzn-kiro-agent-mode", "vibe")
		}
		req.Header.Set("Amz-Sdk-Request", "attempt=1; max=3")
		req.Header.Set("Amz-Sdk-Invocation-Id", uuid.New().String())

		resp, err := GetClientForProxy(ResolveAccountProxyURL(account)).Do(req)
		if err != nil {
			lastErr = err
			logger.Warnf("[KiroAPI] Endpoint %s failed: %v", ep.Name, err)
			continue
		}

		if resp.StatusCode == 429 {
			resp.Body.Close()
			logger.Warnf("[KiroAPI] Endpoint %s quota exhausted (429), trying next...", ep.Name)
			lastErr = fmt.Errorf("quota exhausted on %s", ep.Name)
			continue
		}

		if resp.StatusCode != 200 {
			errBody, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			lastErr = fmt.Errorf("HTTP %d from %s: %s", resp.StatusCode, ep.Name, string(errBody))
			// Authentication errors and payment errors are not retried across endpoints.
			if resp.StatusCode == 401 || resp.StatusCode == 403 || resp.StatusCode == 402 {
				return lastErr
			}
			logger.Warnf("[KiroAPI] Endpoint %s error: %v", ep.Name, lastErr)
			continue
		}

		err = parseEventStream(resp.Body, callback)
		resp.Body.Close()
		return err
	}

	if lastErr != nil {
		return lastErr
	}
	return fmt.Errorf("all endpoints failed")
}

func accountEmailForLog(account *config.Account) string {
	if account == nil {
		return "<nil>"
	}
	return account.Email
}

// ==================== Event Stream Parsing ====================

// parseEventStream decodes an AWS binary Event Stream response body.
func parseEventStream(body io.Reader, callback *KiroStreamCallback) error {
	if callback == nil {
		callback = &KiroStreamCallback{}
	}

	var inputTokens, outputTokens int
	var totalCredits float64
	pending := &pendingToolUses{}

	for {
		message, err := readEventStreamMessage(body)
		if err != nil {
			return err
		}
		if message == nil {
			break
		}

		messageType := strings.TrimSpace(message.headers[":message-type"])
		if messageType == "" {
			return fmt.Errorf("event stream message missing :message-type header")
		}

		if messageType == "error" || messageType == "exception" {
			var event map[string]interface{}
			headerMessage := message.headers[":error-message"]
			if len(message.payload) > 0 && string(message.payload) != "null" {
				if err := json.Unmarshal(message.payload, &event); err != nil && headerMessage == "" {
					headerMessage = strings.TrimSpace(string(message.payload))
				}
			}
			if event == nil {
				event = map[string]interface{}{}
			}
			code := message.headers[":error-code"]
			if messageType == "exception" {
				code = message.headers[":exception-type"]
			}
			return newUpstreamEventStreamError(messageType, code, headerMessage, event)
		}
		if messageType != "event" {
			return fmt.Errorf("unsupported event stream message type %q", messageType)
		}

		eventType := strings.TrimSpace(message.headers[":event-type"])
		if eventType == "" {
			return fmt.Errorf("event stream event missing :event-type header")
		}

		var event map[string]interface{}
		if len(message.payload) > 0 {
			if err := json.Unmarshal(message.payload, &event); err != nil {
				return fmt.Errorf("decode event stream %s payload: %w", eventType, err)
			}
		}
		if event == nil {
			event = map[string]interface{}{}
		}

		inputTokens, outputTokens = updateTokensFromEvent(event, inputTokens, outputTokens)

		switch eventType {
		case "assistantResponseEvent":
			if content, ok := event["content"].(string); ok && content != "" && callback.OnText != nil {
				callback.OnText(content, false)
			}
		case "reasoningContentEvent":
			if text, ok := event["text"].(string); ok && text != "" && callback.OnText != nil {
				callback.OnText(text, true)
			}
			if callback.OnReasoningMeta != nil {
				sig, _ := event["signature"].(string)
				redacted, _ := event["redactedContent"].(string)
				if sig != "" || redacted != "" {
					callback.OnReasoningMeta(sig, redacted)
				}
			}
		case "toolUseEvent":
			if err := handleToolUseEvent(event, pending); err != nil {
				return err
			}
		case "meteringEvent":
			if usage, ok := event["usage"].(float64); ok {
				totalCredits += usage
			}
		case "contextUsageEvent":
			if pct, ok := event["contextUsagePercentage"].(float64); ok && callback.OnContextUsage != nil {
				callback.OnContextUsage(pct)
			}
		case "metadataEvent":
			if reason := firstStringField(event, "stopReason", "stop_reason"); reason != "" && callback.OnStopReason != nil {
				callback.OnStopReason(reason)
			}
		case "error", "throttlingError", "validationError", "serviceUnavailableError", "invalidStateEvent":
			return newUpstreamEventStreamError("event", eventType, "", event)
		case "codeReferenceEvent", "documentCitationEvent", "toolResultEvent",
			"supplementaryWebLinksEvent", "messageMetadataEvent", "interactionComponentsEvent",
			"intentsEvent", "followupPromptEvent", "citationEvent", "codeEvent", "dryRunSucceedEvent":
			// These official metadata/presentation events have no portable
			// representation in the OpenAI/Anthropic compatibility APIs.
			logger.Debugf("[EventStream] ignoring known optional event %s", eventType)
		default:
			return fmt.Errorf("unsupported upstream event stream event %q", eventType)
		}
	}

	// Flush tools that omitted an explicit stop frame. Any invalid argument
	// buffer makes the entire parallel tool turn fail.
	if err := pending.flushAll(callback); err != nil {
		return err
	}

	if callback.OnCredits != nil && totalCredits > 0 {
		callback.OnCredits(totalCredits)
	}
	if callback.OnComplete != nil {
		callback.OnComplete(inputTokens, outputTokens)
	}
	return nil
}

func updateTokensFromEvent(event map[string]interface{}, currentInputTokens, currentOutputTokens int) (int, int) {
	candidates := []map[string]interface{}{event}
	collectUsageMaps(event, &candidates)

	inputTokens := currentInputTokens
	outputTokens := currentOutputTokens

	for _, usage := range candidates {
		if usage == nil {
			continue
		}

		if v, ok := readTokenNumber(usage,
			"outputTokens", "completionTokens", "totalOutputTokens",
			"output_tokens", "completion_tokens", "total_output_tokens",
		); ok {
			outputTokens = v
		}

		if v, ok := readTokenNumber(usage,
			"inputTokens", "promptTokens", "totalInputTokens",
			"input_tokens", "prompt_tokens", "total_input_tokens",
		); ok {
			inputTokens = v
			continue
		}

		uncached, _ := readTokenNumber(usage, "uncachedInputTokens", "uncached_input_tokens")
		cacheRead, _ := readTokenNumber(usage, "cacheReadInputTokens", "cache_read_input_tokens")
		cacheWrite, _ := readTokenNumber(usage, "cacheWriteInputTokens", "cache_write_input_tokens", "cacheCreationInputTokens", "cache_creation_input_tokens")
		if uncached+cacheRead+cacheWrite > 0 {
			inputTokens = uncached + cacheRead + cacheWrite
			continue
		}

		total, ok := readTokenNumber(usage, "totalTokens", "total_tokens")
		if ok && total > 0 {
			candidateOutput := outputTokens
			if v, vok := readTokenNumber(usage,
				"outputTokens", "completionTokens", "totalOutputTokens",
				"output_tokens", "completion_tokens", "total_output_tokens",
			); vok {
				candidateOutput = v
			}
			if total-candidateOutput > 0 {
				inputTokens = total - candidateOutput
			}
		}
	}

	return inputTokens, outputTokens
}

// getContextWindowSize returns the context window size (in tokens) for a model.
//
// Per Kiro's ListAvailableModels, the 1M-token context window applies to
// Claude 4.6 and newer (sonnet-4.6, opus-4.6, opus-4.7, opus-4.8, and future
// 4.x releases), while 4.5 and earlier (opus-4.5, sonnet-4.5, sonnet-4,
// haiku-4.5) use a 200K window. This value is used to convert the upstream
// contextUsagePercentage into an absolute input-token count that clients rely
// on to decide when to compact; an undersized window under-reports tokens and
// prevents clients from compacting in time.
func getContextWindowSize(model string) int {
	if isLargeContextModel(model) {
		return 1_000_000
	}
	return 200_000
}

// claudeVersionExtractor matches "claude-<family>-<major>[.<minor>]" (dot or
// dash form) and is used to classify 1M-window models by version. The minor
// component is optional so major-only identifiers such as "claude-opus-5"
// classify correctly instead of falling through to the 200K default.
var claudeVersionExtractor = regexp.MustCompile(`claude-(?:opus|sonnet|haiku)-(\d+)(?:[.-](\d+))?`)

func isLargeContextModel(model string) bool {
	m := strings.ToLower(model)
	if match := claudeVersionExtractor.FindStringSubmatch(m); match != nil {
		major, errMaj := strconv.Atoi(match[1])
		if errMaj == nil {
			// 1M window for any major >= 5 (claude-opus-5, claude-opus-5.1, ...).
			if major > 4 {
				return true
			}
			// Within Claude 4.x the window depends on the minor version, so an
			// absent minor (claude-sonnet-4) is treated as 4.0 -> 200K.
			minor := 0
			if match[2] != "" {
				parsed, errMin := strconv.Atoi(match[2])
				if errMin != nil {
					return false
				}
				minor = parsed
			}
			return major == 4 && minor >= 6
		}
	}
	// Fallback substring checks for non-standard identifiers.
	for _, tag := range []string{"4.6", "4-6", "4.7", "4-7", "4.8", "4-8", "4.9", "4-9"} {
		if strings.Contains(m, tag) {
			return true
		}
	}
	return false
}

func collectUsageMaps(v interface{}, out *[]map[string]interface{}) {
	switch t := v.(type) {
	case map[string]interface{}:
		for k, child := range t {
			lk := strings.ToLower(k)
			if lk == "usage" || lk == "tokenusage" || lk == "token_usage" {
				if m, ok := child.(map[string]interface{}); ok {
					*out = append(*out, m)
				}
			}
			collectUsageMaps(child, out)
		}
	case []interface{}:
		for _, child := range t {
			collectUsageMaps(child, out)
		}
	}
}

func readTokenNumber(m map[string]interface{}, keys ...string) (int, bool) {
	for _, k := range keys {
		v, ok := m[k]
		if !ok {
			continue
		}
		switch n := v.(type) {
		case float64:
			return int(n), true
		case int:
			return n, true
		case int64:
			return int(n), true
		case json.Number:
			if parsed, err := n.Int64(); err == nil {
				return int(parsed), true
			}
		case string:
			if parsed, err := strconv.Atoi(n); err == nil {
				return parsed, true
			}
			if parsed, err := strconv.ParseFloat(n, 64); err == nil {
				return int(parsed), true
			}
		}
	}
	return 0, false
}

// ==================== Tool Use Handling ====================

type toolUseState struct {
	ToolUseID   string
	Name        string
	InputBuffer strings.Builder
	SawInput    bool
	GeneratedID bool
}

// pendingToolUses tracks in-flight tool calls for one stream. Entries are keyed
// by toolUseId so interleaved parallel frames accumulate independently, and
// `order` preserves arrival sequence: tool call order is semantic for clients,
// so a bare map range (randomised in Go) must never decide emit order.
type pendingToolUses struct {
	byID      map[string]*toolUseState
	completed map[string]KiroToolUse
	order     []string
	lastID    string
}

func (p *pendingToolUses) get(id string) *toolUseState {
	if p.byID == nil {
		return nil
	}
	return p.byID[id]
}

func (p *pendingToolUses) add(state *toolUseState) {
	if p.byID == nil {
		p.byID = map[string]*toolUseState{}
	}
	p.byID[state.ToolUseID] = state
	p.order = append(p.order, state.ToolUseID)
	p.lastID = state.ToolUseID
}

func (p *pendingToolUses) isCompleted(id string) bool {
	_, ok := p.completed[id]
	return ok
}

// rekey moves an entry from a generated id to the real id from upstream,
// keeping its position in the arrival order.
func (p *pendingToolUses) rekey(state *toolUseState, newID string) {
	oldID := state.ToolUseID
	delete(p.byID, oldID)
	for i, id := range p.order {
		if id == oldID {
			p.order[i] = newID
			break
		}
	}
	state.ToolUseID = newID
	state.GeneratedID = false
	p.byID[newID] = state
	if p.lastID == oldID {
		p.lastID = newID
	}
}

func (p *pendingToolUses) complete(state *toolUseState) error {
	toolUse, err := decodeToolUse(state)
	if err != nil {
		return err
	}
	if p.completed == nil {
		p.completed = make(map[string]KiroToolUse)
	}
	p.completed[state.ToolUseID] = toolUse
	delete(p.byID, state.ToolUseID)
	if p.lastID == state.ToolUseID {
		p.lastID = ""
		for i := len(p.order) - 1; i >= 0; i-- {
			if p.byID[p.order[i]] != nil {
				p.lastID = p.order[i]
				break
			}
		}
	}
	return nil
}

// flushAll validates the complete parallel set before exposing any tool to the
// caller. A malformed sibling therefore cannot leak an otherwise valid tool.
func (p *pendingToolUses) flushAll(callback *KiroStreamCallback) error {
	for _, id := range p.order {
		if p.isCompleted(id) {
			continue
		}
		if state := p.byID[id]; state != nil {
			if err := p.complete(state); err != nil {
				return err
			}
		}
	}
	if callback != nil && callback.OnToolUse != nil {
		for _, id := range p.order {
			if toolUse, ok := p.completed[id]; ok {
				callback.OnToolUse(toolUse)
			}
		}
	}
	p.byID = nil
	p.completed = nil
	p.order = nil
	p.lastID = ""
	return nil
}

// handleToolUseEvent accumulates a toolUseEvent into pending. Frames for
// different IDs remain independent; completed tools stay buffered until EOF.
func handleToolUseEvent(event map[string]interface{}, pending *pendingToolUses) error {
	toolUseID := firstStringField(event, "toolUseId", "toolUseID", "tool_use_id", "id")
	name := firstStringField(event, "name", "toolName", "tool_name")
	isStop := firstBoolField(event, "stop", "isStop", "done")

	var state *toolUseState
	switch {
	case toolUseID != "":
		if pending.isCompleted(toolUseID) {
			return nil
		}
		state = pending.get(toolUseID)
		if state == nil && pending.lastID != "" {
			if previous := pending.get(pending.lastID); previous != nil && previous.GeneratedID && (name == "" || previous.Name == name) {
				pending.rekey(previous, toolUseID)
				state = previous
			}
		}
		if state == nil {
			if name == "" {
				return nil
			}
			state = &toolUseState{ToolUseID: toolUseID, Name: name}
			pending.add(state)
		} else {
			if name != "" && state.Name == "" {
				state.Name = name
			}
			pending.lastID = state.ToolUseID
		}
	case pending.lastID != "" && pending.get(pending.lastID) != nil:
		state = pending.get(pending.lastID)
		if name != "" && state.Name != name {
			if err := pending.complete(state); err != nil {
				return err
			}
			state = &toolUseState{ToolUseID: "toolu_" + uuid.New().String(), Name: name, GeneratedID: true}
			pending.add(state)
		}
	case name != "":
		state = &toolUseState{ToolUseID: "toolu_" + uuid.New().String(), Name: name, GeneratedID: true}
		pending.add(state)
	default:
		return nil
	}

	if input, ok := event["input"].(string); ok {
		state.SawInput = true
		state.InputBuffer.WriteString(input)
	} else if inputObj, ok := event["input"].(map[string]interface{}); ok {
		state.SawInput = true
		data, _ := json.Marshal(inputObj)
		state.InputBuffer.Reset()
		state.InputBuffer.Write(data)
	}

	if isStop {
		return pending.complete(state)
	}
	return nil
}

func decodeToolUse(state *toolUseState) (KiroToolUse, error) {
	if state == nil || state.Name == "" {
		return KiroToolUse{}, fmt.Errorf("%w: missing tool identity", errIncompleteToolUse)
	}
	if state.ToolUseID == "" {
		state.ToolUseID = "toolu_" + uuid.New().String()
	}
	if !state.SawInput {
		return KiroToolUse{}, fmt.Errorf("%w: %s (%s): missing input", errIncompleteToolUse, state.Name, state.ToolUseID)
	}
	var input map[string]interface{}
	if state.InputBuffer.Len() > 0 {
		if err := json.Unmarshal([]byte(state.InputBuffer.String()), &input); err != nil {
			return KiroToolUse{}, fmt.Errorf("%w: %s (%s): %v", errIncompleteToolUse, state.Name, state.ToolUseID, err)
		}
	}
	if input == nil {
		input = make(map[string]interface{})
	}
	return KiroToolUse{
		ToolUseID: state.ToolUseID,
		Name:      state.Name,
		Input:     input,
	}, nil
}

func firstStringField(m map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if v, ok := m[key].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

func firstBoolField(m map[string]interface{}, keys ...string) bool {
	for _, key := range keys {
		if v, ok := m[key].(bool); ok {
			return v
		}
	}
	return false
}
