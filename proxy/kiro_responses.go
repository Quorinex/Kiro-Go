package proxy

// Upstream transport for Kiro's /v1/responses API.
//
// The legacy `generateAssistantResponse` operation (q.us-east-1 / codewhisperer)
// is no longer served: every request now comes back 403 FEATURE_NOT_SUPPORTED
// ("This version of Kiro is no longer supported"), regardless of the client
// version advertised. The Kiro IDE moved to POST /v1/responses on
// runtime.<region>.kiro.dev, which still answers for the same OAuth token.
//
// This file builds that request from the internal KiroPayload (field mapping
// mirrored from the IDE's own converter) and translates the upstream SSE event
// stream back into KiroStreamCallback calls.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"kiro-go/config"
	"kiro-go/logger"
)

const (
	// responsesProtocolResponses routes new-style requests to /v1/responses.
	responsesProtocolResponses = "responses"
	// responsesProtocolLegacy keeps the retired generateAssistantResponse path
	// available for debugging against a private backend.
	responsesProtocolLegacy = "legacy"
	// responsesDefaultOrigin matches the IDE's chat origin.
	responsesDefaultOrigin = "AI_EDITOR"
	// maxResponsesLineBytes bounds one SSE line (tool arguments can be large).
	maxResponsesLineBytes = 16 << 20
)

// responsesTool mirrors the IDE's tool projection:
// {type:"function", name, description, parameters}.
type responsesTool struct {
	Type        string      `json:"type"`
	Name        string      `json:"name"`
	Description string      `json:"description,omitempty"`
	Parameters  interface{} `json:"parameters,omitempty"`
}

// responsesRequest is the wire body for POST /v1/responses.
type responsesRequest struct {
	Model        string                   `json:"model"`
	Input        []map[string]interface{} `json:"input"`
	Instructions string                   `json:"instructions,omitempty"`
	Tools        []responsesTool          `json:"tools,omitempty"`
	Stream       bool                     `json:"stream"`
	Origin       string                   `json:"origin"`
	ProfileArn   string                   `json:"profileArn,omitempty"`
	Metadata     map[string]string        `json:"metadata,omitempty"`
	Reasoning    map[string]interface{}   `json:"reasoning,omitempty"`
}

type responsesUsage struct {
	Credits struct {
		Value float64 `json:"value"`
	} `json:"kiro:credits"`
	ContextUsagePercentage float64 `json:"kiro:context_usage_percentage"`
}

type responsesOutputItem struct {
	Type      string `json:"type"`
	ID        string `json:"id"`
	CallID    string `json:"call_id"`
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
	Status    string `json:"status"`
}

type responsesPayload struct {
	ID                string `json:"id"`
	Status            string `json:"status"`
	Model             string `json:"model"`
	IncompleteDetails *struct {
		Reason string `json:"reason"`
	} `json:"incomplete_details"`
	Usage  *responsesUsage       `json:"usage"`
	Output []responsesOutputItem `json:"output"`
}

// responsesEvent covers every SSE frame we care about; unknown types are ignored.
type responsesEvent struct {
	Type        string               `json:"type"`
	Delta       string               `json:"delta"`
	Arguments   string               `json:"arguments"`
	ItemID      string               `json:"item_id"`
	OutputIndex int                  `json:"output_index"`
	Item        *responsesOutputItem `json:"item"`
	Response    *responsesPayload    `json:"response"`
	Error       *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
		Code    string `json:"code"`
	} `json:"error"`
}

// useResponsesUpstream reports whether the responses transport should be used
// for this account. API-key accounts keep the legacy CLI runtime path.
func useResponsesUpstream(account *config.Account) bool {
	if account == nil || config.IsAPIKeyAccount(account) {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(config.GetUpstreamProtocol())) {
	case responsesProtocolLegacy:
		return false
	default:
		return true
	}
}

func responsesOrigin(payload *KiroPayload) string {
	if payload != nil {
		if origin := strings.TrimSpace(payload.ConversationState.CurrentMessage.UserInputMessage.Origin); origin != "" {
			return origin
		}
	}
	return responsesDefaultOrigin
}

// responsesEndpointURL is the regional /v1/responses endpoint for an account.
func responsesEndpointURL(account *config.Account) string {
	region := "us-east-1"
	if account != nil {
		if r := strings.TrimSpace(account.Region); r != "" {
			region = r
		}
	}
	return fmt.Sprintf("https://runtime.%s.kiro.dev/v1/responses", region)
}

// buildResponsesRequest projects the internal payload onto the IDE's wire shape.
func buildResponsesRequest(payload *KiroPayload) *responsesRequest {
	if payload == nil {
		return nil
	}
	cur := payload.ConversationState.CurrentMessage.UserInputMessage

	req := &responsesRequest{
		Model:      cur.ModelID,
		Input:      buildResponsesInput(payload),
		Stream:     true,
		Origin:     responsesOrigin(payload),
		ProfileArn: strings.TrimSpace(payload.ProfileArn),
	}
	req.Tools = buildResponsesTools(payload)

	meta := map[string]string{"kiro:agent_mode": "vibe"}
	if id := strings.TrimSpace(payload.ConversationState.ConversationID); id != "" {
		meta["kiro:conversation_id"] = id
	}
	if id := strings.TrimSpace(payload.ConversationState.AgentContinuationId); id != "" {
		meta["kiro:agent_continuation_id"] = id
	}
	if t := strings.TrimSpace(payload.ConversationState.AgentTaskType); t != "" {
		meta["kiro:agent_task_type"] = t
	}
	req.Metadata = meta
	req.Reasoning = buildResponsesReasoning(payload.AdditionalModelRequestFields)

	return req
}

// buildResponsesInput flattens history + current message into input items.
func buildResponsesInput(payload *KiroPayload) []map[string]interface{} {
	items := make([]map[string]interface{}, 0, len(payload.ConversationState.History)+1)
	for _, h := range payload.ConversationState.History {
		items = append(items, responsesItemsForHistory(h)...)
	}
	cur := payload.ConversationState.CurrentMessage.UserInputMessage
	items = append(items, responsesItemsForUser(cur)...)
	return items
}

func responsesItemsForHistory(h KiroHistoryMessage) []map[string]interface{} {
	if h.UserInputMessage != nil {
		return responsesItemsForUser(*h.UserInputMessage)
	}
	if h.AssistantResponseMessage != nil {
		return responsesItemsForAssistant(*h.AssistantResponseMessage)
	}
	return nil
}

func responsesItemsForUser(m KiroUserInputMessage) []map[string]interface{} {
	items := make([]map[string]interface{}, 0, 2)

	// Tool results come first, exactly like the IDE: one function_call_output
	// per toolUseId.
	if m.UserInputMessageContext != nil {
		for _, tr := range m.UserInputMessageContext.ToolResults {
			parts := make([]string, 0, len(tr.Content))
			for _, c := range tr.Content {
				parts = append(parts, c.Text)
			}
			items = append(items, map[string]interface{}{
				"type":    "function_call_output",
				"call_id": tr.ToolUseID,
				"output":  strings.Join(parts, "\n"),
			})
		}
	}

	content := m.Content
	hasMedia := len(m.Images) > 0
	if !hasMedia {
		if strings.TrimSpace(content) != "" {
			items = append(items, map[string]interface{}{"role": "user", "content": content})
		}
		return items
	}

	// Multimodal turn: text first, then images as data URLs.
	parts := make([]map[string]interface{}, 0, len(m.Images)+1)
	if content != "" {
		parts = append(parts, map[string]interface{}{"type": "input_text", "text": content})
	}
	for _, img := range m.Images {
		format := strings.ToLower(strings.TrimSpace(img.Format))
		if format == "" {
			format = "png"
		}
		parts = append(parts, map[string]interface{}{
			"type":      "input_image",
			"image_url": "data:image/" + format + ";base64," + img.Source.Bytes,
		})
	}
	if len(parts) > 0 {
		items = append(items, map[string]interface{}{"role": "user", "content": parts})
	}
	return items
}

func responsesItemsForAssistant(m KiroAssistantResponseMessage) []map[string]interface{} {
	items := make([]map[string]interface{}, 0, len(m.ToolUses)+1)
	if strings.TrimSpace(m.Content) != "" {
		items = append(items, map[string]interface{}{"role": "assistant", "content": m.Content})
	}
	for _, tu := range m.ToolUses {
		args, err := json.Marshal(tu.Input)
		if err != nil {
			args = []byte("{}")
		}
		items = append(items, map[string]interface{}{
			"type":      "function_call",
			"call_id":   tu.ToolUseID,
			"name":      tu.Name,
			"arguments": string(args),
		})
	}
	return items
}

func buildResponsesTools(payload *KiroPayload) []responsesTool {
	if payload == nil || payload.ConversationState.CurrentMessage.UserInputMessage.UserInputMessageContext == nil {
		return nil
	}
	wrappers := payload.ConversationState.CurrentMessage.UserInputMessage.UserInputMessageContext.Tools
	tools := make([]responsesTool, 0, len(wrappers))
	for _, w := range wrappers {
		spec := w.ToolSpecification
		if strings.TrimSpace(spec.Name) == "" {
			continue
		}
		tool := responsesTool{
			Type:        "function",
			Name:        spec.Name,
			Description: spec.Description,
		}
		if spec.InputSchema.JSON != nil {
			tool.Parameters = spec.InputSchema.JSON
		}
		tools = append(tools, tool)
	}
	if len(tools) == 0 {
		return nil
	}
	return tools
}

// buildResponsesReasoning maps the legacy additionalModelRequestFields onto the
// responses `reasoning` block: {type, effort, summary}.
func buildResponsesReasoning(fields map[string]interface{}) map[string]interface{} {
	if len(fields) == 0 {
		return nil
	}
	out := map[string]interface{}{}
	if thinking, ok := fields["thinking"].(map[string]interface{}); ok {
		if t, ok := thinking["type"].(string); ok && t != "" {
			out["type"] = t
		}
	}
	if cfg, ok := fields["output_config"].(map[string]interface{}); ok {
		if e, ok := cfg["effort"].(string); ok && e != "" {
			out["effort"] = e
		}
	}
	if r, ok := fields["reasoning"].(map[string]interface{}); ok {
		for _, key := range []string{"type", "effort", "summary"} {
			if v, ok := r[key].(string); ok && v != "" {
				out[key] = v
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// callKiroResponsesAPIContext sends the payload to /v1/responses and drives the
// callbacks from the SSE stream.
func callKiroResponsesAPIContext(ctx context.Context, account *config.Account, payload *KiroPayload, callback *KiroStreamCallback) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if payload == nil {
		return fmt.Errorf("nil kiro payload")
	}

	originalProfileArn := payload.ProfileArn
	defer func() { payload.ProfileArn = originalProfileArn }()
	setPayloadProfileArnForAccount(payload, account)

	// API-key accounts must not carry IDE/profile semantics; guard again here in
	// case the caller bypassed useResponsesUpstream.
	if strings.TrimSpace(payload.ProfileArn) == "" && !config.IsAPIKeyAccount(account) {
		if profileArn, err := ResolveProfileArn(account); err == nil {
			payload.ProfileArn = profileArn
		} else {
			logger.Debugf("[ResponsesAPI] profile ARN resolution skipped for %s: %v", accountEmailForLog(account), err)
		}
	}

	endpoint := responsesEndpointURL(account)

	body := buildResponsesRequest(payload)
	if body == nil {
		return fmt.Errorf("failed to build responses request")
	}
	reqBody, err := json.Marshal(body)
	if err != nil {
		return err
	}
	logger.Debugf("[ResponsesAPI] Request payload: %s", string(reqBody))

	host := ""
	if parsed, parseErr := url.Parse(endpoint); parseErr == nil {
		host = parsed.Host
	}
	headerValues := buildRuntimeHeaderValues(account, host)
	client := GetClientForProxy(ResolveAccountProxyURL(account))

	var lastErr error
	for attempt := 1; attempt <= maxStreamAttemptsPerEndpoint; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		req, buildErr := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(reqBody))
		if buildErr != nil {
			return buildErr
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "text/event-stream")
		applyKiroBaseHeaders(req, account, headerValues)
		req.Header.Set("x-amzn-kiro-origin", responsesOrigin(payload))
		req.Header.Set("x-amzn-kiro-agent-mode", "vibe")
		req.Header.Set("Amz-Sdk-Request", fmt.Sprintf("attempt=%d; max=%d", attempt, maxStreamAttemptsPerEndpoint))

		resp, doErr := client.Do(req)
		if doErr != nil {
			lastErr = doErr
			logger.Warnf("[ResponsesAPI] request failed (attempt %d/%d): %v", attempt, maxStreamAttemptsPerEndpoint, doErr)
			if !isRetryableStreamError(doErr) {
				return doErr
			}
			if err := streamRetryWait(ctx, streamRetryBackoff); err != nil {
				return err
			}
			continue
		}

		if resp.StatusCode != http.StatusOK {
			errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			lastErr = classifyResponsesHTTPError(resp.StatusCode, errBody)
			logger.Warnf("[ResponsesAPI] HTTP %d: %s", resp.StatusCode, lastErr)
			if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
				if attempt < maxStreamAttemptsPerEndpoint {
					if err := streamRetryWait(ctx, streamRetryBackoff); err != nil {
						return err
					}
					continue
				}
			}
			return lastErr
		}

		emitted, parseErr := parseResponsesSSE(resp.Body, payload, callback)
		resp.Body.Close()
		if parseErr == nil {
			return nil
		}
		lastErr = parseErr
		// Retrying after content reached the client would duplicate the answer,
		// so a mid-stream failure is final.
		if emitted || !isRetryableStreamError(parseErr) {
			return parseErr
		}
		logger.Warnf("[ResponsesAPI] stream failed (attempt %d/%d): %v", attempt, maxStreamAttemptsPerEndpoint, parseErr)
		if attempt < maxStreamAttemptsPerEndpoint {
			if err := streamRetryWait(ctx, streamRetryBackoff); err != nil {
				return err
			}
		}
	}
	if lastErr != nil {
		return lastErr
	}
	return fmt.Errorf("responses upstream failed")
}

// classifyResponsesHTTPError turns the upstream JSON error envelope into an
// error that account failover can classify.
func classifyResponsesHTTPError(status int, body []byte) error {
	var env struct {
		Error struct {
			Message string `json:"message"`
			Type    string `json:"type"`
			Code    string `json:"code"`
		} `json:"error"`
	}
	msg := strings.TrimSpace(string(body))
	if err := json.Unmarshal(body, &env); err == nil && env.Error.Message != "" {
		msg = env.Error.Message
		if env.Error.Code != "" {
			msg = env.Error.Code + ": " + msg
		}
	}
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		return fmt.Errorf("authentication failed: HTTP %d from Kiro responses: %s", status, msg)
	}
	return fmt.Errorf("HTTP %d from Kiro responses: %s", status, msg)
}

// parseResponsesSSE consumes the event stream and republishes it through the
// existing callback surface.
func parseResponsesSSE(body io.Reader, payload *KiroPayload, callback *KiroStreamCallback) (bool, error) {
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 64*1024), maxResponsesLineBytes)

	var (
		sawOutput   bool
		sawThinking bool
		completed   bool
		stopReason  = "END_TURN"
		credits     float64
		contextPct  float64
		outputRunes int
		errMsg      string
	)
	pending := map[string]*KiroToolUse{}
	argBuf := map[string]*strings.Builder{}

	flushTool := func(itemID string) {
		if callback == nil || callback.OnToolUse == nil {
			return
		}
		tu, ok := pending[itemID]
		if !ok {
			return
		}
		delete(pending, itemID)
		if b, ok := argBuf[itemID]; ok {
			delete(argBuf, itemID)
			if tu.Input == nil {
				parsed := map[string]interface{}{}
				if err := json.Unmarshal([]byte(b.String()), &parsed); err == nil {
					tu.Input = parsed
				}
			}
		}
		if tu.Input == nil {
			tu.Input = map[string]interface{}{}
		}
		callback.OnToolUse(*tu)
	}

	handle := func(ev *responsesEvent) error {
		switch ev.Type {
		case "response.output_text.delta":
			if ev.Delta != "" {
				sawOutput = true
				outputRunes += len([]rune(ev.Delta))
				if callback != nil && callback.OnText != nil {
					callback.OnText(ev.Delta, false)
				}
			}
		case "response.reasoning_text.delta", "response.reasoning.delta":
			if ev.Delta != "" {
				sawThinking = true
				outputRunes += len([]rune(ev.Delta))
				if callback != nil && callback.OnText != nil {
					callback.OnText(ev.Delta, true)
				}
			}
		case "response.output_item.added":
			if ev.Item != nil && ev.Item.Type == "function_call" {
				pending[ev.Item.ID] = &KiroToolUse{ToolUseID: ev.Item.CallID, Name: ev.Item.Name}
				argBuf[ev.Item.ID] = &strings.Builder{}
			}
		case "response.function_call_arguments.delta":
			if b, ok := argBuf[ev.ItemID]; ok {
				b.WriteString(ev.Delta)
			}
		case "response.function_call_arguments.done":
			if b, ok := argBuf[ev.ItemID]; ok && ev.Arguments != "" {
				b.Reset()
				b.WriteString(ev.Arguments)
			}
		case "response.output_item.done":
			if ev.Item != nil && ev.Item.Type == "function_call" {
				if b, ok := argBuf[ev.Item.ID]; ok && ev.Item.Arguments != "" && b.Len() == 0 {
					b.WriteString(ev.Item.Arguments)
				}
				flushTool(ev.Item.ID)
				sawOutput = true
			}
		case "response.completed":
			completed = true
			if ev.Response != nil {
				if ev.Response.Usage != nil {
					credits = ev.Response.Usage.Credits.Value
					contextPct = ev.Response.Usage.ContextUsagePercentage
				}
				stopReason = responsesStopReason(ev.Response)
			}
		case "response.failed":
			completed = true
			if ev.Response != nil {
				if d := ev.Response.IncompleteDetails; d != nil && d.Reason != "" {
					errMsg = d.Reason
				}
			}
			if errMsg == "" && ev.Error != nil {
				errMsg = ev.Error.Message
			}
			if errMsg == "" {
				errMsg = "upstream reported response.failed"
			}
		case "error":
			if ev.Error != nil && ev.Error.Message != "" {
				errMsg = ev.Error.Message
			} else {
				errMsg = "upstream stream error"
			}
		}
		return nil
	}

	// SSE frames may span several data: lines; join them until a blank line.
	var dataBuf strings.Builder
	dispatch := func() error {
		if dataBuf.Len() == 0 {
			return nil
		}
		raw := strings.TrimSpace(dataBuf.String())
		dataBuf.Reset()
		if raw == "" || raw == "[DONE]" {
			return nil
		}
		var ev responsesEvent
		if err := json.Unmarshal([]byte(raw), &ev); err != nil {
			logger.Debugf("[ResponsesAPI] skipping unparsable SSE frame: %v", err)
			return nil
		}
		return handle(&ev)
	}

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			if err := dispatch(); err != nil {
				return sawOutput || sawThinking, err
			}
			continue
		}
		if !strings.HasPrefix(line, "data:") {
			continue // event: / id: / comment lines carry nothing we need
		}
		if dataBuf.Len() > 0 {
			dataBuf.WriteString("\n")
		}
		dataBuf.WriteString(strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
	}
	if err := scanner.Err(); err != nil {
		return sawOutput || sawThinking, err
	}
	if err := dispatch(); err != nil {
		return sawOutput || sawThinking, err
	}

	if errMsg != "" {
		return sawOutput || sawThinking, fmt.Errorf("Kiro responses stream failed: %s", errMsg)
	}
	if !completed {
		return sawOutput || sawThinking, fmt.Errorf("upstream truncated response without stop reason")
	}
	if !sawOutput && !sawThinking {
		return false, errEmptyKiroStream
	}

	if callback != nil {
		if callback.OnCredits != nil && credits > 0 {
			callback.OnCredits(credits)
		}
		if callback.OnContextUsage != nil && contextPct > 0 {
			callback.OnContextUsage(contextPct)
		}
		if callback.OnStopReason != nil {
			callback.OnStopReason(stopReason)
		}
		if callback.OnComplete != nil {
			inputTokens := 0
			if contextPct > 0 {
				model := ""
				if payload != nil {
					model = payload.ConversationState.CurrentMessage.UserInputMessage.ModelID
				}
				inputTokens = int(contextPct * float64(getContextWindowSize(model)) / 100.0)
			}
			callback.OnComplete(inputTokens, estimateTokensFromRunes(outputRunes))
		}
	}
	return sawOutput || sawThinking, nil
}

// responsesStopReason normalizes the responses status into the legacy
// stop-reason vocabulary the translators already understand.
func responsesStopReason(resp *responsesPayload) string {
	if resp == nil {
		return "END_TURN"
	}
	if resp.IncompleteDetails != nil {
		switch strings.ToLower(strings.TrimSpace(resp.IncompleteDetails.Reason)) {
		case "max_output_tokens", "max_tokens", "length":
			return "MAX_TOKENS"
		case "content_filter", "refusal":
			return "REFUSAL"
		}
	}
	switch strings.ToLower(strings.TrimSpace(resp.Status)) {
	case "incomplete":
		return "MAX_TOKENS"
	case "failed", "cancelled":
		return "REFUSAL"
	}
	return "END_TURN"
}

// estimateTokensFromRunes approximates token usage when the upstream reports
// credits only. CJK characters run ~1 token each, ASCII ~4 chars per token; the
// ratio below is a middle ground that matches Kiro's observed billing on mixed
// Chinese/English answers.
func estimateTokensFromRunes(runes int) int {
	if runes <= 0 {
		return 0
	}
	tokens := runes*2/5 + 1
	if tokens < 1 {
		return 1
	}
	return tokens
}
