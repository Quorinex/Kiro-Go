// Package proxy Kiro API 代理核心
// 负责调用 Kiro API 并解析 AWS Event Stream 响应
package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"kiro-api-proxy/config"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

const KiroVersion = "0.6.18"

// 双端点配置（429 时自动 fallback）
type kiroEndpoint struct {
	URL       string
	Origin    string
	AmzTarget string
	Name      string
}

var kiroEndpoints = []kiroEndpoint{
	{
		URL:       "https://codewhisperer.us-east-1.amazonaws.com/generateAssistantResponse",
		Origin:    "AI_EDITOR",
		AmzTarget: "AmazonCodeWhispererStreamingService.GenerateAssistantResponse",
		Name:      "CodeWhisperer",
	},
	{
		URL:       "https://q.us-east-1.amazonaws.com/generateAssistantResponse",
		Origin:    "CLI",
		AmzTarget: "AmazonQDeveloperStreamingService.SendMessage",
		Name:      "AmazonQ",
	},
}

// 全局 HTTP 客户端，复用连接池
var kiroHttpClient = &http.Client{
	Timeout: 5 * time.Minute,
	Transport: &http.Transport{
		MaxIdleConns:        100,              // 最大空闲连接数
		MaxIdleConnsPerHost: 20,               // 每个 Host 最大空闲连接数
		IdleConnTimeout:     90 * time.Second, // 空闲连接超时
		DisableCompression:  false,            // 启用压缩
		ForceAttemptHTTP2:   true,             // 尝试使用 HTTP/2
	},
}

// ==================== 请求结构 ====================

// KiroPayload Kiro API 请求体
type KiroPayload struct {
	ConversationState struct {
		ChatTriggerType string `json:"chatTriggerType"`
		ConversationID  string `json:"conversationId"`
		CurrentMessage  struct {
			UserInputMessage KiroUserInputMessage `json:"userInputMessage"`
		} `json:"currentMessage"`
		History []KiroHistoryMessage `json:"history,omitempty"`
	} `json:"conversationState"`
	ProfileArn      string           `json:"profileArn,omitempty"`
	InferenceConfig *InferenceConfig `json:"inferenceConfig,omitempty"`
}

type KiroUserInputMessage struct {
	Content                 string                   `json:"content"`
	ModelID                 string                   `json:"modelId,omitempty"`
	Origin                  string                   `json:"origin"`
	Images                  []KiroImage              `json:"images,omitempty"`
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

type KiroHistoryMessage struct {
	UserInputMessage         *KiroUserInputMessage         `json:"userInputMessage,omitempty"`
	AssistantResponseMessage *KiroAssistantResponseMessage `json:"assistantResponseMessage,omitempty"`
}

type KiroAssistantResponseMessage struct {
	Content  string        `json:"content"`
	ToolUses []KiroToolUse `json:"toolUses,omitempty"`
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

// ==================== 流式回调 ====================

// KiroStreamCallback 流式响应回调
type KiroStreamCallback struct {
	OnText     func(text string, isThinking bool)
	OnToolUse  func(toolUse KiroToolUse)
	OnComplete func(inputTokens, outputTokens int)
	OnError    func(err error)
	OnCredits  func(credits float64)
}

// ==================== API 调用 ====================

// getSortedEndpoints 根据首选端点配置排序端点列表
func getSortedEndpoints(preferred string) []kiroEndpoint {
	if preferred == "amazonq" {
		return []kiroEndpoint{kiroEndpoints[1], kiroEndpoints[0]}
	}
	if preferred == "codewhisperer" {
		return []kiroEndpoint{kiroEndpoints[0], kiroEndpoints[1]}
	}
	// "auto" 或空值：默认顺序
	return []kiroEndpoint{kiroEndpoints[0], kiroEndpoints[1]}
}

// CallKiroAPI 调用 Kiro API（流式），双端点自动 fallback
func CallKiroAPI(account *config.Account, payload *KiroPayload, callback *KiroStreamCallback) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	// 预估输入 token（约 3 字符 = 1 token）
	estimatedInputTokens := max(1, len(body)/3)

	// User-Agent
	machineId := account.MachineId
	var userAgent, amzUserAgent string
	if machineId != "" {
		userAgent = fmt.Sprintf("aws-sdk-js/1.0.18 ua/2.1 os/linux lang/js md/nodejs#20.16.0 api/codewhispererstreaming#1.0.18 m/E KiroIDE-%s-%s", KiroVersion, machineId)
		amzUserAgent = fmt.Sprintf("aws-sdk-js/1.0.18 KiroIDE %s %s", KiroVersion, machineId)
	} else {
		userAgent = fmt.Sprintf("aws-sdk-js/1.0.18 ua/2.1 os/linux lang/js md/nodejs#20.16.0 api/codewhispererstreaming#1.0.18 m/E KiroIDE-%s", KiroVersion)
		amzUserAgent = fmt.Sprintf("aws-sdk-js/1.0.18 KiroIDE %s", KiroVersion)
	}

	// 根据配置排序端点
	endpoints := getSortedEndpoints(config.GetPreferredEndpoint())

	var lastErr error
	for _, ep := range endpoints {
		// 更新 payload 中的 origin
		payload.ConversationState.CurrentMessage.UserInputMessage.Origin = ep.Origin

		reqBody, _ := json.Marshal(payload)
		req, err := http.NewRequest("POST", ep.URL, bytes.NewReader(reqBody))
		if err != nil {
			lastErr = err
			continue
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "*/*")
		req.Header.Set("X-Amz-Target", ep.AmzTarget)
		req.Header.Set("User-Agent", userAgent)
		req.Header.Set("X-Amz-User-Agent", amzUserAgent)
		req.Header.Set("x-amzn-kiro-agent-mode", "spec")
		req.Header.Set("x-amzn-codewhisperer-optout", "true")
		req.Header.Set("Amz-Sdk-Request", "attempt=1; max=3")
		req.Header.Set("Amz-Sdk-Invocation-Id", uuid.New().String())
		req.Header.Set("Authorization", "Bearer "+account.AccessToken)

		resp, err := kiroHttpClient.Do(req)
		if err != nil {
			lastErr = err
			fmt.Printf("[KiroAPI] Endpoint %s failed: %v\n", ep.Name, err)
			continue
		}

		if resp.StatusCode == 429 {
			resp.Body.Close()
			fmt.Printf("[KiroAPI] Endpoint %s quota exhausted (429), trying next...\n", ep.Name)
			lastErr = fmt.Errorf("quota exhausted on %s", ep.Name)
			continue
		}

		if resp.StatusCode != 200 {
			errBody, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			lastErr = fmt.Errorf("HTTP %d from %s: %s", resp.StatusCode, ep.Name, string(errBody))
			// 认证错误不继续尝试
			if resp.StatusCode == 401 || resp.StatusCode == 403 {
				return lastErr
			}
			fmt.Printf("[KiroAPI] Endpoint %s error: %v\n", ep.Name, lastErr)
			continue
		}

		err = parseEventStream(resp.Body, callback, estimatedInputTokens)
		resp.Body.Close()
		return err
	}

	if lastErr != nil {
		return lastErr
	}
	return fmt.Errorf("all endpoints failed")
}

// ==================== Event Stream 解析 ====================

// parseEventStream 解析 AWS Event Stream 二进制格式
func parseEventStream(body io.Reader, callback *KiroStreamCallback, estimatedInputTokens int) error {
	// 不使用 bufio，直接读取避免缓冲延迟
	var inputTokens, outputTokens int
	var totalOutputChars int
	var totalCredits float64
	var currentToolUse *toolUseState

	for {
		// Prelude: 12 bytes (total_len + headers_len + crc)
		prelude := make([]byte, 12)
		_, err := io.ReadFull(body, prelude)
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		totalLength := int(prelude[0])<<24 | int(prelude[1])<<16 | int(prelude[2])<<8 | int(prelude[3])
		headersLength := int(prelude[4])<<24 | int(prelude[5])<<16 | int(prelude[6])<<8 | int(prelude[7])

		if totalLength < 16 {
			continue
		}

		// 读取剩余部分
		remaining := totalLength - 12
		msgBuf := make([]byte, remaining)
		_, err = io.ReadFull(body, msgBuf)
		if err != nil {
			return err
		}

		if headersLength > len(msgBuf)-4 {
			continue
		}

		eventType := extractEventType(msgBuf[0:headersLength])
		payloadBytes := msgBuf[headersLength : len(msgBuf)-4]
		if len(payloadBytes) == 0 {
			continue
		}

		var event map[string]interface{}
		if err := json.Unmarshal(payloadBytes, &event); err != nil {
			continue
		}

		// 处理事件
		switch eventType {
		case "assistantResponseEvent":
			if content, ok := event["content"].(string); ok && content != "" {
				callback.OnText(content, false)
				totalOutputChars += len(content)
			}
		case "reasoningContentEvent":
			if text, ok := event["text"].(string); ok && text != "" {
				callback.OnText(text, true)
				totalOutputChars += len(text)
			}
		case "toolUseEvent":
			currentToolUse = handleToolUseEvent(event, currentToolUse, callback)
		case "messageMetadataEvent", "metadataEvent":
			if tokenUsage, ok := event["tokenUsage"].(map[string]interface{}); ok {
				if v, ok := tokenUsage["outputTokens"].(float64); ok {
					outputTokens = int(v)
				}
				uncached, _ := tokenUsage["uncachedInputTokens"].(float64)
				cacheRead, _ := tokenUsage["cacheReadInputTokens"].(float64)
				cacheWrite, _ := tokenUsage["cacheWriteInputTokens"].(float64)
				inputTokens = int(uncached + cacheRead + cacheWrite)
			}
		case "meteringEvent":
			if usage, ok := event["usage"].(float64); ok {
				totalCredits += usage
			}
		}
	}

	// 估算 token（约 3 字符 = 1 token）
	if outputTokens == 0 && totalOutputChars > 0 {
		outputTokens = max(1, totalOutputChars/3)
	}
	// 如果 Kiro 没返回 inputTokens，使用预估值
	if inputTokens == 0 {
		inputTokens = estimatedInputTokens
	}

	if callback.OnCredits != nil && totalCredits > 0 {
		callback.OnCredits(totalCredits)
	}

	callback.OnComplete(inputTokens, outputTokens)
	return nil
}

// ==================== Tool Use 处理 ====================

type toolUseState struct {
	ToolUseID   string
	Name        string
	InputBuffer strings.Builder
}

func handleToolUseEvent(event map[string]interface{}, current *toolUseState, callback *KiroStreamCallback) *toolUseState {
	toolUseID, _ := event["toolUseId"].(string)
	name, _ := event["name"].(string)
	isStop, _ := event["stop"].(bool)

	if toolUseID != "" && name != "" {
		if current == nil {
			current = &toolUseState{ToolUseID: toolUseID, Name: name}
		} else if current.ToolUseID != toolUseID {
			finishToolUse(current, callback)
			current = &toolUseState{ToolUseID: toolUseID, Name: name}
		}
	}

	if current != nil {
		if input, ok := event["input"].(string); ok {
			current.InputBuffer.WriteString(input)
		} else if inputObj, ok := event["input"].(map[string]interface{}); ok {
			data, _ := json.Marshal(inputObj)
			current.InputBuffer.Reset()
			current.InputBuffer.Write(data)
		}
	}

	if isStop && current != nil {
		finishToolUse(current, callback)
		return nil
	}

	return current
}

func finishToolUse(state *toolUseState, callback *KiroStreamCallback) {
	var input map[string]interface{}
	if state.InputBuffer.Len() > 0 {
		json.Unmarshal([]byte(state.InputBuffer.String()), &input)
	}
	if input == nil {
		input = make(map[string]interface{})
	}
	callback.OnToolUse(KiroToolUse{
		ToolUseID: state.ToolUseID,
		Name:      state.Name,
		Input:     input,
	})
}

// extractEventType 从 headers 中提取事件类型
func extractEventType(headers []byte) string {
	offset := 0
	for offset < len(headers) {
		if offset >= len(headers) {
			break
		}
		nameLen := int(headers[offset])
		offset++
		if offset+nameLen > len(headers) {
			break
		}
		name := string(headers[offset : offset+nameLen])
		offset += nameLen
		if offset >= len(headers) {
			break
		}
		valueType := headers[offset]
		offset++

		if valueType == 7 { // String
			if offset+2 > len(headers) {
				break
			}
			valueLen := int(headers[offset])<<8 | int(headers[offset+1])
			offset += 2
			if offset+valueLen > len(headers) {
				break
			}
			value := string(headers[offset : offset+valueLen])
			offset += valueLen
			if name == ":event-type" {
				return value
			}
			continue
		}

		// 跳过其他类型
		skipSizes := map[byte]int{0: 0, 1: 0, 2: 1, 3: 2, 4: 4, 5: 8, 8: 8, 9: 16}
		if valueType == 6 {
			if offset+2 > len(headers) {
				break
			}
			l := int(headers[offset])<<8 | int(headers[offset+1])
			offset += 2 + l
		} else if skip, ok := skipSizes[valueType]; ok {
			offset += skip
		} else {
			break
		}
	}
	return ""
}
