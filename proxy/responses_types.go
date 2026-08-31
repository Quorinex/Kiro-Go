package proxy

import "encoding/json"

type ResponsesRequest struct {
	Model              string            `json:"model"`
	Input              json.RawMessage   `json:"input"`
	Instructions       string            `json:"instructions,omitempty"`
	Stream             bool              `json:"stream,omitempty"`
	Tools              []OpenAITool      `json:"tools,omitempty"`
	ToolChoice         json.RawMessage   `json:"tool_choice,omitempty"`
	PreviousResponseID string            `json:"previous_response_id,omitempty"`
	Store              *bool             `json:"store,omitempty"`
	Temperature        *float64          `json:"temperature,omitempty"`
	MaxOutputTokens    *int              `json:"max_output_tokens,omitempty"`
	Metadata           map[string]string `json:"metadata,omitempty"`
}

type ResponsesObject struct {
	ID                 string                      `json:"id"`
	Object             string                      `json:"object"`
	CreatedAt          int64                       `json:"created_at"`
	Status             string                      `json:"status"`
	Model              string                      `json:"model"`
	Output             []ResponseOutputItem        `json:"output"`
	Usage              ResponsesUsage              `json:"usage"`
	PreviousResponseID string                      `json:"previous_response_id,omitempty"`
	Metadata           map[string]string           `json:"metadata,omitempty"`
	Error              *ResponsesError             `json:"error,omitempty"`
	IncompleteDetails  *ResponsesIncompleteDetails `json:"incomplete_details,omitempty"`
	Instructions       string                      `json:"instructions,omitempty"`
	StoredInput        json.RawMessage             `json:"-"`
	StoredInstr        string                      `json:"-"`
	StoredAt           int64                       `json:"stored_at,omitempty"`
}

// responsesCustomToolCallType is the output item Codex expects back for a
// freeform (grammar) tool. A freeform call returned as a plain function_call is
// abandoned by Codex instead of being executed.
const responsesCustomToolCallType = "custom_tool_call"

type ResponseOutputItem struct {
	ID        string                `json:"id"`
	Type      string                `json:"type"`
	Role      string                `json:"role,omitempty"`
	Status    string                `json:"status,omitempty"`
	Content   []ResponseContentPart `json:"content,omitempty"`
	CallID    string                `json:"call_id,omitempty"`
	Name      string                `json:"name,omitempty"`
	Arguments string                `json:"arguments,omitempty"`
	// Input carries the raw payload of a custom_tool_call output item, which
	// Codex reads instead of arguments for freeform tools.
	Input string `json:"input,omitempty"`
}

type ResponseContentPart struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

type ResponsesUsage struct {
	InputTokens        int                          `json:"input_tokens"`
	InputTokensDetails *ResponsesInputTokensDetails `json:"input_tokens_details,omitempty"`
	OutputTokens       int                          `json:"output_tokens"`
	TotalTokens        int                          `json:"total_tokens"`
}

type ResponsesInputTokensDetails struct {
	CachedTokens int `json:"cached_tokens"`
}

type ResponsesError struct {
	Type    string `json:"type"`
	Code    string `json:"code,omitempty"`
	Message string `json:"message"`
}

type ResponsesIncompleteDetails struct {
	Reason string `json:"reason"`
}
