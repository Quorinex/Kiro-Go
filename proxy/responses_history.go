package proxy

import "strings"

// maxResponsesHistoryDepth caps how far back we walk the previous_response_id
// chain when expanding history. The cap prevents pathological loops in
// corrupted/cyclic stores from running forever; legitimate chains rarely go
// this deep within the 30-day TTL.
const maxResponsesHistoryDepth = 64

// replayHistoryWindowShare bounds replayed ancestor history as a fraction of the
// model's context window, reserving the remainder for the client's current input
// and its tool schemas.
//
// A depth cap alone is not a size cap: 64 ancestors of full input and output can
// exceed any window on their own. That matters most when a client compacts. A
// compacting client sends a short summary as its new input, but if it keeps
// pointing previous_response_id at the pre-compaction response, every turn it
// just discarded is read back off disk and prepended — so the request after
// compaction is larger than the one before it, and the client sees a context
// that is still full, compacts again, and repeats.
//
// Bounding the replay is what gives compaction somewhere to land: the client's
// own input is authoritative and always kept in full, while replayed history is
// held to this share, so discarding history actually shrinks the request.
const replayHistoryWindowShare = 0.5

// replayTruncationNote marks where replayed ancestor turns were elided. Silently
// dropping them would leave the model reading a conversation that begins
// mid-thought with no indication anything came before.
const replayTruncationNote = "[Earlier turns of this conversation were omitted to fit the model's input limit.]"

// maxReplayHistoryTokens is the token budget for replayed ancestor history on a
// given model.
func maxReplayHistoryTokens(model string) int {
	return int(float64(getContextWindowSize(model)) * replayHistoryWindowShare)
}

// expandPreviousResponseHistory rebuilds the conversation history that led up
// to prev. It walks the previous_response_id chain backwards (oldest → newest)
// and emits OpenAI messages for both stored inputs and stored outputs of every
// ancestor, so a multi-turn /v1/responses session preserves full context.
//
// The result is bounded by replayHistoryWindowShare of the model's window,
// keeping the newest ancestors and dropping the oldest. See that constant for
// why an unbounded replay defeats client-side compaction.
//
// If a link in the chain is missing on disk (e.g. expired past TTL or the
// referenced ID was deleted), expansion stops at the deepest reachable
// ancestor instead of failing — the most recent context is still useful.
func expandPreviousResponseHistory(prev *ResponsesObject, model string) []OpenAIMessage {
	if prev == nil {
		return nil
	}

	chain := collectAncestorChain(prev)

	// Group by ancestor so trimming drops whole turns rather than cutting one in
	// half, which would strand a tool result from its call.
	groups := make([][]OpenAIMessage, 0, len(chain))
	for _, node := range chain {
		group := make([]OpenAIMessage, 0, 4)
		// Inject the instructions stored on the ancestor as a system message
		// so it remains in scope for downstream turns. Without this, an early
		// system prompt set on response A would be lost the moment a new
		// turn omits it.
		if node.Instructions != "" {
			group = append(group, OpenAIMessage{
				Role:    "system",
				Content: node.Instructions,
			})
		}
		if prior, err := parseResponsesInput(node.StoredInput); err == nil {
			group = append(group, prior...)
		}
		group = append(group, outputToMessages(node.Output)...)
		groups = append(groups, group)
	}

	return flattenReplayGroups(groups, maxReplayHistoryTokens(model))
}

// flattenReplayGroups concatenates per-ancestor message groups oldest-first,
// dropping the oldest whole groups until the total fits budget. The newest turns
// are the ones worth keeping: they are what the current turn actually responds
// to. A budget of zero or less disables trimming.
func flattenReplayGroups(groups [][]OpenAIMessage, budget int) []OpenAIMessage {
	keepFrom := 0
	if budget > 0 {
		// Walk newest → oldest and keep the largest suffix that fits. The newest
		// group is kept unconditionally even if it alone exceeds the budget:
		// returning nothing here would silently drop the turn the current
		// message is answering, and truncatePayloadToLimit still enforces the
		// real byte limit downstream.
		total := 0
		keepFrom = len(groups)
		for i := len(groups) - 1; i >= 0; i-- {
			total += estimateReplayGroupTokens(groups[i])
			if total > budget && i < len(groups)-1 {
				break
			}
			keepFrom = i
		}
	}

	messages := make([]OpenAIMessage, 0)
	if keepFrom > 0 {
		messages = append(messages, OpenAIMessage{
			Role:    "user",
			Content: replayTruncationNote,
		})
	}
	for _, group := range groups[keepFrom:] {
		messages = append(messages, group...)
	}

	if keepFrom > 0 {
		messages = dropOrphanedLeadingToolMessages(messages)
	}
	return messages
}

// dropOrphanedLeadingToolMessages removes tool-result messages that lead the
// replay without the assistant tool call they answer. Cutting the chain can
// separate the two: an ancestor's assistant tool_calls live in its output while
// the matching results arrive in the next ancestor's stored input. Kiro rejects
// an unpaired tool result outright, so the orphan has to go.
//
// The leading truncation note is skipped over, not consumed.
func dropOrphanedLeadingToolMessages(messages []OpenAIMessage) []OpenAIMessage {
	seen := make(map[string]bool)
	out := make([]OpenAIMessage, 0, len(messages))
	sawAssistantCall := false

	for _, msg := range messages {
		if msg.Role == "assistant" && len(msg.ToolCalls) > 0 {
			sawAssistantCall = true
			for _, tc := range msg.ToolCalls {
				if tc.ID != "" {
					seen[tc.ID] = true
				}
			}
		}
		if msg.Role == "tool" && !sawAssistantCall && !seen[msg.ToolCallID] {
			continue
		}
		out = append(out, msg)
	}
	return out
}

// estimateReplayGroupTokens approximates the token cost of one ancestor's
// replayed messages, using the same estimator the request-level accounting uses
// so the two cannot disagree about what a turn costs.
func estimateReplayGroupTokens(group []OpenAIMessage) int {
	total := 0
	for _, msg := range group {
		total += estimateOpenAIContentTokens(msg.Content)
		total += estimateApproxTokens(msg.ToolCallID)
		for _, tc := range msg.ToolCalls {
			total += estimateApproxTokens(tc.Function.Name)
			total += estimateApproxTokens(tc.Function.Arguments)
		}
	}
	return total
}

// collectAncestorChain walks previous_response_id backwards, returning the
// chain in oldest-first order: [root, ..., parent, prev]. The walker is
// bounded by maxResponsesHistoryDepth and a visited-set to short-circuit
// any cycle in the stored data.
func collectAncestorChain(prev *ResponsesObject) []*ResponsesObject {
	stack := []*ResponsesObject{prev}
	visited := map[string]bool{prev.ID: true}

	cursor := prev
	for depth := 0; depth < maxResponsesHistoryDepth; depth++ {
		if cursor.PreviousResponseID == "" {
			break
		}
		if visited[cursor.PreviousResponseID] {
			break
		}
		ancestor, err := loadResponse(cursor.PreviousResponseID)
		if err != nil || ancestor == nil {
			break
		}
		visited[ancestor.ID] = true
		stack = append(stack, ancestor)
		cursor = ancestor
	}

	// Reverse to oldest-first.
	for i, j := 0, len(stack)-1; i < j; i, j = i+1, j-1 {
		stack[i], stack[j] = stack[j], stack[i]
	}
	return stack
}

func outputToMessages(items []ResponseOutputItem) []OpenAIMessage {
	if len(items) == 0 {
		return nil
	}
	out := make([]OpenAIMessage, 0, len(items))
	for _, item := range items {
		switch item.Type {
		case "message":
			text := joinTextParts(item.Content)
			role := item.Role
			if role == "" {
				role = "assistant"
			}
			if text == "" && role == "assistant" {
				continue
			}
			out = append(out, OpenAIMessage{Role: role, Content: text})
		case "function_call":
			tc := ToolCall{ID: item.CallID, Type: "function"}
			if tc.ID == "" {
				tc.ID = item.ID
			}
			tc.Function.Name = item.Name
			tc.Function.Arguments = item.Arguments
			out = append(out, OpenAIMessage{
				Role:      "assistant",
				Content:   "",
				ToolCalls: []ToolCall{tc},
			})
		}
	}
	return out
}

func joinTextParts(parts []ResponseContentPart) string {
	if len(parts) == 0 {
		return ""
	}
	out := strings.Builder{}
	for _, p := range parts {
		if p.Type == "output_text" || p.Type == "text" || p.Type == "input_text" {
			out.WriteString(p.Text)
		}
	}
	return out.String()
}
