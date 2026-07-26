package proxy

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// sessionIDs are the two upstream continuity handles for one agent run.
type sessionIDs struct {
	ConversationID string
	ContinuationID string
	Ambiguous      bool
	StoredAt       time.Time
}

const sessionStoreTTL = 2 * time.Hour
const sessionStoreMax = 4096

type sessionStore struct {
	mu    sync.Mutex
	byKey map[string]sessionIDs
}

func newSessionStore() *sessionStore {
	return &sessionStore{byKey: make(map[string]sessionIDs)}
}

var globalSessionStore = newSessionStore()

// chainFingerprint hashes a normalized Claude message prefix.
// Used as the exact-match address for "this transcript ends here".
func chainFingerprintClaude(messages []ClaudeMessage) string {
	h := sha1.New()
	for _, msg := range messages {
		h.Write([]byte(strings.ToLower(strings.TrimSpace(msg.Role))))
		h.Write([]byte{0})
		h.Write([]byte(normalizeClaudeMessageContent(msg.Content)))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func normalizeClaudeMessageContent(content interface{}) string {
	if content == nil {
		return ""
	}
	if text, ok := content.(string); ok {
		return stringifyLoose([]map[string]interface{}{{
			"type": "text",
			"text": text,
		}})
	}

	blocks := contentBlocksAsMaps(content)
	if blocks == nil {
		return stringifyLoose(content)
	}
	normalized := make([]map[string]interface{}, 0, len(blocks))
	for _, block := range blocks {
		typ, _ := block["type"].(string)
		switch typ {
		case "text", "input_text":
			text, _ := block["text"].(string)
			normalized = append(normalized, map[string]interface{}{
				"type": "text",
				"text": text,
			})
		case "thinking":
			thinking, _ := block["thinking"].(string)
			normalized = append(normalized, map[string]interface{}{
				"type":     "thinking",
				"thinking": thinking,
			})
		case "tool_use":
			input := block["input"]
			if input == nil {
				input = map[string]interface{}{}
			}
			normalized = append(normalized, map[string]interface{}{
				"type":  "tool_use",
				"id":    block["id"],
				"name":  block["name"],
				"input": input,
			})
		case "tool_result":
			result := map[string]interface{}{
				"type":        "tool_result",
				"tool_use_id": block["tool_use_id"],
				"content":     block["content"],
			}
			if isError, ok := block["is_error"]; ok {
				result["is_error"] = isError
			}
			normalized = append(normalized, result)
		default:
			normalized = append(normalized, block)
		}
	}
	return stringifyLoose(normalized)
}

// stringifyLoose renders a structured value deterministically for
// fingerprinting. encoding/json sorts map keys, so equivalent in-memory map
// order does not change the chain address. Marshal failures fail closed.
func stringifyLoose(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

func sessionKey(apiKeyID, modelID, chainFP string) string {
	return strings.Join([]string{
		strings.TrimSpace(apiKeyID),
		strings.TrimSpace(modelID),
		strings.TrimSpace(chainFP),
	}, "|")
}

// resolveSessionIDs returns reused IDs when the inbound transcript prefix exactly
// matches a previously successful seal; otherwise mints fresh UUIDs.
//
// prefix = messages without the trailing user turn being answered now.
// Only reuses when prefix is non-empty and ends with an assistant message
// (i.e. this is a true continuation, not a brand-new chat).
func resolveSessionIDs(apiKeyID, modelID string, messages []ClaudeMessage) (convID, contID string, reused bool) {
	prefix := claudePrefixBeforeCurrentUser(messages)
	if len(prefix) == 0 || !claudeEndsWithAssistant(prefix) {
		return uuid.New().String(), uuid.New().String(), false
	}
	fp := chainFingerprintClaude(prefix)
	if ids := globalSessionStore.lookup(apiKeyID, modelID, fp); ids != nil {
		return ids.ConversationID, ids.ContinuationID, true
	}
	return uuid.New().String(), uuid.New().String(), false
}

func claudePrefixBeforeCurrentUser(messages []ClaudeMessage) []ClaudeMessage {
	if len(messages) == 0 {
		return nil
	}
	last := messages[len(messages)-1]
	if strings.EqualFold(last.Role, "user") {
		return messages[:len(messages)-1]
	}
	// Already ends mid-assistant (unusual); treat full list as prefix.
	return messages
}

func claudeEndsWithAssistant(messages []ClaudeMessage) bool {
	if len(messages) == 0 {
		return false
	}
	return strings.EqualFold(messages[len(messages)-1].Role, "assistant")
}

// sealSessionAfterSuccess records continuity for the transcript the client will
// hold after this successful assistant turn: inbound messages with the final
// user turn answered, i.e. prefix+assistant — callers pass the full chain that
// ends with the assistant content just produced.
func sealSessionAfterSuccess(apiKeyID, modelID, convID, contID string, chainEndingWithAssistant []ClaudeMessage) {
	if convID == "" || contID == "" || len(chainEndingWithAssistant) == 0 {
		return
	}
	if !claudeEndsWithAssistant(chainEndingWithAssistant) {
		return
	}
	fp := chainFingerprintClaude(chainEndingWithAssistant)
	globalSessionStore.put(apiKeyID, modelID, fp, convID, contID)
}

func (s *sessionStore) put(apiKeyID, modelID, chainFP, convID, contID string) {
	key := sessionKey(apiKeyID, modelID, chainFP)
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeLocked(now)

	if existing, ok := s.byKey[key]; ok {
		if existing.Ambiguous || existing.ConversationID != convID || existing.ContinuationID != contID {
			s.byKey[key] = sessionIDs{Ambiguous: true, StoredAt: now}
			return
		}
		existing.StoredAt = now
		s.byKey[key] = existing
		return
	}

	if len(s.byKey) >= sessionStoreMax {
		s.dropOldestLocked(sessionStoreMax / 4)
	}
	s.byKey[key] = sessionIDs{
		ConversationID: convID,
		ContinuationID: contID,
		StoredAt:       now,
	}
}

func (s *sessionStore) lookup(apiKeyID, modelID, chainFP string) *sessionIDs {
	key := sessionKey(apiKeyID, modelID, chainFP)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeLocked(time.Now())
	e, ok := s.byKey[key]
	if !ok || e.Ambiguous || e.ConversationID == "" || e.ContinuationID == "" {
		return nil
	}
	cp := e
	return &cp
}

func (s *sessionStore) purgeLocked(now time.Time) {
	for k, e := range s.byKey {
		if now.Sub(e.StoredAt) > sessionStoreTTL {
			delete(s.byKey, k)
		}
	}
}

func (s *sessionStore) dropOldestLocked(n int) {
	type pair struct {
		key      string
		storedAt time.Time
	}
	all := make([]pair, 0, len(s.byKey))
	for k, e := range s.byKey {
		all = append(all, pair{k, e.StoredAt})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].storedAt.Before(all[j].storedAt) })
	if n > len(all) {
		n = len(all)
	}
	for _, p := range all[:n] {
		delete(s.byKey, p.key)
	}
}

// sealClaudeSession records continuity after a successful Claude turn.
//
// The chain MUST be fingerprinted from the client transcript, never from the
// wire payload: ClaudeToKiro rewrites history (system priming pair, flattened
// tool turns, truncation), so a payload-derived chain can never match the
// lookup key that resolveSessionIDs computes from the next inbound request.
//
// assistantText must be the VISIBLE assistant text the client stores — not the
// integrity-check builder that may have tool name/input padding glued on.
// thinkingText + format must mirror how the handler exposed reasoning to the
// client, otherwise the next-turn lookup (which fingerprints thinking blocks
// and folded <think> text the same way the client replays them) will miss.
func sealClaudeSession(apiKeyID, model, convID, contID string, inbound []ClaudeMessage, assistantText, thinkingText string, toolUses []KiroToolUse, format string, omitDisplay bool) {
	if convID == "" || contID == "" || len(inbound) == 0 {
		return
	}
	chain := make([]ClaudeMessage, 0, len(inbound)+1)
	chain = append(chain, inbound...)
	chain = append(chain, claudeAssistantTurn(assistantText, thinkingText, toolUses, format, omitDisplay))
	sealSessionAfterSuccess(apiKeyID, MapModel(model), convID, contID, chain)
}

// sealClaudeSessionFromContent records continuity from the exact assistant
// content the client will store and replay. Mixed web_search responses include
// server_tool_use / web_search_tool_result blocks that are not raw Kiro tool
// uses, so fingerprinting must use that client-visible shape.
func sealClaudeSessionFromContent(apiKeyID, model, convID, contID string, inbound []ClaudeMessage, content []map[string]interface{}) {
	if convID == "" || contID == "" || len(inbound) == 0 || len(content) == 0 {
		return
	}
	blocks := make([]interface{}, 0, len(content))
	for _, block := range content {
		blocks = append(blocks, block)
	}
	chain := make([]ClaudeMessage, 0, len(inbound)+1)
	chain = append(chain, inbound...)
	chain = append(chain, ClaudeMessage{Role: "assistant", Content: blocks})
	sealSessionAfterSuccess(apiKeyID, MapModel(model), convID, contID, chain)
}

// claudeAssistantTurn renders this turn's answer in the same block shape the
// client will replay it as, so seal and lookup fingerprints agree.
func claudeAssistantTurn(text, thinkingText string, toolUses []KiroToolUse, format string, omitDisplay bool) ClaudeMessage {
	includeThinkingBlock := thinkingText != ""
	// Formats that fold reasoning into the text stream: seal the folded text the
	// client actually saw, with no separate thinking block.
	switch format {
	case "think":
		if thinkingText != "" {
			text = "<think>" + thinkingText + "</think>" + text
			thinkingText = ""
			includeThinkingBlock = false
		}
	case "reasoning_content":
		if thinkingText != "" {
			text = thinkingText + text
			thinkingText = ""
			includeThinkingBlock = false
		}
	default:
		// Native thinking with omitted display emits an explicit empty shell.
		if omitDisplay && includeThinkingBlock {
			thinkingText = ""
		}
	}

	needBlocks := includeThinkingBlock || len(toolUses) > 0
	if !needBlocks {
		return ClaudeMessage{Role: "assistant", Content: text}
	}
	blocks := make([]interface{}, 0, len(toolUses)+2)
	if includeThinkingBlock {
		blocks = append(blocks, map[string]interface{}{"type": "thinking", "thinking": thinkingText})
	}
	if text != "" {
		blocks = append(blocks, map[string]interface{}{"type": "text", "text": text})
	}
	for _, tu := range toolUses {
		input := tu.Input
		if input == nil {
			input = map[string]interface{}{}
		}
		blocks = append(blocks, map[string]interface{}{
			"type":  "tool_use",
			"id":    tu.ToolUseID,
			"name":  tu.Name,
			"input": input,
		})
	}
	return ClaudeMessage{Role: "assistant", Content: blocks}
}
