package proxy

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"sort"
	"strings"
	"sync"
	"time"
)

// sealedReasoning is one successful assistant turn's upstream thinking stamp.
// Official client keeps this in process memory (lastSealedReasoning) and pastes
// it onto that assistant message on the next request. As a stateless proxy we
// re-derive the same binding with a turn fingerprint so we never attach a stamp
// to the wrong conversation.
type sealedReasoning struct {
	Text            string
	Signature       string
	RedactedContent string
	ModelID         string
	StoredAt        time.Time
}

const (
	reasoningStoreTTL        = 2 * time.Hour
	reasoningStoreMaxEntries = 4096
)

type reasoningStore struct {
	mu sync.Mutex
	// key -> stamp. key = turnKey(...)
	byKey map[string]sealedReasoning
}

func newReasoningStore() *reasoningStore {
	return &reasoningStore{byKey: make(map[string]sealedReasoning)}
}

var globalReasoningStore = newReasoningStore()

// turnKey builds the exact-match address for one assistant turn.
//
//	apiKey | model | conversationBucket | hash(parentUser, assistantText, ordered tool uses)
//
// No fuzzy matching. Same account + same model alone is never enough.
func turnKey(apiKeyID, modelID, conversationID, parentUser, assistantText string, toolUses []KiroToolUse) string {
	h := sha1.New()
	h.Write([]byte(parentUser))
	h.Write([]byte{0})
	h.Write([]byte(assistantText))
	h.Write([]byte{0})
	for _, tu := range toolUses {
		h.Write([]byte(tu.ToolUseID))
		h.Write([]byte{0})
		h.Write([]byte(tu.Name))
		h.Write([]byte{0})
	}
	fp := hex.EncodeToString(h.Sum(nil))
	return strings.Join([]string{
		strings.TrimSpace(apiKeyID),
		strings.TrimSpace(modelID),
		strings.TrimSpace(conversationID),
		fp,
	}, "|")
}

// put seals a successful turn. Unsigned reasoning (no signature and no
// redacted blob) is dropped — same rule as the official client.
func (s *reasoningStore) put(apiKeyID, modelID, conversationID, parentUser, assistantText string, toolUses []KiroToolUse, text, signature, redacted string) {
	if signature == "" && redacted == "" {
		return
	}
	if text == "" && redacted == "" {
		return
	}
	key := turnKey(apiKeyID, modelID, conversationID, parentUser, assistantText, toolUses)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeLocked(time.Now())
	if len(s.byKey) >= reasoningStoreMaxEntries {
		// Drop a quarter of entries when at capacity.
		s.dropOldestLocked(reasoningStoreMaxEntries / 4)
	}
	s.byKey[key] = sealedReasoning{
		Text:            text,
		Signature:       signature,
		RedactedContent: redacted,
		ModelID:         modelID,
		StoredAt:        time.Now(),
	}
}

// lookup returns a stamp only on exact turn-key hit + model match + not expired.
// Miss → nil. Never guesses.
func (s *reasoningStore) lookup(apiKeyID, modelID, conversationID, parentUser, assistantText string, toolUses []KiroToolUse) *sealedReasoning {
	key := turnKey(apiKeyID, modelID, conversationID, parentUser, assistantText, toolUses)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeLocked(time.Now())
	e, ok := s.byKey[key]
	if !ok {
		return nil
	}
	if modelID != "" && e.ModelID != "" && e.ModelID != modelID {
		return nil
	}
	cp := e
	return &cp
}

func (s *reasoningStore) purgeLocked(now time.Time) {
	for k, e := range s.byKey {
		if now.Sub(e.StoredAt) > reasoningStoreTTL {
			delete(s.byKey, k)
		}
	}
}

func (s *reasoningStore) dropOldestLocked(n int) {
	type pair struct {
		k string
		t time.Time
	}
	all := make([]pair, 0, len(s.byKey))
	for k, e := range s.byKey {
		all = append(all, pair{k, e.StoredAt})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].t.Before(all[j].t) })
	if n > len(all) {
		n = len(all)
	}
	for i := 0; i < n; i++ {
		delete(s.byKey, all[i].k)
	}
}

// toKiroReasoning converts a sealed stamp into the wire reasoningContent object.
func toKiroReasoning(e *sealedReasoning) *KiroReasoningContent {
	if e == nil {
		return nil
	}
	if e.RedactedContent != "" {
		raw, err := base64.StdEncoding.DecodeString(e.RedactedContent)
		if err != nil || len(raw) == 0 {
			return nil
		}
		return &KiroReasoningContent{RedactedContent: raw}
	}
	if e.Signature == "" {
		return nil
	}
	rt := struct {
		Text      string `json:"text"`
		Signature string `json:"signature"`
	}{Text: e.Text, Signature: e.Signature}
	return &KiroReasoningContent{ReasoningText: &rt}
}

// lastUserTextBeforeAssistant returns the nearest preceding user text for an
// assistant history index. Used only for turn-key parent binding.
func lastUserTextBeforeAssistant(history []KiroHistoryMessage, assistantIdx int) string {
	for i := assistantIdx - 1; i >= 0; i-- {
		if history[i].UserInputMessage != nil {
			return history[i].UserInputMessage.Content
		}
	}
	return ""
}

// attachStoredReasoning walks history and pastes exact-match stamps onto
// assistant turns. No fuzzy fill. Safe to call every request.
func attachStoredReasoning(history []KiroHistoryMessage, apiKeyID, modelID, conversationID string) {
	if len(history) == 0 {
		return
	}
	for i := range history {
		as := history[i].AssistantResponseMessage
		if as == nil || as.ReasoningContent != nil {
			continue
		}
		parent := lastUserTextBeforeAssistant(history, i)
		if e := globalReasoningStore.lookup(apiKeyID, modelID, conversationID, parent, as.Content, as.ToolUses); e != nil {
			as.ReasoningContent = toKiroReasoning(e)
		}
	}
}

// sealSuccessfulTurn stores the stamp for this completed turn.
// currentTurnParentUser is the user text of the turn being answered: always
// payload.CurrentMessage, never the last user already in History.
func currentTurnParentUser(payload *KiroPayload) string {
	if payload == nil {
		return ""
	}
	return payload.ConversationState.CurrentMessage.UserInputMessage.Content
}

func sealSuccessfulTurn(apiKeyID, modelID, conversationID, parentUser, assistantText string, toolUses []KiroToolUse, thinkingText, signature, redacted string) {
	globalReasoningStore.put(apiKeyID, modelID, conversationID, parentUser, assistantText, toolUses, thinkingText, signature, redacted)
}

// debugTurnKey is for package tests.
func debugTurnKey(apiKeyID, modelID, conversationID, parentUser, assistantText string, toolUses []KiroToolUse) string {
	return turnKey(apiKeyID, modelID, conversationID, parentUser, assistantText, toolUses)
}

// reasoningCapture accumulates OnReasoningMeta for one upstream attempt.
type reasoningCapture struct {
	sig, red string
}

func (c *reasoningCapture) meta() func(string, string) {
	return func(sig, red string) {
		if c == nil {
			return
		}
		if sig != "" {
			c.sig = sig
		}
		if red != "" {
			c.red = red
		}
	}
}

func (c *reasoningCapture) reset() {
	if c == nil {
		return
	}
	c.sig, c.red = "", ""
}

func (c *reasoningCapture) sealIfPresent(apiKeyID, model, convID, parent, assistant string, tools []KiroToolUse, thinkingText string) {
	if c == nil || (c.sig == "" && c.red == "") {
		return
	}
	sealSuccessfulTurn(apiKeyID, model, convID, parent, assistant, tools, thinkingText, c.sig, c.red)
}
