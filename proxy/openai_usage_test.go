package proxy

import (
	"strings"
	"testing"
	"time"
)

func estimatedOpenAIPayload(currentContent string) *KiroPayload {
	payload := &KiroPayload{}
	payload.ConversationState.CurrentMessage.UserInputMessage = KiroUserInputMessage{
		Content: currentContent,
		ModelID: "claude-sonnet-4.5",
		Origin:  "AI_EDITOR",
	}
	payload.ConversationState.History = []KiroHistoryMessage{
		{UserInputMessage: &KiroUserInputMessage{
			Content: strings.Repeat("stable conversation prefix ", 260),
			ModelID: "claude-sonnet-4.5",
			Origin:  "AI_EDITOR",
		}},
		{AssistantResponseMessage: &KiroAssistantResponseMessage{
			Content: strings.Repeat("stable assistant reply ", 80),
		}},
	}
	return payload
}

func TestResolveOpenAICacheUsageEstimatedLifecycle(t *testing.T) {
	tracker := newPromptCacheTracker(time.Hour)
	firstPayload := estimatedOpenAIPayload("first dynamic user turn")

	first := resolveOpenAICacheUsage(tracker, "account-a", firstPayload, 4096)
	if first == nil {
		t.Fatalf("first cache usage = %#v, want estimated details", first)
	}
	if first.CacheWriteTokens <= 0 || first.CachedTokens != 0 {
		t.Fatalf("first cache details = %#v, want write-only estimate", first)
	}

	// Current message text is deliberately excluded from the stable-prefix
	// fingerprint, so a subsequent turn can reuse the stored prefix.
	secondPayload := estimatedOpenAIPayload("different dynamic user turn")
	second := resolveOpenAICacheUsage(tracker, "account-a", secondPayload, 4096)
	if second == nil {
		t.Fatalf("second cache usage = %#v, want estimated details", second)
	}
	if second.CachedTokens <= 0 || second.CacheWriteTokens != 0 {
		t.Fatalf("second cache details = %#v, want read-only estimate", second)
	}

	otherAccount := resolveOpenAICacheUsage(tracker, "account-b", secondPayload, 4096)
	if otherAccount == nil || otherAccount.CachedTokens != 0 || otherAccount.CacheWriteTokens <= 0 {
		t.Fatalf("other account cache details = %#v, want independent write-only estimate", otherAccount)
	}
}

func TestResolveOpenAICacheUsageHitsEarlierPrefixWhenHistoryGrows(t *testing.T) {
	tracker := newPromptCacheTracker(time.Hour)
	firstPayload := estimatedOpenAIPayload("first dynamic user turn")
	first := resolveOpenAICacheUsage(tracker, "account-a", firstPayload, 4096)
	if first == nil || first.CacheWriteTokens <= 0 {
		t.Fatalf("first cache usage = %#v, want write-only estimate", first)
	}

	// The next turn adds history after the already stored stable prefix. The
	// current user turn remains excluded, so the tracker must still find the
	// earlier cumulative history breakpoint.
	grownPayload := estimatedOpenAIPayload("second dynamic user turn")
	grownPayload.ConversationState.History = append(grownPayload.ConversationState.History,
		KiroHistoryMessage{UserInputMessage: &KiroUserInputMessage{
			Content: strings.Repeat("newer stable history ", 120),
			ModelID: "claude-sonnet-4.5",
			Origin:  "AI_EDITOR",
		}},
	)
	got := resolveOpenAICacheUsage(tracker, "account-a", grownPayload, 6144)
	if got == nil || got.CachedTokens <= 0 {
		t.Fatalf("grown history cache usage = %#v, want read from earlier prefix", got)
	}
}
