package proxy

// OpenAITokenDetails contains the cache components OpenAI-compatible clients
// understand. CachedTokens and CacheWriteTokens are subsets of the top-level
// input/prompt token count.
type OpenAITokenDetails struct {
	CachedTokens     int `json:"cached_tokens"`
	CacheWriteTokens int `json:"cache_write_tokens"`
}

func resolveOpenAICacheUsage(tracker *promptCacheTracker, accountID string, payload *KiroPayload, inputTokens int) *OpenAITokenDetails {
	if tracker == nil {
		return nil
	}
	profile := tracker.BuildOpenAIProfile(payload, inputTokens)
	if profile == nil {
		return nil
	}
	estimated := tracker.Compute(accountID, profile)
	// Store only after a successful upstream response.
	tracker.Update(accountID, profile)
	if estimated.CacheReadInputTokens == 0 && estimated.CacheCreationInputTokens == 0 {
		return nil
	}
	return &OpenAITokenDetails{
		CachedTokens:     estimated.CacheReadInputTokens,
		CacheWriteTokens: estimated.CacheCreationInputTokens,
	}
}

func buildOpenAIUsage(inputTokens, outputTokens int, details *OpenAITokenDetails) map[string]interface{} {
	usage := map[string]interface{}{
		"prompt_tokens":     inputTokens,
		"completion_tokens": outputTokens,
		"total_tokens":      inputTokens + outputTokens,
	}
	if details != nil {
		usage["prompt_tokens_details"] = details
	}
	return usage
}
