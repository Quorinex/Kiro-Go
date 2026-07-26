package proxy

import (
	"errors"
	"kiro-go/config"
	"kiro-go/logger"
	"strings"
)

const maxAccountRetryAttempts = 3

// maxSameAccountStreamRetries mirrors Kiro IDE's empty/truncated response
// recovery: retry the same request a few times before giving up or rotating.
const maxSameAccountStreamRetries = 2

// errUpstreamEmptyResponse and errUpstreamTruncatedResponse are soft failures
// raised when the stream ended without a usable completion signal. They are
// retryable on the same account and must not mark the account unhealthy.
var (
	errUpstreamEmptyResponse     = errors.New("upstream returned empty response without stop reason")
	errUpstreamTruncatedResponse = errors.New("upstream truncated response without stop reason")
	errIncompleteToolUse         = errors.New("upstream returned incomplete tool arguments")
)

// classifyStreamIntegrity decides whether an upstream stream that returned no
// transport error is actually complete. Mirrors Kiro IDE:
//   - empty: no content, no tools, no stopReason
//   - truncated: some content, no tools, no stopReason
//   - complete: stopReason present, or tools present, or both
//
// A stopReason of any non-empty value counts as complete.
func classifyStreamIntegrity(contentChars, toolCallCount int, stopReason string, sawReasoning bool) error {
	if strings.TrimSpace(stopReason) != "" {
		return nil
	}
	if toolCallCount > 0 {
		// Tool turns often complete without a separate stopReason frame; treat
		// a delivered tool call as a terminal signal.
		return nil
	}
	if contentChars == 0 && !sawReasoning {
		return errUpstreamEmptyResponse
	}
	if contentChars > 0 {
		return errUpstreamTruncatedResponse
	}
	// reasoning-only with no stopReason is still truncated for clients that
	// expected a final answer.
	return errUpstreamTruncatedResponse
}

func isSuccessfulKiroTurn(stopReason string, toolCallCount int) bool {
	if strings.TrimSpace(stopReason) == "" {
		// Complete tool turns can legitimately omit metadataEvent.stopReason.
		return toolCallCount > 0
	}
	switch classifyKiroStopReason(stopReason) {
	case kiroStopLength, kiroStopContextLimit, kiroStopFiltered:
		return false
	default:
		return true
	}
}

func isStreamIntegrityError(err error) bool {
	return errors.Is(err, errUpstreamEmptyResponse) || errors.Is(err, errUpstreamTruncatedResponse)
}

func isQuotaErrorMessage(msg string) bool {
	msg = strings.ToLower(msg)
	return strings.Contains(msg, "429") || strings.Contains(msg, "quota")
}

func isOverageErrorMessage(msg string) bool {
	msg = strings.ToLower(msg)
	return strings.Contains(msg, "402") && strings.Contains(msg, "overage")
}

func isSuspensionErrorMessage(msg string) bool {
	msg = strings.ToLower(msg)
	return strings.Contains(msg, "temporarily_suspended") ||
		strings.Contains(msg, "temporarily is suspended") ||
		strings.Contains(msg, "account suspended")
}

func isProfileUnavailableErrorMessage(msg string) bool {
	msg = strings.ToLower(msg)
	return strings.Contains(msg, "no available kiro profile")
}

func isAuthErrorMessage(msg string) bool {
	msg = strings.ToLower(msg)
	return strings.Contains(msg, "http 401") ||
		strings.Contains(msg, "http 403") ||
		strings.Contains(msg, "unauthorized") ||
		strings.Contains(msg, "forbidden") ||
		strings.Contains(msg, "authentication failed") ||
		strings.Contains(msg, "token invalid") ||
		strings.Contains(msg, "token expired") ||
		strings.Contains(msg, "invalid_grant") ||
		strings.Contains(msg, "access token expired") ||
		strings.Contains(msg, "refresh token expired")
}

func (h *Handler) disableAccount(account *config.Account, banStatus, banReason string) {
	if account == nil {
		return
	}

	if !account.Enabled && account.BanStatus == banStatus && account.BanReason == banReason {
		return
	}

	if err := config.SetAccountBanStatus(account.ID, banStatus, banReason); err != nil {
		logger.Warnf("[AccountFailover] Failed to disable %s: %v", account.Email, err)
		return
	}

	logger.Warnf("[AccountFailover] Disabled %s: %s", account.Email, banReason)
	h.pool.Reload()
}

func (h *Handler) disableAccountOverage(account *config.Account) {
	if account == nil {
		return
	}

	snap, fetchErr := FetchOverageStatus(account)
	if fetchErr != nil {
		logger.Warnf("[AccountFailover] Failed to refresh overage status for %s: %v", account.Email, fetchErr)
		return
	}
	if persistErr := PersistOverageSnapshot(account.ID, snap); persistErr != nil {
		logger.Warnf("[AccountFailover] Failed to persist overage snapshot for %s: %v", account.Email, persistErr)
		return
	}

	logger.Warnf("[AccountFailover] Refreshed overage status for %s after upstream overage limit error: %s", account.Email, snap.Status)
	h.pool.Reload()
}

func (h *Handler) handleAccountFailure(account *config.Account, err error) {
	if account == nil || err == nil {
		return
	}

	errMsg := err.Error()
	switch {
	case isOverageErrorMessage(errMsg):
		h.disableAccountOverage(account)
		h.pool.RecordError(account.ID, false)
	case isQuotaErrorMessage(errMsg):
		h.pool.RecordError(account.ID, true)
	case isSuspensionErrorMessage(errMsg):
		h.disableAccount(account, "BANNED", "AWS temporarily suspended - unusual user activity detected")
	case isProfileUnavailableErrorMessage(errMsg):
		// Profile ARN may be transiently unresolvable (upstream blip, stale token).
		// Treat as a soft failure: short cooldown so the next request rotates account,
		// but never auto-disable — operators can still investigate via warn logs.
		h.pool.RecordError(account.ID, false)
	case isAuthErrorMessage(errMsg):
		h.disableAccount(account, "BANNED", "Authentication failed - token invalid or expired")
	default:
		h.pool.RecordError(account.ID, false)
	}
}
