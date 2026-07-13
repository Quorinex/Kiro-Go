package proxy

import (
	"kiro-go/config"
	"kiro-go/logger"
	"math/rand"
	"strings"
	"time"
)

// absoluteMaxAccountRetryAttempts is a defensive ceiling on per-request account
// retries. The budget otherwise means "iterate every selectable account" (see
// resolveAccountRetryBudget): each retry excludes already-tried accounts and
// must pick a different one, so the real retry count converges to the number of
// accounts and never runs away. This only guards pathological cases.
const absoluteMaxAccountRetryAttempts = 64

// resolveAccountRetryBudget returns how many account attempts one request may
// make. Previously this was a fixed 3, so with >3 accounts a request only tried
// the first 3 and gave up while the rest sat idle — under a 429 storm that meant
// an outright failure. Now it scales with the account count so every account
// can be tried. totalAccounts<=0 falls back to 1 (try at least once).
func resolveAccountRetryBudget(totalAccounts int) int {
	if totalAccounts <= 0 {
		return 1
	}
	if totalAccounts > absoluteMaxAccountRetryAttempts {
		return absoluteMaxAccountRetryAttempts
	}
	return totalAccounts
}

// accountRetryBackoff returns the wait before the next retry attempt:
// exponential 200ms→2s cap + jitter, so a transient upstream blip isn't
// amplified by back-to-back retries against the next account. attempt is 0-based.
func accountRetryBackoff(attempt int) time.Duration {
	const baseMS = 200
	const maxMS = 2000
	if attempt < 0 {
		attempt = 0
	}
	shift := attempt
	if shift > 4 {
		shift = 4
	}
	backoff := baseMS << shift
	if backoff > maxMS {
		backoff = maxMS
	}
	jitter := 0
	if j := backoff / 4; j > 0 {
		jitter = rand.Intn(j)
	}
	return time.Duration(backoff+jitter) * time.Millisecond
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

	updatedAccount := *account
	if !updatedAccount.Enabled && updatedAccount.BanStatus == banStatus && updatedAccount.BanReason == banReason {
		return
	}

	updatedAccount.Enabled = false
	updatedAccount.BanStatus = banStatus
	updatedAccount.BanReason = banReason
	updatedAccount.BanTime = time.Now().Unix()

	if err := config.UpdateAccount(account.ID, updatedAccount); err != nil {
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
	case isUpstreamPermanentError(err):
		// The request itself is malformed/rejected by the upstream regardless of
		// which account relays it. Penalising the account's health, cooling it
		// down, or rotating to another account would be wrong (the account is
		// healthy) and harmful (scatters cache affinity, wastes upstream hits).
		// Neutral: release the in-flight slot the selection took (RecordPermanentRejection)
		// without recording any success or failure, then return.
		h.pool.RecordPermanentRejection(account.ID)
		return
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
