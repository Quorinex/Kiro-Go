package proxy

// Token warm-up worker (production resilience).
//
// Complements the coarse 30-minute backgroundRefresh with a tighter 2-minute
// cadence and a 15-minute look-ahead: tokens nearing expiry are refreshed off
// the request path, so requests rarely block on a synchronous refresh and a
// transient refresh failure has time to recover before the token actually
// expires. It reuses tokenRefreshMu (shared with the request path) and
// re-checks under lock, so it never races or double-refreshes.
//
// Ported from kiro-tutu (zero-dep).
import (
	"kiro-go/config"
	"kiro-go/logger"
	"time"
)

const (
	warmupTokenWindowSeconds int64 = 15 * 60
	warmupInterval                 = 2 * time.Minute
)

func (h *Handler) backgroundWarmup() {
	ticker := time.NewTicker(warmupInterval)
	defer ticker.Stop()
	for range ticker.C {
		h.warmupExpiringTokens()
	}
}

func (h *Handler) warmupExpiringTokens() {
	now := time.Now().Unix()
	for _, acc := range h.pool.GetAllAccounts() {
		if acc.ExpiresAt <= 0 || now < acc.ExpiresAt-warmupTokenWindowSeconds {
			continue // not near expiry yet
		}
		account := acc // work on a copy; refresh results are written back via pool/config

		h.tokenRefreshMu.Lock()
		// Re-read latest state under lock in case the request path just refreshed it.
		if latest := h.pool.GetByID(account.ID); latest != nil {
			account.AccessToken = latest.AccessToken
			account.RefreshToken = latest.RefreshToken
			account.ExpiresAt = latest.ExpiresAt
			account.ProfileArn = latest.ProfileArn
		}
		if account.ExpiresAt <= 0 || time.Now().Unix() < account.ExpiresAt-warmupTokenWindowSeconds {
			h.tokenRefreshMu.Unlock()
			continue // already refreshed by another path
		}

		accessToken, refreshToken, expiresAt, profileArn, err := authRefreshToken(&account)
		if err != nil {
			h.tokenRefreshMu.Unlock()
			logger.Warnf("[Warmup] refresh failed for %s: %v", account.ID, err)
			continue
		}
		h.pool.UpdateToken(account.ID, accessToken, refreshToken, expiresAt)
		if profileArn != "" {
			config.UpdateAccountProfileArn(account.ID, profileArn)
		}
		config.UpdateAccountToken(account.ID, accessToken, refreshToken, expiresAt)
		h.tokenRefreshMu.Unlock()
		logger.Infof("[Warmup] proactively refreshed token for %s", account.ID)
	}
}
