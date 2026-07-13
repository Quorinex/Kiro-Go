package pool

// Health-aware account selection (production dispatch quality).
//
// Replaces pure weighted round-robin with a smart scheduler that, among the
// accounts passing the hard filters (model support, not cooling down, token
// valid, quota available), picks the one least likely to fail or stall:
//
//	lowest in-flight  ->  fewest recent failures  ->  fewest recent selections
//	  ->  fewest recent successes
//
// in-flight is incremented when an account is selected and decremented when the
// dispatch finishes (RecordSuccess / RecordError / RecordPermanentRejection /
// DisableAccount / MarkOverLimit), so under concurrency the scheduler spreads
// load instead of piling onto the same account. The per-account concurrency cap
// (pool/tuning.go, default 0 = unlimited) and the selection strategy are opt-in
// via env and default to the smart scheduler.
//
// Ported from kiro-tutu. Differences from tutu, deliberately kept:
//   - This repo's least-cooldown fallback is retained: when no account passes
//     all hard filters, the account with the earliest cooldown is returned
//     (rather than nil -> 503), preserving existing availability behaviour.
//   - endpoint429 / affinity machinery is NOT ported (no cache-affinity layer
//     in this repo; endpoint-429 signals only fed affinity circuit-breaking).
//
// Safety: every finish helper clamps in-flight at 0, so a missed or double
// finish can never drive the counter negative. With the default concurrency cap
// of 0 (unlimited) a leaked in-flight only skews the smart tie-break, never
// starves an account.
import (
	"kiro-go/config"
	"time"
)

// accountFairnessWindow is the rolling window over which "recent" selection /
// success / failure counts are tallied. Beyond it the counters rotate (reset),
// so a transient burst does not permanently skew a healthy account's score.
const accountFairnessWindow = 5 * time.Minute

// AccountRuntimeStats is an in-memory snapshot of dispatch-level account usage,
// exposed for observability (e.g. the kiro_account_inflight metric).
type AccountRuntimeStats struct {
	SelectedCount int64 `json:"selectedCount"`
	SuccessCount  int64 `json:"successCount"`
	FailureCount  int64 `json:"failureCount"`
	InFlight      int64 `json:"inFlight"`
}

// accountRuntimeStats tracks per-account dispatch signals used by the smart
// scheduler. The recent* fields rotate every accountFairnessWindow.
type accountRuntimeStats struct {
	selectedCount int64
	successCount  int64
	failureCount  int64
	inFlight      int64

	windowStartedAt     time.Time
	recentSelectedCount int64
	recentSuccessCount  int64
	recentFailureCount  int64
}

// accountCandidate is a selectable account paired with the health/load signals
// the smart scheduler compares (accountCandidateLess).
type accountCandidate struct {
	account             *config.Account
	inFlight            int64
	recentFailureCount  int64
	recentSelectedCount int64
	recentSuccessCount  int64
}

// ensurePoolMapsLocked lazily initialises the pool's maps so callers (and tests
// that construct an AccountPool directly) cannot nil-deref. Caller holds p.mu.
func (p *AccountPool) ensurePoolMapsLocked() {
	if p.cooldowns == nil {
		p.cooldowns = make(map[string]time.Time)
	}
	if p.errorCounts == nil {
		p.errorCounts = make(map[string]int)
	}
	if p.modelLists == nil {
		p.modelLists = make(map[string]map[string]bool)
	}
	if p.runtimeStats == nil {
		p.runtimeStats = make(map[string]*accountRuntimeStats)
	}
}

func (p *AccountPool) statsForAccountLocked(id string, now time.Time) *accountRuntimeStats {
	p.ensurePoolMapsLocked()
	stats := p.runtimeStats[id]
	if stats == nil {
		stats = &accountRuntimeStats{windowStartedAt: now}
		p.runtimeStats[id] = stats
	}
	rotateAccountStatsWindow(stats, now)
	return stats
}

func rotateAccountStatsWindow(stats *accountRuntimeStats, now time.Time) {
	if stats.windowStartedAt.IsZero() || now.Before(stats.windowStartedAt) {
		stats.windowStartedAt = now
		return
	}
	if now.Sub(stats.windowStartedAt) < accountFairnessWindow {
		return
	}
	stats.windowStartedAt = now
	stats.recentSelectedCount = 0
	stats.recentSuccessCount = 0
	stats.recentFailureCount = 0
}

func (p *AccountPool) accountCandidateLocked(acc *config.Account, now time.Time) accountCandidate {
	stats := p.statsForAccountLocked(acc.ID, now)
	return accountCandidate{
		account:             acc,
		inFlight:            stats.inFlight,
		recentFailureCount:  stats.recentFailureCount,
		recentSelectedCount: stats.recentSelectedCount,
		recentSuccessCount:  stats.recentSuccessCount,
	}
}

// accountCandidateLess orders by production safety first: avoid busy accounts,
// then avoid recently unhealthy accounts, then spread selections and successes.
func accountCandidateLess(a, b accountCandidate) bool {
	switch {
	case a.inFlight != b.inFlight:
		return a.inFlight < b.inFlight
	case a.recentFailureCount != b.recentFailureCount:
		return a.recentFailureCount < b.recentFailureCount
	case a.recentSelectedCount != b.recentSelectedCount:
		return a.recentSelectedCount < b.recentSelectedCount
	default:
		return a.recentSuccessCount < b.recentSuccessCount
	}
}

func (p *AccountPool) markAccountSelectedLocked(id string, now time.Time) {
	stats := p.statsForAccountLocked(id, now)
	stats.selectedCount++
	stats.recentSelectedCount++
	stats.inFlight++
}

// finishAccountUseLocked returns the in-flight slot and records the outcome.
// success -> recentSuccess; otherwise -> recentFailure (and recent429 when
// quotaError). in-flight is clamped at 0 so a missed/double finish is harmless.
func (p *AccountPool) finishAccountUseLocked(id string, success, quotaError bool, now time.Time) {
	stats := p.statsForAccountLocked(id, now)
	if stats.inFlight > 0 {
		stats.inFlight--
	}
	if success {
		stats.successCount++
		stats.recentSuccessCount++
		return
	}
	stats.failureCount++
	stats.recentFailureCount++
}

// finishAccountUseNeutralLocked returns the in-flight slot without recording a
// success or failure. Used when the dispatch outcome reflects the request
// payload (a permanent upstream rejection), not the account's health.
func (p *AccountPool) finishAccountUseNeutralLocked(id string, now time.Time) {
	stats := p.statsForAccountLocked(id, now)
	if stats.inFlight > 0 {
		stats.inFlight--
	}
}

// nextStartIndexLocked advances the round-robin cursor and returns the starting
// index for a selection sweep. Caller holds p.mu.
func (p *AccountPool) nextStartIndexLocked(n int) int {
	p.currentIndex++
	return int(p.currentIndex % uint64(n))
}

// selectAccountLocked is the single selection routine shared by GetNextExcluding
// (requireModel=false) and GetNextForModelExcluding (requireModel=true). It
// gathers eligible candidates, applies the optional concurrency cap, and picks
// one via the configured strategy (default: smart health/load-aware). If no
// candidate passes the hard filters, it falls back to the least-cooldown
// eligible account (never nil when capacity exists) — preserving this repo's
// availability behaviour, which tutu lacks.
func (p *AccountPool) selectAccountLocked(model string, excluded map[string]bool, requireModel bool) *config.Account {
	if len(p.accounts) == 0 {
		return nil
	}

	allowOverUsage := config.GetAllowOverUsage()
	now := time.Now()
	nowUnix := now.Unix()
	n := len(p.accounts)
	start := p.nextStartIndexLocked(n)
	seen := make(map[string]bool)
	candidates := make([]accountCandidate, 0, n)

	for i := 0; i < n; i++ {
		idx := (start + i) % n
		acc := &p.accounts[idx]
		if excluded != nil && excluded[acc.ID] {
			seen[acc.ID] = true
			continue
		}
		if seen[acc.ID] {
			continue
		}
		seen[acc.ID] = true
		if requireModel && !p.accountHasModel(acc.ID, model) {
			continue
		}
		if acc.ExpiresAt > 0 && nowUnix > acc.ExpiresAt-tokenRefreshSkewSeconds {
			continue
		}
		if isQuotaBlocked(*acc, allowOverUsage) {
			continue
		}
		if cooldown, ok := p.cooldowns[acc.ID]; ok && now.Before(cooldown) {
			continue
		}
		candidates = append(candidates, p.accountCandidateLocked(acc, now))
	}

	if selected := p.bestCandidateLocked(candidates, now); selected != nil {
		return selected
	}

	// Fallback: no account passed all hard filters (all cooling down). Return the
	// eligible account (model + quota OK, not excluded) with the earliest cooldown
	// so the caller still gets capacity rather than a hard 503.
	var best *config.Account
	var earliest time.Time
	for i := range p.accounts {
		acc := &p.accounts[i]
		if excluded != nil && excluded[acc.ID] {
			continue
		}
		if requireModel && !p.accountHasModel(acc.ID, model) {
			continue
		}
		if isQuotaBlocked(*acc, allowOverUsage) {
			continue
		}
		if cooldown, ok := p.cooldowns[acc.ID]; ok {
			if best == nil || cooldown.Before(earliest) {
				best = acc
				earliest = cooldown
			}
		} else {
			// No cooldown at all — prefer over any cooling-down account.
			p.markAccountSelectedLocked(acc.ID, now)
			return copyAccount(acc)
		}
	}
	if best != nil {
		p.markAccountSelectedLocked(best.ID, now)
		return copyAccount(best)
	}
	return nil
}

// bestCandidateLocked applies the concurrency cap, picks one candidate via the
// configured strategy, marks it selected (in-flight++), and returns a value
// copy. Returns nil when candidates is empty.
func (p *AccountPool) bestCandidateLocked(candidates []accountCandidate, now time.Time) *config.Account {
	if len(candidates) == 0 {
		return nil
	}
	candidates = applyConcurrencyCap(candidates)
	best := selectCandidate(candidates)
	p.markAccountSelectedLocked(best.account.ID, now)
	// Return a value copy, never an interior pointer into p.accounts: callers
	// (ensureValidToken etc.) mutate AccessToken/ExpiresAt without holding p.mu,
	// which would data-race with UpdateToken/Reload on the shared slice.
	return copyAccount(best.account)
}

// RecordPermanentRejection finishes an account dispatch that failed because the
// upstream rejected the request itself (e.g. "improperly formed request"). Such
// a rejection is inherent to the request payload, not the account, so it returns
// the in-flight slot WITHOUT counting any success or failure: the account's
// health must not be penalised for a bad request it merely relayed.
func (p *AccountPool) RecordPermanentRejection(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ensurePoolMapsLocked()
	p.finishAccountUseNeutralLocked(id, time.Now())
}

// CooldownAccount keeps an account out of routing for the given duration without
// recording a dispatch outcome. Used by failover paths that already accounted for
// the attempt via RecordError but need a fresh short cooldown.
func (p *AccountPool) CooldownAccount(id string, duration time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ensurePoolMapsLocked()
	p.cooldowns[id] = time.Now().Add(duration)
}

// ResetTransientState clears per-account cooldowns, error counters and runtime
// stats and rewinds the round-robin cursor. Intended for test isolation: the
// pool is a process-wide singleton, so a prior test's failures/cooldowns would
// otherwise leak into later tests that reuse the same account IDs.
func (p *AccountPool) ResetTransientState() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cooldowns = make(map[string]time.Time)
	p.errorCounts = make(map[string]int)
	p.runtimeStats = make(map[string]*accountRuntimeStats)
	p.currentIndex = 0
}

// GetRuntimeStatsSnapshot returns a copy of the per-account dispatch stats for
// observability (e.g. the kiro_account_inflight Prometheus gauge).
func (p *AccountPool) GetRuntimeStatsSnapshot() map[string]AccountRuntimeStats {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make(map[string]AccountRuntimeStats, len(p.runtimeStats))
	for id, s := range p.runtimeStats {
		out[id] = AccountRuntimeStats{
			SelectedCount: s.selectedCount,
			SuccessCount:  s.successCount,
			FailureCount:  s.failureCount,
			InFlight:      s.inFlight,
		}
	}
	return out
}
