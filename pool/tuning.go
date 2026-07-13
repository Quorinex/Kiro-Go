package pool

// Pool scheduling tuning: a hard per-account concurrency cap and opt-in account
// selection strategies. Both are configured via environment and default to the
// existing behaviour (no cap, "smart" soft scheduler) so enabling them never
// regresses current deployments.
//
//	KIRO_MAX_CONCURRENT_PER_ACCOUNT  int   hard in-flight cap per account (0 = unlimited)
//	KIRO_SELECTION_STRATEGY          enum  smart|round_robin|random|least_used|most_used
//
// "least_used"/"most_used" rank by remaining quota (UsageLimit-UsageCurrent);
// accounts with no usage limit count as effectively unlimited remaining.
//
// Ported verbatim from kiro-tutu (zero-dep).
import (
	"kiro-go/config"
	"math"
	"math/rand"
	"os"
	"strconv"
	"strings"
)

type selectionStrategy int

const (
	strategySmart selectionStrategy = iota
	strategyRoundRobin
	strategyRandom
	strategyLeastUsed
	strategyMostUsed
)

var (
	poolMaxConcurrent = envIntTuning("KIRO_MAX_CONCURRENT_PER_ACCOUNT", 0)
	poolStrategy      = parseStrategy(os.Getenv("KIRO_SELECTION_STRATEGY"))
)

func envIntTuning(name string, def int) int {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return n
		}
	}
	return def
}

func parseStrategy(s string) selectionStrategy {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "round_robin", "roundrobin", "ordered":
		return strategyRoundRobin
	case "random":
		return strategyRandom
	case "least_used", "leastused", "least-used":
		return strategyLeastUsed
	case "most_used", "mostused", "most-used":
		return strategyMostUsed
	default:
		return strategySmart
	}
}

// applyConcurrencyCap drops candidates whose in-flight count has reached the
// per-account cap. If every candidate is saturated it returns the original set
// unchanged, so a burst degrades to "least-busy" (via the scheduler) rather than
// a hard 503 while capacity technically exists.
func applyConcurrencyCap(candidates []accountCandidate) []accountCandidate {
	if poolMaxConcurrent <= 0 || len(candidates) == 0 {
		return candidates
	}
	filtered := make([]accountCandidate, 0, len(candidates))
	for _, c := range candidates {
		if c.inFlight < int64(poolMaxConcurrent) {
			filtered = append(filtered, c)
		}
	}
	if len(filtered) == 0 {
		return candidates
	}
	return filtered
}

// selectCandidate chooses one candidate according to the configured strategy.
// candidates must be non-empty.
func selectCandidate(candidates []accountCandidate) accountCandidate {
	switch poolStrategy {
	case strategyRandom:
		return candidates[rand.Intn(len(candidates))]
	case strategyRoundRobin:
		// Candidates are gathered in rotation order (selectAccountLocked starts
		// at an advancing index), so taking the first entry yields round-robin.
		return candidates[0]
	case strategyLeastUsed:
		best := candidates[0]
		for _, c := range candidates[1:] {
			if remainingQuota(c.account) > remainingQuota(best.account) {
				best = c
			}
		}
		return best
	case strategyMostUsed:
		best := candidates[0]
		for _, c := range candidates[1:] {
			if remainingQuota(c.account) < remainingQuota(best.account) {
				best = c
			}
		}
		return best
	default: // strategySmart — the health/load-aware soft scheduler
		best := candidates[0]
		for _, c := range candidates[1:] {
			if accountCandidateLess(c, best) {
				best = c
			}
		}
		return best
	}
}

func remainingQuota(acc *config.Account) float64 {
	if acc == nil || acc.UsageLimit <= 0 {
		return math.MaxFloat64
	}
	return acc.UsageLimit - acc.UsageCurrent
}
