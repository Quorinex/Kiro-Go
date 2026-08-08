package proxy

import (
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	externalCircuitFailureThreshold = 2
	externalCircuitDefaultCooldown  = 30 * time.Second
	externalCircuitMinCooldown      = 5 * time.Second
	externalCircuitMaxCooldown      = 5 * time.Minute
	externalCircuitProbeLease       = 30 * time.Second
)

type externalCircuitState struct {
	failures    int
	openUntil   time.Time
	probing     bool
	probeLeased time.Time
}

var externalCircuits = struct {
	sync.Mutex
	states map[string]externalCircuitState
}{
	states: make(map[string]externalCircuitState),
}

func normalizeExternalCircuitKey(baseURL string) string {
	return strings.TrimRight(strings.TrimSpace(baseURL), "/")
}

func resetExternalCircuits() {
	externalCircuits.Lock()
	externalCircuits.states = make(map[string]externalCircuitState)
	externalCircuits.Unlock()
}

func externalCircuitOpenAt(baseURL string, now time.Time) bool {
	key := normalizeExternalCircuitKey(baseURL)
	if key == "" {
		return false
	}

	externalCircuits.Lock()
	defer externalCircuits.Unlock()
	state, ok := externalCircuits.states[key]
	if !ok || state.openUntil.IsZero() {
		return false
	}
	if !now.Before(state.openUntil) {
		return false
	}
	return true
}

// externalCircuitAllowProbe is an atomic circuit admission check. A closed
// circuit admits all traffic; an open circuit admits none; after cooldown only
// one half-open probe is leased at a time. The lease expires so a canceled
// request cannot leave the upstream permanently suppressed.
func externalCircuitAllowProbe(baseURL string, now time.Time) bool {
	key := normalizeExternalCircuitKey(baseURL)
	if key == "" {
		return true
	}
	externalCircuits.Lock()
	defer externalCircuits.Unlock()
	state, ok := externalCircuits.states[key]
	if !ok || state.openUntil.IsZero() {
		return true
	}
	if now.Before(state.openUntil) {
		return false
	}
	if state.probing && now.Sub(state.probeLeased) < externalCircuitProbeLease {
		return false
	}
	state.probing = true
	state.probeLeased = now
	externalCircuits.states[key] = state
	return true
}

func externalCircuitFailure(baseURL, retryAfter string, fallbackCooldown time.Duration) (time.Duration, bool) {
	return externalCircuitFailureAt(baseURL, retryAfter, fallbackCooldown, time.Now())
}

func externalCircuitFailureAt(baseURL, retryAfter string, fallbackCooldown time.Duration, now time.Time) (time.Duration, bool) {
	key := normalizeExternalCircuitKey(baseURL)
	if key == "" {
		return 0, false
	}
	cooldown := externalRetryAfterDuration(retryAfter, now)
	if cooldown <= 0 {
		cooldown = fallbackCooldown
	}
	if cooldown <= 0 {
		cooldown = externalCircuitDefaultCooldown
	}
	if cooldown < externalCircuitMinCooldown {
		cooldown = externalCircuitMinCooldown
	}
	if cooldown > externalCircuitMaxCooldown {
		cooldown = externalCircuitMaxCooldown
	}

	externalCircuits.Lock()
	defer externalCircuits.Unlock()
	state := externalCircuits.states[key]
	state.failures++
	state.probing = false
	state.probeLeased = time.Time{}
	opened := false
	if state.failures >= externalCircuitFailureThreshold {
		state.openUntil = now.Add(cooldown)
		opened = true
	} else {
		state.openUntil = time.Time{}
	}
	externalCircuits.states[key] = state
	return cooldown, opened
}

func externalCircuitStateSnapshot(baseURL string) (failures int, openUntil time.Time) {
	key := normalizeExternalCircuitKey(baseURL)
	externalCircuits.Lock()
	defer externalCircuits.Unlock()
	state := externalCircuits.states[key]
	return state.failures, state.openUntil
}

func externalCircuitSuccess(baseURL string) {
	key := normalizeExternalCircuitKey(baseURL)
	if key == "" {
		return
	}
	externalCircuits.Lock()
	delete(externalCircuits.states, key)
	externalCircuits.Unlock()
}

func externalRetryAfterDuration(value string, now time.Time) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		return time.Duration(seconds) * time.Second
	}
	if at, err := http.ParseTime(value); err == nil {
		return at.Sub(now)
	}
	return 0
}

func isRetryableExternalStatus(status int) bool {
	return status == http.StatusRequestTimeout ||
		status == http.StatusTooEarly ||
		status == http.StatusTooManyRequests ||
		status >= http.StatusInternalServerError
}
