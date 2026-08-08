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
)

type externalCircuitState struct {
	failures   int
	openUntil  time.Time
	probing    bool
	probeToken uint64
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

// externalCircuitAcquire is an atomic circuit admission check. A closed
// circuit admits all traffic; an open circuit admits none; after cooldown only
// one half-open probe is admitted at a time. The returned release callback must
// be called on every terminal path; a generation token prevents an old request
// from releasing a newer probe.
func externalCircuitAcquire(baseURL string, now time.Time) (bool, func()) {
	key := normalizeExternalCircuitKey(baseURL)
	if key == "" {
		return true, func() {}
	}
	externalCircuits.Lock()
	state, ok := externalCircuits.states[key]
	if !ok || state.openUntil.IsZero() {
		externalCircuits.Unlock()
		return true, func() {}
	}
	if now.Before(state.openUntil) {
		externalCircuits.Unlock()
		return false, func() {}
	}
	if state.probing {
		externalCircuits.Unlock()
		return false, func() {}
	}
	state.probing = true
	state.probeToken++
	token := state.probeToken
	externalCircuits.states[key] = state
	externalCircuits.Unlock()

	var once sync.Once
	return true, func() {
		once.Do(func() {
			externalCircuits.Lock()
			current := externalCircuits.states[key]
			if current.probing && current.probeToken == token {
				current.probing = false
				externalCircuits.states[key] = current
			}
			externalCircuits.Unlock()
		})
	}
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
