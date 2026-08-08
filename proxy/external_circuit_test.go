package proxy

import (
	"testing"
	"time"
)

func TestExternalCircuitOpensAfterRetryableFailureAndResetsOnSuccess(t *testing.T) {
	resetExternalCircuits()
	base := "https://custom.example/v1"
	now := time.Unix(1_000, 0)

	if externalCircuitOpenAt(base, now) {
		t.Fatal("circuit should start closed")
	}
	_, _ = externalCircuitFailureAt(base, "", 5*time.Second, now)
	if failures, _ := externalCircuitStateSnapshot(base); failures != 1 {
		t.Fatalf("failures after first error = %d, want 1", failures)
	}
	if externalCircuitOpenAt(base, now.Add(time.Second)) {
		t.Fatal("circuit should not open after one failure")
	}
	_, _ = externalCircuitFailureAt(base, "", 5*time.Second, now.Add(time.Second))
	if failures, openUntil := externalCircuitStateSnapshot(base); failures != 2 || !openUntil.Equal(now.Add(6*time.Second)) {
		t.Fatalf("state after second error = failures %d, openUntil %v", failures, openUntil)
	}
	if !externalCircuitOpenAt(base, now.Add(2*time.Second)) {
		t.Fatal("circuit should open after two retryable failures")
	}
	if externalCircuitOpenAt(base, now.Add(7*time.Second)) {
		t.Fatal("circuit should close after cooldown")
	}

	_, _ = externalCircuitFailureAt(base, "", 5*time.Second, now.Add(8*time.Second))
	externalCircuitSuccess(base)
	if externalCircuitOpenAt(base, now.Add(9*time.Second)) {
		t.Fatal("success should reset the circuit")
	}
}

func TestExternalCircuitHonorsRetryAfterHeader(t *testing.T) {
	resetExternalCircuits()
	base := "https://custom.example/v1"
	now := time.Unix(2_000, 0)

	_, _ = externalCircuitFailureAt(base, "45", time.Second, now)
	_, _ = externalCircuitFailureAt(base, "45", time.Second, now.Add(time.Second))
	if !externalCircuitOpenAt(base, now.Add(44*time.Second)) {
		t.Fatal("Retry-After should keep the circuit open")
	}
	if externalCircuitOpenAt(base, now.Add(47*time.Second)) {
		t.Fatal("circuit should close after Retry-After")
	}
}

func TestExternalCircuitKeysIgnoreTrailingSlash(t *testing.T) {
	resetExternalCircuits()
	now := time.Unix(3_000, 0)
	_, _ = externalCircuitFailureAt("https://custom.example/v1/", "", 5*time.Second, now)
	_, _ = externalCircuitFailureAt("https://custom.example/v1", "", 5*time.Second, now.Add(time.Second))
	if !externalCircuitOpenAt("https://custom.example/v1/", now.Add(2*time.Second)) {
		t.Fatal("equivalent base URLs should share circuit state")
	}
}

func TestExternalCircuitFailureThresholdRequiresTwoFailures(t *testing.T) {
	resetExternalCircuits()
	base := "https://custom.example/v1"
	now := time.Unix(4_000, 0)

	_, _ = externalCircuitFailureAt(base, "", 20*time.Second, now)
	if externalCircuitOpenAt(base, now.Add(time.Second)) {
		t.Fatal("one failure must not open the circuit")
	}
	_, _ = externalCircuitFailureAt(base, "", 20*time.Second, now.Add(2*time.Second))
	if !externalCircuitOpenAt(base, now.Add(3*time.Second)) {
		t.Fatal("second consecutive failure should open the circuit")
	}
}

func TestExternalRetryAfterDurationParsesSecondsAndHTTPDate(t *testing.T) {
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	if got := externalRetryAfterDuration("45", now); got != 45*time.Second {
		t.Fatalf("seconds Retry-After = %s, want 45s", got)
	}
	date := now.Add(30 * time.Second).UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT")
	if got := externalRetryAfterDuration(date, now); got != 30*time.Second {
		t.Fatalf("date Retry-After = %s, want 30s", got)
	}
}

func TestIsRetryableExternalStatus(t *testing.T) {
	for _, status := range []int{408, 425, 429, 500, 503} {
		if !isRetryableExternalStatus(status) {
			t.Errorf("status %d should be retryable", status)
		}
	}
	for _, status := range []int{400, 401, 402, 403, 404} {
		if isRetryableExternalStatus(status) {
			t.Errorf("status %d should not be retryable", status)
		}
	}
}

func TestExternalCircuitAcquireReflectsOpenState(t *testing.T) {
	resetExternalCircuits()
	base := "https://custom.example/v1"
	now := time.Unix(5_000, 0)
	allowed, release := externalCircuitAcquire(base, now)
	if !allowed {
		t.Fatal("closed circuit should allow a probe")
	}
	release()
	_, _ = externalCircuitFailureAt(base, "", 20*time.Second, now)
	_, _ = externalCircuitFailureAt(base, "", 20*time.Second, now.Add(time.Second))
	if allowed, _ := externalCircuitAcquire(base, now.Add(2*time.Second)); allowed {
		t.Fatal("open circuit should suppress normal probes")
	}
	allowed, release = externalCircuitAcquire(base, now.Add(22*time.Second))
	if !allowed {
		t.Fatal("expired circuit should allow a probe")
	}
	if allowed, _ := externalCircuitAcquire(base, now.Add(22*time.Second)); allowed {
		t.Fatal("only one half-open probe may run at a time")
	}
	release()
	if allowed, release = externalCircuitAcquire(base, now.Add(22*time.Second)); !allowed {
		t.Fatal("released half-open probe should allow the next probe")
	}
	release()
}

func TestExternalCircuitAcquireAllowsOnlyOneProbeUntilRelease(t *testing.T) {
	resetExternalCircuits()
	base := "https://custom.example/v1"
	now := time.Unix(5_500, 0)
	_, _ = externalCircuitFailureAt(base, "", 20*time.Second, now)
	_, _ = externalCircuitFailureAt(base, "", 20*time.Second, now.Add(time.Second))

	probeAt := now.Add(22 * time.Second)
	allowed, release := externalCircuitAcquire(base, probeAt)
	if !allowed {
		t.Fatal("expired circuit should allow first half-open probe")
	}
	if allowed, _ := externalCircuitAcquire(base, probeAt.Add(24*time.Hour)); allowed {
		t.Fatal("active half-open probe should suppress another probe regardless of duration")
	}
	release()
	if allowed, release = externalCircuitAcquire(base, probeAt.Add(24*time.Hour)); !allowed {
		t.Fatal("released half-open probe should permit recovery")
	}
	release()
}

func TestExternalCircuitFailureUsesMinimumCooldown(t *testing.T) {
	resetExternalCircuits()
	base := "https://custom.example/v1"
	now := time.Unix(6_000, 0)
	_, _ = externalCircuitFailureAt(base, "1", time.Second, now)
	_, _ = externalCircuitFailureAt(base, "1", time.Second, now.Add(time.Second))
	_, openUntil := externalCircuitStateSnapshot(base)
	if got := openUntil.Sub(now.Add(time.Second)); got != externalCircuitMinCooldown {
		t.Fatalf("minimum cooldown = %s, want %s", got, externalCircuitMinCooldown)
	}
}

func TestExternalCircuitFailureUsesMaximumCooldown(t *testing.T) {
	resetExternalCircuits()
	base := "https://custom.example/v1"
	now := time.Unix(7_000, 0)
	_, _ = externalCircuitFailureAt(base, "999999", time.Second, now)
	_, _ = externalCircuitFailureAt(base, "999999", time.Second, now.Add(time.Second))
	_, openUntil := externalCircuitStateSnapshot(base)
	if got := openUntil.Sub(now.Add(time.Second)); got != externalCircuitMaxCooldown {
		t.Fatalf("maximum cooldown = %s, want %s", got, externalCircuitMaxCooldown)
	}
}

func TestExternalCircuitSuccessClearsFailureState(t *testing.T) {
	resetExternalCircuits()
	base := "https://custom.example/v1"
	now := time.Unix(8_000, 0)
	_, _ = externalCircuitFailureAt(base, "", 20*time.Second, now)
	externalCircuitSuccess(base)
	failures, openUntil := externalCircuitStateSnapshot(base)
	if failures != 0 || !openUntil.IsZero() {
		t.Fatalf("success left circuit state: failures=%d openUntil=%v", failures, openUntil)
	}
}

func TestExternalCircuitEmptyKeyIsAlwaysClosed(t *testing.T) {
	resetExternalCircuits()
	if externalCircuitOpenAt("", time.Unix(9_000, 0)) {
		t.Fatal("empty base URL must not open a circuit")
	}
	if allowed, release := externalCircuitAcquire("", time.Unix(9_000, 0)); !allowed {
		t.Fatal("empty base URL should allow probe")
	} else {
		release()
	}
}

func TestExternalCircuitExpiredOpenStateAllowsSingleHalfOpenProbe(t *testing.T) {
	resetExternalCircuits()
	base := "https://custom.example/v1"
	now := time.Unix(10_000, 0)
	_, _ = externalCircuitFailureAt(base, "", 20*time.Second, now)
	_, _ = externalCircuitFailureAt(base, "", 20*time.Second, now.Add(time.Second))
	if !externalCircuitOpenAt(base, now.Add(2*time.Second)) {
		t.Fatal("circuit never opened before the expiration check")
	}
	if externalCircuitOpenAt(base, now.Add(22*time.Second)) {
		t.Fatal("circuit should be half-open after expiration")
	}
	failures, _ := externalCircuitStateSnapshot(base)
	if failures != 2 {
		t.Fatalf("half-open circuit lost failure history before probe: %d", failures)
	}
	allowed, release := externalCircuitAcquire(base, now.Add(22*time.Second))
	if !allowed {
		t.Fatal("expired circuit should allow a half-open probe")
	}
	if allowed, _ := externalCircuitAcquire(base, now.Add(22*time.Second)); allowed {
		t.Fatal("concurrent half-open probe should be suppressed")
	}
	release()
}
