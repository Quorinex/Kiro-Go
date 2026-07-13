package pool

import (
	"testing"
	"time"
)

// jitterBand returns the inclusive [lo, hi] bounds for a ±10% jitter window
// around base, computed with integer Duration arithmetic (exact for the minute
// multiples used here, and avoids float→Duration constant conversions that Go
// rejects at compile time).
func jitterBand(base time.Duration) (time.Duration, time.Duration) {
	return base * 9 / 10, base * 11 / 10
}

// TestErrorCooldownDurationBelowThresholdIsBase confirms that below the threshold
// the shift is clamped to 0, so the cooldown equals the base duration (±jitter).
func TestErrorCooldownDurationBelowThresholdIsBase(t *testing.T) {
	lo, hi := jitterBand(errorCooldownBase)
	for n := 0; n < errorCooldownThreshold; n++ {
		for i := 0; i < 50; i++ {
			if d := errorCooldownDuration(n); d < lo || d > hi {
				t.Fatalf("errorCooldownDuration(%d)=%v outside [%v,%v]", n, d, lo, hi)
			}
		}
	}
}

// TestErrorCooldownDurationRespectsCap confirms that once the exponential shift
// would exceed errorCooldownMax, the cooldown is clamped at the cap (±jitter) and
// never grows unbounded no matter how high the error count climbs.
func TestErrorCooldownDurationRespectsCap(t *testing.T) {
	lo, hi := jitterBand(errorCooldownMax)
	// n=6 -> steps=3 -> base<<3 = 8m == cap; n>=7 -> capped. Both land at the cap.
	for n := 6; n <= 100; n++ {
		for i := 0; i < 20; i++ {
			if d := errorCooldownDuration(n); d < lo || d > hi {
				t.Fatalf("errorCooldownDuration(%d)=%v outside cap band [%v,%v]", n, d, lo, hi)
			}
		}
	}
}

// TestErrorCooldownDurationStaysPositive confirms jitter can never drive the
// duration to zero or negative (defensive guard d<=0 → backoff).
func TestErrorCooldownDurationStaysPositive(t *testing.T) {
	for n := 0; n < 1000; n++ {
		for i := 0; i < 5; i++ {
			if d := errorCooldownDuration(n); d <= 0 {
				t.Fatalf("errorCooldownDuration(%d) returned non-positive %v", n, d)
			}
		}
	}
}

// TestErrorCooldownDurationGrowsBeforeCap confirms the nominal (jitter-centre)
// backoff grows exponentially with the error count until it hits the cap: the
// minimum observed duration at a higher step should not be below the maximum
// observed at a much lower step.
func TestErrorCooldownDurationGrowsBeforeCap(t *testing.T) {
	var minHigh time.Duration = 1 << 62
	var maxLow time.Duration
	for i := 0; i < 200; i++ {
		// step 1: backoff = 2×base (just above threshold)
		if d := errorCooldownDuration(errorCooldownThreshold + 1); d < minHigh {
			minHigh = d
		}
		// step 0: backoff = base (at threshold)
		if d := errorCooldownDuration(errorCooldownThreshold); d > maxLow {
			maxLow = d
		}
	}
	// 2×base minus 10% jitter (=1.8×base) must exceed 1×base plus 10% jitter (=1.1×base).
	if minHigh <= maxLow {
		t.Fatalf("expected higher-step cooldown to exceed lower-step: minHigh=%v maxLow=%v", minHigh, maxLow)
	}
}
