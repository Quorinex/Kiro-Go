package proxy

import (
	"net/http"
	"testing"
	"time"
)

func TestAccountFailureClassifiers(t *testing.T) {
	tests := []struct {
		name string
		fn   func(string) bool
		msg  string
	}{
		{name: "quota", fn: isQuotaErrorMessage, msg: "HTTP 429: quota exhausted"},
		{name: "overage", fn: isOverageErrorMessage, msg: "HTTP 402 from Kiro IDE: OVERAGE limit exceeded"},
		{name: "suspension", fn: isSuspensionErrorMessage, msg: "Your User ID temporarily is suspended"},
		{name: "profile", fn: isProfileUnavailableErrorMessage, msg: "no available Kiro profile"},
		{name: "auth", fn: isAuthErrorMessage, msg: "Authentication failed - token invalid or expired"},
	}

	for _, tc := range tests {
		if !tc.fn(tc.msg) {
			t.Fatalf("%s classifier did not match %q", tc.name, tc.msg)
		}
	}
}

func TestRetryAfterDurationUsesUpstreamHintWithinBounds(t *testing.T) {
	tests := []struct {
		name       string
		retryAfter string
		want       time.Duration
	}{
		{name: "seconds", retryAfter: "45", want: 45 * time.Second},
		{name: "minimum", retryAfter: "1", want: minQuotaCooldown},
		{name: "maximum", retryAfter: "999999", want: maxQuotaCooldown},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := retryAfterDuration(tc.retryAfter, time.Unix(1_000, 0)); got != tc.want {
				t.Fatalf("retryAfterDuration(%q) = %s, want %s", tc.retryAfter, got, tc.want)
			}
		})
	}
}

func TestRetryAfterDurationParsesHTTPDate(t *testing.T) {
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	retryAt := now.Add(30 * time.Second).UTC().Format(http.TimeFormat)
	if got := retryAfterDuration(retryAt, now); got != 30*time.Second {
		t.Fatalf("retryAfterDuration(%q) = %s, want 30s", retryAt, got)
	}
}
