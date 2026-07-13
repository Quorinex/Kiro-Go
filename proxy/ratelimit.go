package proxy

// Inbound request rate limiting (production hardening).
//
// Provides a dependency-free token-bucket limiter with two tiers:
//   - a global bucket (all inbound API traffic), and
//   - a per-API-key (tenant) bucket.
//
// Both tiers are OFF by default (rate 0 == unlimited) so enabling the limiter
// never silently regresses existing deployments; operators opt in via env:
//
//	KIRO_RATE_LIMIT_RPM           global requests/minute       (0 = unlimited)
//	KIRO_RATE_LIMIT_PER_KEY_RPM   per-API-key requests/minute  (0 = unlimited)
//	KIRO_RATE_LIMIT_BURST_SECONDS burst window in seconds      (default 10)
//
// Per-credential (single-account) concurrency limiting is enforced at the pool
// layer, not here, because the credential is only chosen deep inside the
// request handler.
//
// Ported verbatim from kiro-tutu (zero-dep).
import (
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// tokenBucket is a mutex-guarded token bucket. A rate <= 0 means "unlimited".
type tokenBucket struct {
	mu     sync.Mutex
	rate   float64 // tokens per second
	burst  float64 // maximum tokens held
	tokens float64
	last   time.Time
}

func newTokenBucket(rate, burst float64, now time.Time) *tokenBucket {
	if burst < 1 {
		burst = 1
	}
	return &tokenBucket{rate: rate, burst: burst, tokens: burst, last: now}
}

// allow reports whether a token is available at now. When denied it also returns
// the estimated duration until the next token becomes available.
func (b *tokenBucket) allow(now time.Time) (bool, time.Duration) {
	if b.rate <= 0 {
		return true, 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens += elapsed * b.rate
		if b.tokens > b.burst {
			b.tokens = b.burst
		}
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	wait := (1 - b.tokens) / b.rate
	return false, time.Duration(wait * float64(time.Second))
}

type tokenBucketEntry struct {
	bucket *tokenBucket
	lastAt time.Time
}

// rateLimiter enforces a global bucket plus lazily-created per-key buckets.
type rateLimiter struct {
	globalRate   float64
	perKeyRate   float64
	burstSeconds float64

	global *tokenBucket

	mu     sync.Mutex
	perKey map[string]*tokenBucketEntry
	sweepN int
	nowFn  func() time.Time
}

func bucketBurst(rate, seconds float64) float64 {
	b := rate * seconds
	if b < 1 {
		b = 1
	}
	return b
}

// newRateLimiter builds a limiter from explicit requests-per-minute values.
func newRateLimiter(globalRPM, perKeyRPM, burstSeconds float64) *rateLimiter {
	if burstSeconds <= 0 {
		burstSeconds = 10
	}
	rl := &rateLimiter{
		globalRate:   globalRPM / 60,
		perKeyRate:   perKeyRPM / 60,
		burstSeconds: burstSeconds,
		perKey:       make(map[string]*tokenBucketEntry),
		nowFn:        time.Now,
	}
	if rl.globalRate > 0 {
		rl.global = newTokenBucket(rl.globalRate, bucketBurst(rl.globalRate, burstSeconds), rl.nowFn())
	}
	return rl
}

// newRateLimiterFromEnv reads limits from the KIRO_RATE_LIMIT_* environment.
func newRateLimiterFromEnv() *rateLimiter {
	return newRateLimiter(
		envFloat("KIRO_RATE_LIMIT_RPM", 0),
		envFloat("KIRO_RATE_LIMIT_PER_KEY_RPM", 0),
		envFloat("KIRO_RATE_LIMIT_BURST_SECONDS", 10),
	)
}

func envFloat(name string, def float64) float64 {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f >= 0 {
			return f
		}
	}
	return def
}

func (rl *rateLimiter) enabled() bool {
	return rl != nil && (rl.globalRate > 0 || rl.perKeyRate > 0)
}

func (rl *rateLimiter) bucketFor(key string, now time.Time) *tokenBucket {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.sweepLocked(now)
	e := rl.perKey[key]
	if e == nil {
		e = &tokenBucketEntry{bucket: newTokenBucket(rl.perKeyRate, bucketBurst(rl.perKeyRate, rl.burstSeconds), now)}
		rl.perKey[key] = e
	}
	e.lastAt = now
	return e.bucket
}

// sweepLocked evicts per-key buckets idle for more than 10 minutes. Called under rl.mu.
func (rl *rateLimiter) sweepLocked(now time.Time) {
	rl.sweepN++
	if rl.sweepN < 1024 {
		return
	}
	rl.sweepN = 0
	cutoff := now.Add(-10 * time.Minute)
	for k, e := range rl.perKey {
		if e.lastAt.Before(cutoff) {
			delete(rl.perKey, k)
		}
	}
}

// Allow reports whether a request identified by key may proceed. When denied it
// returns the suggested Retry-After duration. key is typically the API key, or a
// client-IP fallback for unauthenticated paths.
func (rl *rateLimiter) Allow(key string) (bool, time.Duration) {
	if !rl.enabled() {
		return true, 0
	}
	now := rl.nowFn()
	if rl.perKeyRate > 0 && key != "" {
		if ok, retry := rl.bucketFor(key, now).allow(now); !ok {
			return false, retry
		}
	}
	if rl.global != nil {
		if ok, retry := rl.global.allow(now); !ok {
			return false, retry
		}
	}
	return true, 0
}
