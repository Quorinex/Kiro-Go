package proxy

// Production hardening middleware chain (zero-dependency).
//
// WrapHardening composes, from outermost to innermost:
//
//	recover -> request-id -> /metrics router -> security headers
//	        -> instrument (status + latency + counters + 64 MiB body cap)
//	        -> rate limit -> handler
//
// The chain wraps the existing *Handler without touching its large ServeHTTP,
// preserving all current routing/behaviour. Streaming (SSE) is preserved because
// statusRecorder implements http.Flusher and Unwrap. Rate limiting and metrics
// are opt-in / always-on respectively and add no dependency.
//
// The async JSONL audit store (persist.go) is wired from main and fed by
// instrumentMiddleware; kiro_audit_dropped_total reflects its buffer overflow.
// Deliberately NOT included (needs deps/infrastructure absent from this repo):
// cluster drain.
import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"io"
	"kiro-go/config"
	"kiro-go/logger"
	"net/http"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// maxInboundRequestBytes caps every inbound request body so a hostile/oversized
// upload cannot exhaust memory via io.ReadAll on the API endpoints. 64 MiB is
// well above any real Anthropic/OpenAI request (including base64 images).
const maxInboundRequestBytes = 64 << 20

type ctxKeyRequestID struct{}

func requestIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(ctxKeyRequestID{}).(string)
	return v
}

// statusRecorder captures the response status/size while transparently
// forwarding streaming capabilities used by SSE handlers.
type statusRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
	bytes  int
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.wrote {
		s.status = code
		s.wrote = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if !s.wrote {
		s.status = http.StatusOK
		s.wrote = true
	}
	n, err := s.ResponseWriter.Write(b)
	s.bytes += n
	return n, err
}

// Flush forwards to the underlying writer so SSE streaming keeps working.
func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets http.ResponseController reach the underlying writer (deadlines etc.).
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// WrapHardening wraps inner with the full production middleware chain, reading
// rate limits from the environment.
func WrapHardening(inner http.Handler) http.Handler {
	return wrapHardeningWith(inner, newRateLimiterFromEnv())
}

func wrapHardeningWith(inner http.Handler, rl *rateLimiter) http.Handler {
	h := inner
	h = rateLimitMiddleware(h, rl)
	h = instrumentMiddleware(h)
	h = securityHeadersMiddleware(h)
	h = metricsRouter(h)
	h = requestIDMiddleware(h)
	h = recoverMiddleware(h)
	return h
}

// recoverMiddleware turns an unexpected panic in the handler chain into a clean
// 500 instead of crashing the connection (which leaves an SSE client hanging
// forever). http.ErrAbortHandler is re-panicked to preserve net/http's
// intentional abort semantics.
func recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			rec := recover()
			if rec == nil {
				return
			}
			if rec == http.ErrAbortHandler {
				panic(rec)
			}
			metricsPanic()
			logger.Errorf("[Recover] panic on %s %s (req=%s): %v\n%s",
				r.Method, r.URL.Path, requestIDFromContext(r.Context()), rec, debug.Stack())
			func() {
				defer func() { _ = recover() }() // guard against write-after-headers panics
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = io.WriteString(w, `{"type":"error","error":{"type":"api_error","message":"internal server error"}}`)
			}()
		}()
		next.ServeHTTP(w, r)
	})
}

// requestIDMiddleware propagates an inbound X-Request-Id or mints a fresh UUID,
// echoes it back on the response and carries it through context for log lines.
func requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rid := strings.TrimSpace(r.Header.Get("X-Request-Id"))
		if rid == "" {
			rid = uuid.NewString()
		}
		w.Header().Set("x-request-id", rid)
		ctx := context.WithValue(r.Context(), ctxKeyRequestID{}, rid)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// metricsRouter serves /metrics (Prometheus text exposition) and /debug/audit-log
// without forwarding to the inner handler. Everything else passes through.
func metricsRouter(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/metrics":
			w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
			_, _ = io.WriteString(w, globalMetrics.Render())
			return
		case "/debug/audit-log":
			serveAuditLog(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// adminPasswordOK guards the audit-log endpoint with the admin password
// (header X-Admin-Password or ?password=), compared in constant time so a
// network observer cannot time-attack the password. Empty configured password
// fails closed.
func adminPasswordOK(r *http.Request) bool {
	pw := config.GetPassword()
	if pw == "" {
		return false
	}
	got := r.Header.Get("X-Admin-Password")
	if got == "" {
		got = r.URL.Query().Get("password")
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(pw)) == 1
}

// serveAuditLog exposes recent structured audit entries as JSON for the admin
// UI's error/access-log view. Read-only; requires the admin password.
func serveAuditLog(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if !adminPasswordOK(r) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"type":"error","error":{"type":"authentication_error","message":"admin password required"}}`)
		return
	}
	limit := 100
	if v := strings.TrimSpace(r.URL.Query().Get("limit")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	entries, err := AuditRecent(limit)
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, `{"type":"error","error":{"type":"api_error","message":"audit log unavailable"}}`)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"count": len(entries), "entries": entries})
}

// securityHeadersMiddleware sets baseline browser-security headers (admin panel
// clickjacking / MIME-sniffing protection).
func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

// instrumentMiddleware records request count, latency histogram, and bounds the
// request body to 64 MiB. The body cap means a subsequent io.ReadAll inside a
// handler returns an error when the limit is exceeded, which each handler
// already maps to a 400 — the goal (memory bound) is met without changing
// per-endpoint error handling.
func instrumentMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		if r.Body != nil {
			r.Body = http.MaxBytesReader(rec, r.Body, maxInboundRequestBytes)
		}
		start := time.Now()
		next.ServeHTTP(rec, r)
		lat := time.Since(start)
		metricsDuration(lat)
		metricsRequest(r.Method, strconv.Itoa(rec.status), pathClass(r.URL.Path))
		// Audit: one structured entry per request (request id, SHA-256 of the
		// provided API key, method, path, status, latency, response size). Async
		// + non-blocking (recordAudit drops on a full buffer and counts it). The
		// API key is hashed, never stored, so the audit log is safe to expose via
		// /debug/audit-log to an authenticated admin.
		recordAudit(AuditEntry{
			RequestID:  requestIDFromContext(r.Context()),
			TimeUnixMs: start.UnixMilli(),
			APIKeyHash: hashAPIKey(extractProvidedKey(r)),
			Method:     r.Method,
			Path:       r.URL.Path,
			Status:     rec.status,
			LatencyMs:  lat.Milliseconds(),
			Bytes:      rec.bytes,
		})
	})
}

// rateLimitMiddleware enforces the global + per-key token buckets when the
// limiter is enabled. Health/admin/static paths are exempt so the admin UI and
// liveness checks stay reachable even while API traffic is being throttled.
func rateLimitMiddleware(next http.Handler, rl *rateLimiter) http.Handler {
	if !rl.enabled() {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions || rateLimitExempt(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		key := extractProvidedKey(r)
		if key == "" {
			key = "ip:" + clientIP(r)
		}
		if ok, retry := rl.Allow(key); !ok {
			metricsRateLimited()
			secs := int(retry.Seconds())
			if secs < 1 {
				secs = 1
			}
			h := w.Header()
			h.Set("Access-Control-Allow-Origin", "*")
			h.Set("Retry-After", strconv.Itoa(secs))
			h.Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = io.WriteString(w, `{"type":"error","error":{"type":"rate_limit_error","message":"rate limit exceeded, retry later"}}`)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// rateLimitExempt reports paths that bypass rate limiting: health/metrics
// endpoints, and the admin UI / static assets.
func rateLimitExempt(path string) bool {
	switch {
	case path == "/health" || path == "/" || path == "/metrics" || path == "/favicon.ico":
		return true
	case strings.HasPrefix(path, "/admin"),
		strings.HasPrefix(path, "/web"),
		strings.HasPrefix(path, "/static"):
		return true
	}
	return false
}

// clientIP extracts the client address, preferring the first X-Forwarded-For
// entry (set by proxies) and falling back to r.RemoteAddr.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	host := r.RemoteAddr
	if i := strings.LastIndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	return host
}

// pathClass collapses a request path to a stable cardinality for the
// kiro_http_requests_total{path} label, so the metrics series stay bounded.
func pathClass(p string) string {
	switch {
	case p == "/v1/messages" || p == "/messages" || p == "/anthropic/v1/messages":
		return "/v1/messages"
	case strings.HasSuffix(p, "/count_tokens"):
		return "/v1/messages/count_tokens"
	case p == "/v1/chat/completions" || p == "/chat/completions":
		return "/v1/chat/completions"
	case strings.HasPrefix(p, "/v1/responses"):
		return "/v1/responses"
	case p == "/v1/models" || p == "/models":
		return "/v1/models"
	case p == "/health" || p == "/":
		return "/health"
	case p == "/metrics":
		return "/metrics"
	case strings.HasPrefix(p, "/admin"):
		return "/admin"
	default:
		return "other"
	}
}
