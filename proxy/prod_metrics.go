package proxy

// Dependency-free Prometheus metrics exposition (production observability).
//
// Rather than pull in a metrics client library, this exposes a tiny, correct
// subset of the Prometheus text format (v0.0.4). Collection is lock-guarded and
// off the request hot path only by a single map insert + a few atomics, so it
// never blocks the proxied stream. Ported from kiro-tutu. The audit counter
// kiro_audit_dropped_total is incremented by the async audit store
// (persist.go) when its buffer overflows.
import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

var globalMetrics = newProdMetrics()

type prodMetrics struct {
	mu       sync.Mutex
	counters map[string]int64 // fully-rendered series (name or name{labels}) -> value

	hBuckets []float64
	hCounts  []uint64 // cumulative counts aligned with hBuckets
	hSum     float64
	hCount   uint64
}

func newProdMetrics() *prodMetrics {
	buckets := []float64{0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60}
	return &prodMetrics{
		counters: make(map[string]int64),
		hBuckets: buckets,
		hCounts:  make([]uint64, len(buckets)),
	}
}

var counterHelp = map[string]string{
	"kiro_http_requests_total":      "Total HTTP requests handled, labelled by method, code and path class.",
	"kiro_ratelimit_rejected_total": "Total inbound requests rejected by the rate limiter.",
	"kiro_panics_recovered_total":   "Total panics recovered by the recovery middleware.",
	"kiro_audit_dropped_total":      "Audit entries dropped because the async buffer was full.",
	"kiro_token_refresh_total":      "Total OAuth token refresh attempts, by result.",
}

const durationMetric = "kiro_http_request_duration_seconds"

// gaugeSample is one gauge reading emitted at scrape time by gaugeProvider.
type gaugeSample struct {
	name   string
	labels [][2]string
	value  float64
}

// gaugeProvider, when set, supplies dynamic gauges (e.g. pool state) at render time.
var gaugeProvider func() []gaugeSample

var gaugeHelp = map[string]string{
	"kiro_accounts_total":             "Total configured accounts in the pool.",
	"kiro_accounts_available":         "Accounts currently routable (not cooling down).",
	"kiro_account_inflight":           "In-flight dispatches currently assigned to the account.",
	"kiro_credential_quota_remaining": "Remaining usage quota per account (UsageLimit-UsageCurrent).",
}

func escapeLabel(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}

func metricSeries(name string, labels [][2]string) string {
	if len(labels) == 0 {
		return name
	}
	var b strings.Builder
	b.WriteString(name)
	b.WriteByte('{')
	for i, kv := range labels {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(kv[0])
		b.WriteString(`="`)
		b.WriteString(escapeLabel(kv[1]))
		b.WriteByte('"')
	}
	b.WriteByte('}')
	return b.String()
}

func (m *prodMetrics) incCounter(series string) {
	m.mu.Lock()
	m.counters[series]++
	m.mu.Unlock()
}

func (m *prodMetrics) observe(seconds float64) {
	m.mu.Lock()
	m.hCount++
	m.hSum += seconds
	for i, ub := range m.hBuckets {
		if seconds <= ub {
			m.hCounts[i]++
		}
	}
	m.mu.Unlock()
}

// Render returns the current metrics in Prometheus text exposition format.
func (m *prodMetrics) Render() string {
	m.mu.Lock()
	families := make(map[string][]string)
	for series, val := range m.counters {
		name := series
		if i := strings.IndexByte(series, '{'); i >= 0 {
			name = series[:i]
		}
		families[name] = append(families[name], fmt.Sprintf("%s %d", series, val))
	}
	hBuckets := append([]float64(nil), m.hBuckets...)
	hCounts := append([]uint64(nil), m.hCounts...)
	hSum := m.hSum
	hCount := m.hCount
	m.mu.Unlock()

	var b strings.Builder
	names := make([]string, 0, len(families))
	for name := range families {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		help := counterHelp[name]
		if help == "" {
			help = "Counter."
		}
		fmt.Fprintf(&b, "# HELP %s %s\n", name, help)
		fmt.Fprintf(&b, "# TYPE %s counter\n", name)
		lines := families[name]
		sort.Strings(lines)
		for _, l := range lines {
			b.WriteString(l)
			b.WriteByte('\n')
		}
	}

	fmt.Fprintf(&b, "# HELP %s HTTP request duration in seconds.\n", durationMetric)
	fmt.Fprintf(&b, "# TYPE %s histogram\n", durationMetric)
	for i, ub := range hBuckets {
		fmt.Fprintf(&b, "%s_bucket{le=\"%g\"} %d\n", durationMetric, ub, hCounts[i])
	}
	fmt.Fprintf(&b, "%s_bucket{le=\"+Inf\"} %d\n", durationMetric, hCount)
	fmt.Fprintf(&b, "%s_sum %g\n", durationMetric, hSum)
	fmt.Fprintf(&b, "%s_count %d\n", durationMetric, hCount)

	if gaugeProvider != nil {
		gm := make(map[string][]string)
		for _, s := range gaugeProvider() {
			gm[s.name] = append(gm[s.name], fmt.Sprintf("%s %g", metricSeries(s.name, s.labels), s.value))
		}
		gnames := make([]string, 0, len(gm))
		for name := range gm {
			gnames = append(gnames, name)
		}
		sort.Strings(gnames)
		for _, name := range gnames {
			help := gaugeHelp[name]
			if help == "" {
				help = "Gauge."
			}
			fmt.Fprintf(&b, "# HELP %s %s\n", name, help)
			fmt.Fprintf(&b, "# TYPE %s gauge\n", name)
			lines := gm[name]
			sort.Strings(lines)
			for _, l := range lines {
				b.WriteString(l)
				b.WriteByte('\n')
			}
		}
	}

	return b.String()
}

func metricsRequest(method, code, pathClass string) {
	globalMetrics.incCounter(metricSeries("kiro_http_requests_total", [][2]string{
		{"method", method}, {"code", code}, {"path", pathClass},
	}))
}
func metricsRateLimited() { globalMetrics.incCounter("kiro_ratelimit_rejected_total") }
func metricsPanic()       { globalMetrics.incCounter("kiro_panics_recovered_total") }
func metricsAuditDropped() { globalMetrics.incCounter("kiro_audit_dropped_total") }
func metricsTokenRefresh(result string) {
	globalMetrics.incCounter(metricSeries("kiro_token_refresh_total", [][2]string{{"result", result}}))
}

func recordTokenRefreshResult(err error) {
	if err != nil {
		metricsTokenRefresh("error")
		return
	}
	metricsTokenRefresh("success")
}
func metricsDuration(d time.Duration) {
	if d < 0 {
		d = 0
	}
	globalMetrics.observe(d.Seconds())
}
