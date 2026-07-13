package proxy

// Pool-backed Prometheus gauges. Registered as the metrics gaugeProvider so a
// /metrics scrape reflects live pool state: account counts, per-account
// in-flight dispatch load, and remaining credential quota. Collection is
// guarded so a scrape can never panic the metrics endpoint.
//
// Ported from kiro-tutu. kiro_account_inflight is emitted from
// pool.GetRuntimeStatsSnapshot, populated by the health-scoring + inFlight
// dispatch slice.
import "kiro-go/pool"

func init() {
	gaugeProvider = collectPoolGauges
}

func collectPoolGauges() (out []gaugeSample) {
	defer func() {
		if r := recover(); r != nil {
			out = nil
		}
	}()

	p := pool.GetPool()
	out = append(out,
		gaugeSample{name: "kiro_accounts_total", value: float64(p.Count())},
		gaugeSample{name: "kiro_accounts_available", value: float64(p.AvailableCount())},
	)

	// In-flight per account, exposed now that the pool tracks dispatch-level
	// in-flight load (health-scoring slice). A non-zero value means the smart
	// scheduler is actively routing that account.
	for id, s := range p.GetRuntimeStatsSnapshot() {
		out = append(out, gaugeSample{
			name:   "kiro_account_inflight",
			labels: [][2]string{{"account", id}},
			value:  float64(s.InFlight),
		})
	}

	for _, acc := range p.GetAllAccounts() {
		if acc.UsageLimit > 0 {
			out = append(out, gaugeSample{
				name:   "kiro_credential_quota_remaining",
				labels: [][2]string{{"account", acc.ID}},
				value:  acc.UsageLimit - acc.UsageCurrent,
			})
		}
	}
	return out
}
