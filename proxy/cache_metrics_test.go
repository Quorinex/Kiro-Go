package proxy

import (
	"testing"
	"time"

	"kiro-go/config"
)

func dispatch(source, model, accountID, outcome string, read, creation, input, output int) claudeCacheDispatchDiagnostics {
	diag := claudeCacheDispatchDiagnostics{
		Outcome:        outcome,
		Model:          model,
		AffinitySource: source,
		Usage: promptCacheUsage{
			CacheReadInputTokens:     read,
			CacheCreationInputTokens: creation,
		},
		InputTokens:  input,
		OutputTokens: output,
	}
	if accountID != "" {
		diag.Account = &config.Account{ID: accountID}
	}
	return diag
}

func TestCacheDispatchMetricsAggregatesTotalsAndRatios(t *testing.T) {
	m := newCacheDispatchMetrics(cacheMetricsRetain)
	now := time.Unix(1_000_000, 0)

	// 两条成功 dispatch，输入总量合计 1000，其中 cache_read 600、creation 200。
	m.Record(dispatch("conversation", "claude-sonnet-4.5", "acct-1", "success", 300, 100, 500, 50), now)
	m.Record(dispatch("conversation", "claude-sonnet-4.5", "acct-1", "success", 300, 100, 500, 50), now)
	// 一条失败 dispatch（失败路径 token 为 0）。
	m.Record(dispatch("conversation", "claude-sonnet-4.5", "acct-1", "failure", 0, 0, 0, 0), now)

	snap := m.Snapshot(5*time.Minute, now)
	if snap.Total.Dispatches != 3 {
		t.Fatalf("dispatches = %d, want 3", snap.Total.Dispatches)
	}
	if snap.Total.Success != 2 || snap.Total.Failure != 1 {
		t.Fatalf("success/failure = %d/%d, want 2/1", snap.Total.Success, snap.Total.Failure)
	}
	if snap.Total.InputTokens != 1000 || snap.Total.CacheReadInputTokens != 600 || snap.Total.CacheCreationInputTokens != 200 {
		t.Fatalf("token totals = in:%d read:%d creation:%d, want 1000/600/200",
			snap.Total.InputTokens, snap.Total.CacheReadInputTokens, snap.Total.CacheCreationInputTokens)
	}
	// cache_read / total_input = 600/1000 = 0.6
	if got := snap.Ratios.CacheReadRatio; got < 0.5999 || got > 0.6001 {
		t.Fatalf("cacheReadRatio = %v, want 0.6", got)
	}
	// (read + creation) / total = 800/1000 = 0.8
	if got := snap.Ratios.CacheHitRatio; got < 0.7999 || got > 0.8001 {
		t.Fatalf("cacheHitRatio = %v, want 0.8", got)
	}
	// billed = 1000 - 600 - 200 = 200
	if snap.Ratios.BilledInputTokens != 200 {
		t.Fatalf("billedInputTokens = %d, want 200", snap.Ratios.BilledInputTokens)
	}
	// success rate = 2/3
	if got := snap.Ratios.SuccessRate; got < 0.6665 || got > 0.6668 {
		t.Fatalf("successRate = %v, want ~0.6667", got)
	}
}

func TestCacheDispatchMetricsGroupsByDimension(t *testing.T) {
	m := newCacheDispatchMetrics(cacheMetricsRetain)
	now := time.Unix(2_000_000, 0)

	m.Record(dispatch("metadata-conversation", "claude-opus", "acct-A", "success", 100, 0, 200, 10), now)
	m.Record(dispatch("cache-prefix", "claude-sonnet-4.5", "acct-B", "success", 50, 0, 100, 5), now)

	snap := m.Snapshot(time.Hour, now)
	if len(snap.BySource) != 2 {
		t.Fatalf("bySource keys = %d, want 2 (%v)", len(snap.BySource), snap.BySource)
	}
	if g, ok := snap.BySource["metadata-conversation"]; !ok || g.InputTokens != 200 {
		t.Fatalf("metadata-conversation group missing or wrong: %+v ok=%v", g, ok)
	}
	if g, ok := snap.ByModel["claude-opus"]; !ok || g.CacheReadInputTokens != 100 {
		t.Fatalf("claude-opus group missing or wrong: %+v ok=%v", g, ok)
	}
	if g, ok := snap.ByAccount["acct-B"]; !ok || g.InputTokens != 100 {
		t.Fatalf("acct-B group missing or wrong: %+v ok=%v", g, ok)
	}
}

func TestCacheDispatchMetricsWindowExcludesOldBuckets(t *testing.T) {
	m := newCacheDispatchMetrics(cacheMetricsRetain)
	now := time.Unix(3_000_000, 0)

	// 10 分钟前的一条记录，落在 5m 窗口外、1h 窗口内。
	m.Record(dispatch("conversation", "m", "a", "success", 10, 0, 20, 1), now.Add(-10*time.Minute))
	// 当前一条记录。
	m.Record(dispatch("conversation", "m", "a", "success", 30, 0, 60, 2), now)

	short := m.Snapshot(5*time.Minute, now)
	if short.Total.Dispatches != 1 || short.Total.InputTokens != 60 {
		t.Fatalf("5m window = dispatches:%d input:%d, want 1/60", short.Total.Dispatches, short.Total.InputTokens)
	}

	long := m.Snapshot(time.Hour, now)
	if long.Total.Dispatches != 2 || long.Total.InputTokens != 80 {
		t.Fatalf("1h window = dispatches:%d input:%d, want 2/80", long.Total.Dispatches, long.Total.InputTokens)
	}
}

func TestCacheDispatchMetricsPrunesBeyondRetain(t *testing.T) {
	m := newCacheDispatchMetrics(cacheMetricsRetain)
	now := time.Unix(4_000_000, 0)

	m.Record(dispatch("conversation", "m", "a", "success", 1, 0, 2, 1), now.Add(-2*time.Hour))
	// 一条新记录触发对超过 retain 的旧桶的惰性清理。
	m.Record(dispatch("conversation", "m", "a", "success", 1, 0, 2, 1), now)

	m.mu.Lock()
	buckets := len(m.buckets)
	m.mu.Unlock()
	if buckets != 1 {
		t.Fatalf("buckets after prune = %d, want 1", buckets)
	}
}

func TestCacheDispatchMetricsReset(t *testing.T) {
	m := newCacheDispatchMetrics(cacheMetricsRetain)
	now := time.Unix(5_000_000, 0)
	m.Record(dispatch("conversation", "m", "a", "success", 1, 0, 2, 1), now)
	m.Reset()
	snap := m.Snapshot(time.Hour, now)
	if snap.Total.Dispatches != 0 {
		t.Fatalf("dispatches after reset = %d, want 0", snap.Total.Dispatches)
	}
}

func TestCacheDispatchMetricsEmptyRatios(t *testing.T) {
	m := newCacheDispatchMetrics(cacheMetricsRetain)
	now := time.Unix(6_000_000, 0)
	snap := m.Snapshot(time.Hour, now)
	if snap.Ratios.CacheReadRatio != 0 || snap.Ratios.CacheHitRatio != 0 || snap.Ratios.SuccessRate != 0 {
		t.Fatalf("empty ratios should be 0, got %+v", snap.Ratios)
	}
	if snap.Ratios.BilledInputTokens != 0 {
		t.Fatalf("empty billed should be 0, got %d", snap.Ratios.BilledInputTokens)
	}
}

// cache_read/creation 来自本地 prompt cache 模拟器，InputTokens 来自上游实报/估算，
// 两者口径不同：长会话高命中时 cache_read 常超过 InputTokens。此时命中率必须仍
// ≤ 1（分母取 max(input, read+creation)），否则面板会出现 >100% 的假命中率。
// 复现线上实测 cacheHitRatio=1.4 的回归。
func TestCacheDispatchMetricsRatiosNeverExceedOneWhenCachedExceedsInput(t *testing.T) {
	m := newCacheDispatchMetrics(cacheMetricsRetain)
	now := time.Unix(7_000_000, 0)

	// read=205000、creation=49000、input(净/估算)=181000 —— read 已超过 input。
	m.Record(dispatch("agent-prefix", "claude-opus-4.6", "acct-1", "success", 205000, 49000, 181000, 100), now)

	snap := m.Snapshot(5*time.Minute, now)
	if r := snap.Ratios.CacheHitRatio; r > 1.0 {
		t.Fatalf("cacheHitRatio = %v, must be <= 1", r)
	}
	if r := snap.Ratios.CacheReadRatio; r > 1.0 {
		t.Fatalf("cacheReadRatio = %v, must be <= 1", r)
	}
	// 分母 = max(181000, 254000) = 254000；hit = 254000/254000 = 1.0；read = 205000/254000 ≈ 0.807。
	if r := snap.Ratios.CacheHitRatio; r < 0.9999 || r > 1.0001 {
		t.Fatalf("cacheHitRatio = %v, want ~1.0", r)
	}
	if r := snap.Ratios.CacheReadRatio; r < 0.8070 || r > 0.8072 {
		t.Fatalf("cacheReadRatio = %v, want ~0.8071", r)
	}
	// billed = 254000 - 254000 = 0（净输入被缓存量覆盖，不可为负）。
	if snap.Ratios.BilledInputTokens != 0 {
		t.Fatalf("billedInputTokens = %d, want 0", snap.Ratios.BilledInputTokens)
	}
}

// TestCacheHitRatioGuardWarnsAboveThreshold 验证命中率安全阀：滚动窗口聚合命中率
// 超过 cacheHitRatioWarnThreshold 且样本量达标时触发告警，并受节流与最小样本量保护。
// 直接测纯判定函数 shouldWarnHitRatioLocked（无日志 I/O），覆盖阈值/样本量/节流三条。
func TestCacheHitRatioGuardWarnsAboveThreshold(t *testing.T) {
	m := newCacheDispatchMetrics(cacheMetricsRetain)
	now := time.Unix(8_000_000, 0)

	// 喂入命中率 ~95% 的高命中样本，数量越过最小样本量门槛。每条 read=950、
	// creation=0、input=50 → 分母 max(50, 950)=950，hit=950/950=1.0（单条），
	// 聚合命中率远超 0.88。
	for i := 0; i < cacheHitRatioWarnMinDispatches+5; i++ {
		m.Record(dispatch("agent-prefix", "claude-opus-4.6", "acct-1", "success", 950, 0, 50, 100), now)
	}

	// 安全阀应已在某条 Record 中触发并更新 lastHitRatioWarn（节流时间戳被设为 now）。
	if m.lastHitRatioWarn.IsZero() {
		t.Fatalf("高命中率 + 足量样本应已触发命中率告警，但 lastHitRatioWarn 未设置")
	}

	// 节流：紧接着同一时刻再判定应被抑制（距上次告警 < cacheHitRatioWarnInterval）。
	m.mu.Lock()
	warnAgain, _, _ := m.shouldWarnHitRatioLocked(now)
	m.mu.Unlock()
	if warnAgain {
		t.Fatalf("节流失效：同一时刻不应重复告警")
	}

	// 过了节流间隔后应能再次告警（命中率仍高）。
	later := now.Add(cacheHitRatioWarnInterval + time.Second)
	m.mu.Lock()
	warnLater, ratioLater, _ := m.shouldWarnHitRatioLocked(later)
	m.mu.Unlock()
	if !warnLater {
		t.Fatalf("过节流间隔后命中率仍高，应再次告警，got ratio=%.3f", ratioLater)
	}
}

// TestCacheHitRatioGuardSilentBelowThresholdAndSmallSample 验证安全阀不误报：
// 命中率低于阈值、或样本量不足时都不告警。
func TestCacheHitRatioGuardSilentBelowThresholdAndSmallSample(t *testing.T) {
	// 场景一：足量样本但命中率低（~40%），不应告警。
	low := newCacheDispatchMetrics(cacheMetricsRetain)
	now := time.Unix(8_100_000, 0)
	for i := 0; i < cacheHitRatioWarnMinDispatches+5; i++ {
		// read=300、creation=0、input=700 → 分母 max(700,300)=700，hit≈0.43，低于 0.88。
		low.Record(dispatch("agent-prefix", "claude-opus-4.6", "acct-1", "success", 300, 0, 700, 100), now)
	}
	if !low.lastHitRatioWarn.IsZero() {
		t.Fatalf("命中率低于阈值不应告警，但 lastHitRatioWarn 被设置")
	}

	// 场景二：命中率高但样本量不足（< 最小样本量），不应告警。
	small := newCacheDispatchMetrics(cacheMetricsRetain)
	now2 := time.Unix(8_200_000, 0)
	for i := 0; i < cacheHitRatioWarnMinDispatches-1; i++ {
		small.Record(dispatch("agent-prefix", "claude-opus-4.6", "acct-1", "success", 950, 0, 50, 100), now2)
	}
	if !small.lastHitRatioWarn.IsZero() {
		t.Fatalf("样本量不足不应告警，但 lastHitRatioWarn 被设置")
	}
}
