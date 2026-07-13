package proxy

import (
	"sync"
	"time"

	"kiro-go/config"
	"kiro-go/logger"
)

// claudeCacheDispatchDiagnostics captures one cache dispatch's outcome and
// token usage for aggregation by cacheDispatchMetrics. This is a minimal shape
// of the type kiro-tutu defines in cache_affinity.go (which also carries
// affinity-key / endpoint / request-id fields used for affinity logging). This
// repo deliberately has no cache affinity (global fingerprints + simulated
// cache → session→account stickiness yields no real hit-rate gain), so only the
// fields the metrics consume are retained. The fields kept match what tutu's
// cache_metrics.go reads, so the aggregation logic ports verbatim.
type claudeCacheDispatchDiagnostics struct {
	Outcome        string // "success" | "failure"
	Model          string
	AffinitySource string
	Account        *config.Account
	Usage          promptCacheUsage
	InputTokens    int
	OutputTokens   int
}

// cacheDispatchMetrics 在内存中按时间窗口聚合 [claudeCacheDispatchDiagnostics] 诊断数据，
// 使缓存命中率指标无需开启 info 日志即可审计（见 issue #5）。聚合在诊断汇聚点
// recordClaudeCacheDispatch 中无条件进行，因此与日志级别完全解耦。
//
// 数据按分钟桶保留，Snapshot 时合并落在查询窗口内的桶；过期桶在写入时惰性清理，
// 内存占用上界为 retain 分钟 × (1 + 维度基数) 个计数器。
const (
	cacheMetricsBucketSpan = time.Minute
	// 比最大查询窗口（1h）多保留几分钟，避免边界请求被提前裁剪。
	cacheMetricsRetain = 65 * time.Minute
)

// 缓存命中率安全阀：本网关返回给下游的 cache_read 是本地模拟值，命中率越高下游
// 付费越少、由我方补贴。业务约定聚合命中率上限 ~88%（见 ComputeScoped 的 cap 注释）。
// 三个旋钮（前缀断点 / 1h 本地存活 / 0.99 单请求 cap）叠加后真实聚合可能冲破该线，
// 而 cap 只约束单请求、不强制聚合。这里在聚合侧加观测告警：滚动窗口聚合命中率超阈值
// 时打 WARN，使补贴失控可被发现，而不是只靠注释。仅告警、不改数，不影响计费。
const (
	// cacheHitRatioWarnThreshold 是触发 WARN 的聚合命中率（read/总输入，正确口径）。
	cacheHitRatioWarnThreshold = 0.88
	// cacheHitRatioWarnWindow 是计算聚合命中率的滚动窗口。
	cacheHitRatioWarnWindow = 5 * time.Minute
	// cacheHitRatioWarnInterval 是两次告警的最小间隔，避免高频请求刷屏。
	cacheHitRatioWarnInterval = time.Minute
	// cacheHitRatioWarnMinDispatches 是触发告警所需的最小窗口样本量，避免小样本
	// （首轮/冷启动）噪声造成的偶发高比率误报。
	cacheHitRatioWarnMinDispatches = 50
)

// cacheMetricCounters 是一组可累加的计数器。token 字段累加的是每条 dispatch 的
// 原始值：InputTokens 为输入总量（含 cache read+creation），成功路径才非零。
type cacheMetricCounters struct {
	Dispatches               int64 `json:"dispatches"`
	Success                  int64 `json:"success"`
	Failure                  int64 `json:"failure"`
	CacheReadInputTokens     int64 `json:"cacheReadInputTokens"`
	CacheCreationInputTokens int64 `json:"cacheCreationInputTokens"`
	InputTokens              int64 `json:"inputTokens"`
	OutputTokens             int64 `json:"outputTokens"`
}

func (c *cacheMetricCounters) add(o cacheMetricCounters) {
	c.Dispatches += o.Dispatches
	c.Success += o.Success
	c.Failure += o.Failure
	c.CacheReadInputTokens += o.CacheReadInputTokens
	c.CacheCreationInputTokens += o.CacheCreationInputTokens
	c.InputTokens += o.InputTokens
	c.OutputTokens += o.OutputTokens
}

type cacheMetricBucket struct {
	minute    int64
	total     cacheMetricCounters
	bySource  map[string]*cacheMetricCounters
	byModel   map[string]*cacheMetricCounters
	byAccount map[string]*cacheMetricCounters
}

func newCacheMetricBucket(minute int64) *cacheMetricBucket {
	return &cacheMetricBucket{
		minute:    minute,
		bySource:  make(map[string]*cacheMetricCounters),
		byModel:   make(map[string]*cacheMetricCounters),
		byAccount: make(map[string]*cacheMetricCounters),
	}
}

func addDimension(dim map[string]*cacheMetricCounters, key string, delta cacheMetricCounters) {
	if key == "" {
		key = "unknown"
	}
	counter := dim[key]
	if counter == nil {
		counter = &cacheMetricCounters{}
		dim[key] = counter
	}
	counter.add(delta)
}

type cacheDispatchMetrics struct {
	mu      sync.Mutex
	buckets map[int64]*cacheMetricBucket
	retain  time.Duration
	// lastHitRatioWarn 节流命中率告警，避免高频 dispatch 下刷屏。
	lastHitRatioWarn time.Time
}

func newCacheDispatchMetrics(retain time.Duration) *cacheDispatchMetrics {
	if retain <= 0 {
		retain = cacheMetricsRetain
	}
	return &cacheDispatchMetrics{
		buckets: make(map[int64]*cacheMetricBucket),
		retain:  retain,
	}
}

// Record 累加一条 dispatch 诊断。now 由调用方注入以便测试。
func (m *cacheDispatchMetrics) Record(diag claudeCacheDispatchDiagnostics, now time.Time) {
	minute := now.Unix() / 60
	delta := cacheMetricCounters{
		Dispatches:               1,
		CacheReadInputTokens:     int64(diag.Usage.CacheReadInputTokens),
		CacheCreationInputTokens: int64(diag.Usage.CacheCreationInputTokens),
		InputTokens:              int64(diag.InputTokens),
		OutputTokens:             int64(diag.OutputTokens),
	}
	if diag.Outcome == "success" {
		delta.Success = 1
	} else {
		delta.Failure = 1
	}

	source := diag.AffinitySource
	model := diag.Model
	accountID := ""
	if diag.Account != nil {
		accountID = diag.Account.ID
	}

	m.mu.Lock()
	m.pruneLocked(minute)

	bucket := m.buckets[minute]
	if bucket == nil {
		bucket = newCacheMetricBucket(minute)
		m.buckets[minute] = bucket
	}
	bucket.total.add(delta)
	addDimension(bucket.bySource, source, delta)
	addDimension(bucket.byModel, model, delta)
	addDimension(bucket.byAccount, accountID, delta)

	// 命中率安全阀：在锁内聚合近窗并判定，把日志 I/O 留到释放锁之后，避免持锁做 I/O。
	warn, ratio, dispatches := m.shouldWarnHitRatioLocked(now)
	m.mu.Unlock()

	if warn {
		logger.Warnf(
			"[CacheHitRatioGuard] 聚合缓存命中率 %.1f%% 超过约定上限 %.0f%%（近 %s，样本 %d 条）：下游补贴可能失控，请核对 /v1/stats 与 ComputeScoped cap/TTL 参数",
			ratio*100, cacheHitRatioWarnThreshold*100, cacheHitRatioWarnWindow, dispatches,
		)
	}
}

// shouldWarnHitRatioLocked 在持锁状态下聚合近 cacheHitRatioWarnWindow 窗口，判断
// 聚合命中率是否超阈值且满足节流与最小样本量。命中口径复用 computeCacheMetricRatios
// （read/(read+create+input) 取 max 分母），与 admin 接口一致，规避净输入做分母的
// 假数 bug。返回是否告警、命中率、窗口样本量；返回 true 时已就地更新 lastHitRatioWarn。
func (m *cacheDispatchMetrics) shouldWarnHitRatioLocked(now time.Time) (bool, float64, int64) {
	if now.Sub(m.lastHitRatioWarn) < cacheHitRatioWarnInterval {
		return false, 0, 0
	}
	currentMinute := now.Unix() / 60
	windowMinutes := int64((cacheHitRatioWarnWindow + cacheMetricsBucketSpan - 1) / cacheMetricsBucketSpan)
	cutoff := currentMinute - windowMinutes + 1

	var agg cacheMetricCounters
	for minute, bucket := range m.buckets {
		if minute < cutoff || minute > currentMinute {
			continue
		}
		agg.add(bucket.total)
	}
	if agg.Dispatches < cacheHitRatioWarnMinDispatches {
		return false, 0, 0
	}
	ratio := computeCacheMetricRatios(agg).CacheHitRatio
	if ratio <= cacheHitRatioWarnThreshold {
		return false, 0, 0
	}
	m.lastHitRatioWarn = now
	return true, ratio, agg.Dispatches
}

func (m *cacheDispatchMetrics) pruneLocked(currentMinute int64) {
	cutoff := currentMinute - int64(m.retain/time.Minute)
	for minute := range m.buckets {
		if minute < cutoff {
			delete(m.buckets, minute)
		}
	}
}

// cacheMetricsWindowSnapshot 是单个时间窗口的聚合结果。
type cacheMetricsWindowSnapshot struct {
	WindowSeconds int64                       `json:"windowSeconds"`
	Total         cacheMetricCounters         `json:"total"`
	Ratios        cacheMetricRatios           `json:"ratios"`
	BySource      map[string]cacheMetricGroup `json:"bySource"`
	ByModel       map[string]cacheMetricGroup `json:"byModel"`
	ByAccount     map[string]cacheMetricGroup `json:"byAccount"`
}

// cacheMetricGroup 是某个分组维度下的计数器加该分组自身的命中率。
type cacheMetricGroup struct {
	cacheMetricCounters
	Ratios cacheMetricRatios `json:"ratios"`
}

// cacheMetricRatios 给出多个常用缓存率口径，避免与客户口径对不上。
//   - CacheReadRatio:     cache_read / total_input，真正从缓存读取的输入占比。
//   - CacheHitRatio:      (cache_read + cache_creation) / total_input，广义缓存覆盖占比。
//   - BilledInputTokens:  total_input - cache_read - cache_creation，实际计费的未缓存输入。
//   - SuccessRate:        success / dispatches，分发成功率。
//
// 分母 total_input 取 max(InputTokens, cache_read + cache_creation)：缓存读写的
// token 本身就是输入的一部分，总输入不可能小于它们之和。InputTokens 累加的是上游
// 实报/估算的总输入，与 cache_read/creation（本地 prompt cache 模拟器产出）口径不同，
// 长会话高命中时常出现 InputTokens < cache_read，若直接以 InputTokens 作分母会让
// 比率突破 1（线上实测 cacheHitRatio 达 1.4）。以两者较大值为分母即可保证比率 ∈[0,1]
// 且与 Anthropic 官方口径 read/(read+create+uncached) 一致。分母为 0 时返回 0。
type cacheMetricRatios struct {
	CacheReadRatio    float64 `json:"cacheReadRatio"`
	CacheHitRatio     float64 `json:"cacheHitRatio"`
	BilledInputTokens int64   `json:"billedInputTokens"`
	SuccessRate       float64 `json:"successRate"`
}

func computeCacheMetricRatios(c cacheMetricCounters) cacheMetricRatios {
	ratios := cacheMetricRatios{}
	cached := c.CacheReadInputTokens + c.CacheCreationInputTokens
	totalInput := max(c.InputTokens, cached)
	ratios.BilledInputTokens = totalInput - cached
	if totalInput > 0 {
		ratios.CacheReadRatio = float64(c.CacheReadInputTokens) / float64(totalInput)
		ratios.CacheHitRatio = float64(cached) / float64(totalInput)
	}
	if c.Dispatches > 0 {
		ratios.SuccessRate = float64(c.Success) / float64(c.Dispatches)
	}
	return ratios
}

func dimensionSnapshot(dim map[string]*cacheMetricCounters) map[string]cacheMetricGroup {
	out := make(map[string]cacheMetricGroup, len(dim))
	for key, counter := range dim {
		out[key] = cacheMetricGroup{
			cacheMetricCounters: *counter,
			Ratios:              computeCacheMetricRatios(*counter),
		}
	}
	return out
}

// Snapshot 合并落在 [now-window, now] 内的桶。window 超过 retain 时按 retain 截断。
func (m *cacheDispatchMetrics) Snapshot(window time.Duration, now time.Time) cacheMetricsWindowSnapshot {
	if window <= 0 {
		window = cacheMetricsBucketSpan
	}
	if window > m.retain {
		window = m.retain
	}
	currentMinute := now.Unix() / 60
	// 向上取整覆盖整个窗口：window 内涉及的最早分钟桶。
	windowMinutes := int64((window + cacheMetricsBucketSpan - 1) / cacheMetricsBucketSpan)
	cutoff := currentMinute - windowMinutes + 1

	snapshot := cacheMetricsWindowSnapshot{
		WindowSeconds: int64(window / time.Second),
	}
	merged := newCacheMetricBucket(0)

	m.mu.Lock()
	for minute, bucket := range m.buckets {
		if minute < cutoff || minute > currentMinute {
			continue
		}
		merged.total.add(bucket.total)
		for k, v := range bucket.bySource {
			addDimension(merged.bySource, k, *v)
		}
		for k, v := range bucket.byModel {
			addDimension(merged.byModel, k, *v)
		}
		for k, v := range bucket.byAccount {
			addDimension(merged.byAccount, k, *v)
		}
	}
	m.mu.Unlock()

	snapshot.Total = merged.total
	snapshot.Ratios = computeCacheMetricRatios(merged.total)
	snapshot.BySource = dimensionSnapshot(merged.bySource)
	snapshot.ByModel = dimensionSnapshot(merged.byModel)
	snapshot.ByAccount = dimensionSnapshot(merged.byAccount)
	return snapshot
}

// Reset 清空所有桶，供测试使用。
func (m *cacheDispatchMetrics) Reset() {
	m.mu.Lock()
	m.buckets = make(map[int64]*cacheMetricBucket)
	m.mu.Unlock()
}

// 包级单例：诊断汇聚点为包函数（非 Handler 方法，且被测试直接调用），用单例可零侵入
// 接入而无需改各调用方签名。
var defaultCacheDispatchMetrics = newCacheDispatchMetrics(cacheMetricsRetain)

func recordCacheDispatchMetric(diag claudeCacheDispatchDiagnostics) {
	defaultCacheDispatchMetrics.Record(diag, time.Now())
}

// recordClaudeCacheDispatch 是分发完成处的汇聚钩子，把一次 Claude 分发（成功/失败、
// 流式/非流式）喂给窗口化指标。失败路径 token 全部传 0：调用未真正完成，没有 token
// 被读取/生成，喂入模拟的 cache 值会让命中率虚高。source 用 "stream"/"nonstream"，
// 给运维一个真实维度（流式与非流式的缓存覆盖是否不同）；本仓库无 cache affinity，
// 故不复用 tutu 的 affinity source 分类。
func recordClaudeCacheDispatch(outcome, model, source string, account *config.Account, usage promptCacheUsage, inputTokens, outputTokens int) {
	recordCacheDispatchMetric(claudeCacheDispatchDiagnostics{
		Outcome:        outcome,
		Model:          model,
		AffinitySource: source,
		Account:        account,
		Usage:          usage,
		InputTokens:    inputTokens,
		OutputTokens:   outputTokens,
	})
}

// cacheMetricsWindowDurations 是 /v1/stats 默认输出的窗口口径。
var cacheMetricsWindowDurations = []struct {
	Label    string
	Duration time.Duration
}{
	{"5m", 5 * time.Minute},
	{"15m", 15 * time.Minute},
	{"1h", time.Hour},
}

func cacheMetricsSnapshotByWindows(now time.Time) map[string]cacheMetricsWindowSnapshot {
	out := make(map[string]cacheMetricsWindowSnapshot, len(cacheMetricsWindowDurations))
	for _, w := range cacheMetricsWindowDurations {
		out[w.Label] = defaultCacheDispatchMetrics.Snapshot(w.Duration, now)
	}
	return out
}
