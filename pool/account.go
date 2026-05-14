// Package pool 账号池管理
// 实现轮询负载均衡、错误冷却、Token 刷新
package pool

import (
	"kiro-go/config"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const overageFrequencyScale = 10

// AccountPool 账号池
type AccountPool struct {
	mu           sync.RWMutex
	accounts     []config.Account
	totalAccounts int
	currentIndex uint64
	cooldowns    map[string]time.Time // 账号冷却时间
	errorCounts  map[string]int       // 连续错误计数
}

var (
	pool     *AccountPool
	poolOnce sync.Once
)

// GetPool 获取全局账号池单例
func GetPool() *AccountPool {
	poolOnce.Do(func() {
		pool = &AccountPool{
			cooldowns:   make(map[string]time.Time),
			errorCounts: make(map[string]int),
		}
		pool.Reload()
	})
	return pool
}

// Reload 从配置重新加载账号
// 构建加权列表：weight<=1 出现 1 次，weight>=2 出现 weight 次
func (p *AccountPool) Reload() {
	p.mu.Lock()
	defer p.mu.Unlock()
	enabled := config.GetEnabledAccounts()
	var weighted []config.Account
	for _, a := range enabled {
		w := effectiveWeight(a.Weight) * overageFrequencyScale
		if isOverUsageLimit(a) {
			if !a.AllowOverage {
				continue
			}
			w = effectiveOverageWeight(a.OverageWeight)
		}
		for j := 0; j < w; j++ {
			weighted = append(weighted, a)
		}
	}
	p.accounts = weighted
	p.totalAccounts = len(enabled)
}

// GetNext 获取下一个可用账号（加权轮询）
func (p *AccountPool) GetNext() *config.Account {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if len(p.accounts) == 0 {
		return nil
	}

	now := time.Now()
	n := len(p.accounts)
	seen := make(map[string]bool)

	// 加权轮询查找可用账号
	for i := 0; i < n; i++ {
		idx := atomic.AddUint64(&p.currentIndex, 1) % uint64(n)
		acc := &p.accounts[idx]

		if seen[acc.ID] {
			continue
		}

		// 跳过冷却中的账号
		if cooldown, ok := p.cooldowns[acc.ID]; ok && now.Before(cooldown) {
			seen[acc.ID] = true
			continue
		}

		// 跳过即将过期的 Token
		if acc.ExpiresAt > 0 && time.Now().Unix() > acc.ExpiresAt-300 {
			seen[acc.ID] = true
			continue
		}

		// 跳过额度已用尽的账号（适用于所有订阅类型）
		if isOverUsageLimit(*acc) && !acc.AllowOverage {
			seen[acc.ID] = true
			continue
		}

		return acc
	}

	// 无可用账号，返回冷却时间最短的（排除额度用尽的）
	var best *config.Account
	var earliest time.Time
	for i := range p.accounts {
		acc := &p.accounts[i]
		// 额度用尽的账号不作为 fallback
		if isOverUsageLimit(*acc) && !acc.AllowOverage {
			continue
		}
		if cooldown, ok := p.cooldowns[acc.ID]; ok {
			if best == nil || cooldown.Before(earliest) {
				best = acc
				earliest = cooldown
			}
		} else {
			return acc
		}
	}
	return best
}

// GetByID 根据 ID 获取账号
func (p *AccountPool) GetByID(id string) *config.Account {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for i := range p.accounts {
		if p.accounts[i].ID == id {
			return &p.accounts[i]
		}
	}
	return nil
}

// RecordSuccess 记录请求成功，清除冷却
func (p *AccountPool) RecordSuccess(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.cooldowns, id)
	p.errorCounts[id] = 0
}

// RecordError 记录请求错误，设置冷却
func (p *AccountPool) RecordError(id string, isQuotaError bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.errorCounts[id]++

	if isQuotaError {
		// 配额错误，冷却 1 小时
		p.cooldowns[id] = time.Now().Add(time.Hour)
	} else if p.errorCounts[id] >= 3 {
		// 连续 3 次错误，冷却 1 分钟
		p.cooldowns[id] = time.Now().Add(time.Minute)
	}
}

// UpdateToken 更新账号 Token
func (p *AccountPool) UpdateToken(id, accessToken, refreshToken string, expiresAt int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i := range p.accounts {
		if p.accounts[i].ID == id {
			p.accounts[i].AccessToken = accessToken
			if refreshToken != "" {
				p.accounts[i].RefreshToken = refreshToken
			}
			p.accounts[i].ExpiresAt = expiresAt
		}
	}
}

// Count 返回账号总数
func (p *AccountPool) Count() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.totalAccounts > 0 {
		return p.totalAccounts
	}

	seen := make(map[string]bool)
	for _, acc := range p.accounts {
		seen[acc.ID] = true
	}
	return len(seen)
}

// AvailableCount 返回可用账号数
func (p *AccountPool) AvailableCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	now := time.Now()
	count := 0
	seen := make(map[string]bool)
	for _, acc := range p.accounts {
		if seen[acc.ID] {
			continue
		}
		seen[acc.ID] = true
		if cooldown, ok := p.cooldowns[acc.ID]; ok && now.Before(cooldown) {
			continue
		}
		count++
	}
	return count
}

// UpdateStats 更新账号统计
func (p *AccountPool) UpdateStats(id string, tokens int, credits float64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var updated bool
	var requestCount, errorCount, totalTokens int
	var totalCredits float64
	var lastUsed int64
	for i := range p.accounts {
		if p.accounts[i].ID == id {
			if !updated {
				p.accounts[i].RequestCount++
				p.accounts[i].TotalTokens += tokens
				p.accounts[i].TotalCredits += credits
				p.accounts[i].LastUsed = time.Now().Unix()

				requestCount = p.accounts[i].RequestCount
				errorCount = p.accounts[i].ErrorCount
				totalTokens = p.accounts[i].TotalTokens
				totalCredits = p.accounts[i].TotalCredits
				lastUsed = p.accounts[i].LastUsed
				updated = true
				continue
			}
			p.accounts[i].RequestCount = requestCount
			p.accounts[i].ErrorCount = errorCount
			p.accounts[i].TotalTokens = totalTokens
			p.accounts[i].TotalCredits = totalCredits
			p.accounts[i].LastUsed = lastUsed
		}
	}
	if updated {
		go config.UpdateAccountStats(id, requestCount, errorCount, totalTokens, totalCredits, lastUsed)
	}
}

// GetAllAccounts 获取所有账号副本
func (p *AccountPool) GetAllAccounts() []config.Account {
	p.mu.RLock()
	defer p.mu.RUnlock()
	result := make([]config.Account, len(p.accounts))
	copy(result, p.accounts)
	return result
}

func isOverUsageLimit(acc config.Account) bool {
	return acc.UsageLimit > 0 && acc.UsageCurrent >= acc.UsageLimit
}

func effectiveWeight(weight int) int {
	if weight < 1 {
		return 1
	}
	return weight
}

func effectiveOverageWeight(weight int) int {
	if weight < 1 {
		return 1
	}
	if weight > overageFrequencyScale {
		return overageFrequencyScale
	}
	return weight
}

// subscriptionTier returns a numeric tier level for a subscription type.
// Higher tier = more model access.
// FREE=0, PRO=1, PRO_PLUS=2, POWER=3
func subscriptionTier(subType string) int {
	upper := strings.ToUpper(subType)
	if strings.Contains(upper, "POWER") {
		return 3
	}
	if strings.Contains(upper, "PRO_PLUS") || strings.Contains(upper, "PROPLUS") {
		return 2
	}
	if strings.Contains(upper, "PRO") {
		return 1
	}
	return 0
}

// modelRequiredTier returns the minimum subscription tier required for a model.
// Opus models and high-end models require PRO or above.
// FREE tier only supports haiku and sonnet-4 (basic models).
func modelRequiredTier(model string) int {
	lower := strings.ToLower(model)

	// Remove thinking suffix for matching
	lower = strings.TrimSuffix(lower, "-thinking")

	// Opus models require PRO (tier 1)
	if strings.Contains(lower, "opus") {
		return 1
	}

	// Claude 4.7 and above require PRO
	if strings.Contains(lower, "4.7") {
		return 1
	}

	// Sonnet 4.5 and above require PRO
	if strings.Contains(lower, "sonnet-4.5") || strings.Contains(lower, "sonnet-4.6") {
		return 1
	}

	// Basic models (haiku, sonnet-4, gpt-4o, auto) work on FREE
	return 0
}

// accountMatchesModel checks if an account's subscription tier is sufficient for the requested model.
func accountMatchesModel(acc config.Account, model string) bool {
	requiredTier := modelRequiredTier(model)
	if requiredTier == 0 {
		// Basic model, any account works
		return true
	}
	accountTier := subscriptionTier(acc.SubscriptionType)
	return accountTier >= requiredTier
}

// GetNextForModel 获取下一个可用且支持指定模型的账号（加权轮询）
// 如果模型需要高级订阅，只返回满足条件的账号。
// 如果没有满足条件的账号，回退到 GetNext() 行为（尝试所有账号）。
func (p *AccountPool) GetNextForModel(model string) *config.Account {
	requiredTier := modelRequiredTier(model)
	if requiredTier == 0 {
		// Basic model, no filtering needed
		return p.GetNext()
	}

	p.mu.RLock()
	defer p.mu.RUnlock()

	if len(p.accounts) == 0 {
		return nil
	}

	now := time.Now()
	n := len(p.accounts)
	seen := make(map[string]bool)

	// First pass: find accounts that match the model tier
	for i := 0; i < n; i++ {
		idx := atomic.AddUint64(&p.currentIndex, 1) % uint64(n)
		acc := &p.accounts[idx]

		if seen[acc.ID] {
			continue
		}

		// Must match model tier
		if !accountMatchesModel(*acc, model) {
			seen[acc.ID] = true
			continue
		}

		// Skip cooldown accounts
		if cooldown, ok := p.cooldowns[acc.ID]; ok && now.Before(cooldown) {
			seen[acc.ID] = true
			continue
		}

		// Skip expiring tokens
		if acc.ExpiresAt > 0 && time.Now().Unix() > acc.ExpiresAt-300 {
			seen[acc.ID] = true
			continue
		}

		// Skip over-limit accounts
		if isOverUsageLimit(*acc) && !acc.AllowOverage {
			seen[acc.ID] = true
			continue
		}

		return acc
	}

	// Fallback: find the tier-matching account with shortest cooldown
	var best *config.Account
	var earliest time.Time
	seenFallback := make(map[string]bool)
	for i := range p.accounts {
		acc := &p.accounts[i]
		if seenFallback[acc.ID] {
			continue
		}
		seenFallback[acc.ID] = true

		if !accountMatchesModel(*acc, model) {
			continue
		}
		if isOverUsageLimit(*acc) && !acc.AllowOverage {
			continue
		}

		if cooldown, ok := p.cooldowns[acc.ID]; ok {
			if best == nil || cooldown.Before(earliest) {
				best = acc
				earliest = cooldown
			}
		} else {
			return acc
		}
	}

	return best
}
