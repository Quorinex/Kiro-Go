package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"kiro-go/auth"
	"kiro-go/config"
	"kiro-go/logger"
	"net/http"
	neturl "net/url"
	"os"
	"strings"
	"time"
)

const (
	kiroRestAPIBase = "https://codewhisperer.us-east-1.amazonaws.com"
)

// kiroRestBaseForAccount returns the CodeWhisperer REST base. The CodeWhisperer
// host only resolves in us-east-1, so this is always us-east-1 (used for endpoints
// without regional Q equivalents: GetUserInfo, ListAvailableModels).
func kiroRestBaseForAccount(account *config.Account) string {
	return kiroRestAPIBase
}

// kiroUsageBaseForAccount returns the Q Developer base for usage/limit queries,
// targeted at the account's profile region. The Q host (q.<region>) has regional
// endpoints (unlike codewhisperer.<region>, which only exists in us-east-1).
func kiroUsageBaseForAccount(account *config.Account) string {
	region := regionForKiroAPI(account, nil)
	return rewriteEndpointRegion(kiroQAPIBase, region)
}

// GetUsageLimits 获取账户使用量和订阅信息
func GetUsageLimits(account *config.Account) (*UsageLimitsResponse, error) {
	url := fmt.Sprintf("%s/getUsageLimits?origin=AI_EDITOR&resourceType=AGENTIC_REQUEST&isEmailRequired=true", kiroUsageBaseForAccount(account))
	url = withProfileArnQuery(url, account)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	setKiroHeaders(req, account)

	resp, err := GetRestClientForProxy(ResolveAccountProxyURL(account)).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	var result UsageLimitsResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetUserInfo 获取用户信息
func GetUserInfo(account *config.Account) (*UserInfoResponse, error) {
	url := fmt.Sprintf("%s/GetUserInfo", kiroRestBaseForAccount(account))

	payload := `{"origin":"KIRO_IDE"}`
	req, err := http.NewRequest("POST", url, strings.NewReader(payload))
	if err != nil {
		return nil, err
	}

	setKiroHeaders(req, account)
	req.Header.Set("Content-Type", "application/json")

	resp, err := GetRestClientForProxy(ResolveAccountProxyURL(account)).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	var result UserInfoResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ListAvailableModels 获取可用模型列表
func ListAvailableModels(account *config.Account) ([]ModelInfo, error) {
	url := fmt.Sprintf("%s/ListAvailableModels?origin=AI_EDITOR&maxResults=50", kiroRestBaseForAccount(account))
	url = withProfileArnQuery(url, account)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	setKiroHeaders(req, account)

	resp, err := GetRestClientForProxy(ResolveAccountProxyURL(account)).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Models []ModelInfo `json:"models"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result.Models, nil
}

// ResolveProfileArn returns the account profile ARN, fetching and caching it
// when it is missing. First tries ListAvailableProfiles (across regions); if that
// returns empty, falls back to refreshing the token (which returns profileArn in
// the response). When multiple profiles are discovered, all are recorded in the
// account's KnownProfileArns so the admin can route across them.
func ResolveProfileArn(account *config.Account) (string, error) {
	if account == nil {
		return "", fmt.Errorf("account is nil")
	}
	if profileArn := strings.TrimSpace(account.ProfileArn); profileArn != "" {
		return profileArn, nil
	}

	// Discover all profiles (across regions, with pagination), retrying transient errors.
	profiles, err := discoverProfilesWithRetry(account)
	if err == nil && len(profiles) > 0 {
		primary := profiles[0]
		if updateErr := config.UpdateAccountProfileArn(account.ID, primary); updateErr != nil {
			logger.Warnf("[ProfileArn] Failed to cache profile ARN for %s: %v", account.Email, updateErr)
		}
		if len(profiles) > 1 {
			// This account exposes multiple Kiro profiles (possibly across regions).
			// The current config model routes a single profile per account, so we
			// use the first and surface the rest for visibility. To route across
			// all of them, add a separate account entry per profileArn.
			logger.Infof("[ProfileArn] %s has %d profiles; using %s. Others: %s",
				account.Email, len(profiles), primary, strings.Join(profiles[1:], ", "))
		}
		account.ProfileArn = primary
		return primary, nil
	}

	// Fallback: refresh token to get profileArn from auth response
	if account.RefreshToken != "" {
		_, _, _, refreshedArn, refreshErr := auth.RefreshToken(account)
		if refreshErr == nil && refreshedArn != "" {
			if updateErr := config.UpdateAccountProfileArn(account.ID, refreshedArn); updateErr != nil {
				logger.Warnf("[ProfileArn] Failed to cache profile ARN for %s: %v", account.Email, updateErr)
			}
			account.ProfileArn = refreshedArn
			return refreshedArn, nil
		}
	}

	return "", fmt.Errorf("no available Kiro profile")
}

// ListAccountProfiles discovers every Kiro profile available to an account across
// all candidate regions. Returns deduplicated ARNs (any region). Public so the
// admin "refresh profiles" flow can enumerate routes.
func ListAccountProfiles(account *config.Account) ([]string, error) {
	return discoverProfilesWithRetry(account)
}

func discoverProfilesWithRetry(account *config.Account) ([]string, error) {
	const maxAttempts = 3
	backoff := 200 * time.Millisecond

	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		profiles, err := discoverProfiles(account)
		if err == nil && len(profiles) > 0 {
			return profiles, nil
		}
		if err == nil {
			return nil, fmt.Errorf("empty profile list")
		}
		lastErr = err
		if !isTransientProfileFetchError(err) || attempt == maxAttempts {
			return nil, err
		}
		logger.Debugf("[ProfileArn] discoverProfiles transient failure for %s (attempt %d/%d): %v",
			account.Email, attempt, maxAttempts, err)
		time.Sleep(backoff)
		backoff *= 2
	}
	return nil, lastErr
}

// isTransientProfileFetchError reports whether a ListAvailableProfiles error
// is worth retrying. Network errors and upstream 5xx/429 are transient; other
// HTTP errors and an empty profile list are not.
func isTransientProfileFetchError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	if strings.Contains(msg, "empty profile list") {
		return false
	}
	if strings.HasPrefix(msg, "HTTP ") {
		return strings.HasPrefix(msg, "HTTP 5") || strings.HasPrefix(msg, "HTTP 429")
	}
	// Non-HTTP errors are network/transport level — retry.
	return true
}

// discoverProfiles enumerates every Kiro profile available to the account across
// all candidate regions, deduplicated. The Q Developer host (q.<region>) returns
// the profiles that live in that region, so we probe each candidate region and
// merge. Pagination (nextToken) is followed per region.
func discoverProfiles(account *config.Account) ([]string, error) {
	candidateRegions := profileSearchRegions(account)

	seen := map[string]bool{}
	var all []string
	var lastErr error
	for _, region := range candidateRegions {
		base := rewriteEndpointRegion(kiroQAPIBase, region)
		arns, err := listProfilesInRegion(account, base)
		if err != nil {
			lastErr = err
			continue
		}
		for _, arn := range arns {
			if arn != "" && !seen[arn] {
				seen[arn] = true
				all = append(all, arn)
			}
		}
	}
	if len(all) > 0 {
		return all, nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("empty profile list")
}

// listProfilesInRegion returns all profile ARNs from one region endpoint,
// following pagination (nextToken). Caps pages to avoid pathological loops.
func listProfilesInRegion(account *config.Account, base string) ([]string, error) {
	const maxPages = 10
	var arns []string
	nextToken := ""

	for page := 0; page < maxPages; page++ {
		body := `{"maxResults":10}`
		if nextToken != "" {
			b, _ := json.Marshal(map[string]interface{}{"maxResults": 10, "nextToken": nextToken})
			body = string(b)
		}
		req, err := http.NewRequest("POST", fmt.Sprintf("%s/ListAvailableProfiles", base), strings.NewReader(body))
		if err != nil {
			return nil, err
		}
		setKiroHeaders(req, account)
		req.Header.Set("Content-Type", "application/json")

		resp, err := GetRestClientForProxy(ResolveAccountProxyURL(account)).Do(req)
		if err != nil {
			return nil, err
		}
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
		}

		var result struct {
			Profiles []struct {
				Arn string `json:"arn"`
			} `json:"profiles"`
			NextToken string `json:"nextToken"`
		}
		if err := json.Unmarshal(respBody, &result); err != nil {
			return nil, err
		}
		for _, p := range result.Profiles {
			if a := strings.TrimSpace(p.Arn); a != "" {
				arns = append(arns, a)
			}
		}
		if strings.TrimSpace(result.NextToken) == "" {
			break
		}
		nextToken = result.NextToken
	}
	return arns, nil
}

// kiroProfileRegions lists every AWS region where Amazon Q Developer / Kiro
// profiles can live. Used to discover an account's profile region when it is not
// yet known. Ordered by likelihood. The q.<region> host must resolve in each.
// Override/extend via env KIRO_PROFILE_REGIONS (comma-separated).
var kiroProfileRegions = func() []string {
	defaults := []string{
		"us-east-1",
		"eu-central-1",
		"us-west-2",
		"ap-southeast-1",
		"ap-southeast-2",
		"ap-northeast-1",
		"eu-west-1",
	}
	extra := strings.TrimSpace(os.Getenv("KIRO_PROFILE_REGIONS"))
	if extra == "" {
		return defaults
	}
	// Env-provided regions take priority (probed first), then defaults.
	seen := map[string]bool{}
	var out []string
	for _, r := range strings.Split(extra, ",") {
		r = strings.TrimSpace(r)
		if r != "" && !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	for _, r := range defaults {
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	return out
}()

// profileSearchRegions returns the ordered list of regions to probe for the
// account's Kiro profile. Account-specific regions (profileArn, account.Region)
// come first, then the full set of known Kiro regions.
func profileSearchRegions(account *config.Account) []string {
	seen := map[string]bool{}
	var out []string
	add := func(r string) {
		r = strings.TrimSpace(r)
		if r != "" && !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	if account != nil {
		// If a profileArn is already set, its region is authoritative.
		if m := profileArnRegionRe.FindStringSubmatch(strings.TrimSpace(account.ProfileArn)); len(m) == 2 {
			add(m[1])
		}
		add(account.Region)
	}
	// All known Kiro/Q Developer regions as fallback.
	for _, r := range kiroProfileRegions {
		add(r)
	}
	return out
}

func withProfileArnQuery(rawURL string, account *config.Account) string {
	if account == nil {
		return rawURL
	}
	profileArn := strings.TrimSpace(account.ProfileArn)
	if profileArn == "" {
		return rawURL
	}
	return rawURL + "&profileArn=" + neturl.QueryEscape(profileArn)
}

func setKiroHeaders(req *http.Request, account *config.Account) {
	host := ""
	if req.URL != nil {
		host = req.URL.Host
	}
	headerValues := buildRuntimeHeaderValues(account, host)

	req.Header.Set("Accept", "application/json")
	applyKiroBaseHeaders(req, account, headerValues)
}

// RefreshAccountInfo 刷新账户信息（使用量、订阅等）
func RefreshAccountInfo(account *config.Account) (*config.AccountInfo, error) {
	info := &config.AccountInfo{
		LastRefresh: time.Now().Unix(),
	}

	// Resolve the profile ARN first. This is region-aware (searches the account
	// region, then us-east-1/eu-central-1) and locks in the profile's home region
	// so the subsequent usage/limit call targets the correct endpoint. Without
	// this, accounts whose Kiro profile lives outside us-east-1 would get a 403
	// and be wrongly flagged as banned.
	if strings.TrimSpace(account.ProfileArn) == "" {
		if profileArn, perr := ResolveProfileArn(account); perr == nil && profileArn != "" {
			account.ProfileArn = profileArn
		} else if perr != nil {
			logger.Debugf("[RefreshAccountInfo] profileArn resolve failed for %s: %v", account.Email, perr)
		}
	}

	// 获取使用量和订阅信息
	usage, err := GetUsageLimits(account)
	if err != nil {
		// 检测封禁状态
		errMsg := err.Error()
		if strings.Contains(errMsg, "TEMPORARILY_SUSPENDED") {
			// 账户被暂时封禁，自动禁用并标记封禁状态
			logger.Warnf("[RefreshAccountInfo] Account %s is temporarily suspended: %v", account.Email, err)

			// 更新账户封禁状态并自动禁用
			updatedAccount := *account
			updatedAccount.Enabled = false
			updatedAccount.BanStatus = "BANNED"
			updatedAccount.BanReason = "AWS temporarily suspended - unusual user activity detected"
			updatedAccount.BanTime = time.Now().Unix()

			// 保存更新后的账户状态
			if updateErr := config.UpdateAccount(account.ID, updatedAccount); updateErr != nil {
				logger.Errorf("[RefreshAccountInfo] Failed to update account ban status: %v", updateErr)
			}

			return nil, fmt.Errorf("Account suspended: %w", err)
		} else if strings.Contains(errMsg, "403") || strings.Contains(errMsg, "401") ||
			strings.Contains(errMsg, "invalid") || strings.Contains(errMsg, "expired") {
			// Token 相关错误，可能需要重新认证
			logger.Warnf("[RefreshAccountInfo] Authentication error for %s: %v", account.Email, err)

			// 更新账户封禁状态为认证失败并自动禁用
			updatedAccount := *account
			updatedAccount.Enabled = false
			updatedAccount.BanStatus = "BANNED"
			updatedAccount.BanReason = "Authentication failed - token invalid or expired"
			updatedAccount.BanTime = time.Now().Unix()

			// 保存更新后的账户状态
			if updateErr := config.UpdateAccount(account.ID, updatedAccount); updateErr != nil {
				logger.Errorf("[RefreshAccountInfo] Failed to update account ban status: %v", updateErr)
			}
		}

		return nil, fmt.Errorf("GetUsageLimits: %w", err)
	}

	// 如果成功获取信息，清除封禁状态（如果之前被标记）
	if account.BanStatus != "" && account.BanStatus != "ACTIVE" {
		logger.Infof("[RefreshAccountInfo] Account %s is now active, clearing ban status", account.Email)

		updatedAccount := *account
		updatedAccount.BanStatus = "ACTIVE"
		updatedAccount.BanReason = ""
		updatedAccount.BanTime = 0

		// 保存更新后的账户状态
		if updateErr := config.UpdateAccount(account.ID, updatedAccount); updateErr != nil {
			logger.Errorf("[RefreshAccountInfo] Failed to clear account ban status: %v", updateErr)
		}
	}

	// 解析用户信息
	if usage.UserInfo != nil {
		info.Email = usage.UserInfo.Email
		info.UserId = usage.UserInfo.UserId
	}

	// 解析订阅信息
	if usage.SubscriptionInfo != nil {
		// 优先从 SubscriptionTitle 或 SubscriptionName 解析类型
		titleOrName := usage.SubscriptionInfo.SubscriptionTitle
		if titleOrName == "" {
			titleOrName = usage.SubscriptionInfo.SubscriptionName
		}
		if titleOrName == "" {
			titleOrName = usage.SubscriptionInfo.SubscriptionType
		}
		info.SubscriptionType = parseSubscriptionType(titleOrName)
		info.SubscriptionTitle = usage.SubscriptionInfo.SubscriptionTitle
		if info.SubscriptionTitle == "" {
			info.SubscriptionTitle = usage.SubscriptionInfo.SubscriptionName
		}
		logger.Debugf("[RefreshAccountInfo] Subscription: type=%s, title=%s, name=%s, parsed=%s",
			usage.SubscriptionInfo.SubscriptionType,
			usage.SubscriptionInfo.SubscriptionTitle,
			usage.SubscriptionInfo.SubscriptionName,
			info.SubscriptionType)
	}

	// 解析使用量
	if len(usage.UsageBreakdownList) > 0 {
		breakdown := usage.UsageBreakdownList[0]
		info.UsageCurrent = breakdown.CurrentUsage
		info.UsageLimit = breakdown.UsageLimit
		if info.UsageLimit > 0 {
			info.UsagePercent = info.UsageCurrent / info.UsageLimit
		}
	}

	// 解析重置日期
	if usage.NextDateReset != "" {
		if ts, err := usage.NextDateReset.Int64(); err == nil && ts > 0 {
			info.NextResetDate = time.Unix(ts, 0).Format("2006-01-02")
		} else if f, err := usage.NextDateReset.Float64(); err == nil && f > 0 {
			info.NextResetDate = time.Unix(int64(f), 0).Format("2006-01-02")
		}
	}

	// 解析试用配额信息
	if len(usage.UsageBreakdownList) > 0 {
		breakdown := usage.UsageBreakdownList[0]
		if breakdown.FreeTrialInfo != nil {
			info.TrialUsageCurrent = breakdown.FreeTrialInfo.CurrentUsage
			info.TrialUsageLimit = breakdown.FreeTrialInfo.UsageLimit
			if info.TrialUsageLimit > 0 {
				info.TrialUsagePercent = info.TrialUsageCurrent / info.TrialUsageLimit
			}
			info.TrialStatus = breakdown.FreeTrialInfo.FreeTrialStatus

			// 解析试用到期时间
			if breakdown.FreeTrialInfo.FreeTrialExpiry != "" {
				if ts, err := breakdown.FreeTrialInfo.FreeTrialExpiry.Int64(); err == nil && ts > 0 {
					info.TrialExpiresAt = ts
				} else if f, err := breakdown.FreeTrialInfo.FreeTrialExpiry.Float64(); err == nil && f > 0 {
					info.TrialExpiresAt = int64(f)
				}
			}
		}
	}

	return info, nil
}

func parseSubscriptionType(raw string) string {
	upper := strings.ToUpper(raw)
	if strings.Contains(upper, "PRO_PLUS") || strings.Contains(upper, "PROPLUS") {
		return "PRO_PLUS"
	}
	if strings.Contains(upper, "POWER") {
		return "POWER"
	}
	if strings.Contains(upper, "PRO") {
		return "PRO"
	}
	return "FREE"
}

// 响应结构体
type UsageLimitsResponse struct {
	UsageBreakdownList []UsageBreakdown  `json:"usageBreakdownList"`
	NextDateReset      json.Number       `json:"nextDateReset"`
	SubscriptionInfo   *SubscriptionInfo `json:"subscriptionInfo"`
	UserInfo           *UserInfo         `json:"userInfo"`
}

type UsageBreakdown struct {
	ResourceType  string         `json:"resourceType"`
	CurrentUsage  float64        `json:"currentUsage"`
	UsageLimit    float64        `json:"usageLimit"`
	Currency      string         `json:"currency"`
	Unit          string         `json:"unit"`
	OverageRate   float64        `json:"overageRate"`
	FreeTrialInfo *FreeTrialInfo `json:"freeTrialInfo"`
	Bonuses       []BonusInfo    `json:"bonuses"`
}

type FreeTrialInfo struct {
	CurrentUsage    float64     `json:"currentUsage"`
	UsageLimit      float64     `json:"usageLimit"`
	FreeTrialStatus string      `json:"freeTrialStatus"`
	FreeTrialExpiry json.Number `json:"freeTrialExpiry"`
}

type BonusInfo struct {
	BonusCode    string      `json:"bonusCode"`
	DisplayName  string      `json:"displayName"`
	CurrentUsage float64     `json:"currentUsage"`
	UsageLimit   float64     `json:"usageLimit"`
	ExpiresAt    json.Number `json:"expiresAt"`
	Status       string      `json:"status"`
}

type SubscriptionInfo struct {
	SubscriptionName  string `json:"subscriptionName"`
	SubscriptionTitle string `json:"subscriptionTitle"`
	SubscriptionType  string `json:"subscriptionType"`
	Status            string `json:"status"`
	UpgradeCapability string `json:"upgradeCapability"`
}

type UserInfo struct {
	Email  string `json:"email"`
	UserId string `json:"userId"`
}

type UserInfoResponse struct {
	Email  string `json:"email"`
	UserId string `json:"userId"`
	Idp    string `json:"idp"`
	Status string `json:"status"`
}

type ModelInfo struct {
	ModelId        string   `json:"modelId"`
	ModelName      string   `json:"modelName"`
	Description    string   `json:"description"`
	InputTypes     []string `json:"supportedInputTypes"`
	RateMultiplier float64  `json:"rateMultiplier"`
	TokenLimits    *struct {
		MaxInputTokens  int `json:"maxInputTokens"`
		MaxOutputTokens int `json:"maxOutputTokens"`
	} `json:"tokenLimits"`
}
