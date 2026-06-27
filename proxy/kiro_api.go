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
	"sync"
	"time"
)

const (
	kiroRestAPIBase               = "https://codewhisperer.us-east-1.amazonaws.com"
	profileArnUnsupportedCooldown = 24 * time.Hour
)

var profileArnResolutionCooldowns sync.Map

func regionFromProfileArn(profileArn string) string {
	parts := strings.SplitN(strings.TrimSpace(profileArn), ":", 6)
	if len(parts) < 6 || parts[0] != "arn" || parts[2] != "codewhisperer" {
		return ""
	}
	return strings.TrimSpace(parts[3])
}

// kiroRegion returns the AWS data-plane region for Kiro / Q calls.
// Prefer profileArn because account.Region is the auth/OIDC region and can
// differ from the profile's region.
func kiroRegion(account *config.Account) string {
	return kiroRegionForProfile(account, "")
}

func kiroRegionForProfile(account *config.Account, profileArn string) string {
	if r := regionFromProfileArn(profileArn); r != "" {
		return r
	}
	if account != nil {
		if r := regionFromProfileArn(account.ProfileArn); r != "" {
			return r
		}
		if r := strings.TrimSpace(account.Region); r != "" {
			return r
		}
	}
	return "us-east-1"
}

// regionalizeURL points a hardcoded us-east-1 Kiro endpoint at the profile's
// data-plane region (see regionalizeURLForProfile). It is a no-op for us-east-1.
func regionalizeURL(rawURL string, account *config.Account) string {
	return regionalizeURLForProfile(rawURL, account, "")
}

// regionalizeURLForProfile points a hardcoded us-east-1 Kiro endpoint at the
// data-plane region derived from the profile (payload ARN first, then the account's
// cached ARN, then account.Region). account.Region is the auth/OIDC region and can
// differ from the profile's region, so the profile ARN is preferred.
func regionalizeURLForProfile(rawURL string, account *config.Account, profileArn string) string {
	return regionalizeURLForRegion(rawURL, kiroRegionForProfile(account, profileArn))
}

// regionalizeURLForRegion rewrites a hardcoded us-east-1 Kiro endpoint to target
// the given region. Amazon Q is regional (q.{region}.amazonaws.com), but the
// CodeWhisperer REST host only exists in us-east-1 — every other region is served
// by the regional Amazon Q host instead. So for a non-us-east-1 region BOTH
// us-east-1 hosts (q.us-east-1.* and codewhisperer.us-east-1.*) collapse onto
// q.{region}.amazonaws.com; there is deliberately no codewhisperer.{region} host.
// It is a no-op for us-east-1 or an empty region. This region-targeted primitive
// also backs cross-region profile probing (listAvailableProfilesInRegion).
func regionalizeURLForRegion(rawURL, region string) string {
	region = strings.TrimSpace(region)
	if region == "" || region == "us-east-1" {
		return rawURL
	}
	regionalHost := "q." + region + ".amazonaws.com"
	return strings.NewReplacer(
		"q.us-east-1.amazonaws.com", regionalHost,
		"codewhisperer.us-east-1.amazonaws.com", regionalHost,
	).Replace(rawURL)
}

// defaultKiroProfileRegions is the ordered set of regions probed when an account's
// home region is unknown. us-east-1 is the historical default every login falls
// back to; eu-central-1 is where EU-provisioned Azure-tenant profiles
// (e.g. KiroProfile-eu-central-1) live. Override or extend with the
// KIRO_PROFILE_REGIONS env var (comma-separated) to onboard further regions
// without a code change.
var defaultKiroProfileRegions = []string{"us-east-1", "eu-central-1"}

// kiroProfileRegionCandidates returns the ordered, de-duplicated list of regions
// to probe for an account's Kiro profile. The account's currently-configured region
// is always tried first. Cross-region fallbacks are only added when the home region
// is genuinely unknown — an external_idp (Azure-tenant) login, which defaults to
// us-east-1, or an account with no region at all. An idc/social/Builder ID account
// already carries its real region (from the SSO portal / the us-east-1 default), so
// it is probed against that single region exactly as before — no extra upstream calls
// and no chance of its established region being flipped. KIRO_PROFILE_REGIONS, when
// set, replaces the built-in fallback set (the account region is still tried first).
func kiroProfileRegionCandidates(account *config.Account) []string {
	seen := make(map[string]bool)
	var out []string
	add := func(region string) {
		region = strings.TrimSpace(region)
		if region == "" || seen[region] {
			return
		}
		seen[region] = true
		out = append(out, region)
	}

	if account != nil {
		add(account.Region)
	}
	if !shouldProbeFallbackRegions(account) {
		return out
	}
	if env := strings.TrimSpace(os.Getenv("KIRO_PROFILE_REGIONS")); env != "" {
		for _, r := range strings.Split(env, ",") {
			add(r)
		}
		return out
	}
	for _, r := range defaultKiroProfileRegions {
		add(r)
	}
	return out
}

// shouldProbeFallbackRegions reports whether an account's home region is unknown
// enough to justify probing fallback regions. Only external_idp accounts (region
// defaulted to us-east-1 at login) and accounts with no region set qualify; every
// other auth method already carries its authoritative region.
func shouldProbeFallbackRegions(account *config.Account) bool {
	if account == nil {
		return true
	}
	if strings.TrimSpace(account.Region) == "" {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(account.AuthMethod), "external_idp")
}

// GetUsageLimits 获取账户使用量和订阅信息
func GetUsageLimits(account *config.Account) (*UsageLimitsResponse, error) {
	if err := ensureRestProfileArn(account); err != nil {
		return nil, fmt.Errorf("resolve profileArn: %w", err)
	}

	url := fmt.Sprintf("%s/getUsageLimits?origin=AI_EDITOR&resourceType=AGENTIC_REQUEST&isEmailRequired=true", kiroRestAPIBase)
	url = regionalizeURL(url, account)
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
	url := regionalizeURL(fmt.Sprintf("%s/GetUserInfo", kiroRestAPIBase), account)

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
	if err := ensureRestProfileArn(account); err != nil {
		return nil, fmt.Errorf("resolve profileArn: %w", err)
	}

	url := fmt.Sprintf("%s/ListAvailableModels?origin=AI_EDITOR&maxResults=50", kiroRestAPIBase)
	url = regionalizeURL(url, account)
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
// when it is missing. First tries ListAvailableProfiles; if that returns empty,
// falls back to refreshing the token (which returns profileArn in the response).
func ResolveProfileArn(account *config.Account) (string, error) {
	if account == nil {
		return "", fmt.Errorf("account is nil")
	}
	if profileArn := strings.TrimSpace(account.ProfileArn); profileArn != "" {
		return profileArn, nil
	}

	profileLookupSuppressed := isProfileArnResolutionSuppressed(account)
	var profileUnsupportedErr error
	var profileUnsupported bool

	if !profileLookupSuppressed {
		// Probe ListAvailableProfiles across candidate regions, retrying transient
		// failures. The home region is unknown at login for Azure-tenant
		// (external_idp) accounts (they default to us-east-1), so the probe is what
		// discovers a profile that lives outside the account's configured region. The
		// cached ARN then drives the data-plane region via kiroRegionForProfile — no
		// separate region persistence is needed (and account.Region stays the auth
		// region, which can legitimately differ from the profile's region).
		profileArn, err := resolveProfileArnAcrossRegions(account)
		if err == nil && profileArn != "" {
			if updateErr := config.UpdateAccountProfileArn(account.ID, profileArn); updateErr != nil {
				logger.Warnf("[ProfileArn] Failed to cache profile ARN for %s: %v", account.Email, updateErr)
			}
			account.ProfileArn = profileArn
			return profileArn, nil
		}
		profileUnsupportedErr = err
		profileUnsupported = isBuilderIDProfileUnsupportedError(account, err)
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
	if profileLookupSuppressed {
		return "", fmt.Errorf("profile ARN resolution skipped: previous Builder ID profile lookup was unsupported")
	}
	if profileUnsupported {
		suppressProfileArnResolution(account)
		logger.Debugf("[ProfileArn] Builder ID profile lookup unsupported for %s: %v", accountEmailForLog(account), profileUnsupportedErr)
		return "", fmt.Errorf("profile ARN unsupported for Builder ID account")
	}

	return "", fmt.Errorf("no available Kiro profile")
}

func isBuilderIDProfileUnsupportedError(account *config.Account, err error) bool {
	if account == nil || err == nil {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(account.Provider), "BuilderId") {
		return false
	}
	msg := err.Error()
	return strings.HasPrefix(msg, "HTTP 403") && strings.Contains(msg, "AWS Builder ID is not supported for this operation")
}

func profileArnCooldownKey(account *config.Account) string {
	if account == nil {
		return ""
	}
	provider := strings.TrimSpace(account.Provider)
	if id := strings.TrimSpace(account.ID); id != "" {
		return provider + "\x00" + id
	}
	if userID := strings.TrimSpace(account.UserId); userID != "" {
		return provider + "\x00" + userID
	}
	return provider + "\x00" + strings.TrimSpace(account.Email)
}

func suppressProfileArnResolution(account *config.Account) {
	key := profileArnCooldownKey(account)
	if key == "" {
		return
	}
	profileArnResolutionCooldowns.Store(key, time.Now().Add(profileArnUnsupportedCooldown))
}

func isProfileArnResolutionSuppressed(account *config.Account) bool {
	key := profileArnCooldownKey(account)
	if key == "" {
		return false
	}
	value, ok := profileArnResolutionCooldowns.Load(key)
	if !ok {
		return false
	}
	until, ok := value.(time.Time)
	if !ok || time.Now().After(until) {
		profileArnResolutionCooldowns.Delete(key)
		return false
	}
	return true
}

func isProfileArnResolutionSkippedError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "profile ARN resolution skipped")
}

func isProfileArnResolutionUnsupportedError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "profile ARN unsupported for Builder ID account")
}

func isProfileArnResolutionSoftError(err error) bool {
	return isProfileArnResolutionSkippedError(err) || isProfileArnResolutionUnsupportedError(err)
}

func ensureRestProfileArn(account *config.Account) error {
	if account == nil || strings.TrimSpace(account.ProfileArn) != "" {
		return nil
	}
	profileArn, err := ResolveProfileArn(account)
	if err != nil {
		if isProfileArnResolutionSoftError(err) {
			logger.Debugf("[ProfileArn] Continuing REST request without profile ARN for %s: %v", accountEmailForLog(account), err)
			return nil
		}
		return err
	}
	account.ProfileArn = profileArn
	return nil
}

// resolveProfileArnAcrossRegions probes ListAvailableProfiles against each
// candidate region (the account's configured region first, then the fallbacks) and
// returns the first profile ARN found. This is what lets an account whose profile
// lives outside its configured region — every Azure-tenant (external_idp) login
// defaults to us-east-1 — discover that profile (e.g. in eu-central-1) on first use.
// The returned ARN carries its own region, which kiroRegionForProfile then uses for
// data-plane calls. A correctly-regioned account resolves on the first probe. A
// Builder ID "unsupported" 403 is authoritative across all regions, so it
// short-circuits the probe rather than repeating per region.
func resolveProfileArnAcrossRegions(account *config.Account) (string, error) {
	var lastErr error
	for _, region := range kiroProfileRegionCandidates(account) {
		arn, probeErr := listAvailableProfilesWithRetryInRegion(account, region)
		if probeErr == nil && strings.TrimSpace(arn) != "" {
			return arn, nil
		}
		if probeErr != nil {
			lastErr = probeErr
			if isBuilderIDProfileUnsupportedError(account, probeErr) {
				return "", probeErr
			}
		}
	}
	return "", lastErr
}

// listAvailableProfilesWithRetryInRegion calls ListAvailableProfiles against a
// specific region, retrying transient failures (network errors, 5xx, 429) with
// short backoff. An empty profile list or 4xx (other than 429) is treated as
// authoritative and not retried — they reflect account state, not upstream flakiness.
func listAvailableProfilesWithRetryInRegion(account *config.Account, region string) (string, error) {
	const maxAttempts = 3
	backoff := 200 * time.Millisecond

	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		profileArn, err := listAvailableProfilesInRegion(account, region)
		if err == nil {
			return profileArn, nil
		}
		lastErr = err
		if !isTransientProfileFetchError(err) || attempt == maxAttempts {
			return "", err
		}
		logger.Debugf("[ProfileArn] ListAvailableProfiles transient failure for %s in %s (attempt %d/%d): %v",
			account.Email, region, attempt, maxAttempts, err)
		time.Sleep(backoff)
		backoff *= 2
	}
	return "", lastErr
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

// listAvailableProfilesInRegion calls ListAvailableProfiles with the request host
// pointed at a specific region (q.{region} for non-us-east-1, the CodeWhisperer
// REST host for us-east-1). Targeting an explicit region — rather than the account's
// stored one — is what makes cross-region detection possible: the same credential is
// probed against each candidate region until one returns a profile.
func listAvailableProfilesInRegion(account *config.Account, region string) (string, error) {
	endpoint := regionalizeURLForRegion(fmt.Sprintf("%s/ListAvailableProfiles", kiroRestAPIBase), region)
	req, err := http.NewRequest("POST", endpoint, strings.NewReader(`{"maxResults":10}`))
	if err != nil {
		return "", err
	}
	setKiroHeaders(req, account)
	req.Header.Set("Content-Type", "application/json")

	resp, err := GetRestClientForProxy(ResolveAccountProxyURL(account)).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Profiles []struct {
			Arn string `json:"arn"`
		} `json:"profiles"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	for _, profile := range result.Profiles {
		if profileArn := strings.TrimSpace(profile.Arn); profileArn != "" {
			return profileArn, nil
		}
	}
	return "", fmt.Errorf("empty profile list")
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
