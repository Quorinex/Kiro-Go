package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"kiro-go/auth"
	"kiro-go/config"
	"kiro-go/logger"
	"net/http"
	neturl "net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	kiroRestAPIBase               = "https://codewhisperer.us-east-1.amazonaws.com"
	profileArnUnsupportedCooldown = 24 * time.Hour
	maxProfileResponseBytes       = 1 << 20
	maxProfileErrorBytes          = 64 << 10
)

var profileArnResolutionCooldowns sync.Map

var (
	kiroRegionPattern  = regexp.MustCompile(`^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$`)
	kiroAccountPattern = regexp.MustCompile(`^[0-9]{12}$`)
	kiroProfilePattern = regexp.MustCompile(`^[A-Za-z0-9+=,.@_-]+$`)

	// These are the currently known Kiro data-plane regions. Keeping this list
	// explicit avoids turning persisted auth-region input into an arbitrary
	// outbound hostname.
	defaultKiroProfileRegions = []string{"us-east-1", "eu-central-1"}
)

func parseKiroProfileArn(profileArn string) (canonical, region string, ok bool) {
	canonical = strings.TrimSpace(profileArn)
	parts := strings.SplitN(canonical, ":", 6)
	if len(parts) != 6 ||
		parts[0] != "arn" ||
		parts[1] != "aws" ||
		parts[2] != "codewhisperer" ||
		!kiroRegionPattern.MatchString(parts[3]) ||
		!kiroAccountPattern.MatchString(parts[4]) ||
		!strings.HasPrefix(parts[5], "profile/") {
		return "", "", false
	}
	profileID := strings.TrimPrefix(parts[5], "profile/")
	if !kiroProfilePattern.MatchString(profileID) {
		return "", "", false
	}
	return canonical, parts[3], true
}

func regionFromProfileArn(profileArn string) string {
	_, region, ok := parseKiroProfileArn(profileArn)
	if !ok {
		return ""
	}
	return region
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
		// API Key credentials use Region for the CLI runtime data plane.
		// OAuth credentials use Region for authentication only.
		if config.IsAPIKeyAccount(account) {
			if r := strings.TrimSpace(account.Region); r != "" {
				return r
			}
		}
	}
	return "us-east-1"
}

// regionalizeURL points a hardcoded us-east-1 Kiro endpoint at the profile's
// data-plane region. Amazon Q is regional (q.{region}.amazonaws.com), but the CodeWhisperer
// REST host only exists in us-east-1 — non-us-east-1 accounts are served by the
// regional Amazon Q host instead. Both us-east-1 hosts map
// to q.{region}. It is a no-op for us-east-1 profiles.
func regionalizeURL(rawURL string, account *config.Account) string {
	return regionalizeURLForProfile(rawURL, account, "")
}

func regionalizeURLForProfile(rawURL string, account *config.Account, profileArn string) string {
	region := kiroRegionForProfile(account, profileArn)
	return regionalizeURLForRegion(rawURL, region)
}

// regionalizeURLForRegion targets one explicit Kiro data-plane region. The
// caller supplies a validated region candidate; Account.Region is never
// mutated by this operation.
func regionalizeURLForRegion(rawURL, region string) string {
	region = strings.TrimSpace(strings.ToLower(region))
	if region == "us-east-1" {
		return rawURL
	}
	if !kiroRegionPattern.MatchString(region) {
		return rawURL
	}
	regionalHost := "q." + region + ".amazonaws.com"
	return strings.NewReplacer(
		"q.us-east-1.amazonaws.com", regionalHost,
		"codewhisperer.us-east-1.amazonaws.com", regionalHost,
	).Replace(rawURL)
}

func kiroProfileRegionCandidates(account *config.Account) []string {
	seen := make(map[string]struct{})
	candidates := make([]string, 0, len(defaultKiroProfileRegions)+1)
	add := func(region string) {
		region = strings.TrimSpace(strings.ToLower(region))
		if !kiroRegionPattern.MatchString(region) {
			return
		}
		if _, exists := seen[region]; exists {
			return
		}
		seen[region] = struct{}{}
		candidates = append(candidates, region)
	}

	if account != nil {
		// Profile ARN is authoritative. Account.Region is the authentication
		// region and may not host an Amazon Q Developer profile.
		add(regionFromProfileArn(account.ProfileArn))
	}
	for _, region := range defaultKiroProfileRegions {
		add(region)
	}
	return candidates
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
	// Recorded here rather than in each caller: every model-refresh path goes
	// through this function, and a caller that forgot would silently fall back to
	// guessing the context window from the model name.
	recordModelTokenLimits(result.Models)
	return result.Models, nil
}

// ResolveProfileArn returns the account profile ARN, fetching and caching it
// when it is missing. First tries ListAvailableProfiles; if that returns empty,
// falls back to refreshing the token (which returns profileArn in the response).
func ResolveProfileArn(account *config.Account) (string, error) {
	if account == nil {
		return "", fmt.Errorf("account is nil")
	}
	// API Key credentials do not use IDE profile ARNs.
	if config.IsAPIKeyAccount(account) {
		return "", nil
	}
	if profileArn := strings.TrimSpace(account.ProfileArn); profileArn != "" {
		return profileArn, nil
	}

	profileLookupSuppressed := isProfileArnResolutionSuppressed(account)
	var profileUnsupportedErr error
	var profileUnsupported bool

	if !profileLookupSuppressed {
		// external_idp accounts have no authoritative AWS home region, so their
		// candidate data planes are probed without changing Account.Region.
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

	// AWS refresh responses can include profileArn. Microsoft external_idp
	// refresh responses do not, and may rotate refresh_token; invoking refresh
	// here would discard that rotated credential because this resolver only
	// consumes profileArn.
	if account.RefreshToken != "" &&
		!strings.EqualFold(strings.TrimSpace(account.AuthMethod), "external_idp") {
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
	// Headless API keys do not use IDE profile ARNs; REST calls proceed without one.
	if config.IsAPIKeyAccount(account) {
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

func resolveProfileArnAcrossRegions(account *config.Account) (string, error) {
	var probeErrors []error
	for _, region := range kiroProfileRegionCandidates(account) {
		profiles, err := listKiroProfilesWithRetryInRegion(account, region)
		if err != nil {
			if isBuilderIDProfileUnsupportedError(account, err) {
				return "", err
			}
			probeErrors = append(probeErrors, fmt.Errorf("%s: %w", region, err))
			continue
		}
		if len(profiles) != 0 {
			return profiles[0].ARN, nil
		}
	}
	if len(probeErrors) != 0 {
		return "", errors.Join(probeErrors...)
	}
	return "", fmt.Errorf("empty profile list")
}

func listKiroProfilesWithRetryInRegion(account *config.Account, region string) ([]KiroProfile, error) {
	return listKiroProfilesWithRetryInRegionContext(context.Background(), account, region)
}

func listKiroProfilesWithRetryInRegionContext(
	ctx context.Context,
	account *config.Account,
	region string,
) ([]KiroProfile, error) {
	// Retry transient failures (network errors, 5xx, 429) with short backoff.
	// An empty profile list or 4xx (other than 429) is treated as authoritative
	// and not retried — they reflect account state, not upstream flakiness.
	const maxAttempts = 3
	backoff := 200 * time.Millisecond

	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		profiles, err := listKiroProfilesInRegionContext(ctx, account, region)
		if err == nil {
			return profiles, nil
		}
		lastErr = err
		if !isTransientProfileFetchError(err) || attempt == maxAttempts {
			return nil, err
		}
		logger.Debugf("[ProfileArn] ListAvailableProfiles transient failure for %s in %s (attempt %d/%d): %v",
			accountEmailForLog(account), region, attempt, maxAttempts, err)
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return nil, ctx.Err()
		case <-timer.C:
		}
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

// KiroProfile is one selectable Kiro data-plane profile.
type KiroProfile struct {
	ARN    string `json:"arn"`
	Name   string `json:"name"`
	Region string `json:"region"`
}

func listKiroProfilesInRegion(account *config.Account, region string) ([]KiroProfile, error) {
	return listKiroProfilesInRegionContext(context.Background(), account, region)
}

func listKiroProfilesInRegionContext(
	ctx context.Context,
	account *config.Account,
	region string,
) ([]KiroProfile, error) {
	region = strings.TrimSpace(strings.ToLower(region))
	if !kiroRegionPattern.MatchString(region) {
		return nil, fmt.Errorf("invalid Kiro profile region %q", region)
	}
	endpoint := regionalizeURLForRegion(fmt.Sprintf("%s/ListAvailableProfiles", kiroRestAPIBase), region)
	client := GetRestClientForProxy(ResolveAccountProxyURL(account))

	profiles := make([]KiroProfile, 0)
	seen := make(map[string]struct{})
	invalidCount := 0
	nextToken := ""
	// Bound pagination so a misbehaving upstream cannot loop forever. 20 pages
	// of 50 is far above any realistic Kiro profile count.
	const maxProfilePages = 20
	const pageSize = 50
	for page := 0; page < maxProfilePages; page++ {
		requestBody := map[string]interface{}{"maxResults": pageSize}
		if nextToken != "" {
			requestBody["nextToken"] = nextToken
		}
		payload, err := json.Marshal(requestBody)
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(string(payload)))
		if err != nil {
			return nil, err
		}
		setKiroHeaders(req, account)
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, maxProfileErrorBytes))
			resp.Body.Close()
			return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
		}

		responseBody, err := io.ReadAll(io.LimitReader(resp.Body, maxProfileResponseBytes+1))
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		if len(responseBody) > maxProfileResponseBytes {
			return nil, fmt.Errorf("profile response exceeds %d bytes", maxProfileResponseBytes)
		}

		var result struct {
			Profiles []struct {
				ARN  string `json:"arn"`
				Name string `json:"profileName"`
			} `json:"profiles"`
			NextToken string `json:"nextToken"`
		}
		if err := json.Unmarshal(responseBody, &result); err != nil {
			return nil, err
		}

		for _, profile := range result.Profiles {
			profileARN, profileRegion, ok := parseKiroProfileArn(profile.ARN)
			if !ok {
				invalidCount++
				continue
			}
			if _, exists := seen[profileARN]; exists {
				continue
			}
			seen[profileARN] = struct{}{}
			profiles = append(profiles, KiroProfile{
				ARN:    profileARN,
				Name:   strings.TrimSpace(profile.Name),
				Region: profileRegion,
			})
		}

		nextToken = strings.TrimSpace(result.NextToken)
		if nextToken == "" {
			break
		}
		if page == maxProfilePages-1 {
			return nil, fmt.Errorf("profile list exceeded %d pages", maxProfilePages)
		}
	}
	if len(profiles) == 0 && invalidCount != 0 {
		return nil, fmt.Errorf("profile response contained no valid Kiro profile ARN")
	}
	return profiles, nil
}

// DiscoverKiroProfiles returns every strictly validated profile found across
// the account's candidate data-plane regions, de-duplicated by ARN. A failed
// region does not hide profiles found elsewhere; if no region yields a profile,
// all probe failures are returned together.
func DiscoverKiroProfiles(account *config.Account) ([]KiroProfile, error) {
	return DiscoverKiroProfilesContext(context.Background(), account)
}

// DiscoverKiroProfilesContext is the cancelable form used by interactive
// login. Closing the modal can stop outstanding region probes before any
// credential is persisted.
func DiscoverKiroProfilesContext(ctx context.Context, account *config.Account) ([]KiroProfile, error) {
	if account == nil {
		return nil, fmt.Errorf("account is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	profiles := make([]KiroProfile, 0)
	seen := make(map[string]struct{})
	var probeErrors []error
	for _, region := range kiroProfileRegionCandidates(account) {
		discovered, err := listKiroProfilesWithRetryInRegionContext(ctx, account, region)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			probeErrors = append(probeErrors, fmt.Errorf("%s: %w", region, err))
			logger.Warnf("[ProfileArn] Profile discovery failed in %s for %s: %v",
				region, accountEmailForLog(account), err)
			continue
		}
		for _, profile := range discovered {
			if _, exists := seen[profile.ARN]; exists {
				continue
			}
			seen[profile.ARN] = struct{}{}
			profiles = append(profiles, profile)
		}
	}
	if len(profiles) != 0 {
		return profiles, nil
	}
	if len(probeErrors) != 0 {
		return nil, errors.Join(probeErrors...)
	}
	return nil, fmt.Errorf("no available Kiro profile")
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

			if updateErr := config.SetAccountBanStatus(
				account.ID,
				"BANNED",
				"AWS temporarily suspended - unusual user activity detected",
			); updateErr != nil {
				logger.Errorf("[RefreshAccountInfo] Failed to update account ban status: %v", updateErr)
			}

			return nil, fmt.Errorf("Account suspended: %w", err)
		} else if strings.Contains(errMsg, "403") || strings.Contains(errMsg, "401") ||
			strings.Contains(errMsg, "invalid") || strings.Contains(errMsg, "expired") {
			// Token 相关错误，可能需要重新认证
			logger.Warnf("[RefreshAccountInfo] Authentication error for %s: %v", account.Email, err)

			if updateErr := config.SetAccountBanStatus(
				account.ID,
				"BANNED",
				"Authentication failed - token invalid or expired",
			); updateErr != nil {
				logger.Errorf("[RefreshAccountInfo] Failed to update account ban status: %v", updateErr)
			}
		}

		return nil, fmt.Errorf("GetUsageLimits: %w", err)
	}

	// 如果成功获取信息，清除封禁状态（如果之前被标记）
	if account.BanStatus != "" && account.BanStatus != "ACTIVE" {
		logger.Infof("[RefreshAccountInfo] Account %s is now active, clearing ban status", account.Email)

		if updateErr := config.ClearAccountBanStatus(account.ID); updateErr != nil {
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
