package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"kiro-go/config"
	"kiro-go/logger"
	"net/http"
	neturl "net/url"
	"strings"
	"time"
)

// kiroQAPIBase is the AWS Q Developer endpoint that owns the user-level Overages
// switch. Distinct from kiroRestAPIBase (CodeWhisperer) which is used elsewhere.
const kiroQAPIBase = "https://q.us-east-1.amazonaws.com"

// OverageSnapshot captures the upstream Overages state for an account.
type OverageSnapshot struct {
	Status            string  `json:"status"`            // "ENABLED" | "DISABLED" | "UNKNOWN"
	Capability        string  `json:"capability"`        // "OVERAGE_CAPABLE" | ...
	SubscriptionTitle string  `json:"subscriptionTitle"` // e.g. "KIRO PRO+"
	OverageCap        float64 `json:"overageCap"`        // USD upper bound
	OverageRate       float64 `json:"overageRate"`       // per-invocation USD
	CurrentOverages   float64 `json:"currentOverages"`   // accumulated overage USD
	CheckedAt         int64   `json:"checkedAt"`         // Unix seconds
}

// upstreamOverageResponse mirrors the parts of /getUsageLimits we need for
// the Overages switch UI. Other fields are already parsed elsewhere.
type upstreamOverageResponse struct {
	OverageConfiguration *struct {
		OverageStatus string `json:"overageStatus"`
	} `json:"overageConfiguration"`
	SubscriptionInfo *struct {
		OverageCapability string `json:"overageCapability"`
		SubscriptionTitle string `json:"subscriptionTitle"`
	} `json:"subscriptionInfo"`
	UsageBreakdownList []struct {
		ResourceType    string  `json:"resourceType"`
		OverageCap      float64 `json:"overageCap"`
		OverageRate     float64 `json:"overageRate"`
		CurrentOverages float64 `json:"currentOverages"`
	} `json:"usageBreakdownList"`
}

// FetchOverageStatus calls AWS Q `GET /getUsageLimits` and extracts the
// Overages switch state plus subscription metadata.
func FetchOverageStatus(account *config.Account) (*OverageSnapshot, error) {
	if account == nil {
		return nil, fmt.Errorf("account is nil")
	}

	rawURL := regionalizeURL(kiroQAPIBase+"/getUsageLimits?origin=AI_EDITOR&resourceType=AGENTIC_REQUEST&isEmailRequired=true", account)
	if profileArn := strings.TrimSpace(account.ProfileArn); profileArn != "" {
		rawURL += "&profileArn=" + neturl.QueryEscape(profileArn)
	}

	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return nil, err
	}
	setKiroHeaders(req, account)

	resp, err := GetRestClientForProxy(ResolveAccountProxyURL(account)).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	var parsed upstreamOverageResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("decode getUsageLimits: %w", err)
	}

	snap := &OverageSnapshot{
		Status:    "UNKNOWN",
		CheckedAt: time.Now().Unix(),
	}
	if parsed.OverageConfiguration != nil && parsed.OverageConfiguration.OverageStatus != "" {
		snap.Status = strings.ToUpper(parsed.OverageConfiguration.OverageStatus)
	}
	if parsed.SubscriptionInfo != nil {
		snap.Capability = parsed.SubscriptionInfo.OverageCapability
		snap.SubscriptionTitle = parsed.SubscriptionInfo.SubscriptionTitle
	}
	for _, bd := range parsed.UsageBreakdownList {
		if bd.OverageCap > 0 || bd.OverageRate > 0 || bd.CurrentOverages > 0 {
			snap.OverageCap = bd.OverageCap
			snap.OverageRate = bd.OverageRate
			snap.CurrentOverages = bd.CurrentOverages
			break
		}
	}
	return snap, nil
}

// SetOverageStatus calls AWS Q `POST /setUserPreference` to flip the user-level
// Overages switch, then re-fetches the snapshot for cache write-through.
//
// `enabled=true`  → overageStatus="ENABLED"
// `enabled=false` → overageStatus="DISABLED"
func SetOverageStatus(account *config.Account, enabled bool) (*OverageSnapshot, error) {
	if account == nil {
		return nil, fmt.Errorf("account is nil")
	}

	profileArn, err := ResolveProfileArn(account)
	if err != nil {
		return nil, fmt.Errorf("resolve profileArn: %w", err)
	}

	status := "DISABLED"
	if enabled {
		status = "ENABLED"
	}
	payload := map[string]interface{}{
		"overageConfiguration": map[string]string{
			"overageStatus": status,
		},
		"profileArn": profileArn,
	}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequest("POST", regionalizeURL(kiroQAPIBase+"/setUserPreference", account), bytes.NewReader(body))
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

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("setUserPreference HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	logger.Infof("[Overage] account=%s flipped overageStatus=%s upstream", account.Email, status)

	// Best-effort re-read so cached fields (cap/rate/current) stay accurate.
	snap, fetchErr := FetchOverageStatus(account)
	if fetchErr != nil {
		// Still return a synthesized snapshot — the POST succeeded.
		logger.Warnf("[Overage] re-fetch after switch failed for %s: %v", account.Email, fetchErr)
		return &OverageSnapshot{
			Status:    status,
			CheckedAt: time.Now().Unix(),
		}, nil
	}
	// In rare cases AWS lags, force the just-set value.
	snap.Status = status
	return snap, nil
}

// PersistOverageSnapshot writes a snapshot back to config.json for an account.
// Returns the persist error if any (caller decides whether to surface it).
func PersistOverageSnapshot(accountID string, snap *OverageSnapshot) error {
	if snap == nil {
		return nil
	}
	return config.UpdateAccountOverageStatus(
		accountID,
		snap.Status,
		snap.Capability,
		snap.OverageCap,
		snap.OverageRate,
		snap.CurrentOverages,
		snap.CheckedAt,
	)
}
