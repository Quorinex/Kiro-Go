// Package config provides configuration management for Kiro API Proxy.
//
// This package handles persistent storage and retrieval of:
//   - Account credentials and authentication tokens
//   - Server settings (port, host, API keys)
//   - Usage statistics and metrics
//   - Thinking mode configuration for AI responses
//
// All configuration is stored in a JSON file with thread-safe access
// via read-write mutex protection.
package config

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// GenerateMachineId generates a UUID v4 format machine identifier.
// This ID is used to uniquely identify the proxy instance in Kiro API requests,
// helping with request tracking and rate limiting on the server side.
func GenerateMachineId() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	bytes[6] = (bytes[6] & 0x0f) | 0x40 // 版本 4
	bytes[8] = (bytes[8] & 0x3f) | 0x80 // 变体
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		bytes[0:4], bytes[4:6], bytes[6:8], bytes[8:10], bytes[10:16])
}

// DeriveMachineId deterministically derives a stable 64-hex device id from an
// account ID via sha256("kiro-device-" + accountID). It is a pure function:
// the same account ID always yields the same value, so an account looks like a
// single fixed device across requests and across restarts. Ported from
// kiro-tutu (zero-dep: stdlib crypto/sha256 + encoding/hex).
//
// Used as the empty-MachineId fallback in kiro_headers.go so every account's
// User-Agent always carries a unique, stable device suffix instead of all
// empty-id accounts sharing an identical UA (the strongest cross-account
// association signal upstream can correlate on).
func DeriveMachineId(accountID string) string {
	sum := sha256.Sum256([]byte("kiro-device-" + accountID))
	return hex.EncodeToString(sum[:])
}

// clientProfile is one entry in the desktop fingerprint pool: a real
// {OS#kernel, KiroIDE version, node version} triple that a genuine Kiro IDE
// install would report. Every value here MUST be a combination that actually
// shipped — fabricating version numbers would create a fresh "non-genuine
// client" signal, which is exactly what we are trying to avoid. Ported from
// kiro-tutu (zero-dep).
type clientProfile struct {
	systemVersion string
	kiroVersion   string
	nodeVersion   string
	weight        int
}

// clientProfilePool is the weighted distribution of desktop fingerprints used
// to derive a per-account {platform, version} triple.
//
// Design constraints:
//   - macOS-weighted, with a small Windows minority, matching the real account
//     source distribution. A wrong distribution manufactures a new
//     "unrealistic population" signal.
//   - NEVER contains Linux. A Linux server kernel in a Kiro IDE UA is the
//     single strongest "not a real user" tell; this pool guarantees the output
//     platform is always mac/win regardless of runtime.GOOS — so a deploy on a
//     Linux box no longer advertises linux#6.6.87 in every request's UA.
//   - Every systemVersion is a verified real macOS↔Darwin / Windows build:
//     darwin#23.6.0 = macOS 14.6 (Sonoma), darwin#24.5.0 = macOS 15.5,
//     darwin#24.6.0 = macOS 15.6 (Sequoia); win32#10.0.22631 = Win11 23H2,
//     win32#10.0.19045 = Win10 22H2.
//   - KiroVersion/NodeVersion stay on the one combination confirmed against a
//     genuine client (0.11.107 / 22.22.0). Version uniformity is expected
//     (real users auto-update), so only the platform dimension is diversified.
var clientProfilePool = []clientProfile{
	{systemVersion: "darwin#24.6.0", kiroVersion: "0.11.107", nodeVersion: "22.22.0", weight: 35},    // macOS 15.6 Sequoia
	{systemVersion: "darwin#24.5.0", kiroVersion: "0.11.107", nodeVersion: "22.22.0", weight: 25},    // macOS 15.5 Sequoia
	{systemVersion: "darwin#23.6.0", kiroVersion: "0.11.107", nodeVersion: "22.22.0", weight: 25},    // macOS 14.6 Sonoma
	{systemVersion: "win32#10.0.22631", kiroVersion: "0.11.107", nodeVersion: "22.22.0", weight: 10}, // Win11 23H2
	{systemVersion: "win32#10.0.19045", kiroVersion: "0.11.107", nodeVersion: "22.22.0", weight: 5},  // Win10 22H2
}

// DeriveClientProfile deterministically derives a stable desktop fingerprint
// for an account by hashing sha256("kiro-profile-" + accountID) and selecting
// from clientProfilePool by cumulative weight. It is a pure function: the same
// account ID always yields the same {platform, version} triple, across
// requests and across restarts, so an account looks like a single fixed
// desktop install — and it never returns a Linux platform regardless of the
// host OS.
//
// The "kiro-profile-" prefix differs from DeriveMachineId's "kiro-device-" so
// the platform selection is independent of the device-id hash, while both
// remain stably bound to the same account.
func DeriveClientProfile(accountID string) clientProfile {
	totalWeight := 0
	for _, p := range clientProfilePool {
		totalWeight += p.weight
	}
	if totalWeight <= 0 || len(clientProfilePool) == 0 {
		// Defensive: a misconfigured pool must still never emit Linux. Fall back
		// to the first verified mac entry rather than runtime.GOOS.
		return clientProfile{systemVersion: "darwin#24.6.0", kiroVersion: "0.11.107", nodeVersion: "22.22.0"}
	}

	sum := sha256.Sum256([]byte("kiro-profile-" + accountID))
	// Use the first 8 bytes as an unsigned 64-bit selector, then mod by total
	// weight. Deterministic and uniform enough for distribution purposes.
	var selector uint64
	for i := 0; i < 8; i++ {
		selector = selector<<8 | uint64(sum[i])
	}
	target := int(selector % uint64(totalWeight))

	cumulative := 0
	for _, p := range clientProfilePool {
		cumulative += p.weight
		if target < cumulative {
			return p
		}
	}
	return clientProfilePool[len(clientProfilePool)-1] // unreachable, defensive
}

// Account represents a Kiro API account with authentication credentials and usage statistics.
type Account struct {
	// Basic identification
	ID       string `json:"id"`                 // Unique account identifier (UUID)
	Email    string `json:"email,omitempty"`    // User email address
	UserId   string `json:"userId,omitempty"`   // Kiro user ID
	Nickname string `json:"nickname,omitempty"` // Display name for admin panel

	// Authentication credentials
	AccessToken  string `json:"accessToken"`            // OAuth access token for API calls
	RefreshToken string `json:"refreshToken"`           // OAuth refresh token for token renewal
	ClientID     string `json:"clientId,omitempty"`     // OIDC client ID (for IdC auth)
	ClientSecret string `json:"clientSecret,omitempty"` // OIDC client secret (for IdC auth)
	AuthMethod   string `json:"authMethod"`             // Authentication method: "idc" (AWS IdC), "social" (GitHub/Google), "external_idp" (enterprise SSO, e.g. Azure AD), or "api_key" (Kiro API key used directly as bearer)
	KiroApiKey   string `json:"kiroApiKey,omitempty"`   // API key credential, used directly as the bearer token when AuthMethod == "api_key"
	AuthRegion   string `json:"authRegion,omitempty"`   // Region for token-refresh endpoints; falls back to Region
	ApiRegion    string `json:"apiRegion,omitempty"`    // Region for API request hosts; falls back to Region
	Provider     string `json:"provider,omitempty"`     // Identity provider name (e.g., "BuilderId", "GitHub", "AzureAD")
	Region       string `json:"region"`                 // AWS region for OIDC endpoints
	StartUrl     string `json:"startUrl,omitempty"`     // AWS SSO start URL
	ExpiresAt    int64  `json:"expiresAt,omitempty"`    // Token expiration timestamp (Unix seconds)
	MachineId    string `json:"machineId,omitempty"`    // UUID machine identifier for request tracking
	ProfileArn   string `json:"profileArn,omitempty"`   // CodeWhisperer/Kiro profile ARN for generation requests

	// External IdP (enterprise SSO, e.g. Microsoft 365 / Entra ID / Azure AD) refresh material.
	// When AuthMethod == "external_idp" the credential is an IdP-issued OAuth token refreshed
	// against TokenEndpoint using ClientID and Scopes (refresh_token grant), NOT the AWS SSO
	// OIDC endpoint. IssuerURL is the OIDC issuer the endpoints were discovered from.
	TokenEndpoint string `json:"tokenEndpoint,omitempty"` // External IdP OAuth2 token endpoint (refresh)
	IssuerURL     string `json:"issuerUrl,omitempty"`     // External IdP OIDC issuer URL
	Scopes        string `json:"scopes,omitempty"`        // Space-separated scopes granted by the external IdP

	// Per-account outbound proxy (falls back to global ProxyURL if empty)
	ProxyURL string `json:"proxyURL,omitempty"`

	// Priority weight for load balancing (higher = more requests)
	Weight int `json:"weight,omitempty"` // 0 or 1 = normal, 2+ = higher priority

	// Upstream Overages state (mirrored from AWS Q `setUserPreference` / `getUsageLimits`).
	// OverageStatus is the only switch that decides whether to keep dispatching once UsageLimit is reached.
	// Allowed values: "ENABLED", "DISABLED", "UNKNOWN" (or empty when not yet fetched).
	OverageStatus     string  `json:"overageStatus,omitempty"`
	OverageCapability string  `json:"overageCapability,omitempty"` // "OVERAGE_CAPABLE" / "NOT_OVERAGE_CAPABLE"
	OverageCap        float64 `json:"overageCap,omitempty"`        // Hard upper bound (USD)
	OverageRate       float64 `json:"overageRate,omitempty"`       // Per-invocation rate (USD)
	CurrentOverages   float64 `json:"currentOverages,omitempty"`   // Cumulative overage charges (USD)
	OverageCheckedAt  int64   `json:"overageCheckedAt,omitempty"`  // Last successful upstream sync (Unix seconds)

	// LegacyAllowOverage is kept for backward-compatible JSON loading only.
	// Pre-Overages-switch deployments persisted `allowOverage: true` to mean
	// "keep dispatching when quota is exhausted". On first load we migrate it
	// into OverageStatus="ENABLED" and zero this field so it does not get
	// re-emitted on future saves. Do not read this field elsewhere.
	LegacyAllowOverage bool `json:"allowOverage,omitempty"`

	// Account status
	Enabled   bool   `json:"enabled"`             // Whether account is active in the pool
	BanStatus string `json:"banStatus,omitempty"` // Ban status: "ACTIVE", "BANNED", "SUSPENDED"
	BanReason string `json:"banReason,omitempty"` // Reason for ban/suspension
	BanTime   int64  `json:"banTime,omitempty"`   // Timestamp when ban was detected

	// Subscription information
	SubscriptionType  string `json:"subscriptionType,omitempty"`  // Tier: FREE, PRO, PRO_PLUS, or POWER
	SubscriptionTitle string `json:"subscriptionTitle,omitempty"` // Human-readable subscription name
	DaysRemaining     int    `json:"daysRemaining,omitempty"`     // Days until subscription expires

	// Usage tracking
	UsageCurrent  float64 `json:"usageCurrent,omitempty"`  // Current period usage (credits)
	UsageLimit    float64 `json:"usageLimit,omitempty"`    // Maximum allowed usage per period
	UsagePercent  float64 `json:"usagePercent,omitempty"`  // Usage percentage (0.0-1.0)
	NextResetDate string  `json:"nextResetDate,omitempty"` // Date when usage resets (YYYY-MM-DD)
	LastRefresh   int64   `json:"lastRefresh,omitempty"`   // Last info refresh timestamp

	// Trial usage tracking
	TrialUsageCurrent float64 `json:"trialUsageCurrent,omitempty"` // Trial quota current usage
	TrialUsageLimit   float64 `json:"trialUsageLimit,omitempty"`   // Trial quota total limit
	TrialUsagePercent float64 `json:"trialUsagePercent,omitempty"` // Trial quota usage percentage (0.0-1.0)
	TrialStatus       string  `json:"trialStatus,omitempty"`       // Trial status: ACTIVE, EXPIRED, NONE
	TrialExpiresAt    int64   `json:"trialExpiresAt,omitempty"`    // Trial expiration timestamp (Unix seconds)

	// Runtime statistics (updated during operation)
	RequestCount int     `json:"requestCount,omitempty"` // Total requests processed
	ErrorCount   int     `json:"errorCount,omitempty"`   // Total errors encountered
	LastUsed     int64   `json:"lastUsed,omitempty"`     // Last request timestamp
	TotalTokens  int     `json:"totalTokens,omitempty"`  // Cumulative tokens processed
	TotalCredits float64 `json:"totalCredits,omitempty"` // Cumulative credits consumed
}

// IsApiKeyCredential reports whether the account authenticates with a Kiro API
// key used directly as the bearer token (tokentype: API_KEY), bypassing OAuth
// refresh and profile-ARN resolution. True when KiroApiKey is set OR the
// authMethod is "api_key"/"apikey" (case-insensitive).
func (a *Account) IsApiKeyCredential() bool {
	if a == nil {
		return false
	}
	if a.KiroApiKey != "" {
		return true
	}
	m := strings.ToLower(a.AuthMethod)
	return m == "api_key" || m == "apikey"
}

// EffectiveAuthRegion returns the region used for token-refresh endpoints, with
// the fallback chain: account.AuthRegion > account.Region > global AuthRegion
// (if set and not us-east-1) > global Region (if set and not us-east-1) > us-east-1.
func (a *Account) EffectiveAuthRegion() string {
	if a != nil {
		if r := strings.TrimSpace(a.AuthRegion); r != "" {
			return r
		}
		if r := strings.TrimSpace(a.Region); r != "" {
			return r
		}
	}
	if r := GetGlobalAuthRegion(); r != "" && r != "us-east-1" {
		return r
	}
	if r := GetGlobalRegion(); r != "" && r != "us-east-1" {
		return r
	}
	return "us-east-1"
}

// EffectiveApiRegion returns the region used for API request hosts, with the
// same fallback chain as EffectiveAuthRegion but using ApiRegion.
func (a *Account) EffectiveApiRegion() string {
	if a != nil {
		if r := strings.TrimSpace(a.ApiRegion); r != "" {
			return r
		}
		if r := strings.TrimSpace(a.Region); r != "" {
			return r
		}
	}
	if r := GetGlobalApiRegion(); r != "" && r != "us-east-1" {
		return r
	}
	if r := GetGlobalRegion(); r != "" && r != "us-east-1" {
		return r
	}
	return "us-east-1"
}

// PromptFilterRule defines a single custom prompt sanitization rule.
// Type can be: "regex" (regexp find/replace within prompt) or
// "lines-containing" (remove lines containing the match substring).
type PromptFilterRule struct {
	ID      string `json:"id"`                // Unique rule identifier
	Name    string `json:"name"`              // Human-readable rule name
	Type    string `json:"type"`              // "regex" or "lines-containing"
	Match   string `json:"match"`             // Pattern to match (regex pattern or substring)
	Replace string `json:"replace,omitempty"` // Replacement string (only for regex; empty = delete match)
	Enabled bool   `json:"enabled"`           // Whether this rule is active
}

// ApiKeyEntry represents a single API key with optional usage limits and counters.
// Limits with value 0 are treated as "no limit". Counters are cumulative and never reset
// automatically; operators can use the admin endpoint to manually reset them.
type ApiKeyEntry struct {
	ID         string `json:"id"`                 // Unique identifier (UUID)
	Name       string `json:"name,omitempty"`     // Human-readable label
	Key        string `json:"key"`                // The actual key value clients send
	Enabled    bool   `json:"enabled"`            // Whether this key may authenticate
	Migrated   bool   `json:"migrated,omitempty"` // True if migrated from legacy single ApiKey field
	CreatedAt  int64  `json:"createdAt"`          // Creation timestamp (Unix seconds)
	LastUsedAt int64  `json:"lastUsedAt,omitempty"`

	// Limits (0 = unlimited)
	TokenLimit  int64   `json:"tokenLimit,omitempty"`
	CreditLimit float64 `json:"creditLimit,omitempty"`

	// Cumulative usage (never auto-reset)
	TokensUsed    int64   `json:"tokensUsed,omitempty"`
	CreditsUsed   float64 `json:"creditsUsed,omitempty"`
	RequestsCount int64   `json:"requestsCount,omitempty"`
}

// Config represents the global application configuration.
type Config struct {
	// Server settings
	Password      string        `json:"password"`          // Admin panel password
	Port          int           `json:"port"`              // HTTP server port (default: 8080)
	Host          string        `json:"host"`              // HTTP server bind address (default: 0.0.0.0)
	ApiKey        string        `json:"apiKey,omitempty"`  // [Deprecated] Legacy single API key, migrated into ApiKeys on first load
	RequireApiKey bool          `json:"requireApiKey"`     // [Deprecated] Whether to enforce API key validation; with multi-key support, len(ApiKeys)>0 implicitly enforces auth
	ApiKeys       []ApiKeyEntry `json:"apiKeys,omitempty"` // Multiple API keys, each with independent quota
	KiroVersion   string        `json:"kiroVersion,omitempty"`
	SystemVersion string        `json:"systemVersion,omitempty"`
	NodeVersion   string        `json:"nodeVersion,omitempty"`
	Accounts      []Account     `json:"accounts"` // Registered Kiro accounts

	// Thinking mode configuration for extended reasoning output
	ThinkingSuffix       string `json:"thinkingSuffix,omitempty"`       // Model suffix to trigger thinking mode (default: "-thinking")
	OpenAIThinkingFormat string `json:"openaiThinkingFormat,omitempty"` // OpenAI output format: "reasoning_content", "thinking", or "think"
	ClaudeThinkingFormat string `json:"claudeThinkingFormat,omitempty"` // Claude output format: "reasoning_content", "thinking", or "think"

	// Endpoint configuration: "auto", "kiro", "codewhisperer", or "amazonq"
	PreferredEndpoint string `json:"preferredEndpoint,omitempty"`

	// EndpointFallback controls whether to try other endpoints when the preferred one fails.
	// Defaults to true. Set to false to only use the preferred endpoint.
	EndpointFallback *bool `json:"endpointFallback,omitempty"`

	// AllowOverUsage allows accounts to continue serving requests even when their
	// usage quota has been exhausted. When enabled, the pool will not skip accounts
	// solely because usageCurrent >= usageLimit.
	AllowOverUsage bool `json:"allowOverUsage,omitempty"`

	// Region defaults for accounts that omit per-account region/authRegion/apiRegion.
	// Defaults to "us-east-1" when empty (see GetGlobalRegion* / Account.Effective*Region).
	Region        string `json:"region,omitempty"`
	AuthRegion    string `json:"authRegion,omitempty"`
	ApiRegion     string `json:"apiRegion,omitempty"`
	// MaxPayloadBytes caps the serialized Kiro request body before upstream rejects
	// it as oversized. <=0 means use DefaultMaxPayloadBytes.
	MaxPayloadBytes int `json:"maxPayloadBytes,omitempty"`

	// Proxy configuration: optional outbound proxy for Kiro API requests
	// Format: "socks5://host:port", "socks5://user:pass@host:port",
	//         "http://host:port",  "http://user:pass@host:port"
	// Leave empty to connect directly.
	ProxyURL string `json:"proxyURL,omitempty"`

	// SanitizeClaudeCodePrompt is kept for backward-compatible JSON loading only.
	// Migrated to FilterClaudeCode on first load. Do not use directly.
	SanitizeClaudeCodePrompt bool `json:"sanitizeClaudeCodePrompt,omitempty"`

	// FilterClaudeCode detects the Claude Code CLI built-in system prompt and replaces it
	// with a compact backend-only prompt, reducing token usage significantly.
	FilterClaudeCode bool `json:"filterClaudeCode,omitempty"`

	// FilterEnvNoise strips environment metadata lines from system prompts:
	// git status, recent commits, environment sections, fast_mode_info tags, etc.
	FilterEnvNoise bool `json:"filterEnvNoise,omitempty"`

	// FilterStripBoundaries removes --- SYSTEM PROMPT --- / --- END SYSTEM PROMPT --- markers.
	FilterStripBoundaries bool `json:"filterStripBoundaries,omitempty"`

	// PromptFilterRules is a list of user-defined prompt sanitization rules (regex or line-filter).
	PromptFilterRules []PromptFilterRule `json:"promptFilterRules,omitempty"`

	// LogLevel controls verbosity of application logs.
	// Accepted values: "debug", "info", "warn", "error". Defaults to "info".
	// Can be overridden by the LOG_LEVEL environment variable.
	LogLevel string `json:"logLevel,omitempty"`

	// PromptCacheMaxRatio caps the fraction of input tokens reported as cache_read
	// in a single turn. Default 0.85. Raise to 0.95 for "continue"-heavy workloads
	// where the newest content is minimal and >85% of input is genuinely from cache.
	PromptCacheMaxRatio float64 `json:"promptCacheMaxRatio,omitempty"`

	// PromptCacheMaxEntries bounds the in-memory prompt-cache map; once exceeded,
	// the least-recently-used entries are evicted (LRU). Default 131072. Sized so
	// the prefix write-rate × TTL does not evict multi-turn history prefixes
	// before the next turn reuses them (mirrors kiro-rs's 131072 default). The
	// tracker clamps explicit small values up to 256.
	PromptCacheMaxEntries int `json:"promptCacheMaxEntries,omitempty"`

	// Global statistics (persisted across restarts)
	TotalRequests   int     `json:"totalRequests,omitempty"`   // Total API requests received
	SuccessRequests int     `json:"successRequests,omitempty"` // Successful requests count
	FailedRequests  int     `json:"failedRequests,omitempty"`  // Failed requests count
	TotalTokens     int     `json:"totalTokens,omitempty"`     // Total tokens processed
	TotalCredits    float64 `json:"totalCredits,omitempty"`    // Total credits consumed
}

// AccountInfo contains account metadata retrieved from Kiro API.
// Used for updating subscription and usage information.
type AccountInfo struct {
	Email             string
	UserId            string
	SubscriptionType  string
	SubscriptionTitle string
	DaysRemaining     int
	UsageCurrent      float64
	UsageLimit        float64
	UsagePercent      float64
	NextResetDate     string
	LastRefresh       int64
	TrialUsageCurrent float64
	TrialUsageLimit   float64
	TrialUsagePercent float64
	TrialStatus       string
	TrialExpiresAt    int64
}

// DefaultMaxPayloadBytes is the runtime-configurable cap (2 MB) for the Kiro
// request body, below the observed ~2.15 MB AWS upstream rejection threshold.
const DefaultMaxPayloadBytes = 2_000_000

// Version current version
const Version = "1.1.2"

const (
	autoQuarantineSuspicious429Reason = "auto-quarantine: suspicious 429 pattern"
	operatorDisabledReason            = "operator-disabled"
	autoQuarantineDuration            = 30 * time.Minute
)

var (
	cfg     *Config
	cfgLock sync.RWMutex
	cfgPath string
)

// Init initializes the configuration system with the specified file path.
// If the file doesn't exist, a default configuration is created.
func Init(path string) error {
	cfgPath = path
	return Load()
}

func Load() error {
	cfgLock.Lock()
	defer cfgLock.Unlock()

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Create default configuration.
			// Binds to 0.0.0.0 by default for Docker/container compatibility.
			cfg = &Config{
				Password:      "changeme",
				Port:          8080,
				Host:          "0.0.0.0",
				RequireApiKey: false,
				Accounts:      []Account{},
			}
			return saveLocked()
		}
		return err
	}

	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return err
	}
	cfg = &c

	// Migration: if a legacy single ApiKey is present and the new ApiKeys list is empty,
	// promote it into the new structure. The migrated entry inherits the legacy
	// RequireApiKey state — if the legacy deployment was public (RequireApiKey=false),
	// we mark the entry disabled so it doesn't accidentally start enforcing auth.
	// Operators can flip it on later from the admin UI. The legacy field is kept
	// for backward compatibility when reading older config files.
	if cfg.ApiKey != "" && len(cfg.ApiKeys) == 0 {
		cfg.ApiKeys = append(cfg.ApiKeys, ApiKeyEntry{
			ID:        newUUID(),
			Name:      "legacy",
			Key:       cfg.ApiKey,
			Enabled:   cfg.RequireApiKey,
			Migrated:  true,
			CreatedAt: time.Now().Unix(),
		})
		if err := saveLocked(); err != nil {
			return err
		}
	}

	// Migration: per-account AllowOverage → OverageStatus.
	// Pre-Overages-switch deployments stored `allowOverage: true` to mean "keep
	// dispatching when quota is exhausted". The new model reads OverageStatus
	// from the upstream AWS Q switch instead. To avoid silently disabling
	// previously-allowed accounts on first launch, treat allowOverage=true as
	// OverageStatus="ENABLED" (operators can refresh from AWS later). The
	// legacy field is then cleared so future saves don't re-emit it.
	overageMigrated := false
	for i := range cfg.Accounts {
		if cfg.Accounts[i].LegacyAllowOverage {
			if cfg.Accounts[i].OverageStatus == "" {
				cfg.Accounts[i].OverageStatus = "ENABLED"
			}
			cfg.Accounts[i].LegacyAllowOverage = false
			overageMigrated = true
		}
	}
	if overageMigrated {
		if err := saveLocked(); err != nil {
			return err
		}
	}
	return nil
}

// saveLocked persists cfg to disk. Caller MUST already hold cfgLock.
// This is identical to Save() (which does not take the lock either) but is named
// distinctly so call sites that already hold cfgLock are explicit about it.
func saveLocked() error {
	return Save()
}

// newUUID returns a UUID v4 string. Defined here to avoid pulling extra deps in this file.
func newUUID() string {
	return GenerateMachineId()
}

// Save persists the current configuration to the JSON file.
// Uses indented formatting for human readability.
//
// Atomic write: marshalled JSON is written to a sibling temp file, then renamed
// over config.json. A crash mid-write can no longer truncate/corrupt the file —
// which would lose every account token, API key, and the admin password, since
// this is the single source of truth for all credentials. rename is atomic on
// the same filesystem (same dir), so readers see either the old or the new file
// in full, never a partial write.
func Save() error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	tmp := cfgPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, cfgPath); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// SetPassword updates the admin password.
// Primarily used for environment variable override in containerized deployments.
func SetPassword(password string) {
	cfgLock.Lock()
	defer cfgLock.Unlock()
	cfg.Password = password
}

// GetConfigDir returns the directory containing the config JSON file.
// Useful for sibling state (e.g. stored Responses, caches) that should live
// alongside the configuration file.
func GetConfigDir() string {
	cfgLock.RLock()
	defer cfgLock.RUnlock()
	if cfgPath == "" {
		return "."
	}
	dir := cfgPath
	for i := len(dir) - 1; i >= 0; i-- {
		if dir[i] == '/' || dir[i] == '\\' {
			return dir[:i]
		}
	}
	return "."
}

func Get() *Config {
	cfgLock.RLock()
	defer cfgLock.RUnlock()
	return cfg
}

func GetPassword() string {
	cfgLock.RLock()
	defer cfgLock.RUnlock()
	return cfg.Password
}

func GetPort() int {
	cfgLock.RLock()
	defer cfgLock.RUnlock()
	if cfg.Port == 0 {
		return 8080
	}
	return cfg.Port
}

func GetHost() string {
	cfgLock.RLock()
	defer cfgLock.RUnlock()
	if cfg.Host == "" {
		return "127.0.0.1"
	}
	return cfg.Host
}

func GetAccounts() []Account {
	cfgLock.Lock()
	defer cfgLock.Unlock()
	applyAutoRestoreLocked()
	accounts := make([]Account, len(cfg.Accounts))
	copy(accounts, cfg.Accounts)
	return accounts
}

// AccountIDExists reports whether an account with the given ID is already stored.
// Used by the credential-import path to reuse a pasted record's id when it does
// not collide, so re-importing a backup never creates a duplicate entry.
func AccountIDExists(id string) bool {
	if id == "" {
		return false
	}
	cfgLock.RLock()
	defer cfgLock.RUnlock()
	for _, a := range cfg.Accounts {
		if a.ID == id {
			return true
		}
	}
	return false
}

func GetEnabledAccounts() []Account {
	cfgLock.Lock()
	defer cfgLock.Unlock()
	applyAutoRestoreLocked()
	var accounts []Account
	for _, a := range cfg.Accounts {
		if a.Enabled {
			accounts = append(accounts, a)
		}
	}
	return accounts
}

func AddAccount(account Account) error {
	cfgLock.Lock()
	defer cfgLock.Unlock()
	// Reject a duplicate id under the write lock. The import path pre-checks with
	// AccountIDExists (RLock) and mints a fresh id on collision, but that check and this
	// append are not atomic; two concurrent imports of the same pasted id could both
	// pass the pre-check. This makes "add if id absent" the atomic invariant.
	if account.ID != "" {
		for _, a := range cfg.Accounts {
			if a.ID == account.ID {
				return fmt.Errorf("account with id %s already exists", account.ID)
			}
		}
	}
	cfg.Accounts = append(cfg.Accounts, account)
	return Save()
}

func UpdateAccount(id string, account Account) error {
	cfgLock.Lock()
	defer cfgLock.Unlock()
	for i, a := range cfg.Accounts {
		if a.ID == id {
			cfg.Accounts[i] = account
			return Save()
		}
	}
	return nil
}

// UpdateAccountOverageStatus persists the cached upstream overage status fields.
// Called after a successful setUserPreference or getUsageLimits round-trip.
func UpdateAccountOverageStatus(id, status, capability string, cap, rate, current float64, checkedAt int64) error {
	cfgLock.Lock()
	defer cfgLock.Unlock()
	for i, a := range cfg.Accounts {
		if a.ID == id {
			if status != "" {
				cfg.Accounts[i].OverageStatus = status
			}
			if capability != "" {
				cfg.Accounts[i].OverageCapability = capability
			}
			cfg.Accounts[i].OverageCap = cap
			cfg.Accounts[i].OverageRate = rate
			cfg.Accounts[i].CurrentOverages = current
			if checkedAt > 0 {
				cfg.Accounts[i].OverageCheckedAt = checkedAt
			}
			return Save()
		}
	}
	return nil
}

// SetAccountEnabled toggles the enabled state of an account and persists the change.
// Used to disable accounts whose refresh token has been revoked (401 Bad credentials)
// so subsequent requests skip them automatically.
func SetAccountEnabled(id string, enabled bool) error {
	cfgLock.Lock()
	defer cfgLock.Unlock()
	for i, a := range cfg.Accounts {
		if a.ID == id {
			cfg.Accounts[i].Enabled = enabled
			if enabled {
				cfg.Accounts[i].BanStatus = "ACTIVE"
				cfg.Accounts[i].BanReason = ""
				cfg.Accounts[i].BanTime = 0
			} else {
				cfg.Accounts[i].BanStatus = "DISABLED"
				cfg.Accounts[i].BanTime = time.Now().Unix()
			}
			return Save()
		}
	}
	return nil
}

// SetAccountBanStatus marks an account as banned/disabled with a reason.
// Reason is recorded so operators can see why the account was auto-disabled.
func SetAccountBanStatus(id, status, reason string) error {
	cfgLock.Lock()
	defer cfgLock.Unlock()
	for i, a := range cfg.Accounts {
		if a.ID == id {
			cfg.Accounts[i].BanStatus = status
			cfg.Accounts[i].BanReason = reason
			cfg.Accounts[i].BanTime = time.Now().Unix()
			if status == "BANNED" || status == "DISABLED" {
				cfg.Accounts[i].Enabled = false
			}
			return Save()
		}
	}
	return nil
}

func AutoQuarantineSuspicious429Reason() string {
	return autoQuarantineSuspicious429Reason
}

// OperatorDisabledReason is the BanReason stamped when a human operator disables
// an account. It marks the account as DISABLED (not SUSPENDED), which keeps the
// auto-restore sweep from ever re-enabling it.
func OperatorDisabledReason() string {
	return operatorDisabledReason
}

func shouldAutoRestoreSuspendedAccount(a Account, now time.Time) bool {
	return a.BanStatus == "SUSPENDED" && a.BanReason == autoQuarantineSuspicious429Reason && a.BanTime > 0 && now.Unix()-a.BanTime >= int64(autoQuarantineDuration/time.Second)
}

func applyAutoRestoreLocked() bool {
	if cfg == nil {
		return false
	}
	now := time.Now()
	changed := false
	for i := range cfg.Accounts {
		if shouldAutoRestoreSuspendedAccount(cfg.Accounts[i], now) {
			cfg.Accounts[i].Enabled = true
			cfg.Accounts[i].BanStatus = "ACTIVE"
			cfg.Accounts[i].BanReason = ""
			cfg.Accounts[i].BanTime = 0
			changed = true
		}
	}
	if changed {
		_ = Save()
	}
	return changed
}

// AddAccounts appends multiple accounts in a single locked pass and persists
// with exactly one Save(), avoiding the O(n²) write amplification that calling
// AddAccount in a loop would cause (each AddAccount re-serializes the entire
// config.json). Accounts whose RefreshToken already exists (against the current
// config or earlier entries in the same batch) are skipped to keep bulk imports
// idempotent across retries/re-pastes. Entries with an empty RefreshToken are
// also skipped — there is no stable identity to dedup on and they cannot be
// activated later. Returns how many were added and how many were skipped.
//
// Save() is only invoked when at least one account is actually added, so a
// fully-duplicate batch does not churn the config file.
func AddAccounts(accounts []Account) (added int, skipped int, err error) {
	cfgLock.Lock()
	defer cfgLock.Unlock()

	// Seed the seen-set with refresh tokens already persisted so the batch
	// dedups against existing accounts, not just within itself.
	seen := make(map[string]struct{}, len(cfg.Accounts)+len(accounts))
	for i := range cfg.Accounts {
		if rt := cfg.Accounts[i].RefreshToken; rt != "" {
			seen[rt] = struct{}{}
		}
	}

	for _, a := range accounts {
		if a.RefreshToken == "" {
			skipped++
			continue
		}
		if _, dup := seen[a.RefreshToken]; dup {
			skipped++
			continue
		}
		seen[a.RefreshToken] = struct{}{}
		cfg.Accounts = append(cfg.Accounts, a)
		added++
	}

	if added == 0 {
		return 0, skipped, nil
	}
	if err := Save(); err != nil {
		// Roll back the in-memory appends so a failed persist does not leave
		// the running pool out of sync with what is on disk.
		cfg.Accounts = cfg.Accounts[:len(cfg.Accounts)-added]
		return 0, skipped, err
	}
	return added, skipped, nil
}

// RefreshTokenExists reports whether any account already holds the given refresh
// token. Used by bulk import to dedup candidates before spending an upstream
// token-exchange round-trip on a duplicate.
func RefreshTokenExists(refreshToken string) bool {
	if refreshToken == "" {
		return false
	}
	cfgLock.RLock()
	defer cfgLock.RUnlock()
	for i := range cfg.Accounts {
		if cfg.Accounts[i].RefreshToken == refreshToken {
			return true
		}
	}
	return false
}

// FindAccountIDByRefreshToken returns the id of the account that already holds
// the given refresh token, or "" if none. Used by the single credential-import
// path to update an existing entry in place when a backup is re-imported, rather
// than minting a fresh id and leaving two live accounts sharing the same token.
// Mirrors the refresh-token dedup the bulk path applies (AddAccounts).
func FindAccountIDByRefreshToken(refreshToken string) string {
	if refreshToken == "" {
		return ""
	}
	cfgLock.RLock()
	defer cfgLock.RUnlock()
	for i := range cfg.Accounts {
		if cfg.Accounts[i].RefreshToken == refreshToken {
			return cfg.Accounts[i].ID
		}
	}
	return ""
}

func SuspendAccountTemporarily(id, reason string) error {
	cfgLock.Lock()
	defer cfgLock.Unlock()
	now := time.Now().Unix()
	for i, a := range cfg.Accounts {
		if a.ID == id {
			cfg.Accounts[i].Enabled = false
			cfg.Accounts[i].BanStatus = "SUSPENDED"
			cfg.Accounts[i].BanReason = reason
			cfg.Accounts[i].BanTime = now
			return Save()
		}
	}
	return nil
}

// ClearAccountCurrentOverages zeroes the cached CurrentOverages for an account
// while preserving the OverageStatus switch and the cap/rate billing config.
// Called when upstream usage has fallen back within the subscription quota
// (e.g. after a billing-period reset): overage points are zero by definition
// when usage is within quota, so stale points from a previous period must not
// linger in the UI/scheduler. Returns without writing if already zero, so the
// periodic refresh loop does not churn the config file every cycle.
func ClearAccountCurrentOverages(id string, checkedAt int64) error {
	cfgLock.Lock()
	defer cfgLock.Unlock()
	for i, a := range cfg.Accounts {
		if a.ID == id {
			if cfg.Accounts[i].CurrentOverages == 0 {
				return nil
			}
			cfg.Accounts[i].CurrentOverages = 0
			if checkedAt > 0 {
				cfg.Accounts[i].OverageCheckedAt = checkedAt
			}
			return Save()
		}
	}
	return nil
}

func UpdateAccountProfileArn(id, profileArn string) error {
	cfgLock.Lock()
	defer cfgLock.Unlock()
	for i, a := range cfg.Accounts {
		if a.ID == id {
			cfg.Accounts[i].ProfileArn = profileArn
			return Save()
		}
	}
	return nil
}

func DeleteAccount(id string) error {
	cfgLock.Lock()
	defer cfgLock.Unlock()
	for i, a := range cfg.Accounts {
		if a.ID == id {
			cfg.Accounts = append(cfg.Accounts[:i], cfg.Accounts[i+1:]...)
			return Save()
		}
	}
	return nil
}

func UpdateAccountToken(id, accessToken, refreshToken string, expiresAt int64) error {
	cfgLock.Lock()
	defer cfgLock.Unlock()
	for i, a := range cfg.Accounts {
		if a.ID == id {
			cfg.Accounts[i].AccessToken = accessToken
			if refreshToken != "" {
				cfg.Accounts[i].RefreshToken = refreshToken
			}
			cfg.Accounts[i].ExpiresAt = expiresAt
			return Save()
		}
	}
	return nil
}

func GetApiKey() string {
	cfgLock.RLock()
	defer cfgLock.RUnlock()
	return cfg.ApiKey
}

func IsApiKeyRequired() bool {
	cfgLock.RLock()
	defer cfgLock.RUnlock()
	return cfg.RequireApiKey
}

func UpdateSettings(apiKey string, requireApiKey bool, password string) error {
	cfgLock.Lock()
	defer cfgLock.Unlock()
	cfg.ApiKey = apiKey
	cfg.RequireApiKey = requireApiKey
	if password != "" {
		cfg.Password = password
	}
	return Save()
}

func UpdateSettingsPatch(apiKey *string, requireApiKey *bool, password string) error {
	cfgLock.Lock()
	defer cfgLock.Unlock()
	if apiKey != nil {
		cfg.ApiKey = *apiKey
	}
	if requireApiKey != nil {
		cfg.RequireApiKey = *requireApiKey
	}
	if password != "" {
		cfg.Password = password
	}
	return Save()
}

func UpdateStats(totalReq, successReq, failedReq, totalTokens int, totalCredits float64) error {
	cfgLock.Lock()
	defer cfgLock.Unlock()
	cfg.TotalRequests = totalReq
	cfg.SuccessRequests = successReq
	cfg.FailedRequests = failedReq
	cfg.TotalTokens = totalTokens
	cfg.TotalCredits = totalCredits
	return Save()
}

func GetStats() (int, int, int, int, float64) {
	cfgLock.RLock()
	defer cfgLock.RUnlock()
	return cfg.TotalRequests, cfg.SuccessRequests, cfg.FailedRequests, cfg.TotalTokens, cfg.TotalCredits
}

func UpdateAccountStats(id string, requestCount, errorCount, totalTokens int, totalCredits float64, lastUsed int64) error {
	cfgLock.Lock()
	defer cfgLock.Unlock()
	for i, a := range cfg.Accounts {
		if a.ID == id {
			cfg.Accounts[i].RequestCount = requestCount
			cfg.Accounts[i].ErrorCount = errorCount
			cfg.Accounts[i].TotalTokens = totalTokens
			cfg.Accounts[i].TotalCredits = totalCredits
			cfg.Accounts[i].LastUsed = lastUsed
			return Save()
		}
	}
	return nil
}

// UpdateAccountInfo updates an account's subscription and usage information.
// Called after refreshing account data from Kiro API.
func UpdateAccountInfo(id string, info AccountInfo) error {
	cfgLock.Lock()
	defer cfgLock.Unlock()
	for i, a := range cfg.Accounts {
		if a.ID == id {
			if info.Email != "" {
				cfg.Accounts[i].Email = info.Email
			}
			if info.UserId != "" {
				cfg.Accounts[i].UserId = info.UserId
			}
			cfg.Accounts[i].SubscriptionType = info.SubscriptionType
			cfg.Accounts[i].SubscriptionTitle = info.SubscriptionTitle
			cfg.Accounts[i].DaysRemaining = info.DaysRemaining
			cfg.Accounts[i].UsageCurrent = info.UsageCurrent
			cfg.Accounts[i].UsageLimit = info.UsageLimit
			cfg.Accounts[i].UsagePercent = info.UsagePercent
			cfg.Accounts[i].NextResetDate = info.NextResetDate
			cfg.Accounts[i].LastRefresh = info.LastRefresh
			cfg.Accounts[i].TrialUsageCurrent = info.TrialUsageCurrent
			cfg.Accounts[i].TrialUsageLimit = info.TrialUsageLimit
			cfg.Accounts[i].TrialUsagePercent = info.TrialUsagePercent
			cfg.Accounts[i].TrialStatus = info.TrialStatus
			cfg.Accounts[i].TrialExpiresAt = info.TrialExpiresAt
			return Save()
		}
	}
	return nil
}

// GetFilterClaudeCode returns whether Claude Code system prompt detection is enabled.
// Also checks the legacy SanitizeClaudeCodePrompt flag for backward compatibility.
func GetFilterClaudeCode() bool {
	cfgLock.RLock()
	defer cfgLock.RUnlock()
	if cfg == nil {
		return false
	}
	return cfg.FilterClaudeCode || cfg.SanitizeClaudeCodePrompt
}

// GetFilterEnvNoise returns whether environment noise line stripping is enabled.
func GetFilterEnvNoise() bool {
	cfgLock.RLock()
	defer cfgLock.RUnlock()
	if cfg == nil {
		return false
	}
	return cfg.FilterEnvNoise
}

// GetFilterStripBoundaries returns whether boundary marker stripping is enabled.
func GetFilterStripBoundaries() bool {
	cfgLock.RLock()
	defer cfgLock.RUnlock()
	if cfg == nil {
		return false
	}
	return cfg.FilterStripBoundaries
}

// PromptFilterConfig holds all prompt filter settings for API responses.
type PromptFilterConfig struct {
	FilterClaudeCode      bool               `json:"filterClaudeCode"`
	FilterEnvNoise        bool               `json:"filterEnvNoise"`
	FilterStripBoundaries bool               `json:"filterStripBoundaries"`
	Rules                 []PromptFilterRule `json:"rules"`
}

// GetPromptFilterConfig returns all prompt filter settings.
func GetPromptFilterConfig() PromptFilterConfig {
	cfgLock.RLock()
	defer cfgLock.RUnlock()
	if cfg == nil {
		return PromptFilterConfig{Rules: []PromptFilterRule{}}
	}
	rules := make([]PromptFilterRule, len(cfg.PromptFilterRules))
	copy(rules, cfg.PromptFilterRules)
	return PromptFilterConfig{
		FilterClaudeCode:      cfg.FilterClaudeCode || cfg.SanitizeClaudeCodePrompt,
		FilterEnvNoise:        cfg.FilterEnvNoise,
		FilterStripBoundaries: cfg.FilterStripBoundaries,
		Rules:                 rules,
	}
}

// UpdatePromptFilterConfig saves all prompt filter settings atomically.
func UpdatePromptFilterConfig(filterClaudeCode, filterEnvNoise, filterStripBoundaries bool, rules []PromptFilterRule) error {
	cfgLock.Lock()
	defer cfgLock.Unlock()
	cfg.FilterClaudeCode = filterClaudeCode
	cfg.FilterEnvNoise = filterEnvNoise
	cfg.FilterStripBoundaries = filterStripBoundaries
	// Clear legacy flag to avoid double-applying after first save
	cfg.SanitizeClaudeCodePrompt = false
	if rules != nil {
		cfg.PromptFilterRules = rules
	}
	return Save()
}

// GetPromptFilterRules returns the current prompt filter rules.
func GetPromptFilterRules() []PromptFilterRule {
	cfgLock.RLock()
	defer cfgLock.RUnlock()
	if cfg == nil {
		return nil
	}
	rules := make([]PromptFilterRule, len(cfg.PromptFilterRules))
	copy(rules, cfg.PromptFilterRules)
	return rules
}

// ThinkingConfig holds settings for AI thinking/reasoning mode.
// When enabled, models output their reasoning process alongside the response.
type ThinkingConfig struct {
	Suffix       string `json:"suffix"`       // Model name suffix that triggers thinking mode
	OpenAIFormat string `json:"openaiFormat"` // Output format for OpenAI-compatible responses
	ClaudeFormat string `json:"claudeFormat"` // Output format for Claude-compatible responses
}

// GetThinkingConfig 获取 thinking 配置
func GetThinkingConfig() ThinkingConfig {
	cfgLock.RLock()
	defer cfgLock.RUnlock()

	suffix := cfg.ThinkingSuffix
	if suffix == "" {
		suffix = "-thinking"
	}
	openaiFormat := cfg.OpenAIThinkingFormat
	if openaiFormat == "" {
		openaiFormat = "reasoning_content"
	}
	claudeFormat := cfg.ClaudeThinkingFormat
	if claudeFormat == "" {
		claudeFormat = "thinking"
	}

	return ThinkingConfig{
		Suffix:       suffix,
		OpenAIFormat: openaiFormat,
		ClaudeFormat: claudeFormat,
	}
}

// UpdateThinkingConfig 更新 thinking 配置
func UpdateThinkingConfig(suffix, openaiFormat, claudeFormat string) error {
	cfgLock.Lock()
	defer cfgLock.Unlock()
	cfg.ThinkingSuffix = suffix
	cfg.OpenAIThinkingFormat = openaiFormat
	cfg.ClaudeThinkingFormat = claudeFormat
	return Save()
}

// GetPreferredEndpoint 获取首选端点配置
func GetPreferredEndpoint() string {
	cfgLock.RLock()
	defer cfgLock.RUnlock()
	if cfg.PreferredEndpoint == "" {
		return "auto"
	}
	return cfg.PreferredEndpoint
}

// UpdatePreferredEndpoint 更新首选端点配置
func UpdatePreferredEndpoint(endpoint string) error {
	cfgLock.Lock()
	defer cfgLock.Unlock()
	cfg.PreferredEndpoint = endpoint
	return Save()
}

// GetEndpointFallback returns whether endpoint fallback is enabled. Defaults to true.
func GetEndpointFallback() bool {
	cfgLock.RLock()
	defer cfgLock.RUnlock()
	if cfg.EndpointFallback == nil {
		return true
	}
	return *cfg.EndpointFallback
}

// UpdateEndpointFallback sets the endpoint fallback switch and persists the change.
func UpdateEndpointFallback(enabled bool) error {
	cfgLock.Lock()
	defer cfgLock.Unlock()
	cfg.EndpointFallback = &enabled
	return Save()
}

// GetProxyURL 获取出站代理地址
func GetProxyURL() string {
	cfgLock.RLock()
	defer cfgLock.RUnlock()
	return cfg.ProxyURL
}

// UpdateProxySettings 更新出站代理配置
func UpdateProxySettings(proxyURL string) error {
	cfgLock.Lock()
	defer cfgLock.Unlock()
	cfg.ProxyURL = proxyURL
	return Save()
}

// GetAllowOverUsage returns whether over-usage is allowed when account quota is exhausted.
func GetAllowOverUsage() bool {
	cfgLock.RLock()
	defer cfgLock.RUnlock()
	if cfg == nil {
		return false
	}
	return cfg.AllowOverUsage
}

// UpdateAllowOverUsage sets the over-usage setting and persists the change.
func UpdateAllowOverUsage(allow bool) error {
	cfgLock.Lock()
	defer cfgLock.Unlock()
	cfg.AllowOverUsage = allow
	return Save()
}

// GetMaxPayloadBytes returns the configured payload cap, falling back to
// DefaultMaxPayloadBytes when unset (<=0).
func GetMaxPayloadBytes() int {
	cfgLock.RLock()
	defer cfgLock.RUnlock()
	if cfg == nil || cfg.MaxPayloadBytes <= 0 {
		return DefaultMaxPayloadBytes
	}
	return cfg.MaxPayloadBytes
}

// UpdateMaxPayloadBytes sets the payload cap and persists the change.
func UpdateMaxPayloadBytes(n int) error {
	cfgLock.Lock()
	defer cfgLock.Unlock()
	cfg.MaxPayloadBytes = n
	return Save()
}

// GetGlobalRegion returns the configured default region (empty → "us-east-1").
func GetGlobalRegion() string {
	cfgLock.RLock()
	defer cfgLock.RUnlock()
	if cfg == nil || cfg.Region == "" {
		return "us-east-1"
	}
	return cfg.Region
}

// GetGlobalAuthRegion returns the configured default token-refresh region.
func GetGlobalAuthRegion() string {
	cfgLock.RLock()
	defer cfgLock.RUnlock()
	if cfg == nil || cfg.AuthRegion == "" {
		return "us-east-1"
	}
	return cfg.AuthRegion
}

// GetGlobalApiRegion returns the configured default API-request host region.
func GetGlobalApiRegion() string {
	cfgLock.RLock()
	defer cfgLock.RUnlock()
	if cfg == nil || cfg.ApiRegion == "" {
		return "us-east-1"
	}
	return cfg.ApiRegion
}

// GetLogLevel returns the configured log level (debug/info/warn/error). Defaults to "info".
func GetLogLevel() string {
	cfgLock.RLock()
	defer cfgLock.RUnlock()
	if cfg == nil || cfg.LogLevel == "" {
		return "info"
	}
	return cfg.LogLevel
}

// GetPromptCacheMaxRatio returns the cache-read cap ratio (0.0-1.0). Defaults to 0.85.
func GetPromptCacheMaxRatio() float64 {
	cfgLock.RLock()
	defer cfgLock.RUnlock()
	if cfg == nil || cfg.PromptCacheMaxRatio <= 0 || cfg.PromptCacheMaxRatio > 1 {
		return 0.85
	}
	return cfg.PromptCacheMaxRatio
}

// UpdatePromptCacheMaxRatio sets the cache-read cap ratio and persists the change.
func UpdatePromptCacheMaxRatio(ratio float64) error {
	cfgLock.Lock()
	defer cfgLock.Unlock()
	cfg.PromptCacheMaxRatio = ratio
	return Save()
}

const defaultPromptCacheMaxEntries = 131072
const minPromptCacheEntries = 256

// GetPromptCacheMaxEntries returns the prompt-cache LRU bound. Defaults to
// 131072 when unset (≤ 0); an explicit small value is clamped up to
// minPromptCacheEntries (256) so a misconfigured tiny value cannot make the
// cache useless. This is the production safety floor — the tracker constructor
// trusts its caller (tests may use any capacity).
func GetPromptCacheMaxEntries() int {
	cfgLock.RLock()
	defer cfgLock.RUnlock()
	if cfg == nil || cfg.PromptCacheMaxEntries <= 0 {
		return defaultPromptCacheMaxEntries
	}
	if cfg.PromptCacheMaxEntries < minPromptCacheEntries {
		return minPromptCacheEntries
	}
	return cfg.PromptCacheMaxEntries
}

// UpdatePromptCacheMaxEntries sets the prompt-cache LRU bound and persists it.
// Applies on the next tracker construction (restart); it does not resize a
// live tracker.
func UpdatePromptCacheMaxEntries(n int) error {
	cfgLock.Lock()
	defer cfgLock.Unlock()
	cfg.PromptCacheMaxEntries = n
	return Save()
}

// UpdateLogLevel updates the log level setting and persists the change.
func UpdateLogLevel(level string) error {
	cfgLock.Lock()
	defer cfgLock.Unlock()
	cfg.LogLevel = level
	return Save()
}

// KiroClientConfig is the {KiroVersion, SystemVersion, NodeVersion} triple
// embedded into the upstream User-Agent. Populated by GetKiroClientConfig.
type KiroClientConfig struct {
	KiroVersion   string
	SystemVersion string
	NodeVersion   string
}

// GetKiroClientConfig resolves the {KiroVersion, SystemVersion, NodeVersion}
// triple for accountID. When no operator override is set on a field, it derives
// a stable desktop fingerprint from the account via DeriveClientProfile — which
// selects from clientProfilePool (mac/win-weighted) and NEVER returns Linux, so
// a deploy on a Linux box no longer advertises linux#6.6.87 in every request's
// User-Agent. An empty accountID still yields a stable mac-default profile
// (never Linux). Ported from kiro-tutu (zero-dep).
//
// Operator overrides from config (KiroVersion/SystemVersion/NodeVersion) take
// precedence per-field when explicitly set, preserving the manual-override path.
func GetKiroClientConfig(accountID string) KiroClientConfig {
	cfgLock.RLock()
	defer cfgLock.RUnlock()

	profile := DeriveClientProfile(accountID)
	kiroVersion := profile.kiroVersion
	systemVersion := profile.systemVersion
	nodeVersion := profile.nodeVersion

	if cfg != nil {
		if cfg.KiroVersion != "" {
			kiroVersion = cfg.KiroVersion
		}
		if cfg.SystemVersion != "" {
			systemVersion = cfg.SystemVersion
		}
		if cfg.NodeVersion != "" {
			nodeVersion = cfg.NodeVersion
		}
	}

	return KiroClientConfig{
		KiroVersion:   kiroVersion,
		SystemVersion: systemVersion,
		NodeVersion:   nodeVersion,
	}
}
