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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
	"unicode"
)

var (
	ErrAccountNotFound       = errors.New("account not found")
	ErrDuplicateAccountID    = errors.New("account ID already exists")
	ErrDuplicateRefreshToken = errors.New("account refresh token already exists")
	ErrDuplicateAPIKey       = errors.New("account API key already exists")
	ErrEmptyAPIKey           = errors.New("kiroApiKey is empty")
	ErrInvalidModelMapping   = errors.New("invalid model mapping")
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

// Account represents a Kiro API account with authentication credentials and usage statistics.
type Account struct {
	// Basic identification
	ID       string `json:"id"`                 // Unique account identifier (UUID)
	Email    string `json:"email,omitempty"`    // User email address
	UserId   string `json:"userId,omitempty"`   // Kiro user ID
	Nickname string `json:"nickname,omitempty"` // Display name for admin panel

	// Authentication credentials
	AccessToken  string `json:"accessToken"`  // OAuth access token for API calls
	RefreshToken string `json:"refreshToken"` // OAuth refresh token for token renewal
	// RefreshTokenFingerprint is a one-way identifier for the credential that
	// originally created this account. It prevents a previously imported token
	// from being imported again after the provider rotates it.
	RefreshTokenFingerprint string `json:"refreshTokenFingerprint,omitempty"`
	// KiroApiKey is a headless Kiro API key (typically ksk_...). When set,
	// AuthMethod is "api_key" and the key is used directly as the Bearer token
	// without OAuth refresh. AccessToken is kept in sync for the shared request path.
	KiroApiKey   string `json:"kiroApiKey,omitempty"`
	ClientID     string `json:"clientId,omitempty"`     // OIDC client ID (for IdC auth)
	ClientSecret string `json:"clientSecret,omitempty"` // OIDC client secret (for IdC auth)
	AuthMethod   string `json:"authMethod"`             // Authentication method: "idc", "social", "external_idp", or "api_key"
	Provider     string `json:"provider,omitempty"`     // Identity provider name (e.g., "BuilderId", "GitHub", "AzureAD")
	Region       string `json:"region"`                 // AWS region for OIDC endpoints / API Key data plane
	StartUrl     string `json:"startUrl,omitempty"`     // AWS SSO start URL
	ExpiresAt    int64  `json:"expiresAt,omitempty"`    // Token expiration timestamp (Unix seconds); unused for API Key
	MachineId    string `json:"machineId,omitempty"`    // UUID machine identifier for request tracking
	ProfileArn   string `json:"profileArn,omitempty"`   // CodeWhisperer/Kiro profile ARN for generation requests

	// Microsoft Enterprise SSO uses an external OAuth2 public client. These
	// fields are deliberately separate from the AWS IdC client secret/region:
	// Account.Region remains the AWS authentication region, while data-plane
	// routing treats ProfileArn as authoritative whenever it is available.
	TokenEndpoint string `json:"tokenEndpoint,omitempty"` // External IdP OAuth2 token endpoint
	IssuerURL     string `json:"issuerUrl,omitempty"`     // External IdP OIDC issuer
	Scopes        string `json:"scopes,omitempty"`        // Space-separated external IdP scopes

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

// ModelMapping maps a client-facing model ID to the exact Kiro upstream model ID.
// Mappings are case-insensitive on Source and resolve in a single hop.
type ModelMapping struct {
	Source string `json:"source"`
	Target string `json:"target"`
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

	// ModelMappings exposes client-friendly model IDs while keeping upstream IDs internal.
	ModelMappings []ModelMapping `json:"modelMappings,omitempty"`

	// Endpoint configuration: "auto", "kiro", "codewhisperer", or "amazonq"
	PreferredEndpoint string `json:"preferredEndpoint,omitempty"`

	// EndpointFallback controls whether to try other endpoints when the preferred one fails.
	// Defaults to true. Set to false to only use the preferred endpoint.
	EndpointFallback *bool `json:"endpointFallback,omitempty"`

	// AllowOverUsage allows accounts to continue serving requests even when their
	// usage quota has been exhausted. When enabled, the pool will not skip accounts
	// solely because usageCurrent >= usageLimit.
	AllowOverUsage bool `json:"allowOverUsage,omitempty"`

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

// Version current version
const Version = "1.1.5"

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
	normalizedMappings, err := normalizeModelMappings(c.ModelMappings)
	if err != nil {
		return fmt.Errorf("load modelMappings: %w", err)
	}
	c.ModelMappings = normalizedMappings
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
func Save() error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(cfgPath, data, 0600)
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
	cfgLock.RLock()
	defer cfgLock.RUnlock()
	accounts := make([]Account, len(cfg.Accounts))
	copy(accounts, cfg.Accounts)
	return accounts
}

func GetEnabledAccounts() []Account {
	cfgLock.RLock()
	defer cfgLock.RUnlock()
	var accounts []Account
	for _, a := range cfg.Accounts {
		if a.Enabled {
			accounts = append(accounts, a)
		}
	}
	return accounts
}

// RefreshTokenFingerprint returns a stable, non-reversible identifier for an
// opaque refresh token. Empty tokens do not receive a fingerprint.
func RefreshTokenFingerprint(refreshToken string) string {
	if refreshToken == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(refreshToken))
	return fmt.Sprintf("%x", sum[:])
}

// APIKeyFingerprint returns a stable, non-reversible identifier for a Kiro API key.
func APIKeyFingerprint(apiKey string) string {
	if apiKey == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(apiKey))
	return fmt.Sprintf("%x", sum[:])
}

// IsAPIKeyAccount reports whether the account authenticates with a Kiro API key.
func IsAPIKeyAccount(account *Account) bool {
	if account == nil {
		return false
	}
	if strings.TrimSpace(account.KiroApiKey) != "" {
		return true
	}
	method := strings.ToLower(strings.TrimSpace(account.AuthMethod))
	return method == "api_key" || method == "apikey"
}

// SplitKiroAPIKeyAndRegion parses the convenience form "key|region".
// The key itself is not restricted to a fixed prefix so future formats remain compatible.
func SplitKiroAPIKeyAndRegion(raw string) (key, region string, err error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", "", ErrEmptyAPIKey
	}
	parts := strings.Split(trimmed, "|")
	if len(parts) > 2 {
		return "", "", errors.New("multiple pipe separators are not allowed")
	}
	key = strings.TrimSpace(parts[0])
	if key == "" {
		return "", "", errors.New("key before pipe is empty")
	}
	if len(parts) == 2 {
		region = strings.TrimSpace(parts[1])
		if region == "" {
			return "", "", errors.New("region after pipe is empty")
		}
		if err := validateKiroRegionHostLabel(region); err != nil {
			return "", "", err
		}
	}
	return key, region, nil
}

func validateKiroRegionHostLabel(region string) error {
	region = strings.TrimSpace(region)
	if region == "" {
		return errors.New("region is empty")
	}
	for _, r := range region {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
			continue
		}
		return errors.New("region contains host-unsafe characters")
	}
	if strings.Contains(region, " ") || strings.ContainsAny(region, "\n\r\t./") {
		return errors.New("region contains host-unsafe characters")
	}
	return nil
}

// MachineIdFromAPIKey derives the machine id used by Kiro CLI/API-key clients:
// sha256 hex of "KiroAPIKey/<api_key>".
func MachineIdFromAPIKey(apiKey string) string {
	sum := sha256.Sum256([]byte("KiroAPIKey/" + apiKey))
	return fmt.Sprintf("%x", sum[:])
}

// NormalizeAPIKeyAccount fills API-key credential defaults in place.
// It accepts "ksk_xxx|region", sets AuthMethod=api_key, copies the key into
// AccessToken for the shared Bearer path, clears OAuth-only fields, and
// derives MachineId when missing.
func NormalizeAPIKeyAccount(account *Account) error {
	if account == nil {
		return errors.New("account is nil")
	}
	raw := strings.TrimSpace(account.KiroApiKey)
	if raw == "" {
		raw = strings.TrimSpace(account.AccessToken)
	}
	key, region, err := SplitKiroAPIKeyAndRegion(raw)
	if err != nil {
		return err
	}
	account.KiroApiKey = key
	account.AccessToken = key
	account.AuthMethod = "api_key"
	account.RefreshToken = ""
	account.RefreshTokenFingerprint = ""
	account.ClientID = ""
	account.ClientSecret = ""
	account.TokenEndpoint = ""
	account.IssuerURL = ""
	account.Scopes = ""
	account.ProfileArn = ""
	account.ExpiresAt = 0
	if region != "" {
		if strings.TrimSpace(account.Region) == "" {
			account.Region = region
		}
	}
	if strings.TrimSpace(account.Region) == "" {
		account.Region = "us-east-1"
	}
	if err := validateKiroRegionHostLabel(account.Region); err != nil {
		return err
	}
	if strings.TrimSpace(account.MachineId) == "" {
		account.MachineId = MachineIdFromAPIKey(key)
	}
	if strings.TrimSpace(account.Provider) == "" {
		account.Provider = "APIKey"
	}
	if strings.TrimSpace(account.Email) == "" {
		// Stable display label without leaking the full secret.
		fp := APIKeyFingerprint(key)
		if len(fp) > 12 {
			fp = fp[:12]
		}
		account.Email = "api-key-" + fp
	}
	return nil
}

// AccountCredentialExists checks both the current refresh token and the
// original credential fingerprint while holding the configuration read lock.
func AccountCredentialExists(refreshToken string) bool {
	if refreshToken == "" {
		return false
	}
	fingerprint := RefreshTokenFingerprint(refreshToken)
	cfgLock.RLock()
	defer cfgLock.RUnlock()
	for _, account := range cfg.Accounts {
		if account.RefreshToken == refreshToken ||
			(fingerprint != "" && account.RefreshTokenFingerprint == fingerprint) {
			return true
		}
	}
	return false
}

// AccountAPIKeyExists reports whether a Kiro API key is already persisted.
func AccountAPIKeyExists(apiKey string) bool {
	apiKey = strings.TrimSpace(apiKey)
	if apiKey == "" {
		return false
	}
	fingerprint := APIKeyFingerprint(apiKey)
	cfgLock.RLock()
	defer cfgLock.RUnlock()
	for _, account := range cfg.Accounts {
		existing := strings.TrimSpace(account.KiroApiKey)
		if existing == "" {
			continue
		}
		if existing == apiKey || APIKeyFingerprint(existing) == fingerprint {
			return true
		}
	}
	return false
}

// AccountIDExists reports whether an account ID is already persisted.
func AccountIDExists(id string) bool {
	if id == "" {
		return false
	}
	cfgLock.RLock()
	defer cfgLock.RUnlock()
	for _, account := range cfg.Accounts {
		if account.ID == id {
			return true
		}
	}
	return false
}

func AddAccount(account Account) error {
	cfgLock.Lock()
	defer cfgLock.Unlock()
	if IsAPIKeyAccount(&account) {
		if err := NormalizeAPIKeyAccount(&account); err != nil {
			return err
		}
	} else if account.RefreshTokenFingerprint == "" {
		account.RefreshTokenFingerprint = RefreshTokenFingerprint(account.RefreshToken)
	}
	for _, existing := range cfg.Accounts {
		if account.ID != "" && existing.ID == account.ID {
			return ErrDuplicateAccountID
		}
		if account.RefreshToken != "" && existing.RefreshToken == account.RefreshToken {
			return ErrDuplicateRefreshToken
		}
		existingFingerprint := existing.RefreshTokenFingerprint
		if existingFingerprint == "" {
			existingFingerprint = RefreshTokenFingerprint(existing.RefreshToken)
		}
		if account.RefreshTokenFingerprint != "" &&
			existingFingerprint == account.RefreshTokenFingerprint {
			return ErrDuplicateRefreshToken
		}
		if account.KiroApiKey != "" {
			existingKey := strings.TrimSpace(existing.KiroApiKey)
			if existingKey != "" && (existingKey == account.KiroApiKey ||
				APIKeyFingerprint(existingKey) == APIKeyFingerprint(account.KiroApiKey)) {
				return ErrDuplicateAPIKey
			}
		}
	}
	cfg.Accounts = append(cfg.Accounts, account)
	if err := Save(); err != nil {
		cfg.Accounts = cfg.Accounts[:len(cfg.Accounts)-1]
		return err
	}
	return nil
}

func UpdateAccount(id string, account Account) error {
	cfgLock.Lock()
	defer cfgLock.Unlock()
	for i, a := range cfg.Accounts {
		if a.ID == id {
			// Current callers use UpdateAccount for administrative/status fields.
			// Preserve the authoritative credential state so a stale account
			// snapshot cannot overwrite a refresh-token rotation that completed
			// while an upstream status request was in flight.
			account.AccessToken = a.AccessToken
			account.RefreshToken = a.RefreshToken
			account.RefreshTokenFingerprint = a.RefreshTokenFingerprint
			account.KiroApiKey = a.KiroApiKey
			account.ClientID = a.ClientID
			account.ClientSecret = a.ClientSecret
			account.AuthMethod = a.AuthMethod
			account.Provider = a.Provider
			account.Region = a.Region
			account.StartUrl = a.StartUrl
			account.ExpiresAt = a.ExpiresAt
			account.ProfileArn = a.ProfileArn
			account.TokenEndpoint = a.TokenEndpoint
			account.IssuerURL = a.IssuerURL
			account.Scopes = a.Scopes
			if account.RefreshTokenFingerprint == "" {
				account.RefreshTokenFingerprint = RefreshTokenFingerprint(a.RefreshToken)
			}
			previous := cfg.Accounts[i]
			cfg.Accounts[i] = account
			if err := Save(); err != nil {
				cfg.Accounts[i] = previous
				return err
			}
			return nil
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
			previous := cfg.Accounts[i]
			cfg.Accounts[i].Enabled = enabled
			if !enabled {
				cfg.Accounts[i].BanStatus = "DISABLED"
				cfg.Accounts[i].BanTime = time.Now().Unix()
			}
			if err := Save(); err != nil {
				cfg.Accounts[i] = previous
				return err
			}
			return nil
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
			previous := cfg.Accounts[i]
			cfg.Accounts[i].BanStatus = status
			cfg.Accounts[i].BanReason = reason
			cfg.Accounts[i].BanTime = time.Now().Unix()
			if status == "BANNED" || status == "DISABLED" {
				cfg.Accounts[i].Enabled = false
			}
			if err := Save(); err != nil {
				cfg.Accounts[i] = previous
				return err
			}
			return nil
		}
	}
	return nil
}

// ClearAccountBanStatus marks an account active without replacing any
// credential fields from a potentially stale caller snapshot.
func ClearAccountBanStatus(id string) error {
	cfgLock.Lock()
	defer cfgLock.Unlock()
	for i, account := range cfg.Accounts {
		if account.ID == id {
			previous := cfg.Accounts[i]
			cfg.Accounts[i].BanStatus = "ACTIVE"
			cfg.Accounts[i].BanReason = ""
			cfg.Accounts[i].BanTime = 0
			if err := Save(); err != nil {
				cfg.Accounts[i] = previous
				return err
			}
			return nil
		}
	}
	return nil
}

func UpdateAccountProfileArn(id, profileArn string) error {
	cfgLock.Lock()
	defer cfgLock.Unlock()
	for i, a := range cfg.Accounts {
		if a.ID == id {
			previous := cfg.Accounts[i].ProfileArn
			cfg.Accounts[i].ProfileArn = profileArn
			if err := Save(); err != nil {
				cfg.Accounts[i].ProfileArn = previous
				return err
			}
			return nil
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
	return UpdateAccountCredentialState(id, accessToken, refreshToken, expiresAt, "")
}

// UpdateAccountCredentialState atomically updates all fields produced by one
// refresh-token exchange. If persistence fails, the in-memory configuration is
// restored so a rotated token is never published from a state that cannot
// survive restart.
func UpdateAccountCredentialState(
	id string,
	accessToken string,
	refreshToken string,
	expiresAt int64,
	profileArn string,
) error {
	cfgLock.Lock()
	defer cfgLock.Unlock()
	for i, a := range cfg.Accounts {
		if a.ID == id {
			previous := cfg.Accounts[i]
			if cfg.Accounts[i].RefreshTokenFingerprint == "" {
				cfg.Accounts[i].RefreshTokenFingerprint = RefreshTokenFingerprint(a.RefreshToken)
			}
			cfg.Accounts[i].AccessToken = accessToken
			if refreshToken != "" {
				cfg.Accounts[i].RefreshToken = refreshToken
			}
			cfg.Accounts[i].ExpiresAt = expiresAt
			if profileArn != "" {
				cfg.Accounts[i].ProfileArn = profileArn
			}
			if err := Save(); err != nil {
				cfg.Accounts[i] = previous
				return err
			}
			return nil
		}
	}
	return ErrAccountNotFound
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

const (
	maxModelMappings = 200
	maxModelIDLength = 256
)

// GetModelMappings returns a detached copy of the configured model mappings.
func GetModelMappings() []ModelMapping {
	cfgLock.RLock()
	defer cfgLock.RUnlock()
	if cfg == nil || len(cfg.ModelMappings) == 0 {
		return []ModelMapping{}
	}
	mappings := make([]ModelMapping, len(cfg.ModelMappings))
	copy(mappings, cfg.ModelMappings)
	return mappings
}

// ResolveModelMapping resolves a client model ID using an exact,
// case-insensitive match. Targets are returned as stored and are not remapped.
func ResolveModelMapping(model string) (string, bool) {
	model = strings.TrimSpace(model)
	if model == "" {
		return "", false
	}
	cfgLock.RLock()
	defer cfgLock.RUnlock()
	if cfg == nil {
		return "", false
	}
	for _, mapping := range cfg.ModelMappings {
		if strings.EqualFold(mapping.Source, model) {
			return mapping.Target, true
		}
	}
	return "", false
}

// UpdateModelMappings validates and atomically replaces all model mappings.
func UpdateModelMappings(mappings []ModelMapping) error {
	normalized, err := normalizeModelMappings(mappings)
	if err != nil {
		return err
	}
	cfgLock.Lock()
	defer cfgLock.Unlock()
	if cfg == nil {
		return fmt.Errorf("configuration is not initialized")
	}
	cfg.ModelMappings = normalized
	return Save()
}

func normalizeModelMappings(mappings []ModelMapping) ([]ModelMapping, error) {
	if len(mappings) > maxModelMappings {
		return nil, fmt.Errorf("%w: at most %d mappings are allowed", ErrInvalidModelMapping, maxModelMappings)
	}
	normalized := make([]ModelMapping, 0, len(mappings))
	sources := make([]string, 0, len(mappings))
	for i, mapping := range mappings {
		source := strings.TrimSpace(mapping.Source)
		target := strings.TrimSpace(mapping.Target)
		if source == "" || target == "" {
			return nil, fmt.Errorf("%w at index %d: source and target are required", ErrInvalidModelMapping, i)
		}
		if !validModelMappingID(source) || !validModelMappingID(target) {
			return nil, fmt.Errorf("%w at index %d: model IDs must be at most %d bytes and contain no whitespace or control characters", ErrInvalidModelMapping, i, maxModelIDLength)
		}
		if strings.EqualFold(source, target) {
			return nil, fmt.Errorf("%w at index %d: source and target must differ", ErrInvalidModelMapping, i)
		}
		for _, existingSource := range sources {
			if strings.EqualFold(existingSource, source) {
				return nil, fmt.Errorf("%w at index %d: duplicate source %q", ErrInvalidModelMapping, i, source)
			}
		}
		sources = append(sources, source)
		normalized = append(normalized, ModelMapping{Source: source, Target: target})
	}
	for i, mapping := range normalized {
		for _, source := range sources {
			if strings.EqualFold(source, mapping.Target) {
				return nil, fmt.Errorf("%w at index %d: target %q is another mapping source; mappings must resolve in one hop", ErrInvalidModelMapping, i, mapping.Target)
			}
		}
	}
	return normalized, nil
}

func validModelMappingID(model string) bool {
	if len(model) > maxModelIDLength {
		return false
	}
	for _, r := range model {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return false
		}
	}
	return true
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

// GetLogLevel returns the configured log level (debug/info/warn/error). Defaults to "info".
func GetLogLevel() string {
	cfgLock.RLock()
	defer cfgLock.RUnlock()
	if cfg == nil || cfg.LogLevel == "" {
		return "info"
	}
	return cfg.LogLevel
}

// UpdateLogLevel updates the log level setting and persists the change.
func UpdateLogLevel(level string) error {
	cfgLock.Lock()
	defer cfgLock.Unlock()
	cfg.LogLevel = level
	return Save()
}

type KiroClientConfig struct {
	KiroVersion   string
	SystemVersion string
	NodeVersion   string
}

func GetKiroClientConfig() KiroClientConfig {
	cfgLock.RLock()
	defer cfgLock.RUnlock()

	kiroVersion := "0.11.107"
	if cfg != nil && cfg.KiroVersion != "" {
		kiroVersion = cfg.KiroVersion
	}

	systemVersion := ""
	if cfg != nil {
		systemVersion = cfg.SystemVersion
	}
	if systemVersion == "" {
		systemVersion = defaultSystemVersion()
	}

	nodeVersion := "22.22.0"
	if cfg != nil && cfg.NodeVersion != "" {
		nodeVersion = cfg.NodeVersion
	}

	return KiroClientConfig{
		KiroVersion:   kiroVersion,
		SystemVersion: systemVersion,
		NodeVersion:   nodeVersion,
	}
}

func defaultSystemVersion() string {
	switch runtime.GOOS {
	case "windows":
		return "win32#10.0.22631"
	case "darwin":
		return "darwin#24.6.0"
	default:
		return "linux#6.6.87"
	}
}
