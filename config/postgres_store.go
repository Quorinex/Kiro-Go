package config

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type postgresStore struct {
	pool          *pgxpool.Pool
	migrationPath string
}

var settingsColumns = []string{
	"id",
	"password",
	"port",
	"host",
	"api_key",
	"require_api_key",
	"kiro_version",
	"system_version",
	"node_version",
	"thinking_suffix",
	"openai_thinking_format",
	"claude_thinking_format",
	"preferred_endpoint",
	"endpoint_fallback",
	"allow_over_usage",
	"proxy_url",
	"sanitize_claude_code_prompt",
	"filter_claude_code",
	"filter_env_noise",
	"filter_strip_boundaries",
	"log_level",
	"total_requests",
	"success_requests",
	"failed_requests",
	"total_tokens",
	"total_credits",
}

var accountColumns = []string{
	"id",
	"email",
	"user_id",
	"nickname",
	"access_token",
	"refresh_token",
	"client_id",
	"client_secret",
	"auth_method",
	"provider",
	"region",
	"start_url",
	"expires_at",
	"machine_id",
	"profile_arn",
	"proxy_url",
	"weight",
	"allow_overage",
	"overage_weight",
	"enabled",
	"ban_status",
	"ban_reason",
	"ban_time",
	"subscription_type",
	"subscription_title",
	"days_remaining",
	"usage_current",
	"usage_limit",
	"usage_percent",
	"next_reset_date",
	"last_refresh",
	"trial_usage_current",
	"trial_usage_limit",
	"trial_usage_percent",
	"trial_status",
	"trial_expires_at",
	"request_count",
	"error_count",
	"last_used",
	"total_tokens",
	"total_credits",
}

var promptFilterRuleColumns = []string{
	"id",
	"name",
	"type",
	"match_text",
	"replace_text",
	"enabled",
	"position",
}

func init() {
	RegisterStoreBackend("postgres", openPostgresStore)
	RegisterStoreBackend("postgresql", openPostgresStore)
}

func openPostgresStore(ctx context.Context, configPath, databaseURL string) (Store, error) {
	return NewPostgresStore(ctx, databaseURL, configPath)
}

func NewPostgresStore(ctx context.Context, databaseURL, migrationPath string) (Store, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return &postgresStore{pool: pool, migrationPath: migrationPath}, nil
}

func (s *postgresStore) Name() string {
	return "postgres"
}

func (s *postgresStore) Load(ctx context.Context) (*Config, error) {
	if err := s.ensureSchema(ctx); err != nil {
		return nil, err
	}

	empty, err := s.isEmpty(ctx)
	if err != nil {
		return nil, err
	}
	if empty {
		initial := defaultConfig()
		if migrated, exists, err := loadJSONConfigIfExists(s.migrationPath); err != nil {
			return nil, err
		} else if exists {
			initial = migrated
		}
		if err := s.Save(ctx, initial); err != nil {
			return nil, err
		}
	}

	return s.loadConfig(ctx)
}

func (s *postgresStore) Save(ctx context.Context, cfg *Config) error {
	if err := s.ensureSchema(ctx); err != nil {
		return err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, upsertSQL("app_settings", settingsColumns, "id"), settingsArgs(cfg)...); err != nil {
		return err
	}

	if _, err := tx.Exec(ctx, "DELETE FROM accounts"); err != nil {
		return err
	}
	accountSQL := insertSQL("accounts", accountColumns)
	for _, account := range cfg.Accounts {
		if _, err := tx.Exec(ctx, accountSQL, accountArgs(account)...); err != nil {
			return err
		}
	}

	if _, err := tx.Exec(ctx, "DELETE FROM prompt_filter_rules"); err != nil {
		return err
	}
	ruleSQL := insertSQL("prompt_filter_rules", promptFilterRuleColumns)
	for i, rule := range cfg.PromptFilterRules {
		if _, err := tx.Exec(ctx, ruleSQL, promptFilterRuleArgs(rule, i)...); err != nil {
			return err
		}
	}

	return tx.Commit(ctx)
}

func (s *postgresStore) Close() error {
	if s.pool != nil {
		s.pool.Close()
	}
	return nil
}

func (s *postgresStore) ensureSchema(ctx context.Context) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS app_settings (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			password TEXT NOT NULL DEFAULT '',
			port INTEGER NOT NULL DEFAULT 0,
			host TEXT NOT NULL DEFAULT '',
			api_key TEXT NOT NULL DEFAULT '',
			require_api_key BOOLEAN NOT NULL DEFAULT false,
			kiro_version TEXT NOT NULL DEFAULT '',
			system_version TEXT NOT NULL DEFAULT '',
			node_version TEXT NOT NULL DEFAULT '',
			thinking_suffix TEXT NOT NULL DEFAULT '',
			openai_thinking_format TEXT NOT NULL DEFAULT '',
			claude_thinking_format TEXT NOT NULL DEFAULT '',
			preferred_endpoint TEXT NOT NULL DEFAULT '',
			endpoint_fallback BOOLEAN,
			allow_over_usage BOOLEAN NOT NULL DEFAULT false,
			proxy_url TEXT NOT NULL DEFAULT '',
			sanitize_claude_code_prompt BOOLEAN NOT NULL DEFAULT false,
			filter_claude_code BOOLEAN NOT NULL DEFAULT false,
			filter_env_noise BOOLEAN NOT NULL DEFAULT false,
			filter_strip_boundaries BOOLEAN NOT NULL DEFAULT false,
			log_level TEXT NOT NULL DEFAULT '',
			total_requests INTEGER NOT NULL DEFAULT 0,
			success_requests INTEGER NOT NULL DEFAULT 0,
			failed_requests INTEGER NOT NULL DEFAULT 0,
			total_tokens INTEGER NOT NULL DEFAULT 0,
			total_credits DOUBLE PRECISION NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS accounts (
			id TEXT PRIMARY KEY,
			email TEXT NOT NULL DEFAULT '',
			user_id TEXT NOT NULL DEFAULT '',
			nickname TEXT NOT NULL DEFAULT '',
			access_token TEXT NOT NULL DEFAULT '',
			refresh_token TEXT NOT NULL DEFAULT '',
			client_id TEXT NOT NULL DEFAULT '',
			client_secret TEXT NOT NULL DEFAULT '',
			auth_method TEXT NOT NULL DEFAULT '',
			provider TEXT NOT NULL DEFAULT '',
			region TEXT NOT NULL DEFAULT '',
			start_url TEXT NOT NULL DEFAULT '',
			expires_at BIGINT NOT NULL DEFAULT 0,
			machine_id TEXT NOT NULL DEFAULT '',
			profile_arn TEXT NOT NULL DEFAULT '',
			proxy_url TEXT NOT NULL DEFAULT '',
			weight INTEGER NOT NULL DEFAULT 0,
			allow_overage BOOLEAN NOT NULL DEFAULT false,
			overage_weight INTEGER NOT NULL DEFAULT 0,
			enabled BOOLEAN NOT NULL DEFAULT false,
			ban_status TEXT NOT NULL DEFAULT '',
			ban_reason TEXT NOT NULL DEFAULT '',
			ban_time BIGINT NOT NULL DEFAULT 0,
			subscription_type TEXT NOT NULL DEFAULT '',
			subscription_title TEXT NOT NULL DEFAULT '',
			days_remaining INTEGER NOT NULL DEFAULT 0,
			usage_current DOUBLE PRECISION NOT NULL DEFAULT 0,
			usage_limit DOUBLE PRECISION NOT NULL DEFAULT 0,
			usage_percent DOUBLE PRECISION NOT NULL DEFAULT 0,
			next_reset_date TEXT NOT NULL DEFAULT '',
			last_refresh BIGINT NOT NULL DEFAULT 0,
			trial_usage_current DOUBLE PRECISION NOT NULL DEFAULT 0,
			trial_usage_limit DOUBLE PRECISION NOT NULL DEFAULT 0,
			trial_usage_percent DOUBLE PRECISION NOT NULL DEFAULT 0,
			trial_status TEXT NOT NULL DEFAULT '',
			trial_expires_at BIGINT NOT NULL DEFAULT 0,
			request_count INTEGER NOT NULL DEFAULT 0,
			error_count INTEGER NOT NULL DEFAULT 0,
			last_used BIGINT NOT NULL DEFAULT 0,
			total_tokens INTEGER NOT NULL DEFAULT 0,
			total_credits DOUBLE PRECISION NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS prompt_filter_rules (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL DEFAULT '',
			type TEXT NOT NULL DEFAULT '',
			match_text TEXT NOT NULL DEFAULT '',
			replace_text TEXT NOT NULL DEFAULT '',
			enabled BOOLEAN NOT NULL DEFAULT false,
			position INTEGER NOT NULL DEFAULT 0
		)`,
	}

	for _, statement := range statements {
		if _, err := s.pool.Exec(ctx, statement); err != nil {
			return err
		}
	}
	return nil
}

func (s *postgresStore) isEmpty(ctx context.Context) (bool, error) {
	var count int
	err := s.pool.QueryRow(ctx, `
		SELECT
			(SELECT COUNT(*) FROM app_settings) +
			(SELECT COUNT(*) FROM accounts) +
			(SELECT COUNT(*) FROM prompt_filter_rules)
	`).Scan(&count)
	return count == 0, err
}

func (s *postgresStore) loadConfig(ctx context.Context) (*Config, error) {
	cfg := defaultConfig()

	var endpointFallback sql.NullBool
	err := s.pool.QueryRow(ctx, `SELECT `+strings.Join(settingsColumns[1:], ", ")+` FROM app_settings WHERE id = 1`).Scan(
		&cfg.Password,
		&cfg.Port,
		&cfg.Host,
		&cfg.ApiKey,
		&cfg.RequireApiKey,
		&cfg.KiroVersion,
		&cfg.SystemVersion,
		&cfg.NodeVersion,
		&cfg.ThinkingSuffix,
		&cfg.OpenAIThinkingFormat,
		&cfg.ClaudeThinkingFormat,
		&cfg.PreferredEndpoint,
		&endpointFallback,
		&cfg.AllowOverUsage,
		&cfg.ProxyURL,
		&cfg.SanitizeClaudeCodePrompt,
		&cfg.FilterClaudeCode,
		&cfg.FilterEnvNoise,
		&cfg.FilterStripBoundaries,
		&cfg.LogLevel,
		&cfg.TotalRequests,
		&cfg.SuccessRequests,
		&cfg.FailedRequests,
		&cfg.TotalTokens,
		&cfg.TotalCredits,
	)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	if endpointFallback.Valid {
		cfg.EndpointFallback = &endpointFallback.Bool
	}

	accounts, err := s.loadAccounts(ctx)
	if err != nil {
		return nil, err
	}
	cfg.Accounts = accounts

	rules, err := s.loadPromptFilterRules(ctx)
	if err != nil {
		return nil, err
	}
	cfg.PromptFilterRules = rules

	return normalizeConfig(cfg), nil
}

func (s *postgresStore) loadAccounts(ctx context.Context) ([]Account, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+strings.Join(accountColumns, ", ")+` FROM accounts ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	accounts := []Account{}
	for rows.Next() {
		var account Account
		if err := rows.Scan(
			&account.ID,
			&account.Email,
			&account.UserId,
			&account.Nickname,
			&account.AccessToken,
			&account.RefreshToken,
			&account.ClientID,
			&account.ClientSecret,
			&account.AuthMethod,
			&account.Provider,
			&account.Region,
			&account.StartUrl,
			&account.ExpiresAt,
			&account.MachineId,
			&account.ProfileArn,
			&account.ProxyURL,
			&account.Weight,
			&account.AllowOverage,
			&account.OverageWeight,
			&account.Enabled,
			&account.BanStatus,
			&account.BanReason,
			&account.BanTime,
			&account.SubscriptionType,
			&account.SubscriptionTitle,
			&account.DaysRemaining,
			&account.UsageCurrent,
			&account.UsageLimit,
			&account.UsagePercent,
			&account.NextResetDate,
			&account.LastRefresh,
			&account.TrialUsageCurrent,
			&account.TrialUsageLimit,
			&account.TrialUsagePercent,
			&account.TrialStatus,
			&account.TrialExpiresAt,
			&account.RequestCount,
			&account.ErrorCount,
			&account.LastUsed,
			&account.TotalTokens,
			&account.TotalCredits,
		); err != nil {
			return nil, err
		}
		accounts = append(accounts, account)
	}
	return accounts, rows.Err()
}

func (s *postgresStore) loadPromptFilterRules(ctx context.Context) ([]PromptFilterRule, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, name, type, match_text, replace_text, enabled FROM prompt_filter_rules ORDER BY position, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	rules := []PromptFilterRule{}
	for rows.Next() {
		var rule PromptFilterRule
		if err := rows.Scan(&rule.ID, &rule.Name, &rule.Type, &rule.Match, &rule.Replace, &rule.Enabled); err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return rules, rows.Err()
}

func settingsArgs(cfg *Config) []interface{} {
	var endpointFallback interface{}
	if cfg.EndpointFallback != nil {
		endpointFallback = *cfg.EndpointFallback
	}
	return []interface{}{
		1,
		cfg.Password,
		cfg.Port,
		cfg.Host,
		cfg.ApiKey,
		cfg.RequireApiKey,
		cfg.KiroVersion,
		cfg.SystemVersion,
		cfg.NodeVersion,
		cfg.ThinkingSuffix,
		cfg.OpenAIThinkingFormat,
		cfg.ClaudeThinkingFormat,
		cfg.PreferredEndpoint,
		endpointFallback,
		cfg.AllowOverUsage,
		cfg.ProxyURL,
		cfg.SanitizeClaudeCodePrompt,
		cfg.FilterClaudeCode,
		cfg.FilterEnvNoise,
		cfg.FilterStripBoundaries,
		cfg.LogLevel,
		cfg.TotalRequests,
		cfg.SuccessRequests,
		cfg.FailedRequests,
		cfg.TotalTokens,
		cfg.TotalCredits,
	}
}

func accountArgs(account Account) []interface{} {
	return []interface{}{
		account.ID,
		account.Email,
		account.UserId,
		account.Nickname,
		account.AccessToken,
		account.RefreshToken,
		account.ClientID,
		account.ClientSecret,
		account.AuthMethod,
		account.Provider,
		account.Region,
		account.StartUrl,
		account.ExpiresAt,
		account.MachineId,
		account.ProfileArn,
		account.ProxyURL,
		account.Weight,
		account.AllowOverage,
		account.OverageWeight,
		account.Enabled,
		account.BanStatus,
		account.BanReason,
		account.BanTime,
		account.SubscriptionType,
		account.SubscriptionTitle,
		account.DaysRemaining,
		account.UsageCurrent,
		account.UsageLimit,
		account.UsagePercent,
		account.NextResetDate,
		account.LastRefresh,
		account.TrialUsageCurrent,
		account.TrialUsageLimit,
		account.TrialUsagePercent,
		account.TrialStatus,
		account.TrialExpiresAt,
		account.RequestCount,
		account.ErrorCount,
		account.LastUsed,
		account.TotalTokens,
		account.TotalCredits,
	}
}

func promptFilterRuleArgs(rule PromptFilterRule, position int) []interface{} {
	return []interface{}{
		rule.ID,
		rule.Name,
		rule.Type,
		rule.Match,
		rule.Replace,
		rule.Enabled,
		position,
	}
}

func insertSQL(table string, columns []string) string {
	return fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)", table, strings.Join(columns, ", "), placeholders(len(columns)))
}

func upsertSQL(table string, columns []string, conflictColumn string) string {
	assignments := make([]string, 0, len(columns)-1)
	for _, column := range columns {
		if column == conflictColumn {
			continue
		}
		assignments = append(assignments, fmt.Sprintf("%s = EXCLUDED.%s", column, column))
	}
	return fmt.Sprintf(
		"INSERT INTO %s (%s) VALUES (%s) ON CONFLICT (%s) DO UPDATE SET %s",
		table,
		strings.Join(columns, ", "),
		placeholders(len(columns)),
		conflictColumn,
		strings.Join(assignments, ", "),
	)
}

func placeholders(count int) string {
	values := make([]string, count)
	for i := 0; i < count; i++ {
		values[i] = fmt.Sprintf("$%d", i+1)
	}
	return strings.Join(values, ", ")
}
