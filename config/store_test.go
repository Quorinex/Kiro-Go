package config

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestJSONStoreCreatesDefaultConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	store := NewJSONStore(path)

	got, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.Password != "changeme" {
		t.Fatalf("expected default password, got %q", got.Password)
	}
	if got.Port != 8080 {
		t.Fatalf("expected default port 8080, got %d", got.Port)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected config file to be created: %v", err)
	}
}

func TestOpenStoreFromEnvAutoFallsBackToJSON(t *testing.T) {
	t.Setenv("STORE_BACKEND", "")
	t.Setenv("DATABASE_URL", "")

	store, err := OpenStoreFromEnv(context.Background(), filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatalf("OpenStoreFromEnv: %v", err)
	}
	defer store.Close()

	if store.Name() != "json" {
		t.Fatalf("expected json store, got %q", store.Name())
	}
}

func TestOpenStoreFromEnvRequiresDatabaseURLForPostgres(t *testing.T) {
	t.Setenv("STORE_BACKEND", "postgres")
	t.Setenv("DATABASE_URL", "")

	_, err := OpenStoreFromEnv(context.Background(), filepath.Join(t.TempDir(), "config.json"))
	if err == nil {
		t.Fatal("expected error for missing DATABASE_URL")
	}
}

func TestOpenStoreFromEnvRejectsUnknownDatabaseURLScheme(t *testing.T) {
	t.Setenv("STORE_BACKEND", "auto")
	t.Setenv("DATABASE_URL", "mysql://user:pass@localhost/db")

	_, err := OpenStoreFromEnv(context.Background(), filepath.Join(t.TempDir(), "config.json"))
	if err == nil {
		t.Fatal("expected error for unsupported DATABASE_URL scheme")
	}
}

func TestPostgresStoreMigratesJSONAndPersists(t *testing.T) {
	dsn := os.Getenv("POSTGRES_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set POSTGRES_TEST_DATABASE_URL to run PostgreSQL integration test")
	}

	ctx := context.Background()
	configPath := filepath.Join(t.TempDir(), "config.json")
	fallback := false
	initial := &Config{
		Password:         "secret",
		Port:             9090,
		Host:             "127.0.0.1",
		ApiKey:           "api-key",
		RequireApiKey:    true,
		EndpointFallback: &fallback,
		PromptFilterRules: []PromptFilterRule{{
			ID:      "rule-1",
			Name:    "Strip",
			Type:    "lines-containing",
			Match:   "noise",
			Enabled: true,
		}},
		Accounts: []Account{{
			ID:           "acct-1",
			Email:        "user@example.com",
			AccessToken:  "access",
			RefreshToken: "refresh",
			Enabled:      true,
			UsageCurrent: 7,
			UsageLimit:   10,
		}},
	}
	data, err := json.Marshal(initial)
	if err != nil {
		t.Fatalf("marshal initial config: %v", err)
	}
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatalf("write initial config: %v", err)
	}

	store, err := NewPostgresStore(ctx, dsn, configPath)
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}
	ps := store.(*postgresStore)
	defer ps.Close()
	defer ps.pool.Exec(ctx, "DROP TABLE IF EXISTS prompt_filter_rules, accounts, app_settings")
	if _, err := ps.pool.Exec(ctx, "DROP TABLE IF EXISTS prompt_filter_rules, accounts, app_settings"); err != nil {
		t.Fatalf("drop existing test tables: %v", err)
	}

	loaded, err := ps.Load(ctx)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.Password != initial.Password || loaded.Port != initial.Port {
		t.Fatalf("expected migrated settings, got password=%q port=%d", loaded.Password, loaded.Port)
	}
	if loaded.EndpointFallback == nil || *loaded.EndpointFallback != false {
		t.Fatal("expected migrated endpointFallback=false")
	}
	if len(loaded.Accounts) != 1 || loaded.Accounts[0].Email != "user@example.com" {
		t.Fatalf("expected migrated account, got %#v", loaded.Accounts)
	}
	if len(loaded.PromptFilterRules) != 1 || loaded.PromptFilterRules[0].Match != "noise" {
		t.Fatalf("expected migrated prompt filter rule, got %#v", loaded.PromptFilterRules)
	}

	loaded.ApiKey = "updated"
	loaded.Accounts[0].TotalTokens = 123
	if err := ps.Save(ctx, loaded); err != nil {
		t.Fatalf("Save: %v", err)
	}
	reloaded, err := ps.Load(ctx)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if reloaded.ApiKey != "updated" || reloaded.Accounts[0].TotalTokens != 123 {
		t.Fatalf("expected persisted updates, got apiKey=%q totalTokens=%d", reloaded.ApiKey, reloaded.Accounts[0].TotalTokens)
	}
}
