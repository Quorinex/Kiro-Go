package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestUpdateSettingsPatchPreservesOmittedAPIKeyFields(t *testing.T) {
	if err := Init(filepath.Join(t.TempDir(), "config.json")); err != nil {
		t.Fatalf("init config: %v", err)
	}
	if err := UpdateSettings("proxy-api-key", true, "admin-password"); err != nil {
		t.Fatalf("seed settings: %v", err)
	}

	if err := UpdateSettingsPatch(nil, nil, "new-admin-password"); err != nil {
		t.Fatalf("patch settings: %v", err)
	}

	if got := GetApiKey(); got != "proxy-api-key" {
		t.Fatalf("expected API key to be preserved, got %q", got)
	}
	if !IsApiKeyRequired() {
		t.Fatalf("expected requireApiKey to stay enabled")
	}
	if got := GetPassword(); got != "new-admin-password" {
		t.Fatalf("expected password to update, got %q", got)
	}
}

func TestUpdateSettingsPatchCanExplicitlyDisableAPIKey(t *testing.T) {
	if err := Init(filepath.Join(t.TempDir(), "config.json")); err != nil {
		t.Fatalf("init config: %v", err)
	}
	if err := UpdateSettings("proxy-api-key", true, "admin-password"); err != nil {
		t.Fatalf("seed settings: %v", err)
	}

	emptyKey := ""
	requireAPIKey := false
	if err := UpdateSettingsPatch(&emptyKey, &requireAPIKey, ""); err != nil {
		t.Fatalf("patch settings: %v", err)
	}

	if got := GetApiKey(); got != "" {
		t.Fatalf("expected API key to be cleared, got %q", got)
	}
	if IsApiKeyRequired() {
		t.Fatalf("expected requireApiKey to be disabled")
	}
	if got := GetPassword(); got != "admin-password" {
		t.Fatalf("expected password to be preserved, got %q", got)
	}
}

// TestAccountAllowOverageMigration verifies that a config.json from before the
// upstream-Overages-switch refactor (which carried `allowOverage: true` per
// account) is migrated into OverageStatus="ENABLED" on first load, and that
// the legacy field is cleared so future saves don't re-emit it.
func TestAccountAllowOverageMigration(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "config.json")

	seed := map[string]interface{}{
		"password":      "p",
		"port":          8080,
		"host":          "0.0.0.0",
		"requireApiKey": false,
		"accounts": []map[string]interface{}{
			{"id": "acc-allow", "enabled": true, "allowOverage": true},
			{"id": "acc-deny", "enabled": true, "allowOverage": false},
			{"id": "acc-already-set", "enabled": true, "allowOverage": true, "overageStatus": "DISABLED"},
		},
	}
	raw, err := json.MarshalIndent(seed, "", "  ")
	if err != nil {
		t.Fatalf("marshal seed: %v", err)
	}
	if err := os.WriteFile(cfgFile, raw, 0600); err != nil {
		t.Fatalf("write seed: %v", err)
	}

	if err := Init(cfgFile); err != nil {
		t.Fatalf("init: %v", err)
	}

	accounts := GetAccounts()
	byID := map[string]Account{}
	for _, a := range accounts {
		byID[a.ID] = a
	}

	if got := byID["acc-allow"].OverageStatus; got != "ENABLED" {
		t.Fatalf("expected acc-allow to migrate to OverageStatus=ENABLED, got %q", got)
	}
	if byID["acc-allow"].LegacyAllowOverage {
		t.Fatalf("expected legacy allowOverage to be cleared after migration")
	}
	if got := byID["acc-deny"].OverageStatus; got != "" {
		t.Fatalf("expected acc-deny to keep empty OverageStatus, got %q", got)
	}
	// Pre-set OverageStatus must win over the legacy field.
	if got := byID["acc-already-set"].OverageStatus; got != "DISABLED" {
		t.Fatalf("expected acc-already-set OverageStatus to be preserved, got %q", got)
	}
	if byID["acc-already-set"].LegacyAllowOverage {
		t.Fatalf("expected legacy field to still be cleared on acc-already-set")
	}

	// Re-read the file and confirm legacy field is gone (so it doesn't drift
	// back in on later saves).
	on_disk, err := os.ReadFile(cfgFile)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	var reloaded struct {
		Accounts []map[string]interface{} `json:"accounts"`
	}
	if err := json.Unmarshal(on_disk, &reloaded); err != nil {
		t.Fatalf("decode reload: %v", err)
	}
	for _, a := range reloaded.Accounts {
		if _, ok := a["allowOverage"]; ok {
			t.Fatalf("expected allowOverage to be omitted from persisted file, got %+v", a)
		}
	}
}

func TestIsApiKeyCredential(t *testing.T) {
	cases := []struct {
		name string
		a    Account
		want bool
	}{
		{"key present", Account{KiroApiKey: "k"}, true},
		{"api_key lower", Account{AuthMethod: "api_key"}, true},
		{"apikey lower", Account{AuthMethod: "apikey"}, true},
		{"API_KEY upper", Account{AuthMethod: "API_KEY"}, true},
		{"key wins over idc", Account{KiroApiKey: "k", AuthMethod: "idc"}, true},
		{"idc not api key", Account{AuthMethod: "idc"}, false},
		{"external_idp not api key", Account{AuthMethod: "external_idp"}, false},
		{"empty", Account{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.a.IsApiKeyCredential(); got != tc.want {
				t.Fatalf("IsApiKeyCredential() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestEffectiveRegionsFallbackChain(t *testing.T) {
	if err := Init(filepath.Join(t.TempDir(), "config.json")); err != nil {
		t.Fatalf("init: %v", err)
	}

	// account-level wins
	a := &Account{AuthRegion: "eu-west-1", ApiRegion: "ap-southeast-1", Region: "us-west-2"}
	if got := a.EffectiveAuthRegion(); got != "eu-west-1" {
		t.Fatalf("auth: want eu-west-1, got %q", got)
	}
	if got := a.EffectiveApiRegion(); got != "ap-southeast-1" {
		t.Fatalf("api: want ap-southeast-1, got %q", got)
	}

	// falls back to Region
	b := &Account{Region: "us-west-2"}
	if got := b.EffectiveAuthRegion(); got != "us-west-2" {
		t.Fatalf("auth fallback: want us-west-2, got %q", got)
	}
	if got := b.EffectiveApiRegion(); got != "us-west-2" {
		t.Fatalf("api fallback: want us-west-2, got %q", got)
	}

	// empty account → default us-east-1
	c := &Account{}
	if got := c.EffectiveAuthRegion(); got != "us-east-1" {
		t.Fatalf("auth default: want us-east-1, got %q", got)
	}
	if got := c.EffectiveApiRegion(); got != "us-east-1" {
		t.Fatalf("api default: want us-east-1, got %q", got)
	}
}

func TestMaxPayloadBytesDefaultFallbackAndPersist(t *testing.T) {
	if err := Init(filepath.Join(t.TempDir(), "config.json")); err != nil {
		t.Fatalf("init: %v", err)
	}
	if got := GetMaxPayloadBytes(); got != DefaultMaxPayloadBytes {
		t.Fatalf("default: want %d, got %d", DefaultMaxPayloadBytes, got)
	}
	if err := UpdateMaxPayloadBytes(2100000); err != nil {
		t.Fatalf("update: %v", err)
	}
	if got := GetMaxPayloadBytes(); got != 2100000 {
		t.Fatalf("after set: want 2100000, got %d", got)
	}
}
