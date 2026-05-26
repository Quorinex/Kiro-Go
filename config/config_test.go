package config

import (
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

func TestUpdateProxySettingsSupportsMultipleURLs(t *testing.T) {
	if err := Init(filepath.Join(t.TempDir(), "config.json")); err != nil {
		t.Fatalf("init config: %v", err)
	}

	proxies := []string{
		" socks5://user:pass@127.0.0.1:1080 ",
		"",
		"http://proxy.local:8080",
		"socks5://user:pass@127.0.0.1:1080",
	}
	if err := UpdateProxySettings(proxies); err != nil {
		t.Fatalf("update proxy settings: %v", err)
	}

	want := []string{
		"socks5://user:pass@127.0.0.1:1080",
		"http://proxy.local:8080",
	}
	got := GetProxyURLs()
	if len(got) != len(want) {
		t.Fatalf("expected %d proxies, got %d: %#v", len(want), len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("proxy %d: expected %q, got %q", i, want[i], got[i])
		}
	}
	if got := GetProxyURL(); got != want[0] {
		t.Fatalf("expected legacy proxy URL %q, got %q", want[0], got)
	}
	if got := []string{GetNextProxyURL(), GetNextProxyURL(), GetNextProxyURL()}; got[0] != want[0] || got[1] != want[1] || got[2] != want[0] {
		t.Fatalf("unexpected round-robin order: %#v", got)
	}
}
