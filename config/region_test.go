package config

import (
	"path/filepath"
	"testing"
)

func TestIsApiKeyCredential(t *testing.T) {
	tests := []struct {
		name     string
		account  Account
		expected bool
	}{
		{
			name:     "account with kiroApiKey is api_key",
			account:  Account{KiroApiKey: "ksk_abc123"},
			expected: true,
		},
		{
			name:     "account with authMethod api_key is api_key",
			account:  Account{AuthMethod: "api_key"},
			expected: true,
		},
		{
			name:     "account with authMethod apikey (lowercase) is api_key",
			account:  Account{AuthMethod: "apikey"},
			expected: true,
		},
		{
			name:     "account with authMethod APIKEY (uppercase) is api_key",
			account:  Account{AuthMethod: "APIKEY"},
			expected: true,
		},
		{
			name:     "account with authMethod API_KEY (uppercase) is api_key",
			account:  Account{AuthMethod: "API_KEY"},
			expected: true,
		},
		{
			name:     "oauth account with idc is not api_key",
			account:  Account{AuthMethod: "idc", AccessToken: "token"},
			expected: false,
		},
		{
			name:     "oauth account with social is not api_key",
			account:  Account{AuthMethod: "social", AccessToken: "token"},
			expected: false,
		},
		{
			name:     "empty account is not api_key",
			account:  Account{},
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.account.IsApiKeyCredential()
			if got != tc.expected {
				t.Fatalf("IsApiKeyCredential() = %v, want %v", got, tc.expected)
			}
		})
	}
}

func TestEffectiveApiRegion(t *testing.T) {
	tests := []struct {
		name             string
		accountApiRegion string
		accountRegion    string
		globalApiRegion  string
		globalRegion     string
		expected         string
	}{
		{
			name:             "account apiRegion wins",
			accountApiRegion: "eu-central-1",
			accountRegion:    "eu-west-1",
			globalApiRegion:  "ap-southeast-1",
			globalRegion:     "us-west-2",
			expected:         "eu-central-1",
		},
		{
			name:             "account region used when apiRegion empty",
			accountApiRegion: "",
			accountRegion:    "eu-west-1",
			globalApiRegion:  "ap-southeast-1",
			globalRegion:     "us-west-2",
			expected:         "eu-west-1",
		},
		{
			name:             "global apiRegion used when account regions empty",
			accountApiRegion: "",
			accountRegion:    "",
			globalApiRegion:  "ap-southeast-1",
			globalRegion:     "us-west-2",
			expected:         "ap-southeast-1",
		},
		{
			name:             "global region used when account/global apiRegion empty",
			accountApiRegion: "",
			accountRegion:    "",
			globalApiRegion:  "",
			globalRegion:     "us-west-2",
			expected:         "us-west-2",
		},
		{
			name:             "default us-east-1 when all empty",
			accountApiRegion: "",
			accountRegion:    "",
			globalApiRegion:  "",
			globalRegion:     "",
			expected:         "us-east-1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Init config with test values
			tmpDir := t.TempDir()
			if err := Init(filepath.Join(tmpDir, "config.json")); err != nil {
				t.Fatalf("init config: %v", err)
			}

			// Set global regions if provided
			if tc.globalApiRegion != "" || tc.globalRegion != "" {
				cfg.ApiRegion = tc.globalApiRegion
				cfg.Region = tc.globalRegion
			}

			// Create account and test
			account := Account{
				ApiRegion: tc.accountApiRegion,
				Region:    tc.accountRegion,
			}

			got := account.EffectiveApiRegion()
			if got != tc.expected {
				t.Fatalf("EffectiveApiRegion() = %s, want %s", got, tc.expected)
			}
		})
	}
}

func TestEffectiveAuthRegion(t *testing.T) {
	tests := []struct {
		name             string
		accountAuthRegion string
		accountRegion     string
		globalAuthRegion  string
		globalRegion      string
		expected          string
	}{
		{
			name:             "account authRegion wins",
			accountAuthRegion: "eu-west-1",
			accountRegion:     "eu-central-1",
			globalAuthRegion:  "ap-southeast-1",
			globalRegion:      "us-west-2",
			expected:          "eu-west-1",
		},
		{
			name:             "account region used when authRegion empty",
			accountAuthRegion: "",
			accountRegion:     "eu-central-1",
			globalAuthRegion:  "ap-southeast-1",
			globalRegion:      "us-west-2",
			expected:          "eu-central-1",
		},
		{
			name:             "global authRegion used when account regions empty",
			accountAuthRegion: "",
			accountRegion:     "",
			globalAuthRegion:  "ap-southeast-1",
			globalRegion:      "us-west-2",
			expected:          "ap-southeast-1",
		},
		{
			name:             "global region used when account/global authRegion empty",
			accountAuthRegion: "",
			accountRegion:     "",
			globalAuthRegion:  "",
			globalRegion:      "us-west-2",
			expected:          "us-west-2",
		},
		{
			name:             "default us-east-1 when all empty",
			accountAuthRegion: "",
			accountRegion:     "",
			globalAuthRegion:  "",
			globalRegion:      "",
			expected:          "us-east-1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Init config with test values
			tmpDir := t.TempDir()
			if err := Init(filepath.Join(tmpDir, "config.json")); err != nil {
				t.Fatalf("init config: %v", err)
			}

			// Set global regions if provided
			if tc.globalAuthRegion != "" || tc.globalRegion != "" {
				cfg.AuthRegion = tc.globalAuthRegion
				cfg.Region = tc.globalRegion
			}

			// Create account and test
			account := Account{
				AuthRegion: tc.accountAuthRegion,
				Region:     tc.accountRegion,
			}

			got := account.EffectiveAuthRegion()
			if got != tc.expected {
				t.Fatalf("EffectiveAuthRegion() = %s, want %s", got, tc.expected)
			}
		})
	}
}
