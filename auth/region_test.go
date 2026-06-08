package auth

import (
	"testing"
)

func TestOIDCTokenURL(t *testing.T) {
	tests := []struct {
		region   string
		expected string
	}{
		{region: "us-east-1", expected: "https://oidc.us-east-1.amazonaws.com/token"},
		{region: "eu-west-1", expected: "https://oidc.eu-west-1.amazonaws.com/token"},
		{region: "ap-southeast-1", expected: "https://oidc.ap-southeast-1.amazonaws.com/token"},
		{region: "", expected: "https://oidc.us-east-1.amazonaws.com/token"},
	}

	for _, tc := range tests {
		t.Run(tc.region, func(t *testing.T) {
			got := oidcTokenURL(tc.region)
			if got != tc.expected {
				t.Fatalf("oidcTokenURL(%q) = %s, want %s", tc.region, got, tc.expected)
			}
		})
	}
}

func TestSocialTokenURL(t *testing.T) {
	tests := []struct {
		region   string
		expected string
	}{
		{region: "us-east-1", expected: "https://prod.us-east-1.auth.desktop.kiro.dev/refreshToken"},
		{region: "eu-west-1", expected: "https://prod.eu-west-1.auth.desktop.kiro.dev/refreshToken"},
		{region: "ap-southeast-1", expected: "https://prod.ap-southeast-1.auth.desktop.kiro.dev/refreshToken"},
		{region: "", expected: "https://prod.us-east-1.auth.desktop.kiro.dev/refreshToken"},
	}

	for _, tc := range tests {
		t.Run(tc.region, func(t *testing.T) {
			got := socialTokenURL(tc.region)
			if got != tc.expected {
				t.Fatalf("socialTokenURL(%q) = %s, want %s", tc.region, got, tc.expected)
			}
		})
	}
}
