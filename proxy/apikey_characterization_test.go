package proxy

import (
	"kiro-go/auth"
	"kiro-go/config"
	accountpool "kiro-go/pool"
	"testing"
)

// TestApiKeyAccountDoesNotRefreshOnHandlerPath pins spec §6: an api_key account
// (ExpiresAt=0, RefreshToken="") must not trigger auth.RefreshToken on the
// handler refresh path. refreshAccountToken's not-near-expiry guard returns
// early (force=false, ExpiresAt==0), so the OIDC URL builder is never consulted.
func TestApiKeyAccountDoesNotRefreshOnHandlerPath(t *testing.T) {
	if err := config.Init(t.TempDir() + "/config.json"); err != nil {
		t.Fatalf("config.Init: %v", err)
	}
	// Sentinel: if a refresh fires, the OIDC URL builder is consulted (to derive
	// the token endpoint), which would mean a round-trip was about to happen.
	prev := auth.GetOIDCTokenURLForTest()
	auth.SetOIDCTokenURLForTest(func(string) string {
		t.Fatal("refresh must not be called for an api_key account")
		return ""
	})
	defer auth.SetOIDCTokenURLForTest(prev)

	account := &config.Account{
		ID:           "ak-1",
		AuthMethod:   "api_key",
		KiroApiKey:   "k",
		AccessToken:  "k",
		ExpiresAt:    0,
		RefreshToken: "",
		Enabled:      true,
	}
	if !account.IsApiKeyCredential() {
		t.Fatalf("expected IsApiKeyCredential() == true")
	}
	h := &Handler{pool: accountpool.GetPool()}
	if err := h.refreshAccountToken(account, false); err != nil {
		t.Fatalf("refreshAccountToken returned error: %v", err)
	}
}
