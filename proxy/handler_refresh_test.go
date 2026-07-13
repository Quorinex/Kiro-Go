package proxy

import (
	"io"
	"kiro-go/auth"
	"kiro-go/config"
	accountpool "kiro-go/pool"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestRefreshAccountTokenDedupConcurrentCalls verifies the central token-refresh
// path deduplicates concurrent refreshes of the SAME account: N goroutines all
// needing a refresh must collapse into a SINGLE upstream auth.RefreshToken call.
//
// Without the lock + pool re-check, each goroutine refreshes independently. For
// an IdP that rotates refresh tokens (one-time-use — e.g. external_idp / Azure
// AD, see oidc.go comment), the loser of the race sends an already-consumed
// refresh token and gets invalid_grant → handleAccountFailure bans the account.
// This is Bug A.
func TestRefreshAccountTokenDedupConcurrentCalls(t *testing.T) {
	cfgFile := t.TempDir() + "/config.json"
	if err := config.Init(cfgFile); err != nil {
		t.Fatalf("config.Init: %v", err)
	}

	var refreshCount int32
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&refreshCount, 1)
		// Hold the request open briefly so concurrent callers queue on the
		// token-refresh lock, widening the race window the dedup must close.
		time.Sleep(75 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"accessToken":"new-access","refreshToken":"new-refresh","expiresIn":3600,"profileArn":"arn:aws:codewhisperer:profile/dedup"}`)
	}))
	t.Cleanup(authServer.Close)

	oldTokenURL := auth.GetOIDCTokenURLForTest()
	auth.SetOIDCTokenURLForTest(func(string) string { return authServer.URL })
	t.Cleanup(func() { auth.SetOIDCTokenURLForTest(oldTokenURL) })
	oldAuthClient := auth.SetGlobalAuthClientForTest(authServer.Client())
	t.Cleanup(func() { auth.SetGlobalAuthClientForTest(oldAuthClient) })

	account := config.Account{
		ID:           "acct-dedup",
		Email:        "dedup@example.com",
		AccessToken:  "stale-access",
		RefreshToken: "stale-refresh",
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		AuthMethod:   "idc",
		Region:       "us-east-1",
		Enabled:      true,
		ExpiresAt:    time.Now().Unix() - 1, // already expired → refresh forced
	}
	if err := config.AddAccount(account); err != nil {
		t.Fatalf("add account: %v", err)
	}

	p := accountpool.GetPool()
	p.Reload()
	h := &Handler{pool: p}

	const N = 8
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start // release all goroutines together to maximize concurrency
			local := account // each goroutine simulates an independent per-request copy
			_ = h.refreshAccountToken(&local, false)
		}()
	}
	close(start)
	wg.Wait()

	if got := atomic.LoadInt32(&refreshCount); got != 1 {
		t.Fatalf("expected exactly 1 upstream refresh (dedup collapsed concurrent callers), got %d", got)
	}
}
