package proxy

import (
	"kiro-go/auth"
	"kiro-go/config"
)

// authRefreshToken wraps auth.RefreshToken so every refresh attempt — on the
// request path, in the background refresher, and in the warm-up worker — is
// counted in the kiro_token_refresh_total metric from a single choke point.
//
// Ported from kiro-tutu. Behavior is identical to auth.RefreshToken; only the
// metric counter is added.
func authRefreshToken(account *config.Account) (string, string, int64, string, error) {
	accessToken, refreshToken, expiresAt, profileArn, err := auth.RefreshToken(account)
	recordTokenRefreshResult(err)
	return accessToken, refreshToken, expiresAt, profileArn, err
}
