package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"kiro-go/config"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// oidcTokenURL 构造 idc/builderId 刷新 endpoint。测试可替换以拦截网络调用。
var oidcTokenURL = func(region string) string {
	return fmt.Sprintf("https://oidc.%s.amazonaws.com/token", region)
}

// socialTokenURL 构造 social 刷新 endpoint。测试可替换以拦截网络调用。
var socialTokenURL = func() string {
	return "https://prod.us-east-1.auth.desktop.kiro.dev/refreshToken"
}

// RefreshToken 刷新 access token
// Returns: accessToken, refreshToken, expiresAt, profileArn, error
func RefreshToken(account *config.Account) (string, string, int64, string, error) {
	// Resolve per-account proxy: account.ProxyURL > global config
	proxyURL := account.ProxyURL
	if proxyURL == "" {
		proxyURL = config.GetProxyURL()
	}
	client := GetAuthClientForProxy(proxyURL)

	// External IdP (enterprise SSO, e.g. Azure AD) tokens are refreshed against the
	// IdP token endpoint (refresh_token grant, public client), NOT the AWS SSO OIDC
	// endpoint. Selecting it on AuthMethod (rather than letting it fall through to the
	// OIDC branch, which requires clientSecret) is what makes these accounts refresh.
	if account.AuthMethod == "external_idp" {
		return refreshExternalIdpToken(account.RefreshToken, account.ClientID, account.TokenEndpoint, account.Scopes, client)
	}
	if account.AuthMethod == "social" {
		return refreshSocialToken(account.RefreshToken, client)
	}
	return refreshOIDCToken(account.RefreshToken, account.ClientID, account.ClientSecret, account.Region, client)
}

// refreshExternalIdpToken refreshes an external-IdP (enterprise SSO) access token
// through the IdP token endpoint using the OAuth2 refresh_token grant for a public
// client (no client secret). offline_access in the original scopes is what makes a
// refresh token available. The IdP issues no profileArn (it is resolved separately
// via ListAvailableProfiles using the EXTERNAL_IDP token type), so "" is returned
// for the profileArn.
func refreshExternalIdpToken(refreshToken, clientID, tokenEndpoint, scopes string, client *http.Client) (string, string, int64, string, error) {
	if clientID == "" || tokenEndpoint == "" {
		return "", "", 0, "", fmt.Errorf("external IdP refresh requires clientId and tokenEndpoint")
	}
	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	if scopes != "" {
		form.Set("scope", scopes)
	}
	accessToken, newRefreshToken, expiresIn, err := postExternalIdpToken(client, tokenEndpoint, form)
	if err != nil {
		return "", "", 0, "", err
	}
	// Some IdPs (Azure AD) rotate refresh tokens; others omit it on refresh. Keep the
	// existing refresh token when the response does not carry a new one.
	if newRefreshToken == "" {
		newRefreshToken = refreshToken
	}
	expiresAt := time.Now().Unix() + int64(expiresIn)
	return accessToken, newRefreshToken, expiresAt, "", nil
}

// postExternalIdpToken performs a form-encoded POST to an external-IdP token
// endpoint and maps the snake_case OAuth2 token response onto the standard return
// shape. Shared by the authorization-code exchange (login) and the refresh_token
// grant (renewal).
func postExternalIdpToken(client *http.Client, tokenEndpoint string, form url.Values) (accessToken, refreshToken string, expiresIn int, err error) {
	if strings.TrimSpace(tokenEndpoint) == "" {
		return "", "", 0, fmt.Errorf("external IdP token endpoint is empty")
	}
	// Defense-in-depth: re-validate the endpoint at the outbound-POST boundary so the
	// refresh token is never sent to a non-allow-listed host — even if a persisted
	// account's TokenEndpoint was set out-of-band (backup restore, an external file
	// write, or a future caller that stores an endpoint without validating). This makes
	// allow-list validation an invariant of the exfiltration-sensitive operation itself
	// rather than of every caller. Uses the exported ValidateExternalIdpEndpoint so the
	// test seam (SetExternalIdpValidatorForTest) still relaxes it for httptest servers.
	if err := ValidateExternalIdpEndpoint(tokenEndpoint); err != nil {
		return "", "", 0, fmt.Errorf("external IdP token endpoint rejected: %w", err)
	}
	req, err := http.NewRequest("POST", tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", "", 0, fmt.Errorf("failed to build external IdP token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", "", 0, fmt.Errorf("external IdP token request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", 0, fmt.Errorf("failed to read external IdP token response: %w", err)
	}
	var out struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
		Error        string `json:"error"`
		ErrorDesc    string `json:"error_description"`
	}
	_ = json.Unmarshal(body, &out)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || out.AccessToken == "" {
		if out.Error != "" {
			return "", "", 0, fmt.Errorf("external IdP token exchange failed (status %d): %s: %s", resp.StatusCode, out.Error, out.ErrorDesc)
		}
		return "", "", 0, fmt.Errorf("external IdP token exchange failed (status %d): %s", resp.StatusCode, string(body))
	}
	return out.AccessToken, out.RefreshToken, out.ExpiresIn, nil
}

// refreshOIDCToken IdC/Builder ID token 刷新
func refreshOIDCToken(refreshToken, clientID, clientSecret, region string, client *http.Client) (string, string, int64, string, error) {
	if clientID == "" || clientSecret == "" {
		return "", "", 0, "", fmt.Errorf("OIDC refresh requires clientId and clientSecret")
	}
	if region == "" {
		region = "us-east-1"
	}

	url := oidcTokenURL(region)

	payload := map[string]string{
		"clientId":     clientID,
		"clientSecret": clientSecret,
		"refreshToken": refreshToken,
		"grantType":    "refresh_token",
	}

	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", "", 0, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return "", "", 0, "", fmt.Errorf("refresh failed: %d %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		AccessToken  string `json:"accessToken"`
		RefreshToken string `json:"refreshToken"`
		ExpiresIn    int    `json:"expiresIn"`
		ProfileArn   string `json:"profileArn"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", 0, "", err
	}

	expiresAt := time.Now().Unix() + int64(result.ExpiresIn)
	return result.AccessToken, result.RefreshToken, expiresAt, result.ProfileArn, nil
}

// refreshSocialToken Social (GitHub/Google) token 刷新
func refreshSocialToken(refreshToken string, client *http.Client) (string, string, int64, string, error) {
	url := socialTokenURL()

	payload := map[string]string{
		"refreshToken": refreshToken,
	}

	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", "", 0, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return "", "", 0, "", fmt.Errorf("refresh failed: %d %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		AccessToken  string `json:"accessToken"`
		RefreshToken string `json:"refreshToken"`
		ExpiresIn    int    `json:"expiresIn"`
		ProfileArn   string `json:"profileArn"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", 0, "", err
	}

	expiresAt := time.Now().Unix() + int64(result.ExpiresIn)
	return result.AccessToken, result.RefreshToken, expiresAt, result.ProfileArn, nil
}
