package auth

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

// TestKiroCallbackBindAddrs locks in the secure default (loopback-only) and the
// KIRO_SSO_CALLBACK_BIND override used for containerized deployments.
func TestKiroCallbackBindAddrs(t *testing.T) {
	// Unset/blank -> loopback v4 (mandatory) + v6 (best-effort).
	t.Setenv("KIRO_SSO_CALLBACK_BIND", "")
	if got, want := kiroCallbackBindAddrs(), []string{"127.0.0.1:3128", "[::1]:3128"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("default bind addrs = %v, want %v", got, want)
	}
	// Whitespace is treated as unset (still the secure default).
	t.Setenv("KIRO_SSO_CALLBACK_BIND", "   ")
	if got := kiroCallbackBindAddrs(); len(got) != 2 {
		t.Fatalf("whitespace should fall back to loopback default, got %v", got)
	}
	// IPv4 wildcard override -> single mandatory bind.
	t.Setenv("KIRO_SSO_CALLBACK_BIND", "0.0.0.0")
	if got, want := kiroCallbackBindAddrs(), []string{"0.0.0.0:3128"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("0.0.0.0 bind addrs = %v, want %v", got, want)
	}
	// IPv6 wildcard override -> bracketed host:port.
	t.Setenv("KIRO_SSO_CALLBACK_BIND", "::")
	if got, want := kiroCallbackBindAddrs(), []string{"[::]:3128"}; !reflect.DeepEqual(got, want) {
		t.Fatalf(":: bind addrs = %v, want %v", got, want)
	}
}

// makeJWT builds an unsigned JWT-shaped string whose payload encodes claims, for
// testing the best-effort claim extraction (the signature is never verified).
func makeJWT(claims map[string]string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payloadBytes, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	return header + "." + payload + ".sig"
}

func TestExtractEmailFromJWT(t *testing.T) {
	cases := []struct {
		name   string
		claims map[string]string
		want   string
	}{
		{"email claim", map[string]string{"email": "a@b.com"}, "a@b.com"},
		// Azure AD v2.0 tokens usually omit "email" and carry preferred_username.
		{"preferred_username fallback", map[string]string{"preferred_username": "user@tenant.onmicrosoft.com"}, "user@tenant.onmicrosoft.com"},
		{"upn fallback", map[string]string{"upn": "u@corp.com"}, "u@corp.com"},
		{"none", map[string]string{"sub": "xyz"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ExtractEmailFromJWT(makeJWT(tc.claims)); got != tc.want {
				t.Fatalf("ExtractEmailFromJWT = %q, want %q", got, tc.want)
			}
		})
	}
	if got := ExtractEmailFromJWT("not-a-jwt"); got != "" {
		t.Fatalf("malformed token should yield empty email, got %q", got)
	}
}

func TestValidateExternalIdpEndpoint(t *testing.T) {
	valid := []string{
		"https://login.microsoftonline.com/5fbc183e/v2.0",
		"https://login.microsoftonline.us/tenant/v2.0",
		"https://login.microsoftonline.cn/tenant/oauth2/v2.0/token",
	}
	for _, u := range valid {
		if err := validateExternalIdpEndpoint(u); err != nil {
			t.Fatalf("expected %q to be allowed, got %v", u, err)
		}
	}
	invalid := []string{
		"http://login.microsoftonline.com/x",      // not https
		"https://evil-microsoftonline.com/x",       // suffix not anchored to a subdomain boundary
		"https://login.microsoftonline.com.evil.co", // not an allowed suffix
		"https://10.0.0.5/x",                        // IP literal
		"https://accounts.google.com/x",             // not allow-listed
		"https:///x",                                // no host
	}
	for _, u := range invalid {
		if err := validateExternalIdpEndpoint(u); err == nil {
			t.Fatalf("expected %q to be rejected", u)
		}
	}
}

func TestExternalIdpAuthorizeURL(t *testing.T) {
	raw := externalIdpAuthorizeURL(
		"https://login.microsoftonline.com/t/oauth2/v2.0/authorize",
		"client-123",
		"http://localhost:3128/oauth/callback",
		"api://client-123/codewhisperer:conversations offline_access",
		"challenge-abc",
		"state-xyz",
		"user@corp.com",
	)
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	q := u.Query()
	checks := map[string]string{
		"client_id":             "client-123",
		"response_type":         "code",
		"redirect_uri":          "http://localhost:3128/oauth/callback",
		"code_challenge":        "challenge-abc",
		"code_challenge_method": "S256",
		"response_mode":         "query",
		"state":                 "state-xyz",
		"login_hint":            "user@corp.com",
	}
	for k, want := range checks {
		if got := q.Get(k); got != want {
			t.Fatalf("authorize url param %q = %q, want %q", k, got, want)
		}
	}
	if !strings.Contains(q.Get("scope"), "offline_access") {
		t.Fatalf("expected offline_access in scope, got %q", q.Get("scope"))
	}
}

// TestExternalIdpAuthorizeURLOmitsEmptyLoginHint ensures we don't emit an empty
// login_hint parameter when the portal supplied none.
func TestExternalIdpAuthorizeURLOmitsEmptyLoginHint(t *testing.T) {
	raw := externalIdpAuthorizeURL("https://login.microsoftonline.com/t/authorize", "c", "http://localhost:3128/oauth/callback", "s", "ch", "st", "")
	u, _ := url.Parse(raw)
	if _, ok := u.Query()["login_hint"]; ok {
		t.Fatalf("login_hint should be omitted when empty")
	}
}

// TestRefreshExternalIdpToken drives the refresh_token grant against a stub IdP
// token endpoint and asserts the form encoding and response mapping.
func TestRefreshExternalIdpToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		if r.Form.Get("grant_type") != "refresh_token" {
			t.Fatalf("grant_type = %q", r.Form.Get("grant_type"))
		}
		if r.Form.Get("client_id") != "azure-client" {
			t.Fatalf("client_id = %q", r.Form.Get("client_id"))
		}
		if r.Form.Get("refresh_token") != "old-refresh" {
			t.Fatalf("refresh_token = %q", r.Form.Get("refresh_token"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"new-access","refresh_token":"new-refresh","expires_in":3600}`))
	}))
	defer srv.Close()

	access, refresh, expiresAt, profileArn, err := refreshExternalIdpToken(
		"old-refresh", "azure-client", srv.URL, "api://x/codewhisperer:conversations offline_access", srv.Client(),
	)
	if err != nil {
		t.Fatalf("refreshExternalIdpToken: %v", err)
	}
	if access != "new-access" {
		t.Fatalf("access = %q", access)
	}
	if refresh != "new-refresh" {
		t.Fatalf("refresh = %q", refresh)
	}
	if profileArn != "" {
		t.Fatalf("external IdP refresh should not return a profileArn, got %q", profileArn)
	}
	if expiresAt == 0 {
		t.Fatalf("expected a non-zero absolute expiry")
	}
}

// TestRefreshExternalIdpTokenKeepsRefreshTokenWhenOmitted verifies the existing
// refresh token is retained when the IdP response omits a rotated one.
func TestRefreshExternalIdpTokenKeepsRefreshTokenWhenOmitted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"a2","expires_in":1200}`))
	}))
	defer srv.Close()

	_, refresh, _, _, err := refreshExternalIdpToken("keep-me", "c", srv.URL, "", srv.Client())
	if err != nil {
		t.Fatalf("refreshExternalIdpToken: %v", err)
	}
	if refresh != "keep-me" {
		t.Fatalf("expected refresh token to be retained, got %q", refresh)
	}
}

// TestRefreshExternalIdpTokenRequiresClientAndEndpoint guards the precondition
// that distinguishes the external-IdP branch from the AWS OIDC branch.
func TestRefreshExternalIdpTokenRequiresClientAndEndpoint(t *testing.T) {
	if _, _, _, _, err := refreshExternalIdpToken("r", "", "https://login.microsoftonline.com/t/token", "", http.DefaultClient); err == nil {
		t.Fatalf("expected error when clientID is empty")
	}
	if _, _, _, _, err := refreshExternalIdpToken("r", "c", "", "", http.DefaultClient); err == nil {
		t.Fatalf("expected error when tokenEndpoint is empty")
	}
}

// TestValidateExternalIdpEndpointAcceptsAllowListed verifies the exported validator
// accepts real Azure / Microsoft 365 token endpoints (commercial, us-gov, china).
func TestValidateExternalIdpEndpointAcceptsAllowListed(t *testing.T) {
	for _, raw := range []string{
		"https://login.microsoftonline.com/tenant/oauth2/v2.0/token",
		"https://login.microsoftonline.us/tenant/v2.0",
		"https://login.partner.microsoftonline.cn/tenant/oauth2/v2.0/token",
	} {
		if err := ValidateExternalIdpEndpoint(raw); err != nil {
			t.Errorf("expected %q accepted, got %v", raw, err)
		}
	}
}

// TestValidateExternalIdpEndpointRejectsUnsafe verifies the validator rejects the
// SSRF shapes a pasted credential JSON could carry: cleartext http, IP literals,
// and non-allow-listed hosts.
func TestValidateExternalIdpEndpointRejectsUnsafe(t *testing.T) {
	for _, raw := range []string{
		"http://login.microsoftonline.com/x",  // not https
		"https://127.0.0.1/oauth/token",       // IP literal
		"https://evil.example.com/oauth/token", // not allow-listed
	} {
		if err := ValidateExternalIdpEndpoint(raw); err == nil {
			t.Errorf("expected %q rejected, got nil", raw)
		}
	}
}

// TestSetExternalIdpValidatorForTestSwapsAndRestores verifies the test seam lets a
// test override (and restore) the validator so happy-path import tests can POST
// against an httptest server (http + 127.0.0.1) that the real allow-list rejects.
func TestSetExternalIdpValidatorForTestSwapsAndRestores(t *testing.T) {
	restore := SetExternalIdpValidatorForTest(func(string) error { return nil })
	defer SetExternalIdpValidatorForTest(restore)
	if err := ValidateExternalIdpEndpoint("https://evil.example.com/x"); err != nil {
		t.Fatalf("expected swapped no-op validator to accept, got %v", err)
	}
}

// TestDeriveExternalIdpEndpoints verifies the endpoints+scopes are reconstructed
// from userId (Kiro export) OR the accessToken JWT issuer (bare blobs), plus the
// Kiro client ID. This is what lets the import path accept shapes that omit
// tokenEndpoint/issuerUrl/scopes.
func TestDeriveExternalIdpEndpoints(t *testing.T) {
	const userID = "https://login.microsoftonline.com/5fbc183e-3d09-4043-b36f-0c49d3665977/v2.0.8db0e2eb-d491-4a1a-98f1-cbdc12bb60a0"
	const clientID = "fa6d79bf-cdaa-495e-8359-78aab7c7cd9b"
	const wantTE = "https://login.microsoftonline.com/5fbc183e-3d09-4043-b36f-0c49d3665977/oauth2/v2.0/token"
	const wantIss = "https://login.microsoftonline.com/5fbc183e-3d09-4043-b36f-0c49d3665977/v2.0"

	// From userId (Kiro export carries it at account level).
	te, iss, sc := DeriveExternalIdpEndpoints(userID, clientID, "")
	if te != wantTE || iss != wantIss {
		t.Fatalf("from userId: te=%q iss=%q (want %q / %q)", te, iss, wantTE, wantIss)
	}
	if !strings.Contains(sc, "api://"+clientID+"/codewhisperer:conversations") || !strings.Contains(sc, "offline_access") {
		t.Fatalf("scopes: got %q", sc)
	}

	// From the accessToken JWT issuer (bare blobs carry no userId).
	jwt := "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"`+userID+`"}`)) + "."
	te2, iss2, sc2 := DeriveExternalIdpEndpoints("", clientID, jwt)
	if te2 != wantTE || iss2 != wantIss {
		t.Fatalf("from accessToken JWT: te=%q iss=%q (want %q / %q)", te2, iss2, wantTE, wantIss)
	}
	if sc2 == "" {
		t.Fatalf("scopes from JWT path: got empty")
	}

	// Neither source → all-empty (caller falls back to its 400).
	if te3, iss3, sc3 := DeriveExternalIdpEndpoints("", clientID, ""); te3 != "" || iss3 != "" || sc3 != "" {
		t.Fatalf("empty sources should yield all-empty, got %q %q %q", te3, iss3, sc3)
	}
	// userId takes precedence over accessToken.
	if te4, _, _ := DeriveExternalIdpEndpoints(userID, clientID, jwt); te4 != wantTE {
		t.Fatalf("userId should take precedence over accessToken, got %q", te4)
	}
}

// TestExpFromAccessTokenJWT pins the exp extraction used for trust-on-import.
func TestExpFromAccessTokenJWT(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"x","exp":2000000000}`))
	jwt := "eyJhbGciOiJub25lIn0." + payload + "."
	if got := ExpFromAccessTokenJWT(jwt); got != 2000000000 {
		t.Fatalf("ExpFromAccessTokenJWT: got %d, want 2000000000", got)
	}
	if got := ExpFromAccessTokenJWT(""); got != 0 {
		t.Fatalf("empty → 0, got %d", got)
	}
	if got := ExpFromAccessTokenJWT("not-a-jwt"); got != 0 {
		t.Fatalf("non-JWT → 0, got %d", got)
	}
}
