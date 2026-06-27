package auth

import "net/http"

// SetOIDCTokenURLForTest replaces the OIDC token URL builder. Test-only.
func SetOIDCTokenURLForTest(fn func(region string) string) {
	if fn == nil {
		return
	}
	oidcTokenURL = fn
}

// GetOIDCTokenURLForTest returns the current OIDC token URL builder so tests
// can restore it after replacement.
func GetOIDCTokenURLForTest() func(region string) string { return oidcTokenURL }

// SetGlobalAuthClientForTest swaps the global auth HTTP client. The package's
// init() installs a client whose Transport calls http.ProxyFromEnvironment, and
// that function caches env vars on first call — which corrupts later tests
// that rely on t.Setenv("HTTPS_PROXY", ...). Tests that need to issue an HTTP
// request against a httptest server should install a client whose Transport
// has Proxy=nil to keep env-proxy state clean. Returns the previous client so
// callers can restore it.
func SetGlobalAuthClientForTest(c *http.Client) *http.Client {
	old := httpClientStore.Load()
	if c != nil {
		httpClientStore.Store(c)
	}
	return old
}

// SetExternalIdpValidatorForTest swaps the validator behind ValidateExternalIdpEndpoint
// and returns the previous one so callers can restore it. Tests POST against httptest
// servers (http + 127.0.0.1), which the real allow-list validator rejects, so tests
// install a no-op validator here. Mirrors SetGlobalAuthClientForTest's swap-and-restore
// shape. Test-only.
func SetExternalIdpValidatorForTest(fn func(string) error) func(string) error {
	old := externalIdpEndpointValidator
	if fn != nil {
		externalIdpEndpointValidator = fn
	}
	return old
}
