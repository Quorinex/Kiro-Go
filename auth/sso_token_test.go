package auth

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestPollForTokenRejectsNonJSON200 guards against the empty-token account bug:
// a corporate filtering proxy that substitutes an HTML block-page (HTTP 200,
// non-JSON body) between the proxy and AWS must NOT be decoded into empty
// credentials and returned as a nil-error success. Previously pollForToken
// discarded the decode error, returned ("","",0,nil), and ImportFromSsoToken /
// PollBuilderIdAuth propagated that as success — silently creating an account
// with empty AccessToken/RefreshToken treated as valid until first use fails.
// See Bug G.
func TestPollForTokenRejectsNonJSON200(t *testing.T) {
	// Install a client whose Transport does not consult ProxyFromEnvironment so
	// the POST reliably reaches the in-process httptest server regardless of the
	// ambient proxy env.
	prevClient := SetGlobalAuthClientForTest(&http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{},
	})
	defer SetGlobalAuthClientForTest(prevClient)

	// Fake token endpoint substitutes a corporate block-page: HTTP 200 + HTML.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<html><body>Blocked by corporate policy</body></html>")
	}))
	defer server.Close()

	// interval=1 keeps the first poll ~1s out; the 200 branch returns on it.
	accessToken, refreshToken, expiresIn, err := pollForToken(server.URL, "cid", "secret", "device-code", 1)

	if err == nil {
		t.Fatalf("pollForToken must return an error when the token endpoint returns a non-JSON 200 (e.g. a corporate block-page); got empty tokens (access=%q refresh=%q expiresIn=%d) and nil error", accessToken, refreshToken, expiresIn)
	}
	if accessToken != "" || refreshToken != "" {
		t.Fatalf("on a non-JSON 200, pollForToken must not return token values; got access=%q refresh=%q", accessToken, refreshToken)
	}
}
