package proxy

import (
	"kiro-go/config"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBuildStreamingHeaderValuesAlignsWithKiroIDEFormat(t *testing.T) {
	account := &config.Account{MachineId: "machine-123"}
	values := buildStreamingHeaderValues(account, "q.us-east-1.amazonaws.com")

	if values.Host != "q.us-east-1.amazonaws.com" {
		t.Fatalf("expected host to be preserved, got %q", values.Host)
	}
	if !strings.Contains(values.UserAgent, "aws-sdk-js/1.0.34") {
		t.Fatalf("expected streaming sdk version in user agent, got %q", values.UserAgent)
	}
	if !strings.Contains(values.UserAgent, "api/codewhispererstreaming#1.0.34") {
		t.Fatalf("expected streaming API marker in user agent, got %q", values.UserAgent)
	}
	if !strings.Contains(values.UserAgent, "KiroIDE-0.11.107-machine-123") {
		t.Fatalf("expected kiro version and machine id in user agent, got %q", values.UserAgent)
	}
	if !strings.Contains(values.AmzUserAgent, "aws-sdk-js/1.0.34 KiroIDE-0.11.107-machine-123") {
		t.Fatalf("expected x-amz-user-agent to include version and machine id, got %q", values.AmzUserAgent)
	}
}

func TestBuildRuntimeHeaderValuesUsesRuntimeAPIFormat(t *testing.T) {
	account := &config.Account{MachineId: "machine-456"}
	values := buildRuntimeHeaderValues(account, "codewhisperer.us-east-1.amazonaws.com")

	if !strings.Contains(values.UserAgent, "aws-sdk-js/1.0.0") {
		t.Fatalf("expected runtime sdk version in user agent, got %q", values.UserAgent)
	}
	if !strings.Contains(values.UserAgent, "api/codewhispererruntime#1.0.0") {
		t.Fatalf("expected runtime API marker in user agent, got %q", values.UserAgent)
	}
	if !strings.Contains(values.UserAgent, "m/N,E") {
		t.Fatalf("expected runtime mode marker in user agent, got %q", values.UserAgent)
	}
}

// TestBuildKiroHeaderValuesFallsBackToDerivedMachineId asserts an account with an
// empty MachineId still gets a unique, stable device suffix in the User-Agent.
// Without the fallback every empty-id account shares an identical UA, which is the
// strongest cross-account association signal upstream can correlate on. The fallback
// must be deterministic so the same account always looks like the same device.
func TestBuildKiroHeaderValuesFallsBackToDerivedMachineId(t *testing.T) {
	acc := &config.Account{ID: "acct-empty-id", MachineId: ""}
	a := buildKiroHeaderValues(acc, "q.us-east-1.amazonaws.com", "codewhispererstreaming", "1.0.34", "m/E")
	b := buildKiroHeaderValues(acc, "q.us-east-1.amazonaws.com", "codewhispererstreaming", "1.0.34", "m/E")

	// Deterministic: same account → same UA.
	if a.UserAgent != b.UserAgent {
		t.Fatalf("empty-id fallback must be stable across calls:\n a=%q\n b=%q", a.UserAgent, b.UserAgent)
	}
	// UA must carry a device suffix (the derived id) rather than ending at the version.
	suffix := "-" + config.DeriveMachineId("acct-empty-id")
	if !strings.Contains(a.UserAgent, suffix) {
		t.Fatalf("expected UA to carry derived machine id suffix %q, got %q", suffix, a.UserAgent)
	}

	// Distinct across accounts: two empty-id accounts must NOT share a UA.
	other := &config.Account{ID: "acct-other-id", MachineId: ""}
	c := buildKiroHeaderValues(other, "q.us-east-1.amazonaws.com", "codewhispererstreaming", "1.0.34", "m/E")
	if a.UserAgent == c.UserAgent {
		t.Fatalf("two distinct empty-id accounts must get distinct device suffixes, both got %q", a.UserAgent)
	}

	// An explicitly-set MachineId still wins over the fallback.
	explicit := &config.Account{ID: "acct-empty-id", MachineId: "explicit-machine"}
	e := buildKiroHeaderValues(explicit, "q.us-east-1.amazonaws.com", "codewhispererstreaming", "1.0.34", "m/E")
	if !strings.Contains(e.UserAgent, "-explicit-machine") {
		t.Fatalf("explicit MachineId must win over fallback, got %q", e.UserAgent)
	}

	// A nil account (no ID to derive from) keeps the suffix-less UA — nothing to derive from.
	none := buildKiroHeaderValues(nil, "q.us-east-1.amazonaws.com", "codewhispererstreaming", "1.0.34", "m/E")
	if strings.Contains(none.UserAgent, suffix) {
		t.Fatalf("nil account must not carry a derived suffix, got %q", none.UserAgent)
	}
}

// TestApplyKiroBaseHeadersApiKeyBranch asserts an api_key account sends the key
// as the bearer with tokentype: API_KEY, while an OAuth account keeps the plain
// bearer and the external_idp TokenType branch is preserved.
func TestApplyKiroBaseHeadersApiKeyBranch(t *testing.T) {
	mk := func(account *config.Account) http.Header {
		req := httptest.NewRequest("POST", "https://q.us-east-1.amazonaws.com/x", nil)
		applyKiroBaseHeaders(req, account, kiroHeaderValues{UserAgent: "ua", AmzUserAgent: "aua"})
		return req.Header
	}

	// api_key: bearer is the key, tokentype is API_KEY.
	h := mk(&config.Account{AuthMethod: "api_key", KiroApiKey: "key-xyz", AccessToken: "key-xyz"})
	if got := h.Get("Authorization"); got != "Bearer key-xyz" {
		t.Fatalf("api_key bearer: want %q, got %q", "Bearer key-xyz", got)
	}
	if got := h.Get("tokentype"); got != "API_KEY" {
		t.Fatalf("api_key tokentype: want API_KEY, got %q", got)
	}

	// OAuth (idc): plain bearer, no tokentype header.
	h = mk(&config.Account{AuthMethod: "idc", AccessToken: "at-oauth"})
	if got := h.Get("Authorization"); got != "Bearer at-oauth" {
		t.Fatalf("oauth bearer: want %q, got %q", "Bearer at-oauth", got)
	}
	if got := h.Get("tokentype"); got != "" {
		t.Fatalf("oauth must NOT set tokentype, got %q", got)
	}

	// external_idp preserved: the (canonical) Tokentype header carries EXTERNAL_IDP.
	// "tokentype" and "TokenType" canonicalize to the same key in net/http, but
	// api_key and external_idp are mutually exclusive account types, so the two
	// values never collide at runtime.
	h = mk(&config.Account{AuthMethod: "external_idp", AccessToken: "at-ext"})
	if got := h.Get("TokenType"); got != "EXTERNAL_IDP" {
		t.Fatalf("external_idp TokenType: want EXTERNAL_IDP, got %q", got)
	}

	// empty account: no Authorization header.
	h = mk(&config.Account{})
	if got := h.Get("Authorization"); got != "" {
		t.Fatalf("empty account must not set Authorization, got %q", got)
	}
}
