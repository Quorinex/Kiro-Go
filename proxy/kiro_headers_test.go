package proxy

import (
	"kiro-go/config"
	"net/http"
	"strings"
	"testing"
)

func TestBuildStreamingHeaderValuesAlignsWithKiroRuntimeIDE(t *testing.T) {
	account := &config.Account{MachineId: "machine-123"}
	values := buildKiroRuntimeHeaderValues(account, "runtime.us-east-1.kiro.dev")

	if values.Host != "runtime.us-east-1.kiro.dev" {
		t.Fatalf("expected host to be preserved, got %q", values.Host)
	}
	for _, want := range []string{
		"aws-sdk-js/1.0.0",
		"api/kiroruntime#1.0.0",
		"KiroIDE-1.0.212-machine-123",
	} {
		if !strings.Contains(values.UserAgent, want) {
			t.Fatalf("official KiroRuntime user agent %q missing %q", values.UserAgent, want)
		}
	}
	if !strings.Contains(values.AmzUserAgent, "aws-sdk-js/1.0.0 KiroIDE-1.0.212-machine-123") {
		t.Fatalf("x-amz-user-agent does not match KiroRuntime IDE format: %q", values.AmzUserAgent)
	}
}

func TestBuildLegacyStreamingHeaderValuesRetainsEndpointSDK(t *testing.T) {
	account := &config.Account{MachineId: "machine-123"}
	values := buildLegacyStreamingHeaderValues(account, "q.us-east-1.amazonaws.com")

	for _, want := range []string{
		"aws-sdk-js/1.0.39",
		"api/codewhispererstreaming#1.0.39",
		"KiroIDE-1.0.212-machine-123",
	} {
		if !strings.Contains(values.UserAgent, want) {
			t.Fatalf("legacy fallback user agent %q missing %q", values.UserAgent, want)
		}
	}
}

func TestResolveKiroCLIEndpointUsesCLIIdentity(t *testing.T) {
	account := &config.Account{AuthMethod: "api_key", KiroApiKey: "ksk_test", Region: "eu-central-1"}
	resolved, err := resolveKiroEndpoint(kiroCLIEndpoint, account, "")
	if err != nil {
		t.Fatal(err)
	}
	if resolved.URL != "https://runtime.eu-central-1.kiro.dev/" || resolved.ContentType != "application/x-amz-json-1.0" || resolved.AgentMode {
		t.Fatalf("resolved CLI endpoint = %+v", resolved)
	}
	for _, want := range []string{
		"KiroCLI/2.14.2",
		"md/appVersion-2.14.2",
		"app/AmazonQ-For-CLI",
		"api/codewhispererstreaming#0.1.17975",
	} {
		if !strings.Contains(resolved.HeaderValues.UserAgent, want) {
			t.Fatalf("CLI user agent %q missing %q", resolved.HeaderValues.UserAgent, want)
		}
	}
	if strings.Contains(resolved.HeaderValues.UserAgent, "KiroIDE") || strings.Contains(resolved.HeaderValues.UserAgent, "aws-sdk-js") {
		t.Fatalf("API key path must not mix IDE/JS identity into CLI UA: %q", resolved.HeaderValues.UserAgent)
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

func TestApplyKiroBaseHeadersMarksExternalIdentityProviderTokens(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "https://q.us-east-1.amazonaws.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	account := &config.Account{
		AccessToken: "external-access",
		AuthMethod:  " External_IDP ",
	}

	applyKiroBaseHeaders(req, account, buildRuntimeHeaderValues(account, req.URL.Host))

	if got := req.Header.Get("Authorization"); got != "Bearer external-access" {
		t.Fatalf("expected bearer authorization, got %q", got)
	}
	if got := req.Header.Get("TokenType"); got != "EXTERNAL_IDP" {
		t.Fatalf("expected EXTERNAL_IDP token type, got %q", got)
	}
}

func TestApplyKiroBaseHeadersOmitsTokenTypeForAWSAuthentication(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "https://q.us-east-1.amazonaws.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("TokenType", "stale")
	account := &config.Account{AccessToken: "aws-access", AuthMethod: "idc"}

	applyKiroBaseHeaders(req, account, buildRuntimeHeaderValues(account, req.URL.Host))

	if got := req.Header.Get("TokenType"); got != "" {
		t.Fatalf("expected no token type for AWS auth, got %q", got)
	}
}

func TestApplyKiroBaseHeadersMarksAPIKeyCredentials(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "https://runtime.us-east-1.kiro.dev/", nil)
	if err != nil {
		t.Fatal(err)
	}
	account := &config.Account{
		KiroApiKey:  "ksk_test_key",
		AccessToken: "should-not-win",
		AuthMethod:  "api_key",
	}

	applyKiroBaseHeaders(req, account, buildKiroCLIHeaderValues(req.URL.Host, "codewhispererstreaming"))

	if got := req.Header.Get("Authorization"); got != "Bearer ksk_test_key" {
		t.Fatalf("expected API key bearer, got %q", got)
	}
	// net/http.Header is case-insensitive; either casing maps to the same entry.
	if got := req.Header.Get("tokentype"); got != "API_KEY" {
		t.Fatalf("expected tokentype API_KEY, got %q", got)
	}
	if got := req.Header.Get("TokenType"); got != "API_KEY" {
		t.Fatalf("expected TokenType/tokentype API_KEY, got %q", got)
	}
	if got := req.Header.Get("x-amzn-codewhisperer-optout"); got != "false" {
		t.Fatalf("expected CLI optout=false, got %q", got)
	}
}
