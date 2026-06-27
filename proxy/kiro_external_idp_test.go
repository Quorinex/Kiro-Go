package proxy

import (
	"kiro-go/config"
	"net/http"
	"testing"
)

// TestSetKiroHeadersExternalIdpSendsTokenType verifies that external-IdP
// (enterprise SSO, e.g. Azure AD) accounts get the TokenType: EXTERNAL_IDP
// header. Without it, CodeWhisperer silently returns an empty profile list and
// rejects data-plane calls, which is exactly what broke Azure-tenant SSO.
func TestSetKiroHeadersExternalIdpSendsTokenType(t *testing.T) {
	account := &config.Account{
		AccessToken: "azure-access-token",
		AuthMethod:  "external_idp",
		MachineId:   "machine-xyz",
	}
	req, err := http.NewRequest("POST", "https://codewhisperer.us-east-1.amazonaws.com/ListAvailableProfiles", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	setKiroHeaders(req, account)

	if got := req.Header.Get("TokenType"); got != "EXTERNAL_IDP" {
		t.Fatalf("expected TokenType=EXTERNAL_IDP for external_idp account, got %q", got)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer azure-access-token" {
		t.Fatalf("expected bearer authorization, got %q", got)
	}
}

// TestSetKiroHeadersNonExternalIdpOmitsTokenType verifies the header is NOT sent
// for the other auth methods, so existing Builder ID / IDC / social accounts are
// unaffected.
func TestSetKiroHeadersNonExternalIdpOmitsTokenType(t *testing.T) {
	for _, method := range []string{"idc", "social", ""} {
		account := &config.Account{AccessToken: "tok", AuthMethod: method, MachineId: "m"}
		req, err := http.NewRequest("POST", "https://codewhisperer.us-east-1.amazonaws.com/ListAvailableProfiles", nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		setKiroHeaders(req, account)
		if got := req.Header.Get("TokenType"); got != "" {
			t.Fatalf("auth method %q should not set TokenType, got %q", method, got)
		}
	}
}
