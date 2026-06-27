# external_idp Credential JSON Adapter — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the "Add credential JSON" import path (`apiImportCredentials` handler + `importCredentials` frontend) accept and persist `external_idp` (Azure AD / Microsoft 365) accounts from any JSON shape without erroring.

**Architecture:** Extend the backend handler and two frontend functions to recognize `external_idp`, read its refresh material (`tokenEndpoint`/`issuerUrl`/`scopes`), validate the user-supplied IdP endpoint against the existing allow-list (SSRF guard), and route refresh through the already-working `refreshExternalIdpToken`. No changes to the refresh/dispatch logic in `auth/oidc.go`.

**Tech Stack:** Go 1.21 (module `kiro-go`, stdlib + `github.com/google/uuid v1.6.0`); vanilla JS statically served by the Go server.

## Global Constraints

- Canonical AuthMethod value is exactly `external_idp` (snake_case); all aliases normalize to it.
- External IdP endpoints MUST be https, non-IP-literal, and host must `HasSuffix` one of `allowedExternalIdpIssuerSuffixes` (`.microsoftonline.com`, `.microsoftonline.us`, `.microsoftonline.cn`); reject with HTTP 400 otherwise.
- Import MUST succeed at one live token refresh before persisting (regression: `TestApiImportCredentialsRejectsWhenRefreshFails`); refresh failure → HTTP 400, no account persisted.
- External IdP token responses use snake_case JSON (`access_token`/`refresh_token`/`expires_in`); IdC/social use camelCase.
- Provider defaults when empty: external_idp→`AzureAD`, social→`Google`, idc→`BuilderId`.
- Alias `enterprise` maps to `idc` (Kiro Account Manager contract) — do NOT remap to external_idp.
- `external_idp` accounts carry `clientId` but NOT `clientSecret`; detection must precede the clientId+clientSecret→idc default.
- No new third-party Go dependencies.
- Module path is `kiro-go`; run `go test ./...` from the repo root `C:\Users\Admin\Kiro-Go`.

---

## File Structure

| File | Responsibility | Change |
|---|---|---|
| `auth/kiro_sso.go` | Exported external-IdP endpoint validator | add `externalIdpEndpointValidator` var + `ValidateExternalIdpEndpoint` |
| `auth/testhooks.go` | Test seams | add `SetExternalIdpValidatorForTest` |
| `auth/kiro_sso_test.go` | Validator + seam tests | add 3 tests |
| `proxy/handler.go` | `apiImportCredentials` + authMethod normalization helper | modify handler; add `normalizeImportAuthMethod` + `externalIdpAuthMethodAliases` |
| `proxy/import_credentials_test.go` | import + normalization tests | add happy/SSRF/refresh-fail/identity tests + normalization table test |
| `config/config.go` | account store | add `AccountIDExists` |
| `web/app.js` | current admin UI `importCredentials` | map fields + normalize + payload |
| `web/index-legacy.html` | legacy admin UI `importCredentials` | parity edits |

---

### Task 1: Export `ValidateExternalIdpEndpoint` + add `SetExternalIdpValidatorForTest` seam

**Files:**
- Modify: `auth/kiro_sso.go` (after the closing brace of `validateExternalIdpEndpoint`, line ~534)
- Modify: `auth/testhooks.go` (after `SetGlobalAuthClientForTest`, line ~30)
- Test: `auth/kiro_sso_test.go` (append; file is `package auth` — call functions with no package prefix)

**Interfaces:**
- Produces: `auth.ValidateExternalIdpEndpoint(rawURL string) error` (used by Task 3); `auth.SetExternalIdpValidatorForTest(fn func(string) error) func(string) error` (used by Task 3 tests to bypass the allow-list for `http://127.0.0.1` httptest servers).

- [ ] **Step 1: Write the failing tests**

Append to `auth/kiro_sso_test.go`:

```go
// TestValidateExternalIdpEndpointAcceptsAllowListed verifies the exported validator
// accepts real Azure / Microsoft 365 token endpoints (com/global, us-gov, china).
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./auth/ -run 'TestValidateExternalIdpEndpoint|TestSetExternalIdpValidatorForTest' -v`
Expected: FAIL — `undefined: ValidateExternalIdpEndpoint` and `undefined: SetExternalIdpValidatorForTest` (compile error).

- [ ] **Step 3: Add the exported validator (kiro_sso.go)**

In `auth/kiro_sso.go`, immediately after the closing `}` of `validateExternalIdpEndpoint` (after line 534), add:

```go
// externalIdpEndpointValidator is the function ValidateExternalIdpEndpoint delegates
// to. Tests override it via SetExternalIdpValidatorForTest so a happy-path import
// test can POST against an httptest server (http + 127.0.0.1) that the real
// allow-list would reject.
var externalIdpEndpointValidator = validateExternalIdpEndpoint

// ValidateExternalIdpEndpoint is the exported entry point for validating a user- or
// discovery-supplied external IdP endpoint URL. The credential-import path
// (package proxy) uses this to guard against SSRF / refresh-token exfiltration: a
// pasted tokenEndpoint pointing at an internal or attacker-controlled host would
// otherwise cause the server to POST the account's refresh token there.
func ValidateExternalIdpEndpoint(rawURL string) error {
	return externalIdpEndpointValidator(rawURL)
}
```

- [ ] **Step 4: Add the test seam (testhooks.go)**

In `auth/testhooks.go`, after `SetGlobalAuthClientForTest` (after line 30), add:

```go
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
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./auth/ -run 'TestValidateExternalIdpEndpoint|TestSetExternalIdpValidatorForTest' -v`
Expected: PASS (3 tests). If a real-network call is suspected, note these tests hit no network — they are pure string validation.

- [ ] **Step 6: Commit**

```bash
git add auth/kiro_sso.go auth/testhooks.go auth/kiro_sso_test.go
git commit -m "feat(auth): export ValidateExternalIdpEndpoint + test seam"
```

---

### Task 2: `normalizeImportAuthMethod` helper

**Files:**
- Modify: `proxy/handler.go` (append after `apiImportCredentials`, after line 3109)
- Test: `proxy/import_credentials_test.go` (append)

**Interfaces:**
- Produces: `normalizeImportAuthMethod(authMethod, clientID, clientSecret, tokenEndpoint string) string` (used by Task 3).
- Consumes: package `strings` (already imported in handler.go).

- [ ] **Step 1: Write the failing test**

Append to `proxy/import_credentials_test.go`:

```go
// TestNormalizeImportAuthMethod pins the auth-method normalization for import,
// including the key regression: external_idp accounts carry clientId but NO
// clientSecret, so the old default branch misclassified them as "social".
func TestNormalizeImportAuthMethod(t *testing.T) {
	cases := []struct {
		name          string
		authMethod    string
		clientID      string
		clientSecret  string
		tokenEndpoint string
		want          string
	}{
		{"explicit external_idp", "external_idp", "c", "", "https://login.microsoftonline.com/t/oauth2/v2.0/token", "external_idp"},
		{"azure alias", "AzureAD", "c", "", "https://login.microsoftonline.com/t/oauth2/v2.0/token", "external_idp"},
		{"microsoft alias", "microsoft", "c", "", "https://login.microsoftonline.com/t/oauth2/v2.0/token", "external_idp"},
		{"inferred from tokenEndpoint", "", "c", "", "https://login.microsoftonline.com/t/oauth2/v2.0/token", "external_idp"},
		{"external_idp even with clientSecret", "external_idp", "c", "s", "https://login.microsoftonline.com/t/oauth2/v2.0/token", "external_idp"},
		{"enterprise stays idc", "enterprise", "c", "s", "", "idc"},
		{"idc with clientid+secret", "idc", "c", "s", "", "idc"},
		{"empty + clientid (no secret) -> idc", "", "c", "", "", "idc"},
		{"empty no clientid -> social", "", "", "", "", "social"},
		{"social explicit", "social", "", "", "", "social"},
		{"google alias", "google", "", "", "", "social"},
		{"unrecognized with clientid+secret -> idc", "weird", "c", "s", "", "idc"},
		{"unrecognized without secret -> social", "weird", "c", "", "", "social"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizeImportAuthMethod(tc.authMethod, tc.clientID, tc.clientSecret, tc.tokenEndpoint); got != tc.want {
				t.Fatalf("normalizeImportAuthMethod(%q,%q,%q,%q) = %q, want %q",
					tc.authMethod, tc.clientID, tc.clientSecret, tc.tokenEndpoint, got, tc.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./proxy/ -run TestNormalizeImportAuthMethod -v`
Expected: FAIL — `undefined: normalizeImportAuthMethod` (compile error).

- [ ] **Step 3: Write the helper**

In `proxy/handler.go`, append after `apiImportCredentials` (after line 3109):

```go
// externalIdpAuthMethodAliases are lower-cased authMethod values (or Kiro Account
// Manager provider labels) that mean "external IdP / enterprise SSO" and must
// normalize to "external_idp".
var externalIdpAuthMethodAliases = map[string]bool{
	"external_idp": true,
	"azuread":      true,
	"azure":        true,
	"entra":        true,
	"entra-id":     true,
	"entra_id":     true,
	"microsoft":    true,
	"m365":         true,
	"office365":    true,
	"external":     true,
}

// normalizeImportAuthMethod maps a pasted credential JSON's authMethod (plus its
// clientId/clientSecret/tokenEndpoint) onto one of the three canonical methods
// ("external_idp" | "idc" | "social"). external_idp MUST be detected before the
// clientId+clientSecret→idc inference, because external_idp accounts carry clientId
// but NO clientSecret, so the old default branch misclassified them as "social" and
// refresh hit the wrong endpoint.
//
// It preserves the pre-existing idc/social heuristics:
//   - empty authMethod + clientId present             -> idc
//   - empty authMethod, no clientId                   -> social
//   - "enterprise" (Kiro Account Manager IdC label)   -> idc
//   - unrecognized non-empty + clientId+clientSecret  -> idc, else social
func normalizeImportAuthMethod(authMethod, clientID, clientSecret, tokenEndpoint string) string {
	am := strings.ToLower(strings.TrimSpace(authMethod))
	switch {
	case externalIdpAuthMethodAliases[am]:
		return "external_idp"
	case tokenEndpoint != "": // infer when not declared explicitly
		return "external_idp"
	case am == "social" || am == "google" || am == "github":
		return "social"
	case am == "idc" || am == "builderid" || am == "enterprise":
		return "idc"
	}
	if am == "" {
		if clientID != "" {
			return "idc"
		}
		return "social"
	}
	if clientID != "" && clientSecret != "" {
		return "idc"
	}
	return "social"
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./proxy/ -run TestNormalizeImportAuthMethod -v`
Expected: PASS (13 subtests).

- [ ] **Step 5: Commit**

```bash
git add proxy/handler.go proxy/import_credentials_test.go
git commit -m "feat(proxy): add normalizeImportAuthMethod helper"
```

---

### Task 3: Wire `external_idp` into `apiImportCredentials`

**Files:**
- Modify: `proxy/handler.go` `apiImportCredentials` (lines 3008–3109)
- Test: `proxy/import_credentials_test.go` (append)

**Interfaces:**
- Consumes: `normalizeImportAuthMethod` (Task 2), `auth.ValidateExternalIdpEndpoint` + `auth.SetExternalIdpValidatorForTest` (Task 1).
- Produces: a backend that accepts, validates, refreshes, and persists `external_idp` accounts.

- [ ] **Step 1: Write the failing tests**

Append to `proxy/import_credentials_test.go`:

```go
// TestApiImportCredentialsExternalIdpHappyPath verifies an external_idp credential
// imports successfully: authMethod normalizes to external_idp, refresh hits the
// (fake) IdP token endpoint, and the account is persisted with all refresh material.
func TestApiImportCredentialsExternalIdpHappyPath(t *testing.T) {
	cfgFile := t.TempDir() + "/config.json"
	if err := config.Init(cfgFile); err != nil {
		t.Fatalf("config.Init: %v", err)
	}
	defer installCleanAuthClient(t)()

	const upstreamExpiresIn = 3600
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		if got := r.PostForm.Get("grant_type"); got != "refresh_token" {
			t.Errorf("expected grant_type=refresh_token, got %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		// external IdP token responses are snake_case.
		fmt.Fprintf(w, `{"access_token":"at-ext","refresh_token":"rt-rotated","expires_in":%d}`, upstreamExpiresIn)
	}))
	defer fake.Close()

	// fake.URL is http + 127.0.0.1; bypass the allow-list validator for this test.
	restore := auth.SetExternalIdpValidatorForTest(func(string) error { return nil })
	defer auth.SetExternalIdpValidatorForTest(restore)

	h := &Handler{pool: accountpool.GetPool()}

	body := fmt.Sprintf(`{"authMethod":"external_idp","refreshToken":"rt-ext","clientId":"ext-client","tokenEndpoint":%q,"issuerUrl":"https://login.microsoftonline.com/t/v2.0","scopes":"api://x/codewhisperer:conversations offline_access","region":"eu-central-1"}`, fake.URL)
	req := httptest.NewRequest("POST", "/auth/credentials", strings.NewReader(body))
	rec := httptest.NewRecorder()
	before := time.Now().Unix()
	h.apiImportCredentials(rec, req)
	after := time.Now().Unix()

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	accs := config.GetAccounts()
	if len(accs) != 1 {
		t.Fatalf("expected 1 account persisted, got %d", len(accs))
	}
	got := accs[0]
	if got.AuthMethod != "external_idp" {
		t.Fatalf("AuthMethod: want external_idp, got %q", got.AuthMethod)
	}
	if got.AccessToken != "at-ext" {
		t.Fatalf("AccessToken: want at-ext, got %q", got.AccessToken)
	}
	if got.RefreshToken != "rt-rotated" {
		t.Fatalf("RefreshToken: want rt-rotated (rotated), got %q", got.RefreshToken)
	}
	if got.TokenEndpoint != fake.URL {
		t.Fatalf("TokenEndpoint not persisted: got %q", got.TokenEndpoint)
	}
	if got.ClientID != "ext-client" {
		t.Fatalf("ClientID not persisted: got %q", got.ClientID)
	}
	if got.Scopes == "" {
		t.Fatalf("Scopes not persisted: got %q", got.Scopes)
	}
	if got.Provider != "AzureAD" {
		t.Fatalf("Provider default: want AzureAD, got %q", got.Provider)
	}
	if got.Region != "eu-central-1" {
		t.Fatalf("Region: want eu-central-1, got %q", got.Region)
	}
	if got.ExpiresAt < before+upstreamExpiresIn-5 || got.ExpiresAt > after+upstreamExpiresIn+5 {
		t.Fatalf("ExpiresAt not from upstream expiresIn: got %d (want ~now+%d)", got.ExpiresAt, upstreamExpiresIn)
	}
}

// TestApiImportCredentialsExternalIdpRejectsNonAllowListedEndpoint verifies the SSRF
// guard: a tokenEndpoint outside the IdP allow-list is rejected with 400 before any
// refresh POST, and nothing is persisted. (Validator is NOT bypassed here.)
func TestApiImportCredentialsExternalIdpRejectsNonAllowListedEndpoint(t *testing.T) {
	cfgFile := t.TempDir() + "/config.json"
	if err := config.Init(cfgFile); err != nil {
		t.Fatalf("config.Init: %v", err)
	}
	defer installCleanAuthClient(t)()

	h := &Handler{pool: accountpool.GetPool()}

	body := `{"authMethod":"external_idp","refreshToken":"rt","clientId":"c","tokenEndpoint":"https://evil.example.com/oauth/token","region":"us-east-1"}`
	req := httptest.NewRequest("POST", "/auth/credentials", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.apiImportCredentials(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body.String())
	}
	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !strings.Contains(resp["error"], "endpoint rejected") {
		t.Fatalf("expected endpoint-rejected error, got %q", resp["error"])
	}
	if accs := config.GetAccounts(); len(accs) != 0 {
		t.Fatalf("expected no account persisted, got %d", len(accs))
	}
}

// TestApiImportCredentialsExternalIdpRejectsWhenRefreshFails verifies the refresh
// gate holds for external_idp: a refresh that 400s (invalid_grant) must reject the
// import and persist nothing.
func TestApiImportCredentialsExternalIdpRejectsWhenRefreshFails(t *testing.T) {
	cfgFile := t.TempDir() + "/config.json"
	if err := config.Init(cfgFile); err != nil {
		t.Fatalf("config.Init: %v", err)
	}
	defer installCleanAuthClient(t)()

	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
	}))
	defer fake.Close()

	restore := auth.SetExternalIdpValidatorForTest(func(string) error { return nil })
	defer auth.SetExternalIdpValidatorForTest(restore)

	h := &Handler{pool: accountpool.GetPool()}

	body := fmt.Sprintf(`{"authMethod":"external_idp","refreshToken":"rt-broken","clientId":"c","tokenEndpoint":%q,"region":"us-east-1"}`, fake.URL)
	req := httptest.NewRequest("POST", "/auth/credentials", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.apiImportCredentials(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body.String())
	}
	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !strings.Contains(resp["error"], "Token refresh failed") {
		t.Fatalf("expected refresh-failed error, got %q", resp["error"])
	}
	if accs := config.GetAccounts(); len(accs) != 0 {
		t.Fatalf("expected no account persisted, got %d", len(accs))
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./proxy/ -run 'TestApiImportCredentialsExternalIdp' -v`
Expected: `TestApiImportCredentialsExternalIdpHappyPath` FAIL (current code normalizes external_idp→social→refresh hits the real AWS social endpoint, not `fake.URL`, so returns 400). The reject-SSRF test FAIL too (no validation yet → it would attempt refresh / return a different error).

- [ ] **Step 3: Modify the request struct (handler.go 3009–3017)**

Replace:
```go
	var req struct {
		AccessToken  string `json:"accessToken"`
		RefreshToken string `json:"refreshToken"`
		ClientID     string `json:"clientId"`
		ClientSecret string `json:"clientSecret"`
		AuthMethod   string `json:"authMethod"`
		Provider     string `json:"provider"`
		Region       string `json:"region"`
	}
```
With:
```go
	var req struct {
		AccessToken  string `json:"accessToken"`
		RefreshToken string `json:"refreshToken"`
		ClientID     string `json:"clientId"`
		ClientSecret string `json:"clientSecret"`
		AuthMethod   string `json:"authMethod"`
		Provider     string `json:"provider"`
		Region       string `json:"region"`
		// external_idp (enterprise SSO / Azure AD) refresh material.
		TokenEndpoint string `json:"tokenEndpoint"`
		IssuerURL     string `json:"issuerUrl"`
		Scopes        string `json:"scopes"`
		// Optional identity preservation when pasting a full account record.
		ID         string `json:"id"`
		Email      string `json:"email"`
		ProfileArn string `json:"profileArn"`
	}
```

- [ ] **Step 4: Replace the authMethod normalization block (handler.go 3034–3053)**

Replace (the `if req.AuthMethod == "" { ... }` block AND the `switch strings.ToLower(req.AuthMethod) { ... }` block):
```go
	if req.AuthMethod == "" {
		if req.ClientID != "" {
			req.AuthMethod = "idc"
		} else {
			req.AuthMethod = "social"
		}
	}
	// 标准化 authMethod
	switch strings.ToLower(req.AuthMethod) {
	case "idc", "builderid", "enterprise":
		req.AuthMethod = "idc"
	case "social", "google", "github":
		req.AuthMethod = "social"
	default:
		if req.ClientID != "" && req.ClientSecret != "" {
			req.AuthMethod = "idc"
		} else {
			req.AuthMethod = "social"
		}
	}
```
With:
```go
	// 标准化 authMethod。external_idp 必须先于 clientId+clientSecret→idc 的推断被识别
	//（external_idp 带 clientId 但没有 clientSecret），否则会被误判成 social 而 refresh 到错误端点。
	req.AuthMethod = normalizeImportAuthMethod(req.AuthMethod, req.ClientID, req.ClientSecret, req.TokenEndpoint)

	// external_idp 的 tokenEndpoint 是用户可填的新信任边界：必须经 allow-list 校验，
	// 否则一份不信任的 credential JSON 可指向内网/攻击者主机，导致 refresh token 被外泄。
	if req.AuthMethod == "external_idp" {
		if req.ClientID == "" || req.TokenEndpoint == "" {
			w.WriteHeader(400)
			json.NewEncoder(w).Encode(map[string]string{"error": "external_idp requires clientId and tokenEndpoint"})
			return
		}
		if err := auth.ValidateExternalIdpEndpoint(req.TokenEndpoint); err != nil {
			w.WriteHeader(400)
			json.NewEncoder(w).Encode(map[string]string{"error": "external IdP endpoint rejected: " + err.Error()})
			return
		}
		if req.IssuerURL != "" {
			if err := auth.ValidateExternalIdpEndpoint(req.IssuerURL); err != nil {
				w.WriteHeader(400)
				json.NewEncoder(w).Encode(map[string]string{"error": "external IdP issuer rejected: " + err.Error()})
				return
			}
		}
	}
```

- [ ] **Step 5: Carry refresh material in tempAccount (handler.go 3058–3064)**

Replace:
```go
	tempAccount := &config.Account{
		RefreshToken: req.RefreshToken,
		ClientID:     req.ClientID,
		ClientSecret: req.ClientSecret,
		AuthMethod:   req.AuthMethod,
		Region:       req.Region,
	}
```
With:
```go
	tempAccount := &config.Account{
		RefreshToken:  req.RefreshToken,
		ClientID:      req.ClientID,
		ClientSecret:  req.ClientSecret,
		AuthMethod:    req.AuthMethod,
		Region:        req.Region,
		TokenEndpoint: req.TokenEndpoint,
		Scopes:        req.Scopes,
	}
```

- [ ] **Step 6: Persist external_idp fields + provider default in created account (handler.go 3079–3093)**

Replace:
```go
	// 创建账号
	account := config.Account{
		ID:           auth.GenerateAccountID(),
		Email:        email,
		AccessToken:  accessToken,
		RefreshToken: req.RefreshToken,
		ClientID:     req.ClientID,
		ClientSecret: req.ClientSecret,
		AuthMethod:   req.AuthMethod,
		Provider:     req.Provider,
		Region:       req.Region,
		ExpiresAt:    expiresAt,
		Enabled:      true,
		MachineId:    config.GenerateMachineId(),
		ProfileArn:   newProfileArn,
	}
```
With:
```go
	// 创建账号
	provider := req.Provider
	if provider == "" && req.AuthMethod == "external_idp" {
		provider = "AzureAD"
	}
	account := config.Account{
		ID:            auth.GenerateAccountID(),
		Email:         email,
		AccessToken:   accessToken,
		RefreshToken:  req.RefreshToken,
		ClientID:      req.ClientID,
		ClientSecret:  req.ClientSecret,
		AuthMethod:    req.AuthMethod,
		Provider:      provider,
		Region:        req.Region,
		ExpiresAt:     expiresAt,
		Enabled:       true,
		MachineId:     config.GenerateMachineId(),
		ProfileArn:    newProfileArn,
		TokenEndpoint: req.TokenEndpoint,
		IssuerURL:     req.IssuerURL,
		Scopes:        req.Scopes,
	}
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `go test ./proxy/ -run 'TestApiImportCredentialsExternalIdp' -v`
Expected: PASS (3 tests). Also run the full handler suite to confirm no regressions:
Run: `go test ./proxy/ ./auth/ ./config/ ./pool/ -v`
Expected: all PASS (including pre-existing `TestApiImportCredentialsRejectsWhenRefreshFails` and `TestApiImportCredentialsUsesUpstreamExpiresAt`).

- [ ] **Step 8: Commit**

```bash
git add proxy/handler.go proxy/import_credentials_test.go
git commit -m "feat(auth): import external_idp credentials via Add credential JSON"
```

---

### Task 4: Identity preservation for full-record paste

**Files:**
- Modify: `config/config.go` (after `GetAccounts`, line ~414)
- Modify: `proxy/handler.go` `apiImportCredentials` (email line ~3076, created-account block)
- Test: `proxy/import_credentials_test.go` (append)

**Interfaces:**
- Consumes: `req.ID`, `req.Email`, `req.ProfileArn` (added to struct in Task 3).
- Produces: `config.AccountIDExists(id string) bool` (used by the handler to avoid duplicate IDs when re-importing a backup).

- [ ] **Step 1: Write the failing test**

Append to `proxy/import_credentials_test.go`:

```go
// TestApiImportCredentialsExternalIdpPreservesFullRecordIdentity verifies that when
// a full account record (with id/email/profileArn) is pasted, those are preserved
// rather than regenerated, so re-importing a backup does not duplicate accounts.
func TestApiImportCredentialsExternalIdpPreservesFullRecordIdentity(t *testing.T) {
	cfgFile := t.TempDir() + "/config.json"
	if err := config.Init(cfgFile); err != nil {
		t.Fatalf("config.Init: %v", err)
	}
	defer installCleanAuthClient(t)()

	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token":"at-ext","refresh_token":"rt-rotated","expires_in":3600}`)
	}))
	defer fake.Close()

	restore := auth.SetExternalIdpValidatorForTest(func(string) error { return nil })
	defer auth.SetExternalIdpValidatorForTest(restore)

	h := &Handler{pool: accountpool.GetPool()}

	const providedID = "11111111-2222-3333-4444-555555555555"
	body := fmt.Sprintf(`{"id":%q,"email":"ada@example.com","profileArn":"arn:aws:codewhisperer:eu-central-1:1:profile/PRESERVED","authMethod":"external_idp","refreshToken":"rt","clientId":"c","tokenEndpoint":%q,"region":"eu-central-1"}`, providedID, fake.URL)
	req := httptest.NewRequest("POST", "/auth/credentials", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.apiImportCredentials(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	got := config.GetAccounts()[0]
	if got.ID != providedID {
		t.Fatalf("ID: want reused %q, got %q", providedID, got.ID)
	}
	if got.Email != "ada@example.com" {
		t.Fatalf("Email: want ada@example.com (GetUserInfo empty in test → fallback), got %q", got.Email)
	}
	if got.ProfileArn != "arn:aws:codewhisperer:eu-central-1:1:profile/PRESERVED" {
		t.Fatalf("ProfileArn: want preserved, got %q", got.ProfileArn)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./proxy/ -run TestApiImportCredentialsExternalIdpPreservesFullRecordIdentity -v`
Expected: FAIL — the ID is a fresh `GenerateAccountID()` (not `providedID`), email is whatever `GetUserInfo` returned (likely empty, not `ada@example.com`), and ProfileArn is `""` (external_idp refresh returns no profileArn), not the preserved value.

- [ ] **Step 3: Add `config.AccountIDExists` (config.go)**

In `config/config.go`, immediately after `GetAccounts` (after line 414, before `GetEnabledAccounts`), add:

```go
// AccountIDExists reports whether an account with the given ID is already stored.
// Used by the credential-import path to reuse a pasted record's id when it does
// not collide, so re-importing a backup never creates a duplicate entry.
func AccountIDExists(id string) bool {
	if id == "" {
		return false
	}
	cfgLock.RLock()
	defer cfgLock.RUnlock()
	for _, a := range cfg.Accounts {
		if a.ID == id {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Add email fallback (handler.go, the `GetUserInfo` line ~3076)**

Replace:
```go
	// 获取用户信息
	email, _, _ := auth.GetUserInfo(accessToken)
```
With:
```go
	// 获取用户信息
	email, _, _ := auth.GetUserInfo(accessToken)
	if email == "" {
		email = req.Email // fall back to a pasted full record's email
	}
```

- [ ] **Step 5: Add id reuse + profileArn fallback (handler.go created-account block)**

In Task 3's created-account block, replace:
```go
	// 创建账号
	provider := req.Provider
	if provider == "" && req.AuthMethod == "external_idp" {
		provider = "AzureAD"
	}
	account := config.Account{
		ID:            auth.GenerateAccountID(),
		Email:         email,
```
With:
```go
	// 创建账号
	provider := req.Provider
	if provider == "" && req.AuthMethod == "external_idp" {
		provider = "AzureAD"
	}
	// Reuse a pasted record's id when it does not collide; otherwise mint a fresh one
	// so re-importing a backup never creates a duplicate entry.
	id := req.ID
	if id == "" || config.AccountIDExists(id) {
		id = auth.GenerateAccountID()
	}
	profileArn := newProfileArn
	if profileArn == "" {
		profileArn = req.ProfileArn // external_idp refresh returns no profileArn
	}
	account := config.Account{
		ID:            id,
		Email:         email,
```

And in the same struct literal, replace `ProfileArn: newProfileArn,` with `ProfileArn: profileArn,`:
```go
		ProfileArn:    profileArn,
```

- [ ] **Step 6: Run test to verify it passes**

Run: `go test ./proxy/ -run TestApiImportCredentialsExternalIdpPreservesFullRecordIdentity -v`
Expected: PASS.
Then the full suite: `go test ./... ` (from repo root)
Expected: all PASS.

- [ ] **Step 7: Commit**

```bash
git add config/config.go proxy/handler.go proxy/import_credentials_test.go
git commit -m "feat(auth): preserve id/email/profileArn when importing full records"
```

---

### Task 5: Frontend `importCredentials` (current UI, `web/app.js`)

**Files:**
- Modify: `web/app.js` `importCredentials` (lines 2289–2299, 2319–2333)
- Verification: manual (no JS test harness in this repo)

**Interfaces:**
- Consumes: backend `/auth/credentials` (now accepts `tokenEndpoint`/`issuerUrl`/`scopes`/`id`/`email`/`profileArn` and recognizes `external_idp`).
- Produces: a UI that pastes all three JSON shapes (single object, array/Kiro export, full record) into a correct payload.

- [ ] **Step 1: Extend the `json.accounts` map (app.js 2289–2299)**

Replace:
```js
        items = json.accounts.map(a => {
          const c = a.credentials || {};
          return {
            refreshToken: c.refreshToken || a.refreshToken,
            clientId: c.clientId || a.clientId,
            clientSecret: c.clientSecret || a.clientSecret,
            region: c.region || a.region,
            authMethod: c.authMethod || a.authMethod,
            provider: c.provider || a.provider || a.idp
          };
        });
```
With:
```js
        items = json.accounts.map(a => {
          const c = a.credentials || {};
          return {
            refreshToken: c.refreshToken || a.refreshToken,
            clientId: c.clientId || a.clientId,
            clientSecret: c.clientSecret || a.clientSecret,
            region: c.region || a.region,
            authMethod: c.authMethod || a.authMethod,
            provider: c.provider || a.provider || a.idp,
            tokenEndpoint: c.tokenEndpoint || a.tokenEndpoint,
            issuerUrl: c.issuerUrl || a.issuerUrl,
            scopes: c.scopes || a.scopes,
            id: a.id,
            email: c.email || a.email,
            profileArn: c.profileArn || a.profileArn
          };
        });
```

- [ ] **Step 2: Recognize `external_idp` + extend payload (app.js 2319–2333)**

Replace:
```js
      let authMethod = item.authMethod || '';
      if (item.clientId && item.clientSecret) authMethod = 'idc';
      else if (!authMethod || authMethod === 'social') authMethod = 'social';
      else authMethod = authMethod.toLowerCase() === 'idc' ? 'idc' : 'social';
      let provider = item.provider || '';
      if (!provider && authMethod === 'social') provider = 'Google';
      if (!provider && authMethod === 'idc') provider = 'BuilderId';
      const payload = {
        refreshToken: item.refreshToken,
        accessToken: item.accessToken || '',
        clientId: item.clientId || '',
        clientSecret: item.clientSecret || '',
        authMethod, provider,
        region: item.region || 'us-east-1'
      };
```
With:
```js
      const EXTERNAL_IDP = ['external_idp','azuread','azure','entra','entra-id','microsoft','m365','office365','external'];
      let authMethod = (item.authMethod || '').toLowerCase();
      if (EXTERNAL_IDP.includes(authMethod) || item.tokenEndpoint) {
        authMethod = 'external_idp';
      } else if (item.clientId && item.clientSecret) {
        authMethod = 'idc';
      } else if (!authMethod || authMethod === 'social') {
        authMethod = 'social';
      } else {
        authMethod = authMethod === 'idc' ? 'idc' : 'social';
      }
      let provider = item.provider || '';
      if (!provider && authMethod === 'external_idp') provider = 'AzureAD';
      if (!provider && authMethod === 'social') provider = 'Google';
      if (!provider && authMethod === 'idc') provider = 'BuilderId';
      const payload = {
        refreshToken: item.refreshToken,
        accessToken: item.accessToken || '',
        clientId: item.clientId || '',
        clientSecret: item.clientSecret || '',
        authMethod, provider,
        region: item.region || 'us-east-1',
        tokenEndpoint: item.tokenEndpoint || '',
        issuerUrl: item.issuerUrl || '',
        scopes: item.scopes || '',
        ...(item.id ? { id: item.id } : {}),
        ...(item.email ? { email: item.email } : {}),
        ...(item.profileArn ? { profileArn: item.profileArn } : {})
      };
```

- [ ] **Step 3: Verify (manual)**

Rebuild & restart the server (so any embedded assets pick up the change):
Run: `go build -o kiro-go.exe .`
Launch: `./kiro-go.exe` (in a separate terminal)
Then in the admin panel (log in), go to **Accounts → Add → "Credential JSON"**:

a. **Single object:** paste
```json
{"authMethod":"external_idp","refreshToken":"<real>","clientId":"<real>","tokenEndpoint":"https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token","issuerUrl":"https://login.microsoftonline.com/<tenant>/v2.0","scopes":"<real>","region":"eu-central-1"}
```
Expected: toast "Imported: 1", account appears with provider "AzureAD", region eu-central-1, the real email.

b. **Full record:** paste a record copied from `data/config.json` (the `external_idp` object with `id`/`email`/`profileArn`).
Expected: account imported with the SAME `id` (no duplicate) and the preserved `profileArn`/`email`.

c. **Kiro export:** paste `{"version":2,"accounts":[{"credentials":{...external_idp fields...}}]}`.
Expected: "Imported: 1".

d. **Negative (SSRF):** paste the single object but change `tokenEndpoint` to `https://evil.example.com/x`.
Expected: "Failed: 1" in the toast (exact reason visible in the browser devtools Network tab on the `/auth/credentials` response: `external IdP endpoint rejected: ...`).

If a step fails, re-read the relevant diff above; do not edit by guess.

- [ ] **Step 4: Commit**

```bash
git add web/app.js
git commit -m "feat(ui): import external_idp credentials from Add credential JSON"
```

---

### Task 6: Frontend parity (`web/index-legacy.html`)

**Files:**
- Modify: `web/index-legacy.html` `importCredentials` (lines 2850–2861, 2869–2881)
- Verification: manual

**Interfaces:** same as Task 5 — keep the two UIs in sync so the legacy page also imports `external_idp`.

- [ ] **Step 1: Extend the `json.accounts` map (index-legacy.html 2850–2861)**

Replace:
```js
                    items = json.accounts.map(a => {
                        const c = a.credentials || {};
                        return {
                            refreshToken: c.refreshToken || a.refreshToken,
                            clientId: c.clientId || a.clientId,
                            clientSecret: c.clientSecret || a.clientSecret,
                            region: c.region || a.region,
                            // 不传 accessToken，强制后端用 refreshToken 刷新获取新 token
                            authMethod: c.authMethod || a.authMethod,
                            provider: c.provider || a.provider || a.idp
                        };
                    });
```
With:
```js
                    items = json.accounts.map(a => {
                        const c = a.credentials || {};
                        return {
                            refreshToken: c.refreshToken || a.refreshToken,
                            clientId: c.clientId || a.clientId,
                            clientSecret: c.clientSecret || a.clientSecret,
                            region: c.region || a.region,
                            // 不传 accessToken，强制后端用 refreshToken 刷新获取新 token
                            authMethod: c.authMethod || a.authMethod,
                            provider: c.provider || a.provider || a.idp,
                            tokenEndpoint: c.tokenEndpoint || a.tokenEndpoint,
                            issuerUrl: c.issuerUrl || a.issuerUrl,
                            scopes: c.scopes || a.scopes,
                            id: a.id,
                            email: c.email || a.email,
                            profileArn: c.profileArn || a.profileArn
                        };
                    });
```

- [ ] **Step 2: Recognize `external_idp` + extend payload (index-legacy.html 2869–2881)**

Replace:
```js
                    // 映射 authMethod: IdC/idc -> idc, social -> social
                    let authMethod = item.authMethod || '';
                    if (item.clientId && item.clientSecret) {
                        authMethod = 'idc';
                    } else if (!authMethod || authMethod === 'social') {
                        authMethod = 'social';
                    } else {
                        authMethod = authMethod.toLowerCase() === 'idc' ? 'idc' : 'social';
                    }
                    // 映射 provider
                    let provider = item.provider || '';
                    if (!provider && authMethod === 'social') provider = 'Google';
                    if (!provider && authMethod === 'idc') provider = 'BuilderId';
                    const payload = { refreshToken: item.refreshToken, accessToken: item.accessToken || '', clientId: item.clientId || '', clientSecret: item.clientSecret || '', authMethod: authMethod, provider: provider, region: item.region || 'us-east-1' };
```
With:
```js
                    // 映射 authMethod: external_idp -> external_idp, IdC/idc -> idc, social -> social
                    const EXTERNAL_IDP = ['external_idp','azuread','azure','entra','entra-id','microsoft','m365','office365','external'];
                    let authMethod = (item.authMethod || '').toLowerCase();
                    if (EXTERNAL_IDP.includes(authMethod) || item.tokenEndpoint) {
                        authMethod = 'external_idp';
                    } else if (item.clientId && item.clientSecret) {
                        authMethod = 'idc';
                    } else if (!authMethod || authMethod === 'social') {
                        authMethod = 'social';
                    } else {
                        authMethod = authMethod.toLowerCase() === 'idc' ? 'idc' : 'social';
                    }
                    // 映射 provider
                    let provider = item.provider || '';
                    if (!provider && authMethod === 'external_idp') provider = 'AzureAD';
                    if (!provider && authMethod === 'social') provider = 'Google';
                    if (!provider && authMethod === 'idc') provider = 'BuilderId';
                    const payload = { refreshToken: item.refreshToken, accessToken: item.accessToken || '', clientId: item.clientId || '', clientSecret: item.clientSecret || '', authMethod: authMethod, provider: provider, region: item.region || 'us-east-1', tokenEndpoint: item.tokenEndpoint || '', issuerUrl: item.issuerUrl || '', scopes: item.scopes || '', ...(item.id ? { id: item.id } : {}), ...(item.email ? { email: item.email } : {}), ...(item.profileArn ? { profileArn: item.profileArn } : {}) };
```

- [ ] **Step 3: Verify (manual)**

Rebuild (`go build -o kiro-go.exe .`) and restart. Open the legacy page and repeat the four paste scenarios from Task 5 Step 3. Expected outcomes are identical (alert shows "Imported: 1" / "Failed: 1").

- [ ] **Step 4: Commit**

```bash
git add web/index-legacy.html
git commit -m "feat(ui): legacy parity for external_idp credential import"
```

---

## Final Verification

- [ ] Full test suite passes: `go test ./...` (from `C:\Users\Admin\Kiro-Go`)
- [ ] `go vet ./...` is clean
- [ ] Server builds: `go build -o kiro-go.exe .`
- [ ] Manual end-to-end: paste each of the three JSON shapes (single object, full record, Kiro export) for a real `external_idp` account → all import successfully and the account refreshes + serves a request; pasting an off-allow-list `tokenEndpoint` is rejected.

## Out of scope (explicitly deferred)

- No JWT `exp` trust-on-import (refresh-on-import remains mandatory).
- No changes to `parseLineCredentials` (line format does not carry `tokenEndpoint`/`scopes`).
- No new external IdPs beyond the Microsoft allow-list; add new suffixes to `allowedExternalIdpIssuerSuffixes` separately if needed.
- No upsert-by-email; duplicate IDs are avoided via `config.AccountIDExists`, but re-importing a record whose `email` already exists under a different `id` creates a second entry (acceptable; out of scope).
