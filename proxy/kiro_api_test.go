package proxy

import (
	"io"
	"kiro-go/auth"
	"kiro-go/config"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestResolveProfileArnReturnsCachedValueWithoutRequest(t *testing.T) {
	kiroRestHttpStore.Store(&http.Client{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			t.Fatal("unexpected HTTP request for cached profile ARN")
			return nil, nil
		}),
	})
	t.Cleanup(func() { InitKiroHttpClient("") })

	account := &config.Account{ProfileArn: " arn:aws:codewhisperer:profile/test "}
	got, err := ResolveProfileArn(account)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "arn:aws:codewhisperer:profile/test" {
		t.Fatalf("expected trimmed cached ARN, got %q", got)
	}
}

func TestRegionalizeURLPrefersProfileArnRegion(t *testing.T) {
	account := &config.Account{
		Region:     "ap-southeast-1",
		ProfileArn: "arn:aws:codewhisperer:us-east-1:123456789012:profile/test",
	}

	rawURL := "https://q.us-east-1.amazonaws.com/getUsageLimits?origin=AI_EDITOR"
	if got := regionalizeURL(rawURL, account); got != rawURL {
		t.Fatalf("expected profile ARN region to keep us-east-1 URL, got %q", got)
	}
}

func TestRegionalizeURLForProfileUsesPayloadProfileArnRegion(t *testing.T) {
	account := &config.Account{Region: "ap-southeast-1"}

	got := regionalizeURLForProfile(
		"https://codewhisperer.us-east-1.amazonaws.com/generateAssistantResponse",
		account,
		"arn:aws:codewhisperer:eu-central-1:123456789012:profile/test",
	)
	want := "https://q.eu-central-1.amazonaws.com/generateAssistantResponse"
	if got != want {
		t.Fatalf("expected payload profile ARN region URL %q, got %q", want, got)
	}
}

func TestRegionalizeURLDoesNotUseOAuthAuthenticationRegion(t *testing.T) {
	account := &config.Account{
		AuthMethod: "idc",
		Region:     "ap-southeast-2",
	}

	rawURL := "https://q.us-east-1.amazonaws.com/generateAssistantResponse"
	if got := regionalizeURL(rawURL, account); got != rawURL {
		t.Fatalf("expected missing profile ARN to keep the safe default endpoint, got %q", got)
	}
}

func TestResolveProfileArnFetchesAndCachesProfile(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.json")
	if err := config.Init(configPath); err != nil {
		t.Fatalf("init config: %v", err)
	}
	account := config.Account{
		ID:           "acct-1",
		Email:        "user@example.com",
		AccessToken:  "access-token",
		Region:       "us-east-1",
		UsageCurrent: 7,
	}
	if err := config.AddAccount(account); err != nil {
		t.Fatalf("add account: %v", err)
	}

	kiroRestHttpStore.Store(&http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.Method != http.MethodPost {
				t.Fatalf("expected POST, got %s", req.Method)
			}
			if req.URL.Path != "/ListAvailableProfiles" {
				t.Fatalf("expected ListAvailableProfiles path, got %s", req.URL.Path)
			}
			if got := req.Header.Get("Content-Type"); got != "application/json" {
				t.Fatalf("expected JSON content type, got %q", got)
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"profiles":[{"arn":" arn:aws:codewhisperer:us-east-1:123456789012:profile/fetched "}]} `)),
				Header:     make(http.Header),
			}, nil
		}),
	})
	t.Cleanup(func() { InitKiroHttpClient("") })

	requestAccount := account
	requestAccount.UsageCurrent = 0
	got, err := ResolveProfileArn(&requestAccount)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "arn:aws:codewhisperer:us-east-1:123456789012:profile/fetched" {
		t.Fatalf("expected fetched ARN, got %q", got)
	}
	if requestAccount.ProfileArn != got {
		t.Fatalf("expected account to be updated with fetched ARN, got %q", requestAccount.ProfileArn)
	}

	accounts := config.GetAccounts()
	if len(accounts) != 1 {
		t.Fatalf("expected one persisted account, got %d", len(accounts))
	}
	if accounts[0].ProfileArn != got {
		t.Fatalf("expected persisted account profile ARN %q, got %q", got, accounts[0].ProfileArn)
	}
	if accounts[0].UsageCurrent != 7 {
		t.Fatalf("expected profile cache update to preserve usage fields, got usageCurrent=%v", accounts[0].UsageCurrent)
	}
}

func TestResolveProfileArnSuppressesBuilderIDUnsupportedLookup(t *testing.T) {
	clearProfileArnResolutionCooldowns()
	t.Cleanup(clearProfileArnResolutionCooldowns)

	var calls int32
	kiroRestHttpStore.Store(&http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			atomic.AddInt32(&calls, 1)
			if req.URL.Path != "/ListAvailableProfiles" {
				t.Fatalf("expected ListAvailableProfiles path, got %s", req.URL.Path)
			}
			return &http.Response{
				StatusCode: http.StatusForbidden,
				Body:       io.NopCloser(strings.NewReader(`{"message":"AWS Builder ID is not supported for this operation.","reason":null}`)),
				Header:     make(http.Header),
			}, nil
		}),
	})
	t.Cleanup(func() { InitKiroHttpClient("") })

	account := &config.Account{
		ID:          "builder-1",
		Email:       "builder@example.com",
		AccessToken: "access-token",
		Provider:    "BuilderId",
		Region:      "us-east-1",
	}

	_, err := ResolveProfileArn(account)
	if err == nil || !isProfileArnResolutionUnsupportedError(err) {
		t.Fatalf("expected Builder ID unsupported error, got %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("expected one profile lookup, got %d", got)
	}

	_, err = ResolveProfileArn(account)
	if err == nil || !isProfileArnResolutionSkippedError(err) {
		t.Fatalf("expected skipped profile ARN resolution error, got %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("expected no repeated profile lookup after suppression, got %d", got)
	}
}

func TestResolveProfileArnKeepsRefreshFallbackForBuilderIDUnsupportedLookup(t *testing.T) {
	clearProfileArnResolutionCooldowns()
	t.Cleanup(clearProfileArnResolutionCooldowns)

	kiroRestHttpStore.Store(&http.Client{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusForbidden,
				Body:       io.NopCloser(strings.NewReader(`{"message":"AWS Builder ID is not supported for this operation.","reason":null}`)),
				Header:     make(http.Header),
			}, nil
		}),
	})
	t.Cleanup(func() { InitKiroHttpClient("") })

	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"accessToken":"new-access","refreshToken":"new-refresh","expiresIn":3600,"profileArn":"arn:aws:codewhisperer:profile/from-refresh"}`))
	}))
	t.Cleanup(authServer.Close)

	oldTokenURL := auth.GetOIDCTokenURLForTest()
	auth.SetOIDCTokenURLForTest(func(string) string { return authServer.URL })
	t.Cleanup(func() { auth.SetOIDCTokenURLForTest(oldTokenURL) })
	oldAuthClient := auth.SetGlobalAuthClientForTest(authServer.Client())
	t.Cleanup(func() { auth.SetGlobalAuthClientForTest(oldAuthClient) })

	account := &config.Account{
		ID:           "builder-refresh-1",
		Email:        "builder@example.com",
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		AuthMethod:   "idc",
		Provider:     "BuilderId",
		Region:       "us-east-1",
	}

	got, err := ResolveProfileArn(account)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "arn:aws:codewhisperer:profile/from-refresh" {
		t.Fatalf("expected refresh fallback ARN, got %q", got)
	}
	if isProfileArnResolutionSuppressed(account) {
		t.Fatalf("refresh fallback success should not suppress future profile resolution")
	}
}

func TestRefreshAccountInfoDoesNotDisableBuilderIDWhenProfileLookupUnsupported(t *testing.T) {
	clearProfileArnResolutionCooldowns()
	t.Cleanup(clearProfileArnResolutionCooldowns)

	configPath := filepath.Join(t.TempDir(), "config.json")
	if err := config.Init(configPath); err != nil {
		t.Fatalf("init config: %v", err)
	}
	account := config.Account{
		ID:          "builder-refresh-info-1",
		Email:       "builder@example.com",
		AccessToken: "access-token",
		Provider:    "BuilderId",
		Region:      "us-east-1",
		Enabled:     true,
	}
	if err := config.AddAccount(account); err != nil {
		t.Fatalf("add account: %v", err)
	}

	var profileCalls, usageCalls int32
	kiroRestHttpStore.Store(&http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			switch req.URL.Path {
			case "/ListAvailableProfiles":
				atomic.AddInt32(&profileCalls, 1)
				return &http.Response{
					StatusCode: http.StatusForbidden,
					Body:       io.NopCloser(strings.NewReader(`{"message":"AWS Builder ID is not supported for this operation.","reason":null}`)),
					Header:     make(http.Header),
				}, nil
			case "/getUsageLimits":
				atomic.AddInt32(&usageCalls, 1)
				if strings.Contains(req.URL.RawQuery, "profileArn=") {
					t.Fatalf("expected Builder ID usage refresh to continue without profileArn, got query %q", req.URL.RawQuery)
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`{}`)),
					Header:     make(http.Header),
				}, nil
			default:
				t.Fatalf("unexpected request path %s", req.URL.Path)
				return nil, nil
			}
		}),
	})
	t.Cleanup(func() { InitKiroHttpClient("") })

	requestAccount := account
	if _, err := RefreshAccountInfo(&requestAccount); err != nil {
		t.Fatalf("expected refresh to continue without profile ARN, got %v", err)
	}
	if got := atomic.LoadInt32(&profileCalls); got != 1 {
		t.Fatalf("expected one profile lookup, got %d", got)
	}
	if got := atomic.LoadInt32(&usageCalls); got != 1 {
		t.Fatalf("expected one usage request, got %d", got)
	}
	accounts := config.GetAccounts()
	if len(accounts) != 1 {
		t.Fatalf("expected one account, got %d", len(accounts))
	}
	if !accounts[0].Enabled || accounts[0].BanStatus != "" {
		t.Fatalf("expected account to remain enabled, got enabled=%v banStatus=%q", accounts[0].Enabled, accounts[0].BanStatus)
	}
}

func TestListKiroProfilesFollowsNextTokenPagination(t *testing.T) {
	if err := config.Init(filepath.Join(t.TempDir(), "config.json")); err != nil {
		t.Fatalf("config.Init: %v", err)
	}
	var pages []string
	kiroRestHttpStore.Store(&http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path != "/ListAvailableProfiles" {
				t.Fatalf("unexpected path %s", req.URL.Path)
			}
			body, _ := io.ReadAll(req.Body)
			pages = append(pages, string(body))
			if strings.Contains(string(body), `"nextToken":"page-2"`) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body: io.NopCloser(strings.NewReader(`{
						"profiles":[{"arn":"arn:aws:codewhisperer:us-east-1:123456789012:profile/two","profileName":"Two"}]
					}`)),
				}, nil
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body: io.NopCloser(strings.NewReader(`{
					"profiles":[{"arn":"arn:aws:codewhisperer:us-east-1:123456789012:profile/one","profileName":"One"}],
					"nextToken":"page-2"
				}`)),
			}, nil
		}),
	})
	t.Cleanup(func() { InitKiroHttpClient("") })

	profiles, err := listKiroProfilesInRegion(&config.Account{
		AccessToken: "token",
		AuthMethod:  "external_idp",
		Region:      "us-east-1",
	}, "us-east-1")
	if err != nil {
		t.Fatalf("list profiles: %v", err)
	}
	if len(pages) != 2 {
		t.Fatalf("pages = %d (%v), want 2", len(pages), pages)
	}
	if len(profiles) != 2 || profiles[0].ARN == "" || profiles[1].ARN == "" {
		t.Fatalf("profiles = %+v, want two ARNs across pages", profiles)
	}
	if strings.Contains(pages[0], "maxResults") {
		t.Fatalf("first page body = %s, must not send maxResults", pages[0])
	}
}

func TestParseKiroProfileARNStrictly(t *testing.T) {
	valid := "arn:aws:codewhisperer:eu-central-1:123456789012:profile/Profile_01"
	canonical, region, ok := parseKiroProfileArn(" " + valid + " ")
	if !ok || canonical != valid || region != "eu-central-1" {
		t.Fatalf("expected valid ARN, got canonical=%q region=%q ok=%v", canonical, region, ok)
	}

	invalid := []string{
		"arn:aws:codewhisperer:profile/test",
		"arn:aws:s3:eu-central-1:123456789012:profile/test",
		"arn:aws:codewhisperer:eu-central-1.evil:123456789012:profile/test",
		"arn:aws:codewhisperer:eu-central-1:not-an-account:profile/test",
		"arn:aws:codewhisperer:eu-central-1:123456789012:project/test",
		"arn:aws:codewhisperer:eu-central-1:123456789012:profile/test/child",
	}
	for _, candidate := range invalid {
		if _, _, ok := parseKiroProfileArn(candidate); ok {
			t.Errorf("expected invalid ARN to be rejected: %q", candidate)
		}
	}
}

func TestKiroProfileRegionCandidatesExternalIncludesBothDataPlanes(t *testing.T) {
	account := &config.Account{AuthMethod: "external_idp", Region: "us-east-1"}
	got := kiroProfileRegionCandidates(account)
	want := []string{"us-east-1", "eu-central-1"}
	if len(got) != len(want) {
		t.Fatalf("expected candidates %v, got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("expected candidates %v, got %v", want, got)
		}
	}

	awsAccount := &config.Account{AuthMethod: "idc", Region: "ap-southeast-2"}
	got = kiroProfileRegionCandidates(awsAccount)
	if len(got) != len(want) {
		t.Fatalf("expected IAM Identity Center candidates %v, got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("expected IAM Identity Center candidates %v, got %v", want, got)
		}
	}
}

func TestKiroProfileRegionCandidatesRejectsUnsafeAccountRegion(t *testing.T) {
	got := kiroProfileRegionCandidates(&config.Account{
		AuthMethod: "external_idp",
		Region:     "evil.amazonaws.com",
	})
	want := []string{"us-east-1", "eu-central-1"}
	if len(got) != len(want) {
		t.Fatalf("expected candidates %v, got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("expected candidates %v, got %v", want, got)
		}
	}
}

func TestDiscoverKiroProfilesAcrossRegionsDeduplicatesAndPreservesAuthRegion(t *testing.T) {
	const (
		usARN = "arn:aws:codewhisperer:us-east-1:123456789012:profile/US_PROFILE"
		euARN = "arn:aws:codewhisperer:eu-central-1:123456789012:profile/EU_PROFILE"
	)
	var hosts []string
	kiroRestHttpStore.Store(&http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			hosts = append(hosts, req.URL.Host)
			if got := req.Header.Get("TokenType"); got != "EXTERNAL_IDP" {
				t.Fatalf("expected EXTERNAL_IDP header, got %q", got)
			}
			var body string
			switch req.URL.Host {
			case "codewhisperer.us-east-1.amazonaws.com":
				body = `{"profiles":[
					{"arn":"` + usARN + `","profileName":"US profile"},
					{"arn":"` + usARN + `","profileName":"duplicate"},
					{"arn":"arn:aws:codewhisperer:bad","profileName":"invalid"}
				]}`
			case "q.eu-central-1.amazonaws.com":
				body = `{"profiles":[
					{"arn":"` + euARN + `","profileName":"EU profile"},
					{"arn":"` + usARN + `","profileName":"cross-region duplicate"}
				]}`
			default:
				t.Fatalf("unexpected profile discovery host %q", req.URL.Host)
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(body)),
				Header:     make(http.Header),
			}, nil
		}),
	})
	t.Cleanup(func() { InitKiroHttpClient("") })

	account := &config.Account{
		AuthMethod:  "external_idp",
		AccessToken: "access-token",
		Region:      "us-east-1",
	}
	profiles, err := DiscoverKiroProfiles(account)
	if err != nil {
		t.Fatalf("discover profiles: %v", err)
	}
	if len(profiles) != 2 {
		t.Fatalf("expected two de-duplicated profiles, got %#v", profiles)
	}
	if profiles[0].ARN != usARN || profiles[0].Name != "US profile" || profiles[0].Region != "us-east-1" {
		t.Fatalf("unexpected US profile: %#v", profiles[0])
	}
	if profiles[1].ARN != euARN || profiles[1].Name != "EU profile" || profiles[1].Region != "eu-central-1" {
		t.Fatalf("unexpected EU profile: %#v", profiles[1])
	}
	if account.Region != "us-east-1" {
		t.Fatalf("profile discovery must not change auth region, got %q", account.Region)
	}
	if len(hosts) != 2 {
		t.Fatalf("expected both data planes to be probed, got hosts %v", hosts)
	}
}

func TestDiscoverKiroProfilesReturnsPartialSuccess(t *testing.T) {
	const euARN = "arn:aws:codewhisperer:eu-central-1:123456789012:profile/EU_PROFILE"
	kiroRestHttpStore.Store(&http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			status := http.StatusOK
			body := `{"profiles":[{"arn":"` + euARN + `","profileName":"EU profile"}]}`
			if req.URL.Host == "codewhisperer.us-east-1.amazonaws.com" {
				status = http.StatusForbidden
				body = `{"message":"not provisioned in this region"}`
			}
			return &http.Response{
				StatusCode: status,
				Body:       io.NopCloser(strings.NewReader(body)),
				Header:     make(http.Header),
			}, nil
		}),
	})
	t.Cleanup(func() { InitKiroHttpClient("") })

	profiles, err := DiscoverKiroProfiles(&config.Account{
		AuthMethod:  "external_idp",
		AccessToken: "access-token",
		Region:      "us-east-1",
	})
	if err != nil {
		t.Fatalf("a failed region must not hide a usable profile: %v", err)
	}
	if len(profiles) != 1 || profiles[0].ARN != euARN {
		t.Fatalf("expected EU partial result, got %#v", profiles)
	}
}

func TestDiscoverKiroProfilesReportsAllRegionFailures(t *testing.T) {
	kiroRestHttpStore.Store(&http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusForbidden,
				Body:       io.NopCloser(strings.NewReader(req.URL.Host + " denied")),
				Header:     make(http.Header),
			}, nil
		}),
	})
	t.Cleanup(func() { InitKiroHttpClient("") })

	profiles, err := DiscoverKiroProfiles(&config.Account{
		AuthMethod:  "external_idp",
		AccessToken: "access-token",
		Region:      "us-east-1",
	})
	if err == nil {
		t.Fatalf("expected aggregate discovery error, got profiles %#v", profiles)
	}
	for _, want := range []string{"us-east-1", "eu-central-1"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("expected error to include %q failure, got %v", want, err)
		}
	}
}

func TestDiscoverKiroProfilesReportsEmptyDiscovery(t *testing.T) {
	kiroRestHttpStore.Store(&http.Client{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"profiles":[]}`)),
				Header:     make(http.Header),
			}, nil
		}),
	})
	t.Cleanup(func() { InitKiroHttpClient("") })

	profiles, err := DiscoverKiroProfiles(&config.Account{
		AuthMethod:  "external_idp",
		AccessToken: "access-token",
		Region:      "us-east-1",
	})
	if err == nil || !strings.Contains(err.Error(), "no available Kiro profile") {
		t.Fatalf("expected empty discovery error, got profiles=%#v err=%v", profiles, err)
	}
}

func TestResolveProfileArnExternalIDPSkipsRefreshFallback(t *testing.T) {
	var authCalls int32
	oldAuthClient := auth.SetGlobalAuthClientForTest(&http.Client{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			atomic.AddInt32(&authCalls, 1)
			return &http.Response{
				StatusCode: http.StatusInternalServerError,
				Body:       io.NopCloser(strings.NewReader(`{"error":"unexpected refresh"}`)),
				Header:     make(http.Header),
			}, nil
		}),
	})
	t.Cleanup(func() { auth.SetGlobalAuthClientForTest(oldAuthClient) })

	kiroRestHttpStore.Store(&http.Client{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"profiles":[]}`)),
				Header:     make(http.Header),
			}, nil
		}),
	})
	t.Cleanup(func() { InitKiroHttpClient("") })

	account := &config.Account{
		AuthMethod:   "external_idp",
		Provider:     "AzureAD",
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
		ClientID:     "11111111-1111-4111-8111-111111111111",
		TokenEndpoint: "https://login.microsoftonline.com/" +
			"22222222-2222-4222-8222-222222222222/oauth2/v2.0/token",
		IssuerURL: "https://login.microsoftonline.com/" +
			"22222222-2222-4222-8222-222222222222/v2.0",
		Scopes: "openid offline_access",
		Region: "us-east-1",
	}
	if _, err := ResolveProfileArn(account); err == nil {
		t.Fatal("expected missing profile error")
	}
	if got := atomic.LoadInt32(&authCalls); got != 0 {
		t.Fatalf("external profile resolution must not refresh tokens, got %d auth calls", got)
	}
	if account.Region != "us-east-1" {
		t.Fatalf("profile resolution must not change auth region, got %q", account.Region)
	}
}

func clearProfileArnResolutionCooldowns() {
	profileArnResolutionCooldowns.Range(func(key, _ interface{}) bool {
		profileArnResolutionCooldowns.Delete(key)
		return true
	})
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}
