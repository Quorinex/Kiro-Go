package auth

// kiro_sso.go implements the Kiro hosted browser sign-in flow — the same flow
// the Kiro IDE uses at https://app.kiro.dev/signin. Unlike Builder ID / IAM
// Identity Center (AWS SSO OIDC), this portal federates Google, GitHub, AND
// enterprise identity providers (e.g. a Microsoft 365 / Entra ID / Azure AD
// tenant) behind a single PKCE authorization-code flow. It is the only way an
// enterprise Azure-tenant account — which is neither an AWS Builder ID nor an
// AWS IAM Identity Center account — can sign in to Kiro.
//
// The flow has two possible legs, both captured by one transient loopback
// listener bound on the fixed redirect port:
//
//   - Social (Google/GitHub): the portal authenticates via its Cognito backend
//     and redirects the authorization code straight back to the loopback
//     redirect. The code is exchanged at the Kiro social token endpoint.
//
//   - Enterprise / external IdP (Azure AD): the portal detects the email belongs
//     to an external IdP and redirects to /signin/callback with the IdP
//     descriptor (issuer_url, client_id, scopes) instead of a code. We then drive
//     a SECOND OIDC authorization-code+PKCE flow directly against that IdP
//     (loopback redirect to /oauth/callback) and exchange the code at the IdP
//     token endpoint. The resulting access token is an IdP-issued token scoped
//     for CodeWhisperer; it is used as the runtime bearer and refreshed against
//     the IdP token endpoint (see refreshExternalIdpToken in oidc.go).
//
// The login is exposed through the admin panel with the same Start/Poll session
// pattern as Builder ID: StartKiroSsoLogin binds the listener and returns the
// sign-in URL; the operator opens it in a browser ON THE SAME HOST (the redirect
// targets 127.0.0.1:3128); PollKiroSsoAuth reports pending until the listener
// captures the code, then exchanges it and returns the credential.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"kiro-go/config"
	"kiro-go/logger"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	// kiroSignInBaseURL is the Kiro hosted sign-in page opened in the browser.
	kiroSignInBaseURL = "https://app.kiro.dev/signin"
	// kiroRedirectURI is the fixed loopback redirect the portal validates and
	// redirects back to once sign-in succeeds. The host is "localhost" (the value
	// the portal expects) while the listener binds the 127.0.0.1 / [::1] literals;
	// the browser resolving "localhost" to either loopback address is what bridges
	// the two, so the operator's host must resolve localhost to loopback.
	kiroRedirectURI = "http://localhost:3128"
	// kiroRedirectPort is the loopback port embedded in kiroRedirectURI.
	kiroRedirectPort = "3128"
	// kiroRedirectFrom mirrors the Kiro IDE client tag the portal expects.
	kiroRedirectFrom = "KiroIDE"
	// kiroOAuthCallbackPath is the loopback path the enterprise (external IdP)
	// leg redirects the authorization code back to. It is distinct from the
	// portal's /signin/callback so the listener can tell the two legs apart.
	kiroOAuthCallbackPath = "/oauth/callback"
	// kiroSocialTokenURL is the Cognito-backed social code-exchange endpoint. Note
	// this is deliberately a DIFFERENT path from the social refresh endpoint
	// (socialTokenURL() in oidc.go -> /refreshToken): the Kiro IDE exchanges the
	// login code at /oauth/token and refreshes at /refreshToken. Do not unify them.
	kiroSocialTokenURL = "https://prod.us-east-1.auth.desktop.kiro.dev/oauth/token"
	// kiroSsoLoginTimeout bounds how long the listener waits for the user.
	kiroSsoLoginTimeout = 10 * time.Minute
)

// allowedExternalIdpIssuerSuffixes restricts which IdP issuer/endpoint hosts the
// enterprise leg will discover and redirect to. The issuer arrives in an
// attacker-influenceable portal callback query, so it is constrained to known
// enterprise IdP hosts (Microsoft Entra / Azure AD — the supported provider).
// This is the primary control against SSRF, open-redirect, and forced-auth abuse
// via a forged /signin/callback. The leading dot anchors each suffix to a real
// subdomain boundary so "evil-microsoftonline.com" cannot match. Extend this
// list to onboard additional enterprise IdPs.
var allowedExternalIdpIssuerSuffixes = []string{
	".microsoftonline.com",
	".microsoftonline.us",
	".microsoftonline.cn",
}

// KiroSsoSession holds the transient state for one hosted-portal sign-in attempt.
type KiroSsoSession struct {
	ID        string
	Verifier  string // social-leg PKCE verifier (sent at social code exchange)
	State     string // portal anti-CSRF state echoed on the social redirect
	Region    string
	ProxyURL  string
	ExpiresAt time.Time

	srv       *http.Server
	resultCh  chan kiroSsoCapture
	once      sync.Once
	closeOnce sync.Once
	timer     *time.Timer // deadline self-teardown; freed in close()

	mu   sync.Mutex
	leg2 *kiroLeg2 // set when the enterprise descriptor arrives
}

// kiroLeg2 is the per-attempt state captured when the enterprise descriptor
// arrives at /signin/callback and consumed when the IdP redirects the code back.
type kiroLeg2 struct {
	state         string
	verifier      string
	tokenEndpoint string
	issuerURL     string
	clientID      string
	scopes        string
	redirectURI   string
}

// kiroSsoCapture is the raw outcome delivered by the loopback listener: either a
// social authorization code, an enterprise (external IdP) code plus its leg-2
// context, or an error.
type kiroSsoCapture struct {
	kind string // "social" | "external_idp"
	code string
	err  error

	tokenEndpoint string
	issuerURL     string
	clientID      string
	scopes        string
	redirectURI   string
	codeVerifier  string
}

// KiroSsoResult is the resolved credential returned to the admin handler once the
// captured code has been exchanged for tokens.
type KiroSsoResult struct {
	AccessToken   string
	RefreshToken  string
	AuthMethod    string // "external_idp" | "social"
	Provider      string // "AzureAD" | "Kiro SSO"
	ClientID      string // external IdP client id (refresh material)
	TokenEndpoint string // external IdP token endpoint (refresh material)
	IssuerURL     string
	Scopes        string
	ProfileArn    string // social exchange may return it; external IdP resolves lazily
	Region        string
	ExpiresIn     int
	Email         string
}

var (
	kiroSsoSessions   = make(map[string]*KiroSsoSession)
	kiroSsoSessionsMu sync.RWMutex
)

// StartKiroSsoLogin generates PKCE codes, binds the loopback listener, and
// returns the session plus the hosted sign-in URL the operator must open.
func StartKiroSsoLogin(region string) (*KiroSsoSession, string, error) {
	if region == "" {
		region = "us-east-1"
	}

	verifier := generateCodeVerifier()
	challenge := generateCodeChallenge(verifier)
	state := uuid.New().String()

	session := &KiroSsoSession{
		ID:        uuid.New().String(),
		Verifier:  verifier,
		State:     state,
		Region:    region,
		ProxyURL:  config.GetProxyURL(),
		ExpiresAt: time.Now().Add(kiroSsoLoginTimeout),
		resultCh:  make(chan kiroSsoCapture, 1),
	}

	if err := session.startListener(); err != nil {
		return nil, "", err
	}

	params := url.Values{}
	params.Set("state", state)
	params.Set("code_challenge", challenge)
	params.Set("code_challenge_method", "S256")
	params.Set("redirect_uri", kiroRedirectURI)
	params.Set("redirect_from", kiroRedirectFrom)
	signInURL := kiroSignInBaseURL + "?" + params.Encode()

	kiroSsoSessionsMu.Lock()
	kiroSsoSessions[session.ID] = session
	kiroSsoSessionsMu.Unlock()

	// Self-teardown at the deadline: free the loopback listener and drop the
	// session even if the operator abandons the sign-in and the front end stops
	// polling. Without this an abandoned login would hold 127.0.0.1:3128 until the
	// process restarts and block every subsequent SSO login (the redirect port is
	// fixed, so only one sign-in can use it at a time).
	session.timer = time.AfterFunc(kiroSsoLoginTimeout, func() {
		session.close()
		removeKiroSsoSession(session.ID)
	})

	return session, signInURL, nil
}

// PollKiroSsoAuth reports the login status. It returns ("pending", nil) until the
// listener captures a code, then exchanges it and returns the resolved
// credential with status "completed". A terminal error (timeout, exchange
// failure) is returned as a non-nil error.
func PollKiroSsoAuth(sessionID string) (*KiroSsoResult, string, error) {
	kiroSsoSessionsMu.RLock()
	session, ok := kiroSsoSessions[sessionID]
	kiroSsoSessionsMu.RUnlock()
	if !ok {
		return nil, "", fmt.Errorf("session not found or expired")
	}

	select {
	case capture := <-session.resultCh:
		// Terminal: a code (or error) was captured. Tear the listener down and
		// drop the session regardless of exchange outcome.
		session.close()
		removeKiroSsoSession(sessionID)
		if capture.err != nil {
			return nil, "", capture.err
		}
		return session.exchange(capture)
	default:
		if time.Now().After(session.ExpiresAt) {
			session.close()
			removeKiroSsoSession(sessionID)
			return nil, "", fmt.Errorf("SSO login timed out after %s", kiroSsoLoginTimeout)
		}
		return nil, "pending", nil
	}
}

// exchange swaps a captured authorization code for tokens and assembles the
// resolved credential.
func (s *KiroSsoSession) exchange(capture kiroSsoCapture) (*KiroSsoResult, string, error) {
	client := GetAuthClientForProxy(s.ProxyURL)

	if capture.kind == "external_idp" {
		access, refresh, expiresIn, err := exchangeExternalIdpCode(
			client, capture.tokenEndpoint, capture.clientID, capture.code,
			capture.codeVerifier, capture.redirectURI, capture.scopes,
		)
		if err != nil {
			return nil, "", fmt.Errorf("enterprise SSO token exchange failed: %w", err)
		}
		return &KiroSsoResult{
			AccessToken:   access,
			RefreshToken:  refresh,
			AuthMethod:    "external_idp",
			Provider:      "AzureAD",
			ClientID:      capture.clientID,
			TokenEndpoint: capture.tokenEndpoint,
			IssuerURL:     capture.issuerURL,
			Scopes:        capture.scopes,
			Region:        s.Region,
			ExpiresIn:     expiresIn,
			Email:         ExtractEmailFromJWT(access),
		}, "completed", nil
	}

	access, refresh, expiresIn, profileArn, err := exchangeSocialCode(client, capture.code, s.Verifier)
	if err != nil {
		return nil, "", fmt.Errorf("SSO token exchange failed: %w", err)
	}
	return &KiroSsoResult{
		AccessToken:  access,
		RefreshToken: refresh,
		AuthMethod:   "social",
		Provider:     "Kiro SSO",
		ProfileArn:   profileArn,
		Region:       s.Region,
		ExpiresIn:    expiresIn,
		Email:        ExtractEmailFromJWT(access),
	}, "completed", nil
}

// --- Loopback callback listener (state machine across the legs) -------------

// kiroCallbackBindAddrs returns the address(es) the SSO callback listener binds.
//
// By default it binds loopback only — IPv4 127.0.0.1 plus, best-effort, IPv6 ::1
// (a browser resolving "localhost" may use either) — which is the secure default:
// only the same host can reach the transient callback. Set KIRO_SSO_CALLBACK_BIND
// to override the bind host; this is needed when the proxy runs in a container and
// the operator's browser reaches the published port on a non-loopback interface
// (e.g. KIRO_SSO_CALLBACK_BIND=0.0.0.0 with `3128:3128` published in compose). The
// callback is transient (closed at the deadline) and every leg is anti-CSRF
// state-matched, but a non-loopback bind does expose it on the network for the
// login window, so only set it in a trusted/containerized network.
func kiroCallbackBindAddrs() []string {
	if bind := strings.TrimSpace(os.Getenv("KIRO_SSO_CALLBACK_BIND")); bind != "" {
		return []string{net.JoinHostPort(bind, kiroRedirectPort)}
	}
	return []string{"127.0.0.1:" + kiroRedirectPort, "[::1]:" + kiroRedirectPort}
}

// startListener binds the SSO callback listener(s) on the fixed redirect port and
// serves the redirect state machine. The first address is mandatory (its bind
// failure aborts the login); any remaining addresses are best-effort (e.g. the IPv6
// loopback when IPv6 is unavailable).
func (s *KiroSsoSession) startListener() error {
	addrs := kiroCallbackBindAddrs()

	ln, err := net.Listen("tcp", addrs[0])
	if err != nil {
		return fmt.Errorf("cannot bind %s for the SSO callback (is the port already in use?): %w", addrs[0], err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleCallback)
	// ReadHeaderTimeout bounds a stalled local client (slowloris-style).
	s.srv = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}

	serve := func(l net.Listener) {
		go func() {
			if errServe := s.srv.Serve(l); errServe != nil && errServe != http.ErrServerClosed {
				logger.Debugf("[KiroSSO] callback listener (%s) stopped: %v", l.Addr(), errServe)
			}
		}()
	}
	serve(ln)
	for _, addr := range addrs[1:] {
		if extra, errExtra := net.Listen("tcp", addr); errExtra == nil {
			serve(extra)
		} else {
			logger.Debugf("[KiroSSO] secondary callback bind %s skipped: %v", addr, errExtra)
		}
	}
	return nil
}

// close shuts the loopback listener(s) down and stops the deadline timer. Safe to
// call more than once and from multiple goroutines (Poll, the cancel endpoint, and
// the deadline AfterFunc may all race to tear the session down).
func (s *KiroSsoSession) close() {
	s.closeOnce.Do(func() {
		if s.timer != nil {
			s.timer.Stop()
		}
		if s.srv != nil {
			_ = s.srv.Close()
		}
	})
}

// CancelKiroSsoLogin tears an in-flight session down immediately (operator
// cancelled in the admin panel), freeing the loopback port without waiting for the
// deadline. A no-op for an unknown or already-finished session.
func CancelKiroSsoLogin(sessionID string) {
	kiroSsoSessionsMu.RLock()
	session, ok := kiroSsoSessions[sessionID]
	kiroSsoSessionsMu.RUnlock()
	if !ok {
		return
	}
	session.close()
	removeKiroSsoSession(sessionID)
}

// deliver pushes the first (and only) capture onto the result channel.
func (s *KiroSsoSession) deliver(capture kiroSsoCapture) {
	s.once.Do(func() { s.resultCh <- capture })
}

// handleCallback implements the redirect state machine: enterprise leg-1
// descriptor -> 302 to the IdP; enterprise leg-2 code at /oauth/callback;
// otherwise the social code.
func (s *KiroSsoSession) handleCallback(w http.ResponseWriter, req *http.Request) {
	// Only browser GET redirects are expected; reject other methods to shrink
	// the local attack surface.
	if req.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	q := req.URL.Query()

	// --- Enterprise leg-1: external IdP descriptor (no code) ---
	// Gate on path != /oauth/callback so a forged /oauth/callback?issuer_url=...
	// cannot be routed here and reset an in-flight leg-2.
	if req.URL.Path != kiroOAuthCallbackPath &&
		(strings.EqualFold(strings.TrimSpace(q.Get("login_option")), "external_idp") || strings.TrimSpace(q.Get("issuer_url")) != "") {
		// Single-shot: once a leg-2 is in flight, ignore further descriptors so a
		// stray or forged local request cannot reset/hijack the active login.
		s.mu.Lock()
		alreadyStarted := s.leg2 != nil
		s.mu.Unlock()
		if alreadyStarted {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		issuerURL := strings.TrimSpace(q.Get("issuer_url"))
		clientID := strings.TrimSpace(q.Get("client_id"))
		scopes := strings.TrimSpace(q.Get("scopes"))
		loginHint := strings.TrimSpace(q.Get("login_hint"))
		if clientID == "" {
			writeKiroCallbackPage(w, false)
			s.deliver(kiroSsoCapture{err: fmt.Errorf("invalid external IdP descriptor (missing client_id)")})
			return
		}
		// oidcDiscover validates the issuer + both discovered endpoints against
		// the IdP host allow-list, so the issuer here is not trusted blindly.
		authEndpoint, tokenEndpoint, errDisc := oidcDiscover(GetAuthClientForProxy(s.ProxyURL), issuerURL, s.ProxyURL)
		if errDisc != nil {
			writeKiroCallbackPage(w, false)
			s.deliver(kiroSsoCapture{err: errDisc})
			return
		}
		verifier := generateCodeVerifier()
		state2 := uuid.New().String()
		redirectURI := kiroRedirectURI + kiroOAuthCallbackPath
		s.mu.Lock()
		// Re-check under the lock to resolve a race between concurrent
		// descriptors: only the first sets leg2 and is redirected.
		if s.leg2 != nil {
			s.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
			return
		}
		s.leg2 = &kiroLeg2{
			state:         state2,
			verifier:      verifier,
			tokenEndpoint: tokenEndpoint,
			issuerURL:     issuerURL,
			clientID:      clientID,
			scopes:        scopes,
			redirectURI:   redirectURI,
		}
		s.mu.Unlock()
		authURL := externalIdpAuthorizeURL(authEndpoint, clientID, redirectURI, scopes, generateCodeChallenge(verifier), state2, loginHint)
		// Redirect the SAME browser tab on to the IdP login page.
		http.Redirect(w, req, authURL, http.StatusFound)
		return
	}

	// --- Enterprise leg-2: IdP authorization code at /oauth/callback ---
	if req.URL.Path == kiroOAuthCallbackPath {
		s.mu.Lock()
		ctx2 := s.leg2
		s.mu.Unlock()
		code := strings.TrimSpace(q.Get("code"))
		state := strings.TrimSpace(q.Get("state"))
		errParam := strings.TrimSpace(q.Get("error"))
		// Ignore callbacks that don't match the in-flight leg-2 state.
		if ctx2 == nil || state == "" || state != ctx2.state {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if errParam != "" {
			desc := strings.TrimSpace(q.Get("error_description"))
			writeKiroCallbackPage(w, false)
			s.deliver(kiroSsoCapture{err: fmt.Errorf("external IdP authorization error: %s %s", errParam, desc)})
			return
		}
		if code == "" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeKiroCallbackPage(w, true)
		s.deliver(kiroSsoCapture{
			kind:          "external_idp",
			code:          code,
			tokenEndpoint: ctx2.tokenEndpoint,
			issuerURL:     ctx2.issuerURL,
			clientID:      ctx2.clientID,
			scopes:        ctx2.scopes,
			redirectURI:   ctx2.redirectURI,
			codeVerifier:  ctx2.verifier,
		})
		return
	}

	// --- Social leg-1: Cognito authorization code ---
	code := strings.TrimSpace(q.Get("code"))
	errParam := strings.TrimSpace(q.Get("error"))
	state := strings.TrimSpace(q.Get("state"))
	// Ignore stray hits with neither a code nor an error, and any callback whose
	// state does not match — without consuming the one-shot.
	if code == "" && errParam == "" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if s.State == "" || state != s.State {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if errParam != "" {
		desc := strings.TrimSpace(q.Get("error_description"))
		writeKiroCallbackPage(w, false)
		s.deliver(kiroSsoCapture{err: fmt.Errorf("SSO authorization error: %s %s", errParam, desc)})
		return
	}
	writeKiroCallbackPage(w, true)
	s.deliver(kiroSsoCapture{kind: "social", code: code})
}

// --- OIDC discovery + token exchange (enterprise / external IdP leg) ---------

// validateExternalIdpEndpoint verifies rawURL is an https URL whose host is a
// non-IP, allow-listed enterprise IdP host. It gates the issuer (before
// discovery) and BOTH discovered endpoints (the authorize URL the browser is
// 302'd to, and the token endpoint the code is exchanged at).
func validateExternalIdpEndpoint(rawURL string) error {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return fmt.Errorf("invalid external IdP URL: %w", err)
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return fmt.Errorf("external IdP URL must be https")
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return fmt.Errorf("external IdP URL has no host")
	}
	// Reject IP-literal hosts outright; only named, allow-listed hosts pass.
	if net.ParseIP(host) != nil {
		return fmt.Errorf("external IdP host must not be an IP literal")
	}
	for _, suffix := range allowedExternalIdpIssuerSuffixes {
		if strings.HasSuffix(host, suffix) {
			return nil
		}
	}
	return fmt.Errorf("external IdP host %q is not allow-listed", host)
}

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

// issuerFromAccessTokenJWT decodes an unverified Azure AD access token's payload
// and returns its iss claim (e.g. https://login.microsoftonline.com/<tenant>/v2.0).
// No signature verification: this is used only to classify a pasted credential and
// recover the Azure tenant, never to trust the token itself. Returns "" if
// accessToken is not a JWT or has no iss.
func issuerFromAccessTokenJWT(accessToken string) string {
	raw := strings.TrimSpace(accessToken)
	if raw == "" {
		return ""
	}
	parts := strings.Split(raw, ".")
	if len(parts) < 2 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	return claims.Iss
}

// ExpFromAccessTokenJWT decodes an unverified access token's payload and returns
// its exp claim (Unix seconds). No signature verification: this is used only to
// set a trustworthy ExpiresAt when importing an external_idp credential WITHOUT a
// live refresh round-trip (trust-on-import), never to authenticate the token.
// Returns 0 if accessToken is not a JWT or has no exp.
func ExpFromAccessTokenJWT(accessToken string) int64 {
	raw := strings.TrimSpace(accessToken)
	if raw == "" {
		return 0
	}
	parts := strings.Split(raw, ".")
	if len(parts) < 2 {
		return 0
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return 0
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return 0
	}
	return claims.Exp
}

// DeriveExternalIdpEndpoints reconstructs the Microsoft / Azure AD token endpoint,
// OIDC issuer, and default scopes for an external-IdP credential. The Azure tenant
// is recovered from userId (Kiro Account Manager exports carry it at account
// level) or, failing that, from the accessToken JWT's issuer (bare blobs with only
// clientId + accessToken + refreshToken). This lets the credential-import path
// accept those shapes even though they omit tokenEndpoint/issuerUrl/scopes.
//
// userId / iss look like: https://login.microsoftonline.com/<tenant>/v2.0.<oid>
// Returns empty strings if neither source yields a usable tenant, so the caller
// can fall back to its "requires clientId and tokenEndpoint" error. The derived
// tokenEndpoint is re-validated against the IdP allow-list by the caller, so a
// non-allow-listed host (or the test's http+127.0.0.1 fake) is still gated.
func DeriveExternalIdpEndpoints(userId, clientID, accessToken string) (tokenEndpoint, issuerURL, scopes string) {
	src := strings.TrimSpace(userId)
	if src == "" {
		// Bare credential blobs carry only clientId + accessToken: recover the
		// tenant from the access token's JWT issuer.
		src = strings.TrimSpace(issuerFromAccessTokenJWT(accessToken))
	}
	if src == "" {
		return "", "", ""
	}
	u, err := url.Parse(src)
	if err != nil || u.Host == "" {
		return "", "", ""
	}
	segments := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(segments) == 0 || segments[0] == "" {
		return "", "", ""
	}
	tenant := segments[0]
	scheme := u.Scheme
	if scheme == "" {
		scheme = "https"
	}
	tokenEndpoint = fmt.Sprintf("%s://%s/%s/oauth2/v2.0/token", scheme, u.Host, tenant)
	issuerURL = fmt.Sprintf("%s://%s/%s/v2.0", scheme, u.Host, tenant)
	if clientID != "" {
		scopes = fmt.Sprintf("api://%s/codewhisperer:conversations api://%s/codewhisperer:completions offline_access", clientID, clientID)
	}
	return tokenEndpoint, issuerURL, scopes
}

// oidcDiscover fetches the OpenID Connect discovery document for issuerURL and
// returns its authorization and token endpoints. The issuer and BOTH discovered
// endpoints are validated against the IdP host allow-list; redirects are NOT
// followed (so a discovery host cannot bounce the fetch to an internal target);
// and no response body is echoed into errors.
func oidcDiscover(client *http.Client, issuerURL, proxyURL string) (authEndpoint, tokenEndpoint string, err error) {
	if err = validateExternalIdpEndpoint(issuerURL); err != nil {
		return "", "", err
	}
	docURL := strings.TrimRight(strings.TrimSpace(issuerURL), "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequest(http.MethodGet, docURL, nil)
	if err != nil {
		return "", "", fmt.Errorf("failed to build OIDC discovery request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	// Do not follow redirects: the allow-listed issuer host must answer directly,
	// so a 3xx (which could point at an internal/link-local target) is a failure.
	noRedirect := &http.Client{
		Timeout:       30 * time.Second,
		Transport:     buildAuthTransport(proxyURL),
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := noRedirect.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("OIDC discovery request failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", "", fmt.Errorf("failed to read OIDC discovery response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Deliberately omit the body to avoid exfiltrating an internal response.
		return "", "", fmt.Errorf("OIDC discovery failed (status %d)", resp.StatusCode)
	}
	var doc struct {
		AuthorizationEndpoint string `json:"authorization_endpoint"`
		TokenEndpoint         string `json:"token_endpoint"`
	}
	if err = json.Unmarshal(body, &doc); err != nil {
		return "", "", fmt.Errorf("failed to parse OIDC discovery document: %w", err)
	}
	if doc.AuthorizationEndpoint == "" || doc.TokenEndpoint == "" {
		return "", "", fmt.Errorf("OIDC discovery document missing authorization_endpoint or token_endpoint")
	}
	// Both endpoints must themselves be https + allow-listed. The allow-list (the
	// trust boundary) is the only check applied here, not equality with the issuer
	// host: within Microsoft's own *.microsoftonline.com infrastructure the
	// discovery doc legitimately points authorize/token at sibling hosts. If the
	// allow-list is ever broadened to multiple distinct IdPs, tighten this to also
	// pin the endpoints to the issuer's registrable host.
	if err = validateExternalIdpEndpoint(doc.AuthorizationEndpoint); err != nil {
		return "", "", fmt.Errorf("discovered authorization_endpoint rejected: %w", err)
	}
	if err = validateExternalIdpEndpoint(doc.TokenEndpoint); err != nil {
		return "", "", fmt.Errorf("discovered token_endpoint rejected: %w", err)
	}
	return doc.AuthorizationEndpoint, doc.TokenEndpoint, nil
}

// externalIdpAuthorizeURL builds the IdP authorization-code+PKCE URL the browser
// is redirected to for the enterprise leg. scopes is passed through verbatim from
// the portal (already a space-separated list).
func externalIdpAuthorizeURL(authEndpoint, clientID, redirectURI, scopes, challenge, state, loginHint string) string {
	q := url.Values{}
	q.Set("client_id", clientID)
	q.Set("response_type", "code")
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", scopes)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	q.Set("response_mode", "query")
	q.Set("state", state)
	if strings.TrimSpace(loginHint) != "" {
		q.Set("login_hint", loginHint)
	}
	return authEndpoint + "?" + q.Encode()
}

// exchangeExternalIdpCode exchanges an IdP authorization code (with its PKCE
// verifier) for IdP tokens at the discovered token endpoint. Standard OAuth2
// authorization_code grant for a public client (PKCE, no client secret);
// request is form-encoded and the response is snake_case.
func exchangeExternalIdpCode(client *http.Client, tokenEndpoint, clientID, code, codeVerifier, redirectURI, scopes string) (accessToken, refreshToken string, expiresIn int, err error) {
	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("grant_type", "authorization_code")
	form.Set("code", strings.TrimSpace(code))
	form.Set("redirect_uri", redirectURI)
	form.Set("code_verifier", codeVerifier)
	if strings.TrimSpace(scopes) != "" {
		form.Set("scope", scopes)
	}
	return postExternalIdpToken(client, tokenEndpoint, form)
}

// exchangeSocialCode exchanges a Cognito authorization code (with its PKCE
// verifier) for Kiro tokens at the social token endpoint. Request body matches
// the Kiro IDE client — {code, code_verifier, redirect_uri} — and the response
// is camelCase (accessToken/refreshToken/profileArn/expiresIn).
func exchangeSocialCode(client *http.Client, code, codeVerifier string) (accessToken, refreshToken string, expiresIn int, profileArn string, err error) {
	payload := map[string]string{
		"code":          strings.TrimSpace(code),
		"code_verifier": codeVerifier,
		"redirect_uri":  kiroRedirectURI,
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequest(http.MethodPost, kiroSocialTokenURL, bytes.NewReader(body))
	if err != nil {
		return "", "", 0, "", fmt.Errorf("failed to build social token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", "", 0, "", err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	var out struct {
		AccessToken  string `json:"accessToken"`
		RefreshToken string `json:"refreshToken"`
		ProfileArn   string `json:"profileArn"`
		ExpiresIn    int    `json:"expiresIn"`
	}
	_ = json.Unmarshal(respBody, &out)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || out.AccessToken == "" {
		return "", "", 0, "", fmt.Errorf("social token exchange failed (status %d): %s", resp.StatusCode, string(respBody))
	}
	return out.AccessToken, out.RefreshToken, out.ExpiresIn, out.ProfileArn, nil
}

// writeKiroCallbackPage renders a minimal HTML page shown in the browser after
// the final redirect.
func writeKiroCallbackPage(w http.ResponseWriter, ok bool) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	msg := "Kiro sign-in complete. You can close this tab and return to the admin panel."
	if !ok {
		msg = "Kiro sign-in failed. Return to the admin panel and try again."
	}
	_, _ = fmt.Fprintf(w, "<!doctype html><html><head><meta charset=\"utf-8\"><title>Kiro Sign-In</title></head><body style=\"font-family:sans-serif;padding:2rem\"><p>%s</p></body></html>", msg)
}

// ExtractEmailFromJWT decodes the JWT payload of an access token (best-effort)
// and returns the account email. Azure AD v2.0 tokens frequently omit the
// "email" claim and carry the sign-in name in "preferred_username"/"upn", so
// those are used as fallbacks.
func ExtractEmailFromJWT(accessToken string) string {
	parts := strings.Split(strings.TrimSpace(accessToken), ".")
	if len(parts) < 2 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// Some tokens use standard (padded) base64; retry leniently.
		if payload, err = base64.StdEncoding.DecodeString(parts[1]); err != nil {
			return ""
		}
	}
	var claims struct {
		Email             string `json:"email"`
		PreferredUsername string `json:"preferred_username"`
		Upn               string `json:"upn"`
		UniqueName        string `json:"unique_name"`
	}
	if err = json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	for _, candidate := range []string{claims.Email, claims.PreferredUsername, claims.Upn, claims.UniqueName} {
		if v := strings.TrimSpace(candidate); v != "" {
			return v
		}
	}
	return ""
}

// removeKiroSsoSession deletes a session from the registry.
func removeKiroSsoSession(sessionID string) {
	kiroSsoSessionsMu.Lock()
	delete(kiroSsoSessions, sessionID)
	kiroSsoSessionsMu.Unlock()
}

