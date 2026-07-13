package proxy

import (
	"fmt"
	"kiro-go/config"
	"net/http"
)

const (
	kiroStreamingSDKVersion = "1.0.34"
	kiroRuntimeSDKVersion   = "1.0.0"
)

type kiroHeaderValues struct {
	UserAgent    string
	AmzUserAgent string
	Host         string
}

func buildStreamingHeaderValues(account *config.Account, host string) kiroHeaderValues {
	return buildKiroHeaderValues(account, host, "codewhispererstreaming", kiroStreamingSDKVersion, "m/E")
}

func buildRuntimeHeaderValues(account *config.Account, host string) kiroHeaderValues {
	return buildKiroHeaderValues(account, host, "codewhispererruntime", kiroRuntimeSDKVersion, "m/N,E")
}

func buildKiroHeaderValues(account *config.Account, host, apiName, sdkVersion, mode string) kiroHeaderValues {
	accountID := ""
	if account != nil {
		accountID = account.ID
	}
	// Derive the desktop fingerprint (platform/version) from the same accountID
	// used for the device id below, so an account's platform and device stay
	// mutually consistent — one stable mac/win install, never a Linux server.
	clientCfg := config.GetKiroClientConfig(accountID)
	machineID := ""
	if account != nil {
		machineID = account.MachineId
		// Never let machineId be empty: an empty value drops the UA suffix and
		// makes this account's User-Agent identical to every other empty-id
		// account, which is the strongest cross-account association signal
		// upstream can correlate on. Fall back to a stable, account-derived
		// 64-hex id (sha256) so the UA always carries a unique, fixed device
		// fingerprint — same value per account across requests and restarts.
		// Ported from kiro-tutu (zero-dep: config.DeriveMachineId is stdlib).
		if machineID == "" && account.ID != "" {
			machineID = config.DeriveMachineId(account.ID)
		}
	}

	userAgent := fmt.Sprintf(
		"aws-sdk-js/%s ua/2.1 os/%s lang/js md/nodejs#%s api/%s#%s %s KiroIDE-%s",
		sdkVersion,
		clientCfg.SystemVersion,
		clientCfg.NodeVersion,
		apiName,
		sdkVersion,
		mode,
		clientCfg.KiroVersion,
	)
	amzUserAgent := fmt.Sprintf("aws-sdk-js/%s KiroIDE-%s", sdkVersion, clientCfg.KiroVersion)
	if machineID != "" {
		userAgent += "-" + machineID
		amzUserAgent += "-" + machineID
	}

	return kiroHeaderValues{
		UserAgent:    userAgent,
		AmzUserAgent: amzUserAgent,
		Host:         host,
	}
}

func applyKiroBaseHeaders(req *http.Request, account *config.Account, values kiroHeaderValues) {
	if account != nil {
		if account.IsApiKeyCredential() {
			if account.KiroApiKey != "" {
				req.Header.Set("Authorization", "Bearer "+account.KiroApiKey)
				req.Header.Set("tokentype", "API_KEY")
			}
		} else if account.AccessToken != "" {
			req.Header.Set("Authorization", "Bearer "+account.AccessToken)
		}
	}
	req.Header.Set("User-Agent", values.UserAgent)
	req.Header.Set("x-amz-user-agent", values.AmzUserAgent)
	req.Header.Set("x-amzn-codewhisperer-optout", "true")
	// External IdP (enterprise SSO, e.g. Azure AD) tokens MUST carry this header or
	// CodeWhisperer does not recognize the token type and silently returns an empty
	// profile list (and rejects data-plane calls). With it, a provisioned account
	// resolves its profile; an unprovisioned one gets a clear 403.
	if account != nil && account.AuthMethod == "external_idp" {
		req.Header.Set("TokenType", "EXTERNAL_IDP")
	}
	if values.Host != "" {
		req.Host = values.Host
	}
}
