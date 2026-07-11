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
	clientCfg := config.GetKiroClientConfig()
	machineID := ""
	if account != nil {
		machineID = account.MachineId
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
	if account != nil && account.AccessToken != "" {
		req.Header.Set("Authorization", "Bearer "+account.AccessToken)
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
