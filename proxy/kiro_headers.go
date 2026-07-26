package proxy

import (
	"fmt"
	"kiro-go/config"
	"net/http"
	"strings"
)

const (
	kiroLegacyStreamingSDKVersion = "1.0.39"
	kiroRuntimeSDKVersion         = "1.0.0"
	kiroCLIVersion                = "2.14.2"
	kiroCLIServiceClientVersion   = "0.1.17975"
)

type kiroHeaderValues struct {
	UserAgent    string
	AmzUserAgent string
	Host         string
}

func buildKiroRuntimeHeaderValues(account *config.Account, host string) kiroHeaderValues {
	return buildKiroHeaderValues(account, host, "kiroruntime", kiroRuntimeSDKVersion, "m/E")
}

func buildLegacyStreamingHeaderValues(account *config.Account, host string) kiroHeaderValues {
	return buildKiroHeaderValues(account, host, "codewhispererstreaming", kiroLegacyStreamingSDKVersion, "m/E")
}

func buildRuntimeHeaderValues(account *config.Account, host string) kiroHeaderValues {
	if config.IsAPIKeyAccount(account) {
		return buildKiroCLIHeaderValues(host, "codewhispererruntime")
	}
	return buildKiroHeaderValues(account, host, "codewhispererruntime", kiroRuntimeSDKVersion, "m/N,E")
}

func buildKiroCLIHeaderValues(host, apiName string) kiroHeaderValues {
	userAgent := fmt.Sprintf(
		"KiroCLI/%s md/appVersion-%s app/AmazonQ-For-CLI api/%s#%s",
		kiroCLIVersion,
		kiroCLIVersion,
		apiName,
		kiroCLIServiceClientVersion,
	)
	return kiroHeaderValues{
		UserAgent:    userAgent,
		AmzUserAgent: userAgent,
		Host:         host,
	}
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
	token := accountBearerToken(account)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	// Kiro requires external identity-provider access tokens and API keys to be
	// identified explicitly. Keep this in the shared header path so streaming
	// and REST requests cannot drift apart.
	req.Header.Del("TokenType")
	req.Header.Del("tokentype")
	if account != nil {
		if config.IsAPIKeyAccount(account) {
			// Upstream accepts either casing; CLI captures use lowercase "tokentype".
			req.Header.Set("tokentype", "API_KEY")
		} else if strings.EqualFold(strings.TrimSpace(account.AuthMethod), "external_idp") {
			req.Header.Set("TokenType", "EXTERNAL_IDP")
		}
	}
	req.Header.Set("User-Agent", values.UserAgent)
	req.Header.Set("x-amz-user-agent", values.AmzUserAgent)
	if account != nil && config.IsAPIKeyAccount(account) {
		req.Header.Set("x-amzn-codewhisperer-optout", "false")
	} else {
		req.Header.Set("x-amzn-codewhisperer-optout", "true")
	}
	if values.Host != "" {
		req.Host = values.Host
	}
}

// accountBearerToken returns the token used for Authorization: Bearer.
// API Key accounts prefer KiroApiKey; OAuth accounts use AccessToken.
func accountBearerToken(account *config.Account) string {
	if account == nil {
		return ""
	}
	if config.IsAPIKeyAccount(account) {
		if key := strings.TrimSpace(account.KiroApiKey); key != "" {
			return key
		}
	}
	return strings.TrimSpace(account.AccessToken)
}
