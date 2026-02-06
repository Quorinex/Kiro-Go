package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// ImportFromSsoToken 从 SSO Token (x-amz-sso_authn) 导入账号
func ImportFromSsoToken(bearerToken, region string) (accessToken, refreshToken, clientID, clientSecret string, expiresIn int, err error) {
	if region == "" {
		region = "us-east-1"
	}

	oidcBase := fmt.Sprintf("https://oidc.%s.amazonaws.com", region)
	portalBase := "https://portal.sso.us-east-1.amazonaws.com"
	startUrl := "https://view.awsapps.com/start"

	// 1. 注册 OIDC 客户端
	clientID, clientSecret, err = registerDeviceClient(oidcBase, startUrl)
	if err != nil {
		return "", "", "", "", 0, fmt.Errorf("注册客户端失败: %w", err)
	}

	// 2. 发起设备授权
	deviceCode, userCode, interval, err := startDeviceAuth(oidcBase, clientID, clientSecret, startUrl)
	if err != nil {
		return "", "", "", "", 0, fmt.Errorf("设备授权失败: %w", err)
	}

	// 3. 验证 Bearer Token
	if err := verifyBearerToken(portalBase, bearerToken); err != nil {
		return "", "", "", "", 0, fmt.Errorf("Token 验证失败: %w", err)
	}

	// 4. 获取设备会话令牌
	deviceSessionToken, err := getDeviceSessionToken(portalBase, bearerToken)
	if err != nil {
		return "", "", "", "", 0, fmt.Errorf("获取设备会话失败: %w", err)
	}

	// 5. 接受用户代码
	deviceContext, err := acceptUserCode(oidcBase, userCode, deviceSessionToken)
	if err != nil {
		return "", "", "", "", 0, fmt.Errorf("接受用户代码失败: %w", err)
	}

	// 6. 批准授权
	if deviceContext != nil {
		if err := approveAuth(oidcBase, deviceContext, deviceSessionToken); err != nil {
			return "", "", "", "", 0, fmt.Errorf("批准授权失败: %w", err)
		}
	}

	// 7. 轮询获取 Token
	accessToken, refreshToken, expiresIn, err = pollForToken(oidcBase, clientID, clientSecret, deviceCode, interval)
	if err != nil {
		return "", "", "", "", 0, fmt.Errorf("获取 Token 失败: %w", err)
	}

	return accessToken, refreshToken, clientID, clientSecret, expiresIn, nil
}

func registerDeviceClient(oidcBase, startUrl string) (clientID, clientSecret string, err error) {
	payload := map[string]interface{}{
		"clientName": "Kiro API Proxy",
		"clientType": "public",
		"scopes":     scopes,
		"grantTypes": []string{"urn:ietf:params:oauth:grant-type:device_code", "refresh_token"},
		"issuerUrl":  startUrl,
	}

	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", oidcBase+"/client/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	client := httpClient
	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return "", "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		ClientID     string `json:"clientId"`
		ClientSecret string `json:"clientSecret"`
	}
	json.NewDecoder(resp.Body).Decode(&result)
	return result.ClientID, result.ClientSecret, nil
}

func startDeviceAuth(oidcBase, clientID, clientSecret, startUrl string) (deviceCode, userCode string, interval int, err error) {
	payload := map[string]string{
		"clientId":     clientID,
		"clientSecret": clientSecret,
		"startUrl":     startUrl,
	}

	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", oidcBase+"/device_authorization", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	client := httpClient
	resp, err := client.Do(req)
	if err != nil {
		return "", "", 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return "", "", 0, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		DeviceCode string `json:"deviceCode"`
		UserCode   string `json:"userCode"`
		Interval   int    `json:"interval"`
	}
	json.NewDecoder(resp.Body).Decode(&result)
	if result.Interval == 0 {
		result.Interval = 1
	}
	return result.DeviceCode, result.UserCode, result.Interval, nil
}

func verifyBearerToken(portalBase, bearerToken string) error {
	req, _ := http.NewRequest("GET", portalBase+"/token/whoAmI", nil)
	req.Header.Set("Authorization", "Bearer "+bearerToken)
	req.Header.Set("Accept", "application/json")

	client := httpClient
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

func getDeviceSessionToken(portalBase, bearerToken string) (string, error) {
	req, _ := http.NewRequest("POST", portalBase+"/session/device", bytes.NewReader([]byte("{}")))
	req.Header.Set("Authorization", "Bearer "+bearerToken)
	req.Header.Set("Content-Type", "application/json")

	client := httpClient
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Token string `json:"token"`
	}
	json.NewDecoder(resp.Body).Decode(&result)
	return result.Token, nil
}

type deviceContextInfo struct {
	DeviceContextID string `json:"deviceContextId"`
	ClientID        string `json:"clientId"`
	ClientType      string `json:"clientType"`
}

func acceptUserCode(oidcBase, userCode, deviceSessionToken string) (*deviceContextInfo, error) {
	payload := map[string]string{
		"userCode":      userCode,
		"userSessionId": deviceSessionToken,
	}

	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", oidcBase+"/device_authorization/accept_user_code", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Referer", "https://view.awsapps.com/")

	client := httpClient
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		DeviceContext *deviceContextInfo `json:"deviceContext"`
	}
	json.NewDecoder(resp.Body).Decode(&result)
	return result.DeviceContext, nil
}

func approveAuth(oidcBase string, deviceContext *deviceContextInfo, deviceSessionToken string) error {
	payload := map[string]interface{}{
		"deviceContext": map[string]string{
			"deviceContextId": deviceContext.DeviceContextID,
			"clientId":        deviceContext.ClientID,
			"clientType":      deviceContext.ClientType,
		},
		"userSessionId": deviceSessionToken,
	}

	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", oidcBase+"/device_authorization/associate_token", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Referer", "https://view.awsapps.com/")

	client := httpClient
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

func pollForToken(oidcBase, clientID, clientSecret, deviceCode string, interval int) (accessToken, refreshToken string, expiresIn int, err error) {
	payload := map[string]string{
		"clientId":     clientID,
		"clientSecret": clientSecret,
		"grantType":    "urn:ietf:params:oauth:grant-type:device_code",
		"deviceCode":   deviceCode,
	}

	timeout := time.After(2 * time.Minute)
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			return "", "", 0, fmt.Errorf("授权超时")
		case <-ticker.C:
			body, _ := json.Marshal(payload)
			req, _ := http.NewRequest("POST", oidcBase+"/token", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")

			client := httpClient
			resp, err := client.Do(req)
			if err != nil {
				continue
			}

			if resp.StatusCode == 200 {
				var result struct {
					AccessToken  string `json:"accessToken"`
					RefreshToken string `json:"refreshToken"`
					ExpiresIn    int    `json:"expiresIn"`
				}
				json.NewDecoder(resp.Body).Decode(&result)
				resp.Body.Close()
				return result.AccessToken, result.RefreshToken, result.ExpiresIn, nil
			}

			if resp.StatusCode == 400 {
				var errResult struct {
					Error string `json:"error"`
				}
				json.NewDecoder(resp.Body).Decode(&errResult)
				resp.Body.Close()

				if errResult.Error == "authorization_pending" {
					continue
				} else if errResult.Error == "slow_down" {
					interval += 5
					ticker.Reset(time.Duration(interval) * time.Second)
					continue
				}
				return "", "", 0, fmt.Errorf("授权错误: %s", errResult.Error)
			}
			resp.Body.Close()
		}
	}
}

// GetUserInfo 获取用户信息
func GetUserInfo(accessToken string) (email, userID string, err error) {
	// 调用 Kiro API 获取用量信息（包含用户信息）
	url := "https://q.us-east-1.amazonaws.com/getUsageLimits?origin=AI_EDITOR&resourceType=AGENTIC_REQUEST&isEmailRequired=true"

	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "aws-sdk-js/1.0.18 KiroAPIProxy")
	req.Header.Set("x-amz-user-agent", "aws-sdk-js/1.0.18 KiroAPIProxy")

	client := httpClient
	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var result struct {
		UserInfo struct {
			Email  string `json:"email"`
			UserID string `json:"userId"`
		} `json:"userInfo"`
	}
	json.NewDecoder(resp.Body).Decode(&result)
	return result.UserInfo.Email, result.UserInfo.UserID, nil
}

// GenerateAccountID 生成账号 ID
func GenerateAccountID() string {
	return uuid.New().String()
}
