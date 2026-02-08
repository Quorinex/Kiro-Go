package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// BuilderIdSession Builder ID 登录会话
type BuilderIdSession struct {
	ID              string
	ClientID        string
	ClientSecret    string
	DeviceCode      string
	UserCode        string
	VerificationUri string
	Interval        int
	ExpiresAt       time.Time
	Region          string
}

var (
	builderIdSessions = make(map[string]*BuilderIdSession)
	builderIdMu       sync.RWMutex
)

// StartBuilderIdLogin 开始 Builder ID 登录
func StartBuilderIdLogin(region string) (*BuilderIdSession, error) {
	if region == "" {
		region = "us-east-1"
	}

	oidcBase := fmt.Sprintf("https://oidc.%s.amazonaws.com", region)
	startUrl := "https://view.awsapps.com/start"
	scopes := []string{
		"codewhisperer:completions",
		"codewhisperer:analysis",
		"codewhisperer:conversations",
		"codewhisperer:transformations",
		"codewhisperer:taskassist",
	}

	// Step 1: 注册 OIDC 客户端
	regPayload := map[string]interface{}{
		"clientName": "Kiro",
		"clientType": "public",
		"scopes":     scopes,
		"grantTypes": []string{"urn:ietf:params:oauth:grant-type:device_code", "refresh_token"},
		"issuerUrl":  startUrl,
	}

	regBody, _ := json.Marshal(regPayload)
	regReq, _ := http.NewRequest("POST", oidcBase+"/client/register", bytes.NewReader(regBody))
	regReq.Header.Set("Content-Type", "application/json")

	client := httpClient
	regResp, err := client.Do(regReq)
	if err != nil {
		return nil, fmt.Errorf("register client failed: %v", err)
	}
	defer regResp.Body.Close()

	if regResp.StatusCode != 200 {
		respBody, _ := io.ReadAll(regResp.Body)
		return nil, fmt.Errorf("register client failed: %d %s", regResp.StatusCode, string(respBody))
	}

	var regResult struct {
		ClientID     string `json:"clientId"`
		ClientSecret string `json:"clientSecret"`
	}
	if err := json.NewDecoder(regResp.Body).Decode(&regResult); err != nil {
		return nil, fmt.Errorf("parse register response failed: %v", err)
	}

	// Step 2: 发起设备授权
	authPayload := map[string]string{
		"clientId":     regResult.ClientID,
		"clientSecret": regResult.ClientSecret,
		"startUrl":     startUrl,
	}

	authBody, _ := json.Marshal(authPayload)
	authReq, _ := http.NewRequest("POST", oidcBase+"/device_authorization", bytes.NewReader(authBody))
	authReq.Header.Set("Content-Type", "application/json")

	authResp, err := client.Do(authReq)
	if err != nil {
		return nil, fmt.Errorf("device authorization failed: %v", err)
	}
	defer authResp.Body.Close()

	if authResp.StatusCode != 200 {
		respBody, _ := io.ReadAll(authResp.Body)
		return nil, fmt.Errorf("device authorization failed: %d %s", authResp.StatusCode, string(respBody))
	}

	var authResult struct {
		DeviceCode              string `json:"deviceCode"`
		UserCode                string `json:"userCode"`
		VerificationUri         string `json:"verificationUri"`
		VerificationUriComplete string `json:"verificationUriComplete"`
		Interval                int    `json:"interval"`
		ExpiresIn               int    `json:"expiresIn"`
	}
	if err := json.NewDecoder(authResp.Body).Decode(&authResult); err != nil {
		return nil, fmt.Errorf("parse auth response failed: %v", err)
	}

	if authResult.Interval == 0 {
		authResult.Interval = 5
	}
	if authResult.ExpiresIn == 0 {
		authResult.ExpiresIn = 600
	}

	verificationUri := authResult.VerificationUriComplete
	if verificationUri == "" {
		verificationUri = authResult.VerificationUri
	}

	session := &BuilderIdSession{
		ID:              GenerateAccountID(),
		ClientID:        regResult.ClientID,
		ClientSecret:    regResult.ClientSecret,
		DeviceCode:      authResult.DeviceCode,
		UserCode:        authResult.UserCode,
		VerificationUri: verificationUri,
		Interval:        authResult.Interval,
		ExpiresAt:       time.Now().Add(time.Duration(authResult.ExpiresIn) * time.Second),
		Region:          region,
	}

	builderIdMu.Lock()
	builderIdSessions[session.ID] = session
	builderIdMu.Unlock()

	// 清理过期会话
	go cleanupExpiredBuilderIdSessions()

	return session, nil
}

// PollBuilderIdAuth 轮询 Builder ID 授权状态
func PollBuilderIdAuth(sessionID string) (accessToken, refreshToken, clientID, clientSecret, region string, expiresIn int, status string, err error) {
	builderIdMu.RLock()
	session, exists := builderIdSessions[sessionID]
	builderIdMu.RUnlock()

	if !exists {
		return "", "", "", "", "", 0, "", fmt.Errorf("session not found or expired")
	}

	if time.Now().After(session.ExpiresAt) {
		builderIdMu.Lock()
		delete(builderIdSessions, sessionID)
		builderIdMu.Unlock()
		return "", "", "", "", "", 0, "", fmt.Errorf("authorization expired")
	}

	oidcBase := fmt.Sprintf("https://oidc.%s.amazonaws.com", session.Region)

	tokenPayload := map[string]string{
		"clientId":     session.ClientID,
		"clientSecret": session.ClientSecret,
		"grantType":    "urn:ietf:params:oauth:grant-type:device_code",
		"deviceCode":   session.DeviceCode,
	}

	tokenBody, _ := json.Marshal(tokenPayload)
	tokenReq, _ := http.NewRequest("POST", oidcBase+"/token", bytes.NewReader(tokenBody))
	tokenReq.Header.Set("Content-Type", "application/json")

	client := httpClient
	tokenResp, err := client.Do(tokenReq)
	if err != nil {
		return "", "", "", "", "", 0, "", fmt.Errorf("token request failed: %v", err)
	}
	defer tokenResp.Body.Close()

	if tokenResp.StatusCode == 200 {
		var tokenResult struct {
			AccessToken  string `json:"accessToken"`
			RefreshToken string `json:"refreshToken"`
			ExpiresIn    int    `json:"expiresIn"`
		}
		if err := json.NewDecoder(tokenResp.Body).Decode(&tokenResult); err != nil {
			return "", "", "", "", "", 0, "", fmt.Errorf("parse token response failed: %v", err)
		}

		// 清理会话
		builderIdMu.Lock()
		delete(builderIdSessions, sessionID)
		builderIdMu.Unlock()

		return tokenResult.AccessToken, tokenResult.RefreshToken, session.ClientID, session.ClientSecret, session.Region, tokenResult.ExpiresIn, "completed", nil
	}

	if tokenResp.StatusCode == 400 {
		var errResult struct {
			Error string `json:"error"`
		}
		json.NewDecoder(tokenResp.Body).Decode(&errResult)

		switch errResult.Error {
		case "authorization_pending":
			return "", "", "", "", "", 0, "pending", nil
		case "slow_down":
			// 增加轮询间隔
			builderIdMu.Lock()
			if s, ok := builderIdSessions[sessionID]; ok {
				s.Interval += 5
			}
			builderIdMu.Unlock()
			return "", "", "", "", "", 0, "slow_down", nil
		case "expired_token":
			builderIdMu.Lock()
			delete(builderIdSessions, sessionID)
			builderIdMu.Unlock()
			return "", "", "", "", "", 0, "", fmt.Errorf("device code expired")
		case "access_denied":
			builderIdMu.Lock()
			delete(builderIdSessions, sessionID)
			builderIdMu.Unlock()
			return "", "", "", "", "", 0, "", fmt.Errorf("user denied authorization")
		default:
			return "", "", "", "", "", 0, "", fmt.Errorf("authorization error: %s", errResult.Error)
		}
	}

	return "", "", "", "", "", 0, "", fmt.Errorf("unexpected response: %d", tokenResp.StatusCode)
}

// GetBuilderIdSession 获取会话信息
func GetBuilderIdSession(sessionID string) *BuilderIdSession {
	builderIdMu.RLock()
	defer builderIdMu.RUnlock()
	return builderIdSessions[sessionID]
}

// cleanupExpiredBuilderIdSessions 清理过期会话
func cleanupExpiredBuilderIdSessions() {
	builderIdMu.Lock()
	defer builderIdMu.Unlock()

	now := time.Now()
	for id, session := range builderIdSessions {
		if now.After(session.ExpiresAt) {
			delete(builderIdSessions, id)
		}
	}
}
