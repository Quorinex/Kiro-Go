// Package auth 提供认证相关功能的 HTTP 客户端
package auth

import (
	"net/http"
	"time"
)

// 全局 HTTP 客户端，复用连接池
// 用于所有 auth 模块的 HTTP 请求
var httpClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:        50,               // 最大空闲连接数
		MaxIdleConnsPerHost: 10,               // 每个 Host 最大空闲连接数
		IdleConnTimeout:     90 * time.Second, // 空闲连接超时
		DisableCompression:  false,            // 启用压缩
		ForceAttemptHTTP2:   true,             // 尝试使用 HTTP/2
	},
}
