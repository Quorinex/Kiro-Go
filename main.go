// Kiro API Proxy - 将 Kiro API 转换为 OpenAI/Anthropic 兼容格式
// 支持多账号池、自动 Token 刷新、流式响应
package main

import (
	"fmt"
	"kiro-api-proxy/config"
	"kiro-api-proxy/pool"
	"kiro-api-proxy/proxy"
	"log"
	"net/http"
	"os"
	"path/filepath"
)

func main() {
	// 配置文件路径，支持环境变量覆盖
	configPath := "data/config.json"
	if envPath := os.Getenv("CONFIG_PATH"); envPath != "" {
		configPath = envPath
	}

	// 确保数据目录存在
	if err := os.MkdirAll(filepath.Dir(configPath), 0755); err != nil {
		log.Fatalf("Failed to create data directory: %v", err)
	}

	// 加载配置
	if err := config.Init(configPath); err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// 环境变量覆盖密码
	if envPassword := os.Getenv("ADMIN_PASSWORD"); envPassword != "" {
		config.SetPassword(envPassword)
	}

	// 初始化账号池
	pool.GetPool()

	// 创建 HTTP 处理器（包含后台刷新任务）
	handler := proxy.NewHandler()

	// 启动服务器
	addr := fmt.Sprintf("%s:%d", config.GetHost(), config.GetPort())
	log.Printf("Kiro API Proxy starting on http://%s", addr)
	log.Printf("Admin panel: http://%s/admin", addr)
	log.Printf("Claude API: http://%s/v1/messages", addr)
	log.Printf("OpenAI API: http://%s/v1/chat/completions", addr)

	if err := http.ListenAndServe(addr, handler); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
