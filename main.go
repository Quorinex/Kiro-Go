// Package main provides the entry point for Kiro API Proxy.
//
// Kiro API Proxy is a reverse proxy service that translates Kiro API requests
// into OpenAI and Anthropic (Claude) compatible formats. Key features include:
//   - Multi-account pool with round-robin load balancing
//   - Automatic OAuth token refresh
//   - Streaming response support for real-time AI interactions
//   - Admin panel for account and configuration management
//
// The service exposes the following endpoints:
//   - /v1/messages - Claude API compatible endpoint
//   - /v1/chat/completions - OpenAI API compatible endpoint
//   - /admin - Web-based administration panel
package main

import (
	"context"
	"errors"
	"fmt"
	"kiro-go/config"
	"kiro-go/logger"
	"kiro-go/pool"
	"kiro-go/proxy"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
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

	// Initialize log level: LOG_LEVEL env var takes priority over config, defaulting to "info".
	logger.Init(config.GetLogLevel())

	// 环境变量覆盖密码
	if envPassword := os.Getenv("ADMIN_PASSWORD"); envPassword != "" {
		config.SetPassword(envPassword)
	}

	// 生产安全态势告警（不改变行为，仅提示）：默认密码 / 公网无认证裸奔。
	// 这两个组合是真实事故的高频根因，启动时一次性提示，方便运维尽早发现。
	if config.GetPassword() == "changeme" {
		logger.Warnf("[SECURITY] 管理密码仍为默认 'changeme'，请通过 ADMIN_PASSWORD 环境变量或管理面板尽快修改")
	}
	if config.GetHost() == "0.0.0.0" && !config.IsApiKeyRequired() {
		logger.Warnf("[SECURITY] 监听 0.0.0.0 且未强制 API Key 鉴权：服务对外无认证开放；生产环境请设置 requireApiKey=true 或限制绑定地址")
	}

	// 初始化账号池
	pool.GetPool()

	// 初始化请求审计持久化（默认 JSONL，失败自动禁用；KIRO_AUDIT_DISABLE 可关闭）。
	// 审计写入异步非阻塞，缓冲满即丢弃并计数（kiro_audit_dropped_total），绝不拖垮主流程。
	proxy.InitAuditStore(filepath.Dir(configPath))
	defer proxy.CloseAuditStore()

	// 创建 HTTP 处理器（包含后台刷新任务）
	handler := proxy.NewHandler()

	// 启动服务器
	addr := fmt.Sprintf("%s:%d", config.GetHost(), config.GetPort())
	logger.Infof("Kiro-Go starting on http://%s (log level: %s)", addr, logger.LevelName(logger.GetLevel()))
	logger.Infof("Admin panel: http://%s/admin", addr)
	logger.Infof("Claude API: http://%s/v1/messages", addr)
	logger.Infof("OpenAI API: http://%s/v1/chat/completions", addr)

	// WrapHardening adds the outer zero-dep hardening chain (panic recovery,
	// request-id, security headers, 64 MiB body cap) around the existing handler
	// without altering its routing.
	rootHandler := proxy.WrapHardening(handler)

	// WriteTimeout intentionally 0: SSE streams can run for minutes while the
	// upstream model produces tokens. ReadHeaderTimeout + ReadTimeout still
	// guard against slowloris-style header/body stalls.
	srv := &http.Server{
		Addr:              addr,
		Handler:           rootHandler,
		ReadHeaderTimeout: 30 * time.Second,
		ReadTimeout:       60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Graceful shutdown: SIGINT/SIGTERM drains in-flight requests (including
	// long SSE streams) for up to shutdownTimeout before forcing exit. Without
	// this a rolling deploy / Ctrl+C killed the process mid-stream, dropping
	// every in-flight request and leaving clients hanging on a half-open stream.
	//
	// The serve/shutdown loop is factored into runServerWithDrain so the
	// signal->drain->shutdown path is unit-testable (Windows taskkill cannot
	// deliver SIGINT to a detached console process, so the only reliable way to
	// exercise this path here is via a test harness).
	const shutdownTimeout = 55 * time.Second
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signals)

	if err := runServerWithDrain(srv.ListenAndServe, srv.Shutdown, nil, signals, shutdownTimeout); err != nil {
		logger.Fatalf("Server failed: %v", err)
	}
}

// runServerWithDrain runs serve() until either a signal arrives or serve errors.
// On signal it calls drain (if non-nil), then shutdown(ctx) bounded by timeout,
// and finally waits for serve to return (or the timeout to elapse) before
// returning. A nil drain is a no-op — this repo has no cluster worker to drain.
func runServerWithDrain(serve func() error, shutdown func(context.Context) error, drain func(), signals <-chan os.Signal, timeout time.Duration) error {
	errCh := make(chan error, 1)
	go func() { errCh <- serve() }()

	select {
	case sig := <-signals:
		logger.Infof("Received %s, shutting down (draining in-flight requests for up to %s)", sig, timeout)
		if drain != nil {
			drain()
		}
		if timeout <= 0 {
			timeout = 55 * time.Second
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		if err := shutdown(ctx); err != nil {
			cancel()
			return err
		}
		// shutdown returned (all in-flight drained) — wait for ListenAndServe
		// to actually unblock, or give up when the deadline passes.
		select {
		case err := <-errCh:
			cancel()
			return normalizeServerShutdownError(err)
		case <-ctx.Done():
			cancel()
			return ctx.Err()
		}
	case err := <-errCh:
		return normalizeServerShutdownError(err)
	}
}

// normalizeServerShutdownError treats http.ErrServerClosed as success — that is
// the error ListenAndServe returns after a graceful Shutdown, not a real failure.
func normalizeServerShutdownError(err error) error {
	if err == nil || errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
