package config

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
)

// Store 是配置持久化中间层；新增 MySQL 等后端只需实现并注册该接口。
type Store interface {
	Name() string
	Load(ctx context.Context) (*Config, error)
	Save(ctx context.Context, cfg *Config) error
	Close() error
}

// StoreOpener 根据配置文件路径和数据库 URL 创建具体存储后端。
type StoreOpener func(ctx context.Context, configPath, databaseURL string) (Store, error)

var (
	storeRegistryMu sync.RWMutex
	storeRegistry   = map[string]StoreOpener{}
)

// RegisterStoreBackend 注册一个存储后端，供后续 MySQL/SQLite 扩展复用。
func RegisterStoreBackend(name string, opener StoreOpener) {
	key := strings.ToLower(strings.TrimSpace(name))
	if key == "" || opener == nil {
		return
	}
	storeRegistryMu.Lock()
	storeRegistry[key] = opener
	storeRegistryMu.Unlock()
}

// OpenStoreFromEnv 按环境变量选择存储后端。
func OpenStoreFromEnv(ctx context.Context, configPath string) (Store, error) {
	backend := strings.ToLower(strings.TrimSpace(os.Getenv("STORE_BACKEND")))
	if backend == "" {
		backend = "auto"
	}
	databaseURL := strings.TrimSpace(os.Getenv("DATABASE_URL"))

	if backend == "auto" {
		if databaseURL == "" {
			return openStore(ctx, "json", configPath, databaseURL)
		}
		detected, err := detectStoreBackend(databaseURL)
		if err != nil {
			return nil, err
		}
		return openStore(ctx, detected, configPath, databaseURL)
	}

	if backend != "json" && databaseURL == "" {
		return nil, fmt.Errorf("DATABASE_URL is required when STORE_BACKEND=%s", backend)
	}
	return openStore(ctx, backend, configPath, databaseURL)
}

func openStore(ctx context.Context, backend, configPath, databaseURL string) (Store, error) {
	storeRegistryMu.RLock()
	opener := storeRegistry[backend]
	storeRegistryMu.RUnlock()
	if opener == nil {
		return nil, fmt.Errorf("unsupported config store backend %q", backend)
	}
	return opener(ctx, configPath, databaseURL)
}

func detectStoreBackend(databaseURL string) (string, error) {
	parsed, err := url.Parse(databaseURL)
	if err != nil {
		return "", fmt.Errorf("invalid DATABASE_URL: %w", err)
	}
	switch strings.ToLower(parsed.Scheme) {
	case "postgresql":
		return "postgres", nil
	}
	scheme := strings.ToLower(parsed.Scheme)
	storeRegistryMu.RLock()
	_, ok := storeRegistry[scheme]
	storeRegistryMu.RUnlock()
	if ok {
		return scheme, nil
	}
	return "", fmt.Errorf("unsupported DATABASE_URL scheme %q", parsed.Scheme)
}
