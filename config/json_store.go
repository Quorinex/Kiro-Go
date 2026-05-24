package config

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
)

type jsonStore struct {
	path string
}

func init() {
	RegisterStoreBackend("json", func(_ context.Context, configPath, _ string) (Store, error) {
		return NewJSONStore(configPath), nil
	})
}

func NewJSONStore(path string) Store {
	return &jsonStore{path: path}
}

func (s *jsonStore) Name() string {
	return "json"
}

func (s *jsonStore) Load(ctx context.Context) (*Config, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c, exists, err := loadJSONConfigIfExists(s.path)
	if err != nil {
		return nil, err
	}
	if exists {
		return normalizeConfig(c), nil
	}

	c = defaultConfig()
	if err := s.Save(ctx, c); err != nil {
		return nil, err
	}
	return c, nil
}

func (s *jsonStore) Save(ctx context.Context, cfg *Config) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(normalizeConfig(cfg), "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0755); err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0600)
}

func (s *jsonStore) Close() error {
	return nil
}

func loadJSONConfigIfExists(path string) (*Config, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, err
	}

	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, false, err
	}
	return normalizeConfig(&c), true, nil
}
