package proxy

import (
	"os"
	"strconv"
	"strings"

	"kiro-go/logger"
	"kiro-go/rtk"
)

func maybeCompressRequestBody(raw []byte) []byte {
	cfg := rtkConfigFromEnv()
	if !cfg.Enabled {
		return raw
	}
	updated, stats, changed, err := rtk.TransformJSON(raw, cfg)
	if err != nil {
		logger.Warnf("[RTK] request transform skipped: %v", err)
		return raw
	}
	if !changed {
		return raw
	}
	if line := rtk.FormatLog(stats); line != "" {
		logger.Infof("%s", line)
	}
	return updated
}

func rtkConfigFromEnv() rtk.Config {
	cfg := rtk.DefaultConfig()
	switch strings.ToLower(strings.TrimSpace(os.Getenv("KIRO_GO_RTK"))) {
	case "0", "false", "off", "no", "disabled":
		cfg.Enabled = false
	case "1", "true", "on", "yes", "enabled":
		cfg.Enabled = true
	}
	if v := strings.TrimSpace(os.Getenv("KIRO_GO_RTK_MIN_BYTES")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.MinBytes = n
		}
	}
	if v := strings.TrimSpace(os.Getenv("KIRO_GO_RTK_MAX_BYTES")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.MaxBytes = n
		}
	}
	return cfg
}
