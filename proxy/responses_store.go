package proxy

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"kiro-go/config"
	"kiro-go/logger"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	responsesDirName    = "responses"
	responsesDefaultTTL = 30 * 24 * time.Hour
)

func responsesDir() string {
	return filepath.Join(config.GetConfigDir(), responsesDirName)
}

func generateResponseID() string {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("resp_%d%012x", time.Now().UnixNano(), 0)
	}
	return "resp_" + hex.EncodeToString(buf) + fmt.Sprintf("%08x", time.Now().Unix()&0xffffffff)
}

func generateOutputItemID(prefix string) string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("%s_%d", prefix, time.Now().UnixNano())
	}
	return prefix + "_" + hex.EncodeToString(buf)
}

func saveResponse(resp *ResponsesObject) error {
	if resp == nil || resp.ID == "" {
		return fmt.Errorf("response missing id")
	}
	dir := responsesDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create responses dir: %w", err)
	}
	if resp.StoredAt == 0 {
		resp.StoredAt = time.Now().Unix()
	}

	persisted := storedResponseDoc{
		ID:                 resp.ID,
		Object:             resp.Object,
		CreatedAt:          resp.CreatedAt,
		Status:             resp.Status,
		Model:              resp.Model,
		Output:             resp.Output,
		Usage:              resp.Usage,
		PreviousResponseID: resp.PreviousResponseID,
		Metadata:           resp.Metadata,
		Instructions:       resp.Instructions,
		StoredInput:        resp.StoredInput,
		OwnerKeyID:         resp.OwnerKeyID,
		StoredAt:           resp.StoredAt,
	}

	path := filepath.Join(dir, sanitizeResponseID(resp.ID)+".json")
	data, err := json.MarshalIndent(persisted, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal stored response: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write stored response: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("commit stored response: %w", err)
	}
	return nil
}

func loadResponse(id string) (*ResponsesObject, error) {
	if id == "" {
		return nil, fmt.Errorf("empty response id")
	}
	path := filepath.Join(responsesDir(), sanitizeResponseID(id)+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc storedResponseDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("decode stored response: %w", err)
	}
	if doc.StoredAt > 0 && time.Since(time.Unix(doc.StoredAt, 0)) > responsesDefaultTTL {
		_ = os.Remove(path)
		return nil, fmt.Errorf("stored response expired")
	}
	return &ResponsesObject{
		ID:                 doc.ID,
		Object:             doc.Object,
		CreatedAt:          doc.CreatedAt,
		Status:             doc.Status,
		Model:              doc.Model,
		Output:             doc.Output,
		Usage:              doc.Usage,
		PreviousResponseID: doc.PreviousResponseID,
		Metadata:           doc.Metadata,
		Instructions:       doc.Instructions,
		StoredInput:        doc.StoredInput,
		OwnerKeyID:         doc.OwnerKeyID,
		StoredAt:           doc.StoredAt,
	}, nil
}

// loadResponseForOwner loads a stored response and verifies ownership.
// If the stored response has an OwnerKeyID set and it doesn't match the
// given apiKeyID, a generic "not found" error is returned (identical to
// a missing ID) to prevent response-ID enumeration. Responses created
// before the ownership field was added (OwnerKeyID=="") are accessible
// by anyone for backward compatibility.
func loadResponseForOwner(id, apiKeyID string) (*ResponsesObject, error) {
	resp, err := loadResponse(id)
	if err != nil {
		return nil, err
	}
	if resp.OwnerKeyID != "" && apiKeyID != "" && resp.OwnerKeyID != apiKeyID {
		return nil, fmt.Errorf("stored response not found")
	}
	return resp, nil
}

func purgeExpiredResponses(ttl time.Duration) {
	if ttl <= 0 {
		ttl = responsesDefaultTTL
	}
	dir := responsesDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-ttl)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		full := filepath.Join(dir, e.Name())
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			if err := os.Remove(full); err != nil {
				logger.Warnf("[Responses] purge %s failed: %v", e.Name(), err)
			}
		}
	}
}

func logResponsesPersistFailure(id string, err error) {
	logger.Warnf("[Responses] persist %s failed: %v", id, err)
}

func sanitizeResponseID(id string) string {
	cleaned := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r
		case r >= 'A' && r <= 'Z':
			return r
		case r >= '0' && r <= '9':
			return r
		case r == '_' || r == '-':
			return r
		default:
			return -1
		}
	}, id)
	if cleaned == "" {
		return "invalid"
	}
	return cleaned
}

type storedResponseDoc struct {
	ID                 string               `json:"id"`
	Object             string               `json:"object"`
	CreatedAt          int64                `json:"created_at"`
	Status             string               `json:"status"`
	Model              string               `json:"model"`
	Output             []ResponseOutputItem `json:"output"`
	Usage              ResponsesUsage       `json:"usage"`
	PreviousResponseID string               `json:"previous_response_id,omitempty"`
	Metadata           map[string]string    `json:"metadata,omitempty"`
	Instructions       string               `json:"instructions,omitempty"`
	StoredInput        json.RawMessage      `json:"stored_input,omitempty"`
	OwnerKeyID         string               `json:"owner_key_id,omitempty"`
	StoredAt           int64                `json:"stored_at"`
}
