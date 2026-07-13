package proxy

import (
	"encoding/json"
	"kiro-go/config"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadResponseForOwnerIsolation(t *testing.T) {
	// Set up a temp config dir so responses are written to a temp directory.
	cfgFile := filepath.Join(t.TempDir(), "config.json")
	if err := config.Init(cfgFile); err != nil {
		t.Fatalf("config.Init: %v", err)
	}

	// Helper to create and save a minimal response with the given ID and owner.
	makeResponse := func(id, ownerKeyID string) *ResponsesObject {
		return &ResponsesObject{
			ID:        id,
			Object:    "response",
			CreatedAt: time.Now().Unix(),
			Status:    "completed",
			Model:     "claude-sonnet-4.5",
			Output: []ResponseOutputItem{{
				ID:   "msg_test",
				Type: "message",
				Role: "assistant",
				Content: []ResponseContentPart{{
					Type: "output_text",
					Text: "test output",
				}},
			}},
			StoredInput: json.RawMessage(`"test input"`),
			OwnerKeyID:  ownerKeyID,
			StoredAt:    time.Now().Unix(),
		}
	}

	t.Run("access allowed same key", func(t *testing.T) {
		resp := makeResponse("resp_owner_allowed", "key-A")
		if err := saveResponse(resp); err != nil {
			t.Fatalf("save: %v", err)
		}

		loaded, err := loadResponseForOwner("resp_owner_allowed", "key-A")
		if err != nil {
			t.Fatalf("expected access allowed for same key, got error: %v", err)
		}
		if loaded.ID != "resp_owner_allowed" {
			t.Fatalf("loaded ID mismatch: got %q", loaded.ID)
		}
		if loaded.OwnerKeyID != "key-A" {
			t.Fatalf("loaded OwnerKeyID mismatch: got %q", loaded.OwnerKeyID)
		}
	})

	t.Run("access denied different key", func(t *testing.T) {
		resp := makeResponse("resp_owner_denied", "key-A")
		if err := saveResponse(resp); err != nil {
			t.Fatalf("save: %v", err)
		}

		_, err := loadResponseForOwner("resp_owner_denied", "key-B")
		if err == nil {
			t.Fatalf("expected error for different key, got nil")
		}
		// Error message is intentionally generic ("not found") to prevent
		// response-ID enumeration — do not assert specific wording.
		if !strings.Contains(err.Error(), "not found") {
			t.Fatalf("expected 'not found' in error, got: %v", err)
		}
	})

	t.Run("legacy compatibility empty owner", func(t *testing.T) {
		resp := makeResponse("resp_legacy_no_owner", "")
		if err := saveResponse(resp); err != nil {
			t.Fatalf("save: %v", err)
		}

		loaded, err := loadResponseForOwner("resp_legacy_no_owner", "key-B")
		if err != nil {
			t.Fatalf("expected legacy response accessible by any key, got error: %v", err)
		}
		if loaded.ID != "resp_legacy_no_owner" {
			t.Fatalf("loaded ID mismatch: got %q", loaded.ID)
		}
	})

	t.Run("empty caller key allowed", func(t *testing.T) {
		resp := makeResponse("resp_empty_caller", "key-A")
		if err := saveResponse(resp); err != nil {
			t.Fatalf("save: %v", err)
		}

		loaded, err := loadResponseForOwner("resp_empty_caller", "")
		if err != nil {
			t.Fatalf("expected unauthenticated access allowed, got error: %v", err)
		}
		if loaded.ID != "resp_empty_caller" {
			t.Fatalf("loaded ID mismatch: got %q", loaded.ID)
		}
	})
}
