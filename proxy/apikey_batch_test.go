package proxy

import (
	"encoding/json"
	"io"
	"kiro-go/config"
	accountpool "kiro-go/pool"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestMaskKey verifies head-6 … tail-4 masking and the short-key fallback.
func TestMaskKey(t *testing.T) {
	if got := maskKey("ABCDEFGHIJKLMNOP"); got != "ABCDEF…MNOP" {
		t.Fatalf("mask long: want ABCDEF…MNOP, got %q", got)
	}
	if got := maskKey("short"); got != "****" {
		t.Fatalf("mask short: want ****, got %q", got)
	}
}

// TestImportApiKeysDedupAndPerKeyResult verifies dedup against existing accounts
// and within the batch, plus per-key result + maskedKey in the summary. The
// best-effort RefreshAccountInfo is exercised against a stubbed REST store that
// 404s (best-effort → InfoFailed++, never a fatal/ban path).
func TestImportApiKeysDedupAndPerKeyResult(t *testing.T) {
	if err := config.Init(t.TempDir() + "/config.json"); err != nil {
		t.Fatalf("config.Init: %v", err)
	}
	// Seed an existing api_key account to dedup against.
	if err := config.AddAccount(config.Account{ID: "existing-1", AuthMethod: "api_key", KiroApiKey: "key-already-present", AccessToken: "key-already-present", Enabled: true}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Stub the REST store so the best-effort RefreshAccountInfo / model-cache
	// fetches don't hit real network. A 404 is NOT an auth error, so it never
	// trips the ban path — it just records InfoFailed.
	kiroRestHttpStore.Store(&http.Client{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Body:       io.NopCloser(strings.NewReader("not found")),
				Header:     make(http.Header),
			}, nil
		}),
	})
	t.Cleanup(func() { InitKiroHttpClient("") })

	h := &Handler{pool: accountpool.GetPool()}
	// One duplicate of the seeded key, one within-batch duplicate, two fresh keys.
	keys := "key-already-present\nKEY-FRESH-1234567890\nKEY-FRESH-1234567890\nKEY-FRESH-2234567890"
	summary := h.ImportApiKeys(keys, "eu-central-1", "", "")

	if summary.Total != 4 {
		t.Fatalf("total: want 4, got %d", summary.Total)
	}
	// 1 existing-skip + 1 within-batch-skip = 2 skipped; 2 imported.
	if summary.Imported != 2 {
		t.Fatalf("imported: want 2, got %d", summary.Imported)
	}
	if summary.Skipped != 2 {
		t.Fatalf("skipped: want 2, got %d", summary.Skipped)
	}
	if len(summary.Results) != 4 {
		t.Fatalf("results: want 4, got %d", len(summary.Results))
	}

	// Persisted accounts: the 1 seed + 2 fresh = 3.
	accs := config.GetAccounts()
	if len(accs) != 3 {
		t.Fatalf("persisted accounts: want 3, got %d", len(accs))
	}
	for _, a := range accs {
		if a.AuthMethod != "api_key" {
			t.Fatalf("account %s AuthMethod: want api_key, got %q", a.ID, a.AuthMethod)
		}
		if a.ExpiresAt != 0 {
			t.Fatalf("account %s ExpiresAt: want 0, got %d", a.ID, a.ExpiresAt)
		}
	}
}

// TestApiImportApiKeysHandler verifies the POST /auth/apikeys-batch handler
// decodes the body and returns the summary shape.
func TestApiImportApiKeysHandler(t *testing.T) {
	if err := config.Init(t.TempDir() + "/config.json"); err != nil {
		t.Fatalf("config.Init: %v", err)
	}
	kiroRestHttpStore.Store(&http.Client{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Body:       io.NopCloser(strings.NewReader("not found")),
				Header:     make(http.Header),
			}, nil
		}),
	})
	t.Cleanup(func() { InitKiroHttpClient("") })

	h := &Handler{pool: accountpool.GetPool()}
	body := `{"keys":"KEY-A-1234567890\nKEY-B-1234567890","region":"us-east-1"}`
	req := httptest.NewRequest("POST", "/auth/apikeys-batch", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.apiImportApiKeys(rec, req)

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var resp map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, k := range []string{"success", "total", "imported", "skipped", "infoFailed", "results"} {
		if string(resp[k]) == "" {
			t.Fatalf("response missing key %q: %v", k, resp)
		}
	}
}

// TestApiImportApiKeysRejectsEmpty verifies the 400 guard.
func TestApiImportApiKeysRejectsEmpty(t *testing.T) {
	if err := config.Init(t.TempDir() + "/config.json"); err != nil {
		t.Fatalf("config.Init: %v", err)
	}
	h := &Handler{pool: accountpool.GetPool()}
	req := httptest.NewRequest("POST", "/auth/apikeys-batch", strings.NewReader(`{"keys":""}`))
	rec := httptest.NewRecorder()
	h.apiImportApiKeys(rec, req)
	if rec.Code != 400 {
		t.Fatalf("expected 400 for empty keys, got %d", rec.Code)
	}
}
