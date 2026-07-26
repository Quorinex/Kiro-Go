package proxy

import (
	"encoding/base64"
	"strings"
	"testing"
)

// Seam: extractClaudeUserContent must split images vs documents.
// PDF/base64 document blocks become KiroDocument; image/* stay images.
func TestExtractClaudeUserContentDocumentsVsImages(t *testing.T) {
	pdfB64 := base64.StdEncoding.EncodeToString([]byte("%PDF-1.4 fake"))
	imgB64 := base64.StdEncoding.EncodeToString([]byte{0x89, 0x50, 0x4e, 0x47}) // PNG magic-ish

	content := []interface{}{
		map[string]interface{}{"type": "text", "text": "see attached"},
		map[string]interface{}{
			"type": "document",
			"source": map[string]interface{}{
				"type":       "base64",
				"media_type": "application/pdf",
				"data":       pdfB64,
			},
			"title": "report.pdf",
		},
		map[string]interface{}{
			"type": "image",
			"source": map[string]interface{}{
				"type":       "base64",
				"media_type": "image/png",
				"data":       imgB64,
			},
		},
	}

	text, images, docs, tools, errMsg := extractClaudeUserContent(content)
	if errMsg != "" {
		t.Fatalf("unexpected document error: %s", errMsg)
	}
	if text != "see attached" {
		t.Fatalf("text=%q", text)
	}
	if len(tools) != 0 {
		t.Fatalf("tools=%d", len(tools))
	}
	if len(images) != 1 || images[0].Format != "png" {
		t.Fatalf("images=%+v", images)
	}
	if len(docs) != 1 {
		t.Fatalf("docs=%d %+v", len(docs), docs)
	}
	if docs[0].Format != "pdf" {
		t.Fatalf("doc format=%q", docs[0].Format)
	}
	if docs[0].Name == "" {
		t.Fatal("doc name empty")
	}
	if docs[0].Source.Bytes != pdfB64 {
		t.Fatal("doc bytes mismatch")
	}
}

// Seam: ClaudeToKiro must put documents on current user message.
func TestClaudeToKiroWiresDocumentsOnCurrentMessage(t *testing.T) {
	pdfB64 := base64.StdEncoding.EncodeToString([]byte("%PDF-1.4 x"))
	req := &ClaudeRequest{
		Model: "claude-sonnet-4.5",
		Messages: []ClaudeMessage{
			{Role: "user", Content: []interface{}{
				map[string]interface{}{"type": "text", "text": "read this"},
				map[string]interface{}{
					"type": "document",
					"source": map[string]interface{}{
						"type":       "base64",
						"media_type": "application/pdf",
						"data":       pdfB64,
					},
					"title": "a.pdf",
				},
			}},
		},
	}
	payload := ClaudeToKiro(req, false)
	docs := payload.ConversationState.CurrentMessage.UserInputMessage.Documents
	if len(docs) != 1 || docs[0].Format != "pdf" {
		t.Fatalf("current documents=%+v", docs)
	}
	if payload.ConversationState.CurrentMessage.UserInputMessage.Content == "" {
		t.Fatal("content should remain non-empty with documents")
	}
}

// Unsupported document mime types are skipped, not turned into images.
func TestExtractClaudeUserContentSkipsUnknownDocumentMime(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString([]byte("zzz"))
	content := []interface{}{
		map[string]interface{}{
			"type": "document",
			"source": map[string]interface{}{
				"media_type": "application/x-unknown",
				"data":       b64,
			},
			"title": "x.bin",
		},
	}
	_, images, docs, _, errMsg := extractClaudeUserContent(content)
	if errMsg != "" {
		t.Fatalf("unknown mime must skip without error: %s", errMsg)
	}
	if len(docs) != 0 || len(images) != 0 {
		t.Fatalf("unknown mime must skip: docs=%+v images=%+v", docs, images)
	}
}

func claudeDocumentBlock(name, mediaType string, data []byte) map[string]interface{} {
	return map[string]interface{}{
		"type": "document",
		"source": map[string]interface{}{
			"type":       "base64",
			"media_type": mediaType,
			"data":       base64.StdEncoding.EncodeToString(data),
		},
		"title": name,
	}
}

func TestClaudeDocumentValidationRejectsBadBase64AndMagic(t *testing.T) {
	for _, tc := range []struct {
		name      string
		block     map[string]interface{}
		wantError string
	}{
		{
			name: "bad base64",
			block: map[string]interface{}{
				"type": "document",
				"source": map[string]interface{}{
					"media_type": "application/pdf",
					"data":       "AQI",
				},
				"title": "bad.pdf",
			},
			wantError: "base64",
		},
		{
			name:      "bad magic",
			block:     claudeDocumentBlock("fake.pdf", "application/pdf", []byte("not a pdf")),
			wantError: "does not match",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := &ClaudeRequest{Messages: []ClaudeMessage{{Role: "user", Content: []interface{}{tc.block}}}}
			if got := validateClaudeRequestShape(req); !strings.Contains(strings.ToLower(got), tc.wantError) {
				t.Fatalf("validation error = %q, want %q", got, tc.wantError)
			}
		})
	}
}

func TestClaudeDocumentsSanitizeAndDeduplicateNames(t *testing.T) {
	pdf := []byte("%PDF-1.7 valid")
	content := []interface{}{
		claudeDocumentBlock("Quarter:Report.pdf", "application/pdf", pdf),
		claudeDocumentBlock("Quarter?Report.pdf", "application/pdf", pdf),
	}
	_, _, docs, _, errMsg := extractClaudeUserContent(content)
	if errMsg != "" {
		t.Fatalf("unexpected document error: %s", errMsg)
	}
	if len(docs) != 1 {
		t.Fatalf("normalized duplicate documents = %+v, want one", docs)
	}
	if docs[0].Name != "Quarter-Report" {
		t.Fatalf("sanitized document name = %q", docs[0].Name)
	}
}

func TestClaudeDocumentsAcceptOfficeMagicBytes(t *testing.T) {
	content := []interface{}{
		claudeDocumentBlock("report.docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", []byte{0x50, 0x4b, 0x03, 0x04, 0x01}),
		claudeDocumentBlock("legacy.xls", "application/vnd.ms-excel", []byte{0xd0, 0xcf, 0x11, 0xe0, 0x01}),
	}
	_, _, docs, _, errMsg := extractClaudeUserContent(content)
	if errMsg != "" {
		t.Fatalf("unexpected document error: %s", errMsg)
	}
	if len(docs) != 2 || docs[0].Format != "docx" || docs[1].Format != "xls" {
		t.Fatalf("Office documents = %+v", docs)
	}
}

func TestClaudeDocumentLimitAcrossConversation(t *testing.T) {
	pdf := []byte("%PDF-1.7 valid")
	messages := make([]ClaudeMessage, 0, 6)
	for i := 0; i < 6; i++ {
		messages = append(messages, ClaudeMessage{Role: "user", Content: []interface{}{
			claudeDocumentBlock(string(rune('a'+i))+".pdf", "application/pdf", pdf),
		}})
	}
	got := validateClaudeRequestShape(&ClaudeRequest{Messages: messages})
	if !strings.Contains(strings.ToLower(got), "maximum is 5") {
		t.Fatalf("document limit validation = %q", got)
	}
}

func TestClaudeToKiroDropsDuplicateDocumentsAcrossConversation(t *testing.T) {
	pdf := []byte("%PDF-1.7 valid")
	req := &ClaudeRequest{Model: "claude-sonnet-4.5", Messages: []ClaudeMessage{
		{Role: "user", Content: []interface{}{claudeDocumentBlock("same.pdf", "application/pdf", pdf)}},
		{Role: "assistant", Content: "seen"},
		{Role: "user", Content: []interface{}{claudeDocumentBlock("same.pdf", "application/pdf", pdf)}},
	}}
	payload := ClaudeToKiro(req, false)
	total := len(payload.ConversationState.CurrentMessage.UserInputMessage.Documents)
	for _, message := range payload.ConversationState.History {
		if message.UserInputMessage != nil {
			total += len(message.UserInputMessage.Documents)
		}
	}
	if total != 1 {
		t.Fatalf("duplicate documents across conversation = %d, want one", total)
	}
}

func TestClaudeRequestWithOnlyDocumentHasUserContext(t *testing.T) {
	req := &ClaudeRequest{Messages: []ClaudeMessage{{
		Role: "user",
		Content: []interface{}{
			claudeDocumentBlock("only.pdf", "application/pdf", []byte("%PDF-1.7 valid")),
		},
	}}}
	if got := validateClaudeRequestShape(req); got != "" {
		t.Fatalf("document-only request rejected: %s", got)
	}
}

func TestClaudeRawTextDocumentMapsToKiroTXT(t *testing.T) {
	block := map[string]interface{}{
		"type": "document",
		"source": map[string]interface{}{
			"type":       "text",
			"media_type": "text/plain",
			"data":       "hello  world\nexact text",
		},
		"title": "notes.txt",
	}
	req := &ClaudeRequest{Model: "claude-sonnet-4.5", Messages: []ClaudeMessage{{Role: "user", Content: []interface{}{block}}}}
	if got := validateClaudeRequestShape(req); got != "" {
		t.Fatalf("valid raw-text document rejected: %s", got)
	}
	payload := ClaudeToKiro(req, false)
	documents := payload.ConversationState.CurrentMessage.UserInputMessage.Documents
	if len(documents) != 1 || documents[0].Format != "txt" {
		t.Fatalf("raw-text documents = %+v", documents)
	}
	raw, err := base64.StdEncoding.DecodeString(documents[0].Source.Bytes)
	if err != nil || string(raw) != "hello  world\nexact text" {
		t.Fatalf("raw-text bytes = %q, err=%v", raw, err)
	}
}
