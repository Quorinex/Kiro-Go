package proxy

import (
	"errors"
	"strings"
	"testing"
)

// TestImproperlyFormedClientMessageTranslatesOpaqueRejection verifies the upstream's
// opaque "Improperly formed request" wording is translated into a readable, actionable
// hint. Case-insensitive so a minor upstream wording/casing change does not bypass it.
func TestImproperlyFormedClientMessageTranslatesOpaqueRejection(t *testing.T) {
	cases := []string{
		"Improperly formed request.",
		"improperly formed request",
		"HTTP 400: IMPROPERLY FORMED REQUEST body",
	}
	for _, raw := range cases {
		got := improperlyFormedClientMessage(errors.New(raw))
		if got == raw {
			t.Fatalf("expected translation for %q, got raw message back", raw)
		}
		if !strings.Contains(got, "tool definitions") || !strings.Contains(got, "reducing") {
			t.Fatalf("expected actionable hint about tools/payload, got %q", got)
		}
	}
}

// TestImproperlyFormedClientMessagePassesThroughOtherErrors verifies non-matching
// errors pass through unchanged — the helper must only rewrite the one known opaque
// rejection, not munge unrelated upstream/client messages.
func TestImproperlyFormedClientMessagePassesThroughOtherErrors(t *testing.T) {
	cases := []string{
		"upstream returned empty assistant response",
		"HTTP 500 from q: internal error",
		"quota exhausted on codewhisperer",
		"context length exceeded",
	}
	for _, raw := range cases {
		got := improperlyFormedClientMessage(errors.New(raw))
		if got != raw {
			t.Fatalf("expected pass-through for %q, got %q", raw, got)
		}
	}
}

// TestImproperlyFormedClientMessageHandlesNil locks the nil-safety contract so a
// nil error (a missed guard at a call site) returns "" rather than panicking.
func TestImproperlyFormedClientMessageHandlesNil(t *testing.T) {
	if got := improperlyFormedClientMessage(nil); got != "" {
		t.Fatalf("nil error must yield empty string, got %q", got)
	}
}
