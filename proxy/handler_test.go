package proxy

import "testing"

func TestThinkingSourceReasoningFirst(t *testing.T) {
	var source thinkingStreamSource

	if !allowReasoningSource(&source) {
		t.Fatalf("expected reasoning source to be accepted first")
	}
	if source != thinkingSourceReasoningEvent {
		t.Fatalf("expected source to be reasoning, got %v", source)
	}
	if allowTagSource(&source) {
		t.Fatalf("expected tag source to be rejected after reasoning source selected")
	}
}

func TestThinkingSourceTagFirst(t *testing.T) {
	var source thinkingStreamSource

	if !allowTagSource(&source) {
		t.Fatalf("expected tag source to be accepted first")
	}
	if source != thinkingSourceTagBlock {
		t.Fatalf("expected source to be tag, got %v", source)
	}
	if allowReasoningSource(&source) {
		t.Fatalf("expected reasoning source to be rejected after tag source selected")
	}
}

func TestThinkingSourceSameSourceRemainsAllowed(t *testing.T) {
	var source thinkingStreamSource

	if !allowTagSource(&source) {
		t.Fatalf("expected initial tag source selection to succeed")
	}
	if !allowTagSource(&source) {
		t.Fatalf("expected repeated tag source selection to stay allowed")
	}

	source = thinkingSourceUnknown
	if !allowReasoningSource(&source) {
		t.Fatalf("expected initial reasoning source selection to succeed")
	}
	if !allowReasoningSource(&source) {
		t.Fatalf("expected repeated reasoning source selection to stay allowed")
	}
}
