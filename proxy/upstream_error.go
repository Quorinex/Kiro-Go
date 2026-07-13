package proxy

import (
	"errors"
	"strings"
)

// improperlyFormedMarker is the substring AWS returns in the 400 response body
// when it rejects the request payload itself ("Improperly formed request.").
// Matched case-insensitively so a minor upstream wording/casing change does not
// silently bypass the permanent-error short-circuit. Ported from kiro-tutu.
const improperlyFormedMarker = "improperly formed request"

// isImproperlyFormedRejection reports whether an upstream error body marks the
// request as improperly formed. Both the endpoint short-circuit (kiro.go) and
// handleAccountFailure key off this single predicate so they can never disagree.
func isImproperlyFormedRejection(errBody string) bool {
	return strings.Contains(strings.ToLower(errBody), improperlyFormedMarker)
}

// upstreamPermanentErrorCode marks a request that the upstream rejects for a
// reason inherent to the request itself (e.g. "Improperly formed request").
// Retrying it — across endpoints or accounts — cannot succeed and only
// amplifies the damage (wasted upstream hits, scattered cache affinity,
// unwarranted account health penalties), so it must short-circuit both layers.
const upstreamPermanentErrorCode = "upstream_permanent_rejection"

// upstreamPermanentError signals an upstream rejection that is inherent to the
// request and therefore not retryable. Both the endpoint loop (kiro.go) and the
// account loop short-circuit on it: no other endpoint/account is tried, account
// health is not penalised (handleAccountFailure treats it as neutral).
type upstreamPermanentError struct {
	status  int
	code    string
	message string
}

func newUpstreamPermanentError(status int, message string) error {
	return &upstreamPermanentError{
		status:  status,
		code:    upstreamPermanentErrorCode,
		message: message,
	}
}

func (e *upstreamPermanentError) Error() string {
	return e.message
}

func asUpstreamPermanentError(err error) (*upstreamPermanentError, bool) {
	var target *upstreamPermanentError
	if errors.As(err, &target) {
		return target, true
	}
	return nil, false
}

func isUpstreamPermanentError(err error) bool {
	_, ok := asUpstreamPermanentError(err)
	return ok
}

// improperlyFormedClientMessage translates the upstream's opaque "Improperly
// formed request" rejection into a readable client hint. In practice the vast
// majority of these rejections occur when the request structure is perfectly
// valid but the tool definitions are too numerous or the payload too large
// (upstream limits on large requests); the raw wording makes users think the
// gateway is buggy. Other errors pass through unchanged.
//
// Complements tool_compression.go (compressToolsIfNeeded): compression prevents
// the rejection when it can; when it cannot, this surfaces a actionable message
// instead of the raw upstream text. Ported from kiro-tutu (zero-dep).
func improperlyFormedClientMessage(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	if isImproperlyFormedRejection(msg) {
		return "upstream rejected the request (commonly caused by too many tool definitions or an oversized payload); try reducing the number of tools or shortening the context"
	}
	return msg
}
