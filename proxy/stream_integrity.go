package proxy

import (
	"context"
	"kiro-go/config"
	"kiro-go/logger"
)

// runKiroWithIntegrityRetry calls Kiro and recovers a truncated upstream stream
// the way Kiro IDE does: retry the same request on the same account within a
// bounded budget before surfacing the failure.
//
// callback is reused across attempts. Both CallKiroAPIContext and
// parseEventStreamTracked copy the struct before wrapping any field, so a retry
// cannot double-wrap it; per-attempt state is cleared by reset instead. This
// function wraps OnMetering the same way, once before the loop, to observe
// upstream billing without asking callers to report it.
// measure reports the remaining integrity inputs after a transport-successful
// call.
// reset clears per-attempt state before a same-account retry; may be nil.
// canRetry reports whether a retry is still safe (for streaming: nothing has
// been flushed to the client yet). nil means always retryable.
//
// Return contract:
//   - nil: complete success only
//   - transport error from CallKiroAPIContext: caller should rotate/ban as usual
//   - integrity error while still retryable: retries exhausted; caller should
//     rotate account without treating it as an auth/quota failure
//   - integrity error after client flush: caller must surface failure to the
//     client (do not fake end_turn / normal completion). Retry is unsafe.
func runKiroWithIntegrityRetry(
	ctx context.Context,
	account *config.Account,
	payload *KiroPayload,
	callback *KiroStreamCallback,
	measure func() (contentChars, toolCount int, stopReason string, sawReasoning bool),
	reset func(),
	canRetry func() bool,
) error {
	label := accountEmailForLog(account)
	retryable := func() bool {
		if canRetry == nil {
			return true
		}
		return canRetry()
	}

	if callback == nil {
		callback = &KiroStreamCallback{}
	}

	// meteringEvent arrival is tracked here rather than threaded through every
	// caller's measure func: upstream billing is an integrity signal, and no
	// handler has a use for it. Wrapped once outside the loop so a retry cannot
	// double-wrap the callback; the flag is cleared per attempt instead.
	var sawMetering bool
	tracked := *callback
	callerOnMetering := tracked.OnMetering
	tracked.OnMetering = func() {
		sawMetering = true
		if callerOnMetering != nil {
			callerOnMetering()
		}
	}
	callback = &tracked

	for attempt := 0; attempt <= maxSameAccountStreamRetries; attempt++ {
		if attempt > 0 && reset != nil {
			reset()
		}
		sawMetering = false

		err := CallKiroAPIContext(ctx, account, payload, callback)
		if err != nil {
			return err
		}

		contentChars, toolCount, stopReason, sawReasoning := measure()
		integrityErr := classifyStreamIntegrity(contentChars, toolCount, stopReason, sawReasoning, sawMetering)
		if integrityErr == nil {
			return nil
		}

		// A canceled client is not an integrity failure: the turn is over and
		// reissuing it would only burn upstream quota.
		if ctx != nil && ctx.Err() != nil {
			return ctx.Err()
		}

		if retryable() && attempt < maxSameAccountStreamRetries {
			logger.Warnf("[StreamIntegrity] %v on %s; retrying same account (%d/%d)",
				integrityErr, label, attempt+1, maxSameAccountStreamRetries)
			continue
		}

		if !retryable() {
			// Bytes already reached the client; reissuing would duplicate output.
			// Return the integrity error so callers emit an error event instead of
			// finishing with a forged end_turn/tool_use success.
			logger.Warnf("[StreamIntegrity] %v after client flush; signaling error (no retry)", integrityErr)
			return integrityErr
		}

		logger.Warnf("[StreamIntegrity] giving up after retries: %v", integrityErr)
		return integrityErr
	}

	// Unreachable: every branch inside the loop returns or continues, and the
	// final iteration cannot continue.
	return errUpstreamTruncatedResponse
}
