package proxy

import (
	"errors"
	"fmt"
	"io"
	"kiro-go/config"
	"kiro-go/logger"
)

type streamIntegrityState struct {
	ContentChars int
	ToolCount    int
	StopReason   string
	SawReasoning bool
}

func (s streamIntegrityState) classify() error {
	return classifyStreamIntegrity(s.ContentChars, s.ToolCount, s.StopReason, s.SawReasoning)
}

func (s *streamIntegrityState) observeText(text string, isReasoning bool) {
	if text == "" {
		return
	}
	if isReasoning {
		s.SawReasoning = true
		return
	}
	s.ContentChars += len(text)
}

func (s *streamIntegrityState) observeToolUse() {
	s.ToolCount++
}

func (s *streamIntegrityState) observeStopReason(reason string) {
	s.StopReason = reason
}

func (s *streamIntegrityState) reset() {
	*s = streamIntegrityState{}
}

// runKiroWithIntegrityRetry calls CallKiroAPI and recovers empty/truncated
// upstream streams the way Kiro IDE does: retry the same request on the same
// account a few times before surfacing the failure.
//
// build is invoked at the start of every attempt (including the first) so the
// caller can close over fresh accumulators. state owns the integrity snapshot
// and is reset automatically between attempts. reset clears the caller's other
// per-attempt accumulators; it may be nil.
// canRetry reports whether a retry is still safe (for streaming: nothing has
// been flushed to the client yet). nil means always retryable.
//
// Return contract:
//   - nil: complete success only
//   - transport error from CallKiroAPI: caller should rotate/ban as usual
//   - integrity error while still retryable: retries exhausted; caller should
//     rotate account without treating it as an auth/quota failure
//   - integrity error after client flush: caller must surface failure to the
//     client (do not fake end_turn / normal completion). Retry is unsafe.
func runKiroWithIntegrityRetry(
	account *config.Account,
	payload *KiroPayload,
	state *streamIntegrityState,
	build func() *KiroStreamCallback,
	reset func(),
	canRetry func() bool,
) error {
	label := accountEmailForLog(account)
	if state == nil {
		state = &streamIntegrityState{}
	}
	retryable := func() bool {
		if canRetry == nil {
			return true
		}
		return canRetry()
	}
	for attempt := 0; attempt <= maxSameAccountStreamRetries; attempt++ {
		if attempt > 0 {
			if reset != nil {
				reset()
			}
			state.reset()
		}
		callback := build()
		err := CallKiroAPI(account, payload, callback)

		var integrityErr error
		if err != nil {
			if !errors.Is(err, errIncompleteToolUse) && !errors.Is(err, io.ErrUnexpectedEOF) {
				return err
			}
			integrityErr = fmt.Errorf("%w: %v", errUpstreamTruncatedResponse, err)
		} else {
			integrityErr = state.classify()
		}

		if integrityErr == nil {
			return nil
		}

		if retryable() && attempt < maxSameAccountStreamRetries {
			logger.Warnf("[StreamIntegrity] %v on %s; retrying same account (%d/%d)",
				integrityErr, label, attempt+1, maxSameAccountStreamRetries)
			continue
		}

		if !retryable() {
			// Bytes already reached the client; reissuing would duplicate output.
			// Return the integrity error so callers emit an error event instead of
			// finishing with a forged end_turn/tool_use success (kiro2cc-proxy #13).
			logger.Warnf("[StreamIntegrity] %v after client flush; signaling error (no retry)", integrityErr)
			return integrityErr
		}

		logger.Warnf("[StreamIntegrity] giving up after retries: %v", integrityErr)
		return integrityErr
	}

	return errUpstreamTruncatedResponse
}
