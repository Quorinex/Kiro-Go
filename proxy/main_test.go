package proxy

import (
	"os"
	"testing"
)

// TestMain pins the upstream transport to the legacy event-stream path for the
// whole package: every handler/transport test stubs the AWS event stream, not
// the /v1/responses SSE endpoint. Tests for the new transport opt in explicitly
// through config.UpdateUpstreamProtocol, and the responses parsers are covered
// by direct unit tests that never touch the network.
//
// Only the env override is set here: initialising config would change the
// defaults other tests assert on.
func TestMain(m *testing.M) {
	if err := os.Setenv("KIRO_UPSTREAM_PROTOCOL", responsesProtocolLegacy); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}
