package proxy

import (
	"kiro-go/config"
	"testing"
)

// TestRegionalizeURLForRegion asserts that a non-us-east-1 region collapses BOTH
// hardcoded us-east-1 hosts (q.* and codewhisperer.*) onto q.{region} — there is no
// codewhisperer.{region} host — and that us-east-1/empty are no-ops.
func TestRegionalizeURLForRegion(t *testing.T) {
	cases := []struct {
		name   string
		rawURL string
		region string
		want   string
	}{
		{
			name:   "codewhisperer host to q.eu-central-1",
			rawURL: "https://codewhisperer.us-east-1.amazonaws.com/ListAvailableProfiles",
			region: "eu-central-1",
			want:   "https://q.eu-central-1.amazonaws.com/ListAvailableProfiles",
		},
		{
			name:   "q host to q.eu-central-1",
			rawURL: "https://q.us-east-1.amazonaws.com/generateAssistantResponse",
			region: "eu-central-1",
			want:   "https://q.eu-central-1.amazonaws.com/generateAssistantResponse",
		},
		{
			name:   "us-east-1 is a no-op (codewhisperer host kept)",
			rawURL: "https://codewhisperer.us-east-1.amazonaws.com/ListAvailableProfiles",
			region: "us-east-1",
			want:   "https://codewhisperer.us-east-1.amazonaws.com/ListAvailableProfiles",
		},
		{
			name:   "empty region is a no-op",
			rawURL: "https://q.us-east-1.amazonaws.com/x",
			region: "",
			want:   "https://q.us-east-1.amazonaws.com/x",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := regionalizeURLForRegion(tc.rawURL, tc.region)
			if got != tc.want {
				t.Fatalf("regionalizeURLForRegion(%q, %q) = %q, want %q", tc.rawURL, tc.region, got, tc.want)
			}
		})
	}
}

// TestRegionalizeURLForRegionNoCodewhispererRegionalHost guards the user-stated
// invariant directly: a regionalized URL must never produce codewhisperer.{region}.
func TestRegionalizeURLForRegionNoCodewhispererRegionalHost(t *testing.T) {
	got := regionalizeURLForRegion("https://codewhisperer.us-east-1.amazonaws.com/GetUserInfo", "eu-central-1")
	if want := "https://q.eu-central-1.amazonaws.com/GetUserInfo"; got != want {
		t.Fatalf("got %q, want %q (must not be codewhisperer.eu-central-1)", got, want)
	}
}

// TestKiroProfileRegionCandidatesExternalIdp checks that an external_idp account —
// whose home region is unknown and defaults to us-east-1 — probes the account region
// first and then the built-in fallbacks, de-duplicated.
func TestKiroProfileRegionCandidatesExternalIdp(t *testing.T) {
	// Default us-east-1 external_idp login: fallbacks follow.
	got := kiroProfileRegionCandidates(&config.Account{AuthMethod: "external_idp", Region: "us-east-1"})
	assertOrder(t, got, []string{"us-east-1", "eu-central-1"})

	// Already-detected eu-central-1 leads; us-east-1 fallback follows.
	got = kiroProfileRegionCandidates(&config.Account{AuthMethod: "external_idp", Region: "eu-central-1"})
	assertOrder(t, got, []string{"eu-central-1", "us-east-1"})

	// A non-default region leads, both defaults follow.
	got = kiroProfileRegionCandidates(&config.Account{AuthMethod: "external_idp", Region: "ap-southeast-2"})
	assertOrder(t, got, []string{"ap-southeast-2", "us-east-1", "eu-central-1"})
}

// TestKiroProfileRegionCandidatesNoRegion checks an account with no region set falls
// back across the defaults regardless of auth method.
func TestKiroProfileRegionCandidatesNoRegion(t *testing.T) {
	got := kiroProfileRegionCandidates(&config.Account{})
	assertOrder(t, got, []string{"us-east-1", "eu-central-1"})
}

// TestKiroProfileRegionCandidatesSingleRegionAuthMethods checks that idc/social/
// Builder ID accounts — which already carry their authoritative region — are probed
// against that single region only, with no fallback probing.
func TestKiroProfileRegionCandidatesSingleRegionAuthMethods(t *testing.T) {
	for _, method := range []string{"idc", "social", "builderId", ""} {
		got := kiroProfileRegionCandidates(&config.Account{AuthMethod: method, Region: "eu-central-1"})
		if len(got) != 1 || got[0] != "eu-central-1" {
			t.Fatalf("authMethod %q: candidate regions = %v, want [eu-central-1] only", method, got)
		}
	}
}

// TestKiroProfileRegionCandidatesEnvOverride checks KIRO_PROFILE_REGIONS replaces
// the built-in fallbacks (external_idp only) while the account region is tried first.
func TestKiroProfileRegionCandidatesEnvOverride(t *testing.T) {
	t.Setenv("KIRO_PROFILE_REGIONS", "eu-west-1, ap-south-1 ,eu-west-1")
	got := kiroProfileRegionCandidates(&config.Account{AuthMethod: "external_idp", Region: "us-east-1"})
	// us-east-1 (account) first; env values de-duplicated and trimmed; no built-in defaults.
	assertOrder(t, got, []string{"us-east-1", "eu-west-1", "ap-south-1"})

	// A non-external_idp account ignores the env fallbacks entirely.
	got = kiroProfileRegionCandidates(&config.Account{AuthMethod: "idc", Region: "us-east-1"})
	assertOrder(t, got, []string{"us-east-1"})
}

func assertOrder(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("candidate regions = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("candidate regions = %v, want %v", got, want)
		}
	}
}
