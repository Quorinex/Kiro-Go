package proxy

import (
	"kiro-go/config"
	"testing"
)

func TestRegionForKiroAPI_FromProfileArn(t *testing.T) {
	acc := &config.Account{Region: "us-east-1", ProfileArn: "arn:aws:codewhisperer:eu-central-1:621638299260:profile/ABC"}
	got := regionForKiroAPI(acc, nil)
	if got != "eu-central-1" {
		t.Fatalf("expected eu-central-1 from profileArn, got %q", got)
	}
}

func TestRegionForKiroAPI_PayloadProfileArnWins(t *testing.T) {
	acc := &config.Account{Region: "us-east-1", ProfileArn: "arn:aws:codewhisperer:us-east-1:1:profile/X"}
	payload := &KiroPayload{ProfileArn: "arn:aws:codewhisperer:ap-southeast-1:2:profile/Y"}
	got := regionForKiroAPI(acc, payload)
	if got != "ap-southeast-1" {
		t.Fatalf("expected ap-southeast-1 from payload profileArn, got %q", got)
	}
}

func TestRegionForKiroAPI_FallbackToAccountRegion(t *testing.T) {
	acc := &config.Account{Region: "eu-west-2", ProfileArn: ""}
	got := regionForKiroAPI(acc, nil)
	if got != "eu-west-2" {
		t.Fatalf("expected eu-west-2 from account.Region, got %q", got)
	}
}

func TestRegionForKiroAPI_DefaultUsEast1(t *testing.T) {
	got := regionForKiroAPI(&config.Account{}, nil)
	if got != "us-east-1" {
		t.Fatalf("expected default us-east-1, got %q", got)
	}
}

func TestRewriteEndpointRegion(t *testing.T) {
	cases := []struct {
		url, region, want string
	}{
		{"https://q.us-east-1.amazonaws.com/generateAssistantResponse", "eu-central-1",
			"https://q.eu-central-1.amazonaws.com/generateAssistantResponse"},
		{"https://codewhisperer.us-east-1.amazonaws.com/generateAssistantResponse", "eu-central-1",
			"https://codewhisperer.eu-central-1.amazonaws.com/generateAssistantResponse"},
		// us-east-1 → no-op
		{"https://q.us-east-1.amazonaws.com/generateAssistantResponse", "us-east-1",
			"https://q.us-east-1.amazonaws.com/generateAssistantResponse"},
		// empty region → no-op
		{"https://q.us-east-1.amazonaws.com/generateAssistantResponse", "",
			"https://q.us-east-1.amazonaws.com/generateAssistantResponse"},
	}
	for _, c := range cases {
		got := rewriteEndpointRegion(c.url, c.region)
		if got != c.want {
			t.Errorf("rewriteEndpointRegion(%q, %q) = %q, want %q", c.url, c.region, got, c.want)
		}
	}
}
