package hostfixture

import (
	"errors"
	"testing"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

func TestPolicyChainCanonicalArtifactsFailClosedWithoutCapabilities(t *testing.T) {
	ipArtifact := buildIPPolicyArtifact(t)
	rateArtifact := buildRateLimitArtifact(t)
	wafArtifact := buildWAFArtifact(t)
	for name, artifact := range map[string][]byte{
		"ip-policy":  ipArtifact,
		"rate-limit": rateArtifact,
		"waf":        wafArtifact,
	} {
		if err := pluginsdk.ValidatePolicyV1WASM(artifact, pluginsdk.PolicyV1MaxMemoryBytes); err != nil {
			t.Fatalf("%s canonical ABI validation: %v", name, err)
		}
	}

	ipStatus, _ := runWAFArtifact(t, ipArtifact, []byte(`{"default":"allow"}`), "/", nil, true)
	rateStatus, _ := runWAFArtifact(t, rateArtifact, []byte(`{"enabled":true}`), "/", nil, true)
	wafStatus, _ := runWAFArtifact(t, wafArtifact, []byte(`{"mode":"deny"}`), "/", nil, true)
	if ipStatus != pluginsdk.PolicyStatusIncompatibleABI {
		t.Fatalf("IP artifact without trusted-source capability status = %d", ipStatus)
	}
	if rateStatus != pluginsdk.PolicyStatusIncompatibleABI {
		t.Fatalf("rate artifact without monotonic/atomic capabilities status = %d", rateStatus)
	}
	if wafStatus != pluginsdk.PolicyStatusOK {
		t.Fatalf("WAF artifact canonical init status = %d", wafStatus)
	}
	err := GateCanonicalPolicyChain([]PolicyArtifactInit{
		{Stage: "ip-policy", Status: ipStatus},
		{Stage: "rate-limit", Status: rateStatus},
		{Stage: "waf", Status: wafStatus},
	})
	if !errors.Is(err, ErrCanonicalPolicyChainUnavailable) {
		t.Fatalf("release chain did not fail closed: %v", err)
	}
}

func TestPolicyChainCanonicalArtifactOrderIsMandatory(t *testing.T) {
	err := GateCanonicalPolicyChain([]PolicyArtifactInit{
		{Stage: "rate-limit", Status: pluginsdk.PolicyStatusOK},
		{Stage: "ip-policy", Status: pluginsdk.PolicyStatusOK},
		{Stage: "waf", Status: pluginsdk.PolicyStatusOK},
	})
	if !errors.Is(err, ErrCanonicalPolicyChainUnavailable) {
		t.Fatalf("out-of-order artifact chain was accepted: %v", err)
	}
}
