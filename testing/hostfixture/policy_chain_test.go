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

	var sessions []*policyArtifactSession
	defer func() {
		for _, session := range sessions {
			session.Close()
		}
	}()
	results := make([]PolicyArtifactInit, 0, 3)
	for _, stage := range []struct {
		name     string
		artifact []byte
		config   []byte
	}{
		{name: "ip-policy", artifact: ipArtifact, config: []byte(`{"default":"allow"}`)},
		{name: "rate-limit", artifact: rateArtifact, config: []byte(`{"enabled":true}`)},
		{name: "waf", artifact: wafArtifact, config: []byte(`{"mode":"deny"}`)},
	} {
		session, status := initPolicyArtifact(t, stage.artifact, stage.config, "/", nil, true)
		sessions = append(sessions, session)
		results = append(results, PolicyArtifactInit{Stage: stage.name, Status: status})
	}
	ipStatus, rateStatus, wafStatus := results[0].Status, results[1].Status, results[2].Status
	if ipStatus != pluginsdk.PolicyStatusIncompatibleABI {
		t.Fatalf("IP artifact without trusted-source capability status = %d", ipStatus)
	}
	if rateStatus != pluginsdk.PolicyStatusIncompatibleABI {
		t.Fatalf("rate artifact without monotonic/atomic capabilities status = %d", rateStatus)
	}
	if wafStatus != pluginsdk.PolicyStatusOK {
		t.Fatalf("WAF artifact canonical init status = %d", wafStatus)
	}
	err := GateCanonicalPolicyChain(results)
	if !errors.Is(err, ErrCanonicalPolicyChainUnavailable) {
		t.Fatalf("release chain did not fail closed: %v", err)
	}
	for index, session := range sessions {
		if session.evaluateCount != 0 || session.eventCount != 0 || session.statePutCount != 0 {
			t.Fatalf("stage %s ran before init gate: evaluates=%d events=%d state_puts=%d", results[index].Stage, session.evaluateCount, session.eventCount, session.statePutCount)
		}
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
