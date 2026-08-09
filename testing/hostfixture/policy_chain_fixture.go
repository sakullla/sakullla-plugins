package hostfixture

import (
	"errors"
	"fmt"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

var ErrCanonicalPolicyChainUnavailable = errors.New("canonical policy chain is unavailable")

type PolicyArtifactInit struct {
	Stage  string
	Status pluginsdk.PolicyStatus
}

// GateCanonicalPolicyChain requires the actual artifacts to initialize in the
// fixed IP→rate→WAF order. It does not invent a resource or host wire contract.
func GateCanonicalPolicyChain(results []PolicyArtifactInit) error {
	want := [...]string{"ip-policy", "rate-limit", "waf"}
	if len(results) != len(want) {
		return fmt.Errorf("%w: got %d artifacts, want %d", ErrCanonicalPolicyChainUnavailable, len(results), len(want))
	}
	for index, stage := range want {
		if results[index].Stage != stage {
			return fmt.Errorf("%w: position %d is %q, want %q", ErrCanonicalPolicyChainUnavailable, index, results[index].Stage, stage)
		}
		if results[index].Status != pluginsdk.PolicyStatusOK {
			return fmt.Errorf("%w: %s init status %d", ErrCanonicalPolicyChainUnavailable, stage, results[index].Status)
		}
	}
	return nil
}
