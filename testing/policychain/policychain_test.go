package policychain

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

func TestPolicyChainOrderIsIPPolicyRateLimitWAF(t *testing.T) {
	mutableCopy := FixedStages()
	mutableCopy[0] = StageWAF
	var calls []Stage
	harness := configuredHarness(t, func(stage Stage, _ Request, _ map[string]string) (Decision, error) {
		calls = append(calls, stage)
		return allow("ok"), nil
	})
	trace := harness.Evaluate(context.Background(), requestFor("binding-a"))
	if trace.Decision.Action != pluginsdk.PolicyActionAllow {
		t.Fatalf("chain decision = %#v", trace)
	}
	if !reflect.DeepEqual(calls, FixedStages()) || !reflect.DeepEqual(trace.Stages, FixedStages()) {
		t.Fatalf("chain order calls=%v trace=%v", calls, trace.Stages)
	}
}

func TestPolicyChainSharedRefOverlayIsolation(t *testing.T) {
	harness := configuredHarness(t, func(stage Stage, request Request, overlay map[string]string) (Decision, error) {
		if stage == StageWAF && overlay["mode"] == "deny" {
			return Decision{Action: pluginsdk.PolicyActionDeny, Reason: request.BindingID + " overlay"}, nil
		}
		return allow("ok"), nil
	})
	if err := harness.PutBinding(binding("binding-b", Overlay{StageWAF: {"mode": "allow"}})); err != nil {
		t.Fatal(err)
	}
	first := harness.Evaluate(context.Background(), requestFor("binding-a"))
	second := harness.Evaluate(context.Background(), requestFor("binding-b"))
	if first.ChainRef != second.ChainRef || first.Decision.Action != pluginsdk.PolicyActionDeny || second.Decision.Action != pluginsdk.PolicyActionAllow {
		t.Fatalf("shared chain overlay results first=%#v second=%#v", first, second)
	}
}

func TestPolicyChainDisableAndRevoke(t *testing.T) {
	harness := configuredHarness(t, func(Stage, Request, map[string]string) (Decision, error) { return allow("ok"), nil })
	if err := harness.Disable("binding-a"); err != nil {
		t.Fatal(err)
	}
	disabled := harness.Evaluate(context.Background(), requestFor("binding-a"))
	if !disabled.Disabled || len(disabled.Stages) != 0 || disabled.Decision.Action != pluginsdk.PolicyActionAllow {
		t.Fatalf("disabled binding result = %#v", disabled)
	}
	if err := harness.PutBinding(binding("binding-a", nil)); err != nil {
		t.Fatal(err)
	}
	if err := harness.Revoke("binding-a"); err != nil {
		t.Fatal(err)
	}
	revoked := harness.Evaluate(context.Background(), requestFor("binding-a"))
	if !errors.Is(revoked.Failure, ErrGrantRevoked) || revoked.Decision.Action != pluginsdk.PolicyActionDeny || len(revoked.Stages) != 0 {
		t.Fatalf("revoked binding result = %#v", revoked)
	}
}

func TestPolicyChainFailureIsolationAndStreamingUnbound(t *testing.T) {
	harness := configuredHarness(t, func(stage Stage, request Request, _ map[string]string) (Decision, error) {
		if stage == StageRateLimit && request.BindingID == "binding-a" {
			return Decision{}, errors.New("fixture pool saturated")
		}
		return allow("ok"), nil
	})
	if err := harness.PutBinding(binding("binding-b", nil)); err != nil {
		t.Fatal(err)
	}
	failed := harness.Evaluate(context.Background(), requestFor("binding-a"))
	unrelated := harness.Evaluate(context.Background(), requestFor("binding-b"))
	unbound := harness.Evaluate(context.Background(), Request{RequestID: "streaming", Payload: make([]byte, 1<<20)})
	if failed.Decision.Action != pluginsdk.PolicyActionDeny || failed.Failure == nil {
		t.Fatalf("bound failure result = %#v", failed)
	}
	if unrelated.Decision.Action != pluginsdk.PolicyActionAllow || unrelated.Failure != nil {
		t.Fatalf("unrelated binding result = %#v", unrelated)
	}
	if !unbound.Unbound || unbound.Decision.Action != pluginsdk.PolicyActionAllow || len(unbound.Stages) != 0 {
		t.Fatalf("unbound streaming result = %#v", unbound)
	}
}

func TestPolicyChainDeadlineIsolationDoesNotBlockUnboundOrOtherBinding(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	finished := make(chan struct{})
	var once sync.Once
	harness := configuredHarness(t, func(stage Stage, request Request, _ map[string]string) (Decision, error) {
		if stage == StageIPPolicy && request.BindingID == "binding-a" {
			once.Do(func() { close(started) })
			<-release
			close(finished)
		}
		return allow("ok"), nil
	})
	bound := binding("binding-a", nil)
	bound.StageTimeout = 10 * time.Millisecond
	if err := harness.PutBinding(bound); err != nil {
		t.Fatal(err)
	}
	if err := harness.PutBinding(binding("binding-b", nil)); err != nil {
		t.Fatal(err)
	}

	result := make(chan Trace, 1)
	go func() { result <- harness.Evaluate(context.Background(), requestFor("binding-a")) }()
	<-started
	unrelated := harness.Evaluate(context.Background(), requestFor("binding-b"))
	unbound := harness.Evaluate(context.Background(), Request{RequestID: "streaming"})
	trace := <-result
	if !errors.Is(trace.Failure, context.DeadlineExceeded) || trace.Decision.Action != pluginsdk.PolicyActionDeny {
		t.Fatalf("deadline result = %#v", trace)
	}
	if unrelated.Failure != nil || unrelated.Decision.Action != pluginsdk.PolicyActionAllow || !unbound.Unbound {
		t.Fatalf("parallel isolation unrelated=%#v unbound=%#v", unrelated, unbound)
	}
	close(release)
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("blocked evaluator goroutine was not released")
	}
}

func TestPolicyChainLateTransactionEffectsAreDiscarded(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	finished := make(chan struct{})
	harness := NewHarness()
	evaluators := make(map[Stage]Evaluator, len(FixedStages()))
	for _, stage := range FixedStages() {
		current := stage
		evaluators[current] = func(_ context.Context, request Request, _ map[string]string, transaction *Transaction) (Decision, error) {
			if current == StageIPPolicy && request.BindingID == "binding-a" {
				close(started)
				<-release
				transaction.PutState("shared-rate", "late-write")
				transaction.EmitEvent("late-event")
				close(finished)
			}
			if current == StageWAF && request.BindingID == "binding-b" {
				if _, exists := transaction.State("shared-rate"); exists {
					return Decision{Action: pluginsdk.PolicyActionDeny, Reason: "observed late state"}, nil
				}
			}
			return allow("ok"), nil
		}
	}
	if err := harness.PutDefinition(Definition{Ref: "chain-shared", Evaluators: evaluators}); err != nil {
		t.Fatal(err)
	}
	first := binding("binding-a", nil)
	first.StageTimeout = 10 * time.Millisecond
	if err := harness.PutBinding(first); err != nil {
		t.Fatal(err)
	}
	if err := harness.PutBinding(binding("binding-b", nil)); err != nil {
		t.Fatal(err)
	}

	result := make(chan Trace, 1)
	go func() { result <- harness.Evaluate(context.Background(), requestFor("binding-a")) }()
	<-started
	if trace := <-result; !errors.Is(trace.Failure, context.DeadlineExceeded) {
		t.Fatalf("timed-out binding result = %#v", trace)
	}
	close(release)
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("late evaluator was not released")
	}
	second := harness.Evaluate(context.Background(), requestFor("binding-b"))
	if second.Failure != nil || second.Decision.Action != pluginsdk.PolicyActionAllow {
		t.Fatalf("binding B observed discarded transaction: %#v", second)
	}
	if _, exists := harness.State("shared-rate"); exists || len(harness.Events()) != 0 {
		t.Fatalf("late effects committed state=%v events=%v", exists, harness.Events())
	}
}

func TestPolicyChainBudgetAndPoolFailuresAreBindingLocal(t *testing.T) {
	for _, test := range []struct {
		name    string
		failure error
	}{
		{name: "budget", failure: ErrBudgetExceeded},
		{name: "pool", failure: ErrPoolSaturated},
	} {
		t.Run(test.name, func(t *testing.T) {
			harness := configuredHarness(t, func(stage Stage, request Request, _ map[string]string) (Decision, error) {
				if stage == StageRateLimit && request.BindingID == "binding-a" {
					return Decision{}, test.failure
				}
				return allow("ok"), nil
			})
			if err := harness.PutBinding(binding("binding-b", nil)); err != nil {
				t.Fatal(err)
			}
			failed := harness.Evaluate(context.Background(), requestFor("binding-a"))
			unrelated := harness.Evaluate(context.Background(), requestFor("binding-b"))
			unbound := harness.Evaluate(context.Background(), Request{RequestID: "streaming"})
			if !errors.Is(failed.Failure, test.failure) || failed.Decision.Action != pluginsdk.PolicyActionDeny {
				t.Fatalf("local failure = %#v", failed)
			}
			if unrelated.Failure != nil || unrelated.Decision.Action != pluginsdk.PolicyActionAllow || !unbound.Unbound {
				t.Fatalf("failure escaped binding unrelated=%#v unbound=%#v", unrelated, unbound)
			}
		})
	}
}

func TestIPPolicyDenyShortCircuitsRateLimitAndWAF(t *testing.T) {
	var calls []Stage
	harness := configuredHarness(t, func(stage Stage, _ Request, _ map[string]string) (Decision, error) {
		calls = append(calls, stage)
		if stage == StageIPPolicy {
			return Decision{Action: pluginsdk.PolicyActionDeny, Reason: "blocked source"}, nil
		}
		return allow("ok"), nil
	})
	trace := harness.Evaluate(context.Background(), requestFor("binding-a"))
	if trace.Decision.Action != pluginsdk.PolicyActionDeny || !reflect.DeepEqual(calls, []Stage{StageIPPolicy}) {
		t.Fatalf("IP policy short circuit = %#v calls=%v", trace, calls)
	}
}

func TestPolicyChainGenerationIsolation(t *testing.T) {
	harness := configuredHarness(t, func(Stage, Request, map[string]string) (Decision, error) { return allow("ok"), nil })
	request := requestFor("binding-a")
	request.Generation = "stale"
	trace := harness.Evaluate(context.Background(), request)
	if !errors.Is(trace.Failure, ErrGenerationMismatch) || trace.Decision.Action != pluginsdk.PolicyActionDeny || len(trace.Stages) != 0 {
		t.Fatalf("stale generation result = %#v", trace)
	}
}

func configuredHarness(t *testing.T, evaluate func(Stage, Request, map[string]string) (Decision, error)) *Harness {
	t.Helper()
	harness := NewHarness()
	evaluators := make(map[Stage]Evaluator, len(FixedStages()))
	for _, stage := range FixedStages() {
		current := stage
		evaluators[current] = func(_ context.Context, request Request, overlay map[string]string, _ *Transaction) (Decision, error) {
			return evaluate(current, request, overlay)
		}
	}
	if err := harness.PutDefinition(Definition{Ref: "chain-shared", Evaluators: evaluators}); err != nil {
		t.Fatal(err)
	}
	if err := harness.PutBinding(binding("binding-a", Overlay{StageWAF: {"mode": "deny"}})); err != nil {
		t.Fatal(err)
	}
	return harness
}

func binding(id string, overlay Overlay) Binding {
	return Binding{
		ID: id, ChainRef: "chain-shared", Generation: "generation-1", Enabled: true, Granted: true,
		FailureAction: pluginsdk.PolicyActionDeny, Overlay: overlay,
	}
}

func requestFor(bindingID string) Request {
	return Request{
		BindingID: bindingID, Generation: "generation-1", RequestID: "request-1",
		Source: "192.0.2.10", SourceTrusted: true, Payload: []byte("fixture"),
	}
}
