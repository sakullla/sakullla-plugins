// Package policychain is a deterministic local harness for policy composition.
// It is not an Agent host and cannot provide trusted-source, atomic-state, or
// monotonic-clock evidence for a release profile.
package policychain

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

type Stage string

const (
	StageIPPolicy  Stage = "ip-policy"
	StageRateLimit Stage = "rate-limit"
	StageWAF       Stage = "waf"
)

var fixedOrder = [...]Stage{StageIPPolicy, StageRateLimit, StageWAF}

func FixedStages() []Stage {
	return append([]Stage(nil), fixedOrder[:]...)
}

var (
	ErrGenerationMismatch = errors.New("policy binding generation is stale")
	ErrGrantRevoked       = errors.New("policy binding grant is revoked")
	ErrInvalidDefinition  = errors.New("policy chain definition is invalid")
	ErrBudgetExceeded     = errors.New("policy evaluation budget exceeded")
	ErrPoolSaturated      = errors.New("policy evaluator pool saturated")
)

const DefaultStageTimeout = 50 * time.Millisecond

type Request struct {
	BindingID     string
	Generation    string
	RequestID     string
	Source        string
	SourceTrusted bool
	Payload       []byte
}

type Decision struct {
	Action pluginsdk.PolicyAction
	Reason string
}

type Evaluator func(context.Context, Request, map[string]string, *Transaction) (Decision, error)

// Transaction owns all model state and event effects for one Evaluate call.
// Effects are committed only after an on-time successful chain result. Direct
// side effects captured by arbitrary evaluator closures are outside this local
// model; real hard isolation still requires a supervised process boundary.
type Transaction struct {
	base   map[string]string
	writes map[string]string
	events []string
}

func (transaction *Transaction) State(key string) (string, bool) {
	if value, exists := transaction.writes[key]; exists {
		return value, true
	}
	value, exists := transaction.base[key]
	return value, exists
}

func (transaction *Transaction) PutState(key, value string) {
	transaction.writes[key] = value
}

func (transaction *Transaction) EmitEvent(event string) {
	transaction.events = append(transaction.events, event)
}

type Definition struct {
	Ref        string
	Evaluators map[Stage]Evaluator
}

type Overlay map[Stage]map[string]string

type Binding struct {
	ID            string
	ChainRef      string
	Generation    string
	Enabled       bool
	Granted       bool
	FailureAction pluginsdk.PolicyAction
	Overlay       Overlay
	StageTimeout  time.Duration
}

type Trace struct {
	BindingID string
	ChainRef  string
	Stages    []Stage
	Decision  Decision
	Unbound   bool
	Disabled  bool
	Failure   error
}

type Harness struct {
	mu          sync.RWMutex
	definitions map[string]Definition
	bindings    map[string]Binding
	state       map[string]string
	events      []string
}

func NewHarness() *Harness {
	return &Harness{definitions: make(map[string]Definition), bindings: make(map[string]Binding), state: make(map[string]string)}
}

func (harness *Harness) State(key string) (string, bool) {
	harness.mu.RLock()
	defer harness.mu.RUnlock()
	value, exists := harness.state[key]
	return value, exists
}

func (harness *Harness) Events() []string {
	harness.mu.RLock()
	defer harness.mu.RUnlock()
	return append([]string(nil), harness.events...)
}

func (harness *Harness) PutDefinition(definition Definition) error {
	if definition.Ref == "" || len(definition.Evaluators) != len(fixedOrder) {
		return ErrInvalidDefinition
	}
	copy := Definition{Ref: definition.Ref, Evaluators: make(map[Stage]Evaluator, len(fixedOrder))}
	for _, stage := range fixedOrder {
		evaluator := definition.Evaluators[stage]
		if evaluator == nil {
			return fmt.Errorf("%w: stage %s is missing", ErrInvalidDefinition, stage)
		}
		copy.Evaluators[stage] = evaluator
	}
	harness.mu.Lock()
	harness.definitions[copy.Ref] = copy
	harness.mu.Unlock()
	return nil
}

func (harness *Harness) PutBinding(binding Binding) error {
	if binding.ID == "" || binding.ChainRef == "" || binding.Generation == "" {
		return errors.New("binding id, one chain ref, and generation are required")
	}
	if binding.FailureAction != pluginsdk.PolicyActionAllow && binding.FailureAction != pluginsdk.PolicyActionDeny {
		return errors.New("binding failure action must be allow or deny")
	}
	if binding.StageTimeout < 0 {
		return errors.New("binding stage timeout cannot be negative")
	}
	if binding.StageTimeout == 0 {
		binding.StageTimeout = DefaultStageTimeout
	}
	for stage := range binding.Overlay {
		if stage != StageIPPolicy && stage != StageRateLimit && stage != StageWAF {
			return fmt.Errorf("binding overlay stage %q is not in the fixed chain", stage)
		}
	}
	harness.mu.RLock()
	_, exists := harness.definitions[binding.ChainRef]
	harness.mu.RUnlock()
	if !exists {
		return fmt.Errorf("chain ref %q does not exist", binding.ChainRef)
	}
	binding.Overlay = cloneOverlay(binding.Overlay)
	harness.mu.Lock()
	harness.bindings[binding.ID] = binding
	harness.mu.Unlock()
	return nil
}

func (harness *Harness) Disable(bindingID string) error {
	return harness.updateBinding(bindingID, func(binding *Binding) { binding.Enabled = false })
}

func (harness *Harness) Revoke(bindingID string) error {
	return harness.updateBinding(bindingID, func(binding *Binding) { binding.Granted = false })
}

func (harness *Harness) updateBinding(bindingID string, update func(*Binding)) error {
	harness.mu.Lock()
	defer harness.mu.Unlock()
	binding, exists := harness.bindings[bindingID]
	if !exists {
		return fmt.Errorf("binding %q does not exist", bindingID)
	}
	update(&binding)
	harness.bindings[bindingID] = binding
	return nil
}

func (harness *Harness) Evaluate(ctx context.Context, request Request) Trace {
	if request.BindingID == "" {
		return Trace{Unbound: true, Decision: allow("unbound traffic")}
	}
	harness.mu.RLock()
	binding, exists := harness.bindings[request.BindingID]
	definition := harness.definitions[binding.ChainRef]
	harness.mu.RUnlock()
	if !exists {
		return Trace{BindingID: request.BindingID, Unbound: true, Decision: allow("unknown binding is isolated")}
	}
	trace := Trace{BindingID: binding.ID, ChainRef: binding.ChainRef}
	if !binding.Enabled {
		trace.Disabled = true
		trace.Decision = allow("binding disabled")
		return trace
	}
	if !binding.Granted {
		trace.Failure = ErrGrantRevoked
		trace.Decision = Decision{Action: binding.FailureAction, Reason: ErrGrantRevoked.Error()}
		return trace
	}
	if request.Generation != binding.Generation {
		trace.Failure = ErrGenerationMismatch
		trace.Decision = Decision{Action: binding.FailureAction, Reason: ErrGenerationMismatch.Error()}
		return trace
	}

	request.Payload = append([]byte(nil), request.Payload...)
	transaction := harness.newTransaction()
	for _, stage := range fixedOrder {
		if err := ctx.Err(); err != nil {
			trace.Failure = err
			trace.Decision = Decision{Action: binding.FailureAction, Reason: err.Error()}
			return trace
		}
		trace.Stages = append(trace.Stages, stage)
		stageRequest := request
		stageRequest.Payload = append([]byte(nil), request.Payload...)
		decision, err := runEvaluator(ctx, binding.StageTimeout, definition.Evaluators[stage], stageRequest, cloneValues(binding.Overlay[stage]), transaction)
		if err != nil {
			trace.Failure = fmt.Errorf("%s: %w", stage, err)
			trace.Decision = Decision{Action: binding.FailureAction, Reason: trace.Failure.Error()}
			return trace
		}
		if !decision.Action.Valid() {
			trace.Failure = fmt.Errorf("%s returned an invalid action", stage)
			trace.Decision = Decision{Action: binding.FailureAction, Reason: trace.Failure.Error()}
			return trace
		}
		if decision.Action == pluginsdk.PolicyActionDeny {
			harness.commit(transaction)
			trace.Decision = decision
			return trace
		}
	}
	harness.commit(transaction)
	trace.Decision = allow("fixed chain allowed request")
	return trace
}

func (harness *Harness) newTransaction() *Transaction {
	harness.mu.RLock()
	defer harness.mu.RUnlock()
	return &Transaction{base: cloneValues(harness.state), writes: make(map[string]string)}
}

func (harness *Harness) commit(transaction *Transaction) {
	harness.mu.Lock()
	defer harness.mu.Unlock()
	for key, value := range transaction.writes {
		harness.state[key] = value
	}
	harness.events = append(harness.events, transaction.events...)
}

type evaluatorResult struct {
	decision Decision
	err      error
}

// runEvaluator isolates lifecycle state from an evaluator that ignores its
// context. A timed-out result is never committed; callers that install a
// non-cooperative test evaluator remain responsible for releasing its goroutine.
func runEvaluator(ctx context.Context, timeout time.Duration, evaluator Evaluator, request Request, overlay map[string]string, transaction *Transaction) (Decision, error) {
	if err := ctx.Err(); err != nil {
		return Decision{}, err
	}
	evaluatorCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	result := make(chan evaluatorResult, 1)
	go func() {
		decision, err := evaluator(evaluatorCtx, request, overlay, transaction)
		result <- evaluatorResult{decision: decision, err: err}
	}()
	select {
	case <-evaluatorCtx.Done():
		return Decision{}, evaluatorCtx.Err()
	case returned := <-result:
		if err := evaluatorCtx.Err(); err != nil {
			return Decision{}, err
		}
		return returned.decision, returned.err
	}
}

func allow(reason string) Decision {
	return Decision{Action: pluginsdk.PolicyActionAllow, Reason: reason}
}

func cloneOverlay(overlay Overlay) Overlay {
	copy := make(Overlay, len(overlay))
	for stage, values := range overlay {
		copy[stage] = cloneValues(values)
	}
	return copy
}

func cloneValues(values map[string]string) map[string]string {
	copy := make(map[string]string, len(values))
	for key, value := range values {
		copy[key] = value
	}
	return copy
}
